use rocket::{
    fairing::{self, Fairing, Info},
    http::Status,
    outcome::{try_outcome, Outcome},
    request::{FromRequest, Request},
    Build, Rocket, State,
};
use rocket_sqlxsession::{SQLxSessionID, SQLxSessionStore};
use sqlx::{pool::PoolConnection, postgres::PgPool};
use std::marker::PhantomData;

pub use anyhow::Error;
/// An anyhow::Result with default return type of ()
pub type Result<T = ()> = std::result::Result<T, Error>;

#[rocket::async_trait]
pub trait SQLxSessionAuth<D> {
    async fn load_user(userid: i64, pool: &mut PoolConnection<sqlx::Postgres>) -> Result<D>;
    fn is_authenticated(&self) -> bool;
    fn is_active(&self) -> bool;
    fn is_anonymous(&self) -> bool;
}

#[derive(Debug, Clone)]
pub struct SQLxSessionAuthPool<D>
where
    D: 'static + Sync + Send + SQLxSessionAuth<D>,
{
    pub client: Option<PgPool>,
    pub anonymous_user_id: Option<i64>,
    phantom: PhantomData<D>,
}

impl<D> SQLxSessionAuthPool<D>
where
    D: 'static + Sync + Send + SQLxSessionAuth<D>,
{
    pub fn new(client: Option<PgPool>, anonymous_user_id: Option<i64>) -> Self {
        Self {
            client,
            anonymous_user_id,
            phantom: PhantomData,
        }
    }
}

#[derive(Debug)]
pub struct SQLxAuth<D>
where
    D: 'static + Sync + Send + SQLxSessionAuth<D>,
{
    pub current_user: Option<D>,
    current_id: Option<i64>,
    session: SQLxSessionStore,
    session_id: SQLxSessionID,
}

impl<D> SQLxAuth<D>
where
    D: 'static + Sync + Send + SQLxSessionAuth<D>,
{
    /// Use this to check if the user is Authenticated
    pub fn is_authenticated(&self) -> bool {
        match &self.current_user {
            Some(n) => n.is_authenticated(),
            None => false,
        }
    }

    /// Use this to check if the user is Active
    pub fn is_active(&self) -> bool {
        match &self.current_user {
            Some(n) => n.is_active(),
            None => false,
        }
    }

    /// Use this to check if the user is Anonymous
    pub fn is_anonymous(&self) -> bool {
        match &self.current_user {
            Some(n) => n.is_anonymous(),
            None => true,
        }
    }

    /// Use this to Set the user login into the Session so it can auto login the user on request.
    pub fn login_user(&self, id: i64) {
        let store_rg = self.session.inner.read();

        let mut instance = store_rg
            .get(self.session_id.inner())
            .expect("Session data unexpectedly missing")
            .lock();

        let value = serde_json::to_string(&id).unwrap_or_else(|_| "".to_string());
        if instance.data.get("user_auth_session_id") != Some(&value) {
            instance.data.insert("user_auth_session_id".into(), value);
        }
    }

    /// Use this to remove the users login. Forcing them to login as anonymous.
    pub fn logout_user(&self) {
        let store_rg = self.session.inner.read();

        let mut instance = store_rg
            .get(self.session_id.inner())
            .expect("Session data unexpectedly missing")
            .lock();

        instance.data.remove("user_auth_session_id");
    }
}

#[rocket::async_trait]
impl<'r, D> FromRequest<'r> for SQLxAuth<D>
where
    D: 'static + Sync + Send + SQLxSessionAuth<D>,
{
    type Error = ();

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, (Status, Self::Error), ()> {
        let store = try_outcome!(request.guard::<&State<SQLxSessionStore>>().await);
        let authpool = try_outcome!(request.guard::<&State<SQLxSessionAuthPool<D>>>().await);

        let session_id = request.local_cache(|| SQLxSessionID::new("".to_string()));

        let current_id = {
            let store_ug = store.inner.read();

            if let Some(m) = store_ug.get(session_id.inner()) {
                let inner = m.lock();

                if let Some(data) = inner.data.get("user_auth_session_id") {
                    let uid: Option<i64> = match serde_json::from_str(data).ok() {
                        Some(i) => Some(i),
                        None => authpool.anonymous_user_id,
                    };

                    uid
                } else {
                    authpool.anonymous_user_id
                }
            } else {
                authpool.anonymous_user_id
            }
        };

        let current_user = {
            match current_id {
                None => None,
                Some(uid) => {
                    if let Some(client) = &authpool.client {
                        let mut guard: PoolConnection<sqlx::Postgres> =
                            client.acquire().await.unwrap();

                        match D::load_user(uid, &mut guard).await {
                            Ok(user) => Some(user),
                            Err(_) => None,
                        }
                    } else {
                        let mut guard: PoolConnection<sqlx::Postgres> =
                            store.client.acquire().await.unwrap();

                        match D::load_user(uid, &mut guard).await {
                            Ok(user) => Some(user),
                            Err(_) => None,
                        }
                    }
                }
            }
        };

        Outcome::Success(SQLxAuth {
            current_id,
            current_user,
            session: store.inner().clone(),
            session_id: session_id.clone(),
        })
    }
}

/// Fairing struct
pub struct SqlxSessionAuthFairing<D>
where
    D: 'static + Sync + Send + SQLxSessionAuth<D>,
{
    poll: Option<PgPool>,
    anonymous_user_id: Option<i64>,
    phantom: PhantomData<D>,
}

impl<D> Default for SqlxSessionAuthFairing<D>
where
    D: 'static + Sync + Send + SQLxSessionAuth<D>,
{
    fn default() -> Self {
        Self::new(None, None)
    }
}

impl<D> SqlxSessionAuthFairing<D>
where
    D: 'static + Sync + Send + SQLxSessionAuth<D>,
{
    pub fn new(poll: Option<PgPool>, anonymous_user_id: Option<i64>) -> Self {
        Self {
            poll,
            anonymous_user_id,
            phantom: PhantomData,
        }
    }
}

#[rocket::async_trait]
impl<D> Fairing for SqlxSessionAuthFairing<D>
where
    D: 'static + Sync + Send + SQLxSessionAuth<D>,
{
    fn info(&self) -> Info {
        Info {
            name: "SQLxSessionAuth",
            kind: fairing::Kind::Ignite,
        }
    }

    async fn on_ignite(
        &self,
        rocket: Rocket<Build>,
    ) -> std::result::Result<Rocket<Build>, Rocket<Build>> {
        Ok(rocket.manage(SQLxSessionAuthPool::<D>::new(
            self.poll.clone(),
            self.anonymous_user_id,
        )))
    }
}
