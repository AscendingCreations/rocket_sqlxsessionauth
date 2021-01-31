use crate::SQLxSessionAuth;
use rocket::http::Method;
use sqlx::pool::PoolConnection;
use std::marker::PhantomData;
use async_recursion::async_recursion;

#[rocket::async_trait]
pub trait HasPermission {
    async fn has(&self, perm: &String, pool: &Option<&mut PoolConnection<sqlx::Postgres>>) -> bool;
}

#[derive(Clone)]
pub enum Rights {
    All(Box<[Rights]>),
    Any(Box<[Rights]>),
    NoneOf(Box<[Rights]>),
    Permission(String),
    None,
}

impl Rights {
    pub fn all(data: &[Rights]) -> Rights {
        Rights::All(data.iter().cloned().collect())
    }

    pub fn any(data: &[Rights]) -> Rights {
        Rights::Any(data.iter().cloned().collect())
    }

    pub fn none(data: &[Rights]) -> Rights {
        Rights::NoneOf(data.iter().cloned().collect())
    }

    #[async_recursion()]
    pub async fn evaluate(
        &self,
        user: &(dyn HasPermission + Sync),
        db: &Option<&mut PoolConnection<sqlx::Postgres>>,
    ) -> bool {
        match self {
            Self::All(rights) => {
                let mut all = true;
                    for r in rights.iter() {
                        if !r.evaluate(user, &db).await {
                            all = false;
                            break;
                        }
                    }

                all
            }
            Self::Any(rights) => {
                let mut all = false;
                    for r in rights.iter() {
                        if r.evaluate(user, &db).await {
                            all = true;
                            break;
                        }
                    }

                all
            }
            Self::NoneOf(rights) => !{
                let mut all = true;
                    for r in rights.iter() {
                        if !r.evaluate(user, &db).await {
                            all = false;
                            break;
                        }
                    }

                all
            },
            Self::Permission(perm) => user.has(&perm, &db).await,
            Self::None => false,
        }
    }
}

pub struct Auth<D>
where
    D: 'static +  SQLxSessionAuth<D> + HasPermission,
{
    pub rights: Rights,
    pub auth_required: bool,
    pub methods: Box<[Method]>,
    phantom: PhantomData<D>,
}

impl<D> Auth<D>
where
    D: 'static + SQLxSessionAuth<D> + HasPermission,
{
    pub fn build(methods: &[Method], auth_req: bool) -> Auth<D> {
        Auth::<D> {
            rights: Rights::None,
            auth_required: auth_req,
            methods: methods.into(),
            phantom: PhantomData,
        }
    }

    pub fn requires(&mut self, rights: Rights) -> &mut Self {
        self.rights = rights;
        self
    }

    pub async fn validate(
        &self,
        user: &D,
        method: &Method,
        db: Option<&mut PoolConnection<sqlx::Postgres>>,
    ) -> bool where D: HasPermission +  SQLxSessionAuth<D> + Sync {
        if self.auth_required && !user.is_authenticated() {
            return false;
        }

        if self.methods.iter().any(|r| r == method) {
            self.rights.evaluate(user, &db).await
        } else {
            false
        }
    }
}
