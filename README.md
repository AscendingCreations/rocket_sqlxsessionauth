# rocket_sqlxsessionauth
Auth Addon for SQLX Session.


```rust
#![feature(proc_macro_hygiene, decl_macro)]
#[macro_use] extern crate rocket;

use rocket_sqlxsession::{SqlxSessionFairing, SQLxSession, SqlxSessionConfig};
use rocket_sqlxsessionauth::{SQLxAuth, SqlxSessionAuthFairing};
use anyhow::Error;
/// An anyhow::Result with default return type of ()
pub type Result<T = ()> = std::result::Result<T, Error>;

#[derive(sqlx::FromRow)]
pub struct SqlUser {
    pub id: i32,
    pub anonymous: Option<bool>,
    pub username: Option<String>,
}

#[derive(Debug)]
pub struct User {
    pub id: i32,
    pub anonymous: bool,
    pub username: String,
}

#[rocket::async_trait]
impl SQLxSessionAuth<User> for User {
    async fn load_user(userid: i64, pool: &mut PoolConnection<sqlx::Postgres>) -> Result<User> {
        let sqluser = match sqlx::query_as::<_, SqlUser>("SELECT * FROM users WHERE id = $1")
            .bind(userid)
            .fetch_one(pool)
            .await
        {
            Ok(user) => user,
            Err(e) => {
                return Err(anyhow::anyhow!("Could not load user: {}", e));
            }
        };

        Ok(User {
            id: sqluser.id,
            anonymous: sqluser.anonymous.unwrap_or(true),
            username: sqluser.username.unwrap_or("username_not_found".into()),
        })
    }

    fn is_authenticated(&self) -> bool {
        !self.anonymous
    }

    fn is_active(&self) -> bool {
        !self.anonymous
    }

    fn is_anonymous(&self) -> bool {
        self.anonymous
    }
}

fn main() {
    let config = SqlxSessionConfig::default()
            .with_database("databasename")
            .with_username("username")
            .with_password("password")
            .with_host("localhost")
            .with_port("5432");

    rocket::build()
        .attach(SqlxSessionFairing::new(config, None))
        .attach(SqlxSessionAuthFairing::<User>::new(None, None))
        .mount("/", routes![index])
        .launch();
}

//Auth must be placed After SQLxSession as it needs SQLxSession to load first before it can load the current_user.
#[get("/")]
fn index(method: Method, sqlxsession: SQLxSession, auth: SQLxAuth<User>) -> String {
    let mut count: usize = sqlxsession.get("count").unwrap_or(0);
    count += 1;
    sqlxsession.set("count", count);

    let username = if !auth.is_authenticated() {
        //Set the user ID of the User to the Session so it can be Auto Loaded the next load or redirect
        auth.login_user(2);
        "".to_string()
    } else {
        //if the user is loaded and is Authenticated then we can use it.
        if let Some(user) = auth.current_user {
            user.username.clone()
        } else {
            "".to_string()
        }
    };

    format!("{} visits, User: {}", count, username)
}
```

This library will attempt to load the Current authenticated User. you must place SQLxSession and SQLxAuth within the function parameters if you want to use SQLxAuth.
SQLxAuth also must always be placed After SQLxSession in order for it to use SQLxSession Data and get the Correct SessionID. Otherwise a Panic Error will Occur.
If you want it to always load an account you can set the anonymous_user_id og the Guest or Unathorized account before attaching it to Rocket. Example:

```rust

.attach(SqlxSessionAuthFairing::<User>::new(None, Some(1)))

```


This Library Also offers a Permission builder that uses Rockets Methods and String Token permissions. To use this system you must implement the HasPermission trait and
you must also impl SQLxSessionAuth as it uses is_authenticated.

```rust
#[rocket::async_trait]
impl HasPermission for User {
    async fn has(&self, perm: &String, pool: &Option<&mut PoolConnection<sqlx::Postgres>>) -> bool {
        match &perm[..] {
            "Token::UseAdmin" => true,
            "Token::ModifyUser" => true,
            _ => false,
        }
    }
}
```

This is used to check if the permission Exists or not. We also have a Optional SQLx Pool connection so you can use SQL querys to see if they Exist for the User.
the next step is to build the permission and then validate it within the function you want to check for permissions.

```rust
use rocket::http::Method;
use rocket_sqlxsession::SQLxSession;
use rocket_sqlxsessionauth::{Auth, Rights, SQLxAuth, SqlxSessionAuthFairing};

#[get("/")]
fn index(method: Method, sqlxsession: SQLxSession, auth: SQLxAuth<User>) -> String {
    let current_user = auth.current_user.clone();

    if let Some(cur_user) = current_user {
        if !Auth::<User>::build(&[Method::Get], false)
            .requires(Rights::none(&[
                Rights::Permission("Token::UseAdmin".into()),
                Rights::Permission("Token::ModifyPerms".into()),
            ]))
            .validate(&cur_user, &Method::Get, None)
            .await
        {
            return Some(format!("No Permissions! for {}", cur_user.username));
        }

        let mut count: usize = sqlxsession.get("count").unwrap_or(0);
        count += 1;
        sqlxsession.set("count", count);

        format!("{} visits, User: {}", count, cur_user.username)
    } else {
        //Do login and check here can do another Auth build.
        if !auth.is_authenticated() {
            //Set the user ID of the User to the Session so it can be Auto Loaded the next load or redirect
            auth.login_user(2);
            //redirect here after login if we did indeed login.
        }

        return Some("No Permissions!".to_string());
    }
}
```