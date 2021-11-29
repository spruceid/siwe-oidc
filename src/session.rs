use async_redis_session::RedisSessionStore;
use async_session::{Session, SessionStore as _};
use axum::{
    async_trait,
    extract::{Extension, FromRequest, RequestParts},
    http::{self, header::HeaderValue, StatusCode},
};
use cookie::Cookie;
use rand::{distributions::Alphanumeric, Rng};
use serde::{Deserialize, Serialize};
use tracing::debug;
use uuid::Uuid;

const SESSION_COOKIE_NAME: &str = "session";
const SESSION_KEY: &str = "user_session";

pub enum UserSessionFromSession {
    FoundUserSession(String),
    CreatedFreshUserSession { header: HeaderValue, nonce: String },
    InvalidUserSession(HeaderValue),
}

#[async_trait]
impl<B> FromRequest<B> for UserSessionFromSession
where
    B: Send,
{
    type Rejection = (StatusCode, String);

    async fn from_request(req: &mut RequestParts<B>) -> Result<Self, Self::Rejection> {
        let Extension(store) = match Extension::<RedisSessionStore>::from_request(req).await {
            Ok(s) => s,
            Err(e) => {
                return Err((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("`MemoryStore` extension missing: {}", e),
                ))
            }
        };

        let headers = if let Some(h) = req.headers() {
            h
        } else {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                "other extractor taken headers".to_string(),
            ));
        };

        let session_cookie: Cookie = if let Some(session_cookie) = headers
            .get(http::header::COOKIE)
            .and_then(|value| value.to_str().ok())
            .map(|header| {
                header
                    .split(";")
                    .map(|cookie| Cookie::parse(cookie).ok())
                    .filter(|cookie| {
                        cookie.is_some() && cookie.as_ref().unwrap().name() == SESSION_COOKIE_NAME
                    })
                    .next()
            })
            .flatten()
            .flatten()
        {
            session_cookie
        } else {
            let user_session = UserSession::new();
            let mut session = Session::new();
            session.insert(SESSION_KEY, user_session.clone()).unwrap();
            let cookie = store.store_session(session).await.unwrap().unwrap();

            return Ok(Self::CreatedFreshUserSession {
                header: Cookie::new(SESSION_COOKIE_NAME, cookie)
                    .to_string()
                    .parse()
                    .unwrap(),
                nonce: user_session.nonce,
            });
        };

        let session = match store.load_session(session_cookie.value().to_string()).await {
            Ok(Some(s)) => s,
            _ => {
                debug!("Could not load session");
                let mut cookie = session_cookie.clone();
                cookie.make_removal();
                return Ok(Self::InvalidUserSession(
                    cookie.to_string().parse().unwrap(),
                ));
            }
        };
        let user_session = if let Some(user_session) = session.get::<UserSession>(SESSION_KEY) {
            user_session
        } else {
            debug!("No `user_session` found in session");
            let mut cookie = session_cookie.clone();
            cookie.make_removal();
            return Ok(Self::InvalidUserSession(
                cookie.to_string().parse().unwrap(),
            ));
        };

        Ok(Self::FoundUserSession(user_session.nonce))
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct UserSession {
    id: Uuid,
    nonce: String,
}

impl UserSession {
    fn new() -> Self {
        Self {
            id: Uuid::new_v4(),
            nonce: rand::thread_rng()
                .sample_iter(&Alphanumeric)
                .take(16)
                .map(char::from)
                .collect(),
        }
    }
}
