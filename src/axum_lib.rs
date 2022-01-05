use anyhow::{anyhow, Result};
use async_redis_session::RedisSessionStore;
use axum::{
    extract::{self, Extension, Form, Query, TypedHeader},
    http::{
        header::{self, HeaderMap},
        StatusCode,
    },
    response::{self, IntoResponse, Redirect},
    routing::{get, get_service, post},
    AddExtensionLayer, Json, Router,
};
use bb8_redis::{bb8, RedisConnectionManager};
use figment::{
    providers::{Env, Format, Serialized, Toml},
    Figment,
};
use headers::{
    self,
    authorization::{Basic, Bearer},
    Authorization,
};
use openidconnect::core::{
    CoreClientMetadata, CoreClientRegistrationResponse, CoreJsonWebKeySet, CoreProviderMetadata,
    CoreResponseType, CoreTokenResponse, CoreUserInfoClaims,
};
use rand::rngs::OsRng;
use rsa::{
    pkcs1::{FromRsaPrivateKey, ToRsaPrivateKey},
    RsaPrivateKey,
};
use std::net::SocketAddr;
use tower_http::{
    services::{ServeDir, ServeFile},
    trace::TraceLayer,
};
use tracing::info;

use super::config;
use super::oidc::{self, CustomError};
use super::session::*;
use ::siwe_oidc::db::*;

impl IntoResponse for CustomError {
    fn into_response(self) -> response::Response {
        match self {
            CustomError::BadRequest(_) => {
                (StatusCode::BAD_REQUEST, self.to_string()).into_response()
            }
            CustomError::BadRequestToken(e) => {
                (StatusCode::BAD_REQUEST, Json::from(e)).into_response()
            }
            CustomError::Unauthorized(_) => {
                (StatusCode::UNAUTHORIZED, self.to_string()).into_response()
            }
            CustomError::Redirect(uri) => Redirect::to(
                uri.parse().unwrap(),
                // .map_err(|e| anyhow!("Could not parse URI: {}", e))?,
            )
            .into_response(),
            CustomError::Other(_) => {
                (StatusCode::INTERNAL_SERVER_ERROR, self.to_string()).into_response()
            }
        }
    }
}

async fn jwk_set(
    Extension(private_key): Extension<RsaPrivateKey>,
) -> Result<Json<CoreJsonWebKeySet>, CustomError> {
    let jwks = oidc::jwks(private_key)?;
    Ok(jwks.into())
}

async fn provider_metadata(
    Extension(config): Extension<config::Config>,
) -> Result<Json<CoreProviderMetadata>, CustomError> {
    Ok(oidc::metadata(config.base_url)?.into())
}

// TODO should check Authorization header
// Actually, client secret can be
// 1. in the POST (currently supported) [x]
// 2. Authorization header              [x]
// 3. JWT                               [ ]
// 4. signed JWT                        [ ]
// according to Keycloak

async fn token(
    Form(form): Form<oidc::TokenForm>,
    bearer: Option<TypedHeader<Authorization<Bearer>>>,
    basic: Option<TypedHeader<Authorization<Basic>>>,
    Extension(private_key): Extension<RsaPrivateKey>,
    Extension(config): Extension<config::Config>,
    Extension(redis_client): Extension<RedisClient>,
) -> Result<Json<CoreTokenResponse>, CustomError> {
    let secret = if let Some(b) = bearer {
        Some(b.0 .0.token().to_string())
    } else {
        basic.map(|b| b.0 .0.password().to_string())
    };
    let token_response = oidc::token(
        form,
        secret,
        private_key,
        config.base_url,
        config.require_secret,
        &redis_client,
    )
    .await?;
    Ok(token_response.into())
}

// TODO handle `registration` parameter
async fn authorize(
    session: UserSessionFromSession,
    Query(params): Query<oidc::AuthorizeParams>,
    Extension(redis_client): Extension<RedisClient>,
) -> Result<(HeaderMap, Redirect), CustomError> {
    let (nonce, headers) = match session {
        UserSessionFromSession::Found(nonce) => (nonce, HeaderMap::new()),
        UserSessionFromSession::Invalid(cookie) => {
            let mut headers = HeaderMap::new();
            headers.insert(header::SET_COOKIE, cookie);
            return Ok((
                headers,
                Redirect::to(
                    format!(
"/authorize?client_id={}&redirect_uri={}&scope={}&response_type={}&state={}&client_id={}{}",
&params.client_id,
&params.redirect_uri.to_string(),
&params.scope.to_string(),
&params.response_type.unwrap_or(CoreResponseType::Code).as_ref(),
&params.state.unwrap_or_default(),
&params.client_id,
&params.nonce.map(|n| format!("&nonce={}", n.secret())).unwrap_or_default()
)
                    .parse()
                    .map_err(|e| anyhow!("Could not parse URI: {}", e))?,
                ),
            ));
        }
        UserSessionFromSession::Created { header, nonce } => {
            let mut headers = HeaderMap::new();
            headers.insert(header::SET_COOKIE, header);
            (nonce, headers)
        }
    };

    let url = oidc::authorize(params, nonce, &redis_client).await?;
    Ok((
        headers,
        Redirect::to(
            url.as_str()
                .parse()
                .map_err(|e| anyhow!("Could not parse URI: {}", e))?,
        ),
    ))
}

async fn sign_in(
    session: UserSessionFromSession,
    Query(params): Query<oidc::SignInParams>,
    TypedHeader(cookies): TypedHeader<headers::Cookie>,
    Extension(redis_client): Extension<RedisClient>,
) -> Result<(HeaderMap, Redirect), CustomError> {
    let (nonce, headers) = match session {
        UserSessionFromSession::Found(nonce) => (nonce, HeaderMap::new()),
        UserSessionFromSession::Invalid(header) => {
            let mut headers = HeaderMap::new();
            headers.insert(header::SET_COOKIE, header);
            return Ok((
                headers,
                Redirect::to(
                    format!(
    "/authorize?client_id={}&redirect_uri={}&scope=openid&response_type=code&state={}",
    &params.client_id.clone(),
    &params.redirect_uri.to_string(),
&params.state,
)
                    .parse()
                    .map_err(|e| anyhow!("Could not parse URI: {}", e))?,
                ),
            ));
        }
        UserSessionFromSession::Created { .. } => {
            return Ok((
                HeaderMap::new(),
                Redirect::to(
                    format!(
                "/authorize?client_id={}&redirect_uri={}&scope=openid&response_type=code&state={}",
                &params.client_id.clone(),
                &params.redirect_uri.to_string(),
                &params.state,
            )
                    .parse()
                    .map_err(|e| anyhow!("Could not parse URI: {}", e))?,
                ),
            ))
        }
    };

    let url = oidc::sign_in(params, Some(nonce), cookies, &redis_client).await?;

    Ok((
        headers,
        Redirect::to(
            url.as_str()
                .parse()
                .map_err(|e| anyhow!("Could not parse URI: {}", e))?,
        ),
    ))
    // TODO clear session
}

async fn register(
    extract::Json(payload): extract::Json<CoreClientMetadata>,
    Extension(redis_client): Extension<RedisClient>,
) -> Result<(StatusCode, Json<CoreClientRegistrationResponse>), CustomError> {
    let registration = oidc::register(payload, &redis_client).await?;
    Ok((StatusCode::CREATED, registration.into()))
}

// TODO CORS
// TODO need validation of the token
async fn userinfo(
    payload: Option<Form<oidc::UserInfoPayload>>,
    bearer: Option<TypedHeader<Authorization<Bearer>>>, // TODO maybe go through FromRequest https://github.com/tokio-rs/axum/blob/main/examples/jwt/src/main.rs
    Extension(redis_client): Extension<RedisClient>,
) -> Result<Json<CoreUserInfoClaims>, CustomError> {
    let payload = if let Some(Form(p)) = payload {
        p
    } else {
        oidc::UserInfoPayload { access_token: None }
    };
    let claims = oidc::userinfo(bearer.map(|b| b.0 .0), payload, &redis_client).await?;
    Ok(claims.into())
}

async fn healthcheck() {}

pub async fn main() {
    let config = Figment::from(Serialized::defaults(config::Config::default()))
        .merge(Toml::file("siwe-oidc.toml").nested())
        .merge(Env::prefixed("SIWEOIDC_").split("__").global());
    let config = config.extract::<config::Config>().unwrap();

    tracing_subscriber::fmt::init();

    let manager = RedisConnectionManager::new(config.redis_url.clone()).unwrap();
    let pool = bb8::Pool::builder().build(manager.clone()).await.unwrap();
    // let pool2 = bb8::Pool::builder().build(manager).await.unwrap();

    let redis_client = RedisClient { pool };

    for (id, secret) in &config.default_clients.clone() {
        let client_entry = ClientEntry {
            secret: secret.to_string(),
            redirect_uris: vec![],
        };
        redis_client
            .set_client(id.to_string(), client_entry)
            .await
            .unwrap(); // TODO
    }

    let private_key = if let Some(key) = &config.rsa_pem {
        RsaPrivateKey::from_pkcs1_pem(key)
            .map_err(|e| anyhow!("Failed to load private key: {}", e))
            .unwrap()
    } else {
        info!("Generating key...");
        let mut rng = OsRng;
        let bits = 2048;
        let private = RsaPrivateKey::new(&mut rng, bits)
            .map_err(|e| anyhow!("Failed to generate a key: {}", e))
            .unwrap();

        info!("Generated key.");
        info!("{:?}", private.to_pkcs1_pem().unwrap());
        private
    };

    let app = Router::new()
        .nest(
            "/build",
            get_service(ServeDir::new("./static/build")).handle_error(
                |error: std::io::Error| async move {
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        format!("Unhandled internal error: {}", error),
                    )
                },
            ),
        )
        .nest(
            "/img",
            get_service(ServeDir::new("./static/img")).handle_error(
                |error: std::io::Error| async move {
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        format!("Unhandled internal error: {}", error),
                    )
                },
            ),
        )
        .route(
            "/",
            get_service(ServeFile::new("./static/index.html")).handle_error(
                |error: std::io::Error| async move {
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        format!("Unhandled internal error: {}", error),
                    )
                },
            ),
        )
        .route(
            "/error",
            get_service(ServeFile::new("./static/error.html")).handle_error(
                |error: std::io::Error| async move {
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        format!("Unhandled internal error: {}", error),
                    )
                },
            ),
        )
        .route(
            "/favicon.png",
            get_service(ServeFile::new("./static/favicon.png")).handle_error(
                |error: std::io::Error| async move {
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        format!("Unhandled internal error: {}", error),
                    )
                },
            ),
        )
        .route(oidc::METADATA_PATH, get(provider_metadata))
        .route(oidc::JWK_PATH, get(jwk_set))
        .route(oidc::TOKEN_PATH, post(token))
        .route(oidc::AUTHORIZE_PATH, get(authorize))
        .route(oidc::REGISTER_PATH, post(register))
        .route(oidc::USERINFO_PATH, get(userinfo).post(userinfo))
        .route(oidc::SIGNIN_PATH, get(sign_in))
        .route("/health", get(healthcheck))
        .layer(AddExtensionLayer::new(private_key))
        .layer(AddExtensionLayer::new(config.clone()))
        .layer(AddExtensionLayer::new(redis_client))
        .layer(AddExtensionLayer::new(
            RedisSessionStore::new(config.redis_url.clone())
                .unwrap()
                .with_prefix("async-sessions/"),
        ))
        .layer(TraceLayer::new_for_http());

    let addr = SocketAddr::from((config.address, config.port));
    tracing::info!("Listening on {}", addr);
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}
