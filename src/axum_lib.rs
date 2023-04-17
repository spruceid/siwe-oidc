use anyhow::{anyhow, Result};
use axum::{
    extract::{self, Extension, Form, Path, Query, TypedHeader},
    http::{
        header::{self, HeaderMap},
        StatusCode,
    },
    response::{self, IntoResponse, Redirect},
    routing::{delete, get, get_service, post},
    Json, Router,
};
use figment::{
    providers::{Env, Format, Serialized, Toml},
    Figment,
};
use headers::{
    self,
    authorization::{Basic, Bearer},
    Authorization, ContentType, Header,
};
use openidconnect::core::{
    CoreClientMetadata, CoreClientRegistrationResponse, CoreJsonWebKeySet, CoreProviderMetadata,
    CoreTokenResponse, CoreUserInfoClaims, CoreUserInfoJsonWebToken,
};
use rand::rngs::OsRng;
use rsa::{
    pkcs1::{DecodeRsaPrivateKey, EncodeRsaPrivateKey, LineEnding},
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
use ::siwe_oidc::db::*;

impl IntoResponse for CustomError {
    fn into_response(self) -> response::Response {
        match self {
            CustomError::BadRequest(_) => {
                (StatusCode::BAD_REQUEST, self.to_string()).into_response()
            }
            CustomError::BadRequestRegister(e) => {
                (StatusCode::BAD_REQUEST, Json::from(e)).into_response()
            }
            CustomError::BadRequestToken(e) => {
                (StatusCode::BAD_REQUEST, Json::from(e)).into_response()
            }
            CustomError::Unauthorized(_) => {
                (StatusCode::UNAUTHORIZED, self.to_string()).into_response()
            }
            CustomError::NotFound => (StatusCode::NOT_FOUND, self.to_string()).into_response(),
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
        config.eth_provider,
        &redis_client,
    )
    .await?;
    Ok(token_response.into())
}

async fn authorize(
    Query(params): Query<oidc::AuthorizeParams>,
    Extension(redis_client): Extension<RedisClient>,
) -> Result<(HeaderMap, Redirect), CustomError> {
    let (url, session_cookie) = oidc::authorize(params, &redis_client).await?;
    let mut headers = HeaderMap::new();
    headers.insert(
        header::SET_COOKIE,
        session_cookie.to_string().parse().unwrap(),
    );
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
    Query(params): Query<oidc::SignInParams>,
    TypedHeader(cookies): TypedHeader<headers::Cookie>,
    Extension(redis_client): Extension<RedisClient>,
    Extension(config): Extension<config::Config>,
) -> Result<Redirect, CustomError> {
    let url = oidc::sign_in(&config.base_url, params, cookies, &redis_client).await?;
    Ok(Redirect::to(
        url.as_str()
            .parse()
            .map_err(|e| anyhow!("Could not parse URI: {}", e))?,
    ))
}

async fn register(
    extract::Json(payload): extract::Json<CoreClientMetadata>,
    Extension(config): Extension<config::Config>,
    Extension(redis_client): Extension<RedisClient>,
) -> Result<(StatusCode, Json<CoreClientRegistrationResponse>), CustomError> {
    let registration = oidc::register(payload, config.base_url, &redis_client).await?;
    Ok((StatusCode::CREATED, registration.into()))
}

struct UserInfoResponseJWT(Json<CoreUserInfoJsonWebToken>);

impl IntoResponse for UserInfoResponseJWT {
    fn into_response(self) -> response::Response {
        response::Response::builder()
            .status(StatusCode::OK)
            .header(ContentType::name(), "application/jwt")
            .body(
                serde_json::to_string(&self.0 .0)
                    .unwrap()
                    .replace('"', "")
                    .into_response()
                    .into_body(),
            )
            .unwrap()
    }
}

enum UserInfoResponse {
    Json(Json<CoreUserInfoClaims>),
    Jwt(UserInfoResponseJWT),
}

impl IntoResponse for UserInfoResponse {
    fn into_response(self) -> response::Response {
        match self {
            UserInfoResponse::Json(j) => j.into_response(),
            UserInfoResponse::Jwt(j) => j.into_response(),
        }
    }
}

// TODO CORS
// TODO need validation of the token
async fn userinfo(
    Extension(private_key): Extension<RsaPrivateKey>,
    Extension(config): Extension<config::Config>,
    payload: Option<Form<oidc::UserInfoPayload>>,
    bearer: Option<TypedHeader<Authorization<Bearer>>>, // TODO maybe go through FromRequest https://github.com/tokio-rs/axum/blob/main/examples/jwt/src/main.rs
    Extension(redis_client): Extension<RedisClient>,
) -> Result<UserInfoResponse, CustomError> {
    let payload = if let Some(Form(p)) = payload {
        p
    } else {
        oidc::UserInfoPayload { access_token: None }
    };
    let claims = oidc::userinfo(
        config.base_url,
        config.eth_provider,
        private_key,
        bearer.map(|b| b.0 .0),
        payload,
        &redis_client,
    )
    .await?;
    Ok(match claims {
        oidc::UserInfoResponse::Json(c) => UserInfoResponse::Json(c.into()),
        oidc::UserInfoResponse::Jwt(c) => UserInfoResponse::Jwt(UserInfoResponseJWT(c.into())),
    })
}

async fn clientinfo(
    Path(client_id): Path<String>,
    Extension(redis_client): Extension<RedisClient>,
) -> Result<Json<CoreClientMetadata>, CustomError> {
    Ok(oidc::clientinfo(client_id, &redis_client).await?.into())
}

async fn client_update(
    Path(client_id): Path<String>,
    extract::Json(payload): extract::Json<CoreClientMetadata>,
    bearer: Option<TypedHeader<Authorization<Bearer>>>,
    Extension(redis_client): Extension<RedisClient>,
) -> Result<(), CustomError> {
    oidc::client_update(client_id, payload, bearer.map(|b| b.0 .0), &redis_client).await
}

async fn client_delete(
    Path(client_id): Path<String>,
    bearer: Option<TypedHeader<Authorization<Bearer>>>,
    Extension(redis_client): Extension<RedisClient>,
) -> Result<(StatusCode, ()), CustomError> {
    Ok((
        StatusCode::NO_CONTENT,
        oidc::client_delete(client_id, bearer.map(|b| b.0 .0), &redis_client).await?,
    ))
}

async fn healthcheck() {}

pub async fn main() {
    let config = Figment::from(Serialized::defaults(config::Config::default()))
        .merge(Toml::file("siwe-oidc.toml").nested())
        .merge(Env::prefixed("SIWEOIDC_").split("__").global());
    let config = config.extract::<config::Config>().unwrap();

    tracing_subscriber::fmt::init();

    let redis_client = RedisClient::new(&config.redis_url)
        .await
        .expect("Could not build Redis client");

    for (id, entry) in &config.default_clients.clone() {
        let entry: ClientEntry =
            serde_json::from_str(entry).expect("Deserialisation of ClientEntry failed");
        redis_client
            .set_client(id.to_string(), entry.clone())
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
        info!("{:?}", private.to_pkcs1_pem(LineEnding::LF).unwrap());
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
            "/legal",
            get_service(ServeDir::new("./static/legal")).handle_error(
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
        .route(&format!("{}/:id", oidc::CLIENT_PATH), get(clientinfo))
        .route(&format!("{}/:id", oidc::CLIENT_PATH), delete(client_delete))
        .route(&format!("{}/:id", oidc::CLIENT_PATH), post(client_update))
        .route(oidc::SIGNIN_PATH, get(sign_in))
        .route("/health", get(healthcheck))
        .layer(Extension(private_key))
        .layer(Extension(config.clone()))
        .layer(Extension(redis_client))
        .layer(TraceLayer::new_for_http());

    let addr = SocketAddr::from((config.address, config.port));
    tracing::info!("Listening on {}", addr);
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}
