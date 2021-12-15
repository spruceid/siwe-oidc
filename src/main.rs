use anyhow::{anyhow, Result};
use async_redis_session::RedisSessionStore;
use axum::{
    body::{Bytes, Full},
    error_handling::HandleErrorExt,
    extract::{self, Extension, Form, Query, TypedHeader},
    http::{
        header::{self, HeaderMap},
        Response, StatusCode,
    },
    response::{IntoResponse, Redirect},
    routing::{get, post, service_method_routing},
    AddExtensionLayer, Json, Router,
};
use bb8_redis::{bb8, bb8::Pool, redis::AsyncCommands, RedisConnectionManager};
use chrono::{Duration, Utc};
use figment::{
    providers::{Env, Format, Serialized, Toml},
    Figment,
};
use headers::{self, authorization::Bearer, Authorization};
use hex::FromHex;
use iri_string::types::{UriAbsoluteString, UriString};
use openidconnect::{
    core::{
        CoreClaimName, CoreClientAuthMethod, CoreClientMetadata, CoreClientRegistrationResponse,
        CoreGrantType, CoreIdToken, CoreIdTokenClaims, CoreIdTokenFields, CoreJsonWebKeySet,
        CoreJwsSigningAlgorithm, CoreProviderMetadata, CoreResponseType, CoreRsaPrivateSigningKey,
        CoreSubjectIdentifierType, CoreTokenResponse, CoreTokenType, CoreUserInfoClaims,
    },
    registration::{EmptyAdditionalClientMetadata, EmptyAdditionalClientRegistrationResponse},
    AccessToken, Audience, AuthUrl, ClientId, EmptyAdditionalClaims,
    EmptyAdditionalProviderMetadata, EmptyExtraTokenFields, IssuerUrl, JsonWebKeyId,
    JsonWebKeySetUrl, Nonce, PrivateSigningKey, RedirectUrl, RegistrationUrl, ResponseTypes, Scope,
    StandardClaims, SubjectIdentifier, TokenUrl, UserInfoUrl,
};
use rand::rngs::OsRng;
use rsa::{
    pkcs1::{FromRsaPrivateKey, ToRsaPrivateKey},
    RsaPrivateKey,
};
use serde::{Deserialize, Serialize};
use siwe::eip4361::{Message, Version};
use std::{convert::Infallible, net::SocketAddr, str::FromStr};
use thiserror::Error;
use tower_http::{
    services::{ServeDir, ServeFile},
    trace::TraceLayer,
};
use tracing::info;
use urlencoding::decode;
use uuid::Uuid;

mod config;
mod session;

use session::*;

const KID: &str = "key1";
const KV_CLIENT_PREFIX: &str = "clients";
const ENTRY_LIFETIME: usize = 60 * 60 * 24 * 2;

type ConnectionPool = Pool<RedisConnectionManager>;

#[derive(Debug, Error)]
pub enum CustomError {
    #[error("{0}")]
    BadRequest(String),
    #[error("{0}")]
    Unauthorized(String),
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

impl IntoResponse for CustomError {
    type Body = Full<Bytes>;
    type BodyError = Infallible;

    fn into_response(self) -> Response<Self::Body> {
        match self {
            CustomError::BadRequest(_) => (StatusCode::BAD_REQUEST, self.to_string()),
            CustomError::Unauthorized(_) => (StatusCode::UNAUTHORIZED, self.to_string()),
            CustomError::Other(_) => (StatusCode::INTERNAL_SERVER_ERROR, self.to_string()),
        }
        .into_response()
    }
}

async fn jwk_set(
    Extension(private_key): Extension<RsaPrivateKey>,
) -> Result<Json<CoreJsonWebKeySet>, CustomError> {
    let pem = private_key
        .to_pkcs1_pem()
        .map_err(|e| anyhow!("Failed to serialise key as PEM: {}", e))?;
    let jwks = CoreJsonWebKeySet::new(vec![CoreRsaPrivateSigningKey::from_pem(
        &pem,
        Some(JsonWebKeyId::new(KID.to_string())),
    )
    .map_err(|e| anyhow!("Invalid RSA private key: {}", e))?
    .as_verification_key()]);
    Ok(jwks.into())
}

async fn provider_metadata(
    Extension(config): Extension<config::Config>,
) -> Result<Json<CoreProviderMetadata>, CustomError> {
    let pm = CoreProviderMetadata::new(
        IssuerUrl::from_url(config.base_url.clone()),
        AuthUrl::from_url(
            config
                .base_url
                .join("authorize")
                .map_err(|e| anyhow!("Unable to join URL: {}", e))?,
        ),
        JsonWebKeySetUrl::from_url(
            config
                .base_url
                .join("jwk")
                .map_err(|e| anyhow!("Unable to join URL: {}", e))?,
        ),
        vec![
            ResponseTypes::new(vec![CoreResponseType::Code]),
            ResponseTypes::new(vec![CoreResponseType::Token, CoreResponseType::IdToken]),
        ],
        vec![CoreSubjectIdentifierType::Pairwise],
        vec![CoreJwsSigningAlgorithm::RsaSsaPssSha256],
        EmptyAdditionalProviderMetadata {},
    )
    .set_token_endpoint(Some(TokenUrl::from_url(
        config
            .base_url
            .join("token")
            .map_err(|e| anyhow!("Unable to join URL: {}", e))?,
    )))
    .set_userinfo_endpoint(Some(UserInfoUrl::from_url(
        config
            .base_url
            .join("userinfo")
            .map_err(|e| anyhow!("Unable to join URL: {}", e))?,
    )))
    .set_scopes_supported(Some(vec![
        Scope::new("openid".to_string()),
        // Scope::new("email".to_string()),
        // Scope::new("profile".to_string()),
    ]))
    .set_claims_supported(Some(vec![
        CoreClaimName::new("sub".to_string()),
        CoreClaimName::new("aud".to_string()),
        // CoreClaimName::new("email".to_string()),
        // CoreClaimName::new("email_verified".to_string()),
        CoreClaimName::new("exp".to_string()),
        CoreClaimName::new("iat".to_string()),
        CoreClaimName::new("iss".to_string()),
        // CoreClaimName::new("name".to_string()),
        // CoreClaimName::new("given_name".to_string()),
        // CoreClaimName::new("family_name".to_string()),
        // CoreClaimName::new("picture".to_string()),
        // CoreClaimName::new("locale".to_string()),
    ]))
    .set_registration_endpoint(Some(RegistrationUrl::from_url(
        config
            .base_url
            .join("register")
            .map_err(|e| anyhow!("Unable to join URL: {}", e))?,
    )))
    .set_token_endpoint_auth_methods_supported(Some(vec![CoreClientAuthMethod::ClientSecretPost]));

    Ok(pm.into())
}

#[derive(Deserialize)]
struct TokenForm {
    code: String,
    client_id: String,
    client_secret: Option<String>,
    grant_type: CoreGrantType, // TODO should just be authorization_code apparently?
}

// TODO should check Authorization header
// Actually, client secret can be
// 1. in the POST (currently supported)
// 2. Authorization header
// 3. JWT
// 4. signed JWT
// according to Keycloak

async fn token(
    form: Form<TokenForm>,
    Extension(private_key): Extension<RsaPrivateKey>,
    Extension(config): Extension<config::Config>,
    Extension(pool): Extension<ConnectionPool>,
) -> Result<Json<CoreTokenResponse>, CustomError> {
    let mut conn = pool
        .get()
        .await
        .map_err(|e| anyhow!("Failed to get connection to database: {}", e))?;

    if let Some(secret) = form.client_secret.clone() {
        let stored_secret: Option<String> = conn
            .get(format!("{}/{}", KV_CLIENT_PREFIX, form.client_id))
            .await
            .map_err(|e| anyhow!("Failed to get kv: {}", e))?;
        if stored_secret.is_none() {
            Err(CustomError::Unauthorized(
                "Unrecognised client id.".to_string(),
            ))?;
        }
        if secret != stored_secret.unwrap() {
            Err(CustomError::Unauthorized("Bad secret.".to_string()))?;
        }
    } else if config.require_secret {
        Err(CustomError::Unauthorized("Secret required.".to_string()))?;
    }

    let serialized_entry: Option<Vec<u8>> = conn
        .get(form.code.to_string())
        .await
        .map_err(|e| anyhow!("Failed to get kv: {}", e))?;
    if serialized_entry.is_none() {
        Err(CustomError::BadRequest("Unknown code.".to_string()))?;
    }
    let code_entry: CodeEntry = bincode::deserialize(
        &hex::decode(serialized_entry.unwrap())
            .map_err(|e| anyhow!("Failed to decode code entry: {}", e))?,
    )
    .map_err(|e| anyhow!("Failed to deserialize code: {}", e))?;

    if code_entry.exchange_count > 0 {
        // TODO use Oauth error response
        Err(anyhow!("Code was previously exchanged."))?;
    }
    conn.set_ex(
        form.code.to_string(),
        hex::encode(
            bincode::serialize(&code_entry)
                .map_err(|e| anyhow!("Failed to serialise code: {}", e))?,
        ),
        ENTRY_LIFETIME,
    )
    .await
    .map_err(|e| anyhow!("Failed to set kv: {}", e))?;

    let access_token = AccessToken::new(form.code.clone());
    let core_id_token = CoreIdTokenClaims::new(
        IssuerUrl::from_url(config.base_url),
        vec![Audience::new(form.client_id.clone())],
        Utc::now() + Duration::seconds(60),
        Utc::now(),
        StandardClaims::new(SubjectIdentifier::new(code_entry.address)),
        EmptyAdditionalClaims {},
    )
    .set_nonce(code_entry.nonce);

    let pem = private_key
        .to_pkcs1_pem()
        .map_err(|e| anyhow!("Failed to serialise key as PEM: {}", e))?;

    let id_token = CoreIdToken::new(
        core_id_token,
        &CoreRsaPrivateSigningKey::from_pem(&pem, Some(JsonWebKeyId::new(KID.to_string())))
            .map_err(|e| anyhow!("Invalid RSA private key: {}", e))?,
        CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256,
        Some(&access_token),
        None,
    )
    .map_err(|e| anyhow!("{}", e))?;

    Ok(CoreTokenResponse::new(
        access_token,
        CoreTokenType::Bearer,
        CoreIdTokenFields::new(Some(id_token), EmptyExtraTokenFields {}),
    )
    .into())
}

#[derive(Deserialize)]
struct AuthorizeParams {
    client_id: String,
    redirect_uri: RedirectUrl,
    scope: Scope,
    response_type: CoreResponseType,
    state: String,
    nonce: Option<Nonce>,
}

// TODO handle `registration` parameter
async fn authorize(
    session: UserSessionFromSession,
    params: Query<AuthorizeParams>,
    // Extension(private_key): Extension<RsaPrivateKey>,
) -> Result<(HeaderMap, Redirect), CustomError> {
    // TODO: Enforce Client Registration
    // let d = std::str::from_utf8(
    //     &jwk.decrypt(
    //         PaddingScheme::new_pkcs1v15_encrypt(),
    //         &params.client_id.as_bytes(),
    //     )
    //     .map_err(|e| anyhow!("Failed to decrypt client id: {}", e))?,
    // )
    // .map_err(|e| anyhow!("Failed to decrypt client id: {}", e))?
    // if d != params.redirect_uri.as_str() {
    //     return Err(anyhow!("Client id not composed of redirect url"));
    // };

    if params.scope != Scope::new("openid".to_string()) {
        Err(anyhow!("Scope not supported"))?;
    }

    let (nonce, headers) = match session {
        UserSessionFromSession::FoundUserSession(nonce) => (nonce, HeaderMap::new()),
        UserSessionFromSession::InvalidUserSession(cookie) => {
            let mut headers = HeaderMap::new();
            headers.insert(header::SET_COOKIE, cookie);
            return Ok((
                headers,
                Redirect::to(
                    format!(
"/authorize?client_id={}&redirect_uri={}&scope={}&response_type={}&state={}{}",
&params.0.client_id,
&params.0.redirect_uri.to_string(),
&params.0.scope.to_string(),
&params.0.response_type.as_ref(),
&params.0.state,
&params.0.nonce.map(|n| format!("&nonce={}", n.secret())).unwrap_or(String::new())
)
                    .to_string()
                    .parse()
                    .map_err(|e| anyhow!("Could not parse URI: {}", e))?,
                ),
            ));
        }
        UserSessionFromSession::CreatedFreshUserSession { header, nonce } => {
            let mut headers = HeaderMap::new();
            headers.insert(header::SET_COOKIE, header);
            (nonce, headers)
        }
    };

    let domain = params.redirect_uri.url().host().unwrap();
    let oidc_nonce_param = if let Some(n) = &params.nonce {
        format!("&oidc_nonce={}", n.secret())
    } else {
        "".to_string()
    };
    Ok((
        headers,
        Redirect::to(
            format!(
                "/?nonce={}&domain={}&redirect_uri={}&state={}{}",
                nonce,
                domain,
                params.redirect_uri.to_string(),
                params.state,
                oidc_nonce_param
            )
            .parse()
            .map_err(|e| anyhow!("Could not parse URI: {}", e))?,
        ),
    ))
}

#[derive(Serialize, Deserialize)]
struct SiweCookie {
    message: Web3ModalMessage,
    signature: String,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Web3ModalMessage {
    pub domain: String,
    pub address: String,
    pub statement: String,
    pub uri: String,
    pub version: String,
    pub chain_id: String,
    pub nonce: String,
    pub issued_at: String,
    pub expiration_time: Option<String>,
    pub not_before: Option<String>,
    pub request_id: Option<String>,
    pub resources: Option<Vec<String>>,
}

impl Web3ModalMessage {
    pub fn to_eip4361_message(&self) -> Result<Message> {
        let mut next_resources: Vec<UriString> = Vec::new();
        match &self.resources {
            Some(resources) => {
                for resource in resources {
                    let x = UriString::from_str(resource)?;
                    next_resources.push(x)
                }
            }
            None => {}
        }

        Ok(Message {
            domain: self.domain.clone().try_into()?,
            address: <[u8; 20]>::from_hex(self.address.chars().skip(2).collect::<String>())?,
            statement: self.statement.to_string(),
            uri: UriAbsoluteString::from_str(&self.uri)?,
            version: Version::from_str(&self.version)?,
            chain_id: self.chain_id.to_string(),
            nonce: self.nonce.to_string(),
            issued_at: self.issued_at.to_string(),
            expiration_time: self.expiration_time.clone(),
            not_before: self.not_before.clone(),
            request_id: self.request_id.clone(),
            resources: next_resources,
        })
    }
}

#[derive(Serialize, Deserialize)]
struct CodeEntry {
    exchange_count: usize,
    address: String,
    nonce: Option<Nonce>,
}

#[derive(Deserialize)]
struct SignInParams {
    redirect_uri: RedirectUrl,
    state: String,
    oidc_nonce: Option<Nonce>,
}

async fn sign_in(
    session: UserSessionFromSession,
    params: Query<SignInParams>,
    TypedHeader(cookies): TypedHeader<headers::Cookie>,
    Extension(pool): Extension<ConnectionPool>,
) -> Result<(HeaderMap, Redirect), CustomError> {
    let mut headers = HeaderMap::new();
    let siwe_cookie: SiweCookie = match cookies.get("siwe") {
        Some(c) => serde_json::from_str(
            &decode(c).map_err(|e| anyhow!("Could not decode siwe cookie: {}", e))?,
        )
        .map_err(|e| anyhow!("Could not deserialize siwe cookie: {}", e))?,
        None => Err(anyhow!("No `siwe` cookie"))?,
    };

    let (nonce, headers) = match session {
        UserSessionFromSession::FoundUserSession(nonce) => (nonce, HeaderMap::new()),
        UserSessionFromSession::InvalidUserSession(header) => {
            headers.insert(header::SET_COOKIE, header);
            return Ok((
                headers,
                Redirect::to(
                    format!(
    "/authorize?client_id={}&redirect_uri={}&scope=openid&response_type=code&state={}",
    &params.0.redirect_uri.to_string(),
    &params.0.redirect_uri.to_string(),
&params.0.state,
)
                    .to_string()
                    .parse()
                    .map_err(|e| anyhow!("Could not parse URI: {}", e))?,
                ),
            ));
        }
        UserSessionFromSession::CreatedFreshUserSession { .. } => {
            return Ok((
                headers,
                Redirect::to(
                    format!(
                "/authorize?client_id={}&redirect_uri={}&scope=openid&response_type=code&state={}",
                &params.0.redirect_uri.to_string(),
                &params.0.redirect_uri.to_string(),
                &params.0.state,
            )
                    .to_string()
                    .parse()
                    .map_err(|e| anyhow!("Could not parse URI: {}", e))?,
                ),
            ))
        }
    };

    let signature = match <[u8; 65]>::from_hex(
        siwe_cookie
            .signature
            .chars()
            .skip(2)
            .take(130)
            .collect::<String>()
            .clone(),
    ) {
        Ok(s) => s,
        Err(e) => Err(CustomError::BadRequest(format!("Bad signature: {}", e)))?,
    };

    let message = siwe_cookie
        .message
        .to_eip4361_message()
        .map_err(|e| anyhow!("Failed to serialise message: {}", e))?;
    info!("{}", message);
    message
        .verify_eip191(signature)
        .map_err(|e| anyhow!("Failed signature validation: {}", e))?;

    let domain = params.redirect_uri.url().host().unwrap();
    if domain.to_string() != siwe_cookie.message.domain {
        Err(anyhow!("Conflicting domains in message and redirect"))?
    }
    if nonce != siwe_cookie.message.nonce {
        Err(anyhow!("Conflicting nonces in message and session"))?
    }

    let code_entry = CodeEntry {
        address: siwe_cookie.message.address,
        nonce: params.oidc_nonce.clone(),
        exchange_count: 0,
    };

    let code = Uuid::new_v4();
    let mut conn = pool
        .get()
        .await
        .map_err(|e| anyhow!("Failed to get connection to database: {}", e))?;
    conn.set_ex(
        code.to_string(),
        hex::encode(
            bincode::serialize(&code_entry)
                .map_err(|e| anyhow!("Failed to serialise code: {}", e))?,
        ),
        ENTRY_LIFETIME,
    )
    .await
    .map_err(|e| anyhow!("Failed to set kv: {}", e))?;

    let mut url = params.redirect_uri.url().clone();
    url.query_pairs_mut().append_pair("code", &code.to_string());
    url.query_pairs_mut().append_pair("state", &params.state);
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
    Extension(pool): Extension<ConnectionPool>,
) -> Result<Json<CoreClientRegistrationResponse>, CustomError> {
    let id = Uuid::new_v4();
    let secret = Uuid::new_v4();

    let mut conn = pool
        .get()
        .await
        .map_err(|e| anyhow!("Failed to get connection to database: {}", e))?;
    conn.set(format!("{}/{}", KV_CLIENT_PREFIX, id), secret.to_string())
        .await
        .map_err(|e| anyhow!("Failed to set kv: {}", e))?;

    Ok(CoreClientRegistrationResponse::new(
        ClientId::new(id.to_string()),
        payload.redirect_uris().to_vec(),
        EmptyAdditionalClientMetadata::default(),
        EmptyAdditionalClientRegistrationResponse::default(),
    )
    .into())
}

// TODO CORS
// TODO need validation of the token
// TODO restrict access token use to only once?
async fn userinfo(
    // access_token: AccessTokenUserInfo, // TODO maybe go through FromRequest https://github.com/tokio-rs/axum/blob/main/examples/jwt/src/main.rs
    TypedHeader(Authorization(bearer)): TypedHeader<Authorization<Bearer>>, // TODO maybe go through FromRequest https://github.com/tokio-rs/axum/blob/main/examples/jwt/src/main.rs
    Extension(pool): Extension<ConnectionPool>,
) -> Result<Json<CoreUserInfoClaims>, CustomError> {
    let code = bearer.token().to_string();
    let mut conn = pool
        .get()
        .await
        .map_err(|e| anyhow!("Failed to get connection to database: {}", e))?;
    let serialized_entry: Option<Vec<u8>> = conn
        .get(code)
        .await
        .map_err(|e| anyhow!("Failed to get kv: {}", e))?;
    if serialized_entry.is_none() {
        Err(CustomError::BadRequest("Unknown code.".to_string()))?;
    }
    let code_entry: CodeEntry = bincode::deserialize(
        &hex::decode(serialized_entry.unwrap())
            .map_err(|e| anyhow!("Failed to decode code entry: {}", e))?,
    )
    .map_err(|e| anyhow!("Failed to deserialize code: {}", e))?;

    Ok(CoreUserInfoClaims::new(
        StandardClaims::new(SubjectIdentifier::new(code_entry.address)),
        EmptyAdditionalClaims::default(),
    )
    .into())
}

async fn healthcheck() {}

#[tokio::main]
async fn main() {
    let config = Figment::from(Serialized::defaults(config::Config::default()))
        .merge(Toml::file("siwe-oidc.toml").nested())
        .merge(Env::prefixed("SIWEOIDC_").split("__").global());
    let config = config.extract::<config::Config>().unwrap();

    tracing_subscriber::fmt::init();

    let manager = RedisConnectionManager::new(config.redis_url.clone()).unwrap();
    let pool = bb8::Pool::builder().build(manager.clone()).await.unwrap();
    let pool2 = bb8::Pool::builder().build(manager).await.unwrap();

    let mut conn = pool2
        .get()
        .await
        .map_err(|e| anyhow!("Failed to get connection to database: {}", e))
        .unwrap();
    for (id, secret) in &config.default_clients.clone() {
        let _: () = conn
            .set(format!("{}/{}", KV_CLIENT_PREFIX, id), secret)
            .await
            .map_err(|e| anyhow!("Failed to set kv: {}", e))
            .unwrap();
    }

    let private_key = if let Some(key) = &config.rsa_pem {
        RsaPrivateKey::from_pkcs1_pem(&key)
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
            service_method_routing::get(ServeDir::new("./static/build")).handle_error(
                |error: std::io::Error| {
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        format!("Unhandled internal error: {}", error),
                    )
                },
            ),
        )
        .route(
            "/",
            service_method_routing::get(ServeFile::new("./static/index.html")).handle_error(
                |error: std::io::Error| {
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        format!("Unhandled internal error: {}", error),
                    )
                },
            ),
        )
        .route(
            "/favicon.png",
            service_method_routing::get(ServeFile::new("./static/favicon.png")).handle_error(
                |error: std::io::Error| {
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        format!("Unhandled internal error: {}", error),
                    )
                },
            ),
        )
        .route("/.well-known/openid-configuration", get(provider_metadata))
        .route("/jwk", get(jwk_set))
        .route("/token", post(token))
        .route("/authorize", get(authorize))
        .route("/register", post(register))
        .route("/userinfo", get(userinfo).post(userinfo))
        .route("/sign_in", get(sign_in))
        .route("/health", get(healthcheck))
        .layer(AddExtensionLayer::new(private_key))
        .layer(AddExtensionLayer::new(config.clone()))
        .layer(AddExtensionLayer::new(pool))
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
