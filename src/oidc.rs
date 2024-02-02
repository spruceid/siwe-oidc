use anyhow::{anyhow, Result};
use chrono::{Duration, Utc};
use cookie::{Cookie, SameSite};
use ethers_core::{types::H160, utils::to_checksum};
use ethers_providers::{Http, Middleware, Provider};
use headers::{self, authorization::Bearer};
use hex::FromHex;
use iri_string::types::UriString;
use openidconnect::{
    core::{
        CoreAuthErrorResponseType, CoreAuthPrompt, CoreClaimName, CoreClientAuthMethod,
        CoreClientMetadata, CoreClientRegistrationResponse, CoreErrorResponseType, CoreGenderClaim,
        CoreGrantType, CoreIdToken, CoreIdTokenClaims, CoreIdTokenFields, CoreJsonWebKeySet,
        CoreJwsSigningAlgorithm, CoreProviderMetadata, CoreRegisterErrorResponseType,
        CoreResponseType, CoreRsaPrivateSigningKey, CoreSubjectIdentifierType, CoreTokenResponse,
        CoreTokenType, CoreUserInfoClaims, CoreUserInfoJsonWebToken,
    },
    registration::{EmptyAdditionalClientMetadata, EmptyAdditionalClientRegistrationResponse},
    url::Url,
    AccessToken, Audience, AuthUrl, ClientConfigUrl, ClientId, ClientSecret, EmptyAdditionalClaims,
    EmptyAdditionalProviderMetadata, EmptyExtraTokenFields, EndUserPictureUrl, EndUserUsername,
    IssuerUrl, JsonWebKeyId, JsonWebKeySetUrl, LocalizedClaim, Nonce, OpPolicyUrl, OpTosUrl,
    PrivateSigningKey, RedirectUrl, RegistrationAccessToken, RegistrationUrl, RequestUrl,
    ResponseTypes, Scope, StandardClaims, SubjectIdentifier, TokenUrl, UserInfoUrl,
};
use rand::{distributions::Alphanumeric, thread_rng, Rng};
use rsa::{
    pkcs1::{EncodeRsaPrivateKey, LineEnding},
    RsaPrivateKey,
};
use serde::{Deserialize, Serialize};
use siwe::{Message, TimeStamp, VerificationOpts, Version};
use std::{str::FromStr, time};
use thiserror::Error;
use tracing::{error, info};
use urlencoding::decode;
use uuid::Uuid;

#[cfg(target_arch = "wasm32")]
use super::db::*;
#[cfg(not(target_arch = "wasm32"))]
use siwe_oidc::db::*;

lazy_static::lazy_static! {
    static ref SCOPES: [Scope; 2] = [
        Scope::new("openid".to_string()),
        Scope::new("profile".to_string()),
    ];
}
const SIGNING_ALG: [CoreJwsSigningAlgorithm; 1] = [CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256];
const KID: &str = "key1";
pub const METADATA_PATH: &str = "/.well-known/openid-configuration";
pub const JWK_PATH: &str = "/jwk";
pub const TOKEN_PATH: &str = "/token";
pub const AUTHORIZE_PATH: &str = "/authorize";
pub const REGISTER_PATH: &str = "/register";
pub const CLIENT_PATH: &str = "/client";
pub const USERINFO_PATH: &str = "/userinfo";
pub const SIGNIN_PATH: &str = "/sign_in";
pub const SIWE_COOKIE_KEY: &str = "siwe";
pub const TOU_PATH: &str = "/legal/terms-of-use.pdf";
pub const PP_PATH: &str = "/legal/privacy-policy.pdf";

#[cfg(not(target_arch = "wasm32"))]
type DBClientType = (dyn DBClient + Sync);
#[cfg(target_arch = "wasm32")]
type DBClientType = dyn DBClient;

#[derive(Serialize, Debug)]
pub struct TokenError {
    pub error: CoreErrorResponseType,
    pub error_description: String,
}

#[derive(Debug, Error)]
pub enum CustomError {
    #[error("{0}")]
    BadRequest(String),
    #[error("{0:?}")]
    BadRequestRegister(RegisterError),
    #[error("{0:?}")]
    BadRequestToken(TokenError),
    #[error("{0}")]
    Unauthorized(String),
    #[error("Not found")]
    NotFound,
    #[error("{0:?}")]
    Redirect(String),
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

fn jwk(private_key: RsaPrivateKey) -> Result<CoreRsaPrivateSigningKey> {
    let pem = private_key
        .to_pkcs1_pem(LineEnding::LF)
        .map_err(|e| anyhow!("Failed to serialise key as PEM: {}", e))?;
    CoreRsaPrivateSigningKey::from_pem(&pem, Some(JsonWebKeyId::new(KID.to_string())))
        .map_err(|e| anyhow!("Invalid RSA private key: {}", e))
}

pub fn jwks(private_key: RsaPrivateKey) -> Result<CoreJsonWebKeySet, CustomError> {
    let signing_key = jwk(private_key)?;
    let jwks = CoreJsonWebKeySet::new(vec![signing_key.as_verification_key()]);
    Ok(jwks)
}

pub fn metadata(base_url: Url) -> Result<CoreProviderMetadata, CustomError> {
    let pm = CoreProviderMetadata::new(
        IssuerUrl::from_url(base_url.clone()),
        AuthUrl::from_url(
            base_url
                .join(AUTHORIZE_PATH)
                .map_err(|e| anyhow!("Unable to join URL: {}", e))?,
        ),
        JsonWebKeySetUrl::from_url(
            base_url
                .join(JWK_PATH)
                .map_err(|e| anyhow!("Unable to join URL: {}", e))?,
        ),
        vec![
            ResponseTypes::new(vec![CoreResponseType::Code]),
            ResponseTypes::new(vec![CoreResponseType::IdToken]),
            ResponseTypes::new(vec![CoreResponseType::Token, CoreResponseType::IdToken]),
        ],
        vec![CoreSubjectIdentifierType::Pairwise],
        SIGNING_ALG.to_vec(),
        EmptyAdditionalProviderMetadata {},
    )
    .set_token_endpoint(Some(TokenUrl::from_url(
        base_url
            .join(TOKEN_PATH)
            .map_err(|e| anyhow!("Unable to join URL: {}", e))?,
    )))
    .set_userinfo_endpoint(Some(UserInfoUrl::from_url(
        base_url
            .join(USERINFO_PATH)
            .map_err(|e| anyhow!("Unable to join URL: {}", e))?,
    )))
    .set_userinfo_signing_alg_values_supported(Some(SIGNING_ALG.to_vec()))
    .set_scopes_supported(Some(SCOPES.to_vec()))
    .set_claims_supported(Some(vec![
        CoreClaimName::new("sub".to_string()),
        CoreClaimName::new("aud".to_string()),
        CoreClaimName::new("exp".to_string()),
        CoreClaimName::new("iat".to_string()),
        CoreClaimName::new("iss".to_string()),
        CoreClaimName::new("preferred_username".to_string()),
        CoreClaimName::new("picture".to_string()),
    ]))
    .set_registration_endpoint(Some(RegistrationUrl::from_url(
        base_url
            .join(REGISTER_PATH)
            .map_err(|e| anyhow!("Unable to join URL: {}", e))?,
    )))
    .set_token_endpoint_auth_methods_supported(Some(vec![
        CoreClientAuthMethod::ClientSecretBasic,
        CoreClientAuthMethod::ClientSecretPost,
        CoreClientAuthMethod::PrivateKeyJwt,
    ]))
    .set_op_policy_uri(Some(OpPolicyUrl::from_url(
        base_url
            .join(PP_PATH)
            .map_err(|e| anyhow!("Unable to join URL: {}", e))?,
    )))
    .set_op_tos_uri(Some(OpTosUrl::from_url(
        base_url
            .join(TOU_PATH)
            .map_err(|e| anyhow!("Unable to join URL: {}", e))?,
    )));

    Ok(pm)
}

fn build_provider(eth_provider: Url) -> Result<Provider<Http>> {
    match Provider::<Http>::try_from(eth_provider.to_string()) {
        Ok(p) => Ok(p),
        Err(e) => {
            error!("Failed to initialise Eth provider: {}", e);
            Err(e)?
        }
    }
}

async fn resolve_name(eth_provider: Option<Url>, address: H160) -> Result<String, String> {
    let address_string = to_checksum(&address, None);
    let eth_provider = if let Some(p) = eth_provider {
        p
    } else {
        return Err(address_string);
    };
    let provider = if let Ok(p) = build_provider(eth_provider) {
        p
    } else {
        return Err(address_string);
    };
    match provider.lookup_address(address).await {
        Ok(n) => Ok(n),
        Err(e) => {
            error!("Failed to resolve Eth domain: {}", e);
            Err(address_string)
        }
    }
}

async fn resolve_avatar(eth_provider: Option<Url>, ens_name: &str) -> Option<Url> {
    if let Some(provider) = eth_provider {
        if let Ok(p) = build_provider(provider) {
            match p.resolve_avatar(ens_name).await {
                Ok(a) => Some(a),
                Err(e) => {
                    error!("Could not resolve avatar: {}", e);
                    None
                }
            }
        } else {
            None
        }
    } else {
        None
    }
}

async fn resolve_claims(
    eth_provider: Option<Url>,
    address: H160,
    chain_id: u64,
) -> StandardClaims<CoreGenderClaim> {
    let subject_id = SubjectIdentifier::new(format!(
        "eip155:{}:{}",
        chain_id,
        to_checksum(&address, None)
    ));
    let ens_name = resolve_name(eth_provider.clone(), address).await;
    let username = match ens_name.clone() {
        Ok(n) | Err(n) => n,
    };
    let avatar = match ens_name {
        Ok(n) => resolve_avatar(eth_provider.clone(), &n).await,
        Err(_) => None,
    };
    StandardClaims::new(subject_id)
        .set_preferred_username(Some(EndUserUsername::new(username)))
        .set_picture(avatar.map(|a| {
            let mut avatar_localized = LocalizedClaim::new();
            avatar_localized.insert(None, EndUserPictureUrl::new(a.to_string()));
            avatar_localized
        }))
}

#[derive(Serialize, Deserialize)]
pub struct TokenForm {
    pub code: String,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub grant_type: CoreGrantType, // TODO should just be authorization_code apparently?
}

pub async fn token(
    form: TokenForm,
    // From the request's Authorization header
    secret: Option<String>,
    private_key: RsaPrivateKey,
    base_url: Url,
    require_secret: bool,
    eth_provider: Option<Url>,
    db_client: &DBClientType,
) -> Result<CoreTokenResponse, CustomError> {
    let code_entry = if let Some(c) = db_client.get_code(form.code.to_string()).await? {
        c
    } else {
        return Err(CustomError::BadRequestToken(TokenError {
            error: CoreErrorResponseType::InvalidGrant,
            error_description: "Unknown code.".to_string(),
        }));
    };

    let client_id = if let Some(c) = form.client_id.clone() {
        c
    } else {
        code_entry.client_id.clone()
    };

    if let Some(secret) = if let Some(b) = secret {
        Some(b)
    } else {
        form.client_secret.clone()
    } {
        let client_entry = db_client.get_client(client_id.clone()).await?;
        if client_entry.is_none() {
            return Err(CustomError::Unauthorized(
                "Unrecognised client id.".to_string(),
            ));
        }
        if secret != client_entry.unwrap().secret {
            return Err(CustomError::Unauthorized("Bad secret.".to_string()));
        }
    } else if require_secret {
        return Err(CustomError::Unauthorized("Secret required.".to_string()));
    }

    if code_entry.exchange_count > 0 {
        // TODO use Oauth error response
        return Err(CustomError::BadRequestToken(TokenError {
            error: CoreErrorResponseType::InvalidGrant,
            error_description: "Code was previously exchanged.".to_string(),
        }));
    }
    let mut code_entry2 = code_entry.clone();
    code_entry2.exchange_count += 1;
    db_client
        .set_code(form.code.to_string(), code_entry2)
        .await?;
    let access_token = AccessToken::new(form.code);
    let core_id_token = CoreIdTokenClaims::new(
        IssuerUrl::from_url(base_url),
        vec![Audience::new(client_id.clone())],
        Utc::now() + Duration::seconds(60),
        Utc::now(),
        resolve_claims(
            eth_provider,
            code_entry.address,
            code_entry.chain_id.unwrap_or(1),
        )
        .await,
        EmptyAdditionalClaims {},
    )
    .set_nonce(code_entry.nonce)
    .set_auth_time(Some(code_entry.auth_time));

    let pem = private_key
        .to_pkcs1_pem(LineEnding::LF)
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

    let mut response = CoreTokenResponse::new(
        access_token,
        CoreTokenType::Bearer,
        CoreIdTokenFields::new(Some(id_token), EmptyExtraTokenFields {}),
    );
    response.set_expires_in(Some(&time::Duration::from_secs(
        ENTRY_LIFETIME.try_into().unwrap(),
    )));
    Ok(response)
}

#[derive(Deserialize)]
pub struct AuthorizeParams {
    pub client_id: String,
    pub redirect_uri: RedirectUrl,
    pub scope: Scope,
    pub response_type: Option<CoreResponseType>,
    pub state: Option<String>,
    pub nonce: Option<Nonce>,
    pub prompt: Option<CoreAuthPrompt>,
    pub request_uri: Option<RequestUrl>,
    pub request: Option<String>,
}

pub async fn authorize(
    params: AuthorizeParams,
    db_client: &DBClientType,
) -> Result<(String, Box<Cookie<'_>>), CustomError> {
    let client_entry = db_client
        .get_client(params.client_id.clone())
        .await
        .map_err(|e| anyhow!("Failed to get kv: {}", e))?;
    if client_entry.is_none() {
        return Err(CustomError::Unauthorized(
            "Unrecognised client id.".to_string(),
        ));
    }

    let nonce: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(16)
        .map(char::from)
        .collect();

    let mut r_u = params.redirect_uri.clone().url().clone();
    r_u.set_query(None);
    let mut r_us: Vec<Url> = client_entry
        .unwrap()
        .metadata
        .redirect_uris()
        .clone()
        .iter_mut()
        .map(|u| u.url().clone())
        .collect();
    r_us.iter_mut().for_each(|u| u.set_query(None));
    if !r_us.contains(&r_u) {
        return Err(CustomError::Redirect(
            "/error?message=unregistered_redirect_uri".to_string(),
        ));
    }

    let state = if let Some(s) = params.state.clone() {
        s
    } else if params.request_uri.is_some() {
        let mut url = params.redirect_uri.url().clone();
        url.query_pairs_mut().append_pair(
            "error",
            CoreAuthErrorResponseType::RequestUriNotSupported.as_ref(),
        );
        return Err(CustomError::Redirect(url.to_string()));
    } else if params.request.is_some() {
        let mut url = params.redirect_uri.url().clone();
        url.query_pairs_mut().append_pair(
            "error",
            CoreAuthErrorResponseType::RequestNotSupported.as_ref(),
        );
        return Err(CustomError::Redirect(url.to_string()));
    } else {
        let mut url = params.redirect_uri.url().clone();
        url.query_pairs_mut()
            .append_pair("error", CoreAuthErrorResponseType::InvalidRequest.as_ref());
        url.query_pairs_mut()
            .append_pair("error_description", "Missing state");
        return Err(CustomError::Redirect(url.to_string()));
    };

    if let Some(CoreAuthPrompt::None) = params.prompt {
        let mut url = params.redirect_uri.url().clone();
        url.query_pairs_mut().append_pair("state", &state);
        url.query_pairs_mut().append_pair(
            "error",
            CoreAuthErrorResponseType::InteractionRequired.as_ref(),
        );
        return Err(CustomError::Redirect(url.to_string()));
    }

    if params.response_type.is_none() {
        let mut url = params.redirect_uri.url().clone();
        url.query_pairs_mut().append_pair("state", &state);
        url.query_pairs_mut()
            .append_pair("error", CoreAuthErrorResponseType::InvalidRequest.as_ref());
        url.query_pairs_mut()
            .append_pair("error_description", "Missing response_type");
        return Err(CustomError::Redirect(url.to_string()));
    }
    let _response_type = params.response_type.as_ref().unwrap();

    for scope in params.scope.as_str().trim().split(' ') {
        if !SCOPES.contains(&Scope::new(scope.to_string())) {
            return Err(anyhow!("Scope not supported: {}", scope).into());
        }
    }

    let session_id = Uuid::new_v4();
    let session_secret: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(16)
        .map(char::from)
        .collect();
    db_client
        .set_session(
            session_id.to_string(),
            SessionEntry {
                siwe_nonce: nonce.clone(),
                oidc_nonce: params.nonce.clone(),
                secret: session_secret.clone(),
                signin_count: 0,
            },
        )
        .await?;
    let session_cookie = Cookie::build(SESSION_COOKIE_NAME, session_id.to_string())
        .same_site(SameSite::Strict)
        .http_only(true)
        .max_age(cookie::time::Duration::seconds(
            SESSION_LIFETIME.try_into().unwrap(),
        ))
        .finish();

    let domain = params.redirect_uri.url().host().unwrap();
    let oidc_nonce_param = if let Some(n) = &params.nonce {
        format!("&oidc_nonce={}", n.secret())
    } else {
        "".to_string()
    };
    Ok((
        format!(
            "/?nonce={}&domain={}&redirect_uri={}&state={}&client_id={}{}",
            nonce, domain, *params.redirect_uri, state, params.client_id, oidc_nonce_param
        ),
        Box::new(session_cookie),
    ))
}

#[derive(Serialize, Deserialize)]
pub struct SiweCookie {
    message: Web3ModalMessage,
    signature: String,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Web3ModalMessage {
    pub domain: String,
    pub address: H160,
    pub statement: String,
    pub uri: String,
    pub version: String,
    pub chain_id: u64,
    pub nonce: String,
    pub issued_at: String,
    pub expiration_time: Option<String>,
    pub not_before: Option<String>,
    pub request_id: Option<String>,
    pub resources: Vec<UriString>,
}

impl Web3ModalMessage {
    fn to_eip4361_message(&self) -> Result<Message> {
        Ok(Message {
            domain: self.domain.clone().try_into()?,
            address: self.address.0,
            statement: Some(self.statement.to_string()),
            uri: UriString::from_str(&self.uri)?,
            version: Version::from_str(&self.version)?,
            chain_id: self.chain_id,
            nonce: self.nonce.to_string(),
            issued_at: TimeStamp::from_str(&self.issued_at)?,
            expiration_time: match &self.expiration_time {
                Some(t) => Some(TimeStamp::from_str(t)?),
                None => None,
            },
            not_before: match &self.not_before {
                Some(t) => Some(TimeStamp::from_str(t)?),
                None => None,
            },
            request_id: self.request_id.clone(),
            resources: self.resources.clone(),
        })
    }
}

#[derive(Deserialize)]
pub struct SignInParams {
    pub redirect_uri: RedirectUrl,
    pub state: String,
    pub oidc_nonce: Option<Nonce>,
    pub client_id: String,
}

pub async fn sign_in(
    base_url: &Url,
    params: SignInParams,
    // cookies_header: String,
    cookies: headers::Cookie,
    db_client: &DBClientType,
) -> Result<Url, CustomError> {
    // TODO redirect on session errors
    let session_id = if let Some(c) = cookies.get(SESSION_COOKIE_NAME) {
        c
    } else {
        return Err(CustomError::BadRequest(
            "Session cookie not found".to_string(),
        ));
    };
    let session_entry = if let Some(e) = db_client.get_session(session_id.to_string()).await? {
        e
    } else {
        return Err(CustomError::BadRequest("Session not found".to_string()));
    };
    if session_entry.signin_count > 0 {
        return Err(CustomError::BadRequest(
            "Session has already logged in".to_string(),
        ));
    }

    let siwe_cookie: SiweCookie = match cookies.get(SIWE_COOKIE_KEY) {
        Some(c) => serde_json::from_str(
            &decode(c).map_err(|e| anyhow!("Could not decode siwe cookie: {}", e))?,
        )
        .map_err(|e| anyhow!("Could not deserialize siwe cookie: {}", e))?,
        None => {
            return Err(anyhow!("No `siwe` cookie").into());
        }
    };

    let signature = match <[u8; 65]>::from_hex(
        siwe_cookie
            .signature
            .chars()
            .skip(2)
            .take(130)
            .collect::<String>(),
    ) {
        Ok(s) => s,
        Err(e) => {
            return Err(CustomError::BadRequest(format!("Bad signature: {}", e)));
        }
    };

    let message = siwe_cookie
        .message
        .to_eip4361_message()
        .map_err(|e| anyhow!("Failed to serialise message: {}", e))?;
    info!("{}", message);

    let domain = if let Some(d) = base_url.domain() {
        match d.try_into() {
            Ok(dd) => Some(dd),
            Err(e) => {
                error!("Failed to translate domain into authority: {}", e);
                None
            }
        }
    } else {
        None
    };
    message
        .verify(
            &signature,
            &VerificationOpts {
                domain,
                nonce: Some(session_entry.siwe_nonce.clone()),
                timestamp: None,
            },
        )
        .await
        .map_err(|e| anyhow!("Failed message verification: {}", e))?;

    let domain = params.redirect_uri.url();
    if let Some(r) = siwe_cookie.message.resources.first() {
        if *domain != Url::from_str(r.as_ref()).unwrap() {
            return Err(anyhow!("Conflicting domains in message and redirect").into());
        }
    } else {
        return Err(anyhow!("Missing resource in SIWE message").into());
    }

    let code_entry = CodeEntry {
        address: siwe_cookie.message.address,
        nonce: params.oidc_nonce.clone(),
        exchange_count: 0,
        client_id: params.client_id.clone(),
        auth_time: Utc::now(),
        chain_id: Some(siwe_cookie.message.chain_id),
    };

    let mut new_session_entry = session_entry.clone();
    new_session_entry.signin_count += 1;
    db_client
        .set_session(session_id.to_string(), new_session_entry)
        .await?;

    let code = Uuid::new_v4();
    db_client.set_code(code.to_string(), code_entry).await?;

    let mut url = params.redirect_uri.url().clone();
    url.query_pairs_mut().append_pair("code", &code.to_string());
    url.query_pairs_mut().append_pair("state", &params.state);
    Ok(url)
}

#[derive(Debug, Serialize)]
pub struct RegisterError {
    error: CoreRegisterErrorResponseType,
}

pub async fn register(
    payload: CoreClientMetadata,
    base_url: Url,
    db_client: &DBClientType,
) -> Result<CoreClientRegistrationResponse, CustomError> {
    let id = Uuid::new_v4();
    let secret: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(16)
        .map(char::from)
        .collect();

    let redirect_uris = payload.redirect_uris().to_vec();
    for uri in redirect_uris.iter() {
        if uri.url().fragment().is_some() {
            return Err(CustomError::BadRequestRegister(RegisterError {
                error: CoreRegisterErrorResponseType::InvalidRedirectUri,
            }));
        }
    }

    let access_token = RegistrationAccessToken::new(
        thread_rng()
            .sample_iter(&Alphanumeric)
            .take(11)
            .map(char::from)
            .collect(),
    );

    let entry = ClientEntry {
        secret: secret.clone(),
        metadata: payload,
        access_token: Some(access_token.clone()),
    };
    db_client.set_client(id.to_string(), entry).await?;

    Ok(CoreClientRegistrationResponse::new(
        ClientId::new(id.to_string()),
        redirect_uris,
        EmptyAdditionalClientMetadata::default(),
        EmptyAdditionalClientRegistrationResponse::default(),
    )
    .set_client_secret(Some(ClientSecret::new(secret)))
    .set_registration_client_uri(Some(ClientConfigUrl::from_url(
        base_url
            .join(&format!("{}/{}", CLIENT_PATH, id))
            .map_err(|e| anyhow!("Unable to join URL: {}", e))?,
    )))
    .set_registration_access_token(Some(access_token)))
}

async fn client_access(
    client_id: String,
    bearer: Option<Bearer>,
    db_client: &DBClientType,
) -> Result<ClientEntry, CustomError> {
    let access_token = if let Some(b) = bearer {
        b.token().to_string()
    } else {
        return Err(CustomError::BadRequest("Missing access token.".to_string()));
    };
    let client_entry = db_client
        .get_client(client_id)
        .await?
        .ok_or(CustomError::NotFound)?;
    let stored_access_token = client_entry.access_token.clone();
    if stored_access_token.is_none() || *stored_access_token.unwrap().secret() != access_token {
        return Err(CustomError::Unauthorized("Bad access token.".to_string()));
    }
    Ok(client_entry)
}

pub async fn clientinfo(
    client_id: String,
    db_client: &DBClientType,
) -> Result<CoreClientMetadata, CustomError> {
    Ok(db_client
        .get_client(client_id)
        .await?
        .ok_or(CustomError::NotFound)?
        .metadata)
}

pub async fn client_delete(
    client_id: String,
    bearer: Option<Bearer>,
    db_client: &DBClientType,
) -> Result<(), CustomError> {
    client_access(client_id.clone(), bearer, db_client).await?;
    Ok(db_client.delete_client(client_id).await?)
}

pub async fn client_update(
    client_id: String,
    payload: CoreClientMetadata,
    bearer: Option<Bearer>,
    db_client: &DBClientType,
) -> Result<(), CustomError> {
    let mut client_entry = client_access(client_id.clone(), bearer, db_client).await?;
    client_entry.metadata = payload;
    Ok(db_client.set_client(client_id, client_entry).await?)
}

#[derive(Deserialize)]
pub struct UserInfoPayload {
    pub access_token: Option<String>,
}

pub enum UserInfoResponse {
    Json(CoreUserInfoClaims),
    Jwt(CoreUserInfoJsonWebToken),
}

pub async fn userinfo(
    base_url: Url,
    eth_provider: Option<Url>,
    private_key: RsaPrivateKey,
    bearer: Option<Bearer>,
    payload: UserInfoPayload,
    db_client: &DBClientType,
) -> Result<UserInfoResponse, CustomError> {
    let code = if let Some(b) = bearer {
        b.token().to_string()
    } else if let Some(c) = payload.access_token {
        c
    } else {
        return Err(CustomError::BadRequest("Missing access token.".to_string()));
    };
    let code_entry = if let Some(c) = db_client.get_code(code).await? {
        c
    } else {
        return Err(CustomError::BadRequest("Unknown code.".to_string()));
    };

    let client_entry = if let Some(c) = db_client.get_client(code_entry.client_id.clone()).await? {
        c
    } else {
        return Err(CustomError::BadRequest("Unknown client.".to_string()));
    };

    let response = CoreUserInfoClaims::new(
        resolve_claims(
            eth_provider,
            code_entry.address,
            code_entry.chain_id.unwrap_or(1),
        )
        .await,
        EmptyAdditionalClaims::default(),
    )
    .set_issuer(Some(IssuerUrl::from_url(base_url.clone())))
    .set_audiences(Some(vec![Audience::new(code_entry.client_id)]));
    match client_entry.metadata.userinfo_signed_response_alg() {
        None => Ok(UserInfoResponse::Json(response)),
        Some(alg) => {
            let signing_key = jwk(private_key)?;
            Ok(UserInfoResponse::Jwt(
                CoreUserInfoJsonWebToken::new(response, &signing_key, alg.clone())
                    .map_err(|_| anyhow!("Error signing response."))?,
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::config::Config;

    use super::*;
    use ethers_signers::{LocalWallet, Signer};
    use headers::{HeaderMap, HeaderMapExt, HeaderValue};
    use rand::rngs::OsRng;
    use test_log::test;

    async fn default_config() -> (Config, RedisClient) {
        let config = Config::default();
        let db_client = RedisClient::new(&config.redis_url).await.unwrap();
        db_client
            .set_client(
                "client".into(),
                ClientEntry {
                    secret: "secret".into(),
                    metadata: CoreClientMetadata::new(
                        vec![RedirectUrl::new("https://example.com".into()).unwrap()],
                        EmptyAdditionalClientMetadata {},
                    ),
                    access_token: None,
                },
            )
            .await
            .unwrap();
        (config, db_client)
    }

    #[test(tokio::test)]
    async fn test_claims() {
        let res = resolve_claims(
            Some("https://cloudflare-eth.com".try_into().unwrap()),
            <[u8; 20]>::from_hex("d8da6bf26964af9d7eed9e03e53415d37aa96045")
                .unwrap()
                .into(),
            1,
        )
        .await;
        assert_eq!(
            res.preferred_username().map(|u| u.to_string()),
            Some("vitalik.eth".to_string())
        );
        assert_eq!(
            res.picture().map(|u| u.get(None).unwrap().as_str()),
            Some("https://ipfs.io/ipfs/QmSP4nq9fnN9dAiCj42ug9Wa79rqmQerZXZch82VqpiH7U/image.gif")
        );
    }

    #[derive(Deserialize)]
    struct AuthorizeQueryParams {
        nonce: String,
    }

    #[derive(Deserialize)]
    struct SignInQueryParams {
        code: String,
    }

    #[tokio::test]
    async fn e2e_flow() {
        let (_config, db_client) = default_config().await;
        let wallet = "dcf2cbdd171a21c480aa7f53d77f31bb102282b3ff099c78e3118b37348c72f7"
            .parse::<LocalWallet>()
            .unwrap();

        let base_url = Url::parse("https://example.com").unwrap();
        let params = AuthorizeParams {
            client_id: "client".into(),
            redirect_uri: RedirectUrl::from_url(base_url.clone()),
            scope: Scope::new("openid".to_string()),
            response_type: Some(CoreResponseType::IdToken),
            state: Some("state".into()),
            nonce: None,
            prompt: None,
            request_uri: None,
            request: None,
        };
        let (redirect_url, cookie) = authorize(params, &db_client).await.unwrap();
        let authorize_params: AuthorizeQueryParams =
            serde_urlencoded::from_str(redirect_url.split("/?").collect::<Vec<&str>>()[1]).unwrap();
        let params: SignInParams = serde_urlencoded::from_str(&redirect_url).unwrap();
        let message = Web3ModalMessage {
            domain: "example.com".into(),
            address: wallet.address(),
            statement: "statement".to_string(),
            uri: base_url.to_string(),
            version: "1".into(),
            chain_id: 1,
            nonce: authorize_params.nonce,
            issued_at: "2023-04-17T11:01:24.862Z".into(),
            expiration_time: None,
            not_before: None,
            request_id: None,
            resources: vec!["https://example.com".try_into().unwrap()],
        };
        let signature = wallet
            .sign_message(message.to_eip4361_message().unwrap().to_string())
            .await
            .unwrap();
        let signature = format!("0x{signature}");
        let siwe_cookie = serde_json::to_string(&SiweCookie { message, signature }).unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(
            "cookie",
            HeaderValue::from_str(&format!("{cookie}; {SIWE_COOKIE_KEY}={siwe_cookie}")).unwrap(),
        );
        let cookie = headers.typed_get::<headers::Cookie>().unwrap();
        let redirect_url = sign_in(&base_url, params, cookie, &db_client)
            .await
            .unwrap();
        let signin_params: SignInQueryParams =
            serde_urlencoded::from_str(redirect_url.query().unwrap()).unwrap();
        let _ = userinfo(
            base_url,
            None,
            RsaPrivateKey::new(&mut OsRng, 1024).unwrap(),
            None,
            UserInfoPayload {
                access_token: Some(signin_params.code),
            },
            &db_client,
        )
        .await
        .unwrap();
    }
}
