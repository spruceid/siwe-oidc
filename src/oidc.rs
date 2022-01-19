use anyhow::{anyhow, Result};
use chrono::{Duration, Utc};
use headers::{self, authorization::Bearer};
use hex::FromHex;
use iri_string::types::UriString;
use openidconnect::{
    core::{
        CoreAuthErrorResponseType, CoreAuthPrompt, CoreClaimName, CoreClientAuthMethod,
        CoreClientMetadata, CoreClientRegistrationResponse, CoreErrorResponseType, CoreGrantType,
        CoreIdToken, CoreIdTokenClaims, CoreIdTokenFields, CoreJsonWebKeySet,
        CoreJwsSigningAlgorithm, CoreProviderMetadata, CoreRegisterErrorResponseType,
        CoreResponseType, CoreRsaPrivateSigningKey, CoreSubjectIdentifierType, CoreTokenResponse,
        CoreTokenType, CoreUserInfoClaims, CoreUserInfoJsonWebToken,
    },
    registration::{EmptyAdditionalClientMetadata, EmptyAdditionalClientRegistrationResponse},
    url::Url,
    AccessToken, Audience, AuthUrl, ClientId, ClientSecret, EmptyAdditionalClaims,
    EmptyAdditionalProviderMetadata, EmptyExtraTokenFields, IssuerUrl, JsonWebKeyId,
    JsonWebKeySetUrl, Nonce, PrivateSigningKey, RedirectUrl, RegistrationUrl, RequestUrl,
    ResponseTypes, Scope, StandardClaims, SubjectIdentifier, TokenUrl, UserInfoUrl,
};
use rsa::{pkcs1::ToRsaPrivateKey, RsaPrivateKey};
use serde::{Deserialize, Serialize};
use siwe::eip4361::{Message, Version};
use std::{str::FromStr, time};
use thiserror::Error;
use tracing::info;
use urlencoding::decode;
use uuid::Uuid;

#[cfg(target_arch = "wasm32")]
use super::db::*;
#[cfg(not(target_arch = "wasm32"))]
use siwe_oidc::db::*;

const SIGNING_ALG: [CoreJwsSigningAlgorithm; 1] = [CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256];
const KID: &str = "key1";
pub const METADATA_PATH: &str = "/.well-known/openid-configuration";
pub const JWK_PATH: &str = "/jwk";
pub const TOKEN_PATH: &str = "/token";
pub const AUTHORIZE_PATH: &str = "/authorize";
pub const REGISTER_PATH: &str = "/register";
pub const USERINFO_PATH: &str = "/userinfo";
pub const SIGNIN_PATH: &str = "/sign_in";
pub const SIWE_COOKIE_KEY: &str = "siwe";

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
    #[error("{0:?}")]
    Redirect(String),
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

fn jwk(private_key: RsaPrivateKey) -> Result<CoreRsaPrivateSigningKey> {
    let pem = private_key
        .to_pkcs1_pem()
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
        base_url
            .join(REGISTER_PATH)
            .map_err(|e| anyhow!("Unable to join URL: {}", e))?,
    )))
    .set_token_endpoint_auth_methods_supported(Some(vec![
        CoreClientAuthMethod::ClientSecretBasic,
        CoreClientAuthMethod::ClientSecretPost,
        CoreClientAuthMethod::PrivateKeyJwt,
    ]));

    Ok(pm)
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
        StandardClaims::new(SubjectIdentifier::new(code_entry.address)),
        EmptyAdditionalClaims {},
    )
    .set_nonce(code_entry.nonce)
    .set_auth_time(Some(code_entry.auth_time));

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
    nonce: String,
    db_client: &DBClientType,
) -> Result<String, CustomError> {
    let client_entry = db_client
        .get_client(params.client_id.clone())
        .await
        .map_err(|e| anyhow!("Failed to get kv: {}", e))?;
    if client_entry.is_none() {
        return Err(CustomError::Unauthorized(
            "Unrecognised client id.".to_string(),
        ));
    }

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
            "/error?message=unregistered_request_uri".to_string(),
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

    if params.scope != Scope::new("openid".to_string()) {
        return Err(anyhow!("Scope not supported").into());
    }

    let domain = params.redirect_uri.url().host().unwrap();
    let oidc_nonce_param = if let Some(n) = &params.nonce {
        format!("&oidc_nonce={}", n.secret())
    } else {
        "".to_string()
    };
    Ok(format!(
        "/?nonce={}&domain={}&redirect_uri={}&state={}&client_id={}{}",
        nonce, domain, *params.redirect_uri, state, params.client_id, oidc_nonce_param
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
    fn to_eip4361_message(&self) -> Result<Message> {
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
            uri: UriString::from_str(&self.uri)?,
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

#[derive(Deserialize)]
pub struct SignInParams {
    pub redirect_uri: RedirectUrl,
    pub state: String,
    pub oidc_nonce: Option<Nonce>,
    pub client_id: String,
}

pub async fn sign_in(
    params: SignInParams,
    expected_nonce: Option<String>,
    cookies: headers::Cookie,
    db_client: &DBClientType,
) -> Result<Url, CustomError> {
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
    message
        .verify(signature)
        .map_err(|e| anyhow!("Failed signature validation: {}", e))?;

    let domain = params.redirect_uri.url().host().unwrap();
    if domain.to_string() != siwe_cookie.message.domain {
        return Err(anyhow!("Conflicting domains in message and redirect").into());
    }
    if expected_nonce.is_some() && expected_nonce.unwrap() != siwe_cookie.message.nonce {
        return Err(anyhow!("Conflicting nonces in message and session").into());
    }

    let code_entry = CodeEntry {
        address: siwe_cookie.message.address,
        nonce: params.oidc_nonce.clone(),
        exchange_count: 0,
        client_id: params.client_id.clone(),
        auth_time: Utc::now(),
    };

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
    db_client: &DBClientType,
) -> Result<CoreClientRegistrationResponse, CustomError> {
    let id = Uuid::new_v4();
    let secret = Uuid::new_v4();

    let redirect_uris = payload.redirect_uris().to_vec();
    for uri in redirect_uris.iter() {
        if uri.url().fragment().is_some() {
            return Err(CustomError::BadRequestRegister(RegisterError {
                error: CoreRegisterErrorResponseType::InvalidRedirectUri,
            }));
        }
    }

    let entry = ClientEntry {
        secret: secret.to_string(),
        metadata: payload,
    };
    db_client.set_client(id.to_string(), entry).await?;

    Ok(CoreClientRegistrationResponse::new(
        ClientId::new(id.to_string()),
        redirect_uris,
        EmptyAdditionalClientMetadata::default(),
        EmptyAdditionalClientRegistrationResponse::default(),
    )
    .set_client_secret(Some(ClientSecret::new(secret.to_string()))))
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
        StandardClaims::new(SubjectIdentifier::new(code_entry.address)),
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
