use anyhow::anyhow;
use console_error_panic_hook;
use headers::{
    self,
    authorization::{Bearer, Credentials},
    Authorization, Header, HeaderValue,
};
use rand::{distributions::Alphanumeric, Rng};
use rsa::{pkcs1::FromRsaPrivateKey, RsaPrivateKey};
use tracing_wasm;
use worker::*;

use super::db::CFClient;
use super::oidc::{self, CustomError, TokenForm};

const BASE_URL_KEY: &str = "BASE_URL";
const RSA_PEM_KEY: &str = "RSA_PEM";

use wee_alloc;
#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

impl From<CustomError> for Result<Response> {
    fn from(error: CustomError) -> Self {
        match error {
            CustomError::BadRequest(_) => Response::error(&error.to_string(), 400),
            CustomError::BadRequestToken(e) => Response::from_json(&e).map(|r| r.with_status(400)),
            CustomError::Unauthorized(_) => Response::error(&error.to_string(), 401),
            CustomError::Redirect(uri) => Response::redirect(uri.parse().unwrap()),
            CustomError::Other(_) => Response::error(&error.to_string(), 500),
        }
    }
}

#[event(fetch)]
pub async fn main(req: Request, env: Env) -> Result<Response> {
    console_error_panic_hook::set_once();
    tracing_wasm::set_as_global_default();

    let userinfo = |req: Request, ctx: RouteContext<()>| async move {
        let bearer = if let Some(b) = req
            .headers()
            .get(Authorization::<Bearer>::name().as_str())?
            .and_then(|b| HeaderValue::from_str(b.as_ref()).ok())
            .as_ref()
            .and_then(|b| Bearer::decode(b))
        {
            b
        } else {
            return Response::error("Missing Bearer", 400);
        };
        let db_client = CFClient { ctx };
        match oidc::userinfo(bearer, &db_client).await {
            Ok(r) => Ok(Response::from_json(&r)?),
            Err(e) => e.into(),
        }
    };

    let router = Router::new();
    router
        .get_async(oidc::METADATA_PATH, |_req, ctx| async move {
            match oidc::metadata(ctx.var(BASE_URL_KEY)?.to_string().parse().unwrap()) {
                Ok(m) => Response::from_json(&m),
                Err(e) => e.into(),
            }
        })
        .get_async(oidc::JWK_PATH, |_req, ctx| async move {
            let private_key = RsaPrivateKey::from_pkcs1_pem(&ctx.secret(RSA_PEM_KEY)?.to_string())
                .map_err(|e| anyhow!("Failed to load private key: {}", e))
                .unwrap();
            match oidc::jwks(private_key) {
                Ok(m) => Response::from_json(&m),
                Err(e) => e.into(),
            }
        })
        .post_async(oidc::JWK_PATH, |mut req, ctx| async move {
            let form_data = req.form_data().await?;
            let code = if let Some(FormEntry::Field(c)) = form_data.get("code") {
                c
            } else {
                return Response::error("Missing code", 400);
            };
            let client_id = match form_data.get("client_id") {
                Some(FormEntry::Field(c)) => Some(c),
                None => None,
                _ => return Response::error("Client ID not a field", 400),
            };
            let client_secret = match form_data.get("client_secret") {
                Some(FormEntry::Field(c)) => Some(c),
                None => None,
                _ => return Response::error("Client secret not a field", 400),
            };
            let grant_type = if let Some(FormEntry::Field(c)) = form_data.get("code") {
                if let Ok(cc) = serde_json::from_str(&format!("\"{}\"", c)) {
                    cc
                } else {
                    return Response::error("Invalid grant type", 400);
                }
            } else {
                return Response::error("Missing grant type", 400);
            };
            let bearer = req
                .headers()
                .get(Authorization::<Bearer>::name().as_str())?
                .and_then(|b| HeaderValue::from_str(b.as_ref()).ok())
                .as_ref()
                .and_then(|b| Bearer::decode(b));

            let private_key = RsaPrivateKey::from_pkcs1_pem(&ctx.secret(RSA_PEM_KEY)?.to_string())
                .map_err(|e| anyhow!("Failed to load private key: {}", e))
                .unwrap();
            let base_url = ctx.var(BASE_URL_KEY)?.to_string().parse().unwrap();
            let db_client = CFClient { ctx };
            let token_response = oidc::token(
                TokenForm {
                    code,
                    client_id,
                    client_secret,
                    grant_type,
                },
                bearer,
                private_key,
                base_url,
                false,
                &db_client,
            )
            .await;
            match token_response {
                Ok(m) => Response::from_json(&m),
                Err(e) => e.into(),
            }
        })
        // TODO add browser session
        .get_async(oidc::AUTHORIZE_PATH, |mut req, ctx| async move {
            let params = req.json().await?;
            let nonce = rand::thread_rng()
                .sample_iter(&Alphanumeric)
                .take(16)
                .map(char::from)
                .collect();
            let db_client = CFClient { ctx };
            match oidc::authorize(params, nonce, &db_client).await {
                Ok(url) => Response::redirect(url.parse().unwrap()),
                Err(e) => e.into(),
            }
        })
        .post_async(oidc::REGISTER_PATH, |mut req, ctx| async move {
            let payload = req.json().await?;
            let db_client = CFClient { ctx };
            match oidc::register(payload, &db_client).await {
                Ok(r) => Ok(Response::from_json(&r)?.with_status(201)),
                Err(e) => e.into(),
            }
        })
        .post_async(oidc::USERINFO_PATH, userinfo)
        .get_async(oidc::USERINFO_PATH, userinfo)
        .get_async(oidc::SIGNIN_PATH, |mut req, ctx| async move {
            let params = req.json().await?;
            let cookies = req
                .headers()
                .get(headers::Cookie::name().as_str())?
                .and_then(|c| HeaderValue::from_str(&c).ok())
                .and_then(|c| headers::Cookie::decode(&mut [c].iter()).ok());
            if cookies.is_none() {
                return Response::error("Missing cookies", 400);
            }
            let db_client = CFClient { ctx };
            match oidc::sign_in(params, None, cookies.unwrap(), &db_client).await {
                Ok(url) => Response::redirect(url),
                Err(e) => e.into(),
            }
        })
        .run(req, env)
        .await
}
