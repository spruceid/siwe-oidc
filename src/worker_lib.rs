use anyhow::anyhow;
use headers::{
    self,
    authorization::{Basic, Bearer, Credentials},
    Authorization, ContentType, Header, HeaderValue,
};
use rsa::{pkcs1::DecodeRsaPrivateKey, RsaPrivateKey};
use worker::*;

use super::db::CFClient;
use super::oidc::{self, CustomError, TokenForm, UserInfoPayload};

const BASE_URL_KEY: &str = "BASE_URL";
const ETH_PROVIDER_KEY: &str = "ETH_PROVIDER";
const RSA_PEM_KEY: &str = "RSA_PEM";

// https://github.com/cloudflare/workers-rs/issues/64
// #[global_allocator]
// static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

/// To be used in conjunction of Request::json
macro_rules! json_bad_request {
    ($expression:expr) => {
        match $expression {
            Err(Error::SerdeJsonError(e)) => return Response::error(&e.to_string(), 400),
            r => r,
        }
    };
}

impl From<CustomError> for Result<Response> {
    fn from(error: CustomError) -> Self {
        match error {
            CustomError::BadRequest(_) => Response::error(error.to_string(), 400),
            CustomError::BadRequestRegister(e) => {
                Response::from_json(&e).map(|r| r.with_status(400))
            }
            CustomError::BadRequestToken(e) => Response::from_json(&e).map(|r| r.with_status(400)),
            CustomError::Unauthorized(_) => Response::error(error.to_string(), 401),
            CustomError::NotFound => Response::error(error.to_string(), 404),
            CustomError::Redirect(uri) => Response::redirect(uri.parse().unwrap()),
            CustomError::Other(_) => Response::error(error.to_string(), 500),
        }
    }
}

fn get_cors() -> Cors {
    Cors::new()
        .with_origins(vec!["*".to_string()])
        .with_allowed_headers(vec!["authorization".to_string()])
}

pub async fn main(req: Request, env: Env) -> Result<Response> {
    console_error_panic_hook::set_once();
    // tracing_subscriber::fmt::init();
    // console_log::init_with_level(log::Level::Info).expect("error initializing log");

    let userinfo = |mut req: Request, ctx: RouteContext<()>| async move {
        let bearer = req
            .headers()
            .get(Authorization::<Bearer>::name().as_str())?
            .and_then(|b| HeaderValue::from_str(b.as_ref()).ok())
            .as_ref()
            .and_then(Bearer::decode);
        let payload = if bearer.is_none() {
            match req.form_data().await {
                Ok(f) => {
                    let access_token = if let Some(FormEntry::Field(a)) = f.get("access_token") {
                        Some(a)
                    } else {
                        return Response::error("Missing code", 400);
                    };
                    UserInfoPayload { access_token }
                }
                Err(_) => return Response::error("Bad request", 400),
            }
        } else {
            UserInfoPayload { access_token: None }
        };
        let base_url = ctx.var(BASE_URL_KEY)?.to_string().parse().unwrap();
        let eth_provider = ctx
            .var(ETH_PROVIDER_KEY)
            .map(|p| p.to_string().parse().unwrap())
            .ok();
        let private_key = RsaPrivateKey::from_pkcs1_pem(&ctx.secret(RSA_PEM_KEY)?.to_string())
            .map_err(|e| anyhow!("Failed to load private key: {}", e))
            .unwrap();
        let url = req.url()?;
        let db_client = CFClient { ctx, url };
        match oidc::userinfo(
            base_url,
            eth_provider,
            private_key,
            bearer,
            payload,
            &db_client,
        )
        .await
        {
            Ok(oidc::UserInfoResponse::Json(r)) => Ok(Response::from_json(&r)?),
            Ok(oidc::UserInfoResponse::Jwt(r)) => {
                let mut headers = Headers::new();
                headers.append(ContentType::name().as_ref(), "application/jwt")?;
                Ok(Response::from_bytes(
                    serde_json::to_string(&r)
                        .unwrap()
                        .replace('"', "")
                        .as_bytes()
                        .to_vec(),
                )?
                .with_headers(headers))
            }
            Err(e) => e.into(),
        }
        .and_then(|r| r.with_cors(&get_cors()))
    };

    let router = Router::new();
    router
        .get_async(oidc::METADATA_PATH, |_req, ctx| async move {
            match oidc::metadata(ctx.var(BASE_URL_KEY)?.to_string().parse().unwrap()) {
                Ok(m) => Response::from_json(&m),
                Err(e) => e.into(),
            }
            .and_then(|r| r.with_cors(&get_cors()))
        })
        .get_async(oidc::JWK_PATH, |_req, ctx| async move {
            let private_key = RsaPrivateKey::from_pkcs1_pem(&ctx.secret(RSA_PEM_KEY)?.to_string())
                .map_err(|e| anyhow!("Failed to load private key: {}", e))
                .unwrap();
            match oidc::jwks(private_key) {
                Ok(m) => Response::from_json(&m),
                Err(e) => e.into(),
            }
            .and_then(|r| r.with_cors(&get_cors()))
        })
        .options_async(oidc::TOKEN_PATH, |mut _req, _ctx| async move {
            Response::empty()?.with_cors(&get_cors())
        })
        .post_async(oidc::TOKEN_PATH, |mut req, ctx| async move {
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
            let secret = req
                .headers()
                .get(Authorization::<Bearer>::name().as_str())?
                .and_then(|b| HeaderValue::from_str(b.as_ref()).ok())
                .as_ref()
                .and_then(|b| {
                    if b.to_str().unwrap().starts_with("Bearer") {
                        Bearer::decode(b).map(|bb| bb.token().to_string())
                    } else {
                        Basic::decode(b).map(|bb| bb.password().to_string())
                    }
                });
            let private_key = RsaPrivateKey::from_pkcs1_pem(&ctx.secret(RSA_PEM_KEY)?.to_string())
                .map_err(|e| anyhow!("Failed to load private key: {}", e))
                .unwrap();
            let base_url = ctx.var(BASE_URL_KEY)?.to_string().parse().unwrap();
            let url = req.url()?;
            let eth_provider = ctx
                .var(ETH_PROVIDER_KEY)
                .map(|p| p.to_string().parse().unwrap())
                .ok();
            let db_client = CFClient { ctx, url };
            let token_response = oidc::token(
                TokenForm {
                    code,
                    client_id,
                    client_secret,
                    grant_type,
                },
                secret,
                private_key,
                base_url,
                false,
                eth_provider,
                &db_client,
            )
            .await;
            match token_response {
                Ok(m) => Response::from_json(&m),
                Err(e) => e.into(),
            }
            .and_then(|r| r.with_cors(&get_cors()))
        })
        .get_async(oidc::AUTHORIZE_PATH, |req, ctx| async move {
            let base_url: Url = ctx.var(BASE_URL_KEY)?.to_string().parse().unwrap();
            let url = req.url()?;
            let query = url.query().unwrap_or_default();
            let params = match serde_urlencoded::from_str(query) {
                Ok(p) => p,
                Err(_) => return CustomError::BadRequest("Bad query params".to_string()).into(),
            };
            let url = req.url()?;
            let db_client = CFClient { ctx, url };
            match oidc::authorize(params, &db_client).await {
                Ok((url, session_cookie)) => {
                    Response::redirect(base_url.join(&url).unwrap()).map(|r| {
                        let mut headers = r.headers().clone();
                        headers
                            .set("set-cookie", &session_cookie.to_string())
                            .unwrap();
                        r.with_headers(headers)
                    })
                }
                Err(e) => match e {
                    CustomError::Redirect(url) => {
                        CustomError::Redirect(base_url.join(&url).unwrap().to_string())
                    }
                    c => c,
                }
                .into(),
            }
        })
        .post_async(oidc::REGISTER_PATH, |mut req, ctx| async move {
            let payload = json_bad_request!(req.json().await)?;
            let base_url = ctx.var(BASE_URL_KEY)?.to_string().parse().unwrap();
            let url = req.url()?;
            let db_client = CFClient { ctx, url };
            match oidc::register(payload, base_url, &db_client).await {
                Ok(r) => Ok(Response::from_json(&r)?.with_status(201)),
                Err(e) => e.into(),
            }
        })
        .post_async(oidc::USERINFO_PATH, userinfo)
        .get_async(oidc::USERINFO_PATH, userinfo)
        .get_async(
            &format!("{}/:id", oidc::CLIENT_PATH),
            |req, ctx| async move {
                let client_id = if let Some(id) = ctx.param("id") {
                    id.clone()
                } else {
                    return Response::error("Bad Request", 400);
                };
                let url = req.url()?;
                let db_client = CFClient { ctx, url };
                match oidc::clientinfo(client_id, &db_client).await {
                    Ok(r) => Ok(Response::from_json(&r)?),
                    Err(e) => e.into(),
                }
            },
        )
        .delete_async(
            &format!("{}/:id", oidc::CLIENT_PATH),
            |req, ctx| async move {
                let client_id = if let Some(id) = ctx.param("id") {
                    id.clone()
                } else {
                    return Response::error("Bad Request", 400);
                };
                let bearer = req
                    .headers()
                    .get(Authorization::<Bearer>::name().as_str())?
                    .and_then(|b| HeaderValue::from_str(b.as_ref()).ok())
                    .as_ref()
                    .and_then(Bearer::decode);
                let url = req.url()?;
                let db_client = CFClient { ctx, url };
                match oidc::client_delete(client_id, bearer, &db_client).await {
                    Ok(()) => Ok(Response::empty()?.with_status(204)),
                    Err(e) => e.into(),
                }
            },
        )
        .post_async(
            &format!("{}/:id", oidc::CLIENT_PATH),
            |mut req, ctx| async move {
                let client_id = if let Some(id) = ctx.param("id") {
                    id.clone()
                } else {
                    return Response::error("Bad Request", 400);
                };
                let bearer = req
                    .headers()
                    .get(Authorization::<Bearer>::name().as_str())?
                    .and_then(|b| HeaderValue::from_str(b.as_ref()).ok())
                    .as_ref()
                    .and_then(Bearer::decode);
                let payload = json_bad_request!(req.json().await)?;
                let url = req.url()?;
                let db_client = CFClient { ctx, url };
                match oidc::client_update(client_id, payload, bearer, &db_client).await {
                    Ok(()) => Ok(Response::empty()?),
                    Err(e) => e.into(),
                }
            },
        )
        .get_async(oidc::SIGNIN_PATH, |req, ctx| async move {
            let url = req.url()?;
            let query = url.query().unwrap_or_default();
            let params = match serde_urlencoded::from_str(query) {
                Ok(p) => p,
                Err(_) => return CustomError::BadRequest("Bad query params".to_string()).into(),
            };
            let cookies = req
                .headers()
                .get(headers::Cookie::name().as_str())?
                .and_then(|c| HeaderValue::from_str(&c).ok())
                .and_then(|c| headers::Cookie::decode(&mut [c].iter()).ok());
            if cookies.is_none() {
                return Response::error("Missing cookies", 400);
            }
            let url = req.url()?;
            let base_url = ctx.var(BASE_URL_KEY)?.to_string().parse().unwrap();
            let db_client = CFClient { ctx, url };
            match oidc::sign_in(&base_url, params, cookies.unwrap(), &db_client).await {
                Ok(url) => Response::redirect(url),
                Err(e) => e.into(),
            }
        })
        .run(req, env)
        .await
}
