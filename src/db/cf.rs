use anyhow::{anyhow, Result};
use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use matchit::Node;
use std::collections::HashMap;
use worker::*;

use super::*;

const KV_NAMESPACE: &str = "SIWE_OIDC";
const DO_NAMESPACE: &str = "SIWE-OIDC-CODES";

// /!\/!\/!\/!\/!\/!\/!\/!\/!\/!\/!\/!\/!\/!\/!\/!\/!\/!\/!\/!\/!\/!\/!\/!\/!\
// Heavily relying on:
// A Durable Object is given 30 seconds of additional CPU time for every
// request it processes, including WebSocket messages. In the absence of
// failures, in-memory state should not be reset after less than 30 seconds of
// inactivity.
// /!\/!\/!\/!\/!\/!\/!\/!\/!\/!\/!\/!\/!\/!\/!\/!\/!\/!\/!\/!\/!\/!\/!\/!\/!\

// Wanted to use TimedCache but it (probably) crashes because it's using std::time::Instant which isn't available on wasm32.

#[durable_object]
pub struct DOCodes {
    // codes: TimedCache<String, CodeEntry>,
    codes: HashMap<String, (DateTime<Utc>, CodeEntry)>,
    // state: State,
    // env: Env,
}

#[durable_object]
impl DurableObject for DOCodes {
    fn new(state: State, _env: Env) -> Self {
        Self {
            // codes: TimedCache::with_lifespan(ENTRY_LIFETIME.try_into().unwrap()),
            codes: HashMap::new(),
            // state,
            // env,
        }
    }

    async fn fetch(&mut self, mut req: Request) -> worker::Result<Response> {
        // Can't use the Router because we need to reference self (thus move the var to the closure)
        if matches!(req.method(), Method::Get) {
            let mut matcher = Node::new();
            matcher.insert("/:code", ())?;
            let path = req.path();
            let matched = match matcher.at(&path) {
                Ok(m) => m,
                Err(_) => return Response::error("Bad request", 400),
            };
            let code = if let Some(c) = matched.params.get("code") {
                c
            } else {
                return Response::error("Bad request", 400);
            };
            if let Some(c) = self.codes.get(code) {
                if c.0 + Duration::seconds(ENTRY_LIFETIME.try_into().unwrap()) < Utc::now() {
                    self.codes.remove(code);
                    Response::error("Not found", 404)
                } else {
                    Response::from_json(&c.1)
                }
            } else {
                Response::error("Not found", 404)
            }
        } else if matches!(req.method(), Method::Post) {
            let mut matcher = Node::new();
            matcher.insert("/:code", ())?;
            let path = req.path();
            let matched = match matcher.at(&path) {
                Ok(m) => m,
                Err(_) => return Response::error("Bad request", 400),
            };
            let code = if let Some(c) = matched.params.get("code") {
                c
            } else {
                return Response::error("Bad request", 400);
            };
            let code_entry = match req.json().await {
                Ok(p) => p,
                Err(e) => return Response::error(format!("Bad request: {}", e), 400),
            };
            self.codes
                .insert(code.to_string(), (Utc::now(), code_entry));
            Response::empty()
        } else {
            Response::error("Method Not Allowed", 405)
        }
    }
}

pub struct CFClient {
    pub ctx: RouteContext<()>,
    pub url: Url,
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl DBClient for CFClient {
    async fn set_client(&self, client_id: String, client_entry: ClientEntry) -> Result<()> {
        self.ctx
            .kv(KV_NAMESPACE)
            .map_err(|e| anyhow!("Failed to get KV store: {}", e))?
            .put(
                &format!("{}/{}", KV_CLIENT_PREFIX, client_id),
                serde_json::to_string(&client_entry)
                    .map_err(|e| anyhow!("Failed to serialize client entry: {}", e))?,
            )
            .map_err(|e| anyhow!("Failed to build KV put: {}", e))?
            .execute()
            .await
            .map_err(|e| anyhow!("Failed to put KV: {}", e))?;
        Ok(())
    }

    async fn get_client(&self, client_id: String) -> Result<Option<ClientEntry>> {
        Ok(self
            .ctx
            .kv(KV_NAMESPACE)
            .map_err(|e| anyhow!("Failed to get KV store: {}", e))?
            .get(&format!("{}/{}", KV_CLIENT_PREFIX, client_id))
            .json()
            .await
            .map_err(|e| anyhow!("Failed to get KV: {}", e))?)
    }

    async fn delete_client(&self, client_id: String) -> Result<()> {
        Ok(self
            .ctx
            .kv(KV_NAMESPACE)
            .map_err(|e| anyhow!("Failed to get KV store: {}", e))?
            .delete(&format!("{}/{}", KV_CLIENT_PREFIX, client_id))
            .await
            .map_err(|e| anyhow!("Failed to get KV: {}", e))?)
    }

    async fn set_code(&self, code: String, code_entry: CodeEntry) -> Result<()> {
        let namespace = self
            .ctx
            .durable_object(DO_NAMESPACE)
            .map_err(|e| anyhow!("Failed to retrieve Durable Object: {}", e))?;
        let stub = namespace
            .id_from_name(&code)
            .map_err(|e| anyhow!("Failed to retrieve Durable Object from ID: {}", e))?
            .get_stub()
            .map_err(|e| anyhow!("Failed to retrieve Durable Object stub: {}", e))?;
        let mut headers = Headers::new();
        headers.set("Content-Type", "application/json").unwrap();
        let mut url = self.url.clone();
        url.set_path(&code);
        url.set_query(None);
        let req = Request::new_with_init(
            url.as_str(),
            &RequestInit {
                body: Some(wasm_bindgen::JsValue::from_str(
                    &serde_json::to_string(&code_entry)
                        .map_err(|e| anyhow!("Failed to serialize: {}", e))?,
                )),
                method: Method::Post,
                headers,
                ..Default::default()
            },
        )
        .map_err(|e| anyhow!("Failed to construct request for Durable Object: {}", e))?;
        let res = stub
            .fetch_with_request(req)
            .await
            .map_err(|e| anyhow!("Request to Durable Object failed: {}", e))?;
        match res.status_code() {
            200 => Ok(()),
            code => Err(anyhow!("Error fetching from Durable Object: {}", code)),
        }
    }
    async fn get_code(&self, code: String) -> Result<Option<CodeEntry>> {
        let namespace = self
            .ctx
            .durable_object(DO_NAMESPACE)
            .map_err(|e| anyhow!("Failed to retrieve Durable Object: {}", e))?;
        let stub = namespace
            .id_from_name(&code)
            .map_err(|e| anyhow!("Failed to retrieve Durable Object from ID: {}", e))?
            .get_stub()
            .map_err(|e| anyhow!("Failed to retrieve Durable Object stub: {}", e))?;
        let mut url = self.url.clone();
        url.set_path(&code);
        url.set_query(None);
        let mut res = stub
            .fetch_with_str(url.as_str())
            .await
            .map_err(|e| anyhow!("Request to Durable Object failed: {}", e))?;
        match res.status_code() {
            200 => Ok(Some(res.json().await.map_err(|e| {
                anyhow!(
                    "Response to Durable Object failed to be deserialized: {}",
                    e
                )
            })?)),
            404 => Ok(None),
            code => Err(anyhow!("Error fetching from Durable Object: {}", code)),
        }
    }

    async fn set_session(&self, id: String, entry: SessionEntry) -> Result<()> {
        self.ctx
            .kv(KV_NAMESPACE)
            .map_err(|e| anyhow!("Failed to get KV store: {}", e))?
            .put(
                &format!("{}/{}", KV_SESSION_PREFIX, id),
                serde_json::to_string(&entry)
                    .map_err(|e| anyhow!("Failed to serialize client entry: {}", e))?,
            )
            .map_err(|e| anyhow!("Failed to build KV put: {}", e))?
            .expiration_ttl(SESSION_LIFETIME)
            .execute()
            .await
            .map_err(|e| anyhow!("Failed to put KV: {}", e))?;
        Ok(())
    }

    async fn get_session(&self, id: String) -> Result<Option<SessionEntry>> {
        Ok(self
            .ctx
            .kv(KV_NAMESPACE)
            .map_err(|e| anyhow!("Failed to get KV store: {}", e))?
            .get(&format!("{}/{}", KV_SESSION_PREFIX, id))
            .json()
            .await
            .map_err(|e| anyhow!("Failed to get KV: {}", e))?)
    }
}
