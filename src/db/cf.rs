use anyhow::{anyhow, Result};
use async_trait::async_trait;
use worker::RouteContext;

use super::*;

const KV_NAMESPACE: &str = "SIWE-OIDC";

pub struct CFClient {
    pub ctx: RouteContext<()>,
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
            // TODO put some sort of expiration for dynamic registration
            .execute()
            .await
            .map_err(|e| anyhow!("Failed to put KV: {}", e))?;
        Ok(())
    }
    async fn get_client(&self, client_id: String) -> Result<Option<ClientEntry>> {
        let entry = self
            .ctx
            .kv(KV_NAMESPACE)
            .map_err(|e| anyhow!("Failed to get KV store: {}", e))?
            .get(&format!("{}/{}", KV_CLIENT_PREFIX, client_id))
            .await
            .map_err(|e| anyhow!("Failed to get KV: {}", e))?
            .map(|e| e.as_string());
        if let Some(e) = entry {
            Ok(serde_json::from_str(&e)
                .map_err(|e| anyhow!("Failed to deserialize client entry: {}", e))?)
        } else {
            Ok(None)
        }
    }
    async fn set_code(&self, code: String, code_entry: CodeEntry) -> Result<()> {
        self.ctx
            .kv(KV_NAMESPACE)
            .map_err(|e| anyhow!("Failed to get KV store: {}", e))?
            .put(
                &code,
                hex::encode(
                    bincode::serialize(&code_entry)
                        .map_err(|e| anyhow!("Failed to serialise code: {}", e))?,
                ),
            )
            .map_err(|e| anyhow!("Failed to build KV put: {}", e))?
            .expiration_ttl(ENTRY_LIFETIME.try_into().unwrap())
            .execute()
            .await
            .map_err(|e| anyhow!("Failed to put KV: {}", e))?;
        Ok(())
    }
    async fn get_code(&self, code: String) -> Result<Option<CodeEntry>> {
        let serialized_entry = self
            .ctx
            .kv(KV_NAMESPACE)
            .map_err(|e| anyhow!("Failed to get KV store: {}", e))?
            .get(&code)
            .await
            .map_err(|e| anyhow!("Failed to get KV: {}", e))?
            .map(|e| e.as_bytes().to_vec());
        if let Some(e) = serialized_entry {
            let code_entry: CodeEntry = bincode::deserialize(
                &hex::decode(e).map_err(|e| anyhow!("Failed to decode code entry: {}", e))?,
            )
            .map_err(|e| anyhow!("Failed to deserialize code: {}", e))?;
            Ok(Some(code_entry))
        } else {
            Ok(None)
        }
    }
}
