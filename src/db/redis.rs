use anyhow::{anyhow, Result};
use async_trait::async_trait;
use bb8_redis::{bb8::Pool, redis::AsyncCommands, RedisConnectionManager};

use super::*;

#[derive(Clone)]
pub struct RedisClient {
    pub pool: Pool<RedisConnectionManager>,
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl DBClient for RedisClient {
    async fn set_client(&self, client_id: String, client_entry: ClientEntry) -> Result<()> {
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| anyhow!("Failed to get connection to database: {}", e))?;

        conn.set(
            format!("{}/{}", KV_CLIENT_PREFIX, client_id),
            serde_json::to_string(&client_entry)
                .map_err(|e| anyhow!("Failed to serialize client entry: {}", e))?,
        )
        .await
        .map_err(|e| anyhow!("Failed to set kv: {}", e))?;
        Ok(())
    }

    async fn get_client(&self, client_id: String) -> Result<Option<ClientEntry>> {
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| anyhow!("Failed to get connection to database: {}", e))?;
        let entry: Option<String> = conn
            .get(format!("{}/{}", KV_CLIENT_PREFIX, client_id))
            .await
            .map_err(|e| anyhow!("Failed to get kv: {}", e))?;
        if let Some(e) = entry {
            Ok(serde_json::from_str(&e)
                .map_err(|e| anyhow!("Failed to deserialize client entry: {}", e))?)
        } else {
            Ok(None)
        }
    }

    async fn set_code(&self, code: String, code_entry: CodeEntry) -> Result<()> {
        let mut conn = self
            .pool
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
        Ok(())
    }

    async fn get_code(&self, code: String) -> Result<Option<CodeEntry>> {
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| anyhow!("Failed to get connection to database: {}", e))?;
        let serialized_entry: Option<Vec<u8>> = conn
            .get(code)
            .await
            .map_err(|e| anyhow!("Failed to get kv: {}", e))?;
        if serialized_entry.is_none() {
            return Ok(None);
        }
        let code_entry: CodeEntry = bincode::deserialize(
            &hex::decode(serialized_entry.unwrap())
                .map_err(|e| anyhow!("Failed to decode code entry: {}", e))?,
        )
        .map_err(|e| anyhow!("Failed to deserialize code: {}", e))?;
        Ok(Some(code_entry))
    }
}
