use anyhow::{anyhow, Result};
use bb8_redis::{bb8::PooledConnection, redis::AsyncCommands, RedisConnectionManager};
use openidconnect::RedirectUrl;
use serde::{Deserialize, Serialize};

const KV_CLIENT_PREFIX: &str = "clients";

#[derive(Serialize, Deserialize)]
pub struct ClientEntry {
    pub secret: String,
    pub redirect_uris: Vec<RedirectUrl>,
}

pub async fn set_client(
    mut conn: PooledConnection<'_, RedisConnectionManager>,
    client_id: String,
    client_entry: ClientEntry,
) -> Result<()> {
    conn.set(
        format!("{}/{}", KV_CLIENT_PREFIX, client_id),
        serde_json::to_string(&client_entry)
            .map_err(|e| anyhow!("Failed to serialize client entry: {}", e))?,
    )
    .await
    .map_err(|e| anyhow!("Failed to set kv: {}", e))?;
    Ok(())
}

pub async fn get_client(
    mut conn: PooledConnection<'_, RedisConnectionManager>,
    client_id: String,
) -> Result<Option<ClientEntry>> {
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
