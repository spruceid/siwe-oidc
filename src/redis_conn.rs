use std::ops::DerefMut;

use bb8;
use redis;

use async_trait::async_trait;
use redis::{aio::Connection, ErrorKind};
use redis::{
    cluster::{ClusterClient, ClusterConnection},
    IntoConnectionInfo, RedisError,
};

/// A `bb8::ManageConnection` for `redis::Client::get_async_connection`.
#[derive(Clone)]
pub struct RedisConnectionManager {
    client: ClusterClient,
}

impl RedisConnectionManager {
    /// Create a new `RedisConnectionManager`.
    /// See `redis::Client::open` for a description of the parameter types.
    pub fn new<T: IntoConnectionInfo>(info: T) -> Result<RedisConnectionManager, RedisError> {
        Ok(RedisConnectionManager {
            client: ClusterClient::open(vec![info.into_connection_info()?])?,
        })
    }
}

#[async_trait]
impl bb8::ManageConnection for RedisConnectionManager {
    type Connection = ClusterConnection;
    type Error = RedisError;

    async fn connect(&self) -> Result<Self::Connection, Self::Error> {
        self.client.get_connection()
    }

    async fn is_valid(
        &self,
        conn: &mut bb8::PooledConnection<'_, Self>,
    ) -> Result<(), Self::Error> {
        let pong: String = redis::cmd("PING").query(conn.deref_mut())?;
        match pong.as_str() {
            "PONG" => Ok(()),
            _ => Err((ErrorKind::ResponseError, "ping request").into()),
        }
    }

    fn has_broken(&self, _: &mut Self::Connection) -> bool {
        false
    }
}
