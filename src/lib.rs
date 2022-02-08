#[cfg(target_arch = "wasm32")]
use worker::*;

pub mod db;

#[cfg(target_arch = "wasm32")]
pub mod oidc;
#[cfg(target_arch = "wasm32")]
mod worker_lib;
#[cfg(target_arch = "wasm32")]
use worker_lib::main as worker_main;

#[cfg(target_arch = "wasm32")]
#[event(fetch)]
pub async fn main(req: Request, env: Env, _ctx: worker::Context) -> Result<Response> {
    worker_main(req, env).await
}
