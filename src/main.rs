#[cfg(not(target_arch = "wasm32"))]
mod axum_lib;
#[cfg(not(target_arch = "wasm32"))]
mod config;
#[cfg(not(target_arch = "wasm32"))]
mod oidc;
#[cfg(not(target_arch = "wasm32"))]
use axum_lib::main as axum_main;

#[cfg(not(target_arch = "wasm32"))]
#[tokio::main]
async fn main() {
    axum_main().await
}

#[cfg(target_arch = "wasm32")]
fn main() {}
