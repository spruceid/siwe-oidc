use openidconnect::{
    core::{CoreAuthenticationFlow, CoreClient, CoreProviderMetadata},
    reqwest::async_http_client,
    AuthorizationCode, ClientId, ClientSecret, CsrfToken, IssuerUrl, Nonce, Scope, TokenResponse,
};
use serde::Deserialize;
use url::Url;
use wasm_bindgen_futures::spawn_local;
use yew::prelude::*;
use yew_router::{hooks::use_location, prelude::*};

lazy_static::lazy_static! {
static ref CLIENT_ID: String = option_env!("CLIENT_ID").unwrap_or("fb24a7d9-6db9-476b-93c4-e8562e750250").to_string();
static ref CLIENT_SECRET: String = option_env!("CLIENT_SECRET").unwrap_or("6aae6334-148f-464c-a4bf-a204e62e197c").to_string();
static ref REDIRECT_URI: Url = Url::parse(option_env!("REDIRECT_URI").unwrap_or("http://localhost:8080/callback")).unwrap();
}

#[derive(Clone, Routable, PartialEq)]
enum Route {
    #[at("/")]
    Home,
    #[at("/callback")]
    OIDCCallback,
    #[not_found]
    #[at("/404")]
    NotFound,
}

#[function_component(SIWE)]
pub fn siwe() -> Html {
    html! {
        <>
            <form action="https://oidc.login.xyz/authorize">
                <input type="hidden" name="client_id" value={ CLIENT_ID.clone() } />
                <input type="hidden" name="response_type" value="code" />
                <input type="hidden" name="nonce" value="nonce" />
                <input type="hidden" name="scope" value="openid profile" />
                <input type="hidden" name="state" value="state" />
                <input type="hidden" name="redirect_uri" value={ REDIRECT_URI.to_string() } />
                <input type="submit" value="Sign-In with Ethereum using OpenID Connect" />
            </form>
        </>
    }
}

#[derive(Deserialize)]
struct CallbackParams {
    code: String,
    // state: String,
}

#[function_component(Callback)]
pub fn callback() -> Html {
    let location = use_location().unwrap();
    let params: CallbackParams = location.query().unwrap();

    let claims = use_state(String::default);
    let claims2 = claims.clone();
    spawn_local(async move {
        let provider_metadata = CoreProviderMetadata::discover_async(
            IssuerUrl::new("https://oidc.login.xyz/".to_string()).unwrap(),
            async_http_client,
        )
        .await
        .unwrap();
        let client = CoreClient::from_provider_metadata(
            provider_metadata,
            ClientId::new(CLIENT_ID.to_string()),
            Some(ClientSecret::new(CLIENT_SECRET.to_string())),
        );
        let (_auth_url, _csrf_token, nonce) = client
            .authorize_url(
                CoreAuthenticationFlow::AuthorizationCode,
                || CsrfToken::new("state".to_string()),
                || Nonce::new("nonce".to_string()),
            )
            .add_scope(Scope::new("openid".to_string()))
            .add_scope(Scope::new("profile".to_string()))
            .url();
        let token_response = client
            .exchange_code(AuthorizationCode::new(params.code))
            .request_async(async_http_client)
            .await
            .unwrap();
        let id_token = token_response.id_token().unwrap();
        claims2.set(
            serde_json::to_string(
                id_token
                    .claims(&client.id_token_verifier(), &nonce)
                    .unwrap(),
            )
            .unwrap(),
        );
    });

    html! {
        <>
            <p>{ (*claims).clone() }</p>
        </>
    }
}

fn switch(routes: &Route) -> Html {
    match routes {
        Route::Home => html! { <SIWE /> },
        Route::OIDCCallback => html! { <Callback /> },
        Route::NotFound => html! { <Redirect<Route> to={Route::Home}/> },
    }
}

#[function_component(App)]
fn app() -> Html {
    html! {
        <BrowserRouter>
            <Switch<Route> render={Switch::render(switch)} />
        </BrowserRouter>
    }
}

fn main() {
    yew::start_app::<App>();
}
