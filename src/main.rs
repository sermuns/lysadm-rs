use axum::{
    extract::Query,
    response::{Html, Redirect},
    routing::get,
    Router,
};
use openidconnect::{
    core::{CoreProviderMetadata, CoreClient, CoreResponseType, CoreIdTokenVerifier, CoreAuthPrompt},
    reqwest::async_http_client,
    AuthenticationFlow, AuthorizationCode, CsrfToken, IssuerUrl, RedirectUrl, Scope,
};
use serde::Deserialize;
use std::{net::SocketAddr, sync::Arc};
use tokio::sync::Mutex;

#[tokio::main]
async fn main() {
    // Discover OpenID Connect provider metadata
    let provider_metadata = CoreProviderMetadata::discover_async(
        IssuerUrl::new("https://login.lysator.liu.se/realms/Lysator".to_string()).unwrap(),
        async_http_client,
    )
    .await
    .expect("Failed to discover OIDC metadata");

    // Setup OpenID client
    let client = CoreClient::from_provider_metadata(
        provider_metadata,
        // Replace with your client ID and secret registered in the provider
        openidconnect::ClientId::new("YOUR_CLIENT_ID".to_string()),
        Some(openidconnect::ClientSecret::new("YOUR_CLIENT_SECRET".to_string())),
    )
    .set_redirect_uri(
        RedirectUrl::new("http://localhost:3000/auth/callback".to_string()).unwrap(),
    );

    // Share client with handlers
    let client = Arc::new(client);
    let state = Arc::new(Mutex::new(None::<CsrfToken>));

    // Build app
    let app = Router::new()
        .route("/", get(index))
        .route("/login", get({
            let client = client.clone();
            let state = state.clone();
            move || login(client, state)
        }))
        .route("/auth/callback", get({
            let client = client.clone();
            let state = state.clone();
            move |params| callback(client, state, params)
        }));

    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    println!("Listening on {}", addr);
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}

async fn index() -> Html<&'static str> {
    Html(r#"<a href="/login">Login with Lysator</a>"#)
}

async fn login(
    client: Arc<CoreClient>,
    state: Arc<Mutex<Option<CsrfToken>>>,
) -> Redirect {
    let (auth_url, csrf_token) = client
        .authorize_url(
            AuthenticationFlow::AuthorizationCode,
            || CsrfToken::new_random(),
            || openidconnect::Nonce::new_random(),
        )
        .add_scope(Scope::new("openid".to_string()))
        .add_prompt(CoreAuthPrompt::None)
        .url();

    // Store CSRF token for later verification (super minimal, not persistent)
    *state.lock().await = Some(csrf_token);

    Redirect::to(auth_url.as_str())
}

#[derive(Deserialize)]
struct AuthRequest {
    code: String,
    state: String,
}

async fn callback(
    client: Arc<CoreClient>,
    state: Arc<Mutex<Option<CsrfToken>>>,
    Query(params): Query<AuthRequest>,
) -> Html<String> {
    let csrf_token = state.lock().await.take();
    if csrf_token
        .as_ref()
        .map_or(true, |t| t.secret() != &params.state)
    {
        return Html("Invalid CSRF token".to_string());
    }

    // Exchange code for tokens
    let token_response = client
        .exchange_code(AuthorizationCode::new(params.code))
        .request_async(async_http_client)
        .await;

    match token_response {
        Ok(token) => {
            Html(format!(
                "Logged in!<br>Access token: {:?}<br>ID token: {:?}",
                token.access_token().secret(),
                token.id_token().map(|id| id.secret())
            ))
        }
        Err(err) => Html(format!("Error: {:?}", err)),
    }
}
