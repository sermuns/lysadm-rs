# lysadm-rs MVP

Minimal Axum webapp authenticating via Lysator OpenID Connect.

## Usage

1. Register a client at [Lysator Keycloak](https://login.lysator.liu.se/realms/Lysator).
2. Copy your `client_id` and `client_secret` into `src/main.rs`:
    ```rust
    // Replace:
    openidconnect::ClientId::new("YOUR_CLIENT_ID".to_string()),
    Some(openidconnect::ClientSecret::new("YOUR_CLIENT_SECRET".to_string())),
    ```
3. Run:
    ```sh
    cargo run
    ```
4. Visit [http://localhost:3000](http://localhost:3000) and click "Login with Lysator".

## Security Note

This MVP stores CSRF tokens in memory and does not manage sessions.  
**Do not use in production.**

## License

MIT
