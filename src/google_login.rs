// Reference: https://developers.google.com/identity/protocols/oauth2/web-server?hl=ko

use axum::{
    extract::Query,
    http::StatusCode,
    response::{IntoResponse, Redirect},
    routing::get,
    Router,
};
use dotenvy::dotenv;
use reqwest::header::AUTHORIZATION;
use serde::{Deserialize, Serialize};
use std::env;
use tracing::info;

#[tokio::main]
async fn main() {
    dotenv().ok();
    tracing_subscriber::fmt::init();

    let app = Router::new()
        .route("/", get(google_login))
        .route("/api/auth/sign_up", get(google_login_callback));

    let listener = tokio::net::TcpListener::bind("localhost:4000")
        .await
        .unwrap();
    axum::serve(listener, app).await.unwrap();
}
async fn google_login() -> Redirect {
    let client_id = env::var("GOOGLE_CLIENT_ID").unwrap();
    let redirect_uri = env::var("GOOGLE_REDIRECT_URI").unwrap();
    let scope = "https://www.googleapis.com/auth/userinfo.email+https://www.googleapis.com/auth/userinfo.profile+openid";

    let uri = format!(
        "https://accounts.google.com/o/oauth2/v2/auth?client_id={}&redirect_uri={}&response_type=code&scope={}",
        client_id, redirect_uri, scope
    );

    info!("uri: {:?}", uri);

    Redirect::to(&uri)
}

async fn google_login_callback(Query(query): Query<CodeQuery>) -> impl IntoResponse {
    let client_id = env::var("GOOGLE_CLIENT_ID").unwrap();
    let client_secret = env::var("GOOGLE_CLIENT_SECRET").unwrap();
    let redirect_uri = env::var("GOOGLE_REDIRECT_URI").unwrap();

    info!("code: {:?}", query.code);

    let params = [
        ("code", query.code),
        ("client_id", client_id),
        ("client_secret", client_secret),
        ("redirect_uri", redirect_uri),
        ("grant_type", "authorization_code".to_string()),
    ];

    let token_response = reqwest::Client::new()
        .post("https://oauth2.googleapis.com/token")
        .form(&params)
        .send()
        .await
        .unwrap();

    let body = token_response.text().await.unwrap();

    let token: serde_json::Value = serde_json::from_str(&body).unwrap();

    info!("token: {:?}", token);

    let result = if let serde_json::Value::String(access_token) = &token["access_token"] {
        let resp = reqwest::Client::new()
            .get("https://www.googleapis.com/userinfo/v2/me")
            .header(AUTHORIZATION, format!("Bearer {}", access_token))
            .send()
            .await
            .unwrap();
        Some(resp.text().await.unwrap())
    } else {
        None
    };

    info!("result: {:?}", result);

    match &result {
        Some(_) => {
            // let resp = serde_json::from_str(result).unwrap();
            (StatusCode::OK, "OK")
        }
        None => (StatusCode::UNAUTHORIZED, "Unauthorized"),
    }
}

#[derive(Debug, Deserialize)]
struct CodeQuery {
    code: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct AccessToken {
    access_token: String,
    refresh_token: String,
    token_type: String,
    expires_in: i32,
}
