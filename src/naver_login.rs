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
        .route("/", get(naver_login))
        .route("/api/auth/sign_up", get(naver_login_callback));

    let listener = tokio::net::TcpListener::bind("localhost:4000")
        .await
        .unwrap();
    axum::serve(listener, app).await.unwrap();
}
async fn naver_login() -> Redirect {
    let client_id = env::var("NAVER_CLIENT_ID").unwrap();
    let redirect_uri = env::var("NAVER_REDIRECT_URI").unwrap();
    let uri = format!(
        "https://nid.naver.com/oauth2.0/authorize?client_id={}&redirect_uri={}&response_type=code",
        client_id, redirect_uri
    );

    Redirect::to(&uri)
}

async fn naver_login_callback(Query(query): Query<CodeQuery>) -> impl IntoResponse {
    let client_id = env::var("NAVER_CLIENT_ID").unwrap();
    let client_secret = env::var("NAVER_CLIENT_SECRET").unwrap();

    let request_uri = format!(
        "https://nid.naver.com/oauth2.0/token?grant_type=authorization_code&client_id={}&client_secret={}&code={}", 
        client_id, client_secret, query.code
    );

    let token_response = reqwest::Client::new()
        .get(request_uri)
        .send()
        .await
        .unwrap();

    let body = token_response.text().await.unwrap();
    info!("body: {:?}", body);
    let token: serde_json::Value = serde_json::from_str(&body).unwrap();

    info!("token: {:?}", token);

    let result = if let serde_json::Value::String(access_token) = &token["access_token"] {
        let resp = reqwest::Client::new()
            .get("https://openapi.naver.com/v1/nid/me")
            .header(AUTHORIZATION, format!("Bearer {}", access_token))
            .send()
            .await
            .unwrap();
        Some(resp.text().await.unwrap())
    } else {
        None
    };

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
