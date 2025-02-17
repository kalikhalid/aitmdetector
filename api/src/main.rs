use std::sync::Arc;

use axum::{
    extract::{Path, State}, response::{IntoResponse, Response}, routing::{delete, get, post, put}, Json, Router
};
use chrono::TimeDelta;
use detector::PhishingDetector;
use serde_json::json;
use url::Url;
use tokio::net::TcpListener;
use tracing::info;
use crate::error::Error;
pub type Result<T> = core::result::Result<T, Error>;

mod detector;
mod error;

async fn test_route() -> impl IntoResponse{
    Json(json!({ "status": "ok" }))
}

async fn detector_route(Path(url): Path<String>, State(state): State<Arc<PhishingDetector>>) -> Result<impl IntoResponse>{
    info!("new request");
    let url_obj = Url::parse(&url)
        .map_err(|_| Error::ParseError(String::from("Invalid URL structure!")))?;
    let host = &url_obj.host()
            .ok_or(Error::ParseError("Host not found!".to_string()))?.to_string();
    let mut resp = serde_json::Map::new();
    let detector = state.clone();
    let tls_data = detector.get_tls_certs(&host).await?;
    if detector.is_suspicious_url(&url){
        resp.insert("url_structure".to_string(), json!({"status": "detected", "message": "suspicious url structure(evilginx)"}));
    }else{
        resp.insert("url_structure".to_string(), json!({"status": "not_detected", "message": "no suspicious url structure"}));
    }
    let mut flag = false;
    for (name, _from_start_to_end) in tls_data{
        let name = name.to_lowercase();
        if name.contains("let") && name.contains("encrypt"){
            resp.insert("tls_data".to_string(), json!({"status": "detected", "message": "detected suspicious certs"}));
            flag = true;
        }
    }
    if !flag{
        resp.insert("tls_data".to_string(), json!({"status": "not_detected", "message": "no suspicious certs detected"}));
    }
    let domain_age = detector.get_domain_data(&host).await?;
    if domain_age < TimeDelta::days(30){
        resp.insert("domain_data".to_string(), json!({"status": "detected", "message": "suspicious domain age"}));
    }else{
        resp.insert("domain_data".to_string(), json!({"status": "not_detected"}));
    }
    let main_page_check = detector.check_main_page(&host).await?;
    if !main_page_check{
        resp.insert("main_page".to_string(), json!({"status": "detected", "message": "main page not found"}));
    }else{
        resp.insert("main_page".to_string(), json!({"status": "not_detected"}));
    }
    Ok(Json(resp))
}

#[tokio::main]
async fn main() -> Result<()>{
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_target(false)
        .init();
    let api_key = std::env::var("SECURITYTRAILSAPI").map_err(|e| Error::custom("env SECURITYTRAILSAPI variable not found"))?;
    let detector = Arc::new(PhishingDetector::new(&api_key)?);
    println!("{}", detector.is_suspicious_url("https://trueton.xyz/somesome"));
    let app = Router::new()
        .route("/", get(test_route))
        .route("/api/detect/{url}", post(detector_route))
        .with_state(detector);
        // .route("/api/detect/:url", get(test_route));
    let listener = TcpListener::bind("0.0.0.0:8080").await?;
    axum::serve(listener, app).await.map_err(|e| Error::from(format!("{e}")));
    Ok(())
    
}
