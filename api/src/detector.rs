use axum::http::HeaderMap;
use chrono::{NaiveDate, NaiveDateTime, TimeDelta, Utc};
use levenshtein::levenshtein;
use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode};
use regex::Regex;
use reqwest::Client;
use serde_json::Value;
use url::Host;
use std::net::TcpStream;

use crate::{error::Error, Result};

pub struct PhishingDetector {
    http_client: Client,
}

impl PhishingDetector {
    pub fn new(securitytrails_api_key: &str) -> Result<Self> {
        let mut headers = HeaderMap::new();
        headers.insert(
            "apikey",
            securitytrails_api_key
                .parse()
                .map_err(|_| Error::ParseError("Invalid API key".to_owned()))?,
        );

        let http_client = Client::builder()
            .default_headers(headers)
            .build()
            .map_err(|e| Error::custom(format!("HTTP client init error: {}", e)))?;

        Ok(Self { http_client })
    }

    pub async fn get_tls_certs(&self, host: &str) -> Result<Vec<(String, TimeDelta)>> {
        let tcp_stream =
            TcpStream::connect((host, 443)).map_err(|e| Error::custom(format!("TCP connect error: {}", e)))?;

        let mut builder = SslConnector::builder(SslMethod::tls())
            .map_err(|e| Error::custom(format!("SSL init error: {}", e)))?;
        builder.set_verify(SslVerifyMode::NONE);
        let connector = builder.build();

        let ssl_stream =
            connector.connect(host, tcp_stream).map_err(|e| Error::custom(format!("SSL connect error: {}", e)))?;

        let certs = ssl_stream.ssl().peer_cert_chain().ok_or_else(|| {
            Error::custom("No TLS certificate chain found".to_owned())
        })?;

        let mut result_vec = Vec::new();

        for cert in certs {
            let valid_from = NaiveDateTime::parse_from_str(
                &cert.not_before().to_string(),
                "%b %d %H:%M:%S %Y GMT",
            )
            .map_err(|_| Error::ParseError("Invalid certificate start date".to_owned()))?;

            let valid_until = NaiveDateTime::parse_from_str(
                &cert.not_after().to_string(),
                "%b %d %H:%M:%S %Y GMT",
            )
            .map_err(|_| Error::ParseError("Invalid certificate expiry date".to_owned()))?;

            let duration = valid_until - valid_from;

            let issuer_name = cert
                .issuer_name()
                .entries()
                .nth(1)
                .and_then(|e| e.data().as_utf8().ok())
                .map(|s| s.to_string())
                .unwrap_or_else(|| "Unknown Issuer".to_owned());

            result_vec.push((issuer_name, duration));
        }

        Ok(result_vec)
    }

    pub async fn get_domain_data(&self, host: &str) -> Result<TimeDelta> {
        let url = format!("https://api.securitytrails.com/v1/domain/{}", host);
        let resp = self.http_client.get(&url).send().await.map_err(|e| {
            Error::NetworkError(format!("Request error: {}", e))
        })?;

        let resp_json: Value = resp.json().await.map_err(|e| {
            Error::ParseError(format!("JSON parse error: {}", e))
        })?;

        let first_seen_str = resp_json["current_dns"]["a"]["first_seen"]
            .as_str()
            .ok_or_else(|| Error::ParseError("Missing `first_seen` date".to_owned()))?;

        let first_seen = NaiveDate::parse_from_str(first_seen_str, "%Y-%m-%d")
            .map_err(|_| Error::ParseError("Invalid `first_seen` date format".to_owned()))?;

        let now = Utc::now().date_naive();
        Ok(now - first_seen)
    }

    pub fn is_suspicious_url(&self, url: &str) -> bool {
        let evilginx_pattern = Regex::new(r"https?://[a-zA-Z0-9.-]+/[a-zA-Z]{8}$")
            .expect("Invalid regex pattern");
        evilginx_pattern.is_match(url)
    }
    pub fn check_domain_levalgo(&self, host: &String) -> Result<bool>{
        
        Ok(false)
    }
    pub async fn check_main_page(&self, host: &String) -> Result<bool>{
        let norm_url: Vec<&str> = host.split(".").collect();
        let f = &norm_url[norm_url.len()-2];
        let l = norm_url.last().ok_or(Error::ParseError("host parse error".to_string()))?;
        let url = format!("https://{}.{}/", f, l);
        if let Ok(resp) = self.http_client.get(url).send().await{
            if resp.status().to_string().starts_with("2"){
                return Ok(true);
            }
        }
        Ok(false)
    }
}
