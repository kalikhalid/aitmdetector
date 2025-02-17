use axum::{
    body::Body, http::{Response, StatusCode}, response::{IntoResponse, Json}
};
use serde_json::{json, Value};


#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("Custom {0}")]
    Custom(String),

    #[error("Network Error {0}")]
    NetworkError(String),

    #[error("Parse Error {0}")]
    ParseError(String),

    #[error(transparent)]
    Io(#[from] tokio::io::Error)

    //#[error(transparent)]
    //StdError(#[from] Box<dyn std::error::Error>),
}

impl Error {
    pub fn custom(val: impl std::fmt::Display) -> Self {
        Self::Custom(val.to_string())
    }
}

impl From<&str> for Error {
    fn from(value: &str) -> Self {
        Self::Custom(value.to_string())
    }
}

impl From<String> for Error {
    fn from(value: String) -> Self {
        Self::Custom(value)
    }
}

impl IntoResponse for Error {
    fn into_response(self) -> axum::response::Response {
        let (status, message) = match self {
            Error::Custom(message) | Error::ParseError(message)  => (StatusCode::BAD_REQUEST, message),
            Error::Io(error) => (StatusCode::INTERNAL_SERVER_ERROR, error.to_string()),
            Error::NetworkError(message) => (StatusCode::INTERNAL_SERVER_ERROR, message),
        };

        let payload = Json(json!({
            "status": "error",
            "message": message,
        }));

        // Correctly constructing the response
        (status, payload).into_response()
    }
}
