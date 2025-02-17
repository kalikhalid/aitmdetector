use serde::Deserialize;
use std::env;

const CONFIG_PATH_ENV: &str = "CONFIG_PATH";
#[derive(Deserialize, Debug, Default)]
pub struct Config {
    pub telegram_bot_token: String,
    pub detector_address: String,
}

pub fn read_config() -> Config {
    dotenv::dotenv().ok();
    env::var(CONFIG_PATH_ENV)
        .map_err(|_| format!("{CONFIG_PATH_ENV} environment variable not set"))
        .and_then(|config_path| std::fs::read(config_path).map_err(|e| e.to_string()))
        .and_then(|bytes| toml::from_str(&String::from_utf8_lossy(&bytes)).map_err(|e| e.to_string()))
        .unwrap_or_else(|err| {
            println!("{err}");
            std::process::exit(1);
        })
}
