use anyhow::Result;
use std::sync::OnceLock;
use std::fs;

#[derive(Clone)]
pub struct KeyhouseConf {
    pub base_url: String,
    pub token: String,
}

#[derive(Clone)]
pub struct Config {
    pub hostname: String,
    pub keyhouse: KeyhouseConf,
    pub cache_path: String, // Recieved from main watchdog

    pub github_owner: String,
    pub github_repo: String,
    pub branch: String,
    pub github_token: String,
}

impl Config {
    pub fn new(hostname: String, base_url: String, token: String, cache_path: String) -> Self {
        let parts: Vec<&str> = base_url.split('/').collect();
        let (owner, repo) = if parts.len() >= 6 {
            (parts[4].to_string(), parts[5].to_string())
        } else {
            (String::new(), String::new())
        };

        Config {
            hostname,
            keyhouse: KeyhouseConf {
                base_url,
                token: token.clone(),
            },
            cache_path,
            github_owner: owner,
            github_repo: repo,
            branch: "master".to_string(),
            github_token: token,
        }
    }
}

pub static LOGGER: OnceLock<String> = OnceLock::new();
pub fn get_log_target() -> &'static str {
    LOGGER.get().expect("log target not set").as_str()
}

pub fn set_log_target(log_target: String) {
    LOGGER.set(log_target).expect("log target already set");
}

pub fn init(config: &Config) -> Result<()> {
    if !std::path::Path::new(&config.cache_path).exists() {
        fs::create_dir_all(&config.cache_path)?;
    }
    Ok(())
}
