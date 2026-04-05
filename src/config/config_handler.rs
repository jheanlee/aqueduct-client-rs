use crate::config::args::Args;
use crate::config::error::ConfigError;
use clap::Parser;
use regex::Regex;
use rustls::pki_types::ServerName;
use rustyline::DefaultEditor;
use rustyline::error::ReadlineError;

pub struct Config {
    pub tunnel_host: ServerName<'static>,
    pub tunnel_host_port: u16,
    pub tunnel_service: ServerName<'static>,
    pub tunnel_service_port: u16,
    pub tunnel_username: Option<String>,
    pub tunnel_password: Option<String>,
    pub tunnel_token: Option<String>,
}

///   Reads config from
///     1. command line args
///     2. environment variables
///     3. default value
pub fn read_config() -> Result<Config, ConfigError> {
    let mut config = Config {
        tunnel_host: ServerName::try_from("0.0.0.0").unwrap_or_else(|_| unreachable!()),
        tunnel_host_port: 30330,
        tunnel_service: ServerName::try_from("0.0.0.0").unwrap_or_else(|_| unreachable!()),
        tunnel_service_port: 80,
        tunnel_username: None,
        tunnel_password: None,
        tunnel_token: None,
    };

    //  environment variable
    if let Ok(tunnel_host) = std::env::var("AQUEDUCT_HOST") {
        let host_parts: Vec<&str> = tunnel_host.splitn(2, ':').collect();
        config.tunnel_host = ServerName::try_from(
            host_parts
                .get(0)
                .ok_or_else(|| {
                    ConfigError::InvalidValue(("[host]".to_string(), "AQUEDUCT_HOST".to_string()))
                })?
                .to_string(),
        )
        .map_err(|_| ConfigError::InvalidDNSName)?;
    }
    if let Ok(tunnel_service) = std::env::var("AQUEDUCT_SERVICE") {
        let service_parts: Vec<&str> = tunnel_service.splitn(2, ':').collect();
        config.tunnel_service = ServerName::try_from(
            service_parts
                .get(0)
                .ok_or_else(|| {
                    ConfigError::InvalidValue((
                        "[service]".to_string(),
                        "AQUEDUCT_SERVICE".to_string(),
                    ))
                })?
                .to_string(),
        )
        .map_err(|_| ConfigError::InvalidDNSName)?;
    }
    if let Ok(tunnel_username) = std::env::var("AQUEDUCT_USERNAME") {
        config.tunnel_username = Some(tunnel_username);
    }
    if let Ok(tunnel_password) = std::env::var("AQUEDUCT_PASSWORD") {
        config.tunnel_password = Some(tunnel_password);
    }
    if let Ok(tunnel_token) = std::env::var("AQUEDUCT_TOKEN") {
        config.tunnel_token = Some(tunnel_token);
    }

    //  args
    let args = Args::parse();
    if let Some(tunnel_host) = args.host {
        let host_parts: Vec<&str> = tunnel_host.splitn(2, ':').collect();
        config.tunnel_host = ServerName::try_from(
            host_parts
                .get(0)
                .ok_or_else(|| {
                    ConfigError::InvalidValue(("[host]".to_string(), "AQUEDUCT_HOST".to_string()))
                })?
                .to_string(),
        )
        .map_err(|_| ConfigError::InvalidDNSName)?;
    }
    if let Some(tunnel_service) = args.service {
        let service_parts: Vec<&str> = tunnel_service.splitn(2, ':').collect();
        config.tunnel_service = ServerName::try_from(
            service_parts
                .get(0)
                .ok_or_else(|| {
                    ConfigError::InvalidValue((
                        "[service]".to_string(),
                        "AQUEDUCT_SERVICE".to_string(),
                    ))
                })?
                .to_string(),
        )
        .map_err(|_| ConfigError::InvalidDNSName)?;
    }
    if let Some(tunnel_username) = args.username {
        config.tunnel_username = Some(tunnel_username);
    }
    if let Some(tunnel_password) = args.password {
        config.tunnel_password = Some(tunnel_password);
    }
    if let Some(tunnel_token) = args.token {
        config.tunnel_token = Some(tunnel_token);
    }

    Ok(config)
}

pub enum TunnelCredential {
    Password(String, String),
    Token(String),
}
pub fn get_credentials() -> Option<TunnelCredential> {
    let token_regex = Regex::new("^AQ_[A-Za-z0-9_-]{21}$").unwrap_or_else(|_| unreachable!());
    let mut credential = None;

    let mut rl = DefaultEditor::new().ok()?;

    let handle_line = |line: Result<String, ReadlineError>| -> Result<String, ()> {
        match line {
            Ok(line) => Ok(line.trim().to_string()),
            Err(ReadlineError::Interrupted) => {
                println!("Aborted");
                Err(())
            }
            Err(ReadlineError::Eof) => {
                println!("Aborted");
                Err(())
            }
            Err(error) => {
                println!("Error: {:?}", error);
                Err(())
            }
        }
    };

    loop {
        let line = rl.readline(
            "Please select a method to authenticate:
      1. password-based (if you have an username-password pair)
      2. token-based (if you have a token starting with `AQ_`) \
      Select a method (1-2): ",
        );
        let line = handle_line(line).ok()?;
        match line.as_str() {
            "1" => {
                credential = Some(TunnelCredential::Password("".to_string(), "".to_string()));
                break;
            }
            "2" => {
                credential = Some(TunnelCredential::Token("".to_string()));
                break;
            }
            _ => continue,
        }
    }

    match credential {
        Some(TunnelCredential::Password(_, _)) => {
            let mut username = String::new();
            let mut password = String::new();
            loop {
                let line = rl.readline("Please enter your username: ");
                let line = handle_line(line).ok()?;
                if line.chars().all(|c: char| char::is_ascii_alphanumeric(&c)) {
                    username = line;
                    break;
                } else {
                    println!("Invalid character(s) found, please try again");
                }
            }

            loop {
                let line = rl.readline("Please enter your password: ");
                let line = handle_line(line).ok()?;
                if line.chars().all(|c: char| char::is_ascii_graphic(&c)) {
                    password = line;
                    break;
                } else {
                    println!("Invalid character(s) found, please try again");
                }
            }

            credential = Some(TunnelCredential::Password(username, password));
        }
        Some(TunnelCredential::Token(..)) => loop {
            let line = rl.readline("Please enter your token: ");
            let line = handle_line(line).ok()?;
            if token_regex.is_match(line.as_str()) {
                credential = Some(TunnelCredential::Token(line));
                break;
            } else {
                println!("Invalid format. Please try again");
            }
        },
        None => {}
    }

    credential
}
