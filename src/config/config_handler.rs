/*
 * Copyright 2026 Jhe-An Lee
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

use crate::config::args::Args;
use crate::config::error::ConfigError;
use crate::config::error::ConfigError::AuthenticationRequired;
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
    pub tunnel_user: Option<String>,
    pub tunnel_password: Option<String>,
    pub tunnel_token: Option<String>,
    pub tunnel_disable_certificate_check: bool,
}

///   Reads config from
///     1. command line args
///     2. environment variables
///     3. default value
pub fn read_config() -> Result<Config, ConfigError> {
    let mut config = Config {
        tunnel_host: ServerName::try_from("127.0.0.1").unwrap_or_else(|_| unreachable!()),
        tunnel_host_port: 30330,
        tunnel_service: ServerName::try_from("127.0.0.1").unwrap_or_else(|_| unreachable!()),
        tunnel_service_port: 80,
        tunnel_user: None,
        tunnel_password: None,
        tunnel_token: None,
        tunnel_disable_certificate_check: false,
    };

    //  environment variable
    if let Ok(tunnel_host) = std::env::var("AQUEDUCT_HOST") {
        let host_parts: Vec<&str> = tunnel_host.splitn(2, ':').collect();
        config.tunnel_host = ServerName::try_from(
            host_parts
                .first()
                .ok_or_else(|| {
                    ConfigError::InvalidValue(("host".to_string(), "AQUEDUCT_HOST".to_string()))
                })?
                .to_string(),
        )
        .map_err(|_| ConfigError::InvalidDNSName)?;
        config.tunnel_host_port = host_parts.get(1).unwrap_or(&"30330").parse()?;
    }
    if let Ok(tunnel_service) = std::env::var("AQUEDUCT_SERVICE") {
        let service_parts: Vec<&str> = tunnel_service.splitn(2, ':').collect();
        config.tunnel_service = ServerName::try_from(
            service_parts
                .first()
                .ok_or_else(|| {
                    ConfigError::InvalidValue((
                        "service".to_string(),
                        "AQUEDUCT_SERVICE".to_string(),
                    ))
                })?
                .to_string(),
        )
        .map_err(|_| ConfigError::InvalidDNSName)?;
        config.tunnel_service_port = service_parts.get(1).unwrap_or(&"80").parse()?;
    }
    if let Ok(tunnel_user) = std::env::var("AQUEDUCT_USER") {
        config.tunnel_user = Some(tunnel_user);
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
                .first()
                .ok_or_else(|| {
                    ConfigError::InvalidValue(("host".to_string(), "AQUEDUCT_HOST".to_string()))
                })?
                .to_string(),
        )
        .map_err(|_| ConfigError::InvalidDNSName)?;
        config.tunnel_host_port = host_parts.get(1).unwrap_or(&"30330").parse()?;
    }
    if let Some(tunnel_service) = args.service {
        let service_parts: Vec<&str> = tunnel_service.splitn(2, ':').collect();
        config.tunnel_service =
            ServerName::try_from(service_parts.first().unwrap_or(&"localhost").to_string())
                .map_err(|_| ConfigError::InvalidDNSName)?;
        config.tunnel_service_port = service_parts
            .get(1)
            .ok_or_else(|| {
                ConfigError::InvalidValue(("service".to_string(), "AQUEDUCT_SERVICE".to_string()))
            })?
            .parse()?;
    }
    if let Some(tunnel_username) = args.user {
        config.tunnel_user = Some(tunnel_username);
    }
    if let Some(tunnel_password) = args.password {
        config.tunnel_password = Some(tunnel_password);
    }
    if let Some(tunnel_token) = args.token {
        config.tunnel_token = Some(tunnel_token);
    }
    if args.insecure_tls {
        config.tunnel_disable_certificate_check = args.insecure_tls;
    }

    //  clean up values

    if let Some(user) = config.tunnel_user.as_ref()
        && user.is_empty()
    {
        config.tunnel_user = None;
    }

    if let Some(password) = config.tunnel_password.as_ref()
        && password.is_empty()
    {
        config.tunnel_password = None;
    }

    if let Some(token) = config.tunnel_token.as_ref()
        && token.is_empty()
    {
        config.tunnel_token = None;
    }

    if config.tunnel_token.is_none()
        && (config.tunnel_user.is_none() || config.tunnel_password.is_none())
    {
        match get_credentials() {
            Some(TunnelCredential::Token(token)) => config.tunnel_token = Some(token),
            Some(TunnelCredential::Password(username, password)) => {
                config.tunnel_user = Some(username);
                config.tunnel_password = Some(password);
            }
            None => Err(AuthenticationRequired)?,
        }
    }

    Ok(config)
}

pub enum TunnelCredential {
    Password(String, String),
    Token(String),
}
pub fn get_credentials() -> Option<TunnelCredential> {
    let token_regex =
        Regex::new("^aq_[1-9A-HJ-NP-Za-km-z]{43,44}$").unwrap_or_else(|_| unreachable!());
    let mut credential;

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
      2. token-based (if you have a token starting with `aq_`) \
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
            let username;
            let password;
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
