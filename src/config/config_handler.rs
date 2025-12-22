use std::net::SocketAddr;
use std::str::FromStr;
use clap::Parser;
use crate::config::args::Args;
use crate::config::error::ConfigError;

pub struct Config {
  pub tunnel_host: SocketAddr,
  pub tunnel_service: SocketAddr,
  pub tunnel_username: Option<String>,
  pub tunnel_password: Option<String>,
  pub tunnel_token: Option<String>,
}

///   Reads config from
///     1. command line args
///     2. environment variables
///     3. default value
pub fn read_config() -> Result<Config, ConfigError> {
  let mut config =  Config {
    tunnel_host: SocketAddr::from_str("0.0.0.0:30330")?,
    tunnel_service: SocketAddr::from_str("0.0.0.0:80")?,
    tunnel_username: None,
    tunnel_password: None,
    tunnel_token: None,
  };

  //  environment variable
  if let Ok(tunnel_host) = std::env::var("AQUEDUCT_HOST") {
    config.tunnel_host = tunnel_host.parse()?;
  }
  if let Ok(tunnel_service) = std::env::var("AQUEDUCT_SERVICE") {
    config.tunnel_service = tunnel_service.parse()?;
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
    config.tunnel_host = tunnel_host;
  }
  if let Some(tunnel_service) = args.service {
    config.tunnel_service = tunnel_service;
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