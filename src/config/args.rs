use std::net::SocketAddr;

#[derive(clap::Parser)]
pub struct Args {
  pub host: Option<SocketAddr>,
  pub service: Option<SocketAddr>,
  #[arg(short, long)]
  pub username: Option<String>,
  #[arg(short, long)]
  pub password: Option<String>,
  #[arg(short, long)]
  pub token: Option<String>,
}