use std::sync::Arc;
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio_rustls::TlsConnector;
use tokio_util::sync::CancellationToken;
use crate::config::config_handler::read_config;
use crate::tunnel::control::tunnel_client_control;
use crate::tunnel::model::{Flags, Shared, TunnelStream};
mod common;
mod tunnel;
mod message;
mod config;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
  let _ = dotenv::dotenv();
  let config = read_config()?;

  let mut root_cert_store = rustls::RootCertStore::empty();
  for cert in rustls_native_certs::load_native_certs().expect("unable to load certificates") {
    root_cert_store.add(cert).unwrap();
  }

  let mut tls_config = rustls::ClientConfig::builder()
    .with_root_certificates(root_cert_store)
    .with_no_client_auth();
  tls_config.key_log = Arc::new(rustls::KeyLogFile::new());

  let tls_connector = TlsConnector::from(Arc::new(tls_config.clone()));

  let tcp_stream = TcpStream::connect((config.tunnel_host.to_str().to_string(), config.tunnel_host_port)).await
    .expect("Unable to connect to server");
  let tunnel_server_addr = tcp_stream.peer_addr()?;
  let tls_stream = tls_connector.connect(
    config.tunnel_host.clone(),
    tcp_stream
  ).await.expect("Unable to connect to server");

  let cancellation_token = CancellationToken::new();
  
  let shared = Arc::new(Shared {
    tls_config,
    config,
  });
  
  tunnel_client_control(
    Flags {
      global_cancellation_token: cancellation_token.clone(),
      local_cancellation_token: CancellationToken::new(),
    },
    shared.clone(),
    Arc::new(TunnelStream {
      stream: Mutex::new(tls_stream),
      addr: tunnel_server_addr,
    })
  ).await;

  Ok(())
}
