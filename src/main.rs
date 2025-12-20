use std::sync::Arc;
use clap::Parser;
use rustls::pki_types::ServerName;
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio_rustls::TlsConnector;
use tokio_util::sync::CancellationToken;
use crate::common::args::Args;
use crate::tunnel::control::tunnel_client_control;
use crate::tunnel::model::{Flags, Shared, TunnelStream};

mod common;
mod tunnel;
mod message;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
  let _ = dotenv::dotenv();
  let args = Args::parse();

  //  TODO env
  //  TODO REPL input support

  let mut root_cert_store = rustls::RootCertStore::empty();
  for cert in rustls_native_certs::load_native_certs().expect("unable to load certifications") {
    root_cert_store.add(cert).unwrap();
  }

  let mut tls_config = rustls::ClientConfig::builder()
    .with_root_certificates(root_cert_store)
    .with_no_client_auth();
  tls_config.key_log = Arc::new(rustls::KeyLogFile::new());

  let tls_connector = TlsConnector::from(Arc::new(tls_config.clone()));

  let host = format!("{}:{}", args.host_addr, args.host_port);

  let tcp_stream = TcpStream::connect(host.as_str()).await?;
  let tunnel_server_addr = tcp_stream.peer_addr()?;
  let tls_stream = tls_connector.connect(ServerName::try_from(host)?, tcp_stream).await?;

  let cancellation_token = CancellationToken::new();
  
  let shared = Arc::new(Shared {
    tls_config,
    service_addr: format!("{}:{}", args.service_addr, args.service_port)
  });
  
  tunnel_client_control(
    Flags {
      global_cancellation_token: CancellationToken::new(),
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
