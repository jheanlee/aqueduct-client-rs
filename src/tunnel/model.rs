use std::net::SocketAddr;
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio_rustls::client::TlsStream;
use tokio_util::sync::CancellationToken;

#[derive(Clone)]
pub struct Flags {
  pub global_cancellation_token: CancellationToken,
  pub local_cancellation_token: CancellationToken
}

pub struct Shared {
  pub tls_config: rustls::ClientConfig,
  pub service_addr: SocketAddr
}

pub struct TunnelStream {
  pub stream: Mutex<TlsStream<TcpStream>>,
  pub addr: SocketAddr
}
