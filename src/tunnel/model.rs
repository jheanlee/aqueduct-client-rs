use rustls::pki_types::ServerName;
use std::net::SocketAddr;
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio_rustls::client::TlsStream;
use tokio_util::sync::CancellationToken;

#[derive(Clone)]
pub struct Flags {
    pub global_cancellation_token: CancellationToken,
    pub local_cancellation_token: CancellationToken,
}

pub struct TunnelConfig {
    pub tunnel_host: ServerName<'static>,
    pub tunnel_host_port: u16,
    pub tunnel_service: ServerName<'static>,
    pub tunnel_service_port: u16,
    pub tunnel_username: Option<String>,
    pub tunnel_password: Option<String>,
    pub tunnel_token: Option<String>,
}

pub struct Shared {
    pub tls_config: rustls::ClientConfig,
    pub config: TunnelConfig,
}

pub struct TunnelStream {
    pub stream: Mutex<TlsStream<TcpStream>>,
    pub addr: SocketAddr,
}
