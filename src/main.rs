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
use crate::config::config_handler::read_config;
use crate::tunnel::control::tunnel_client_control;
use crate::tunnel::model::{Flags, Shared, TunnelConfig};
use crate::tunnel::tls::DisableCertVerification;
use socket2::SockRef;
use std::process::exit;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_util::sync::CancellationToken;
use tracing::{error, warn};
use tracing_subscriber::EnvFilter;
use tracing_subscriber::util::SubscriberInitExt;

mod common;
mod config;
mod message;
mod tunnel;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
    let _ = dotenv::dotenv();
    let config = read_config().expect("ConfigError");

    //  log
    let (non_blocking_stdout, _guard) = tracing_appender::non_blocking(std::io::stdout());
    let subscriber = tracing_subscriber::fmt()
        .with_writer(non_blocking_stdout)
        .with_env_filter(EnvFilter::from_default_env())
        .finish();
    subscriber.init();

    //  TLS
    let mut root_cert_store = rustls::RootCertStore::empty();
    for cert in rustls_native_certs::load_native_certs().expect("Unable to load certificates") {
        root_cert_store.add(cert)?;
    }

    let mut tls_config = rustls::ClientConfig::builder()
        .with_root_certificates(root_cert_store)
        .with_no_client_auth();
    tls_config.key_log = Arc::new(rustls::KeyLogFile::new());

    if config.tunnel_disable_certificate_check {
        warn!("TLS certificate check is disabled; the connection is considered insecure");
        tls_config
            .dangerous()
            .set_certificate_verifier(Arc::new(DisableCertVerification {}));
    }

    let tls_connector = TlsConnector::from(Arc::new(tls_config.clone()));

    //  connect (control)
    let tcp_stream = TcpStream::connect((
        config.tunnel_host.to_str().to_string(),
        config.tunnel_host_port,
    ))
    .await
    .unwrap_or_else(|error| {
        error!("Unable to connect to the server: {:?}", error);
        exit(1);
    });

    let socket_ref = SockRef::from(&tcp_stream);
    socket_ref.set_tcp_nodelay(true).unwrap_or_else(|error| {
        error!("Unable to configure the control connection: {:?}", error);
        exit(1);
    });

    let tunnel_server_addr = tcp_stream.peer_addr()?;
    let tls_stream = tls_connector
        .connect(config.tunnel_host.clone(), tcp_stream)
        .await
        .unwrap_or_else(|error| {
            error!("Unable to connect to the server: {:?}", error);
            exit(1);
        });

    let cancellation_token = CancellationToken::new();

    let shared = Arc::new(Shared {
        tls_config,
        config: TunnelConfig {
            tunnel_host: config.tunnel_host,
            tunnel_service: config.tunnel_service,
            tunnel_service_port: config.tunnel_service_port,
            tunnel_username: config.tunnel_username,
            tunnel_password: config.tunnel_password,
            tunnel_token: config.tunnel_token,
        },
    });

    tunnel_client_control(
        Flags {
            local_cancellation_token: cancellation_token.child_token(),
        },
        shared.clone(),
        tunnel_server_addr,
        tls_stream,
    )
    .await;

    Ok(())
}
