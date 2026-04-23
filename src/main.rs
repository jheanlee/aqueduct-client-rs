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

use crate::common::log::{color_code, log, Level, LogConfig};
use crate::config::config_handler::read_config;
use crate::tunnel::control::tunnel_client_control;
use crate::tunnel::model::{Flags, Shared, TunnelConfig};
use crate::tunnel::tls::DisableCertVerification;
use std::sync::{Arc, LazyLock};
use tokio::net::TcpStream;
use tokio::sync::RwLock;
use tokio_rustls::TlsConnector;
use tokio_util::sync::CancellationToken;

mod common;
mod config;
mod message;
mod tunnel;

static LOG_CONFIG: LazyLock<RwLock<LogConfig>> = LazyLock::new(|| {
    RwLock::new(LogConfig {
        stdout_filter: Level::Info.into(),
        system_filter: Level::Notice.into(),
        stdout_enabled: true,
        syslog_enabled: false,
        oslog_enabled: false,
    })
});

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
    let _ = dotenv::dotenv();
    let config = read_config().expect("ConfigError");

    //  log
    {
        let mut log_config = LOG_CONFIG.write().await;
        *log_config = config.log_config;
    }

    let mut root_cert_store = rustls::RootCertStore::empty();
    for cert in rustls_native_certs::load_native_certs().expect("Unable to load certificates") {
        root_cert_store.add(cert)?;
    }

    let mut tls_config = rustls::ClientConfig::builder()
        .with_root_certificates(root_cert_store)
        .with_no_client_auth();
    tls_config.key_log = Arc::new(rustls::KeyLogFile::new());

    if config.tunnel_disable_certificate_check {
        log(Level::Always, format!("{}[Warning]{} TLS certificate check is disabled; the connection is considered insecure", color_code::YELLOW, color_code::RESET).as_str(), "core::main").await;
        tls_config
            .dangerous()
            .set_certificate_verifier(Arc::new(DisableCertVerification {}));
    }

    let tls_connector = TlsConnector::from(Arc::new(tls_config.clone()));

    let tcp_stream = TcpStream::connect((
        config.tunnel_host.to_str().to_string(),
        config.tunnel_host_port,
    ))
    .await
    .expect("Unable to connect to server");

    let tunnel_server_addr = tcp_stream.peer_addr()?;
    let tls_stream = tls_connector
        .connect(config.tunnel_host.clone(), tcp_stream)
        .await
        .expect("Unable to connect to server");

    let cancellation_token = CancellationToken::new();

    let shared = Arc::new(Shared {
        tls_config,
        config: TunnelConfig {
            tunnel_host: config.tunnel_host,
            tunnel_host_port: config.tunnel_host_port,
            tunnel_service: config.tunnel_service,
            tunnel_service_port: config.tunnel_service_port,
            tunnel_username: config.tunnel_username,
            tunnel_password: config.tunnel_password,
            tunnel_token: config.tunnel_token,
        },
    });

    tunnel_client_control(
        Flags {
            global_cancellation_token: cancellation_token.clone(),
            local_cancellation_token: CancellationToken::new(),
        },
        shared.clone(),
        tunnel_server_addr,
        tls_stream
    )
    .await;

    Ok(())
}
