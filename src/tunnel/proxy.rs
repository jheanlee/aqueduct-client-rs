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

use crate::common::log::{Level, log};
use crate::message::message::{Message, MessageType, ProxyMessage};
use crate::tunnel::error::TunnelError;
use crate::tunnel::io;
use crate::tunnel::io::send_message;
use crate::tunnel::model::{Flags, Shared, TunnelStream};
use rustls::pki_types::ServerName;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::select;
use tokio::sync::mpsc;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;
use tokio_util::task::JoinMap;

///   Controls all proxy threads, connects to service for each tunnelled external user
pub async fn tunnel_proxy_control(
    flags: Flags,
    shared: Arc<Shared>,
    tunnel_server: Arc<TunnelStream>,
    mut redirect_id_rx: mpsc::Receiver<String>,
) {
    let mut proxy_threads = JoinMap::new();

    loop {
        select! {
            redirect_id = redirect_id_rx.recv() => {
                let Some(redirect_id) = redirect_id else {
                    continue;
                };
                proxy_threads.spawn(
                    redirect_id.clone(),
                    tunnel_proxy_session(
                        flags.clone(),
                        shared.clone(),
                        tunnel_server.clone(),
                        redirect_id
                    )
                );
            }
            _global_cancalled = flags.global_cancellation_token.cancelled() => {
                flags.local_cancellation_token.cancel();
                break;
            },
            _client_cancealled = flags.local_cancellation_token.cancelled() => {
                break;
            },
        }
    }
}

pub async fn tunnel_proxy_session(
    flags: Flags,
    shared: Arc<Shared>,
    tunnel_server: Arc<TunnelStream>,
    redirect_id: String,
) {
    let service_connect_future = async {
        let tcp_stream = TcpStream::connect((
            shared.config.tunnel_service.to_str().to_string(),
            shared.config.tunnel_service_port,
        ))
        .await?;
        Ok::<TcpStream, TunnelError>(tcp_stream)
    };

    let server_connect_future = async {
        let tls_connector = TlsConnector::from(Arc::new(shared.tls_config.clone()));
        let tcp_stream = TcpStream::connect(tunnel_server.addr).await?;
        let tls_stream = tls_connector
            .connect(
                ServerName::try_from(tunnel_server.addr.ip().to_string())?,
                tcp_stream,
            )
            .await?;
        Ok::<TlsStream<TcpStream>, TunnelError>(tls_stream)
    };

    let service_server_stream = service_connect_future.await;
    let server_proxy_stream = server_connect_future.await;

    match server_proxy_stream {
        Ok(mut tunnel_server_stream) => {
            let message = Message::new(
                MessageType::Proxy,
                serde_json::to_string(&ProxyMessage {
                    proxy_id: redirect_id.clone(),
                })
                .unwrap_or_else(|_| unreachable!()),
            );
            if let Err(error) = send_message(&mut tunnel_server_stream, &message).await {
                warning_request_send_proxy_session(flags.clone(), error).await;
                return;
            }

            match service_server_stream {
                Ok(mut service_server_stream) => {
                    //  proxy starts
                    log(
                        Level::Debug,
                        format!(
                            "TCP proxying started {}:{} <=> {} (redirect id: {})",
                            shared.config.tunnel_service.to_str(),
                            shared.config.tunnel_service_port,
                            tunnel_server.addr.to_string(),
                            redirect_id
                        )
                        .as_str(),
                        "tunnel::proxy::tunnel_proxy_session",
                    )
                    .await;

                    let mut tunnel_buffer = [0u8; 32768];
                    let mut service_buffer = [0u8; 32768];

                    loop {
                        tunnel_buffer.fill(0u8);
                        service_buffer.fill(0u8);

                        select! {
                            tunnel_server_read = tunnel_server_stream.read(&mut tunnel_buffer) => {
                                //  tunnel_server (external_client) -> service
                                match tunnel_server_read {
                                    Ok(bytes_read) => {
                                        let write_result = service_server_stream.write_all(&tunnel_buffer[..bytes_read]).await;
                                        if let Err(error) = write_result {
                                            log(
                                                Level::Debug,
                                                format!(
                                                    "Proxy write failed {}:{} <= {} (redirect id: {}): {:?}",
                                                    shared.config.tunnel_service.to_str(),
                                                    shared.config.tunnel_service_port,
                                                    tunnel_server.addr.to_string(),
                                                    redirect_id,
                                                    error
                                                )
                                                .as_str(),
                                                "tunnel::proxy::tunnel_proxy_session"
                                            )
                                            .await;
                                            break;
                                        }
                                    }
                                    Err(error) => {
                                        log(
                                            Level::Debug,
                                            format!(
                                                "Proxy read failed {}:{} <= {} (redirect id: {}): {:?}",
                                                shared.config.tunnel_service.to_str(),
                                                shared.config.tunnel_service_port,
                                                tunnel_server.addr.to_string(),
                                                redirect_id,
                                                error
                                            )
                                            .as_str(),
                                            "tunnel::proxy::tunnel_proxy_session"
                                        )
                                        .await;
                                        break;
                                    }
                                }
                            }
                            service_server_read = service_server_stream.read(&mut service_buffer) => {
                                //  service -> tunnel_server (external_client)
                                match service_server_read {
                                    Ok(bytes_read) => {
                                        let write_result = tunnel_server_stream.write_all(&service_buffer[..bytes_read]).await;
                                        if let Err(error) = write_result {
                                            log(
                                                Level::Debug,
                                                format!(
                                                    "Proxy write failed {}:{} => {} (redirect id: {}): {:?}",
                                                    shared.config.tunnel_service.to_str(),
                                                    shared.config.tunnel_service_port,
                                                    tunnel_server.addr.to_string(),
                                                    redirect_id,
                                                    error
                                                )
                                                .as_str(),
                                                "tunnel::proxy::tunnel_proxy_session"
                                            )
                                            .await;
                                            break;
                                        }
                                    }
                                    Err(error) => {
                                        log(
                                            Level::Debug,
                                            format!(
                                                "Proxy read failed {}:{} => {} (redirect id: {}): {:?}",
                                                shared.config.tunnel_service.to_str(),
                                                shared.config.tunnel_service_port,
                                                tunnel_server.addr.to_string(),
                                                redirect_id,
                                                error
                                            )
                                            .as_str(),
                                            "tunnel::proxy::tunnel_proxy_session"
                                        )
                                        .await;
                                        break;
                                    }
                                }
                            }
                            _client_cancealled = flags.local_cancellation_token.cancelled() => {
                                break;
                            }
                        }
                    }

                    log(
                        Level::Debug,
                        format!(
                            "TCP proxying ended {}:{} <=> {} (redirect id: {})",
                            shared.config.tunnel_service.to_str(),
                            shared.config.tunnel_service_port,
                            tunnel_server.addr.to_string(),
                            redirect_id
                        )
                        .as_str(),
                        "tunnel::proxy::tunnel_proxy_session",
                    )
                    .await;
                }
                Err(error) => {
                    warning_general(flags.clone(), error).await;
                    return;
                }
            }
        }
        Err(error) => {
            warning_general(flags.clone(), error).await;
            return;
        }
    }
}

async fn warning_request_send_proxy_session(flags: Flags, error: io::Error) {
    log(
        Level::Warning,
        format!("Unable to send request to host: {:?}", error).as_str(),
        "tunnel::proxy::tunnel_proxy_session",
    )
    .await;
    flags.local_cancellation_token.cancel();
}

async fn warning_general(flags: Flags, error: impl std::fmt::Debug) {
    log(
        Level::Warning,
        format!("An error has occurred: {:?}", error).as_str(),
        "tunnel::proxy::tunnel_proxy_session",
    )
    .await;
    flags.local_cancellation_token.cancel();
}
