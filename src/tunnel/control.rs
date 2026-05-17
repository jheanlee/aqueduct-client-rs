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
use crate::message::message::{
    ClientServiceMessage, Message, MessageType, ServiceAuth, ServiceMessage,
};
use crate::tunnel::io;
use crate::tunnel::io::{read_message, send_message};
use crate::tunnel::model::{Flags, Shared};
use crate::tunnel::proxy::tunnel_proxy_control;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio::select;
use tokio::sync::mpsc;
use tokio_rustls::client::TlsStream;
use tracing::{debug, error, warn};

pub async fn tunnel_client_control(
    flags: Flags,
    shared: Arc<Shared>,
    tunnel_server_control_addr: SocketAddr,
    tunnel_server_control_stream: TlsStream<TcpStream>,
) {
    let (redirect_id_tx, redirect_id_rx) = mpsc::channel::<String>(1024);
    let mut redirect_id_rx = Some(redirect_id_rx);

    let (mut tunnel_server_control_rx, mut tunnel_server_control_tx) =
        tokio::io::split(tunnel_server_control_stream);

    //  auth
    let auth_token = shared.config.tunnel_token.clone();
    let (auth_username, auth_password) = (
        shared.config.tunnel_username.clone(),
        shared.config.tunnel_password.clone(),
    );

    if auth_token.is_none() && (auth_username.is_none() || auth_password.is_none()) {
        return;
    }

    if let Some(token) = auth_token {
        let auth_message = Message::new(
            MessageType::Service,
            serde_json::to_string(&ServiceMessage {
                auth: ServiceAuth::Token { token },
            })
            .unwrap_or_else(|_| unreachable!()),
        );

        if let Err(error) = send_message(&mut tunnel_server_control_tx, &auth_message).await {
            error_request_send(flags.clone(), error).await;
        }
    } else if let (Some(username), Some(password)) = (auth_username, auth_password) {
        let auth_message = Message::new(
            MessageType::Service,
            serde_json::to_string(&ServiceMessage {
                auth: ServiceAuth::Password { username, password },
            })
            .unwrap_or_else(|_| unreachable!()),
        );

        if let Err(error) = send_message(&mut tunnel_server_control_tx, &auth_message).await {
            error_request_send(flags.clone(), error).await;
        }
    } else {
        flags.local_cancellation_token.cancel();
        return;
    }

    //  spawn control
    let mut proxy_control_thread = None;

    loop {
        let read_future = async { read_message(&mut tunnel_server_control_rx).await };

        select! {
            biased;
            _local_cancelled = flags.local_cancellation_token.cancelled() => {
                break;
            }
            result = read_future => {
                match result {
                    Ok(message) => {
                        match message.message_type {
                            MessageType::Heartbeat => {
                                let heartbeat_message = Message::new(MessageType::Heartbeat, "".to_string());
                                debug!("Heartbeat sent");

                                if let Err(error) = send_message(&mut tunnel_server_control_tx, &heartbeat_message).await {
                                    error_request_send(flags.clone(), error).await;
                                    flags.local_cancellation_token.cancel();
                                    break;
                                }
                            }
                            MessageType::Service => {
                                let Ok(service_message) = serde_json::from_str::<ClientServiceMessage>(message.message_string.as_str()) else {
                                    warn!("Received malformed message from the server");
                                    break;
                                };

                                let Some(redirect_id_rx) = redirect_id_rx.take() else {
                                    warn!("Received malformed message from the server");
                                    break;
                                };

                                warn!(
                                    "Tunnelled service is now available at {}:{}",
                                    shared.config.tunnel_host.to_str(),
                                    service_message.port
                                );

                                proxy_control_thread = Some(tokio::spawn(tunnel_proxy_control(
                                    flags.clone(),
                                    shared.clone(),
                                    service_message.secret,
                                    tunnel_server_control_addr,
                                    redirect_id_rx,
                                )));
                            }
                            MessageType::Proxy => {
                                debug!("Tunnel external user id received: {}", message.message_string);
                                if let Err(error) = redirect_id_tx.send(message.message_string).await {
                                    error_general(flags.clone(), error).await;
                                }
                            }
                            MessageType::Close => {
                                flags.local_cancellation_token.cancel();
                                break;
                            }
                            MessageType::Empty => {
                                //  placeholder
                            }
                            MessageType::Error => {
                                error!("Control connection with the server closed with an error: {:?}", message.message_string);
                                flags.local_cancellation_token.cancel();
                                break;
                            }
                        }
                    }
                    Err(error) => {
                        error!("Control connection with the server closed with an error: {:?}", error);
                        flags.local_cancellation_token.cancel();
                        break;
                    }
                }
            }
        }
    }

    if let Some(proxy_control_thread) = proxy_control_thread {
        let _ = proxy_control_thread.await;
    }

    warn!("Control connection with the server closed");
}

async fn error_request_send(flags: Flags, error: io::Error) {
    error!("Unable to send request to the server: {:?}", error);
    flags.local_cancellation_token.cancel();
}

async fn error_general(flags: Flags, error: impl std::fmt::Debug) {
    error!("An error has occurred: {:?}", error);
    flags.local_cancellation_token.cancel();
}
