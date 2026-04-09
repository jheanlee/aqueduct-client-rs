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
use crate::config::config_handler::{TunnelCredential, get_credentials};
use crate::message::message::{Message, MessageType, ServiceAuth, ServiceMessage};
use crate::tunnel::io;
use crate::tunnel::io::{read_message, send_message};
use crate::tunnel::model::{Flags, Shared, TunnelStream};
use crate::tunnel::proxy::tunnel_proxy_control;
use std::sync::Arc;
use tokio::select;
use tokio::sync::mpsc;

pub async fn tunnel_client_control(
    flags: Flags,
    shared: Arc<Shared>,
    tunnel_server: Arc<TunnelStream>,
) {
    let mut buffer = vec![0u8; 1024];
    let (redirect_id_tx, redirect_id_rx) = mpsc::channel::<String>(32);

    //  auth
    let mut auth_token = shared.config.tunnel_token.clone();
    let (mut auth_username, mut auth_password) = (
        shared.config.tunnel_username.clone(),
        shared.config.tunnel_password.clone(),
    );

    if auth_token.is_none() && (auth_username.is_none() || auth_password.is_none()) {
        match get_credentials() {
            Some(TunnelCredential::Token(token)) => auth_token = Some(token),
            Some(TunnelCredential::Password(username, password)) => {
                auth_username = Some(username);
                auth_password = Some(password);
            }
            None => return,
        }
    }

    if let Some(token) = auth_token {
        let auth_message = Message::new(
            MessageType::Service,
            serde_json::to_string(&ServiceMessage {
                auth: ServiceAuth::Token { token },
            })
            .unwrap_or_else(|_| unreachable!()),
        );

        let mut guard = tunnel_server.stream.lock().await;
        if let Err(error) = send_message(&mut guard, &auth_message).await {
            error_request_send(flags.clone(), error).await;
            return;
        }
    } else if let (Some(username), Some(password)) = (auth_username, auth_password) {
        let auth_message = Message::new(
            MessageType::Service,
            serde_json::to_string(&ServiceMessage {
                auth: ServiceAuth::Password { username, password },
            })
            .unwrap_or_else(|_| unreachable!()),
        );

        let mut guard = tunnel_server.stream.lock().await;
        if let Err(error) = send_message(&mut guard, &auth_message).await {
            error_request_send(flags.clone(), error).await;
            return;
        }
    } else {
        flags.local_cancellation_token.cancel();
        return;
    }

    //  spawn control
    let proxy_control_thread = tokio::spawn(tunnel_proxy_control(
        flags.clone(),
        shared.clone(),
        tunnel_server.clone(),
        redirect_id_rx,
    ));

    loop {
        let read_future = async {
            let mut guard = tunnel_server.stream.lock().await;
            read_message(&mut guard, &mut buffer).await
        };

        select! {
            biased;
            _global_cancelled = flags.global_cancellation_token.cancelled() => {
                flags.local_cancellation_token.cancel();
                break;
            }
            _local_cancelled = flags.local_cancellation_token.cancelled() => {
                break;
            }
            result = read_future => {
                match result {
                    Ok(message) => {
                        match message.message_type {
                            MessageType::Heartbeat => {
                                log(Level::Debug, "Heartbeat", "tunnel_client_control").await;
                                let heartbeat_message = Message::new(MessageType::Heartbeat, "".to_string());
                                let mut guard = tunnel_server.stream.lock().await;

                                if let Err(error) = send_message(&mut guard, &heartbeat_message).await {
                                    error_request_send(flags.clone(), error).await;
                                    flags.local_cancellation_token.cancel();
                                    break;
                                }
                            }
                            MessageType::Service => {
                                //  does not occur under normal circumstances
                                flags.local_cancellation_token.cancel();
                                break;
                            }
                            MessageType::Proxy => {
                                log(
                                    Level::Debug,
                                    format!(
                                        "Tunnel external user id received: {}",
                                        message.message_string
                                    )
                                    .as_str(),
                                    "tunnel_client_control"
                                )
                                .await;
                                if let Err(error) = redirect_id_tx.send(message.message_string).await {
                                    error_general(flags.clone(), error).await;
                                }
                            }
                            MessageType::Port => {
                                log(
                                    Level::Always,
                                    format!(
                                        "Tunnelled service is now available at {}:{}",
                                        shared.config.tunnel_host.to_str(),
                                        message.message_string
                                    )
                                    .as_str(),
                                    "tunnel_client_control"
                                )
                                .await;
                            }
                            MessageType::Close => {
                                flags.local_cancellation_token.cancel();
                                break;
                            }
                            MessageType::Empty => {
                                //  placeholder
                            }
                            MessageType::Error => {
                                log(
                                    Level::Error,
                                    format!(
                                        "Connection with host closed with an error: {}",
                                        message.message_string
                                    )
                                    .as_str(),
                                    "tunnel::control::tunnel_client_control"
                                )
                                .await;
                                flags.local_cancellation_token.cancel();
                                break;
                            }
                        }
                    }
                    Err(_error) => {
                        flags.local_cancellation_token.cancel();
                        break;
                    }
                }
            }
        }
    }

    let _ = proxy_control_thread.await;

    log(
        Level::Error,
        "Connection with host closed",
        "tunnel::control::tunnel_client_control",
    )
    .await;
}

async fn error_request_send(flags: Flags, error: io::Error) {
    log(
        Level::Error,
        format!("Unable to send request to host: {:?}", error).as_str(),
        "tunnel::control::tunnel_client_control",
    )
    .await;
    flags.local_cancellation_token.cancel();
}

async fn error_general(flags: Flags, error: impl std::fmt::Debug) {
    log(
        Level::Error,
        format!("An error has occurred: {:?}", error).as_str(),
        "tunnel::control::tunnel_client_control",
    )
    .await;
    flags.local_cancellation_token.cancel();
}
