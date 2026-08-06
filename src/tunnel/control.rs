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
use crate::message::common::MessageParser;
use crate::message::message::{
    ClientServiceMessage, Message, MessageType, ServiceAuth, ServiceMessage,
};
use crate::message::v1::common::MESSAGE_VERSION_V1;
use crate::tunnel::error::TunnelError;
use crate::tunnel::message_handler::send_message;
use crate::tunnel::model::{Flags, Shared};
use crate::tunnel::proxy::tunnel_proxy_control;
use futures::StreamExt;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio::select;
use tokio::sync::mpsc;
use tokio_rustls::client::TlsStream;
use tokio_util::bytes::BytesMut;
use tokio_util::codec::LengthDelimitedCodec;
use tracing::{debug, error, warn};

pub async fn tunnel_client_control(
    flags: Flags,
    shared: Arc<Shared>,
    tunnel_server_control_addr: SocketAddr,
    tunnel_server_control_stream: TlsStream<TcpStream>,
) {
    let (redirect_id_tx, redirect_id_rx) = mpsc::channel::<String>(1024);
    let mut redirect_id_rx = Some(redirect_id_rx);

    //  writer
    let (mut tunnel_service_control_writer, mut tunnel_service_control_reader) =
        LengthDelimitedCodec::builder()
            .length_field_offset(0)
            .length_field_type::<u8>()
            .length_adjustment(0)
            .new_framed(tunnel_server_control_stream)
            .split();

    let mut write_buffer = BytesMut::with_capacity(255);

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
            MESSAGE_VERSION_V1,
            MessageType::Service,
            serde_json::to_string(&ServiceMessage {
                auth: ServiceAuth::Token { token },
            })
            .unwrap_or_else(|_| unreachable!())
            .as_str(),
        );

        if let Err(error) = send_message(
            &mut tunnel_service_control_writer,
            &mut write_buffer,
            &auth_message,
            flags.local_cancellation_token.clone(),
        )
        .await
        {
            error!("Unable to send request to the server: {:?}", error);
            flags.local_cancellation_token.cancel();
        }
    } else if let (Some(username), Some(password)) = (auth_username, auth_password) {
        let auth_message = Message::new(
            MESSAGE_VERSION_V1,
            MessageType::Service,
            serde_json::to_string(&ServiceMessage {
                auth: ServiceAuth::Password { username, password },
            })
            .unwrap_or_else(|_| unreachable!())
            .as_str(),
        );

        if let Err(error) = send_message(
            &mut tunnel_service_control_writer,
            &mut write_buffer,
            &auth_message,
            flags.local_cancellation_token.clone(),
        )
        .await
        {
            error!("Unable to send request to the server: {:?}", error);
            flags.local_cancellation_token.cancel();
        }
    } else {
        flags.local_cancellation_token.cancel();
        return;
    }

    //  spawn control
    let mut proxy_control_task = None;

    loop {
        let read_future = async {
            let read_result = tunnel_service_control_reader.next().await;
            match read_result {
                Some(Ok(mut bytes_read)) => match MessageParser::parse(bytes_read.split().freeze())
                {
                    Ok(message) => Ok(message),
                    Err(error) => Err(error.into()),
                },
                Some(Err(error)) => Err(error.into()),
                None => Err(TunnelError::ServerClosed),
            }
        };

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
                                let heartbeat_message = Message::new(MESSAGE_VERSION_V1, MessageType::Heartbeat, "");
                                debug!("Heartbeat sent");

                                if let Err(error) = send_message(&mut tunnel_service_control_writer, &mut write_buffer, &heartbeat_message, flags.local_cancellation_token.clone()).await {
                                    error!("Unable to send request to the server: {:?}", error);
                                    flags.local_cancellation_token.cancel();
                                    break;
                                }
                            }
                            MessageType::Service => {
                                //  validation and parsing
                                let Ok(payload_str) = str::from_utf8(&message.message_payload) else {
                                    warn!("Received malformed message from the server");
                                    flags.local_cancellation_token.cancel();
                                    break;
                                };

                                let Ok(service_message) = serde_json::from_str::<ClientServiceMessage>(payload_str) else {
                                    warn!("Received malformed message from the server");
                                    flags.local_cancellation_token.cancel();
                                    break;
                                };

                                //  port opened, spawn tasks
                                let Some(redirect_id_rx) = redirect_id_rx.take() else {
                                    warn!("Received malformed message from the server");
                                    flags.local_cancellation_token.cancel();
                                    break;
                                };

                                warn!(
                                    "Tunnelled service is now available at {}:{}",
                                    shared.config.tunnel_host.to_str(),
                                    service_message.port
                                );

                                proxy_control_task = Some(tokio::spawn(tunnel_proxy_control(
                                    flags.clone(),
                                    shared.clone(),
                                    service_message.secret,
                                    tunnel_server_control_addr,
                                    redirect_id_rx,
                                )));
                            }
                            MessageType::Proxy => {
                                //  validation and parsing
                                let Ok(payload_str) = str::from_utf8(&message.message_payload) else {
                                    warn!("Received malformed message from the server");
                                    flags.local_cancellation_token.cancel();
                                    break;
                                };

                                //  send new id to task
                                debug!("Tunnel external user id received: {}", payload_str);
                                if let Err(error) = redirect_id_tx.send(payload_str.to_string()).await {
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
                                error!("Control connection with the server closed with an error: {}", str::from_utf8(&message.message_payload).unwrap_or("Invalid string"));
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

    if let Some(proxy_control_task) = proxy_control_task {
        let _ = proxy_control_task.await;
    }

    warn!("Control connection with the server closed");
}

async fn error_general(flags: Flags, error: impl std::fmt::Debug) {
    error!("An error has occurred: {:?}", error);
    flags.local_cancellation_token.cancel();
}
