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
use crate::message::r#type::{
    ClientServiceMessage, Message, MessageType, ServiceAuth, ServiceMessage,
};
use crate::message::v1::common::MESSAGE_VERSION_V1;
use crate::tunnel::error::TunnelError;
use crate::tunnel::message_handler::send_message;
use crate::tunnel::model::Shared;
use crate::tunnel::proxy::tunnel_proxy_control;
use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use futures::{SinkExt, StreamExt};
use std::io::ErrorKind;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::select;
use tokio::sync::mpsc;
use tokio::time::timeout;
use tokio_rustls::client::TlsStream;
use tokio_util::bytes::BytesMut;
use tokio_util::codec::LengthDelimitedCodec;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info};

pub async fn tunnel_client_control(
    cancellation_token: CancellationToken,
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
            .expect("ServiceMessage must be serializable")
            .as_str(),
        );

        if let Err(error) = send_message(
            &mut tunnel_service_control_writer,
            &mut write_buffer,
            &auth_message,
            &cancellation_token,
        )
        .await
        {
            error!("Unable to send request to the server: {:?}", error);
            cancellation_token.cancel();
        }
    } else if let (Some(username), Some(password)) = (auth_username, auth_password) {
        let auth_message = Message::new(
            MESSAGE_VERSION_V1,
            MessageType::Service,
            serde_json::to_string(&ServiceMessage {
                auth: ServiceAuth::Password { username, password },
            })
            .expect("ServiceMessage must be serializable")
            .as_str(),
        );

        if let Err(error) = send_message(
            &mut tunnel_service_control_writer,
            &mut write_buffer,
            &auth_message,
            &cancellation_token,
        )
        .await
        {
            error!("Unable to send request to the server: {:?}", error);
            cancellation_token.cancel();
        }
    } else {
        cancellation_token.cancel();
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
            _local_cancelled = cancellation_token.cancelled() => {
                break;
            }
            result = read_future => {
                match result {
                    Ok(message) => {
                        match message.message_type {
                            MessageType::Heartbeat => {
                                let heartbeat_message = Message::new(MESSAGE_VERSION_V1, MessageType::Heartbeat, "");
                                debug!("Heartbeat sent");

                                if let Err(error) = send_message(
                                    &mut tunnel_service_control_writer,
                                    &mut write_buffer,
                                    &heartbeat_message,
                                    &cancellation_token.clone()
                                ).await {
                                    error!("Unable to send request to the server: {:?}", error);
                                    break;
                                }
                            }
                            MessageType::Service => {
                                //  validation and parsing
                                let Ok(payload_str) = str::from_utf8(&message.message_payload) else {
                                    error!("Received malformed message from the server");
                                    break;
                                };

                                let Ok(service_message) = serde_json::from_str::<ClientServiceMessage>(payload_str) else {
                                    error!("Received malformed message from the server");
                                    break;
                                };

                                let Ok(secret) = BASE64_STANDARD.decode(service_message.secret) else {
                                    error!("Received invalid secret from the server");
                                    break;
                                };

                                //  port opened, spawn tasks
                                let Some(redirect_id_rx) = redirect_id_rx.take() else {
                                    error!("Received malformed message from the server");
                                    break;
                                };

                                info!(
                                    "Service {}:{} is now available at {}:{}",
                                    shared.config.tunnel_service.to_str(),
                                    shared.config.tunnel_service_port,
                                    shared.config.tunnel_host.to_str(),
                                    service_message.port
                                );

                                proxy_control_task = Some(tokio::spawn(tunnel_proxy_control(
                                    cancellation_token.clone(),
                                    shared.clone(),
                                    secret.into(),
                                    tunnel_server_control_addr,
                                    redirect_id_rx,
                                )));
                            }
                            MessageType::Proxy => {
                                //  validation and parsing
                                let Ok(payload_str) = str::from_utf8(&message.message_payload) else {
                                    error!("Received malformed message from the server");
                                    break;
                                };

                                //  send new id to task
                                debug!("Tunnel external user id received: {}", payload_str);

                                if let Err(error) = redirect_id_tx.send(payload_str.to_string()).await {
                                    error_general(&cancellation_token, error).await;
                                }
                            }
                            MessageType::Close => {
                                info!("Received control close message");
                                break;
                            }
                            MessageType::Empty => {
                                //  placeholder
                            }
                            MessageType::Error => {
                                error!("Control connection terminated: {}", str::from_utf8(&message.message_payload).unwrap_or("Invalid string"));
                                break;
                            }
                        }
                    }
                    Err(error) => {
                        match error {
                            TunnelError::IoError(error) if matches!(error.kind(), ErrorKind::BrokenPipe | ErrorKind::ConnectionReset | ErrorKind::UnexpectedEof) => {
                                info!("Control connection terminated: {}", error.kind());
                            }
                            _ => {
                                error!("Control connection terminated: {:?}", error);
                            }
                        }
                        break;
                    }
                }
            }
        }
    }

    cancellation_token.cancel();
    info!("Shutting down");

    let _ = timeout(
        Duration::from_millis(1000),
        send_message(
            &mut tunnel_service_control_writer,
            &mut write_buffer,
            &Message::new(MESSAGE_VERSION_V1, MessageType::Close, ""),
            &cancellation_token.clone(),
        ),
    )
    .await;

    let _ = tunnel_service_control_writer.flush().await;
    let mut stream = tunnel_service_control_reader
        .reunite(tunnel_service_control_writer)
        .expect("`tunnel_service_control_reader` and `tunnel_service_control_writer` must be corresponding halves")
        .into_inner();
    let _ = stream.shutdown().await;
    drop(stream);

    if let Some(proxy_control_task) = proxy_control_task {
        let _ = proxy_control_task.await;
        info!("Tunnel closed");
    }

    info!("Control connection closed");
}

async fn error_general(cancellation_token: &CancellationToken, error: impl std::fmt::Debug) {
    error!("An error has occurred: {:?}", error);
    cancellation_token.cancel();
}
