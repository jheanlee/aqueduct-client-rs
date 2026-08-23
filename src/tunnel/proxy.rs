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
use crate::message::r#type::{Message, MessageType, ProxyMessage};
use crate::message::v1::common::MESSAGE_VERSION_V1;
use crate::tunnel::error::TunnelError;
use crate::tunnel::message_handler::send_message;
use crate::tunnel::model::Shared;
use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use bytes::{Bytes, BytesMut};
use hmac::{Hmac, KeyInit, Mac};
use rustls::pki_types::ServerName;
use sha2::Sha256;
use socket2::SockRef;
use std::io::ErrorKind;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::copy_bidirectional_with_sizes;
use tokio::net::TcpStream;
use tokio::select;
use tokio::sync::mpsc;
use tokio::task::JoinSet;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;
use tokio_util::codec::LengthDelimitedCodec;
use tokio_util::future::FutureExt;
use tokio_util::sync::CancellationToken;
use tracing::{debug, instrument, warn};

///   Controls all proxy threads, connects to service for each tunnelled external user
pub async fn tunnel_proxy_control(
    cancellation_token: CancellationToken,
    shared: Arc<Shared>,
    secret: Bytes,
    tunnel_server_control_addr: SocketAddr,
    mut redirect_id_rx: mpsc::Receiver<String>,
) {
    let mut proxy_threads = JoinSet::new();

    loop {
        select! {
            biased;
            _ = cancellation_token.cancelled() => {
                break;
            },
            _ = proxy_threads.join_next(), if !proxy_threads.is_empty() => {},
            redirect_id = redirect_id_rx.recv() => {
                let Some(redirect_id) = redirect_id else {
                    cancellation_token.cancel();
                    break;
                };
                proxy_threads.spawn(
                    tunnel_proxy_session(
                        cancellation_token.child_token(),
                        shared.clone(),
                        secret.clone(),
                        tunnel_server_control_addr,
                        redirect_id
                    )
                );
            }
        }
    }

    let _ = timeout(Duration::from_secs(60), proxy_threads.join_all()).await;
}

#[instrument(
    skip_all,
    fields(
        tunnel_service = format!(
            "{}:{}",
            shared.config.tunnel_service.to_str(),
            shared.config.tunnel_service_port
        ),
        proxy_id = redirect_id
    )
)]
pub async fn tunnel_proxy_session(
    cancellation_token: CancellationToken,
    shared: Arc<Shared>,
    secret: Bytes,
    tunnel_server_control_addr: SocketAddr,
    redirect_id: String,
) {
    let service_connect_future = async {
        let tcp_stream = TcpStream::connect((
            shared.config.tunnel_service.to_str().to_string(),
            shared.config.tunnel_service_port,
        ))
        .await?;
        let socket_ref = SockRef::from(&tcp_stream);
        socket_ref.set_tcp_nodelay(true).unwrap_or_else(|error| {
            warn!("Unable to configure the service connection: {:?}", error);
        });
        Ok::<TcpStream, TunnelError>(tcp_stream)
    };

    let server_connect_future = async {
        let tls_connector = TlsConnector::from(Arc::new(shared.tls_config.clone()));
        let tcp_stream = TcpStream::connect(tunnel_server_control_addr).await?;
        let tls_stream = tls_connector
            .connect(
                ServerName::try_from(tunnel_server_control_addr.ip().to_string())?,
                tcp_stream,
            )
            .await?;
        Ok::<TlsStream<TcpStream>, TunnelError>(tls_stream)
    };

    let (service_server_stream, server_proxy_stream) =
        tokio::join!(service_connect_future, server_connect_future);

    let tunnel_server_stream = match server_proxy_stream {
        Ok(stream) => stream,
        Err(error) => {
            warn!("Unable to connect to the tunnel server: {:?}", error);
            return;
        }
    };

    //  hash
    let mut hmac: Hmac<Sha256> =
        Hmac::new_from_slice(secret.as_ref()).expect("Hmac does not require key size");
    hmac.update(redirect_id.as_bytes());
    let id_hash = BASE64_STANDARD.encode(hmac.finalize().as_bytes());

    //  proxy message (claim external client)
    //  temporarily change tunnel_server_stream into framed
    let mut tunnel_server_stream = LengthDelimitedCodec::builder()
        .length_field_offset(0)
        .length_field_type::<u8>()
        .length_adjustment(0)
        .new_framed(tunnel_server_stream);
    if let Err(error) = async {
        let message = Message::new(
            MESSAGE_VERSION_V1,
            MessageType::Proxy,
            serde_json::to_string(&ProxyMessage {
                proxy_id: id_hash.clone(),
            })
            .expect("ProxyMessage must be serializable")
            .as_str(),
        );
        let mut buffer = BytesMut::with_capacity(256);
        send_message(
            &mut tunnel_server_stream,
            &mut buffer,
            &message,
            &cancellation_token,
        )
        .await
    }
    .await
    {
        warn!("Unable to send request to the tunnel server: {:?}", error);
        cancellation_token.cancel();
        return;
    }

    //  get the inner tunnel_server_stream back
    let mut tunnel_server_stream = tunnel_server_stream.into_inner();

    //  service stream
    let mut service_server_stream = match service_server_stream {
        Ok(stream) => stream,
        Err(error) => {
            warn!("Unable to connect to the tunnelled service: {:?}", error);
            return;
        }
    };

    //  proxy starts
    debug!("TCP proxying started");

    const BUFFER_SIZE: usize = 32768;

    let io_copy = copy_bidirectional_with_sizes(
        &mut tunnel_server_stream,
        &mut service_server_stream,
        BUFFER_SIZE,
        BUFFER_SIZE,
    )
    .with_cancellation_token(&cancellation_token);

    match io_copy.await {
        Some(Ok(_)) => { /* gracefully closed by either service or client */ }
        Some(Err(error)) => {
            match error.kind() {
                ErrorKind::BrokenPipe => {
                    //  often occurs under normal circumstances
                }
                ErrorKind::ConnectionReset => {
                    //  often occurs under normal circumstances
                }
                ErrorKind::UnexpectedEof => {
                    //  often occurs under normal circumstances
                }
                _ => {
                    debug!("TCP proxying ended with error: {:?}", error);
                }
            }
        }
        None => { /* cancelled by cancellation token */ }
    }

    debug!("TCP proxying ended");
}
