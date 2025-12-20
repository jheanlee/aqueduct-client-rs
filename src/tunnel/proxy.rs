use std::sync::Arc;
use rustls::pki_types::ServerName;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::select;
use tokio::sync::mpsc;
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;
use tokio_util::task::JoinMap;
use crate::message::message::{Message, MessageType};
use crate::tunnel::error::TunnelError;
use crate::tunnel::io::send_message;
use crate::tunnel::model::{Flags, Shared, TunnelStream};

///   Controls all proxy threads, connects to service for each tunnelled external user
pub async fn tunnel_proxy_control (
  flags: Flags,
  shared: Arc<Shared>,
  tunnel_server: Arc<TunnelStream>,
  mut redirect_id_rx: mpsc::Receiver<String>,
  mut abort_rx: mpsc::Receiver<String>
) {
  let mut proxy_threads = JoinMap::new();

  loop {
    select! {
      redirect_id = redirect_id_rx.recv() => {
        match redirect_id {
          Some(redirect_id) => {
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
          None => {}
        }
      }
      abort_id = abort_rx.recv() => {
        match abort_id {
          Some(abort_id) => { proxy_threads.abort(&abort_id); }
          None => {}
        }
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

pub async fn tunnel_proxy_session (
  flags: Flags,
  shared: Arc<Shared>,
  tunnel_server: Arc<TunnelStream>,
  redirect_id: String
) {

  let service_connect_future = async {
    let tls_connector = TlsConnector::from(Arc::new(shared.tls_config.clone()));
    let tcp_stream = TcpStream::connect(tunnel_server.addr).await?;
    Ok::<TcpStream, TunnelError>(tcp_stream)
  };

  let server_connect_future = async {
    let tls_connector = TlsConnector::from(Arc::new(shared.tls_config.clone()));
    let tcp_stream = TcpStream::connect(tunnel_server.addr).await?;
    let tls_stream = tls_connector.connect(
      ServerName::try_from(tunnel_server.addr.to_string())?, //  TODO test
      tcp_stream
    ).await?;
    Ok::<TlsStream<TcpStream>, TunnelError>(tls_stream)
  };

  let service_server_stream = service_connect_future.await;
  let server_proxy_stream = server_connect_future.await;

  match server_proxy_stream {
    Ok(mut tunnel_server_stream) => {
      let message = Message::new(MessageType::Proxy, redirect_id);
      match send_message(&mut tunnel_server_stream, &message).await {
        Ok(_) => {},
        Err(error) => {
          //  TODO log
          return;
        }
      }

      match service_server_stream {
        Ok(mut service_server_stream) => {
          //  proxy starts
          //  TODO log proxy started

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
                    match write_result {
                      Ok(_) => {}
                      Err(error) => {
                        //  TODO log closed (debug)
                        break;
                      }
                    }
                  }
                  Err(error) => {
                    //  TODO log closed (debug)
                    break;
                  }
                }
              }
              service_server_read = service_server_stream.read(&mut service_buffer) => {
                //  service -> tunnel_server (external_client)
                match service_server_read {
                  Ok(bytes_read) => {
                    let write_result = tunnel_server_stream.write_all(&tunnel_buffer[..bytes_read]).await;
                    match write_result {
                      Ok(_) => {}
                      Err(error) => {
                        //  TODO log closed (debug)
                        break;
                      }
                    }
                  }
                  Err(error) => {
                    //  TODO log closed (debug)
                    break;
                  }
                }
              }
              _client_cancealled = flags.local_cancellation_token.cancelled() => {
                break;
              }
            }
          }

          //  TODO log proxy ended
        }
        Err(error) => {
          //  TODO log
          return;
        }
      }
    }
    Err(error) => {
      //  TODO log
      return;
    }
  }
}