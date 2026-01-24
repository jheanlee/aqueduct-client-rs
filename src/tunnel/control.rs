use std::ops::DerefMut;
use std::sync::Arc;
use tokio::select;
use tokio::sync::mpsc;
use crate::config::config_handler::{get_credentials, TunnelCredential};
use crate::message::message::{Message, MessageType, ServiceAuth, ServiceMessage};
use crate::tunnel::io::{read_message, send_message};
use crate::tunnel::model::{Flags, Shared, TunnelStream};
use crate::tunnel::proxy::tunnel_proxy_control;

pub async fn tunnel_client_control(flags: Flags, shared: Arc<Shared>, tunnel_server: Arc<TunnelStream>) {
  let mut buffer = [0u8; 1024];
  let (redirect_id_tx, redirect_id_rx) = mpsc::channel::<String>(32);

  //  auth
  let mut auth_token = shared.config.tunnel_token.clone();
  let (mut auth_username, mut auth_password) = (shared.config.tunnel_username.clone(), shared.config.tunnel_password.clone());
  
  if auth_token.is_none() && (auth_username.is_none() || auth_password.is_none()) {
    match get_credentials() {
      Some(TunnelCredential::Token(token)) => {
        auth_token = Some(token)
      }
      Some(TunnelCredential::Password(username, password)) => {
        auth_username = Some(username);
        auth_password = Some(password);
      }
      None => return
    }
  }
  
  if let Some(token) = auth_token {
    let auth_message = Message::new(
      MessageType::Service,
      serde_json::to_string(&ServiceMessage {
        auth: ServiceAuth::Token { token }
      }).unwrap_or_else(|_| { unreachable!() })
    );
    
    let mut guard = tunnel_server.stream.lock().await;
    match send_message(guard.deref_mut(), &auth_message).await {
      Ok(_) => {},
      Err(_error) => {
        //  TODO log
        flags.local_cancellation_token.cancel();
        return;
      }
    }
  } else if let (Some(username), Some(password)) = (auth_username, auth_password) {
    let auth_message = Message::new(
      MessageType::Service,
      serde_json::to_string(&ServiceMessage {
        auth: ServiceAuth::Password { username, password }
      }).unwrap_or_else(|_| { unreachable!() })
    );

    let mut guard = tunnel_server.stream.lock().await;
    match send_message(guard.deref_mut(), &auth_message).await {
      Ok(_) => {},
      Err(_error) => {
        //  TODO log
        flags.local_cancellation_token.cancel();
        return;
      }
    }
  } else {
    flags.local_cancellation_token.cancel();
    return;
  }

  //  spawn control
  let proxy_control_thread = tokio::spawn(
    tunnel_proxy_control(
      flags.clone(),
      shared.clone(),
      tunnel_server.clone(),
      redirect_id_rx,
    )
  );
  
  loop {
    let read_future = async { 
      let mut guard = tunnel_server.stream.lock().await;
      read_message(guard.deref_mut(), buffer.as_mut()).await
    };
    
    select! {
      result = read_future => {
        match result {
          Ok(message) => {
            match message.message_type {
              MessageType::Heartbeat => {
                let heartbeat_message = Message::new(MessageType::Heartbeat, "".to_string());
                let mut guard = tunnel_server.stream.lock().await;

                match send_message(guard.deref_mut(), &heartbeat_message).await {
                  Ok(_) => {},
                  Err(_error) => {
                    //  TODO log
                    flags.local_cancellation_token.cancel();
                    break;
                  }
                }
              }
              MessageType::Service => {
                //  does not occur under normal circumstances
                flags.local_cancellation_token.cancel();
                break;
              }
              MessageType::Proxy => {
                //  TODO print proxy port
                match redirect_id_tx.send(message.message_string).await {
                  Ok(_) => {}
                  Err(error) => {
                    //  TODO log error
                    flags.local_cancellation_token.cancel();
                  }
                }
              }
              MessageType::Port => {
                //  TODO log
              }
              MessageType::Close => {
                flags.local_cancellation_token.cancel();
                break;
              }
              MessageType::Error => {
                //  TODO log
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
      },
      _global_cancelled = flags.global_cancellation_token.cancelled() => {
        flags.local_cancellation_token.cancel();
        break;
      }
      _local_cancelled = flags.local_cancellation_token.cancelled() => {
        break;
      }
    }
  }

  let _ = proxy_control_thread.await;
  
  //  TODO log connection ended
}