use std::ops::DerefMut;
use std::sync::Arc;
use tokio::select;
use tokio::sync::mpsc;
use crate::message::message::{Message, MessageType};
use crate::tunnel::io::{read_message, send_message};
use crate::tunnel::model::{Flags, Shared, TunnelStream};
use crate::tunnel::proxy::tunnel_proxy_control;

pub async fn tunnel_client_control(flags: Flags, shared: Arc<Shared>, tunnel_server: Arc<TunnelStream>) {
  let mut buffer = [0u8; 1024];
  let (redirect_id_tx, redirect_id_rx) = mpsc::channel::<String>(32);
  let (abort_id_tx, abort_id_rx) = mpsc::channel::<String>(32);

  //  TODO send connection message and auth
  todo!();

  let proxy_control_thread = tokio::spawn(
    tunnel_proxy_control(
      flags.clone(),
      shared.clone(),
      tunnel_server.clone(),
      redirect_id_rx,
      abort_id_rx //  TODO: abort from errors
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