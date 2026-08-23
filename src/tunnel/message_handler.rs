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
use crate::message::common::MessageBuilder;
use crate::message::r#type::Message;
use crate::tunnel::error::TunnelError;
use bytes::{Bytes, BytesMut};
use futures::{Sink, SinkExt};
use tokio_util::future::FutureExt;
use tokio_util::sync::CancellationToken;

pub async fn send_message<T>(
    writer: &mut T,
    buffer: &mut BytesMut,
    message: &Message,
    cancellation_token: &CancellationToken,
) -> Result<(), TunnelError>
where
    T: Sink<Bytes, Error = std::io::Error> + Unpin,
{
    MessageBuilder::encode(message, buffer)?;

    writer
        .send(buffer.split().freeze())
        .with_cancellation_token(cancellation_token)
        .await
        .unwrap_or(Ok(()))?;
    Ok(())
}
