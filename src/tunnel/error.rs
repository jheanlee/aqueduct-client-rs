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

use crate::message::error::MessageError;

#[derive(Debug)]
pub enum TunnelError {
    MessageError(MessageError),
    IoError(std::io::Error),
    InvalidDnsNameError(rustls::pki_types::InvalidDnsNameError),
}

impl std::fmt::Display for TunnelError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MessageError(e) => write!(f, "MessageError: {e}"),
            Self::IoError(e) => write!(f, "IoError: {e}"),
            Self::InvalidDnsNameError(e) => write!(f, "InvalidDnsNameError: {e}"),
        }
    }
}

impl std::error::Error for TunnelError {}

impl From<MessageError> for TunnelError {
    fn from(error: MessageError) -> Self {
        Self::MessageError(error)
    }
}

impl From<std::io::Error> for TunnelError {
    fn from(error: std::io::Error) -> Self {
        Self::IoError(error)
    }
}

impl From<rustls::pki_types::InvalidDnsNameError> for TunnelError {
    fn from(error: rustls::pki_types::InvalidDnsNameError) -> Self {
        Self::InvalidDnsNameError(error)
    }
}
