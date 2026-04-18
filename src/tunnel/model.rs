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

use rustls::pki_types::ServerName;
use tokio_util::sync::CancellationToken;

#[derive(Clone)]
pub struct Flags {
    pub global_cancellation_token: CancellationToken,
    pub local_cancellation_token: CancellationToken,
}

pub struct TunnelConfig {
    pub tunnel_host: ServerName<'static>,
    pub tunnel_host_port: u16,
    pub tunnel_service: ServerName<'static>,
    pub tunnel_service_port: u16,
    pub tunnel_username: Option<String>,
    pub tunnel_password: Option<String>,
    pub tunnel_token: Option<String>,
}

pub struct Shared {
    pub tls_config: rustls::ClientConfig,
    pub config: TunnelConfig,
}