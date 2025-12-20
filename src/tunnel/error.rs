use crate::message::error::MessageError;

#[derive(Debug)]
pub enum TunnelError {
  MessageError(MessageError),
  IoError(std::io::Error),
  InvalidDnsNameError(rustls::pki_types::InvalidDnsNameError),
  NoPortsAvailable,
}

impl std::fmt::Display for TunnelError {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    match self {
      Self::MessageError(e) => write!(f, "MessageError: {e}"),
      Self::IoError(e) => write!(f, "IoError: {e}"),
      Self::InvalidDnsNameError(e) => write!(f, "InvalidDnsNameError: {e}"),
      Self::NoPortsAvailable => write!(f, "no ports available"),
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
  fn from(error: rustls::pki_types::InvalidDnsNameError) -> Self { Self::InvalidDnsNameError(error) }
}