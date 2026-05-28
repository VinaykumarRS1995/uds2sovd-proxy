//! Transport layer — TCP and UDP servers that speak DoIP on the wire.

pub mod tcp;
pub mod udp;

use std::io;
use tcp::Tcp;
use udp::Udp;

/// Lifecycle interface shared by the TCP and UDP transports.
// Justification: This trait is only used with concrete types (Tcp, Udp),
// never as `dyn Transport`, so object-safety is not required.
#[allow(async_fn_in_trait)]
pub trait Transport: Send + Sync {
    async fn start(&self) -> Result<(), io::Error>;
}

/// Top-level server owning both transports.
///
/// DoIP is defined as exactly one TCP and one UDP transport (ISO 13400-2).
pub struct Server {
    tcp: Tcp,
    udp: Udp,
}

impl Server {
    /// Create a server owning both transports.
    pub fn new(tcp: Tcp, udp: Udp) -> Self {
        Self { tcp, udp }
    }

    /// Run both transports concurrently. Shuts down gracefully on SIGINT(SIGTERM will also be handled in the future).
    pub async fn start(&self) -> Result<(), io::Error> {
        tokio::try_join!(self.tcp.start(), self.udp.start())?;
        Ok(())
    }
}
