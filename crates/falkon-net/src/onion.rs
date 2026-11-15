use falkon_core::error::FalkonError;

use crate::transport::{BoxFuture, FalkonStream, PeerListener, PeerTransport};

#[derive(Debug, Default, Clone)]
pub struct OnionTransportStub;

impl PeerTransport for OnionTransportStub {
    fn transport_name(&self) -> &'static str {
        "TOR-.ONION(PENDENTE-P7)"
    }

    fn bind<'a>(
        &'a self,
        _addr: &'a str,
    ) -> BoxFuture<'a, Result<Box<dyn PeerListener>, FalkonError>> {
        Box::pin(async {
            Err(FalkonError::InvalidState(
                "transporte .onion sera implementado no Ponto 7",
            ))
        })
    }

    fn connect<'a>(
        &'a self,
        _addr: &'a str,
    ) -> BoxFuture<'a, Result<Box<dyn FalkonStream>, FalkonError>> {
        Box::pin(async {
            Err(FalkonError::InvalidState(
                "transporte .onion sera implementado no Ponto 7",
            ))
        })
    }
}
