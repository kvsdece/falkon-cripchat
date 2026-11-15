use core::future::Future;
use core::pin::Pin;
use std::net::SocketAddr;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};

use falkon_core::error::FalkonError;

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;
pub type BoxedStream = Box<dyn FalkonStream>;
pub type BoxedListener = Box<dyn PeerListener>;
pub type AcceptedPeer = (BoxedStream, PeerEndpoint);

pub trait FalkonStream: AsyncRead + AsyncWrite + Send + Sync + Unpin {}
impl<T: AsyncRead + AsyncWrite + Send + Sync + Unpin> FalkonStream for T {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerEndpoint {
    DirectTcp(SocketAddr),
    OnionV3(String),
}

pub trait PeerListener: Send + Sync {
    fn local_endpoint(&self) -> Result<PeerEndpoint, FalkonError>;
    fn accept(&self) -> BoxFuture<'_, Result<AcceptedPeer, FalkonError>>;
}

pub trait PeerTransport: Send + Sync {
    fn transport_name(&self) -> &'static str;
    fn bind<'a>(&'a self, addr: &'a str) -> BoxFuture<'a, Result<BoxedListener, FalkonError>>;
    fn connect<'a>(&'a self, addr: &'a str) -> BoxFuture<'a, Result<BoxedStream, FalkonError>>;
}

#[derive(Debug, Default, Clone, Copy)]
pub struct DirectTcpTransport;

struct DirectTcpListener {
    inner: TcpListener,
}

impl PeerListener for DirectTcpListener {
    fn local_endpoint(&self) -> Result<PeerEndpoint, FalkonError> {
        let addr = self
            .inner
            .local_addr()
            .map_err(|e| FalkonError::Io(e.to_string()))?;
        Ok(PeerEndpoint::DirectTcp(addr))
    }

    fn accept(&self) -> BoxFuture<'_, Result<AcceptedPeer, FalkonError>> {
        Box::pin(async move {
            let (stream, addr) = self
                .inner
                .accept()
                .await
                .map_err(|e| FalkonError::Io(e.to_string()))?;
            let _ = stream.set_nodelay(true);
            Ok((
                Box::new(stream) as BoxedStream,
                PeerEndpoint::DirectTcp(addr),
            ))
        })
    }
}

impl PeerTransport for DirectTcpTransport {
    fn transport_name(&self) -> &'static str {
        "P2P-TCP"
    }

    fn bind<'a>(&'a self, addr: &'a str) -> BoxFuture<'a, Result<BoxedListener, FalkonError>> {
        Box::pin(async move {
            let listener = TcpListener::bind(addr)
                .await
                .map_err(|e| FalkonError::Io(e.to_string()))?;
            Ok(Box::new(DirectTcpListener { inner: listener }) as BoxedListener)
        })
    }

    fn connect<'a>(&'a self, addr: &'a str) -> BoxFuture<'a, Result<BoxedStream, FalkonError>> {
        Box::pin(async move {
            let stream = TcpStream::connect(addr)
                .await
                .map_err(|e| FalkonError::Io(e.to_string()))?;
            let _ = stream.set_nodelay(true);
            Ok(Box::new(stream) as BoxedStream)
        })
    }
}
