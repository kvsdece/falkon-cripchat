use core::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FalkonError {
    FrameTooLarge { len: usize, max: usize },
    Codec(String),
    Crypto(String),
    InvalidState(&'static str),
    InvalidInput(&'static str),
    Io(String),
}

impl fmt::Display for FalkonError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FrameTooLarge { len, max } => {
                write!(f, "frame excede limite seguro ({len} > {max} bytes)")
            }
            Self::Codec(msg) => write!(f, "erro de serializacao: {msg}"),
            Self::Crypto(msg) => write!(f, "erro criptografico: {msg}"),
            Self::InvalidState(msg) => write!(f, "estado invalido: {msg}"),
            Self::InvalidInput(msg) => write!(f, "entrada invalida: {msg}"),
            Self::Io(msg) => write!(f, "erro de I/O: {msg}"),
        }
    }
}

impl std::error::Error for FalkonError {}
