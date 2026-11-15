use core::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::timeout;

use falkon_core::error::FalkonError;

const PRE_HANDSHAKE_MAGIC: &[u8; 8] = b"FALKON01";
const SALT_IO_TIMEOUT: Duration = Duration::from_secs(5);

pub async fn send_room_salt<W: AsyncWrite + Unpin>(
    writer: &mut W,
    room_salt: &[u8; 16],
) -> Result<(), FalkonError> {
    let mut buf = [0u8; 24];
    buf[..8].copy_from_slice(PRE_HANDSHAKE_MAGIC);
    buf[8..].copy_from_slice(room_salt);

    timeout(SALT_IO_TIMEOUT, async {
        writer.write_all(&buf).await?;
        writer.flush().await
    })
    .await
    .map_err(|_| FalkonError::Io("timeout ao enviar salt da sala".to_owned()))?
    .map_err(|e| FalkonError::Io(e.to_string()))
}

pub async fn recv_room_salt<R: AsyncRead + Unpin>(reader: &mut R) -> Result<[u8; 16], FalkonError> {
    let mut buf = [0u8; 24];
    timeout(SALT_IO_TIMEOUT, reader.read_exact(&mut buf))
        .await
        .map_err(|_| FalkonError::Io("timeout ao receber salt da sala".to_owned()))?
        .map_err(|e| FalkonError::Io(e.to_string()))?;

    if &buf[..8] != PRE_HANDSHAKE_MAGIC {
        return Err(FalkonError::InvalidInput("cabecalho Falkon invalido"));
    }

    let mut salt = [0u8; 16];
    salt.copy_from_slice(&buf[8..]);
    Ok(salt)
}
