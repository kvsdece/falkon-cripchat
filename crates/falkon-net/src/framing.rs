use core::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::timeout;

use falkon_core::crypto::MAX_NOISE_MSG_LEN;
use falkon_core::error::FalkonError;

pub const IO_TIMEOUT: Duration = Duration::from_secs(15);
pub const IDLE_READ_TIMEOUT: Duration = Duration::from_secs(75);

pub async fn write_frame<W: AsyncWrite + Unpin>(
    writer: &mut W,
    payload: &[u8],
) -> Result<(), FalkonError> {
    if payload.len() > MAX_NOISE_MSG_LEN {
        return Err(FalkonError::FrameTooLarge {
            len: payload.len(),
            max: MAX_NOISE_MSG_LEN,
        });
    }

    let len = u32::try_from(payload.len())
        .map_err(|_| FalkonError::InvalidInput("frame maior que u32"))?;

    timeout(IO_TIMEOUT, async {
        writer.write_all(&len.to_be_bytes()).await?;
        writer.write_all(payload).await?;
        writer.flush().await
    })
    .await
    .map_err(|_| FalkonError::Io("timeout ao enviar frame".to_owned()))?
    .map_err(|e| FalkonError::Io(e.to_string()))
}

pub async fn read_frame<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Vec<u8>, FalkonError> {
    read_frame_with_timeout(reader, IO_TIMEOUT).await
}

pub async fn read_frame_with_timeout<R: AsyncRead + Unpin>(
    reader: &mut R,
    dur: Duration,
) -> Result<Vec<u8>, FalkonError> {
    timeout(dur, async {
        let mut len_buf = [0u8; 4];
        reader
            .read_exact(&mut len_buf)
            .await
            .map_err(|e| FalkonError::Io(e.to_string()))?;

        let len = usize::try_from(u32::from_be_bytes(len_buf))
            .map_err(|_| FalkonError::InvalidInput("tamanho de frame invalido"))?;

        if len == 0 || len > MAX_NOISE_MSG_LEN {
            return Err(FalkonError::FrameTooLarge {
                len,
                max: MAX_NOISE_MSG_LEN,
            });
        }

        let mut payload = vec![0u8; len];
        reader
            .read_exact(&mut payload)
            .await
            .map_err(|e| FalkonError::Io(e.to_string()))?;

        Ok(payload)
    })
    .await
    .map_err(|_| FalkonError::Io("timeout ao ler frame".to_owned()))?
}
