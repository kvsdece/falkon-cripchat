use core::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::timeout;

use falkon_core::crypto::MAX_NOISE_MSG_LEN;
use falkon_core::error::FalkonError;

pub const IO_TIMEOUT: Duration = Duration::from_secs(15);
pub const IDLE_READ_TIMEOUT: Duration = Duration::from_secs(75);
pub const HANDSHAKE_MAX_FRAME_LEN: usize = 2048;

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

pub async fn read_handshake_frame<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> Result<Vec<u8>, FalkonError> {
    read_frame_bounded(reader, HANDSHAKE_MAX_FRAME_LEN, IO_TIMEOUT).await
}

pub async fn read_frame<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Vec<u8>, FalkonError> {
    read_frame_bounded(reader, MAX_NOISE_MSG_LEN, IO_TIMEOUT).await
}

pub async fn read_frame_with_timeout<R: AsyncRead + Unpin>(
    reader: &mut R,
    dur: Duration,
) -> Result<Vec<u8>, FalkonError> {
    read_frame_bounded(reader, MAX_NOISE_MSG_LEN, dur).await
}

pub async fn read_frame_bounded<R: AsyncRead + Unpin>(
    reader: &mut R,
    max_len: usize,
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

        if len == 0 || len > max_len {
            return Err(FalkonError::FrameTooLarge { len, max: max_len });
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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn rejects_oversized_and_truncated_frames_safely() {
        // 1. Frame anunciando 4GB (deve rejeitar antes de alocar)
        let (mut tx, mut rx) = tokio::io::duplex(64);
        tokio::spawn(async move {
            let _ = tx.write_all(&u32::MAX.to_be_bytes()).await;
        });
        let res = read_frame(&mut rx).await;
        assert!(matches!(res, Err(FalkonError::FrameTooLarge { .. })));

        // 2. Frame com tamanho zero
        let (mut tx, mut rx) = tokio::io::duplex(64);
        tokio::spawn(async move {
            let _ = tx.write_all(&0u32.to_be_bytes()).await;
        });
        let res = read_frame(&mut rx).await;
        assert!(matches!(
            res,
            Err(FalkonError::FrameTooLarge { len: 0, .. })
        ));

        // 3. Cabecalho truncado (2 bytes e EOF)
        let (mut tx, mut rx) = tokio::io::duplex(64);
        tokio::spawn(async move {
            let _ = tx.write_all(&[0x00, 0x01]).await;
            let _ = tx.shutdown().await;
        });
        let res = read_frame(&mut rx).await;
        assert!(matches!(res, Err(FalkonError::Io(_))));

        // 4. Payload truncado (anuncia 20 bytes, envia 5 e fecha)
        let (mut tx, mut rx) = tokio::io::duplex(64);
        tokio::spawn(async move {
            let _ = tx.write_all(&20u32.to_be_bytes()).await;
            let _ = tx.write_all(b"12345").await;
            let _ = tx.shutdown().await;
        });
        let res = read_frame(&mut rx).await;
        assert!(matches!(res, Err(FalkonError::Io(_))));
    }
}
