use crate::bytebuf::ByteBuf;
use std::error::Error;
use tokio::io::{AsyncRead, AsyncReadExt};

pub async fn read_message<R>(stream: &mut R) -> Result<String, Box<dyn Error>>
where
    R: AsyncRead + Unpin,
{
    let mut length_bytes = [0u8; 4];
    stream.read_exact(&mut length_bytes).await?;

    let length = i32::from_be_bytes(length_bytes);

    if length <= 0 || length > 65536 {
        return Err(format!("invalid message length: {}", length).into());
    }

    let byte_length = usize::try_from(length)?
        .checked_mul(2)
        .ok_or("message byte length overflow")?;
    let mut content_bytes = vec![0u8; byte_length];
    stream.read_exact(&mut content_bytes).await?;

    // ByteBuf::read_string consumes the same length prefix used on the wire.
    let mut buf = ByteBuf::with_capacity(4 + byte_length);
    buf.write_int(length);
    buf.write_bytes(&content_bytes);

    let content = buf.read_string().ok_or("invalid UTF-16 response")?;
    if content.is_empty() {
        return Err("empty response".into());
    }
    Ok(content)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(value: &str) -> Vec<u8> {
        let code_units: Vec<u16> = value.encode_utf16().collect();
        let mut bytes = Vec::with_capacity(4 + code_units.len() * 2);
        bytes.extend_from_slice(&(code_units.len() as i32).to_be_bytes());
        for code_unit in code_units {
            bytes.extend_from_slice(&code_unit.to_be_bytes());
        }
        bytes
    }

    #[tokio::test]
    async fn reads_the_server_utf16_frame() {
        let bytes = frame("ACCEPT");
        let mut input = bytes.as_slice();
        assert_eq!(read_message(&mut input).await.unwrap(), "ACCEPT");
    }

    #[tokio::test]
    async fn rejects_invalid_or_truncated_frames() {
        let mut zero_length = [0u8; 4].as_slice();
        assert!(read_message(&mut zero_length).await.is_err());

        let oversized_bytes = 65_537i32.to_be_bytes();
        let mut oversized = oversized_bytes.as_slice();
        assert!(read_message(&mut oversized).await.is_err());

        let mut truncated = frame("OK");
        truncated.pop();
        assert!(read_message(&mut truncated.as_slice()).await.is_err());
    }

    #[tokio::test]
    async fn rejects_unpaired_utf16_surrogates() {
        let bytes = [0, 0, 0, 1, 0xD8, 0x00];
        let mut input = bytes.as_slice();
        assert!(read_message(&mut input).await.is_err());
    }
}
