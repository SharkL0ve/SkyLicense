use byteorder::{BigEndian, ReadBytesExt};
use bytes::{BufMut, BytesMut};
use std::error::Error;
use std::io::Cursor;
use tokio::io::{AsyncRead, AsyncReadExt};

const MAX_STRING_CODE_UNITS: usize = 1_048_576;
const MAX_ASYNC_READ_BYTES: usize = 256 * 1024 * 1024;

pub struct ByteBuf {
    buffer: BytesMut,
    reader_index: usize,
    writer_index: usize,
}

impl Default for ByteBuf {
    fn default() -> Self {
        Self::new()
    }
}

impl ByteBuf {
    pub fn new() -> Self {
        ByteBuf {
            buffer: BytesMut::new(),
            reader_index: 0,
            writer_index: 0,
        }
    }

    pub fn with_capacity(capacity: usize) -> Self {
        ByteBuf {
            buffer: BytesMut::with_capacity(capacity),
            reader_index: 0,
            writer_index: 0,
        }
    }

    pub fn write_bytes(&mut self, bytes: &[u8]) {
        self.buffer.extend_from_slice(bytes);
        self.writer_index += bytes.len();
    }

    pub fn write_int(&mut self, value: i32) {
        self.buffer.put_i32(value);
        self.writer_index += 4;
    }

    pub fn write_long(&mut self, value: u64) {
        self.buffer.put_u64(value);
        self.writer_index += 8;
    }

    pub fn write_string(&mut self, value: &str) {
        // The Java peer serializes UTF-16 code units, not Unicode scalar values.
        let code_units: Vec<u16> = value.encode_utf16().collect();
        let length = i32::try_from(code_units.len()).expect("string is too long");
        self.write_int(length);
        for code_unit in code_units {
            self.buffer.put_u16(code_unit);
            self.writer_index += 2;
        }
    }

    pub fn read_bytes(&mut self, len: usize) -> Option<Vec<u8>> {
        let end = self.reader_index.checked_add(len)?;
        if end > self.writer_index {
            return None;
        }
        let result = self.buffer[self.reader_index..end].to_vec();
        self.reader_index = end;
        Some(result)
    }

    pub fn read_int(&mut self) -> Option<i32> {
        if self.reader_index + 4 <= self.writer_index {
            let mut cursor = Cursor::new(&self.buffer[self.reader_index..self.reader_index + 4]);
            let result = ReadBytesExt::read_i32::<BigEndian>(&mut cursor).ok()?;
            self.reader_index += 4;
            Some(result)
        } else {
            None
        }
    }

    pub fn read_string(&mut self) -> Option<String> {
        let start = self.reader_index;
        let signed_length = self.read_int()?;
        let length = match usize::try_from(signed_length) {
            Ok(length) => length,
            Err(_) => {
                self.reader_index = start;
                return None;
            }
        };
        if length > MAX_STRING_CODE_UNITS {
            self.reader_index = start;
            return None;
        }
        let byte_length = match length.checked_mul(2) {
            Some(byte_length) => byte_length,
            None => {
                self.reader_index = start;
                return None;
            }
        };
        let end = match self.reader_index.checked_add(byte_length) {
            Some(end) => end,
            None => {
                self.reader_index = start;
                return None;
            }
        };
        if end > self.writer_index {
            self.reader_index = start;
            return None;
        }

        let mut code_units = Vec::with_capacity(length);
        for offset in (self.reader_index..end).step_by(2) {
            let mut cursor = Cursor::new(&self.buffer[offset..offset + 2]);
            let code_unit = match ReadBytesExt::read_u16::<BigEndian>(&mut cursor) {
                Ok(code_unit) => code_unit,
                Err(_) => {
                    self.reader_index = start;
                    return None;
                }
            };
            code_units.push(code_unit);
        }
        let value = match String::from_utf16(&code_units) {
            Ok(value) => value,
            Err(_) => {
                self.reader_index = start;
                return None;
            }
        };
        self.reader_index = end;
        Some(value)
    }

    pub fn readable_bytes(&self) -> usize {
        self.writer_index.saturating_sub(self.reader_index)
    }

    pub fn get_bytes(&self) -> &[u8] {
        &self.buffer[..]
    }

    pub async fn read_from_async<R: AsyncRead + Unpin>(
        stream: &mut R,
        size: usize,
    ) -> Result<ByteBuf, Box<dyn Error>> {
        if size > MAX_ASYNC_READ_BYTES {
            return Err(format!("async read exceeds {} bytes", MAX_ASYNC_READ_BYTES).into());
        }
        let mut buf = ByteBuf::with_capacity(size);
        let mut bytes = vec![0u8; size];
        stream.read_exact(&mut bytes).await?;
        buf.write_bytes(&bytes);
        Ok(buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_utf16_code_units_and_surrogate_pairs() {
        let value = "hello-许可证-🙂";
        let mut buffer = ByteBuf::new();
        buffer.write_string(value);
        assert_eq!(buffer.read_string().as_deref(), Some(value));
    }

    #[test]
    fn rejects_negative_and_overflowing_string_lengths_without_panicking() {
        let mut negative = ByteBuf::new();
        negative.write_int(-1);
        assert!(negative.read_string().is_none());
        assert_eq!(negative.readable_bytes(), 4);

        let mut overflowing = ByteBuf::new();
        overflowing.write_int(i32::MAX);
        assert!(overflowing.read_string().is_none());
        assert_eq!(overflowing.readable_bytes(), 4);
    }

    #[test]
    fn rejects_unpaired_utf16_surrogates() {
        let mut buffer = ByteBuf::new();
        buffer.write_int(1);
        buffer.buffer.put_u16(0xD800);
        buffer.writer_index += 2;
        assert!(buffer.read_string().is_none());
        assert_eq!(buffer.readable_bytes(), 6);
    }

    #[test]
    fn read_bytes_uses_checked_bounds() {
        let mut buffer = ByteBuf::new();
        buffer.write_bytes(&[1, 2, 3]);
        assert_eq!(buffer.read_bytes(2), Some(vec![1, 2]));
        assert!(buffer.read_bytes(usize::MAX).is_none());
        assert_eq!(buffer.read_bytes(1), Some(vec![3]));
    }
}
