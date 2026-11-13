use std::io::Cursor;
use byteorder::{BigEndian, ReadBytesExt};
use bytes::{BufMut, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt};
use std::error::Error;

pub struct ByteBuf {
    buffer: BytesMut,
    reader_index: usize,
    writer_index: usize,
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

    pub fn write_string(&mut self, value: &str) {
        let char_count = value.chars().count() as i32;
        self.write_int(char_count);
        for c in value.chars() {
            self.buffer.put_u16(c as u16);
            self.writer_index += 2;
        }
    }

    pub fn read_bytes(&mut self, len: usize) -> Option<Vec<u8>> {
        if self.reader_index + len <= self.writer_index {
            let result = self.buffer[self.reader_index..self.reader_index + len].to_vec();
            self.reader_index += len;
            Some(result)
        } else {
            None
        }
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
        let len = self.read_int()? as usize;
        let char_data_len = len * 2;
        
        if self.reader_index + char_data_len <= self.writer_index {
            let mut chars = Vec::with_capacity(len);
            for _ in 0..len {
                let mut cursor = Cursor::new(&self.buffer[self.reader_index..self.reader_index + 2]);
                if let Ok(char_value) = ReadBytesExt::read_u16::<BigEndian>(&mut cursor) {
                    if let Some(c) = char::from_u32(char_value as u32) {
                        chars.push(c);
                    }
                }
                self.reader_index += 2;
            }
            Some(chars.into_iter().collect())
        } else {
            None
        }
    }

    pub fn readable_bytes(&self) -> usize {
        self.writer_index - self.reader_index
    }

    pub fn get_bytes(&self) -> &[u8] {
        &self.buffer[..]
    }

    pub async fn read_from_async<R: AsyncRead + Unpin>(
        stream: &mut R,
        size: usize,
    ) -> Result<ByteBuf, Box<dyn Error>> {
        let mut buf = ByteBuf::with_capacity(size);
        let mut bytes = vec![0u8; size];
        stream.read_exact(&mut bytes).await?;
        buf.write_bytes(&bytes);
        Ok(buf)
    }
}
