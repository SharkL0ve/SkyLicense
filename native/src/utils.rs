use std::error::Error;
use jni::JNIEnv;
use jni::objects::JObject;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;
use crate::bytebuf::ByteBuf;

pub async fn read_message(stream: &mut TcpStream) -> Result<String, Box<dyn Error>> {
    let mut length_bytes = [0u8; 4];
    stream.read_exact(&mut length_bytes).await?;

    let mut length_buf = ByteBuf::new();
    length_buf.write_bytes(&length_bytes);
    let length = length_buf.read_int().ok_or("invalid length")?;

    if length <= 0 || length > 65536 {
        return Err(format!("invalid message length: {}", length).into());
    }

    let mut content_bytes = vec![0u8; (length * 2) as usize];
    stream.read_exact(&mut content_bytes).await?;

    let mut buf = ByteBuf::new();
    buf.write_bytes(&content_bytes);

    let mut chars = Vec::with_capacity(length as usize);
    for _ in 0..length {
        if let Some(bytes) = buf.read_bytes(2) {
            if bytes.len() == 2 {
                let char_value = ((bytes[0] as u16) << 8) | (bytes[1] as u16);
                if let Some(c) = char::from_u32(char_value as u32) {
                    chars.push(c);
                }
            }
        }
    }

    let content = chars.into_iter().collect::<String>();
    if content.is_empty() {
        return Err("empty response".into());
    }
    Ok(content)
}

pub fn get_class_name(env: &mut JNIEnv, class: &JObject) -> String {
    let jstr = env.call_method(
        class,
        "getName",
        "()Ljava/lang/String;",
        &[],
    ).expect("AuthLib Exception");

    env.get_string((&jstr.l().unwrap()).into()).expect("AuthLib Exception").into()
}
