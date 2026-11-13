use crate::encrypt::EncryptUtil;
use fxhash::FxHashMap;

#[derive(Clone)]
pub struct ByteCode {
    pub class_name: String,
    pub code: Vec<u8>,
    pub is_keep: bool,
}

#[derive(Clone)]
pub struct MethodInfo {
    pub class_name: String,
    pub method_name: String,
    pub method_desc: String,
    pub func_type: char,
}

#[derive(Clone)]
pub struct Resource {
    pub byte_codes: Vec<ByteCode>,
    pub entry_class: String,
    pub entry_point: String,
    pub random_key: Vec<u8>,
    pub method_map: FxHashMap<String, MethodInfo>,
}

impl Resource {
    pub fn from_bytes(data: &[u8]) -> Result<Self, Box<dyn std::error::Error>> {
        let mut cursor = 0;

        let byte_codes_size = read_int(&data[cursor..cursor + 4])?;
        cursor += 4;

        let mut byte_codes = Vec::with_capacity(byte_codes_size as usize);

        for _ in 0..byte_codes_size {
            let (class_name, read_size) = read_string(&data[cursor..])?;
            cursor += read_size;

            let _original_length = read_int(&data[cursor..cursor + 4])?;
            cursor += 4;

            let compressed_length = read_int(&data[cursor..cursor + 4])?;
            cursor += 4;

            let compressed_data = &data[cursor..cursor + compressed_length as usize];
            cursor += compressed_length as usize;

            let code = EncryptUtil::decompress(compressed_data)?;

            byte_codes.push(ByteCode {
                class_name,
                code,
                is_keep: false,
            });
        }

        let (entry_class, read_size) = read_string(&data[cursor..])?;
        cursor += read_size;

        let (entry_point, read_size) = read_string(&data[cursor..])?;
        cursor += read_size;

        let random_key = data[cursor..cursor + 16].to_vec();
        cursor += 16;

        let method_map_size = read_int(&data[cursor..cursor + 4])?;
        cursor += 4;

        /*let password = base64::encode(EncryptUtil::decode(P.get().expect("AuthLib Exception"), "Rfn5CD0Y7u0q7VJn").expect("AuthLib Exception"));
        let password = password.as_str();*/

        let mut method_map = FxHashMap::default();
        //let start = SystemTime::now();
        for _ in 0..method_map_size {
            //let start = SystemTime::now();
            let (mut key, read_size) = read_string(&data[cursor..])?;
            let func_type = key.pop().expect("AuthLib Exception");
            cursor += read_size;

            let (class_name, read_size) = read_string(&data[cursor..])?;
            cursor += read_size;

            let (method_name, read_size) = read_string(&data[cursor..])?;
            cursor += read_size;

            let (method_desc, read_size) = read_string(&data[cursor..])?;
            cursor += read_size;

            //println!("{} -> {}.{}{}", key, class_name, method_name, method_desc);
            //let key = base64::encode(EncryptUtil::encode(key.as_bytes(), password).expect("AuthLib Exception"));
            /*let class_name = base64::encode(EncryptUtil::encode(class_name.as_bytes(), password).expect("AuthLib Exception"));
            let method_name = base64::encode(EncryptUtil::encode(method_name.as_bytes(), password).expect("AuthLib Exception"));
            let method_desc = base64::encode(EncryptUtil::encode(method_desc.as_bytes(), password).expect("AuthLib Exception"));*/
            let method_info = MethodInfo {
                class_name,
                method_name,
                method_desc,
                func_type,
            };
            method_map.insert(key, method_info);
            /*let end = SystemTime::now();
            println!("inserted {}, time: {}ms", method_map.len(), end.duration_since(start).unwrap().as_millis())*/
        }
        //let end = SystemTime::now();
        //println!("method_map size: {}, time: {}s", method_map_size, end.duration_since(start).unwrap().as_secs());

        Ok(Resource {
            byte_codes,
            entry_class,
            entry_point,
            random_key,
            method_map,
        })
    }
}

fn read_int(data: &[u8]) -> Result<i32, Box<dyn std::error::Error>> {
    if data.len() < 4 {
        return Err("数据长度不足以读取整数".into());
    }
    Ok(EncryptUtil::byte_array_to_int(&data)?)
}

pub fn read_string(data: &[u8]) -> Result<(String, usize), String> {
    if data.len() < 4 {
        return Err("数据长度不足，无法读取字符串长度字段".to_string());
    }
    let (length_bytes, rest) = data.split_at(4);
    let length = EncryptUtil::byte_array_to_int(length_bytes).unwrap() as usize;

    if rest.len() < length {
        return Err("数据长度不足，无法读取完整的字符串内容".to_string());
    }

    let (string_data, _new_rest) = rest.split_at(length);
    let result = String::from_utf8_lossy(string_data).into_owned();
    Ok((result, length + 4))
}
