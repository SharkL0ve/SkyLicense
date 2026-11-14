use crate::encrypt::EncryptUtil;
use rustc_hash::FxHashMap;

const RESOURCE_FORMAT_MAGIC: &[u8; 8] = b"SKYCLS04";

const MAX_CLASS_COUNT: usize = 100_000;
const MAX_METHOD_COUNT: usize = 1_000_000;
const MAX_STRING_BYTES: usize = 1024 * 1024;
const MAX_CLASS_BYTES: usize = 64 * 1024 * 1024;

pub struct ByteCode {
    pub class_name: String,
    pub code: Vec<u8>,
}

pub struct MethodInfo {
    pub class_name: String,
    pub method_name: String,
    pub method_desc: String,
    pub func_type: char,
}

pub struct Resource {
    pub byte_codes: Vec<ByteCode>,
    pub entry_class: String,
    pub entry_point: String,
    pub method_map: FxHashMap<String, MethodInfo>,
}

impl Resource {
    /// Parse the server resource format without unchecked slicing or
    /// attacker-controlled allocations. The outer transport already limits the
    /// complete resource size; these limits constrain individual collections
    /// and compressed class payloads as a second line of defense.
    pub fn from_bytes(data: &[u8]) -> Result<Self, String> {
        let mut cursor = ResourceCursor::new(data);
        if cursor.read_bytes(RESOURCE_FORMAT_MAGIC.len(), "resource magic")?
            != RESOURCE_FORMAT_MAGIC
        {
            return Err("resource format magic is invalid".to_string());
        }
        let class_count = cursor.read_count("class count", MAX_CLASS_COUNT)?;
        let mut byte_codes = Vec::with_capacity(class_count);

        for _ in 0..class_count {
            let class_name = cursor.read_string("class name")?;
            let original_length = cursor.read_count("class length", MAX_CLASS_BYTES)?;
            let compressed_length = cursor.read_count("compressed class length", data.len())?;
            let compressed_data = cursor.read_bytes(compressed_length, "compressed class data")?;
            let code =
                EncryptUtil::decompress_exact(compressed_data, original_length, MAX_CLASS_BYTES)
                    .map_err(|error| format!("invalid compressed class {class_name}: {error}"))?;
            byte_codes.push(ByteCode { class_name, code });
        }

        let entry_class = cursor.read_string("entry class")?;
        let entry_point = cursor.read_string("entry point")?;

        let method_count = cursor.read_count("method count", MAX_METHOD_COUNT)?;
        let mut method_map = FxHashMap::default();
        method_map.reserve(method_count);
        for _ in 0..method_count {
            let mut key = cursor.read_string("method lookup key")?;
            let func_type = key
                .pop()
                .ok_or_else(|| "method lookup key is missing its function type".to_string())?;
            let method_info = MethodInfo {
                class_name: cursor.read_string("method class")?,
                method_name: cursor.read_string("method name")?,
                method_desc: cursor.read_string("method descriptor")?,
                func_type,
            };
            if method_map.insert(key, method_info).is_some() {
                return Err("duplicate method lookup key".to_string());
            }
        }

        cursor.finish()?;
        Ok(Self {
            byte_codes,
            entry_class,
            entry_point,
            method_map,
        })
    }
}

struct ResourceCursor<'a> {
    data: &'a [u8],
    position: usize,
}

impl<'a> ResourceCursor<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, position: 0 }
    }

    fn read_count(&mut self, field: &str, maximum: usize) -> Result<usize, String> {
        let bytes = self.read_bytes(4, field)?;
        let value = i32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let value = usize::try_from(value).map_err(|_| format!("{field} must not be negative"))?;
        if value > maximum {
            return Err(format!("{field} exceeds the configured limit"));
        }
        Ok(value)
    }

    fn read_string(&mut self, field: &str) -> Result<String, String> {
        let length = self.read_count(field, MAX_STRING_BYTES)?;
        let bytes = self.read_bytes(length, field)?;
        String::from_utf8(bytes.to_vec()).map_err(|_| format!("{field} is not valid UTF-8"))
    }

    fn read_bytes(&mut self, length: usize, field: &str) -> Result<&'a [u8], String> {
        let end = self
            .position
            .checked_add(length)
            .ok_or_else(|| format!("{field} length overflow"))?;
        let bytes = self
            .data
            .get(self.position..end)
            .ok_or_else(|| format!("truncated {field}"))?;
        self.position = end;
        Ok(bytes)
    }

    fn finish(self) -> Result<(), String> {
        if self.position == self.data.len() {
            Ok(())
        } else {
            Err("resource contains trailing bytes".to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::Compression;
    use flate2::write::GzEncoder;
    use std::io::Write;

    fn push_string(output: &mut Vec<u8>, value: &str) {
        output.extend_from_slice(&(value.len() as i32).to_be_bytes());
        output.extend_from_slice(value.as_bytes());
    }

    fn minimal_resource() -> Vec<u8> {
        let mut output = Vec::new();
        output.extend_from_slice(RESOURCE_FORMAT_MAGIC);
        output.extend_from_slice(&0i32.to_be_bytes());
        push_string(&mut output, "example.Main");
        push_string(&mut output, "start");
        output.extend_from_slice(&0i32.to_be_bytes());
        output
    }

    fn push_class(output: &mut Vec<u8>, name: &str, bytecode: &[u8]) {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(bytecode).unwrap();
        let compressed = encoder.finish().unwrap();
        push_string(output, name);
        output.extend_from_slice(&(bytecode.len() as i32).to_be_bytes());
        output.extend_from_slice(&(compressed.len() as i32).to_be_bytes());
        output.extend_from_slice(&compressed);
    }

    #[test]
    fn parses_a_minimal_resource() {
        let resource = Resource::from_bytes(&minimal_resource()).unwrap();
        assert_eq!(resource.entry_class, "example.Main");
        assert_eq!(resource.entry_point, "start");
        assert!(resource.byte_codes.is_empty());
        assert!(resource.method_map.is_empty());
    }

    #[test]
    fn every_truncated_prefix_is_rejected_without_panicking() {
        let resource = minimal_resource();
        for length in 0..resource.len() {
            assert!(Resource::from_bytes(&resource[..length]).is_err());
        }
    }

    #[test]
    fn negative_and_excessive_counts_are_rejected() {
        assert!(Resource::from_bytes(&(-1i32).to_be_bytes()).is_err());
        assert!(Resource::from_bytes(&((MAX_CLASS_COUNT + 1) as i32).to_be_bytes()).is_err());
    }

    #[test]
    fn dependency_order_from_the_server_is_preserved() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(RESOURCE_FORMAT_MAGIC);
        bytes.extend_from_slice(&2i32.to_be_bytes());
        push_class(&mut bytes, "example/Outer$Base", &[1, 2, 3]);
        push_class(&mut bytes, "example/TopLevelDependent", &[4, 5, 6]);
        push_string(&mut bytes, "example.TopLevelDependent");
        push_string(&mut bytes, "start");
        bytes.extend_from_slice(&0i32.to_be_bytes());

        let resource = Resource::from_bytes(&bytes).unwrap();
        assert_eq!(resource.byte_codes[0].class_name, "example/Outer$Base");
        assert_eq!(
            resource.byte_codes[1].class_name,
            "example/TopLevelDependent"
        );
    }
}
