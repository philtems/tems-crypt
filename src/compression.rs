use crate::error::{Result, Error};
use std::io::{Read, Write};

pub fn create_compressor<R: Read + 'static>(
    algo: &str,
    level: i32,
    reader: R,
) -> Result<Box<dyn Read>> {
    match algo {
        "gz" => {
            use flate2::read::GzEncoder;
            let level_u32 = if level < 0 { 6 } else { level as u32 };
            Ok(Box::new(GzEncoder::new(reader, flate2::Compression::new(level_u32))))
        }
        "zstd" => {
            use zstd::stream::read::Encoder;
            let encoder = Encoder::new(reader, level)
                .map_err(|e| Error::Compression(format!("Zstd error: {}", e)))?;
            Ok(Box::new(encoder))
        }
        "xz" => {
            use xz2::read::XzEncoder;
            let level_u32 = if level < 0 { 6 } else { level as u32 };
            Ok(Box::new(XzEncoder::new(reader, level_u32)))
        }
        "none" => Ok(Box::new(reader)),
        _ => Err(Error::UnsupportedAlgorithm(algo.to_string())),
    }
}

pub fn create_decompressor<R: Read + 'static>(
    algo: &str,
    reader: R,
) -> Result<Box<dyn Read>> {
    match algo {
        "gz" => {
            use flate2::read::GzDecoder;
            Ok(Box::new(GzDecoder::new(reader)))
        }
        "zstd" => {
            use zstd::stream::read::Decoder;
            let decoder = Decoder::new(reader)
                .map_err(|e| Error::Compression(format!("Zstd error: {}", e)))?;
            Ok(Box::new(decoder))
        }
        "xz" => {
            use xz2::read::XzDecoder;
            Ok(Box::new(XzDecoder::new(reader)))
        }
        "none" => Ok(Box::new(reader)),
        _ => Err(Error::UnsupportedAlgorithm(algo.to_string())),
    }
}

pub fn compress_data(data: &[u8], algo: &str, level: i32) -> Result<Vec<u8>> {
    match algo {
        "gz" => {
            use flate2::write::GzEncoder;
            let level_u32 = if level < 0 { 6 } else { level as u32 };
            let mut encoder = GzEncoder::new(Vec::new(), flate2::Compression::new(level_u32));
            encoder.write_all(data)?;
            encoder.finish()
                .map_err(|e| Error::Compression(format!("Gzip compression error: {}", e)))
        }
        "zstd" => {
            zstd::stream::encode_all(data, level)
                .map_err(|e| Error::Compression(format!("Zstd compression error: {}", e)))
        }
        "xz" => {
            use xz2::write::XzEncoder;
            let level_u32 = if level < 0 { 6 } else { level as u32 };
            let mut encoder = XzEncoder::new(Vec::new(), level_u32);
            encoder.write_all(data)?;
            encoder.finish()
                .map_err(|e| Error::Compression(format!("Xz compression error: {}", e)))
        }
        "none" => Ok(data.to_vec()),
        _ => Err(Error::UnsupportedAlgorithm(algo.to_string())),
    }
}

pub fn decompress_data(data: &[u8], algo: &str) -> Result<Vec<u8>> {
    match algo {
        "gz" => {
            use flate2::read::GzDecoder;
            let mut decoder = GzDecoder::new(data);
            let mut output = Vec::new();
            decoder.read_to_end(&mut output)
                .map_err(|e| Error::Compression(format!("Gzip decompression error: {}", e)))?;
            Ok(output)
        }
        "zstd" => {
            use zstd::stream::read::Decoder;
            let mut decoder = Decoder::new(data)
                .map_err(|e| Error::Compression(format!("Zstd error: {}", e)))?;
            let mut output = Vec::new();
            decoder.read_to_end(&mut output)
                .map_err(|e| Error::Compression(format!("Zstd decompression error: {}", e)))?;
            Ok(output)
        }
        "xz" => {
            use xz2::read::XzDecoder;
            let mut decoder = XzDecoder::new(data);
            let mut output = Vec::new();
            decoder.read_to_end(&mut output)
                .map_err(|e| Error::Compression(format!("Xz decompression error: {}", e)))?;
            Ok(output)
        }
        "none" => Ok(data.to_vec()),
        _ => Err(Error::UnsupportedAlgorithm(algo.to_string())),
    }
}

