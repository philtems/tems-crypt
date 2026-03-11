use crate::error::{Result, Error};
use std::fs::File;
use std::io::{Read, BufReader};
use sha2::Digest;
use sha3::Digest as Sha3Digest;

// Pour un seul algorithme en streaming
pub fn hash_reader_single<R: Read>(
    reader: &mut R,
    algorithm: &str,
    salt: &[u8],
    iterations: Option<u32>,
) -> Result<Vec<u8>> {
    match algorithm {
        "blake3" => {
            let mut hasher = blake3::Hasher::new();
            if !salt.is_empty() {
                hasher.update(salt);
            }
            
            let mut buffer = [0u8; 64 * 1024]; // 64KB buffer
            loop {
                let n = reader.read(&mut buffer)?;
                if n == 0 { break; }
                hasher.update(&buffer[..n]);
            }
            
            Ok(hasher.finalize().as_bytes().to_vec())
        }
        
        "sha256" => {
            let mut hasher = sha2::Sha256::new();
            if !salt.is_empty() {
                hasher.update(salt);
            }
            
            let mut buffer = [0u8; 64 * 1024];
            loop {
                let n = reader.read(&mut buffer)?;
                if n == 0 { break; }
                hasher.update(&buffer[..n]);
            }
            
            Ok(hasher.finalize().to_vec())
        }
        
        "sha3-256" => {
            let mut hasher = sha3::Sha3_256::new();
            if !salt.is_empty() {
                hasher.update(salt);
            }
            
            let mut buffer = [0u8; 64 * 1024];
            loop {
                let n = reader.read(&mut buffer)?;
                if n == 0 { break; }
                hasher.update(&buffer[..n]);
            }
            
            Ok(hasher.finalize().to_vec())
        }
        
        "sha3-512" => {
            let mut hasher = sha3::Sha3_512::new();
            if !salt.is_empty() {
                hasher.update(salt);
            }
            
            let mut buffer = [0u8; 64 * 1024];
            loop {
                let n = reader.read(&mut buffer)?;
                if n == 0 { break; }
                hasher.update(&buffer[..n]);
            }
            
            Ok(hasher.finalize().to_vec())
        }
        
        "xxh3" => {
            use xxhash_rust::xxh3::Xxh3;
            let mut hasher = Xxh3::new();
            if !salt.is_empty() {
                hasher.update(salt);
            }
            
            let mut buffer = [0u8; 64 * 1024];
            loop {
                let n = reader.read(&mut buffer)?;
                if n == 0 { break; }
                hasher.update(&buffer[..n]);
            }
            
            Ok(hasher.digest().to_le_bytes().to_vec())
        }
        
        "pbkdf2-sha256" => {
            // PBKDF2 a besoin de tout le contenu en mémoire
            let mut data = Vec::new();
            reader.read_to_end(&mut data)?;
            
            use sha2::Sha256;
            use pbkdf2::pbkdf2_hmac;
            
            let iterations = iterations.unwrap_or(100_000);
            let mut output = vec![0u8; 32];
            pbkdf2_hmac::<Sha256>(&data, salt, iterations, &mut output);
            Ok(output)
        }
        
        _ => Err(Error::UnsupportedAlgorithm(algorithm.to_string())),
    }
}

// Pour plusieurs algorithmes en streaming
pub fn hash_reader_streaming<R: Read>(
    reader: &mut R,
    algorithms: &[&str],
    salt: &[u8],
    iterations: Option<u32>,
) -> Result<Vec<(String, Vec<u8>)>> {
    let mut results = Vec::new();
    
    // Pour chaque algorithme qui n'est pas PBKDF2
    let mut regular_algos = Vec::new();
    let mut pbkdf2_requested = false;
    
    for &algo in algorithms {
        if algo == "pbkdf2-sha256" {
            pbkdf2_requested = true;
        } else {
            regular_algos.push(algo);
        }
    }
    
    if !regular_algos.is_empty() {
        // Créer tous les hashers
        let mut hashers: Vec<Box<dyn Hasher>> = Vec::new();
        
        for &algo in &regular_algos {
            if let Some(hasher) = create_hasher(algo, salt)? {
                hashers.push(hasher);
            }
        }
        
        // Stream le contenu une seule fois pour tous les hashers
        let mut buffer = [0u8; 64 * 1024];
        loop {
            let n = reader.read(&mut buffer)?;
            if n == 0 { break; }
            
            for hasher in &mut hashers {
                hasher.update(&buffer[..n]);
            }
        }
        
        // Récupérer les résultats
        for mut hasher in hashers {
            results.push((hasher.name().to_string(), hasher.finalize()));
        }
    }
    
    // Si PBKDF2 est demandé, on doit tout lire
    if pbkdf2_requested {
        // Pour PBKDF2, on a besoin de tout le contenu
        let mut data = Vec::new();
        reader.read_to_end(&mut data)?;
        
        use sha2::Sha256;
        use pbkdf2::pbkdf2_hmac;
        
        let iterations = iterations.unwrap_or(100_000);
        let mut output = vec![0u8; 32];
        pbkdf2_hmac::<Sha256>(&data, salt, iterations, &mut output);
        results.push(("pbkdf2-sha256".to_string(), output));
    }
    
    Ok(results)
}

// Trait pour uniformiser les hashers
trait Hasher: Send {
    fn update(&mut self, data: &[u8]);
    fn finalize(&mut self) -> Vec<u8>;
    fn name(&self) -> &'static str;
}

// Implémentations pour chaque algorithme
struct Blake3Hasher(blake3::Hasher);

impl Hasher for Blake3Hasher {
    fn update(&mut self, data: &[u8]) { self.0.update(data); }
    fn finalize(&mut self) -> Vec<u8> { self.0.finalize().as_bytes().to_vec() }
    fn name(&self) -> &'static str { "blake3" }
}

struct Sha256Hasher(sha2::Sha256);

impl Hasher for Sha256Hasher {
    fn update(&mut self, data: &[u8]) { self.0.update(data); }
    fn finalize(&mut self) -> Vec<u8> { self.0.finalize_reset().to_vec() }
    fn name(&self) -> &'static str { "sha256" }
}

struct Sha3_256Hasher(sha3::Sha3_256);

impl Hasher for Sha3_256Hasher {
    fn update(&mut self, data: &[u8]) { self.0.update(data); }
    fn finalize(&mut self) -> Vec<u8> { self.0.finalize_reset().to_vec() }
    fn name(&self) -> &'static str { "sha3-256" }
}

struct Sha3_512Hasher(sha3::Sha3_512);

impl Hasher for Sha3_512Hasher {
    fn update(&mut self, data: &[u8]) { self.0.update(data); }
    fn finalize(&mut self) -> Vec<u8> { self.0.finalize_reset().to_vec() }
    fn name(&self) -> &'static str { "sha3-512" }
}

struct Xxh3Hasher(xxhash_rust::xxh3::Xxh3);

impl Hasher for Xxh3Hasher {
    fn update(&mut self, data: &[u8]) { self.0.update(data); }
    fn finalize(&mut self) -> Vec<u8> { self.0.digest().to_le_bytes().to_vec() }
    fn name(&self) -> &'static str { "xxh3" }
}

fn create_hasher(algo: &str, salt: &[u8]) -> Result<Option<Box<dyn Hasher>>> {
    match algo {
        "blake3" => {
            let mut hasher = blake3::Hasher::new();
            if !salt.is_empty() {
                hasher.update(salt);
            }
            Ok(Some(Box::new(Blake3Hasher(hasher))))
        }
        "sha256" => {
            let mut hasher = sha2::Sha256::new();
            if !salt.is_empty() {
                hasher.update(salt);
            }
            Ok(Some(Box::new(Sha256Hasher(hasher))))
        }
        "sha3-256" => {
            let mut hasher = sha3::Sha3_256::new();
            if !salt.is_empty() {
                hasher.update(salt);
            }
            Ok(Some(Box::new(Sha3_256Hasher(hasher))))
        }
        "sha3-512" => {
            let mut hasher = sha3::Sha3_512::new();
            if !salt.is_empty() {
                hasher.update(salt);
            }
            Ok(Some(Box::new(Sha3_512Hasher(hasher))))
        }
        "xxh3" => {
            let mut hasher = xxhash_rust::xxh3::Xxh3::new();
            if !salt.is_empty() {
                hasher.update(salt);
            }
            Ok(Some(Box::new(Xxh3Hasher(hasher))))
        }
        "pbkdf2-sha256" => Ok(None), // Traité séparément
        _ => Err(Error::UnsupportedAlgorithm(algo.to_string())),
    }
}

pub fn hash_file(
    path: &str,
    algorithm: &str,
    salt: &[u8],
    iterations: Option<u32>,
) -> Result<Vec<u8>> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    hash_reader_single(&mut reader, algorithm, salt, iterations)
}

pub fn hash_data(
    data: &[u8],
    algorithm: &str,
    salt: &[u8],
    iterations: Option<u32>,
) -> Result<Vec<u8>> {
    let mut reader = data;
    hash_reader_single(&mut reader, algorithm, salt, iterations)
}

pub fn format_hash(hash: &[u8], format: &str) -> String {
    match format {
        "hex" => hex::encode(hash),
        "base64" => base64::encode(hash),
        "raw" => String::from_utf8_lossy(hash).to_string(),
        "json" => {
            if hash.len() <= 32 {
                format!("\"{}\"", hex::encode(hash))
            } else {
                format!("\"{}...\"", &hex::encode(&hash[..16]))
            }
        }
        _ => hex::encode(hash),
    }
}

pub fn format_multiple_results(results: &[(String, Vec<u8>)], format: &str) -> String {
    match format {
        "json" => {
            let mut json = String::from("{");
            for (i, (algo, hash)) in results.iter().enumerate() {
                if i > 0 { json.push_str(","); }
                json.push_str(&format!("\"{}\":\"{}\"", algo, hex::encode(hash)));
            }
            json.push_str("}");
            json
        }
        _ => results.iter()
            .map(|(algo, hash)| format!("{}:{}", algo, format_hash(hash, format)))
            .collect::<Vec<_>>()
            .join(" "),
    }
}

pub fn verify_hash(actual: &[u8], expected: &str, format: &str) -> Result<()> {
    let expected_bytes = match format {
        "hex" => hex::decode(expected)
            .map_err(|_| Error::Hash("Invalid hex format".to_string()))?,
        "base64" => base64::decode(expected)
            .map_err(|_| Error::Hash("Invalid base64 format".to_string()))?,
        _ => expected.as_bytes().to_vec(),
    };
    
    if actual == expected_bytes.as_slice() {
        Ok(())
    } else {
        Err(Error::Hash("Hash mismatch".to_string()))
    }
}

pub fn output_results(results: &[(String, Vec<Vec<u8>>)], format: &str, output: Option<&str>) -> Result<()> {
    let mut output_str = String::new();
    
    for (name, hashes) in results {
        output_str.push_str(&format!("{}:\n", name));
        for (i, hash) in hashes.iter().enumerate() {
            output_str.push_str(&format!("  Algo {}: {}\n", i + 1, format_hash(hash, format)));
        }
    }
    
    if let Some(output_path) = output {
        std::fs::write(output_path, output_str)?;
    } else {
        print!("{}", output_str);
    }
    
    Ok(())
}

