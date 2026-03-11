use crate::error::{Result, Error};
use std::fs::{self};
use zeroize::Zeroizing;
use rand::RngCore;
use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey};

pub fn generate_key(
    key_type: &str,
    output_path: &str,
    public_path: Option<&str>,
    format: &str,
    seed: Option<&str>,
    password: Option<String>,
    no_encrypt: bool,
    permissions: Option<&str>,
) -> Result<()> {
    match key_type {
        "aes-128" => generate_symmetric(16, output_path, format, seed, password, no_encrypt, permissions),
        "aes-256" => generate_symmetric(32, output_path, format, seed, password, no_encrypt, permissions),
        "chacha20" => generate_symmetric(32, output_path, format, seed, password, no_encrypt, permissions),
        "x25519" => generate_x25519(output_path, public_path, format, password, no_encrypt, permissions),
        "ed25519" => generate_ed25519(output_path, public_path, format, password, no_encrypt, permissions),
        "rsa-2048" => generate_rsa(2048, output_path, public_path, format, password, no_encrypt, permissions),
        "rsa-4096" => generate_rsa(4096, output_path, public_path, format, password, no_encrypt, permissions),
        _ => Err(Error::UnsupportedAlgorithm(key_type.to_string())),
    }
}

fn generate_symmetric(
    key_size: usize,
    output_path: &str,
    format: &str,
    seed: Option<&str>,
    password: Option<String>,
    no_encrypt: bool,
    permissions: Option<&str>,
) -> Result<()> {
    let key = if let Some(seed_phrase) = seed {
        derive_from_seed(seed_phrase.as_bytes(), key_size)?
    } else {
        let mut key = vec![0u8; key_size];
        rand::rngs::OsRng.fill_bytes(&mut key);
        key
    };
    
    let final_key = if no_encrypt {
        key
    } else if let Some(pw) = password {
        // Encrypt the key with password
        encrypt_key_with_password(&key, &pw)?
    } else {
        key
    };
    
    let encoded = encode_key(&final_key, format)?;
    fs::write(output_path, encoded)?;
    
    if let Some(perm) = permissions {
        set_permissions(output_path, perm)?;
    }
    
    Ok(())
}

fn generate_x25519(
    output_path: &str,
    public_path: Option<&str>,
    format: &str,
    password: Option<String>,
    no_encrypt: bool,
    permissions: Option<&str>,
) -> Result<()> {
    use x25519_dalek::{EphemeralSecret, PublicKey};
    
    let secret = EphemeralSecret::random_from_rng(rand::rngs::OsRng);
    let public = PublicKey::from(&secret);
    
    // Convert secret to bytes (via Diffie-Hellman)
    let secret_bytes: Zeroizing<Vec<u8>> = Zeroizing::new(secret.diffie_hellman(&public).as_bytes().to_vec());
    let public_bytes = public.as_bytes().to_vec();
    
    let final_secret = if no_encrypt {
        secret_bytes.to_vec()
    } else if let Some(pw) = password {
        encrypt_key_with_password(&secret_bytes, &pw)?
    } else {
        secret_bytes.to_vec()
    };
    
    let encoded_secret = encode_key(&final_secret, format)?;
    fs::write(output_path, encoded_secret)?;
    
    if let Some(pub_path) = public_path {
        let encoded_public = encode_key(&public_bytes, format)?;
        fs::write(pub_path, encoded_public)?;
    }
    
    if let Some(perm) = permissions {
        set_permissions(output_path, perm)?;
    }
    
    Ok(())
}

fn generate_ed25519(
    output_path: &str,
    public_path: Option<&str>,
    format: &str,
    password: Option<String>,
    no_encrypt: bool,
    permissions: Option<&str>,
) -> Result<()> {
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;
    
    let mut csprng = OsRng;
    let mut secret_bytes = [0u8; 32];
    csprng.fill_bytes(&mut secret_bytes);
    let signing_key = SigningKey::from_bytes(&secret_bytes);
    let verifying_key = signing_key.verifying_key();
    
    let secret_bytes: Zeroizing<Vec<u8>> = Zeroizing::new(signing_key.to_bytes().to_vec());
    let public_bytes = verifying_key.to_bytes().to_vec();
    
    let final_secret = if no_encrypt {
        secret_bytes.to_vec()
    } else if let Some(pw) = password {
        encrypt_key_with_password(&secret_bytes, &pw)?
    } else {
        secret_bytes.to_vec()
    };
    
    let encoded_secret = encode_key(&final_secret, format)?;
    fs::write(output_path, encoded_secret)?;
    
    if let Some(pub_path) = public_path {
        let encoded_public = encode_key(&public_bytes, format)?;
        fs::write(pub_path, encoded_public)?;
    }
    
    if let Some(perm) = permissions {
        set_permissions(output_path, perm)?;
    }
    
    Ok(())
}

fn generate_rsa(
    bits: usize,
    output_path: &str,
    public_path: Option<&str>,
    format: &str,
    password: Option<String>,
    no_encrypt: bool,
    permissions: Option<&str>,
) -> Result<()> {
    use rsa::{RsaPrivateKey, RsaPublicKey};
    use rand::rngs::OsRng;
    
    let mut rng = OsRng;
    let private_key = RsaPrivateKey::new(&mut rng, bits)
        .map_err(|e| Error::Key(format!("RSA generation failed: {}", e)))?;
    let public_key = RsaPublicKey::from(&private_key);
    
    let private_bytes = private_key.to_pkcs8_der()
        .map_err(|e| Error::Key(format!("RSA encoding failed: {}", e)))?
        .as_bytes()
        .to_vec();
    
    let public_bytes = public_key.to_public_key_der()
        .map_err(|e| Error::Key(format!("RSA public encoding failed: {}", e)))?
        .as_bytes()
        .to_vec();
    
    let final_private = if no_encrypt {
        private_bytes
    } else if let Some(pw) = password {
        encrypt_key_with_password(&private_bytes, &pw)?
    } else {
        private_bytes
    };
    
    let encoded_private = encode_key(&final_private, format)?;
    fs::write(output_path, encoded_private)?;
    
    if let Some(pub_path) = public_path {
        let encoded_public = encode_key(&public_bytes, format)?;
        fs::write(pub_path, encoded_public)?;
    }
    
    if let Some(perm) = permissions {
        set_permissions(output_path, perm)?;
    }
    
    Ok(())
}

fn derive_from_seed(seed: &[u8], key_size: usize) -> Result<Vec<u8>> {
    use sha3::{Sha3_256, Digest};
    let mut hasher = Sha3_256::new();
    hasher.update(seed);
    let hash = hasher.finalize();
    Ok(hash[..key_size].to_vec())
}

fn encrypt_key_with_password(key: &[u8], password: &str) -> Result<Vec<u8>> {
    // Simplified version - in reality, use AEAD
    let mut result = key.to_vec();
    for (i, b) in password.as_bytes().iter().cycle().enumerate() {
        if i >= result.len() { break; }
        result[i] ^= b;
    }
    Ok(result)
}

fn encode_key(key: &[u8], format: &str) -> Result<Vec<u8>> {
    match format {
        "raw" => Ok(key.to_vec()),
        "hex" => Ok(hex::encode(key).into_bytes()),
        "base64" => Ok(base64::encode(key).into_bytes()),
        "pem" => {
            let pem = format!("-----BEGIN KEY-----\n{}\n-----END KEY-----", 
                base64::encode(key));
            Ok(pem.into_bytes())
        }
        _ => Err(Error::InvalidParams(format!("Unknown format: {}", format))),
    }
}

fn set_permissions(path: &str, perm_str: &str) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(mode) = u32::from_str_radix(perm_str, 8) {
            let perm = fs::Permissions::from_mode(mode);
            fs::set_permissions(path, perm)?;
        }
    }
    Ok(())
}

pub fn print_key_info(path: &str, verbose: bool) -> Result<()> {
    let data = fs::read(path)?;
    
    println!("Key file: {}", path);
    println!("Size: {} bytes", data.len());
    
    if verbose {
        println!("First bytes: {:02x?}", &data[..data.len().min(16)]);
    }
    
    // Basic type detection
    if data.len() == 32 {
        println!("Probable type: symmetric key (256 bits)");
    } else if data.len() == 64 {
        println!("Probable type: Ed25519 private key");
    }
    
    Ok(())
}

pub fn calculate_fingerprint(path: &str, algorithm: &str) -> Result<String> {
    let data = fs::read(path)?;
    
    let hash = match algorithm {
        "blake3" => {
            let hash = blake3::hash(&data);
            hex::encode(hash.as_bytes())
        }
        "sha256" => {
            use sha2::{Sha256, Digest};
            let mut hasher = Sha256::new();
            hasher.update(&data);
            hex::encode(hasher.finalize())
        }
        _ => return Err(Error::UnsupportedAlgorithm(algorithm.to_string())),
    };
    
    Ok(hash)
}

pub fn convert_key(input: &str, output: &str, from: &str, to: &str) -> Result<()> {
    let data = fs::read(input)?;
    
    // Decode from source format
    let decoded = match from {
        "raw" => data,
        "hex" => hex::decode(&data)
            .map_err(|_| Error::InvalidFormat("Invalid hex".to_string()))?,
        "base64" => base64::decode(&data)
            .map_err(|_| Error::InvalidFormat("Invalid base64".to_string()))?,
        "pem" => {
            let s = String::from_utf8_lossy(&data);
            let lines: Vec<&str> = s.lines().collect();
            if lines.len() >= 2 {
                base64::decode(lines[1].trim())
                    .map_err(|_| Error::InvalidFormat("Invalid PEM".to_string()))?
            } else {
                return Err(Error::InvalidFormat("Invalid PEM format".to_string()));
            }
        }
        _ => return Err(Error::InvalidParams(format!("Unknown source format: {}", from))),
    };
    
    // Encode to target format
    let encoded = encode_key(&decoded, to)?;
    fs::write(output, encoded)?;
    
    Ok(())
}

