use crate::error::{Result, Error};
use crate::header::{FileHeader, CompressionInfo, HashAlgo};
use crate::compression;
use crate::hashing;
use std::fs::File;
use std::io::{Read, Write, BufReader, Seek, SeekFrom};
use std::path::Path;
use std::time::Instant;
use rand::RngCore;

use aes_gcm::{
    Aes256Gcm, Key, Nonce,
    aead::{Aead, KeyInit},
};
use chacha20poly1305::ChaCha20Poly1305;
use argon2::{Argon2};
use rand::rngs::OsRng;

const BUFFER_SIZE: usize = 64 * 1024; // 64 KB

pub fn encrypt_file(
    input_path: &str,
    output_path: &str,
    key_material: &[u8],
    symmetric_algo: &str,
    _asymmetric_algo: Option<&str>,
    _recipient: Option<&str>,
    compression_algo: &str,
    compress_level: u32,
    kdf_algo: &str,
    kdf_params: Option<&str>,
    integrity_algo: &str,
    preserve_mode: bool,
    preserve_timestamps: bool,
    progress: bool,
) -> Result<()> {
    let input_file = File::open(input_path)?;
    let metadata = input_file.metadata()?;
    let original_size = metadata.len();
    
    // Lire les données originales
    let mut input_reader = BufReader::new(input_file);
    let mut original_data = Vec::new();
    input_reader.read_to_end(&mut original_data)?;
    
    // Générer l'en-tête
    let mut header = FileHeader::new();
    header.algorithm = symmetric_algo.to_string();
    header.original_size = original_size;
    if let Some(name) = Path::new(input_path).file_name() {
        header.original_name = Some(name.to_string_lossy().to_string());
    }
    
    if preserve_mode {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            header.original_mode = Some(metadata.mode());
        }
    }
    
    if preserve_timestamps {
        if let Ok(modified) = metadata.modified() {
            header.original_modified = Some(modified.into());
        }
    }
    
    // Générer salt et IV
    let mut salt = [0u8; 32];
    let mut iv = [0u8; 12];
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut iv);
    header.salt = Some(salt);
    header.iv = iv;
    
    // Dériver la clé de chiffrement
    let key = derive_key(key_material, &salt, kdf_algo, kdf_params)?;
    
    // Compression si demandée
    let data_to_encrypt = if compression_algo != "none" {
        if progress {
            eprintln!("Compressing with {}...", compression_algo);
        }
        
        let compressed = compression::compress_data(&original_data, compression_algo, compress_level as i32)?;
        
        header.compression = Some(CompressionInfo {
            algorithm: compression_algo.to_string(),
            level: compress_level,
            original_size,
            compressed_size: compressed.len() as u64,
        });
        
        compressed
    } else {
        original_data
    };
    
    // Calculer le hash si demandé (après compression)
    if integrity_algo != "none" {
        let hash = hashing::hash_data(&data_to_encrypt, integrity_algo, &[], None)?;
        header.original_hash = Some((hash_algo_from_str(integrity_algo)?, hash));
    }
    
    // Chiffrer les données
    if progress {
        eprintln!("Encrypting with {}...", symmetric_algo);
    }
    
    let ciphertext = match symmetric_algo {
        "aes-256-gcm" => encrypt_aes_gcm(&data_to_encrypt, &key, &iv)?,
        "chacha20" => encrypt_chacha20(&data_to_encrypt, &key, &iv)?,
        _ => return Err(Error::UnsupportedAlgorithm(symmetric_algo.to_string())),
    };
    
    // Écrire l'en-tête ET les données chiffrées dans le même fichier
    let mut final_file = File::create(output_path)?;
    header.write_to_file(&mut final_file)?;
    final_file.write_all(&ciphertext)?;
    final_file.flush()?;
    
    if progress {
        eprintln!("Encryption completed ({} bytes -> {} bytes)", original_size, ciphertext.len());
    }
    
    Ok(())
}

pub fn decrypt_file(
    input_path: &str,
    output_path: &str,
    key_material: &[u8],
    no_decompress: bool,
    verify_integrity: bool,
    restore_mode: bool,
    restore_timestamps: bool,
    progress: bool,
) -> Result<()> {
    // Lire l'en-tête et récupérer le fichier avec le curseur positionné après l'en-tête
    let (header, mut input_file) = FileHeader::read_from_file(input_path)?;
    
    if progress {
        eprintln!("File: {}, Algorithm: {}, Original size: {}, Header size: {}", 
            header.original_name.as_deref().unwrap_or("unknown"),
            header.algorithm,
            header.original_size,
            header.header_size
        );
    }
    
    // Dériver la clé
    let key = if let Some(salt) = &header.salt {
        derive_key(key_material, salt, "argon2", None)?
    } else {
        key_material.to_vec()
    };
    
    // Lire les données chiffrées (le curseur est déjà après l'en-tête)
    let mut ciphertext = Vec::new();
    input_file.read_to_end(&mut ciphertext)?;
    
    if progress {
        eprintln!("Read {} bytes of encrypted data", ciphertext.len());
    }
    
    // Déchiffrer
    if progress {
        eprintln!("Decrypting...");
    }
    
    let decrypted_data = match header.algorithm.as_str() {
        "aes-256-gcm" => decrypt_aes_gcm(&ciphertext, &key, &header.iv)?,
        "chacha20" => decrypt_chacha20(&ciphertext, &key, &header.iv)?,
        algo => return Err(Error::UnsupportedAlgorithm(algo.to_string())),
    };
    
    if progress {
        eprintln!("Decrypted {} bytes", decrypted_data.len());
    }
    
    // Vérifier l'intégrité si demandé
    if verify_integrity {
        if let Some((hash_algo, expected_hash)) = &header.original_hash {
            if progress {
                eprintln!("Verifying integrity...");
            }
            let actual_hash = hashing::hash_data(&decrypted_data, hash_algo_to_str(hash_algo)?, &[], None)?;
            if actual_hash != *expected_hash {
                return Err(Error::IntegrityCheckFailed);
            }
            if progress {
                eprintln!("Integrity verified");
            }
        }
    }
    
    // Décompresser si nécessaire
    let final_data = if let Some(comp) = &header.compression {
        if no_decompress {
            if progress {
                eprintln!("Skipping decompression (--no-decompress)");
            }
            decrypted_data
        } else {
            if progress {
                eprintln!("Decompressing with {}...", comp.algorithm);
            }
            compression::decompress_data(&decrypted_data, &comp.algorithm)?
        }
    } else {
        decrypted_data
    };
    
    // Créer le répertoire parent si nécessaire
    if let Some(parent) = Path::new(output_path).parent() {
        std::fs::create_dir_all(parent)?;
    }
    
    // Écrire le fichier final
    std::fs::write(output_path, &final_data)?;
    
    // Restaurer les métadonnées si demandé
    if restore_mode {
        if let Some(mode) = header.original_mode {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let perm = std::fs::Permissions::from_mode(mode);
                std::fs::set_permissions(output_path, perm)?;
            }
        }
    }
    
    if restore_timestamps {
        if let Some(modified) = header.original_modified {
            let filetime = filetime::FileTime::from_system_time(modified.into());
            filetime::set_file_times(output_path, filetime, filetime)?;
        }
    }
    
    if progress {
        eprintln!("Decryption completed!");
    }
    
    Ok(())
}

// Le reste des fonctions reste identique
fn encrypt_aes_gcm(data: &[u8], key: &[u8], iv: &[u8; 12]) -> Result<Vec<u8>> {
    let key = Key::<Aes256Gcm>::from_slice(key);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(iv);
    
    cipher.encrypt(nonce, data)
        .map_err(|e| Error::Crypto(format!("Encryption failed: {}", e)))
}

fn decrypt_aes_gcm(data: &[u8], key: &[u8], iv: &[u8; 12]) -> Result<Vec<u8>> {
    let key = Key::<Aes256Gcm>::from_slice(key);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(iv);
    
    cipher.decrypt(nonce, data)
        .map_err(|e| Error::Crypto(format!("Decryption failed: {}", e)))
}

fn encrypt_chacha20(data: &[u8], key: &[u8], iv: &[u8; 12]) -> Result<Vec<u8>> {
    use chacha20poly1305::Key as ChaKey;
    
    let key = ChaKey::from_slice(key);
    let cipher = ChaCha20Poly1305::new(key);
    let nonce = chacha20poly1305::Nonce::from_slice(iv);
    
    cipher.encrypt(nonce, data)
        .map_err(|e| Error::Crypto(format!("Encryption failed: {}", e)))
}

fn decrypt_chacha20(data: &[u8], key: &[u8], iv: &[u8; 12]) -> Result<Vec<u8>> {
    use chacha20poly1305::Key as ChaKey;
    
    let key = ChaKey::from_slice(key);
    let cipher = ChaCha20Poly1305::new(key);
    let nonce = chacha20poly1305::Nonce::from_slice(iv);
    
    cipher.decrypt(nonce, data)
        .map_err(|e| Error::Crypto(format!("Decryption failed: {}", e)))
}

pub fn read_key_file(path: &str) -> Result<Vec<u8>> {
    std::fs::read(path)
        .map_err(|e| Error::Key(format!("Unable to read key file: {}", e)))
}

pub fn verify_integrity(input_path: &str, key: &[u8]) -> Result<()> {
    let (header, mut file) = FileHeader::read_from_file(input_path)?;
    
    let mut ciphertext = Vec::new();
    file.read_to_end(&mut ciphertext)?;
    
    let key = if let Some(salt) = &header.salt {
        derive_key(key, salt, "argon2", None)?
    } else {
        key.to_vec()
    };
    
    let decrypted = match header.algorithm.as_str() {
        "aes-256-gcm" => decrypt_aes_gcm(&ciphertext, &key, &header.iv)?,
        "chacha20" => decrypt_chacha20(&ciphertext, &key, &header.iv)?,
        algo => return Err(Error::UnsupportedAlgorithm(algo.to_string())),
    };
    
    if let Some((hash_algo, expected_hash)) = &header.original_hash {
        let actual_hash = hashing::hash_data(&decrypted, hash_algo_to_str(hash_algo)?, &[], None)?;
        if actual_hash != *expected_hash {
            return Err(Error::IntegrityCheckFailed);
        }
    }
    
    Ok(())
}

pub fn run_benchmark(algos: &[&str], data_size: usize) -> Result<()> {
    let data = vec![0u8; data_size];
    let key = vec![0u8; 32];
    let iv = [0u8; 12];
    
    for algo in algos {
        match *algo {
            "aes-256-gcm" => {
                let start = Instant::now();
                let _ = encrypt_aes_gcm(&data, &key, &iv)?;
                let duration = start.elapsed();
                println!("AES-256-GCM: {:?} for {} MB", duration, data_size / (1024 * 1024));
            }
            "chacha20" => {
                let start = Instant::now();
                let _ = encrypt_chacha20(&data, &key, &iv)?;
                let duration = start.elapsed();
                println!("ChaCha20: {:?} for {} MB", duration, data_size / (1024 * 1024));
            }
            "blake3" => {
                let start = Instant::now();
                let _ = hashing::hash_data(&data, "blake3", &[], None)?;
                let duration = start.elapsed();
                println!("BLAKE3: {:?} for {} MB", duration, data_size / (1024 * 1024));
            }
            "sha256" => {
                let start = Instant::now();
                let _ = hashing::hash_data(&data, "sha256", &[], None)?;
                let duration = start.elapsed();
                println!("SHA-256: {:?} for {} MB", duration, data_size / (1024 * 1024));
            }
            "xxh3" => {
                let start = Instant::now();
                let _ = hashing::hash_data(&data, "xxh3", &[], None)?;
                let duration = start.elapsed();
                println!("xxHash3: {:?} for {} MB", duration, data_size / (1024 * 1024));
            }
            _ => println!("Unknown algorithm: {}", algo),
        }
    }
    
    Ok(())
}

fn derive_key(password: &[u8], salt: &[u8], algo: &str, _params: Option<&str>) -> Result<Vec<u8>> {
    let mut key = vec![0u8; 32];
    
    match algo {
        "argon2" => {
            let argon2 = Argon2::default();
            argon2.hash_password_into(password, salt, &mut key)
                .map_err(|e| Error::Crypto(format!("Argon2 failed: {}", e)))?;
        }
        "pbkdf2" => {
            use sha2::Sha256;
            use pbkdf2::pbkdf2_hmac;
            pbkdf2_hmac::<Sha256>(password, salt, 100_000, &mut key);
        }
        _ => return Err(Error::UnsupportedAlgorithm(algo.to_string())),
    }
    
    Ok(key)
}

fn hash_algo_from_str(s: &str) -> Result<HashAlgo> {
    match s {
        "blake3" => Ok(HashAlgo::Blake3),
        "sha256" => Ok(HashAlgo::Sha256),
        "sha3-256" => Ok(HashAlgo::Sha3_256),
        "sha3-512" => Ok(HashAlgo::Sha3_512),
        "xxh3" => Ok(HashAlgo::Xxh3),
        _ => Err(Error::UnsupportedAlgorithm(s.to_string())),
    }
}

fn hash_algo_to_str(algo: &HashAlgo) -> Result<&'static str> {
    match algo {
        HashAlgo::Blake3 => Ok("blake3"),
        HashAlgo::Sha256 => Ok("sha256"),
        HashAlgo::Sha3_256 => Ok("sha3-256"),
        HashAlgo::Sha3_512 => Ok("sha3-512"),
        HashAlgo::Xxh3 => Ok("xxh3"),
    }
}

