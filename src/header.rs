use crate::error::{Result, Error};
use chrono::{DateTime, Utc};
use std::fs::File;
use std::io::{Read, Write, Seek, SeekFrom};
use std::path::Path;
use zeroize::Zeroize;

pub const MAGIC: [u8; 8] = *b"TCRYPT01";
pub const VERSION: u8 = 1;

#[derive(Debug)]
pub struct FileHeader {
    pub magic: [u8; 8],
    pub version: u8,
    pub created_at: DateTime<Utc>,
    pub algorithm: String,
    pub key_derivation: Option<KDFParams>,
    pub salt: Option<[u8; 32]>,
    pub iv: [u8; 12],
    pub auth_type: AuthType,
    pub auth_data: Option<Vec<u8>>,
    pub compression: Option<CompressionInfo>,
    pub original_hash: Option<(HashAlgo, Vec<u8>)>,
    pub original_name: Option<String>,
    pub original_size: u64,
    pub original_mode: Option<u32>,
    pub original_modified: Option<DateTime<Utc>>,
    pub recipients: Option<Vec<RecipientInfo>>,
    pub header_size: usize, // Nouveau champ pour connaître la taille de l'en-tête
}

#[derive(Debug)]
pub enum AuthType {
    None,
    Password,
    KeyFile,
    Asymmetric,
}

#[derive(Debug)]
pub struct KDFParams {
    pub algorithm: String,
    pub memory: u32,
    pub iterations: u32,
    pub parallelism: u32,
}

#[derive(Debug)]
pub struct CompressionInfo {
    pub algorithm: String,
    pub level: u32,
    pub original_size: u64,
    pub compressed_size: u64,
}

#[derive(Debug)]
pub enum HashAlgo {
    Blake3,
    Sha256,
    Sha3_256,
    Sha3_512,
    Xxh3,
}

#[derive(Debug)]
pub struct RecipientInfo {
    pub public_key_fingerprint: String,
    pub encrypted_key: Vec<u8>,
}

impl FileHeader {
    pub fn new() -> Self {
        Self {
            magic: MAGIC,
            version: VERSION,
            created_at: Utc::now(),
            algorithm: String::new(),
            key_derivation: None,
            salt: None,
            iv: [0u8; 12],
            auth_type: AuthType::None,
            auth_data: None,
            compression: None,
            original_hash: None,
            original_name: None,
            original_size: 0,
            original_mode: None,
            original_modified: None,
            recipients: None,
            header_size: 0,
        }
    }

    pub fn read_from_file<P: AsRef<Path>>(path: P) -> Result<(Self, File)> {
        let mut file = File::open(path)?;
        let start_pos = file.stream_position()?;
        let mut header = Self::new();
        
        // Lire le magic number
        let mut magic_buf = [0u8; 8];
        file.read_exact(&mut magic_buf)?;
        header.magic = magic_buf;
        
        if magic_buf != MAGIC {
            return Err(Error::InvalidMagic);
        }
        
        // Lire la version
        let mut version_buf = [0u8; 1];
        file.read_exact(&mut version_buf)?;
        header.version = version_buf[0];
        
        if header.version > VERSION {
            return Err(Error::UnsupportedVersion(header.version));
        }
        
        // Lire created_at (timestamp)
        let mut created_buf = [0u8; 16];
        file.read_exact(&mut created_buf)?;
        // Simplifié - dans la vraie vie, utilisez bincode
        header.created_at = Utc::now();
        
        // Lire la longueur de l'algorithme
        let mut algo_len_buf = [0u8; 4];
        file.read_exact(&mut algo_len_buf)?;
        let algo_len = u32::from_le_bytes(algo_len_buf) as usize;
        
        // Lire le nom de l'algorithme
        let mut algo_buf = vec![0u8; algo_len];
        file.read_exact(&mut algo_buf)?;
        header.algorithm = String::from_utf8_lossy(&algo_buf).to_string();
        
        // Lire le flag salt
        let mut salt_flag = [0u8; 1];
        file.read_exact(&mut salt_flag)?;
        if salt_flag[0] == 1 {
            let mut salt_buf = [0u8; 32];
            file.read_exact(&mut salt_buf)?;
            header.salt = Some(salt_buf);
        }
        
        // Lire IV
        let mut iv_buf = [0u8; 12];
        file.read_exact(&mut iv_buf)?;
        header.iv = iv_buf;
        
        // Lire le type d'authentification
        let mut auth_buf = [0u8; 1];
        file.read_exact(&mut auth_buf)?;
        header.auth_type = match auth_buf[0] {
            0 => AuthType::None,
            1 => AuthType::Password,
            2 => AuthType::KeyFile,
            3 => AuthType::Asymmetric,
            _ => AuthType::None,
        };
        
        // Lire le flag compression
        let mut comp_flag = [0u8; 1];
        file.read_exact(&mut comp_flag)?;
        if comp_flag[0] == 1 {
            // Lire la longueur du nom de l'algo de compression
            let mut comp_algo_len_buf = [0u8; 4];
            file.read_exact(&mut comp_algo_len_buf)?;
            let comp_algo_len = u32::from_le_bytes(comp_algo_len_buf) as usize;
            
            // Lire le nom de l'algo de compression
            let mut comp_algo_buf = vec![0u8; comp_algo_len];
            file.read_exact(&mut comp_algo_buf)?;
            let comp_algo = String::from_utf8_lossy(&comp_algo_buf).to_string();
            
            // Lire le niveau de compression
            let mut level_buf = [0u8; 4];
            file.read_exact(&mut level_buf)?;
            let level = u32::from_le_bytes(level_buf);
            
            // Lire la taille originale
            let mut orig_size_buf = [0u8; 8];
            file.read_exact(&mut orig_size_buf)?;
            let orig_size = u64::from_le_bytes(orig_size_buf);
            
            // Lire la taille compressée
            let mut comp_size_buf = [0u8; 8];
            file.read_exact(&mut comp_size_buf)?;
            let comp_size = u64::from_le_bytes(comp_size_buf);
            
            header.compression = Some(CompressionInfo {
                algorithm: comp_algo,
                level,
                original_size: orig_size,
                compressed_size: comp_size,
            });
        }
        
        // Lire la taille originale
        let mut size_buf = [0u8; 8];
        file.read_exact(&mut size_buf)?;
        header.original_size = u64::from_le_bytes(size_buf);
        
        // Lire le flag nom original
        let mut name_flag = [0u8; 1];
        file.read_exact(&mut name_flag)?;
        if name_flag[0] == 1 {
            // Lire la longueur du nom
            let mut name_len_buf = [0u8; 4];
            file.read_exact(&mut name_len_buf)?;
            let name_len = u32::from_le_bytes(name_len_buf) as usize;
            
            // Lire le nom
            let mut name_buf = vec![0u8; name_len];
            file.read_exact(&mut name_buf)?;
            header.original_name = Some(String::from_utf8_lossy(&name_buf).to_string());
        }
        
        // Calculer la taille de l'en-tête
        let end_pos = file.stream_position()?;
        header.header_size = (end_pos - start_pos) as usize;
        
        Ok((header, file))
    }

    pub fn write_to_file<W: Write>(&self, writer: &mut W) -> Result<()> {
        // Écrire le magic number
        writer.write_all(&MAGIC)?;
        
        // Écrire la version
        writer.write_all(&[VERSION])?;
        
        // Écrire created_at (timestamp simplifié)
        let created_bytes = [0u8; 16]; // Placeholder
        writer.write_all(&created_bytes)?;
        
        // Écrire l'algorithme
        let algo_bytes = self.algorithm.as_bytes();
        writer.write_all(&(algo_bytes.len() as u32).to_le_bytes())?;
        writer.write_all(algo_bytes)?;
        
        // Écrire le salt
        if let Some(salt) = &self.salt {
            writer.write_all(&[1])?;
            writer.write_all(salt)?;
        } else {
            writer.write_all(&[0])?;
        }
        
        // Écrire IV
        writer.write_all(&self.iv)?;
        
        // Écrire le type d'authentification
        let auth_byte = match self.auth_type {
            AuthType::None => 0,
            AuthType::Password => 1,
            AuthType::KeyFile => 2,
            AuthType::Asymmetric => 3,
        };
        writer.write_all(&[auth_byte])?;
        
        // Écrire la compression
        if let Some(comp) = &self.compression {
            writer.write_all(&[1])?;
            
            let comp_algo_bytes = comp.algorithm.as_bytes();
            writer.write_all(&(comp_algo_bytes.len() as u32).to_le_bytes())?;
            writer.write_all(comp_algo_bytes)?;
            
            writer.write_all(&comp.level.to_le_bytes())?;
            writer.write_all(&comp.original_size.to_le_bytes())?;
            writer.write_all(&comp.compressed_size.to_le_bytes())?;
        } else {
            writer.write_all(&[0])?;
        }
        
        // Écrire la taille originale
        writer.write_all(&self.original_size.to_le_bytes())?;
        
        // Écrire le nom original
        if let Some(name) = &self.original_name {
            writer.write_all(&[1])?;
            let name_bytes = name.as_bytes();
            writer.write_all(&(name_bytes.len() as u32).to_le_bytes())?;
            writer.write_all(name_bytes)?;
        } else {
            writer.write_all(&[0])?;
        }
        
        Ok(())
    }

    pub fn validate(&self) -> Result<()> {
        if self.magic != MAGIC {
            return Err(Error::InvalidMagic);
        }
        if self.version > VERSION {
            return Err(Error::UnsupportedVersion(self.version));
        }
        Ok(())
    }
}

impl Zeroize for FileHeader {
    fn zeroize(&mut self) {
        self.magic.zeroize();
        self.version.zeroize();
        self.algorithm.zeroize();
        if let Some(salt) = &mut self.salt {
            salt.zeroize();
        }
        self.iv.zeroize();
        if let Some(auth_data) = &mut self.auth_data {
            auth_data.zeroize();
        }
    }
}

impl Drop for FileHeader {
    fn drop(&mut self) {
        self.zeroize();
    }
}

pub fn print_file_info(path: &str, verbose: bool) -> Result<()> {
    let (header, _) = FileHeader::read_from_file(path)?;
    
    println!("File: {}", path);
    println!("Magic: {:?}", String::from_utf8_lossy(&header.magic));
    println!("Version: {}", header.version);
    println!("Created: {}", header.created_at);
    println!("Algorithm: {}", header.algorithm);
    println!("Original size: {} bytes", header.original_size);
    println!("Header size: {} bytes", header.header_size);
    
    if let Some(name) = &header.original_name {
        println!("Original name: {}", name);
    }
    
    if let Some(comp) = &header.compression {
        println!("Compression: {} (level {})", comp.algorithm, comp.level);
        println!("  Original: {} bytes", comp.original_size);
        println!("  Compressed: {} bytes", comp.compressed_size);
    }
    
    if verbose {
        if let Some(hash) = &header.original_hash {
            println!("Original hash: {:?}", hash);
        }
        if let Some(recipients) = &header.recipients {
            println!("Recipients: {}", recipients.len());
        }
    }
    
    Ok(())
}

