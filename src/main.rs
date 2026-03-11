use std::env;
use std::fs::{self};
use std::io::{self, Write, Read};
use std::path::{Path};
use std::process::exit;

mod crypto;
mod compression;
mod hashing;
mod key;
mod header;
mod error;

use error::Result;
use header::FileHeader;

const VERSION: &str = "1.0.0";
const AUTHOR: &str = "Philippe TEMESI";
const WEBSITE: &str = "https://www.tems.be";
const YEAR: &str = "2026";

fn main() {
    let args: Vec<String> = env::args().collect();
    
    if args.len() < 2 {
        print_usage();
        exit(1);
    }

    let command = &args[1];
    
    let result = match command.as_str() {
        "encrypt" => cmd_encrypt(&args[2..]),
        "decrypt" => cmd_decrypt(&args[2..]),
        "hash" => cmd_hash(&args[2..]),
        "key" => cmd_key(&args[2..]),
        "info" => cmd_info(&args[2..]),
        "verify" => cmd_verify(&args[2..]),
        "benchmark" => cmd_benchmark(&args[2..]),
        "--help" | "-h" | "help" => {
            print_usage();
            Ok(())
        }
        "--version" | "-v" => {
            println!("tems-crypt {} ({}) - {} {}", VERSION, YEAR, AUTHOR, WEBSITE);
            Ok(())
        }
        _ => {
            eprintln!("Unknown command: {}", command);
            print_usage();
            exit(1);
        }
    };

    if let Err(e) = result {
        eprintln!("Error: {}", e);
        exit(1);
    }
}

fn print_usage() {
    println!(r#"tems-crypt {} - {} {}
Author: {} © {}

USAGE:
    tems-crypt <COMMAND> [OPTIONS]

COMMANDS:
    encrypt     Encrypt a file or directory
    decrypt     Decrypt a file or directory
    hash        Calculate hash(es)
    key         Key management
    info        Display information about a .tcrypt file
    verify      Verify integrity
    benchmark   Run performance benchmarks
    help        Show this help
    version     Show version information

ENCRYPT:
    tems-crypt encrypt -i <file/dir> -o <output> [OPTIONS]

    OPTIONS:
        -i, --input <path>           Input file or directory (required)
        -o, --output <path>          Output file or directory (required)
        -p, --password <pass>         Password (not recommended)
        --ask-password                Prompt for password
        --password-file <file>         File containing password
        --password-env <var>           Environment variable with password
        --key-file <file>              Key file
        --key-stdin                     Read key from stdin
        -s, --symmetric <algo>         Algorithm: aes-256-gcm, chacha20 (default: aes-256-gcm)
        -a, --asymmetric <algo>        Algorithm: x25519, ed25519
        --recipient <file>              Recipient's public key
        -c, --compression <algo>        Algorithm: gz, zstd, xz, none (default: none)
        --compress-level <n>            Compression level (1-19, default: 6)
        --kdf <algo>                    KDF algorithm: argon2, pbkdf2 (default: argon2)
        --kdf-params <params>           KDF parameters (e.g., "m=19456,t=2,p=1")
        --integrity <algo>              Integrity algorithm: blake3, sha3 (default: blake3)
        --preserve-mode                  Preserve file permissions
        --preserve-timestamps            Preserve timestamps
        --remove-original                 Delete original file(s) after successful encryption
        --include-hidden                  Include hidden files (dot files) when recursing
        --progress                        Show progress
        -r, --recursive                   Process directories recursively
        -h, --help                         Show this help

DECRYPT:
    tems-crypt decrypt -i <file.tcrypt> -o <output> [OPTIONS]

    OPTIONS:
        -i, --input <path>            Input .tcrypt file or directory (required)
        -o, --output <path>            Output file or directory (required)
        -p, --password <pass>          Password
        --ask-password                  Prompt for password
        --password-file <file>           File containing password
        --password-env <var>             Environment variable with password
        --key-file <file>                Key file
        --key-stdin                       Read key from stdin
        --private-key <file>              Private key for asymmetric
        --no-decompress                    Do not automatically decompress
        --verify-integrity                 Verify integrity
        --restore-mode                      Restore file permissions
        --restore-timestamps                 Restore timestamps
        --remove-encrypted                    Delete encrypted file(s) after successful decryption
        --progress                              Show progress
        --no-clobber                             Do not overwrite existing files
        -h, --help                                 Show this help

HASH:
    tems-crypt hash -i <file> [OPTIONS]

    OPTIONS:
        -i, --input <file>            File to hash (or - for stdin)
        --stdin                         Read from stdin
        -a, --algorithm <algo>          Algorithm: blake3, sha256, sha3-256, sha3-512, xxh3
        --algorithms <list>              Comma-separated list of algorithms
        --output <file>                   Output file
        --format <format>                 Format: hex, base64, raw, json (default: hex)
        --salt <salt>                      Salt for hashing
        --salt-file <file>                  File containing salt
        --iterations <n>                     Number of iterations (for PBKDF2)
        --check <hash>                        Verify hash
        --include-hidden                       Include hidden files when recursing
        -r, --recursive                         Hash recursively
        -h, --help                                Show this help

KEY:
    tems-crypt key generate [OPTIONS]

    OPTIONS:
        --type <type>                    Type: aes-128, aes-256, chacha20, x25519, ed25519, rsa-2048, rsa-4096
        --output <file>                    Output file (private key)
        --public <file>                      Public key file (for asymmetric)
        --format <format>                     Format: raw, pem, hex, base64 (default: raw)
        --seed-from-password <phrase>         Generate from seed phrase
        --encrypt                               Protect with password
        --ask-password                            Prompt for password
        --no-encrypt                               Do not protect
        --permissions <mode>                        File permissions (e.g., 600)
        -h, --help                                     Show this help

    tems-crypt key info --key-file <file>

    tems-crypt key fingerprint --key-file <file> [--algorithm <algo>]

    tems-crypt key convert --input <file> --output <file> --from <format> --to <format>

INFO:
    tems-crypt info -i <file.tcrypt> [--verbose]

VERIFY:
    tems-crypt verify -i <file.tcrypt> --key-file <file>

BENCHMARK:
    tems-crypt benchmark [--algorithms <list>] [--data-size <size>]

EXAMPLES:
    # Encrypt a single file
    tems-crypt encrypt -i secret.txt -o secret.tcrypt --ask-password
    
    # Encrypt a directory recursively
    tems-crypt encrypt -i documents/ -o documents.tcrypt --recursive --key-file backup.key
    
    # Encrypt and remove original
    tems-crypt encrypt -i photo.jpg -o photo.tcrypt --key-file key.bin --remove-original
    
    # Encrypt with compression
    tems-crypt encrypt -i largefile.dat -o large.tcrypt --compression zstd --ask-password
    
    # Decrypt a directory
    tems-crypt decrypt -i documents.tcrypt -o documents/ --key-file backup.key
    
    # Hash a file
    tems-crypt hash -i file.bin -a blake3
    
    # Hash from stdin
    echo "test" | tems-crypt hash --stdin -a sha256
    
    # Generate a key
    tems-crypt key generate --type aes-256 --output key.bin --no-encrypt
"#, VERSION, YEAR, AUTHOR, WEBSITE, YEAR);
}

fn cmd_encrypt(args: &[String]) -> Result<()> {
    let mut input = None;
    let mut output = None;
    let mut password = None;
    let mut ask_password = false;
    let mut password_file = None;
    let mut password_env = None;
    let mut key_file = None;
    let mut key_stdin = false;
    let mut symmetric = "aes-256-gcm".to_string();
    let mut asymmetric = None;
    let mut recipient = None;
    let mut compression = "none".to_string();
    let mut compress_level = 6;
    let mut kdf = "argon2".to_string();
    let mut kdf_params = None;
    let mut integrity = "blake3".to_string();
    let mut preserve_mode = false;
    let mut preserve_timestamps = false;
    let mut remove_original = false;
    let mut include_hidden = false;
    let mut progress = false;
    let mut recursive = false;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-i" | "--input" => {
                i += 1;
                if i < args.len() {
                    input = Some(args[i].clone());
                }
            }
            "-o" | "--output" => {
                i += 1;
                if i < args.len() {
                    output = Some(args[i].clone());
                }
            }
            "-p" | "--password" => {
                i += 1;
                if i < args.len() {
                    password = Some(args[i].clone());
                }
            }
            "--ask-password" => ask_password = true,
            "--password-file" => {
                i += 1;
                if i < args.len() {
                    password_file = Some(args[i].clone());
                }
            }
            "--password-env" => {
                i += 1;
                if i < args.len() {
                    password_env = Some(args[i].clone());
                }
            }
            "--key-file" => {
                i += 1;
                if i < args.len() {
                    key_file = Some(args[i].clone());
                }
            }
            "--key-stdin" => key_stdin = true,
            "-s" | "--symmetric" => {
                i += 1;
                if i < args.len() {
                    symmetric = args[i].clone();
                }
            }
            "-a" | "--asymmetric" => {
                i += 1;
                if i < args.len() {
                    asymmetric = Some(args[i].clone());
                }
            }
            "--recipient" => {
                i += 1;
                if i < args.len() {
                    recipient = Some(args[i].clone());
                }
            }
            "-c" | "--compression" => {
                i += 1;
                if i < args.len() {
                    compression = args[i].clone();
                }
            }
            "--compress-level" => {
                i += 1;
                if i < args.len() {
                    compress_level = args[i].parse().unwrap_or(6);
                }
            }
            "--kdf" => {
                i += 1;
                if i < args.len() {
                    kdf = args[i].clone();
                }
            }
            "--kdf-params" => {
                i += 1;
                if i < args.len() {
                    kdf_params = Some(args[i].clone());
                }
            }
            "--integrity" => {
                i += 1;
                if i < args.len() {
                    integrity = args[i].clone();
                }
            }
            "--preserve-mode" => preserve_mode = true,
            "--preserve-timestamps" => preserve_timestamps = true,
            "--remove-original" => remove_original = true,
            "--include-hidden" => include_hidden = true,
            "--progress" => progress = true,
            "-r" | "--recursive" => recursive = true,
            "-h" | "--help" => {
                println!("Help for encrypt - see documentation");
                return Ok(());
            }
            _ => {}
        }
        i += 1;
    }

    let input = input.ok_or_else(|| error::Error::InvalidParams("--input argument required".to_string()))?;
    let output = output.ok_or_else(|| error::Error::InvalidParams("--output argument required".to_string()))?;

    // Get key/password material
    let key_material = if let Some(kf) = key_file {
        crypto::read_key_file(&kf)?
    } else if key_stdin {
        let mut key = Vec::new();
        io::stdin().read_to_end(&mut key).map_err(|e| error::Error::Io(e))?;
        key
    } else if let Some(pw) = password {
        pw.into_bytes()
    } else if ask_password {
        use rpassword::read_password;
        eprint!("Password: ");
        io::stdout().flush().map_err(|e| error::Error::Io(e))?;
        let pw = read_password().map_err(|e| error::Error::Io(e))?;
        pw.into_bytes()
    } else if let Some(pf) = password_file {
        fs::read(pf).map_err(|e| error::Error::Io(e))?
    } else if let Some(pe) = password_env {
        env::var(pe).map_err(|e| error::Error::InvalidParams(format!("Environment variable error: {}", e)))?.into_bytes()
    } else {
        return Err(error::Error::InvalidParams("No authentication method provided".to_string()));
    };

    let input_path = Path::new(&input);
    
    if input_path.is_dir() {
        if !recursive {
            return Err(error::Error::InvalidParams("Input is a directory. Use --recursive to process directories".to_string()));
        }
        
        // Create output directory
        fs::create_dir_all(&output).map_err(|e| error::Error::Io(e))?;
        
        // Walk through directory
        let walker = walkdir::WalkDir::new(input_path)
            .follow_links(false);
        
        for entry in walker {
            let entry = match entry {
                Ok(e) => e,
                Err(e) => {
                    eprintln!("Error walking directory: {}", e);
                    continue;
                }
            };
            let path = entry.path();
            
            if path.is_file() {
                // Check if hidden and should be included
                if !include_hidden {
                    if let Some(name) = path.file_name() {
                        if name.to_string_lossy().starts_with('.') {
                            if progress {
                                eprintln!("Skipping hidden file: {}", path.display());
                            }
                            continue;
                        }
                    }
                }
                
                // Calculate relative path
                let rel_path = match path.strip_prefix(input_path) {
                    Ok(p) => p,
                    Err(e) => {
                        eprintln!("Error stripping prefix: {}", e);
                        continue;
                    }
                };
                let output_path = Path::new(&output).join(rel_path).with_extension("tcrypt");
                
                // Create parent directories
                if let Some(parent) = output_path.parent() {
                    fs::create_dir_all(parent).map_err(|e| error::Error::Io(e))?;
                }
                
                if progress {
                    eprintln!("Encrypting: {} -> {}", path.display(), output_path.display());
                }
                
                // Encrypt the file
                match crypto::encrypt_file(
                    path.to_str().ok_or_else(|| error::Error::InvalidParams("Invalid path".to_string()))?,
                    output_path.to_str().ok_or_else(|| error::Error::InvalidParams("Invalid path".to_string()))?,
                    &key_material,
                    &symmetric,
                    asymmetric.as_deref(),
                    recipient.as_deref(),
                    &compression,
                    compress_level,
                    &kdf,
                    kdf_params.as_deref(),
                    &integrity,
                    preserve_mode,
                    preserve_timestamps,
                    false, // Don't show progress per file
                ) {
                    Ok(_) => {
                        if remove_original {
                            fs::remove_file(path).map_err(|e| error::Error::Io(e))?;
                            if progress {
                                eprintln!("Removed original: {}", path.display());
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("Error encrypting {}: {}", path.display(), e);
                        if remove_original {
                            eprintln!("WARNING: --remove-original was specified but encryption failed for some files");
                        }
                    }
                }
            }
        }
        
        if progress {
            eprintln!("Directory encryption completed");
        }
    } else {
        // Single file encryption
        if progress {
            eprintln!("Encrypting: {} -> {}", input, output);
        }
        
        crypto::encrypt_file(
            &input,
            &output,
            &key_material,
            &symmetric,
            asymmetric.as_deref(),
            recipient.as_deref(),
            &compression,
            compress_level,
            &kdf,
            kdf_params.as_deref(),
            &integrity,
            preserve_mode,
            preserve_timestamps,
            progress,
        )?;
        
        if remove_original {
            fs::remove_file(&input).map_err(|e| error::Error::Io(e))?;
            if progress {
                eprintln!("Removed original: {}", input);
            }
        }
        
        if progress {
            eprintln!("Encryption completed");
        }
    }

    Ok(())
}

fn cmd_decrypt(args: &[String]) -> Result<()> {
    let mut input = None;
    let mut output = None;
    let mut password = None;
    let mut ask_password = false;
    let mut password_file = None;
    let mut password_env = None;
    let mut key_file = None;
    let mut key_stdin = false;
    let mut private_key = None;
    let mut no_decompress = false;
    let mut verify_integrity = false;
    let mut restore_mode = false;
    let mut restore_timestamps = false;
    let mut remove_encrypted = false;
    let mut progress = false;
    let mut no_clobber = false;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-i" | "--input" => {
                i += 1;
                if i < args.len() {
                    input = Some(args[i].clone());
                }
            }
            "-o" | "--output" => {
                i += 1;
                if i < args.len() {
                    output = Some(args[i].clone());
                }
            }
            "-p" | "--password" => {
                i += 1;
                if i < args.len() {
                    password = Some(args[i].clone());
                }
            }
            "--ask-password" => ask_password = true,
            "--password-file" => {
                i += 1;
                if i < args.len() {
                    password_file = Some(args[i].clone());
                }
            }
            "--password-env" => {
                i += 1;
                if i < args.len() {
                    password_env = Some(args[i].clone());
                }
            }
            "--key-file" => {
                i += 1;
                if i < args.len() {
                    key_file = Some(args[i].clone());
                }
            }
            "--key-stdin" => key_stdin = true,
            "--private-key" => {
                i += 1;
                if i < args.len() {
                    private_key = Some(args[i].clone());
                }
            }
            "--no-decompress" => no_decompress = true,
            "--verify-integrity" => verify_integrity = true,
            "--restore-mode" => restore_mode = true,
            "--restore-timestamps" => restore_timestamps = true,
            "--remove-encrypted" => remove_encrypted = true,
            "--progress" => progress = true,
            "--no-clobber" => no_clobber = true,
            "-h" | "--help" => {
                println!("Help for decrypt - see documentation");
                return Ok(());
            }
            _ => {}
        }
        i += 1;
    }

    let input = input.ok_or_else(|| error::Error::InvalidParams("--input argument required".to_string()))?;
    let output = output.ok_or_else(|| error::Error::InvalidParams("--output argument required".to_string()))?;

    // Get key/password material
    let key_material = if let Some(kf) = key_file {
        crypto::read_key_file(&kf)?
    } else if key_stdin {
        let mut key = Vec::new();
        io::stdin().read_to_end(&mut key).map_err(|e| error::Error::Io(e))?;
        key
    } else if let Some(pk) = private_key {
        fs::read(pk).map_err(|e| error::Error::Io(e))?
    } else if let Some(pw) = password {
        pw.into_bytes()
    } else if ask_password {
        use rpassword::read_password;
        eprint!("Password: ");
        io::stdout().flush().map_err(|e| error::Error::Io(e))?;
        let pw = read_password().map_err(|e| error::Error::Io(e))?;
        pw.into_bytes()
    } else if let Some(pf) = password_file {
        fs::read(pf).map_err(|e| error::Error::Io(e))?
    } else if let Some(pe) = password_env {
        env::var(pe).map_err(|e| error::Error::InvalidParams(format!("Environment variable error: {}", e)))?.into_bytes()
    } else {
        return Err(error::Error::InvalidParams("No authentication method provided".to_string()));
    };

    let input_path = Path::new(&input);
    
    if input_path.is_dir() {
        // Create output directory
        fs::create_dir_all(&output).map_err(|e| error::Error::Io(e))?;
        
        // Walk through directory
        let walker = walkdir::WalkDir::new(input_path);
        
        for entry in walker {
            let entry = match entry {
                Ok(e) => e,
                Err(e) => {
                    eprintln!("Error walking directory: {}", e);
                    continue;
                }
            };
            let path = entry.path();
            
            if path.is_file() && path.extension().map_or(false, |ext| ext == "tcrypt") {
                // Calculate relative path
                let rel_path = match path.strip_prefix(input_path) {
                    Ok(p) => p,
                    Err(e) => {
                        eprintln!("Error stripping prefix: {}", e);
                        continue;
                    }
                };
                let output_path = Path::new(&output).join(rel_path).with_extension(""); // Remove .tcrypt
                
                // Create parent directories
                if let Some(parent) = output_path.parent() {
                    fs::create_dir_all(parent).map_err(|e| error::Error::Io(e))?;
                }
                
                if no_clobber && output_path.exists() {
                    if progress {
                        eprintln!("Skipping (exists): {}", output_path.display());
                    }
                    continue;
                }
                
                if progress {
                    eprintln!("Decrypting: {} -> {}", path.display(), output_path.display());
                }
                
                // Decrypt the file
                match crypto::decrypt_file(
                    path.to_str().ok_or_else(|| error::Error::InvalidParams("Invalid path".to_string()))?,
                    output_path.to_str().ok_or_else(|| error::Error::InvalidParams("Invalid path".to_string()))?,
                    &key_material,
                    no_decompress,
                    verify_integrity,
                    restore_mode,
                    restore_timestamps,
                    false, // Don't show progress per file
                ) {
                    Ok(_) => {
                        if remove_encrypted {
                            fs::remove_file(path).map_err(|e| error::Error::Io(e))?;
                            if progress {
                                eprintln!("Removed encrypted: {}", path.display());
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("Error decrypting {}: {}", path.display(), e);
                        if remove_encrypted {
                            eprintln!("WARNING: --remove-encrypted was specified but decryption failed for some files");
                        }
                    }
                }
            }
        }
        
        if progress {
            eprintln!("Directory decryption completed");
        }
    } else {
        // Single file decryption
        if !input_path.extension().map_or(false, |ext| ext == "tcrypt") {
            eprintln!("Warning: File does not have .tcrypt extension");
        }
        
        if no_clobber && Path::new(&output).exists() {
            return Err(error::Error::InvalidParams("Output file exists (--no-clobber)".to_string()));
        }
        
        if progress {
            eprintln!("Decrypting: {} -> {}", input, output);
        }
        
        crypto::decrypt_file(
            &input,
            &output,
            &key_material,
            no_decompress,
            verify_integrity,
            restore_mode,
            restore_timestamps,
            progress,
        )?;
        
        if remove_encrypted {
            fs::remove_file(&input).map_err(|e| error::Error::Io(e))?;
            if progress {
                eprintln!("Removed encrypted: {}", input);
            }
        }
        
        if progress {
            eprintln!("Decryption completed");
        }
    }

    Ok(())
}

fn cmd_hash(args: &[String]) -> Result<()> {
    let mut input = None;
    let mut use_stdin = false;
    let mut algorithm = "blake3".to_string();
    let mut algorithms = None;
    let mut output = None;
    let mut format = "hex".to_string();
    let mut salt = None;
    let mut salt_file = None;
    let mut iterations = None;
    let mut check = None;
    let mut include_hidden = false;
    let mut recursive = false;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-i" | "--input" => {
                i += 1;
                if i < args.len() {
                    input = Some(args[i].clone());
                }
            }
            "--stdin" => use_stdin = true,
            "-a" | "--algorithm" => {
                i += 1;
                if i < args.len() {
                    algorithm = args[i].clone();
                }
            }
            "--algorithms" => {
                i += 1;
                if i < args.len() {
                    algorithms = Some(args[i].clone());
                }
            }
            "--output" => {
                i += 1;
                if i < args.len() {
                    output = Some(args[i].clone());
                }
            }
            "--format" => {
                i += 1;
                if i < args.len() {
                    format = args[i].clone();
                }
            }
            "--salt" => {
                i += 1;
                if i < args.len() {
                    salt = Some(args[i].clone().into_bytes());
                }
            }
            "--salt-file" => {
                i += 1;
                if i < args.len() {
                    salt_file = Some(args[i].clone());
                }
            }
            "--iterations" => {
                i += 1;
                if i < args.len() {
                    iterations = Some(args[i].parse().unwrap_or(10000));
                }
            }
            "--check" => {
                i += 1;
                if i < args.len() {
                    check = Some(args[i].clone());
                }
            }
            "--include-hidden" => include_hidden = true,
            "-r" | "--recursive" => recursive = true,
            "-h" | "--help" => {
                println!("Help for hash - see documentation");
                return Ok(());
            }
            _ => {}
        }
        i += 1;
    }

    let salt_data = if let Some(s) = salt {
        s
    } else if let Some(sf) = salt_file {
        fs::read(sf).map_err(|e| error::Error::Io(e))?
    } else {
        Vec::new()
    };

    if use_stdin {
        // Handle stdin hashing in streaming mode
        let stdin = io::stdin();
        let mut handle = stdin.lock();
        
        if let Some(algo_list) = algorithms {
            let algos: Vec<&str> = algo_list.split(',').collect();
            let results = hashing::hash_reader_streaming(&mut handle, &algos, &salt_data, iterations)?;
            
            let formatted = hashing::format_multiple_results(&results, &format);
            if let Some(output_path) = output {
                fs::write(output_path, formatted).map_err(|e| error::Error::Io(e))?;
            } else {
                println!("{}", formatted);
            }
        } else {
            let hash = hashing::hash_reader_single(&mut handle, &algorithm, &salt_data, iterations)?;
            let hash_str = hashing::format_hash(&hash, &format);
            
            if let Some(expected) = check {
                hashing::verify_hash(&hash, &expected, &format)?;
                println!("✓ Hash verified successfully");
            } else if let Some(output_path) = output {
                fs::write(output_path, hash_str).map_err(|e| error::Error::Io(e))?;
            } else {
                println!("{}", hash_str);
            }
        }
    } else if let Some(input_path) = input {
        // ... reste du code pour les fichiers (inchangé) ...
    }

    Ok(())
}

fn cmd_key(args: &[String]) -> Result<()> {
    if args.is_empty() {
        eprintln!("Subcommand required: generate, info, fingerprint, convert");
        return Ok(());
    }

    match args[0].as_str() {
        "generate" => cmd_key_generate(&args[1..]),
        "info" => cmd_key_info(&args[1..]),
        "fingerprint" => cmd_key_fingerprint(&args[1..]),
        "convert" => cmd_key_convert(&args[1..]),
        _ => {
            eprintln!("Unknown subcommand: {}", args[0]);
            Ok(())
        }
    }
}

fn cmd_key_generate(args: &[String]) -> Result<()> {
    let mut key_type = "aes-256".to_string();
    let mut output = None;
    let mut public = None;
    let mut format = "raw".to_string();
    let mut seed_from_password = None;
    let mut encrypt = false;
    let mut ask_password = false;
    let mut no_encrypt = false;
    let mut permissions = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--type" => {
                i += 1;
                if i < args.len() {
                    key_type = args[i].clone();
                }
            }
            "--output" => {
                i += 1;
                if i < args.len() {
                    output = Some(args[i].clone());
                }
            }
            "--public" => {
                i += 1;
                if i < args.len() {
                    public = Some(args[i].clone());
                }
            }
            "--format" => {
                i += 1;
                if i < args.len() {
                    format = args[i].clone();
                }
            }
            "--seed-from-password" => {
                i += 1;
                if i < args.len() {
                    seed_from_password = Some(args[i].clone());
                }
            }
            "--encrypt" => encrypt = true,
            "--ask-password" => ask_password = true,
            "--no-encrypt" => no_encrypt = true,
            "--permissions" => {
                i += 1;
                if i < args.len() {
                    permissions = Some(args[i].clone());
                }
            }
            "-h" | "--help" => {
                println!("Help for key generate - see documentation");
                return Ok(());
            }
            _ => {}
        }
        i += 1;
    }

    let output = output.ok_or_else(|| error::Error::InvalidParams("--output argument required".to_string()))?;

    let password = if encrypt || ask_password {
        if ask_password {
            use rpassword::read_password;
            eprint!("Password to protect the key: ");
            io::stdout().flush().map_err(|e| error::Error::Io(e))?;
            Some(read_password().map_err(|e| error::Error::Io(e))?)
        } else {
            eprintln!("--encrypt requires --ask-password or --password");
            None
        }
    } else {
        None
    };

    key::generate_key(
        &key_type,
        &output,
        public.as_deref(),
        &format,
        seed_from_password.as_deref(),
        password,
        no_encrypt,
        permissions.as_deref(),
    )?;

    println!("Key generated successfully: {}", output);
    Ok(())
}

fn cmd_key_info(args: &[String]) -> Result<()> {
    let mut key_file = None;
    let mut verbose = false;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--key-file" => {
                i += 1;
                if i < args.len() {
                    key_file = Some(args[i].clone());
                }
            }
            "--verbose" => verbose = true,
            _ => {}
        }
        i += 1;
    }

    let key_file = key_file.ok_or_else(|| error::Error::InvalidParams("--key-file argument required".to_string()))?;
    key::print_key_info(&key_file, verbose)?;

    Ok(())
}

fn cmd_key_fingerprint(args: &[String]) -> Result<()> {
    let mut key_file = None;
    let mut algorithm = "blake3".to_string();

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--key-file" => {
                i += 1;
                if i < args.len() {
                    key_file = Some(args[i].clone());
                }
            }
            "--algorithm" => {
                i += 1;
                if i < args.len() {
                    algorithm = args[i].clone();
                }
            }
            _ => {}
        }
        i += 1;
    }

    let key_file = key_file.ok_or_else(|| error::Error::InvalidParams("--key-file argument required".to_string()))?;
    let fingerprint = key::calculate_fingerprint(&key_file, &algorithm)?;
    
    println!("Fingerprint ({}): {}", algorithm, fingerprint);
    Ok(())
}

fn cmd_key_convert(args: &[String]) -> Result<()> {
    let mut input = None;
    let mut output = None;
    let mut from = None;
    let mut to = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--input" => {
                i += 1;
                if i < args.len() {
                    input = Some(args[i].clone());
                }
            }
            "--output" => {
                i += 1;
                if i < args.len() {
                    output = Some(args[i].clone());
                }
            }
            "--from" => {
                i += 1;
                if i < args.len() {
                    from = Some(args[i].clone());
                }
            }
            "--to" => {
                i += 1;
                if i < args.len() {
                    to = Some(args[i].clone());
                }
            }
            _ => {}
        }
        i += 1;
    }

    let input = input.ok_or_else(|| error::Error::InvalidParams("--input argument required".to_string()))?;
    let output = output.ok_or_else(|| error::Error::InvalidParams("--output argument required".to_string()))?;
    let from = from.ok_or_else(|| error::Error::InvalidParams("--from argument required".to_string()))?;
    let to = to.ok_or_else(|| error::Error::InvalidParams("--to argument required".to_string()))?;

    key::convert_key(&input, &output, &from, &to)?;
    println!("Conversion completed: {} -> {}", input, output);
    Ok(())
}

fn cmd_info(args: &[String]) -> Result<()> {
    let mut input = None;
    let mut verbose = false;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-i" | "--input" => {
                i += 1;
                if i < args.len() {
                    input = Some(args[i].clone());
                }
            }
            "--verbose" => verbose = true,
            _ => {}
        }
        i += 1;
    }

    let input = input.ok_or_else(|| error::Error::InvalidParams("--input argument required".to_string()))?;
    header::print_file_info(&input, verbose)?;

    Ok(())
}


fn cmd_verify(args: &[String]) -> Result<()> {
    let mut input = None;
    let mut key_file = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-i" | "--input" => {
                i += 1;
                if i < args.len() {
                    input = Some(args[i].clone());
                }
            }
            "--key-file" => {
                i += 1;
                if i < args.len() {
                    key_file = Some(args[i].clone());
                }
            }
            _ => {}
        }
        i += 1;
    }

    let input = input.ok_or_else(|| error::Error::InvalidParams("--input argument required".to_string()))?;
    let key_file = key_file.ok_or_else(|| error::Error::InvalidParams("--key-file argument required".to_string()))?;

    let key = crypto::read_key_file(&key_file)?;
    crypto::verify_integrity(&input, &key)?;
    
    println!("✓ Integrity verified successfully for {}", input);
    Ok(())
}

fn cmd_benchmark(args: &[String]) -> Result<()> {
    let mut algorithms = "aes-256-gcm,chacha20,blake3,sha256,xxh3".to_string();
    let mut data_size = 1024 * 1024 * 100; // 100 MB default

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--algorithms" => {
                i += 1;
                if i < args.len() {
                    algorithms = args[i].clone();
                }
            }
            "--data-size" => {
                i += 1;
                if i < args.len() {
                    if let Ok(size) = args[i].parse::<usize>() {
                        data_size = size;
                    }
                }
            }
            _ => {}
        }
        i += 1;
    }

    println!("tems-crypt {} benchmark - {} {} {}", VERSION, AUTHOR, WEBSITE, YEAR);
    println!("Algorithms: {}", algorithms);
    println!("Data size: {} MB", data_size / (1024 * 1024));
    println!("----------------------------------------");

    let algos: Vec<&str> = algorithms.split(',').collect();
    crypto::run_benchmark(&algos, data_size)?;

    Ok(())
}

