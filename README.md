tems-crypt 1.0.0 - 2026 Philippe TEMESI
https://www.tems.be © 2026

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
    - Encrypt a single file
    tems-crypt encrypt -i secret.txt -o secret.tcrypt --ask-password
    
    - Encrypt a directory recursively
    tems-crypt encrypt -i documents/ -o documents.tcrypt --recursive --key-file backup.key
    
    - Encrypt and remove original
    tems-crypt encrypt -i photo.jpg -o photo.tcrypt --key-file key.bin --remove-original
    
    - Encrypt with compression
    tems-crypt encrypt -i largefile.dat -o large.tcrypt --compression zstd --ask-password
    
    - Decrypt a directory
    tems-crypt decrypt -i documents.tcrypt -o documents/ --key-file backup.key
    
    - Hash a file
    tems-crypt hash -i file.bin -a blake3
    
    - Hash from stdin
    echo "test" | tems-crypt hash --stdin -a sha256
    
    - Generate a key
    tems-crypt key generate --type aes-256 --output key.bin --no-encrypt

