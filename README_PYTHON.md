# Xbox 360 CPU-KEY Generator - Python Port

A complete Python port of the Xbox 360 CPU-KEY generator with full AES encryption, RSA key generation, and HMAC-SHA1 verification.

## Features

✓ Generate cryptographically secure CPU keys (16 bytes / 32 hex characters)  
✓ Generate salted CPU keys using SHA-256  
✓ Generate complete KV.bin files with:
  - AES-128-CBC encryption
  - Real 2048-bit RSA private keys
  - HMAC-SHA1 integrity verification
  - Console identifiers and metadata
✓ Validate and decrypt KV.bin files  
✓ Batch generation of key pairs  
✓ Single pair generation on demand  
✓ Full verification and testing framework  

## Installation

### Requirements

- Python 3.6+
- pycryptodome (for AES and RSA cryptography)

### Setup

```bash
# Install dependencies
pip install -r requirements.txt
```

## Usage

### 1. Generate Single CPU Key (with and without salt)

```bash
python x360_cpu_key_bforce.py
```

This generates:
- One random CPU key (32 hex characters)
- CPU keys with salt using SHA-256 hashing
- Displays first 10 salts from salts.txt

### 2. Generate Batch of Key Pairs

```python
from x360_key_pair_generator import X360KeyPairGenerator

# Generate 10 console key pairs
generator = X360KeyPairGenerator(batch_size=10, output_directory="xbox360_keys")
generator.generate_batch()
```

Outputs for each pair:
- `Xbox360_Console_0001_CPU_KEY.txt` - Plain text CPU key
- `Xbox360_Console_0001_kv.bin` - Encrypted 16KB KeyVault binary
- `Xbox360_Console_0001_info.txt` - Technical information
- `BATCH_MANIFEST.txt` - Index of all generated pairs

### 3. Generate Single Key Pair On-Demand

```python
from x360_key_pair_generator import X360KeyPairGenerator

generator = X360KeyPairGenerator(batch_size=1, output_directory="xbox360_keys")
generator.generate_single_pair("MyConsole")
```

### 4. Validate KV.bin Files

```python
from x360_kv_validator import X360KVValidator

# Validate a kv.bin file
result = X360KVValidator.validate_kv_bin("path/to/kv.bin", "CPU_KEY_HEX_STRING")
result.print()
```

### 5. Run Validation Tests

```bash
python x360_kv_validator.py
```

Runs 10 generation/validation cycles and reports success rate.

## File Structure

```
Xbox360_CPU-KEY/
├── x360_cpu_key_bforce.py        # CPU key generation (with/without salt)
├── x360_kv_generator.py          # KV.bin generation and encryption
├── x360_kv_validator.py          # KV.bin validation and verification
├── x360_key_pair_generator.py    # Batch key pair generation
├── requirements.txt              # Python dependencies
├── salts.txt                     # Salt values for CPU key generation
└── README_PYTHON.md              # This file
```

## Key Components

### X360CpuKeyBForce
Generates CPU keys with optional salt:
- `cpu_key_gen()` - Random 16-byte CPU key
- `xecrypt_cpu_key_gen(salt)` - CPU key with SHA-256 salt hashing
- `get_salts()` - Load salts from external file

### X360KVGenerator
Generates encrypted KV.bin files:
- AES-128-CBC encryption with zero IV
- Real 2048-bit RSA private keys
- Console serial numbers, MAC addresses, DVD keys
- HMAC-SHA1 verification (derived from CPU key)
- Proper field offsets for Xbox 360 compatibility

### X360KVValidator
Validates and decrypts KV.bin files:
- Decrypts with AES-128-CBC
- Verifies HMAC-SHA1 integrity
- Validates CPU key hash
- Extracts metadata (version, serial, etc.)
- Test framework for generation/validation cycles

### X360KeyPairGenerator
Batch generation of matched key pairs:
- Cryptographically secure random generation
- Batch or single-pair generation
- Detailed technical information files
- Batch manifest for tracking
- Ready for Xbox 360 JTAG/glitch flashing

## Technical Details

### Encryption
- **Algorithm**: AES-128-CBC
- **Key**: 16-byte CPU key
- **IV**: All zeros (Xbox 360 standard)
- **Mode**: PKCS#5 padding (handled automatically by pycryptodome)

### Authentication
- **HMAC**: SHA-1 based
- **Key Derivation**: SHA-1("HmacKey" || CPU_KEY)
- **Hashed Data**: Offset 0x10 to 0x3FFF (excludes HMAC field)

### Key Material
- **CPU Key**: 16 bytes (128-bit), cryptographically random
- **RSA Keys**: Real 2048-bit keypairs
- **Serial Numbers**: 12 bytes each (console, motherboard)
- **MAC Address**: 6 bytes, locally administered bit set
- **DVD Key**: 16 bytes random

## Compatibility

- Xbox 360 versions: Zephyr, Opus, Falcon, Jasper
- KV.bin version: 2 (standard format)
- Flashing tools: J-Runner, XeBuild, etc.
- CPU key injection: JTAG, glitch exploits, or software methods

## Security Notice

⚠️ **IMPORTANT**: These keys are cryptographically random and should be treated as sensitive material. Keep them secure and use them only for authorized purposes.

## Examples

### Example 1: Generate and Save 5 Key Pairs

```python
from x360_key_pair_generator import X360KeyPairGenerator

generator = X360KeyPairGenerator(batch_size=5, output_directory="my_keys")
generator.generate_batch()
```

### Example 2: Validate All Generated Key Pairs

```python
import os
from x360_kv_validator import X360KVValidator

output_dir = "my_keys"

# Find all CPU key files
for file in os.listdir(output_dir):
    if file.endswith("_CPU_KEY.txt"):
        console_name = file.replace("_CPU_KEY.txt", "")
        
        # Read CPU key
        with open(os.path.join(output_dir, file)) as f:
            content = f.read()
            cpu_key_hex = content.split(": ")[1].split("\n")[0]
        
        # Validate corresponding kv.bin
        kv_path = os.path.join(output_dir, f"{console_name}_kv.bin")
        result = X360KVValidator.validate_kv_bin(kv_path, cpu_key_hex)
        
        if result.is_valid:
            print(f"✓ {console_name} is valid")
        else:
            print(f"✗ {console_name} failed validation")
```

### Example 3: Generate Custom Named Keys

```python
from x360_key_pair_generator import X360KeyPairGenerator

generator = X360KeyPairGenerator(batch_size=1, output_directory="custom_keys")
generator.generate_single_pair("MyXbox360")
generator.generate_single_pair("AnotherConsole")
```

## Differences from Java Version

- Uses `pycryptodome` for cryptographic operations instead of Java's `javax.crypto`
- Uses Python's `secrets` module for cryptographically secure random generation
- File I/O simplified with Python's built-in functions
- Batch processing and validation integrated into single modules
- No package structure required (flat file organization)
- Cross-platform compatibility without compilation

## Troubleshooting

### Import Error: "No module named 'Crypto'"

```bash
pip install pycryptodome
```

### "File not found: salts.txt"

Ensure `salts.txt` is in the same directory as `x360_cpu_key_bforce.py`

### "Invalid file size" when validating

KV.bin files must be exactly 16,384 bytes (0x4000)

### HMAC verification failed

This indicates either:
- Incorrect CPU key
- Corrupted KV.bin file
- Decryption error

## License

CC0 1.0 Universal (same as original Java project)

## References

- Xbox 360 Hardware (Zephyr, Opus, Falcon, Jasper) documentation
- Xbox Security Architecture research
- Community KeyVault format documentation
- AES-128-CBC encryption standards
