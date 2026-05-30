#!/usr/bin/env python3
"""
Xbox 360 CPU-KEY Brute Force Generator - Python Port
Generate CPU keys with and without salt

Author: Slam (Original Java), Copilot (Python Port)
"""

import os
import hashlib
import secrets
from typing import List


def get_salts() -> List[str]:
    """Fetch salts from external file"""
    salts = []
    try:
        script_dir = os.path.dirname(os.path.abspath(__file__))
        salts_file = os.path.join(script_dir, "salts.txt")
        
        with open(salts_file, 'r') as f:
            for line in f:
                line = line.strip()
                if line:  # Skip empty lines
                    salts.append(line)
    except FileNotFoundError:
        print(f"Error: salts.txt not found in {script_dir}")
    
    return salts


def cpu_key_gen() -> str:
    """CPU-KEY generator - generates 32 hex characters"""
    key_bytes = secrets.token_bytes(16)
    return key_bytes.hex()


def xecrypt_cpu_key_gen(salt: str) -> str:
    """CPU-KEY generator with salt using SHA-256"""
    # Generate 16 random bytes
    random_bytes = secrets.token_bytes(16)
    
    # Add salt to the generated key
    key_with_salt = random_bytes + salt.encode('utf-8')
    
    # Apply SHA-256 hash
    hash_obj = hashlib.sha256(key_with_salt)
    hash_hex = hash_obj.hexdigest()
    
    # Return only first 32 characters
    return hash_hex[:32]


def main():
    """Main entry point"""
    print("="*50)
    print("Xbox 360 CPU-KEY Generator")
    print("="*50)
    print()
    
    # Get salts from file
    salts = get_salts()
    print(f"Loaded {len(salts)} salts from salts.txt\n")
    
    # Generate CPU-KEY without salt
    key = cpu_key_gen()
    print(f"CPU-KEY          : {key.upper()}")
    print()
    
    # Generate CPU-KEYs with salt
    print("CPU-KEYs with Salt:")
    for i, salt in enumerate(salts[:10], 1):  # Show first 10 salts
        key_with_salt = xecrypt_cpu_key_gen(salt)
        print(f"  [{i:3d}] {key_with_salt.upper()} (salt: {salt})")
    
    if len(salts) > 10:
        print(f"  ... and {len(salts) - 10} more salts")
    
    print()
    print("="*50)


if __name__ == "__main__":
    main()
