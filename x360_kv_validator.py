#!/usr/bin/env python3
"""
Xbox 360 KeyVault Validator and Tester
Validates generated kv.bin files and verifies CPU key authenticity

Author: Copilot
"""

import os
import hashlib
import hmac
import struct
from typing import List, Optional
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from x360_kv_generator import X360KVGenerator
from x360_key_pair_generator import X360KeyPairGenerator


class ValidationResult:
    """Validation result holder"""
    
    def __init__(self):
        self.is_valid = False
        self.hmac_valid = False
        self.cpu_key_hash_valid = False
        self.kv_version = 0
        self.console_serial = ""
        self.info = []
        self.errors = []
    
    def print(self):
        """Print validation result"""
        print("\n=== Xbox 360 KV.bin Validation Result ===\n")
        
        if self.is_valid:
            print("✓ VALIDATION PASSED\n")
        else:
            print("✗ VALIDATION FAILED\n")
        
        for msg in self.info:
            print(msg)
        
        for error in self.errors:
            print(f"✗ {error}")
        
        print("\n========================================\n")


class X360KVValidator:
    """Xbox 360 KeyVault Validator"""
    
    KV_SIZE = 0x4000
    OFFSET_HMAC = 0x0000
    OFFSET_KV_VERSION = 0x010
    OFFSET_SERIAL = 0x014
    OFFSET_CPU_KEY_HASH = 0x050
    HMAC_SIZE = 0x14
    HMAC_KEY_PREFIX = b"HmacKey"
    
    @staticmethod
    def hex_string_to_byte_array(hex_string: str) -> bytes:
        """Convert hex string to byte array"""
        return bytes.fromhex(hex_string)
    
    @staticmethod
    def byte_array_to_hex_string(data: bytes) -> str:
        """Convert byte array to hex string"""
        return data.hex().upper()
    
    @staticmethod
    def validate_kv_bin(kv_bin_path: str, cpu_key_hex: str) -> ValidationResult:
        """Load and validate a kv.bin file against a CPU key"""
        result = ValidationResult()
        
        # Read the encrypted kv.bin file
        try:
            with open(kv_bin_path, 'rb') as f:
                encrypted_kv = f.read()
        except FileNotFoundError:
            result.is_valid = False
            result.errors.append(f"File not found: {kv_bin_path}")
            return result
        
        if len(encrypted_kv) != X360KVValidator.KV_SIZE:
            result.is_valid = False
            result.errors.append(f"Invalid file size: {len(encrypted_kv)} (expected {X360KVValidator.KV_SIZE})")
            return result
        
        # Convert CPU key from hex
        try:
            cpu_key = X360KVValidator.hex_string_to_byte_array(cpu_key_hex)
        except ValueError:
            result.is_valid = False
            result.errors.append("Invalid CPU key format (must be hex)")
            return result
        
        if len(cpu_key) != 16:
            result.is_valid = False
            result.errors.append(f"Invalid CPU key length: {len(cpu_key)} (expected 16)")
            return result
        
        # Decrypt kv.bin
        try:
            decrypted_kv = X360KVValidator._decrypt_kv_bin(encrypted_kv, cpu_key)
        except Exception as e:
            result.is_valid = False
            result.errors.append(f"Decryption failed: {str(e)}")
            return result
        
        # Verify HMAC
        if not X360KVValidator._verify_hmac(decrypted_kv, cpu_key):
            result.is_valid = False
            result.errors.append("HMAC verification failed - Invalid CPU key or corrupted data")
            return result
        
        result.hmac_valid = True
        result.info.append("✓ HMAC-SHA1 verification passed")
        
        # Verify CPU key hash
        if not X360KVValidator._verify_cpu_key_hash(decrypted_kv, cpu_key):
            result.is_valid = False
            result.errors.append("CPU key hash mismatch")
            return result
        
        result.cpu_key_hash_valid = True
        result.info.append("✓ CPU key hash verified")
        
        # Extract metadata
        X360KVValidator._extract_metadata(decrypted_kv, result)
        
        result.is_valid = True
        result.info.append("✓ KV.bin is valid and properly encrypted")
        
        return result
    
    @staticmethod
    def _decrypt_kv_bin(encrypted_kv: bytes, cpu_key: bytes) -> bytes:
        """Decrypt kv.bin using AES-128-CBC"""
        cipher = AES.new(cpu_key, AES.MODE_CBC, iv=bytes(16))
        return cipher.decrypt(encrypted_kv)
    
    @staticmethod
    def _verify_hmac(decrypted_kv: bytes, cpu_key: bytes) -> bool:
        """Verify HMAC-SHA1 of kv.bin"""
        # Derive HMAC key
        h = hashlib.sha1()
        h.update(X360KVValidator.HMAC_KEY_PREFIX)
        h.update(cpu_key)
        hmac_key = h.digest()
        
        # Calculate HMAC over data (excluding HMAC field at 0x00)
        h = hmac.new(hmac_key, digestmod=hashlib.sha1)
        h.update(decrypted_kv[0x10:])
        calculated_hmac = h.digest()
        
        # Extract stored HMAC
        stored_hmac = decrypted_kv[X360KVValidator.OFFSET_HMAC:X360KVValidator.OFFSET_HMAC + X360KVValidator.HMAC_SIZE]
        
        # Compare
        return calculated_hmac == stored_hmac
    
    @staticmethod
    def _verify_cpu_key_hash(decrypted_kv: bytes, cpu_key: bytes) -> bool:
        """Verify CPU key hash matches"""
        # Calculate SHA1 of CPU key
        h = hashlib.sha1(cpu_key)
        calculated_hash = h.digest()[:16]
        
        # Extract stored hash
        stored_hash = decrypted_kv[X360KVValidator.OFFSET_CPU_KEY_HASH:X360KVValidator.OFFSET_CPU_KEY_HASH + 16]
        
        # Compare
        return calculated_hash == stored_hash
    
    @staticmethod
    def _extract_metadata(decrypted_kv: bytes, result: ValidationResult):
        """Extract and display metadata from kv.bin"""
        kv_version = struct.unpack('<I', decrypted_kv[X360KVValidator.OFFSET_KV_VERSION:X360KVValidator.OFFSET_KV_VERSION+4])[0]
        serial = decrypted_kv[X360KVValidator.OFFSET_SERIAL:X360KVValidator.OFFSET_SERIAL+12]
        
        result.kv_version = kv_version
        result.console_serial = X360KVValidator.byte_array_to_hex_string(serial)
        
        result.info.append(f"KV Version: {kv_version}")
        result.info.append(f"Console Serial: {result.console_serial}")
    
    @staticmethod
    def test_generation_and_validation(num_tests: int = 10):
        """Test generation and validation cycle"""
        print("="*40)
        print("Xbox 360 KV.bin Generation & Validation Test")
        print("="*40)
        print()
        
        pass_count = 0
        
        for i in range(1, num_tests + 1):
            print(f"[Test {i}/{num_tests}]")
            
            try:
                # Generate CPU key
                cpu_key = get_random_bytes(16)
                cpu_key_hex = X360KVValidator.byte_array_to_hex_string(cpu_key)
                
                # Generate KV.bin
                kv_gen = X360KVGenerator(cpu_key)
                kv_bin = kv_gen.generate_kv()
                
                # Save temporarily
                temp_file = f"temp_kv_{i}.bin"
                with open(temp_file, 'wb') as f:
                    f.write(kv_bin)
                
                # Validate
                result = X360KVValidator.validate_kv_bin(temp_file, cpu_key_hex)
                
                if result.is_valid:
                    print(f"  ✓ PASS - CPU Key: {cpu_key_hex}")
                    pass_count += 1
                else:
                    print(f"  ✗ FAIL - CPU Key: {cpu_key_hex}")
                    for error in result.errors:
                        print(f"    - {error}")
                
                # Clean up
                os.remove(temp_file)
                print()
                
            except Exception as e:
                print(f"  ✗ Error in test {i}: {str(e)}")
                print()
        
        print("="*40)
        print(f"Test Results: {pass_count}/{num_tests} passed")
        print(f"Success Rate: {(pass_count * 100.0 / num_tests):.1f}%")
        print("="*40)
        print()


def main():
    """Main entry point"""
    # Test 10 generation/validation cycles
    X360KVValidator.test_generation_and_validation(10)


if __name__ == "__main__":
    main()
