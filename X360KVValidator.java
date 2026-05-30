package x360cpukeybforce;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.MessageDigest;
import java.util.Arrays;

/**
 * Xbox 360 KeyVault Validator and Tester
 * Validates generated kv.bin files and verifies CPU key authenticity
 * 
 * @author Copilot
 */
public class X360KVValidator {

    private static final int KV_SIZE = 0x4000;
    private static final int OFFSET_HMAC = 0x0000;
    private static final int OFFSET_KV_VERSION = 0x010;
    private static final int OFFSET_SERIAL = 0x014;
    private static final int OFFSET_CPU_KEY_HASH = 0x050;
    private static final int HMAC_SIZE = 0x14;
    private static final byte[] HMAC_KEY_PREFIX = "HmacKey".getBytes();

    /**
     * Load and validate a kv.bin file against a CPU key
     */
    public static ValidationResult validateKVBin(String kvBinPath, String cpuKeyHex) throws Exception {
        ValidationResult result = new ValidationResult();
        
        // Read the encrypted kv.bin file
        byte[] encryptedKV = readFile(kvBinPath);
        if (encryptedKV.length != KV_SIZE) {
            result.isValid = false;
            result.errors.add("Invalid file size: " + encryptedKV.length + " (expected " + KV_SIZE + ")");
            return result;
        }
        
        // Convert CPU key from hex
        byte[] cpuKey = X360KVGenerator.hexStringToByteArray(cpuKeyHex);
        if (cpuKey.length != 16) {
            result.isValid = false;
            result.errors.add("Invalid CPU key length: " + cpuKey.length + " (expected 16)");
            return result;
        }
        
        // Decrypt kv.bin
        byte[] decryptedKV;
        try {
            decryptedKV = decryptKVBin(encryptedKV, cpuKey);
        } catch (Exception e) {
            result.isValid = false;
            result.errors.add("Decryption failed: " + e.getMessage());
            return result;
        }
        
        // Verify HMAC
        if (!verifyHMAC(decryptedKV, cpuKey)) {
            result.isValid = false;
            result.errors.add("HMAC verification failed - Invalid CPU key or corrupted data");
            return result;
        }
        
        result.hmacValid = true;
        result.info.add("✓ HMAC-SHA1 verification passed");
        
        // Verify CPU key hash
        if (!verifyCPUKeyHash(decryptedKV, cpuKey)) {
            result.isValid = false;
            result.errors.add("CPU key hash mismatch");
            return result;
        }
        
        result.cpuKeyHashValid = true;
        result.info.add("✓ CPU key hash verified");
        
        // Extract metadata
        extractMetadata(decryptedKV, result);
        
        result.isValid = true;
        result.info.add("✓ KV.bin is valid and properly encrypted");
        
        return result;
    }

    /**
     * Decrypt kv.bin using AES-128-CBC
     */
    private static byte[] decryptKVBin(byte[] encryptedKV, byte[] cpuKey) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
        SecretKeySpec keySpec = new SecretKeySpec(cpuKey, 0, 16, "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(new byte[16]); // IV of zeros
        
        cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
        return cipher.doFinal(encryptedKV);
    }

    /**
     * Verify HMAC-SHA1 of kv.bin
     */
    private static boolean verifyHMAC(byte[] decryptedKV, byte[] cpuKey) throws Exception {
        // Derive HMAC key
        MessageDigest digest = MessageDigest.getInstance("SHA-1");
        digest.update(HMAC_KEY_PREFIX);
        digest.update(cpuKey);
        byte[] hmacKey = digest.digest();
        
        // Calculate HMAC over data (excluding HMAC field at 0x00)
        Mac mac = Mac.getInstance("HmacSHA1");
        mac.init(new SecretKeySpec(hmacKey, 0, hmacKey.length, "HmacSHA1"));
        mac.update(decryptedKV, 0x10, KV_SIZE - 0x10);
        byte[] calculatedHmac = mac.doFinal();
        
        // Extract stored HMAC
        byte[] storedHmac = Arrays.copyOfRange(decryptedKV, OFFSET_HMAC, OFFSET_HMAC + HMAC_SIZE);
        
        // Compare
        return Arrays.equals(calculatedHmac, storedHmac);
    }

    /**
     * Verify CPU key hash matches
     */
    private static boolean verifyCPUKeyHash(byte[] decryptedKV, byte[] cpuKey) throws Exception {
        // Calculate SHA1 of CPU key
        MessageDigest digest = MessageDigest.getInstance("SHA-1");
        byte[] hash = digest.digest(cpuKey);
        byte[] calculatedHash = Arrays.copyOf(hash, 16);
        
        // Extract stored hash
        byte[] storedHash = Arrays.copyOfRange(decryptedKV, OFFSET_CPU_KEY_HASH, OFFSET_CPU_KEY_HASH + 16);
        
        // Compare
        return Arrays.equals(calculatedHash, storedHash);
    }

    /**
     * Extract and display metadata from kv.bin
     */
    private static void extractMetadata(byte[] decryptedKV, ValidationResult result) {
        int kvVersion = ByteBuffer.wrap(decryptedKV, OFFSET_KV_VERSION, 4)
                .order(ByteOrder.LITTLE_ENDIAN).getInt();
        byte[] serial = Arrays.copyOfRange(decryptedKV, OFFSET_SERIAL, OFFSET_SERIAL + 12);
        
        result.kvVersion = kvVersion;
        result.consoleSerial = X360KVGenerator.byteArrayToHexString(serial);
        
        result.info.add("KV Version: " + kvVersion);
        result.info.add("Console Serial: " + result.consoleSerial);
    }

    /**
     * Read file into byte array
     */
    private static byte[] readFile(String path) throws IOException {
        File file = new File(path);
        FileInputStream fis = new FileInputStream(file);
        byte[] data = new byte[(int) file.length()];
        fis.read(data);
        fis.close();
        return data;
    }

    /**
     * Validation result holder
     */
    public static class ValidationResult {
        public boolean isValid = false;
        public boolean hmacValid = false;
        public boolean cpuKeyHashValid = false;
        public int kvVersion = 0;
        public String consoleSerial = "";
        public java.util.List<String> info = new java.util.ArrayList<>();
        public java.util.List<String> errors = new java.util.ArrayList<>();
        
        public void print() {
            System.out.println("\n=== Xbox 360 KV.bin Validation Result ===\n");
            
            if (isValid) {
                System.out.println("✓ VALIDATION PASSED\n");
            } else {
                System.out.println("✗ VALIDATION FAILED\n");
            }
            
            for (String msg : info) {
                System.out.println(msg);
            }
            
            for (String error : errors) {
                System.out.println("✗ " + error);
            }
            
            System.out.println("\n========================================\n");
        }
    }

    /**
     * Test generation and validation cycle
     */
    public static void testGenerationAndValidation(int numTests) throws Exception {
        System.out.println("========================================");
        System.out.println("Xbox 360 KV.bin Generation & Validation Test");
        System.out.println("========================================\n");
        
        int passCount = 0;
        
        for (int i = 1; i <= numTests; i++) {
            System.out.println("[Test " + i + "/" + numTests + "]");
            
            // Generate CPU key
            byte[] cpuKey = X360KeyPairGenerator.generateCPUKey();
            String cpuKeyHex = X360KVGenerator.byteArrayToHexString(cpuKey);
            
            // Generate KV.bin
            X360KVGenerator kvGen = new X360KVGenerator(cpuKey);
            byte[] kvBin = kvGen.generateKV();
            
            // Save temporarily
            String tempFile = "temp_kv_" + i + ".bin";
            try (FileOutputStream fos = new FileOutputStream(tempFile)) {
                fos.write(kvBin);
            }
            
            // Validate
            ValidationResult result = validateKVBin(tempFile, cpuKeyHex);
            
            if (result.isValid) {
                System.out.println("  ✓ PASS - CPU Key: " + cpuKeyHex);
                passCount++;
            } else {
                System.out.println("  ✗ FAIL - CPU Key: " + cpuKeyHex);
                for (String error : result.errors) {
                    System.out.println("    - " + error);
                }
            }
            
            // Clean up
            new File(tempFile).delete();
            System.out.println();
        }
        
        System.out.println("========================================");
        System.out.println("Test Results: " + passCount + "/" + numTests + " passed");
        System.out.println("Success Rate: " + (passCount * 100.0 / numTests) + "%");
        System.out.println("========================================\n");
    }

    /**
     * Main entry point
     */
    public static void main(String[] args) throws Exception {
        // Test 10 generation/validation cycles
        testGenerationAndValidation(10);
    }
}
