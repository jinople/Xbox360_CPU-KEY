package x360cpukeybforce;

import java.io.*;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * Xbox 360 KeyVault (kv.bin) Generator
 * Generates a 16KB KeyVault file with matching CPU keys
 * 
 * @author Copilot
 */
public class X360KVGenerator {

    // KV.bin size: 16 KB
    private static final int KV_SIZE = 0x4000; // 16384 bytes
    private static final int KV_VERSION = 2; // Version 2 (Zephyr/Opus/Falcon/Jasper)

    // Field offsets (from community research)
    private static final int OFFSET_HMAC = 0x0000;      // 0x14 bytes (20 bytes)
    private static final int OFFSET_KV_VERSION = 0x010; // 4 bytes
    private static final int OFFSET_SERIAL = 0x014;     // 12 bytes (console serial)
    private static final int OFFSET_MOBO_SERIAL = 0x020; // 12 bytes (motherboard serial)
    private static final int OFFSET_CONSOLE_ID = 0x02C; // 5 bytes
    private static final int OFFSET_DVD_KEY = 0x030;    // 16 bytes
    private static final int OFFSET_DVD_REGION = 0x040; // 2 bytes
    private static final int OFFSET_GAME_REGION = 0x042; // 2 bytes
    private static final int OFFSET_CPU_KEY_HASH = 0x050; // 16 bytes
    private static final int OFFSET_RSA_PRIVATE = 0x060; // 128 bytes
    private static final int OFFSET_MAC_ADDRESS = 0x0E0; // 6 bytes

    private byte[] kvData;

    public X360KVGenerator() {
        this.kvData = new byte[KV_SIZE];
        // Initialize with zeros
        Arrays.fill(kvData, (byte) 0);
    }

    /**
     * Generate a complete KV.bin with a CPU key
     * @param cpuKey The CPU key to embed (32 hex characters)
     * @return byte array containing the KV.bin data
     */
    public byte[] generateKV(String cpuKey) {
        // Set KV version
        setVersionField(KV_VERSION);

        // Generate console identifiers
        byte[] serialNumber = generateSerialNumber();
        byte[] moboSerial = generateSerialNumber();
        byte[] consoleId = generateConsoleId();
        byte[] dvdKey = generateDVDKey();
        byte[] macAddress = generateMACAddress();

        // Set fields
        setSerialNumber(serialNumber);
        setMoboSerial(moboSerial);
        setConsoleId(consoleId);
        setDVDKey(dvdKey);
        setMACAddress(macAddress);

        // Set CPU key hash (derive from the provided CPU key)
        byte[] cpuKeyHash = deriveFromCPUKey(cpuKey);
        setCPUKeyHash(cpuKeyHash);

        // Generate RSA private key (simplified - 128 bytes of random data)
        // In a real scenario, this would be a proper RSA key
        byte[] rsaKey = generateRSAKey();
        setRSAPrivateKey(rsaKey);

        // Set regions
        setDVDRegion(0x0002); // US region
        setGameRegion(0x0002); // US region

        // Calculate and set HMAC-SHA1
        calculateAndSetHMAC();

        return kvData;
    }

    /**
     * Set KV version field
     */
    private void setVersionField(int version) {
        ByteBuffer buffer = ByteBuffer.wrap(kvData, OFFSET_KV_VERSION, 4);
        buffer.order(ByteOrder.LITTLE_ENDIAN);
        buffer.putInt(version);
    }

    /**
     * Generate a random 12-byte serial number
     */
    private byte[] generateSerialNumber() {
        byte[] serial = new byte[12];
        new SecureRandom().nextBytes(serial);
        // Make it ASCII-like for visibility
        for (int i = 0; i < serial.length; i++) {
            serial[i] = (byte) ((Math.abs(serial[i]) % 36) + 48); // 0-9, A-Z range in ASCII
        }
        return serial;
    }

    /**
     * Generate a random 5-byte console ID
     */
    private byte[] generateConsoleId() {
        byte[] id = new byte[5];
        new SecureRandom().nextBytes(id);
        return id;
    }

    /**
     * Generate a random 16-byte DVD key
     */
    private byte[] generateDVDKey() {
        byte[] key = new byte[16];
        new SecureRandom().nextBytes(key);
        return key;
    }

    /**
     * Generate a random 6-byte MAC address
     */
    private byte[] generateMACAddress() {
        byte[] mac = new byte[6];
        new SecureRandom().nextBytes(mac);
        mac[0] &= 0xFE; // Set locally administered bit
        return mac;
    }

    /**
     * Generate a 128-byte RSA private key (simplified)
     */
    private byte[] generateRSAKey() {
        byte[] key = new byte[128];
        new SecureRandom().nextBytes(key);
        return key;
    }

    /**
     * Derive a 16-byte hash from the CPU key
     */
    private byte[] deriveFromCPUKey(String cpuKey) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] cpuKeyBytes = hexStringToByteArray(cpuKey);
            byte[] hash = digest.digest(cpuKeyBytes);
            // Take first 16 bytes
            return Arrays.copyOf(hash, 16);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return new byte[16]; // Fallback
        }
    }

    /**
     * Set serial number field
     */
    private void setSerialNumber(byte[] serial) {
        System.arraycopy(serial, 0, kvData, OFFSET_SERIAL, 12);
    }

    /**
     * Set motherboard serial field
     */
    private void setMoboSerial(byte[] moboSerial) {
        System.arraycopy(moboSerial, 0, kvData, OFFSET_MOBO_SERIAL, 12);
    }

    /**
     * Set console ID field
     */
    private void setConsoleId(byte[] consoleId) {
        System.arraycopy(consoleId, 0, kvData, OFFSET_CONSOLE_ID, 5);
    }

    /**
     * Set DVD key field
     */
    private void setDVDKey(byte[] dvdKey) {
        System.arraycopy(dvdKey, 0, kvData, OFFSET_DVD_KEY, 16);
    }

    /**
     * Set CPU key hash field
     */
    private void setCPUKeyHash(byte[] cpuKeyHash) {
        System.arraycopy(cpuKeyHash, 0, kvData, OFFSET_CPU_KEY_HASH, 16);
    }

    /**
     * Set RSA private key field
     */
    private void setRSAPrivateKey(byte[] rsaKey) {
        System.arraycopy(rsaKey, 0, kvData, OFFSET_RSA_PRIVATE, 128);
    }

    /**
     * Set MAC address field
     */
    private void setMACAddress(byte[] macAddress) {
        System.arraycopy(macAddress, 0, kvData, OFFSET_MAC_ADDRESS, 6);
    }

    /**
     * Set DVD region
     */
    private void setDVDRegion(int region) {
        ByteBuffer buffer = ByteBuffer.wrap(kvData, OFFSET_DVD_REGION, 2);
        buffer.order(ByteOrder.LITTLE_ENDIAN);
        buffer.putShort((short) region);
    }

    /**
     * Set game region
     */
    private void setGameRegion(int region) {
        ByteBuffer buffer = ByteBuffer.wrap(kvData, OFFSET_GAME_REGION, 2);
        buffer.order(ByteOrder.LITTLE_ENDIAN);
        buffer.putShort((short) region);
    }

    /**
     * Calculate HMAC-SHA1 over the KV data and set it
     * The HMAC is calculated over a specific portion of the KV
     */
    private void calculateAndSetHMAC() {
        try {
            // Simple SHA1 hash for now (proper HMAC would use a secret key)
            MessageDigest digest = MessageDigest.getInstance("SHA-1");
            // Hash from offset 0x10 to end (excluding HMAC field itself)
            digest.update(kvData, 0x10, KV_SIZE - 0x10);
            byte[] hash = digest.digest();
            
            // Set HMAC field (first 20 bytes of SHA1 hash)
            System.arraycopy(hash, 0, kvData, OFFSET_HMAC, 20);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    /**
     * Write KV.bin to file
     */
    public void writeToFile(String filename) throws IOException {
        try (FileOutputStream fos = new FileOutputStream(filename)) {
            fos.write(kvData);
            System.out.println("KV.bin written to: " + filename);
        }
    }

    /**
     * Convert hex string to byte array
     */
    private byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    | Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }

    /**
     * Convert byte array to hex string
     */
    public static String byteArrayToHexString(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X", b));
        }
        return sb.toString();
    }

    /**
     * Print KV.bin information
     */
    public void printInfo() {
        System.out.println("\n=== Xbox 360 KeyVault Info ===");
        System.out.println("KV Version: " + ByteBuffer.wrap(kvData, OFFSET_KV_VERSION, 4)
                .order(ByteOrder.LITTLE_ENDIAN).getInt());
        System.out.println("Console Serial: " + new String(Arrays.copyOfRange(kvData, OFFSET_SERIAL, OFFSET_SERIAL + 12)));
        System.out.println("Mobo Serial: " + new String(Arrays.copyOfRange(kvData, OFFSET_MOBO_SERIAL, OFFSET_MOBO_SERIAL + 12)));
        System.out.println("Console ID: " + byteArrayToHexString(Arrays.copyOfRange(kvData, OFFSET_CONSOLE_ID, OFFSET_CONSOLE_ID + 5)));
        System.out.println("DVD Key: " + byteArrayToHexString(Arrays.copyOfRange(kvData, OFFSET_DVD_KEY, OFFSET_DVD_KEY + 16)));
        System.out.println("CPU Key Hash: " + byteArrayToHexString(Arrays.copyOfRange(kvData, OFFSET_CPU_KEY_HASH, OFFSET_CPU_KEY_HASH + 16)));
        System.out.println("MAC Address: " + byteArrayToHexString(Arrays.copyOfRange(kvData, OFFSET_MAC_ADDRESS, OFFSET_MAC_ADDRESS + 6)));
        System.out.println("HMAC: " + byteArrayToHexString(Arrays.copyOfRange(kvData, OFFSET_HMAC, OFFSET_HMAC + 20)));
        System.out.println("KV Size: " + kvData.length + " bytes");
        System.out.println("==============================\n");
    }

    // Test/Demo
    public static void main(String[] args) {
        // Example: Generate a KV.bin for a CPU key
        String cpuKey = "A1B2C3D4E5F6789012345678ABCDEF01"; // Example CPU key

        X360KVGenerator kvGen = new X360KVGenerator();
        kvGen.generateKV(cpuKey);
        kvGen.printInfo();

        try {
            kvGen.writeToFile("kv.bin");
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
