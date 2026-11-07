package dev.ghostmap.safelab;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.zip.CRC32;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

/** Dependency-free executable tests for the exact Android guard class. */
public final class ZipSafetyGuardSelfTest {
    private static final int LOCAL = 0x04034b50;
    private static final int CENTRAL = 0x02014b50;
    private static final int EOCD = 0x06054b50;

    private ZipSafetyGuardSelfTest() {}

    public static void main(String[] args) throws Exception {
        if (args.length != 0) {
            throw new IllegalArgumentException("No arguments expected");
        }
        Path directory = Files.createTempDirectory("ghostmap-guard-self-test");
        try {
            assertAccepted(write(directory, "stored.zip", makeZip(false)), "stored");
            byte[] deflatedWithDescriptor = makeZip(true);
            if ((readU16(deflatedWithDescriptor, find(deflatedWithDescriptor, LOCAL) + 6)
                    & 0x0008) == 0) {
                throw new AssertionError("Expected a data-descriptor ZIP fixture");
            }
            assertAccepted(write(directory, "deflated.zip", deflatedWithDescriptor),
                    "deflated with data descriptor");

            byte[] nameMismatch = makeZip(false);
            nameMismatch[find(nameMismatch, LOCAL) + 30] = (byte) 'x';
            assertCode(write(directory, "name-mismatch.zip", nameMismatch),
                    "LOCAL_CENTRAL_NAME_MISMATCH");

            byte[] nameLengthMismatch = makeZip(false);
            writeU16(nameLengthMismatch, find(nameLengthMismatch, LOCAL) + 26, 1);
            assertCode(write(directory, "name-length-mismatch.zip", nameLengthMismatch),
                    "LOCAL_CENTRAL_NAME_MISMATCH");

            byte[] crcMismatch = makeZip(false);
            int crcLocal = find(crcMismatch, LOCAL);
            writeU32(crcMismatch, crcLocal + 14, readU32(crcMismatch, crcLocal + 14) ^ 1);
            assertCode(write(directory, "crc-mismatch.zip", crcMismatch),
                    "LOCAL_CENTRAL_CRC_MISMATCH");

            byte[] compressedSizeMismatch = makeZip(false);
            int compressedLocal = find(compressedSizeMismatch, LOCAL);
            writeU32(compressedSizeMismatch, compressedLocal + 18,
                    readU32(compressedSizeMismatch, compressedLocal + 18) + 1);
            assertCode(write(directory, "compressed-size-mismatch.zip", compressedSizeMismatch),
                    "LOCAL_CENTRAL_SIZE_MISMATCH");

            byte[] uncompressedSizeMismatch = makeZip(false);
            int uncompressedLocal = find(uncompressedSizeMismatch, LOCAL);
            writeU32(uncompressedSizeMismatch, uncompressedLocal + 22,
                    readU32(uncompressedSizeMismatch, uncompressedLocal + 22) + 1);
            assertCode(write(directory, "uncompressed-size-mismatch.zip", uncompressedSizeMismatch),
                    "LOCAL_CENTRAL_SIZE_MISMATCH");

            byte[] descriptorCrcMismatch = makeZip(true);
            int descriptorCrcLocal = find(descriptorCrcMismatch, LOCAL);
            writeU32(descriptorCrcMismatch, descriptorCrcLocal + 14,
                    readU32(descriptorCrcMismatch, find(descriptorCrcMismatch, CENTRAL) + 16)
                            ^ 1);
            assertCode(write(directory, "descriptor-crc-mismatch.zip", descriptorCrcMismatch),
                    "LOCAL_CENTRAL_CRC_MISMATCH");

            byte[] descriptorSizeMismatch = makeZip(true);
            int descriptorSizeLocal = find(descriptorSizeMismatch, LOCAL);
            writeU32(descriptorSizeMismatch, descriptorSizeLocal + 18,
                    readU32(descriptorSizeMismatch,
                            find(descriptorSizeMismatch, CENTRAL) + 20) + 1);
            assertCode(write(directory, "descriptor-size-mismatch.zip", descriptorSizeMismatch),
                    "LOCAL_CENTRAL_SIZE_MISMATCH");

            byte[] storedMismatch = makeZip(false);
            int storedCentral = find(storedMismatch, CENTRAL);
            writeU32(storedMismatch, storedCentral + 24,
                    readU32(storedMismatch, storedCentral + 24) + 1);
            assertCode(write(directory, "stored-mismatch.zip", storedMismatch),
                    "STORED_LENGTH_MISMATCH");

            byte[] outOfBounds = makeZip(true);
            int boundsCentral = find(outOfBounds, CENTRAL);
            writeU32(outOfBounds, boundsCentral + 20, 0x7fffffffL);
            assertCode(write(directory, "out-of-bounds.zip", outOfBounds),
                    "ENTRY_DATA_BEYOND_ARCHIVE");

            byte[] zip64 = makeZip(true);
            int zip64Central = find(zip64, CENTRAL);
            writeU32(zip64, zip64Central + 20, 0xffffffffL);
            assertCode(write(directory, "zip64.zip", zip64), "ZIP64_UNSUPPORTED");

            byte[] metadataMismatch = makeZip(false);
            int local = find(metadataMismatch, LOCAL);
            writeU16(metadataMismatch, local + 8, 8);
            assertCode(write(directory, "metadata-mismatch.zip", metadataMismatch),
                    "LOCAL_CENTRAL_METADATA_MISMATCH");

            byte[] centralRange = makeZip(true);
            int eocd = find(centralRange, EOCD);
            writeU32(centralRange, eocd + 12,
                    readU32(centralRange, eocd + 12) + 1);
            assertCode(write(directory, "central-range.zip", centralRange),
                    "CENTRAL_DIRECTORY_RANGE_INVALID");

            assertCode(write(directory, "truncated.zip", new byte[] {0x50, 0x4b}),
                    "EOCD_NOT_FOUND");
            System.out.println("ZipSafetyGuardSelfTest: PASS");
        } finally {
            deleteTree(directory.toFile());
        }
    }

    private static byte[] makeZip(boolean deflated) throws IOException {
        byte[] content = "GHOSTMAP_GUARD_TEST".getBytes(java.nio.charset.StandardCharsets.UTF_8);
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try (ZipOutputStream output = new ZipOutputStream(bytes)) {
            ZipEntry entry = new ZipEntry("entry.txt");
            if (!deflated) {
                CRC32 crc = new CRC32();
                crc.update(content);
                entry.setMethod(ZipEntry.STORED);
                entry.setSize(content.length);
                entry.setCompressedSize(content.length);
                entry.setCrc(crc.getValue());
            }
            output.putNextEntry(entry);
            output.write(content);
            output.closeEntry();
        }
        return bytes.toByteArray();
    }

    private static File write(Path directory, String name, byte[] data) throws IOException {
        Path path = directory.resolve(name);
        Files.write(path, data);
        return path.toFile();
    }

    private static void assertAccepted(File file, String label) throws IOException {
        ZipSafetyGuard.Result result = ZipSafetyGuard.inspect(file);
        if (!result.accepted) {
            throw new AssertionError(label + " unexpectedly rejected: " + result.describe());
        }
    }

    private static void assertCode(File file, String expected) throws IOException {
        ZipSafetyGuard.Result result = ZipSafetyGuard.inspect(file);
        if (result.accepted || !expected.equals(result.code)) {
            throw new AssertionError(
                    file + ": expected " + expected + ", got " + result.describe());
        }
    }

    private static int find(byte[] data, int signature) {
        byte[] target = {
                (byte) signature,
                (byte) (signature >>> 8),
                (byte) (signature >>> 16),
                (byte) (signature >>> 24),
        };
        for (int offset = 0; offset <= data.length - target.length; offset++) {
            if (Arrays.equals(target, Arrays.copyOfRange(data, offset, offset + 4))) {
                return offset;
            }
        }
        throw new AssertionError("ZIP signature not found: " + Integer.toHexString(signature));
    }

    private static long readU32(byte[] data, int offset) {
        return ((long) data[offset] & 0xff)
                | (((long) data[offset + 1] & 0xff) << 8)
                | (((long) data[offset + 2] & 0xff) << 16)
                | (((long) data[offset + 3] & 0xff) << 24);
    }

    private static int readU16(byte[] data, int offset) {
        return (data[offset] & 0xff) | ((data[offset + 1] & 0xff) << 8);
    }

    private static void writeU16(byte[] data, int offset, int value) {
        data[offset] = (byte) value;
        data[offset + 1] = (byte) (value >>> 8);
    }

    private static void writeU32(byte[] data, int offset, long value) {
        data[offset] = (byte) value;
        data[offset + 1] = (byte) (value >>> 8);
        data[offset + 2] = (byte) (value >>> 16);
        data[offset + 3] = (byte) (value >>> 24);
    }

    private static void deleteTree(File file) {
        File[] children = file.listFiles();
        if (children != null) {
            for (File child : children) {
                deleteTree(child);
            }
        }
        if (!file.delete()) {
            file.deleteOnExit();
        }
    }
}
