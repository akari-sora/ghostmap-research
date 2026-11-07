package dev.ghostmap.safelab;

import java.io.EOFException;
import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * Minimal fail-closed ZIP preflight for files that may later reach Android's
 * APK/resource parsers. It accepts only STORED and DEFLATED entries and proves
 * each entry's compressed data range stays inside the archive data region.
 */
public final class ZipSafetyGuard {
    private static final long LOCAL_FILE_HEADER = 0x04034b50L;
    private static final long CENTRAL_DIRECTORY_HEADER = 0x02014b50L;
    private static final long END_OF_CENTRAL_DIRECTORY = 0x06054b50L;
    private static final int STORED = 0;
    private static final int DEFLATED = 8;
    private static final int DATA_DESCRIPTOR_FLAG = 0x0008;
    private static final int EOCD_SIZE = 22;
    private static final int MAX_COMMENT = 0xffff;
    private static final int MAX_ENTRIES = 100_000;

    private ZipSafetyGuard() {}

    public static final class Result {
        public final boolean accepted;
        public final String code;
        public final String entry;
        public final int method;
        public final int entriesChecked;

        private Result(boolean accepted, String code, String entry, int method,
                       int entriesChecked) {
            this.accepted = accepted;
            this.code = code;
            this.entry = entry;
            this.method = method;
            this.entriesChecked = entriesChecked;
        }

        static Result accept(int entriesChecked) {
            return new Result(true, "PASS", "", -1, entriesChecked);
        }

        static Result reject(String code, String entry, int method, int entriesChecked) {
            return new Result(false, code, entry, method, entriesChecked);
        }

        public String describe() {
            StringBuilder value = new StringBuilder(code);
            if (!entry.isEmpty()) {
                value.append(" entry=").append(entry);
            }
            if (method >= 0) {
                value.append(" method=").append(method);
            }
            value.append(" entries_checked=").append(entriesChecked);
            return value.toString();
        }
    }

    public static Result inspect(File archive) throws IOException {
        try (RandomAccessFile input = new RandomAccessFile(archive, "r")) {
            long fileLength = input.length();
            long eocd = findEocd(input, fileLength);
            if (eocd < 0) {
                return Result.reject("EOCD_NOT_FOUND", "", -1, 0);
            }

            input.seek(eocd + 4);
            int diskNumber = readUnsignedShortLe(input);
            int centralDisk = readUnsignedShortLe(input);
            int entriesOnDisk = readUnsignedShortLe(input);
            int totalEntries = readUnsignedShortLe(input);
            long centralSize = readUnsignedIntLe(input);
            long centralOffset = readUnsignedIntLe(input);
            int commentLength = readUnsignedShortLe(input);

            if (diskNumber != 0 || centralDisk != 0 || entriesOnDisk != totalEntries) {
                return Result.reject("MULTI_DISK_UNSUPPORTED", "", -1, 0);
            }
            if (totalEntries > MAX_ENTRIES) {
                return Result.reject("TOO_MANY_ENTRIES", "", -1, 0);
            }
            if (eocd + EOCD_SIZE + commentLength != fileLength) {
                return Result.reject("EOCD_RANGE_INVALID", "", -1, 0);
            }
            if (centralOffset > eocd || centralSize > eocd - centralOffset
                    || centralOffset + centralSize != eocd) {
                return Result.reject("CENTRAL_DIRECTORY_RANGE_INVALID", "", -1, 0);
            }

            long cursor = centralOffset;
            long centralEnd = centralOffset + centralSize;
            for (int index = 0; index < totalEntries; index++) {
                if (cursor > centralEnd || centralEnd - cursor < 46) {
                    return Result.reject("CENTRAL_ENTRY_TRUNCATED", "", -1, index);
                }
                input.seek(cursor);
                if (readUnsignedIntLe(input) != CENTRAL_DIRECTORY_HEADER) {
                    return Result.reject("CENTRAL_SIGNATURE_INVALID", "", -1, index);
                }
                input.skipBytes(4); // versions
                int flags = readUnsignedShortLe(input);
                int method = readUnsignedShortLe(input);
                input.skipBytes(4); // time and date
                long crc32 = readUnsignedIntLe(input);
                long compressedLength = readUnsignedIntLe(input);
                long uncompressedLength = readUnsignedIntLe(input);
                int nameLength = readUnsignedShortLe(input);
                int extraLength = readUnsignedShortLe(input);
                int entryCommentLength = readUnsignedShortLe(input);
                int entryDisk = readUnsignedShortLe(input);
                input.skipBytes(6); // internal/external attributes
                long localOffset = readUnsignedIntLe(input);

                long variableLength = (long) nameLength + extraLength + entryCommentLength;
                if (variableLength > centralEnd - cursor - 46) {
                    return Result.reject("CENTRAL_ENTRY_RANGE_INVALID", "", method, index);
                }
                byte[] rawName = new byte[nameLength];
                input.readFully(rawName);
                String name = new String(rawName, StandardCharsets.UTF_8);

                if (entryDisk != 0) {
                    return Result.reject("MULTI_DISK_ENTRY_UNSUPPORTED", name, method, index);
                }
                if (compressedLength == 0xffffffffL || uncompressedLength == 0xffffffffL
                        || localOffset == 0xffffffffL) {
                    return Result.reject("ZIP64_UNSUPPORTED", name, method, index);
                }
                if (method != STORED && method != DEFLATED) {
                    return Result.reject("UNSUPPORTED_COMPRESSION_METHOD", name, method, index);
                }
                if (method == STORED && compressedLength != uncompressedLength) {
                    return Result.reject("STORED_LENGTH_MISMATCH", name, method, index);
                }
                if (localOffset > centralOffset || centralOffset - localOffset < 30) {
                    return Result.reject("LOCAL_HEADER_RANGE_INVALID", name, method, index);
                }

                input.seek(localOffset);
                if (readUnsignedIntLe(input) != LOCAL_FILE_HEADER) {
                    return Result.reject("LOCAL_SIGNATURE_INVALID", name, method, index);
                }
                input.skipBytes(2); // version needed
                int localFlags = readUnsignedShortLe(input);
                int localMethod = readUnsignedShortLe(input);
                input.skipBytes(4); // time and date
                long localCrc32 = readUnsignedIntLe(input);
                long localCompressedLength = readUnsignedIntLe(input);
                long localUncompressedLength = readUnsignedIntLe(input);
                int localNameLength = readUnsignedShortLe(input);
                int localExtraLength = readUnsignedShortLe(input);
                if (localMethod != method || localFlags != flags) {
                    return Result.reject("LOCAL_CENTRAL_METADATA_MISMATCH", name, method, index);
                }
                if (localNameLength != nameLength) {
                    return Result.reject("LOCAL_CENTRAL_NAME_MISMATCH", name, method, index);
                }
                if (!matchesLocalValue(localCrc32, crc32, flags)) {
                    return Result.reject("LOCAL_CENTRAL_CRC_MISMATCH", name, method, index);
                }
                if (!matchesLocalValue(localCompressedLength, compressedLength, flags)
                        || !matchesLocalValue(localUncompressedLength, uncompressedLength,
                                flags)) {
                    return Result.reject("LOCAL_CENTRAL_SIZE_MISMATCH", name, method, index);
                }
                long dataOffset = localOffset + 30L + localNameLength + localExtraLength;
                if (dataOffset > centralOffset || compressedLength > centralOffset - dataOffset) {
                    return Result.reject("ENTRY_DATA_BEYOND_ARCHIVE", name, method, index);
                }
                byte[] localName = new byte[localNameLength];
                input.readFully(localName);
                if (!Arrays.equals(rawName, localName)) {
                    return Result.reject("LOCAL_CENTRAL_NAME_MISMATCH", name, method, index);
                }

                cursor += 46L + variableLength;
            }
            if (cursor != centralEnd) {
                return Result.reject("CENTRAL_DIRECTORY_COUNT_MISMATCH", "", -1,
                        totalEntries);
            }
            return Result.accept(totalEntries);
        } catch (EOFException truncated) {
            return Result.reject("TRUNCATED_ZIP", "", -1, 0);
        }
    }

    private static boolean matchesLocalValue(long local, long central, int flags) {
        // Bit 3 permits zero placeholders in the local header; the descriptor
        // and central directory carry the actual CRC and lengths.
        return local == central || ((flags & DATA_DESCRIPTOR_FLAG) != 0 && local == 0);
    }

    private static long findEocd(RandomAccessFile input, long fileLength) throws IOException {
        if (fileLength < EOCD_SIZE) {
            return -1;
        }
        long minimum = Math.max(0, fileLength - EOCD_SIZE - MAX_COMMENT);
        for (long offset = fileLength - EOCD_SIZE; offset >= minimum; offset--) {
            input.seek(offset);
            if (readUnsignedIntLe(input) == END_OF_CENTRAL_DIRECTORY) {
                return offset;
            }
        }
        return -1;
    }

    private static int readUnsignedShortLe(RandomAccessFile input) throws IOException {
        int low = input.readUnsignedByte();
        int high = input.readUnsignedByte();
        return low | (high << 8);
    }

    private static long readUnsignedIntLe(RandomAccessFile input) throws IOException {
        return (readUnsignedShortLe(input) | ((long) readUnsignedShortLe(input) << 16))
                & 0xffffffffL;
    }
}
