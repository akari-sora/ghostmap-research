package dev.ghostmap.scanner;

import java.nio.file.Files;
import java.nio.file.Path;

/** Dependency-free cleanup success/failure regression test. */
public final class PrivateFileCleanupSelfTest {
    private PrivateFileCleanupSelfTest() {}

    public static void main(String[] args) throws Exception {
        Path root = Files.createTempDirectory("apk-guard-cleanup-test");
        Path file = Files.write(root.resolve("copy.apk"), new byte[] {1, 2, 3});
        if (!PrivateFileCleanup.deleteWithRetries(file.toFile()) || Files.exists(file)) {
            throw new AssertionError("private temporary file should be deleted");
        }

        Path nonEmpty = Files.createDirectory(root.resolve("not-a-file"));
        Files.write(nonEmpty.resolve("child"), new byte[] {4});
        if (PrivateFileCleanup.deleteWithRetries(nonEmpty.toFile())) {
            throw new AssertionError("cleanup failure must be observable by the caller");
        }

        Files.delete(nonEmpty.resolve("child"));
        Files.delete(nonEmpty);
        Files.delete(root);
        System.out.println("PrivateFileCleanupSelfTest: PASS");
    }
}
