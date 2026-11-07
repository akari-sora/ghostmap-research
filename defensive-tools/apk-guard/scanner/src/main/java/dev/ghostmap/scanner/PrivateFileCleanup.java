package dev.ghostmap.scanner;

import java.io.File;

/** Bounded deletion retry used for private scan-cache cleanup. */
public final class PrivateFileCleanup {
    private PrivateFileCleanup() {}

    public static boolean deleteWithRetries(File file) {
        for (int attempt = 0; attempt < 3; attempt++) {
            if (!file.exists() || file.delete()) {
                return true;
            }
            try {
                Thread.sleep(25L);
            } catch (InterruptedException interrupted) {
                Thread.currentThread().interrupt();
                break;
            }
        }
        return !file.exists();
    }
}
