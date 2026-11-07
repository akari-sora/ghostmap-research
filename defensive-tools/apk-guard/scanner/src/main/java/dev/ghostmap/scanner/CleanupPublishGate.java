package dev.ghostmap.scanner;

/** Keeps PASS fail-closed until the scanner has confirmed its private cache is clean. */
public final class CleanupPublishGate {
    private boolean cleanupBlocked;

    public CleanupPublishGate(boolean initiallyClean) {
        cleanupBlocked = !initiallyClean;
    }

    public synchronized void recordCleanupOutcome(boolean clean) {
        cleanupBlocked = !clean;
    }

    public synchronized boolean canPublishPass() {
        return !cleanupBlocked;
    }
}
