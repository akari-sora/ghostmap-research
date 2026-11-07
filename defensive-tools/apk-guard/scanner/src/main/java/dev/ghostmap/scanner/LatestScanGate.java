package dev.ghostmap.scanner;

/** Ensures only the newest requested scan may publish a user-visible result. */
public final class LatestScanGate {
    private long generation;

    public synchronized long begin() {
        generation += 1;
        return generation;
    }

    public synchronized boolean isCurrent(long candidate) {
        return candidate == generation;
    }

    public synchronized void cancelAll() {
        generation += 1;
    }
}
