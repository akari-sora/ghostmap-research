package dev.ghostmap.scanner;

/** Dependency-free regressions for cleanup failure across later scan requests. */
public final class CleanupPublishGateSelfTest {
    private CleanupPublishGateSelfTest() {}

    public static void main(String[] args) {
        startupFailureMustBlockExternalPass();
        staleTaskFailureMustBlockNewPass();
        System.out.println("CleanupPublishGateSelfTest: PASS");
    }

    private static void startupFailureMustBlockExternalPass() {
        CleanupPublishGate gate = new CleanupPublishGate(false);
        if (gate.canPublishPass()) {
            throw new AssertionError("startup cleanup failure must survive an external intent");
        }
        gate.recordCleanupOutcome(false);
        if (gate.canPublishPass()) {
            throw new AssertionError("a failed retry must remain fail-closed");
        }
        gate.recordCleanupOutcome(true);
        if (!gate.canPublishPass()) {
            throw new AssertionError("PASS may resume after cleanup is confirmed");
        }
    }

    private static void staleTaskFailureMustBlockNewPass() {
        CleanupPublishGate gate = new CleanupPublishGate(true);
        gate.recordCleanupOutcome(false);
        if (gate.canPublishPass()) {
            throw new AssertionError("a stale task's cleanup failure must not be discarded");
        }
        gate.recordCleanupOutcome(true);
        if (!gate.canPublishPass()) {
            throw new AssertionError("a newer scan may pass only after its cleanup retry succeeds");
        }
    }
}
