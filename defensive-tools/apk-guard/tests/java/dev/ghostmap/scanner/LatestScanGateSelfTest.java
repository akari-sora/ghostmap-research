package dev.ghostmap.scanner;

/** Dependency-free regression test for rapid consecutive Share/Open requests. */
public final class LatestScanGateSelfTest {
    private LatestScanGateSelfTest() {}

    public static void main(String[] args) {
        LatestScanGate gate = new LatestScanGate();
        long first = gate.begin();
        if (!gate.isCurrent(first)) {
            throw new AssertionError("first request should initially be current");
        }

        long second = gate.begin();
        if (gate.isCurrent(first)) {
            throw new AssertionError("older PASS must not replace a newer pending scan");
        }
        if (!gate.isCurrent(second)) {
            throw new AssertionError("newest request must be current");
        }

        gate.cancelAll();
        if (gate.isCurrent(second)) {
            throw new AssertionError("closed controller must suppress pending results");
        }
        System.out.println("LatestScanGateSelfTest: PASS");
    }
}
