# Limits and unresolved questions

1. Results are from named Android emulators. Android 16 and 17 repeated `system_server` SIGBUS events do not prove a kernel failure or repeated physical hardware reboot.
2. Android 17 was headless; no Android 17 camera/screen video exists in this publication. Its evidence is from crash records and build identification.
3. Native tombstones show the faulting native read, not a Java caller frame. The boot-time service attribution is inferred from private timing and diagnostic observations.
4. An older archived summary mislabeled one ZIP compression field. The hash-pinned binary was checked and the private record corrected. This public package still omits the precise construction detail and does not claim patched-system coverage.
5. APK Guard UI acceptance was recorded on Android 15 only. The shared preflight core's Android 15–17 test used a separate fixed corpus; this is not a proof that the phone UI or every installation route is protected on all releases.
6. AOSP proposals have not passed a full patched system build, `atest`, device retest, or upstream review. No platform fix is claimed.
7. The public evidence is deliberately redacted. Full raw logs and the crashing APK are withheld to avoid distributing a persistent denial-of-service capability.
