# APK Guard (experimental)

APK Guard is an offline Android APK preflight scanner. It uses the system file picker or an Android Share/Open intent, copies the selected bytes into a bounded private cache, inspects raw ZIP metadata, and deletes the copy. The manifest requests **no Android permissions**. It never invokes the platform APK parser or installs the selected file.

The actual [PASS](../../media/screenshots/apk-guard-normal.png), [BLOCKED](../../media/screenshots/apk-guard-blocked.png), and [INCONCLUSIVE](../../media/screenshots/apk-guard-cleanup-fail-closed.png) results were captured during Android 15 emulator testing. Screenshots are cropped above file names and hashes. The phone UI was not retested on Android 16 or 17.

| Verdict | Meaning |
|---|---|
| PASS | Implemented ZIP structure checks passed for this SHA-256 snapshot. **This is not a malware or general safety verdict.** |
| BLOCKED | An explicitly checked method, length, offset, or archive structure failed. Do not install that copy. |
| INCONCLUSIVE | The source or scan could not be completed, including private-cache cleanup failures. Treat it as not cleared. |

On a normal phone, users must choose APK Guard before installing a downloaded APK. The scanner cannot intercept every installer path. Rescan if the source may have changed; PASS applies only to the exact scanned bytes.

## Build and test

Requirements: JDK 17, Android SDK platform 35, a compatible Gradle 8.x installation (CI pins 8.9), and network access to Android Gradle Plugin dependencies for the first build.

```bash
gradle -p defensive-tools/apk-guard :scanner:assembleDebug
```

Debug output: `defensive-tools/apk-guard/scanner/build/outputs/apk/debug/scanner-debug.apk`. Verify its SHA-256 locally before use (`sha256sum` on Unix, `Get-FileHash -Algorithm SHA256` on Windows). A debug build is an **experimental** tool, not a store release. The GitLab CI `build:apk-guard` job publishes the debug APK as a job artifact (kept for 30 days) together with `apk-guard-sha256.txt`, `apk-guard-signature.txt` and `apk-guard-permissions.txt`; verify a downloaded artifact against the hash file of that exact job. On 2026-11-07, [pipeline 3039499379](https://gitlab.com/aa22396584/ghostmap-research/-/pipelines/3039499379) for commit `18abd1c4` passed all three jobs; its [build job 17828508697](https://gitlab.com/aa22396584/ghostmap-research/-/jobs/17828508697) produced `scanner-debug.apk` with SHA-256 `d2c9debd643c8025ad0bf5ea8d6a746bfffdacb0cb1a7c0e6bdaa6b849e280d3`. Later commits publish their own hash file. No APK is committed to this repository.

Local build on 2026-11-07 from this clean source checkout: Gradle 8.14.1, JDK 17, Android SDK 35, offline dependency cache; `:scanner:assembleDebug` passed. The 48,221-byte experimental debug APK has SHA-256 `ff59bd6029bdcf2d1a75a06f82c342a925b286d326d03406a99f58ed65d3672f`. Android's `apksigner verify` accepted its v2 debug signature and `aapt dump permissions` listed no requested permissions. The same source was also launched on a dedicated Android 17 emulator before this clean-checkout rebuild. A CI rebuild uses its own debug signing key and will have a different hash; use the hash published with that exact artifact.

The guard also compares the raw local-header and central-directory file names, CRC, and lengths. A data-descriptor ZIP may use zero placeholders in its local header; nonzero contradictory values are rejected. ZIP64 and multi-disk archives remain outside this experimental allowlist. The synthetic Java self-test covers these metadata boundaries.

Dependency-free Java tests are in `tests/java`. The Gradle project includes only `scanner` and `guard-core`; the private research harness, malformed fixture, and crash-producing APK are excluded. The guard self-test uses synthetic in-memory ZIP records and no private fixture.

The code is provided under the repository's MIT license. It does not prove the Android platform is repaired; see [mitigation scope](../../docs/mitigation.md).
