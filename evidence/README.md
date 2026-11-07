# Redacted evidence index

The JSON summaries are derived from verified report files in the private laboratory. Parser summaries pin **separate** native-parser and mitigation-report SHA-256 values; boot-loop summaries pin their source crash-log SHA-256. These digests are calculated from canonical Git blob bytes, so a Windows checkout that rewrites line endings can have a different working-file hash. The crash excerpts contain timestamps and distinct emulator `system_server` PIDs while omitting addresses, resource identifiers, local paths, and full call chains.

| File | Scope |
|---|---|
| `android-15-parser-summary.json` | Isolated native parser and app-preflight results |
| `android-16-parser-summary.json` | Isolated native parser and app-preflight results |
| `android-17-parser-summary.json` | Isolated native parser and app-preflight results |
| `android-16-bootloop-summary.json` | Repeated `system_server` crash observation |
| `android-17-bootloop-summary.json` | Repeated `system_server` crash observation |
| `redacted-crash-logs/` | Selected signal lines with changing PIDs |

Raw tombstones, complete logs, crashing APKs, and payload construction details are not distributed. The evidence supports the stated emulator outcomes; it does not independently establish the exact Java caller.
