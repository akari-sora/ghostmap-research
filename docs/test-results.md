# Independent test results

| Test | Android 15 / API 35 | Android 16 / API 36 | Android 17 / API 37 |
|---|---|---|---|
| Normal parser baseline | Passed | Passed | Passed |
| Isolated app native parser | `SIGBUS` confirmed | `SIGBUS` confirmed | `SIGBUS` confirmed |
| Fixed malformed corpus with app preflight | Rejected safely | Rejected safely | Rejected safely |
| Repeated `system_server` crashes after boot | Not established | Confirmed | Confirmed |
| APK Guard phone UI acceptance | Confirmed | Not rerun | Not rerun |

The parser and app-preflight observations derive from the private laboratory's per-build `report.json` records. The boot-loop rows derive from repeated `system_server` `SIGBUS/BUS_ADRERR` lines with changing PIDs on Google Play `user` emulator builds; [redacted excerpts](../evidence/README.md) and build fingerprints are supplied. The Android 16 footage shows the visible system response. Android 17 was tested headlessly.

The app preflight was tested against a fixed research corpus, **not** by installing the persistent-loop APK through APK Guard. APK Guard's own chooser/scan/result interface was exercised on an Android 15 AVD. No non-emulator device claim is made here.
