# Technical analysis

[繁體中文摘要見首頁](../README.zh-TW.md) · [Results](test-results.md)

Bitdefender Labs publicly described GhostMap on 5 November 2026. The issue is a disagreement between ZIP metadata validation and native resource loading. A malformed archive entry may declare more readable bytes than physically exist. A later file-backed read can cross the real end of the mapping; the observed native outcome is `SIGBUS/BUS_ADRERR`. Bitdefender states that the flaw affects Android 10 and later and that its verified device was a Pixel 10 on Android 17; this laboratory tested Android 15, 16 and 17 emulators only and makes no claim about other releases or physical devices.

The process that fails depends on the reader. The private laboratory separately observed an isolated app parser crash, an installation-time `system_server` crash, and repeated `system_server` failures during later boot processing. Only the last produces the documented persistent user-visible failure. The redacted public evidence shows distinct `system_server` PIDs on Android 16 and 17 without publishing the resource configuration or installer commands.

The Android 16 video is real emulator capture. The Android 17 run was headless, so its evidence consists of build fingerprint and crash records. A Java caller at boot is inferred from event ordering and a service diagnostic in the private lab; the native tombstone itself does not contain the Java stack. This attribution remains a limitation.

An older private summary mislabeled a compression value. The hash-pinned APK metadata was independently checked and the private record corrected. This public analysis omits the exact runtime trigger and executable payload. The [mitigation page](mitigation.md) separates what the guard checks from what has actually been tested on devices.
