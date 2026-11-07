# AOSP defensive proposals — review status

The private laboratory drafted changes for Android 17 `libziparchive` and `libandroidfw` to reject unsupported ZIP compression methods before resource mapping. Source and patch SHA-256 checks passed in that laboratory. This public package describes the defensive intent but does not distribute a complete attack corpus or claim that the proposal is a shipped update.

| Check | Current evidence |
|---|---|
| Static patch integrity and pinned source comparison | Recorded in private laboratory |
| Patch application to a matching AOSP tree | Not established for this publication |
| `atest` / full system image compilation | Not run |
| Patched Android 17 boot-loop retest | Not run |
| Upstream acceptance or security bulletin | Not known |

An older archived summary mislabeled a field; the hash-pinned APK was checked and the private record corrected. Source-level checks target the observed class, but **coverage of that runtime case in a patched system remains unverified** until a patched image is built and tested. The already-tested app-level ZIP preflight has a separate scope; see [mitigation](../docs/mitigation.md).
