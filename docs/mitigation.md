# Defensive mitigation and validation boundary

## APK Guard

The [offline Android scanner](../defensive-tools/apk-guard/README.md) checks ZIP structure before handing the file to an Android APK/resource parser. It allows the expected APK compression methods, checks the central directory and local headers, requires consistent lengths for stored entries, and rejects out-of-range compressed data. A failed read or private-cache cleanup produces **INCONCLUSIVE**, never PASS. Android 15 UI evidence shows PASS, BLOCKED, and INCONCLUSIVE states. The shared guard core was separately tested with a fixed malformed research corpus across Android 15–17.

PASS is a narrow structural result for the exact scanned bytes. It is not antivirus approval, it does not guarantee the system installer will read the same later bytes, and APK Guard cannot intercept every installation on an ordinary phone. It requests no network, storage, or package-install permission.

## Platform proposal

The laboratory holds defensive Android 17 AOSP patch proposals for `libziparchive` and `libandroidfw`. Static source hashes and patch syntax were checked in the private project. **No complete AOSP image build, `atest` run, patched emulator retest, or upstream acceptance has been recorded.** The proposal must not be described as a released fix.

The archived experiment summary once mislabeled a compression-field value; the hash-pinned APK was checked and the private record corrected. The source-level proposal addresses the observed class of unsupported methods, but without a patched system-image build and retest it cannot be claimed to block the archived boot-loop case in practice. [Proposal review](../patches/aosp-proposals.md) and [limitations](limitations.md).
