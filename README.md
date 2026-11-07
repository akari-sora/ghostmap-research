# GhostMap — Android 15–17 Security Research

*Independent Reproduction, Native Crash Analysis, Persistent System Crash Evidence & Defensive Tools*

[繁體中文](README.zh-TW.md) · [Technical analysis](docs/technical-analysis.md) · [Results](docs/test-results.md) · [APK Guard](defensive-tools/apk-guard/README.md)

**GhostMap was discovered and publicly disclosed by [Bitdefender Labs on 5 November 2026](https://www.bitdefender.com/en-us/blog/labs/ghostmap-android).** This project documents an independent, emulator-only reproduction and publishes defensive tools. It is not the original discovery and does not claim that Android has been fixed.

An inconsistency in ZIP metadata can lead an Android native resource parser to read beyond a file-backed mapping. The observed result is `SIGBUS/BUS_ADRERR`. Which process crashes depends on when a resource is read. The repeated system-service failures below are **`system_server` process restarts on emulators**, not kernel crashes or repeated hardware power cycles.

| Android | Isolated native parser | Repeated `system_server` crashes | App preflight on fixed corpus |
|---|---|---|---|
| 15 / API 35 | Confirmed | Not established in this study | Confirmed |
| 16 / API 36 | Confirmed | Confirmed on Google Play `user` emulator | Confirmed |
| 17 / API 37 | Confirmed | Confirmed on Google Play `user` emulator | Confirmed |

These are separate experiments. The APK Guard phone interface was tested on Android 15; its UI was not retested across all three releases. [Per-build results and evidence boundaries](docs/test-results.md).

## Watch the evidence

[90-second public demonstration](media/ghostmap-public-demo.mp4) · [English captions](media/subtitles/en.srt) · [繁體中文字幕](media/subtitles/zh-TW.srt) · [Thumbnail](media/thumbnail.png)

The video uses real Android 16 emulator footage and cropped screenshots from the real APK Guard UI. Android 17 evidence is represented by redacted observations from its headless emulator run, not invented footage. The original capture remains in the private laboratory.

## Defensive tools

- [APK Guard](defensive-tools/apk-guard/README.md) is an offline, permission-free Android preflight scanner. It offers **PASS**, **BLOCKED**, and **INCONCLUSIVE**. It reads ZIP metadata before invoking any Android APK/resource parser and does not install APKs. The [actual PASS](media/screenshots/apk-guard-normal.png), [BLOCKED](media/screenshots/apk-guard-blocked.png), and [INCONCLUSIVE](media/screenshots/apk-guard-cleanup-fail-closed.png) screens were captured on an Android 15 emulator; file identifiers were cropped out.
- [Static scanner](defensive-tools/static-scanner/README.md) performs read-only ZIP metadata checks using Python's standard library.

**PASS means only that the implemented structural checks found no covered pattern in the scanned snapshot.** It is not a malware clearance. A normal third-party app cannot intercept every installation path; users must choose to scan before installing.

## Evidence and scope

This repository includes [redacted per-build summaries](evidence/README.md), build fingerprints, and short crash-line excerpts with distinct `system_server` PIDs. It excludes the crashing APK, payload builders, raw logs, and executable reproduction steps. The boot-time Java caller is inferred from timing and service diagnostics; the native tombstone does not contain a Java caller frame. An older laboratory summary mislabeled a ZIP field; the hash-pinned binary was checked and the private documentation corrected. This public edition omits the construction detail. [Limitations](docs/limitations.md).

The [AOSP mitigation proposal](patches/aosp-proposals.md) is **not** an accepted security update. No complete AOSP system-image build, `atest`, or patched-device boot-loop retest is recorded. Its verified scope and open questions are listed in [Mitigation](docs/mitigation.md).

## Build and citation

The repository CI runs scanner tests, dependency-free Java guard tests, and an Android debug build. See each tool's README for local instructions. If a build artifact is available, its SHA-256 and exact CI job are listed there; no artifact is implied by this text alone.

When citing the vulnerability, cite [Bitdefender Labs](https://www.bitdefender.com/en-us/blog/labs/ghostmap-android) for discovery and this repository for the independent emulator observations. See the [disclosure timeline](docs/disclosure-timeline.md), [security policy](SECURITY.md), and [license](LICENSE).
