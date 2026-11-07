# Working rules for agents and contributors

These rules apply to any automated agent or person editing this repository.

## Scope of this repository

This is the public edition of a private laboratory. It holds redacted summaries, defensive tools, and demonstration media only.

Never add, even in history: a crashing or crafted APK, a payload generator, a malformed fixture, raw logcat or tombstone files, the original screen capture, or any detail that would let a reader rebuild the boot-loop APK (resource names, field values, installer commands). The mechanism may be described only at the level Bitdefender has already published.

## Identity and remotes

- Commit as the repository's configured identity, `GhostMap Research <noreply@ghostmap-research.invalid>`. Do not commit with a personal e-mail address.
- The canonical repository, CI and issues are on GitLab: <https://gitlab.com/aa22396584/ghostmap-research>. The GitHub copy is a read-only push mirror; do not change its settings, do not enable GitHub Actions, and do not open issues there.
- Do not rename or move the project. The demonstration video and README cite the GitLab path.
- Fetch before you push. Never force-push `main`.

## Claims discipline

Say only what the evidence files support:

- Reproduced on Android 16 and 17 Google Play `user` emulators, normal install, no root; repeated `system_server` crashes and restarts.
- APK Guard is a manual pre-install structural check. PASS means the implemented checks found nothing, not that an APK is safe. Its phone UI was exercised on Android 15; the shared preflight core was tested against a fixed corpus on Android 15–17.
- The AOSP patch proposal has not been built into a system image or retested. Do not call it a fix until an evidence file records that build and retest.
- Bitdefender Labs discovered and disclosed GhostMap on 5 November 2026. This project is an independent reproduction.

Do not claim a fix, a CVE, impact on all devices, or that the device never shows the home screen.

## Documentation conventions

- `README.md` (English) and `README.zh-TW.md` (Traditional Chinese) are a pair; change both.
- Every hash cited under `evidence/` must match the laboratory's recorded SHA-256 for that source file.
- Relative links must resolve. Run the test suites below before committing.

## Checks before a push

```zsh
python3 -m unittest discover -s defensive-tools/static-scanner/tests
# Java self-tests: see the test:guard-core job in .gitlab-ci.yml
```

Stage explicit paths only. After pushing, confirm the GitLab pipeline for your commit succeeds.
