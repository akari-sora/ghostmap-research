# Disclosure timeline

- **12 August 2026:** Bitdefender Labs began investigating an APK that crashed analysis emulators, according to its [public report](https://www.bitdefender.com/en-us/blog/labs/ghostmap-android).
- **20 August 2026:** Bitdefender's first report to Google. According to the blog, Google closed it as "Won't Fix (Not Reproducible)".
- **25 August 2026:** Bitdefender's second report, with a proof of concept and the persistent denial-of-service demonstration. According to the blog, Google answered that the issue would not be addressed through a security update and had forwarded the finding to the relevant team for possible inclusion in a future version update.
- **5 November 2026:** Bitdefender Labs published GhostMap. **They are the original discoverers.** The blog states that no fix is available, that the flaw affects Android 10 and later, and that its verified device was a Pixel 10 on Android 17 with the 5 August 2026 security patch.
- **6 November 2026:** This independent laboratory recorded isolated native-parser crashes and app-level preflight results on Android 15, 16, and 17 emulators.
- **7 November 2026:** The laboratory recorded repeated `system_server` failures on Android 16 and 17 Google Play `user` emulators, plus on-device APK Guard UI acceptance on Android 15.

This repository is an independently prepared defensive publication. It makes no claim of upstream patch acceptance or security-update deployment.
