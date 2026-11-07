# GhostMap — Android 15–17 安全研究

*獨立重現、原生崩潰分析、持續性系統程序崩潰證據與防護工具*

[English](README.md) · [技術分析](docs/technical-analysis.md) · [測試結果](docs/test-results.md) · [APK Guard](defensive-tools/apk-guard/README.md)

**GhostMap 由 [Bitdefender Labs 於 2026 年 11 月 5 日首次公開](https://www.bitdefender.com/en-us/blog/labs/ghostmap-android)。** 本專案提供獨立的模擬器重現及防護工具；不主張原始發現權，也不宣稱 Android 已修復。

不一致的 ZIP metadata 可能使 Android 原生資源解析器讀取超出實際檔案映射的記憶體，造成 `SIGBUS/BUS_ADRERR`。以下持續性故障是**模擬器中的 `system_server` 程序反覆重啟**，不是核心崩潰或硬體反覆斷電。

| Android | 隔離的原生解析器 | `system_server` 反覆崩潰 | 固定樣本的應用層前置防護 |
|---|---|---|---|
| 15 / API 35 | 已確認 | 本研究未證實 | 已確認 |
| 16 / API 36 | 已確認 | Google Play `user` 模擬器已確認 | 已確認 |
| 17 / API 37 | 已確認 | Google Play `user` 模擬器已確認 | 已確認 |

上述是不同實驗。手機端 APK Guard 介面僅在 Android 15 模擬器完成手機介面操作驗收，沒有宣稱 UI 在三個版本上都重測。[各版本測試與證據界線](docs/test-results.md)。

## 影片與證據

[90 秒公開展示影片](media/ghostmap-public-demo.mp4) · [英文字幕](media/subtitles/en.srt) · [繁體中文字幕](media/subtitles/zh-TW.srt) · [封面](media/thumbnail.png)

影片使用真實 Android 16 模擬器畫面及 APK Guard 真實介面裁切截圖；Android 17 是 headless 測試，以去敏摘要呈現，沒有假造錄影。原始影片留在私人實驗室。

## 防護工具

- [APK Guard](defensive-tools/apk-guard/README.md)：完全離線、無額外權限的 Android APK 前置掃描器，顯示 **PASS／BLOCKED／INCONCLUSIVE**。掃描 ZIP metadata，不安裝 APK。[真實 PASS](media/screenshots/apk-guard-normal.png)、[BLOCKED](media/screenshots/apk-guard-blocked.png) 及 [INCONCLUSIVE](media/screenshots/apk-guard-cleanup-fail-closed.png) 介面擷取自 Android 15 模擬器，已裁去檔名與雜湊。
- [Python 靜態掃描器](defensive-tools/static-scanner/README.md)：僅用標準函式庫，唯讀檢查 ZIP metadata。

**PASS 只代表目前實作的結構檢查未發現已涵蓋的模式，不代表 APK 完全安全。** 一般第三方 App 無法攔截所有安裝流程，仍須由使用者主動先掃描。

## 公開範圍與限制

本 Repo 提供[去敏感化測試摘要](evidence/README.md)、模擬器 build fingerprint 與不同 PID 的簡短崩潰紀錄；不包含可造成循環的 APK、產生器、原始完整日誌或可直接執行的重現步驟。開機時的 Java 呼叫端由時序與服務診斷推論，原生 Tombstone 沒有 Java 呼叫端 frame。較早的實驗摘要標錯一項 ZIP 欄位；已依 hash-pinned 附件核對並修正私人文件，公開版省略建構細節。[完整限制](docs/limitations.md)。

[AOSP 防護提案](patches/aosp-proposals.md)**不是**已發布的安全更新；尚無完整 AOSP 系統映像編譯、`atest` 或修補後裝置重測紀錄。[防護範圍](docs/mitigation.md)。

本專案 CI 預定執行 Python、Java Guard 測試及 Android debug build；實際 CI 與產物狀態以 GitLab 頁面為準。引用漏洞發現時請引用 [Bitdefender Labs](https://www.bitdefender.com/en-us/blog/labs/ghostmap-android)，引用獨立模擬器結果時可引用本 Repo。另見[揭露時間線](docs/disclosure-timeline.md)、[安全政策](SECURITY.md)與[授權](LICENSE)。
