package dev.ghostmap.scanner;

import android.app.Activity;
import android.content.ClipData;
import android.content.ContentResolver;
import android.content.Context;
import android.content.Intent;
import android.content.res.ColorStateList;
import android.database.Cursor;
import android.graphics.Color;
import android.graphics.Typeface;
import android.net.Uri;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.os.StatFs;
import android.provider.OpenableColumns;
import android.util.Log;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

import dev.ghostmap.safelab.ZipSafetyGuard;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Locale;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

/**
 * Offline, permission-free front end for the fail-closed ZIP/APK guard.
 *
 * <p>The selected content is copied into private cache with a hard size limit
 * and inspected as raw ZIP metadata. It is never passed to PackageManager,
 * ApkAssets, or another Android APK/resource parser.</p>
 */
public final class ScannerActivity extends Activity {
    private static final String TAG = "GhostMapApkGuard";
    private static final int REQUEST_PICK_APK = 1001;
    private static final long MAX_SCAN_BYTES = 2L * 1024 * 1024 * 1024;
    private static final long CACHE_RESERVE_BYTES = 64L * 1024 * 1024;

    private static final int COLOR_GREEN = Color.rgb(15, 122, 74);
    private static final int COLOR_RED = Color.rgb(190, 35, 48);
    private static final int COLOR_AMBER = Color.rgb(160, 96, 0);
    private static final int COLOR_BLUE = Color.rgb(34, 78, 170);

    private ScanController controller;
    private TextView statusTitle;
    private TextView statusDetail;
    private Button selectButton;
    private Button shareButton;
    private ScanReport latestReport;

    @Override
    protected void onCreate(Bundle state) {
        super.onCreate(state);
        buildUi();

        Object retained = getLastNonConfigurationInstance();
        boolean restored = retained instanceof ScanController;
        controller = restored
                ? (ScanController) retained
                : new ScanController(getApplicationContext());
        controller.attach(this);

        // A retained controller already owns the scan that was active before
        // rotation. Re-consuming the Activity intent would enqueue it twice.
        if (!restored) {
            Uri incoming = incomingUri(getIntent());
            if (incoming != null) {
                startScan(incoming);
            }
        }
    }

    @Override
    protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        setIntent(intent);
        Uri incoming = incomingUri(intent);
        if (incoming != null) {
            startScan(incoming);
        }
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode == REQUEST_PICK_APK && resultCode == RESULT_OK && data != null) {
            Uri selected = data.getData();
            if (selected != null) {
                startScan(selected);
            }
        }
    }

    @Override
    public Object onRetainNonConfigurationInstance() {
        return controller;
    }

    @Override
    protected void onDestroy() {
        if (controller != null) {
            controller.detach(this);
            if (!isChangingConfigurations()) {
                controller.close();
            }
        }
        super.onDestroy();
    }

    private void chooseApk() {
        Intent picker = new Intent(Intent.ACTION_OPEN_DOCUMENT);
        picker.addCategory(Intent.CATEGORY_OPENABLE);
        picker.setType("*/*");
        picker.putExtra(Intent.EXTRA_MIME_TYPES, new String[] {
                "application/vnd.android.package-archive",
                "application/zip",
                "application/octet-stream",
        });
        startActivityForResult(picker, REQUEST_PICK_APK);
    }

    private void startScan(Uri uri) {
        controller.start(uri);
    }

    private void renderState(ScanUiState state) {
        if (state.kind == ScanUiState.SCANNING) {
            latestReport = null;
            selectButton.setEnabled(false);
            shareButton.setEnabled(false);
            showStatus("正在離線掃描… / Scanning offline…",
                    state.displayName
                            + "\n只讀取 ZIP metadata，不呼叫 Android APK parser。\n"
                            + "Reading ZIP metadata only; Android's APK parser is not invoked.",
                    COLOR_BLUE);
            return;
        }
        if (state.kind == ScanUiState.REPORT) {
            renderReport(state.report);
            return;
        }
        latestReport = null;
        selectButton.setEnabled(true);
        shareButton.setEnabled(false);
        showStatus("等待 APK / Waiting for an APK",
                "可直接選擇檔案，也可從其他 App 分享進來。\n"
                        + "Choose a file here or share one from another app.", COLOR_BLUE);
    }

    private void renderReport(ScanReport report) {
        latestReport = report;
        selectButton.setEnabled(true);
        shareButton.setEnabled(true);

        if (report.inconclusive) {
            showStatus("無法判定 / Inconclusive",
                    report.asDisplayText() + "\n\n不要把無法判定視為通過。\n"
                            + "Do not treat an inconclusive scan as a pass.", COLOR_AMBER);
        } else if (report.accepted) {
            showStatus("✓ 未發現已知 GhostMap 結構 / No known pattern found",
                    report.asDisplayText()
                            + "\n\n結果只對上列 SHA-256 的掃描快照有效；安裝前若來源可能變動，請立即重掃。\n"
                            + "This verdict applies only to the SHA-256 snapshot above; rescan immediately before installation if the source may change.\n\n"
                            + "這是結構檢查，不是完整惡意程式判定。\n"
                            + "This is a structural check, not a full malware verdict.",
                    COLOR_GREEN);
        } else {
            showStatus("✕ 已阻擋，請勿安裝 / Blocked — do not install",
                    report.asDisplayText() + "\n\n檔案未交給 Android APK parser。\n"
                            + "The file was not passed to Android's APK parser.", COLOR_RED);
        }
    }

    private void shareReport() {
        if (latestReport == null) {
            return;
        }
        Intent share = new Intent(Intent.ACTION_SEND);
        share.setType("text/plain");
        share.putExtra(Intent.EXTRA_SUBJECT, "APK Guard scan report");
        share.putExtra(Intent.EXTRA_TEXT, latestReport.asShareText());
        startActivity(Intent.createChooser(share, "分享掃描結果 / Share scan report"));
    }

    private void buildUi() {
        ScrollView scroll = new ScrollView(this);
        scroll.setFillViewport(true);
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        int padding = dp(24);
        root.setPadding(padding, padding, padding, padding);
        root.setBackgroundColor(Color.rgb(247, 248, 252));
        scroll.addView(root, new ScrollView.LayoutParams(
                ScrollView.LayoutParams.MATCH_PARENT, ScrollView.LayoutParams.WRAP_CONTENT));

        TextView title = text("APK Guard", 29, Color.rgb(20, 24, 34));
        title.setTypeface(Typeface.DEFAULT_BOLD);
        root.addView(title);

        TextView subtitle = text("手機上的 GhostMap APK 預先掃描器\n"
                + "On-device GhostMap APK preflight scanner", 17, Color.DKGRAY);
        subtitle.setPadding(0, dp(6), 0, dp(20));
        root.addView(subtitle);

        TextView steps = text("收到 APK 時：\n"
                + "1. 在瀏覽器、聊天 App 或檔案管理器按「分享／開啟方式」\n"
                + "2. 選擇 APK Guard\n"
                + "3. 只有掃描結果通過時才繼續評估安裝\n\n"
                + "When you receive an APK:\n"
                + "1. Tap Share or Open with\n"
                + "2. Choose APK Guard\n"
                + "3. Continue only after reviewing a passing result",
                16, Color.rgb(45, 49, 58));
        steps.setPadding(0, 0, 0, dp(20));
        root.addView(steps);

        selectButton = button("選擇 APK 掃描 / Choose APK", COLOR_BLUE);
        selectButton.setOnClickListener(view -> chooseApk());
        root.addView(selectButton, buttonLayout());

        shareButton = button("分享掃描結果 / Share report", COLOR_GREEN);
        shareButton.setEnabled(false);
        shareButton.setOnClickListener(view -> shareReport());
        root.addView(shareButton, buttonLayout());

        TextView privacy = text("隱私：完全離線、無網路或儲存權限。私有暫存副本會在掃描後刪除；若清理失敗，結果會明確顯示 INCONCLUSIVE，並於下次啟動或新掃描前重試。\n"
                + "Privacy: fully offline, with no network or storage permission. The private copy is deleted after scanning; cleanup failure is shown as INCONCLUSIVE and retried at the next launch or scan.",
                14, Color.DKGRAY);
        privacy.setPadding(0, dp(10), 0, dp(22));
        root.addView(privacy);

        statusTitle = text("等待 APK / Waiting for an APK", 21, COLOR_BLUE);
        statusTitle.setTypeface(Typeface.DEFAULT_BOLD);
        root.addView(statusTitle);

        statusDetail = text("可直接選擇檔案，也可從其他 App 分享進來。\n"
                + "Choose a file here or share one from another app.", 15, Color.DKGRAY);
        statusDetail.setPadding(0, dp(8), 0, 0);
        statusDetail.setTextIsSelectable(true);
        root.addView(statusDetail);

        setContentView(scroll);
    }

    private static Uri incomingUri(Intent intent) {
        if (intent == null) {
            return null;
        }
        if (Intent.ACTION_VIEW.equals(intent.getAction())) {
            return intent.getData();
        }
        if (Intent.ACTION_SEND.equals(intent.getAction())) {
            @SuppressWarnings("deprecation")
            Uri stream = intent.getParcelableExtra(Intent.EXTRA_STREAM);
            if (stream != null) {
                return stream;
            }
            ClipData clip = intent.getClipData();
            if (clip != null && clip.getItemCount() > 0) {
                return clip.getItemAt(0).getUri();
            }
        }
        return null;
    }

    private TextView text(String value, int sp, int color) {
        TextView view = new TextView(this);
        view.setText(value);
        view.setTextSize(sp);
        view.setTextColor(color);
        view.setLineSpacing(0, 1.15f);
        return view;
    }

    private Button button(String label, int color) {
        Button button = new Button(this);
        button.setText(label);
        button.setTextSize(17);
        button.setTextColor(Color.WHITE);
        button.setTypeface(Typeface.DEFAULT_BOLD);
        button.setAllCaps(false);
        button.setBackgroundTintList(ColorStateList.valueOf(color));
        return button;
    }

    private LinearLayout.LayoutParams buttonLayout() {
        LinearLayout.LayoutParams params = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, dp(58));
        params.bottomMargin = dp(12);
        return params;
    }

    private void showStatus(String title, String detail, int color) {
        statusTitle.setText(title);
        statusTitle.setTextColor(color);
        statusDetail.setText(detail == null ? "" : detail);
    }

    private int dp(int value) {
        return Math.round(value * getResources().getDisplayMetrics().density);
    }

    /** Owns the worker across configuration changes and publishes only latest-request results. */
    private static final class ScanController {
        private final Context context;
        private final Handler mainHandler = new Handler(Looper.getMainLooper());
        // One active and one pending request are enough: newer Share/Open
        // intents replace an older queued request instead of growing memory.
        private final ExecutorService executor = new ThreadPoolExecutor(
                1, 1, 0L, TimeUnit.MILLISECONDS,
                new ArrayBlockingQueue<>(1),
                new ThreadPoolExecutor.DiscardOldestPolicy());
        private final LatestScanGate latestGate = new LatestScanGate();
        private final CleanupPublishGate cleanupGate;

        private ScannerActivity listener;
        private ScanUiState state;
        private boolean closed;

        ScanController(Context context) {
            this.context = context;
            ScanReport cleanupFailure = pruneStaleFiles(context);
            cleanupGate = new CleanupPublishGate(cleanupFailure == null);
            state = cleanupFailure == null
                    ? ScanUiState.waiting()
                    : ScanUiState.report(cleanupFailure);
        }

        void attach(ScannerActivity activity) {
            listener = activity;
            activity.renderState(state);
        }

        void detach(ScannerActivity activity) {
            if (listener == activity) {
                listener = null;
            }
        }

        void start(Uri uri) {
            if (closed) {
                return;
            }
            String displayName = displayName(context, uri);
            long token = latestGate.begin();
            state = ScanUiState.scanning(displayName);
            dispatch();

            executor.execute(() -> {
                ScanReport workerReport = scanOne(context, uri, displayName);
                cleanupGate.recordCleanupOutcome(
                        !"TEMP_CLEANUP_FAILED".equals(workerReport.code));
                mainHandler.post(() -> {
                    if (closed || !latestGate.isCurrent(token)) {
                        return;
                    }
                    ScanReport visibleReport = workerReport;
                    if (workerReport.accepted && !cleanupGate.canPublishPass()) {
                        visibleReport = ScanReport.cleanupFailure(displayName, null,
                                "private scan cache is not confirmed clean");
                    }
                    state = ScanUiState.report(visibleReport);
                    logReport(visibleReport);
                    dispatch();
                });
            });
        }

        void close() {
            if (closed) {
                return;
            }
            closed = true;
            latestGate.cancelAll();
            listener = null;
            executor.shutdownNow();
        }

        private void dispatch() {
            if (listener != null) {
                listener.renderState(state);
            }
        }
    }

    private static ScanReport scanOne(Context context, Uri uri, String displayName) {
        // The executor is serial, so no active scan file can be mistaken for
        // stale data here. A prior cleanup failure must be resolved before a
        // later request may publish PASS.
        ScanReport staleCleanupFailure = pruneStaleFiles(context);
        if (staleCleanupFailure != null) {
            return staleCleanupFailure;
        }

        File temporary = null;
        CopiedInput copied = null;
        ScanReport report;
        try {
            temporary = File.createTempFile("incoming-", ".apk",
                    scanCacheDirectory(context));
            copied = copyIntoPrivateCache(context, uri, temporary);
            ZipSafetyGuard.Result result = ZipSafetyGuard.inspect(temporary);
            String code = result.accepted && result.entriesChecked == 0
                    ? "EMPTY_ARCHIVE" : result.code;
            boolean accepted = result.accepted && result.entriesChecked > 0;
            report = ScanReport.completed(displayName, copied.sizeBytes,
                    copied.sha256, accepted, code, result.entry,
                    result.method, result.entriesChecked);
        } catch (ScanLimitException limit) {
            report = ScanReport.inconclusive(displayName, "FILE_TOO_LARGE",
                    limit.getMessage());
        } catch (Exception error) {
            report = ScanReport.inconclusive(displayName, "SCAN_ERROR",
                    error.getClass().getSimpleName() + ": " + safeMessage(error));
        }

        if (temporary != null && !PrivateFileCleanup.deleteWithRetries(temporary)) {
            String priorCode = report.code;
            report = ScanReport.cleanupFailure(displayName, copied,
                    "temporary file cleanup failed; prior_result=" + priorCode);
        }
        return report;
    }

    private static CopiedInput copyIntoPrivateCache(Context context, Uri uri, File temporary)
            throws IOException, ScanLimitException {
        File directory = temporary.getParentFile();
        StatFs stats = new StatFs(directory.getAbsolutePath());
        long availableForScan = Math.max(0, stats.getAvailableBytes() - CACHE_RESERVE_BYTES);
        long effectiveLimit = Math.min(MAX_SCAN_BYTES, availableForScan);
        Long declaredSize = declaredSize(context, uri);
        if (declaredSize != null && declaredSize > effectiveLimit) {
            throw new ScanLimitException("檔案超過可用掃描空間 / file exceeds scan space");
        }

        MessageDigest digest = sha256Digest();
        long total = 0;
        try (InputStream input = context.getContentResolver().openInputStream(uri);
             FileOutputStream output = new FileOutputStream(temporary)) {
            if (input == null) {
                throw new IOException("Content provider returned no stream");
            }
            byte[] buffer = new byte[128 * 1024];
            int count;
            while ((count = input.read(buffer)) != -1) {
                if (count == 0) {
                    continue;
                }
                if (total > effectiveLimit - count) {
                    throw new ScanLimitException(
                            "檔案超過 2 GiB 或可用掃描空間 / file exceeds scan limit");
                }
                output.write(buffer, 0, count);
                digest.update(buffer, 0, count);
                total += count;
            }
            output.getFD().sync();
        }
        return new CopiedInput(temporary, total, hex(digest.digest()));
    }

    private static ScanReport pruneStaleFiles(Context context) {
        try {
            File[] stale = scanCacheDirectory(context).listFiles();
            if (stale == null) {
                return ScanReport.cleanupFailure("private scan cache", null,
                        "private scan cache could not be listed");
            }
            for (File file : stale) {
                if (file.isFile() && !PrivateFileCleanup.deleteWithRetries(file)) {
                    return ScanReport.cleanupFailure("private scan cache", null,
                            "stale private copy could not be deleted; restart or clear app storage");
                }
            }
        } catch (IOException | SecurityException error) {
            return ScanReport.cleanupFailure("private scan cache", null, safeMessage(error));
        }
        return null;
    }

    private static String displayName(Context context, Uri uri) {
        if (ContentResolver.SCHEME_CONTENT.equals(uri.getScheme())) {
            try (Cursor cursor = context.getContentResolver().query(uri,
                    new String[] {OpenableColumns.DISPLAY_NAME}, null, null, null)) {
                if (cursor != null && cursor.moveToFirst() && !cursor.isNull(0)) {
                    return cursor.getString(0);
                }
            } catch (RuntimeException ignored) {
                // Fall back to the last path segment without exposing a full path.
            }
        }
        String segment = uri.getLastPathSegment();
        return segment == null || segment.isEmpty() ? "selected.apk" : segment;
    }

    private static Long declaredSize(Context context, Uri uri) {
        if (!ContentResolver.SCHEME_CONTENT.equals(uri.getScheme())) {
            return null;
        }
        try (Cursor cursor = context.getContentResolver().query(uri,
                new String[] {OpenableColumns.SIZE}, null, null, null)) {
            if (cursor != null && cursor.moveToFirst() && !cursor.isNull(0)) {
                return cursor.getLong(0);
            }
        } catch (RuntimeException ignored) {
            // The streamed byte count still enforces the limit.
        }
        return null;
    }

    private static File scanCacheDirectory(Context context) throws IOException {
        File directory = new File(context.getCacheDir(), "apk-guard-incoming");
        if (!directory.isDirectory() && !directory.mkdirs()) {
            throw new IOException("Cannot create private scan cache");
        }
        return directory;
    }

    private static MessageDigest sha256Digest() {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException impossible) {
            throw new AssertionError(impossible);
        }
    }

    private static String safeMessage(Exception error) {
        String message = error.getMessage();
        return message == null || message.isEmpty() ? "no detail" : message;
    }

    private static String hex(byte[] data) {
        StringBuilder output = new StringBuilder(data.length * 2);
        for (byte value : data) {
            output.append(String.format(Locale.ROOT, "%02x", value & 0xff));
        }
        return output.toString();
    }

    private static void logReport(ScanReport report) {
        String verdict = report.inconclusive
                ? "INCONCLUSIVE" : (report.accepted ? "PASS" : "BLOCKED");
        Log.i(TAG, "RESULT verdict=" + verdict
                + " code=" + report.code
                + " size=" + report.sizeBytes
                + " sha256=" + report.sha256
                + " entries_checked=" + report.entriesChecked
                + " parser_invoked=false");
    }

    private static String explainCode(String code) {
        switch (code) {
            case "PASS":
                return "壓縮方法與檔案邊界通過 / methods and file bounds passed";
            case "UNSUPPORTED_COMPRESSION_METHOD":
                return "使用 Android APK 不應接受的壓縮方法 / unsupported APK compression method";
            case "ENTRY_DATA_BEYOND_ARCHIVE":
            case "CENTRAL_DIRECTORY_RANGE_INVALID":
            case "CENTRAL_ENTRY_RANGE_INVALID":
            case "LOCAL_HEADER_RANGE_INVALID":
                return "ZIP 宣告範圍超出實際檔案邊界 / declared ZIP range exceeds file bounds";
            case "LOCAL_CENTRAL_METADATA_MISMATCH":
            case "STORED_LENGTH_MISMATCH":
                return "ZIP metadata 前後不一致 / inconsistent ZIP metadata";
            case "ZIP64_UNSUPPORTED":
            case "MULTI_DISK_UNSUPPORTED":
            case "MULTI_DISK_ENTRY_UNSUPPORTED":
                return "此 APK 結構不在安全允許清單 / structure is outside the allowlist";
            case "EOCD_NOT_FOUND":
            case "EOCD_RANGE_INVALID":
            case "CENTRAL_SIGNATURE_INVALID":
            case "LOCAL_SIGNATURE_INVALID":
            case "TRUNCATED_ZIP":
            case "EMPTY_ARCHIVE":
                return "檔案不是完整 APK/ZIP / incomplete APK or ZIP";
            case "FILE_TOO_LARGE":
                return "超過安全掃描容量 / exceeds safe scan capacity";
            case "TEMP_CLEANUP_FAILED":
                return "私有暫存副本清理失敗 / private temporary copy cleanup failed";
            default:
                return "安全檢查未通過 / safety check did not pass";
        }
    }

    private static String formatBytes(long bytes) {
        if (bytes < 1024) {
            return bytes + " B";
        }
        double kib = bytes / 1024.0;
        if (kib < 1024) {
            return String.format(Locale.ROOT, "%.1f KiB", kib);
        }
        double mib = kib / 1024.0;
        if (mib < 1024) {
            return String.format(Locale.ROOT, "%.1f MiB", mib);
        }
        return String.format(Locale.ROOT, "%.2f GiB", mib / 1024.0);
    }

    private static final class ScanUiState {
        static final int WAITING = 0;
        static final int SCANNING = 1;
        static final int REPORT = 2;

        final int kind;
        final String displayName;
        final ScanReport report;

        private ScanUiState(int kind, String displayName, ScanReport report) {
            this.kind = kind;
            this.displayName = displayName;
            this.report = report;
        }

        static ScanUiState waiting() {
            return new ScanUiState(WAITING, "", null);
        }

        static ScanUiState scanning(String displayName) {
            return new ScanUiState(SCANNING, displayName, null);
        }

        static ScanUiState report(ScanReport report) {
            return new ScanUiState(REPORT, "", report);
        }
    }

    private static final class CopiedInput {
        final File file;
        final long sizeBytes;
        final String sha256;

        CopiedInput(File file, long sizeBytes, String sha256) {
            this.file = file;
            this.sizeBytes = sizeBytes;
            this.sha256 = sha256;
        }
    }

    private static final class ScanLimitException extends Exception {
        ScanLimitException(String message) {
            super(message);
        }
    }

    private static final class ScanReport {
        final String fileName;
        final long sizeBytes;
        final String sha256;
        final boolean accepted;
        final boolean inconclusive;
        final String code;
        final String entry;
        final int method;
        final int entriesChecked;
        final String errorDetail;

        private ScanReport(String fileName, long sizeBytes, String sha256,
                           boolean accepted, boolean inconclusive, String code,
                           String entry, int method, int entriesChecked,
                           String errorDetail) {
            this.fileName = fileName;
            this.sizeBytes = sizeBytes;
            this.sha256 = sha256;
            this.accepted = accepted;
            this.inconclusive = inconclusive;
            this.code = code;
            this.entry = entry;
            this.method = method;
            this.entriesChecked = entriesChecked;
            this.errorDetail = errorDetail;
        }

        static ScanReport completed(String fileName, long sizeBytes, String sha256,
                                    boolean accepted, String code, String entry,
                                    int method, int entriesChecked) {
            return new ScanReport(fileName, sizeBytes, sha256, accepted, false,
                    code, entry == null ? "" : entry, method, entriesChecked, "");
        }

        static ScanReport inconclusive(String fileName, String code, String detail) {
            return new ScanReport(fileName, -1, "", false, true, code, "",
                    -1, 0, detail);
        }

        static ScanReport cleanupFailure(String fileName, CopiedInput copied,
                                         String detail) {
            long size = copied == null ? -1 : copied.sizeBytes;
            String hash = copied == null ? "" : copied.sha256;
            return new ScanReport(fileName, size, hash, false, true,
                    "TEMP_CLEANUP_FAILED", "", -1, 0, detail);
        }

        String asDisplayText() {
            StringBuilder text = new StringBuilder();
            text.append("檔案 / File: ").append(fileName).append('\n');
            if (sizeBytes >= 0) {
                text.append("大小 / Size: ").append(formatBytes(sizeBytes)).append('\n');
            }
            if (!sha256.isEmpty()) {
                text.append("SHA-256: ").append(sha256).append('\n');
            }
            text.append("結果碼 / Code: ").append(code).append('\n');
            text.append("說明 / Meaning: ").append(explainCode(code));
            if (entriesChecked > 0) {
                text.append("\nEntries checked: ").append(entriesChecked);
            }
            if (!entry.isEmpty()) {
                text.append("\nEntry: ").append(entry);
            }
            if (method >= 0) {
                text.append("\nZIP method: ").append(method);
            }
            if (!errorDetail.isEmpty()) {
                text.append("\nDetail: ").append(errorDetail);
            }
            return text.toString();
        }

        String asShareText() {
            String verdict = inconclusive ? "INCONCLUSIVE" : (accepted ? "PASS" : "BLOCKED");
            return "APK Guard — " + verdict + "\n" + asDisplayText()
                    + "\n\nVerdict applies only to this SHA-256 snapshot. "
                    + "Offline structural preflight; Android APK parser was not invoked.";
        }
    }
}
