# Read-only Python static scanner

`ghostmap_audit.py` inspects ZIP/APK metadata without extracting entries or invoking Android's native resource parser. It uses Python 3.9+ standard library only.

```bash
python defensive-tools/static-scanner/ghostmap_audit.py sample.apk --json
```

Exit code `0` means no covered structural anomaly was reported, `1` means review is required, and `2` means the file could not be read or parsed. A clean result is **not** an APK security clearance. The scanner reports metadata patterns; it does not establish whether a system service will reach a particular entry.

The public test suite uses ordinary benign ZIPs and malformed non-APK data. It contains no boot-loop APK or payload generator.

Before constructing Python's `ZipFile`, the scanner checks the end record, entry count, central record ranges, and a 64 MiB central-directory size cap. It compares raw local and central file names as well as the other covered fields. ZIP64, multi-disk archives, and directories above that cap fail closed as unreadable/inconclusive for this tool; they do not receive a clean result. A ZIP64 size placeholder left in a local header, or a local size that contradicts the central directory, is reported as a finding.
