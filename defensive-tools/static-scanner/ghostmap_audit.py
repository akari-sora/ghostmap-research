#!/usr/bin/env python3
"""Read-only APK/ZIP metadata auditor for the GhostMap parser mismatch.

Python >= 3.9. Standard library only. Parses archive metadata in place.

Based on the publicly described AOSP parser differential (Nov 2026):
  libziparchive: only bounds-checks uncompressed length if method == STORED.
  libandroidfw: if method == DEFLATED, maps compressed length;
                otherwise maps uncompressed length.

This tool identifies the structural pattern associated with the parser
differential; runtime reachability is recorded by the Android harness.
"""

from __future__ import annotations

import argparse
import json
import os
import struct
import sys
import zipfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Optional

ZIP_STORED = 0
ZIP_DEFLATED = 8
LOCAL_HDR = struct.Struct('<IHHHHHIIIHH')
LOCAL_MAGIC = 0x04034B50
CENTRAL_HDR = struct.Struct('<IHHHHHHIIIHHHHHII')
CENTRAL_MAGIC = 0x02014B50
END_HDR = struct.Struct('<IHHHHIIH')
END_MAGIC = 0x06054B50
MAX_END_SEARCH = END_HDR.size + 65535
MAX_CENTRAL_DIRECTORY_BYTES = 64 * 1024**2
DEFAULT_MAX_FILE_SIZE = 2 * 1024**3  # avoid reading huge untrusted archives
DEFAULT_MAX_ENTRIES = 200_000


@dataclass(frozen=True)
class Differential:
    ziparchive_stored_check_applies: bool
    ziparchive_bounds_check_would_pass: bool
    androidfw_map_length: int
    over_central_directory: bool
    map_beyond_eof: bool
    ghostmap_candidate: bool


def analyze_rules(method: int, compressed_length: int, uncompressed_length: int,
                  bytes_before_cd: int, bytes_to_eof: int) -> Differential:
    """Model the two AOSP code paths without opening an APK or mmap-ing a file.

    Assumes ordinary non-ZIP64 offsets and non-negative quantities. This model
    represents static structure; runtime reachability is an independent result.
    """
    if min(method, compressed_length, uncompressed_length,
           bytes_before_cd, bytes_to_eof) < 0:
        raise ValueError('All inputs must be non-negative')
    stored = method == ZIP_STORED
    checked = compressed_length <= bytes_before_cd and (
        not stored or uncompressed_length <= bytes_before_cd
    )
    mapped = compressed_length if method == ZIP_DEFLATED else uncompressed_length
    over_cd = mapped > bytes_before_cd
    over_eof = mapped > bytes_to_eof
    candidate = method not in (ZIP_STORED, ZIP_DEFLATED) and checked and over_cd
    return Differential(stored, checked, mapped, over_cd, over_eof, candidate)


def _read_local_header(f, offset: int, file_size: int):
    if offset < 0 or offset + LOCAL_HDR.size > file_size:
        raise ValueError('local header outside archive')
    f.seek(offset)
    record = f.read(LOCAL_HDR.size)
    if len(record) != LOCAL_HDR.size:
        raise ValueError('short local header')
    magic, ver, flags, method, mod_time, mod_date, crc, csize, usize, nlen, elen = (
        LOCAL_HDR.unpack(record)
    )
    if magic != LOCAL_MAGIC:
        raise ValueError('bad local header signature')
    if offset + LOCAL_HDR.size + nlen > file_size:
        raise ValueError('local filename outside archive')
    filename = f.read(nlen)
    if len(filename) != nlen:
        raise ValueError('short local filename')
    return {
        'method': method, 'flags': flags, 'compressed_length': csize,
        'uncompressed_length': usize, 'filename_length': nlen,
        'extra_length': elen, 'filename': filename,
        'data_offset': offset + LOCAL_HDR.size + nlen + elen
    }


def _preflight_directory(f, file_size: int, max_entries: int):
    """Bound directory allocation and entry parsing before ZipFile sees the file.

    ZIP64 and multi-disk archives require different end-record handling, so this
    metadata-only auditor rejects them rather than trusting an incomplete limit.
    """
    if max_entries < 0:
        raise ValueError('max entries must be non-negative')
    f.seek(max(0, file_size - MAX_END_SEARCH))
    tail = f.read(MAX_END_SEARCH)
    end_at = tail.rfind(b'PK\x05\x06')
    if end_at < 0 or end_at + END_HDR.size > len(tail):
        raise zipfile.BadZipFile('end of central directory not found')
    (magic, disk, cd_disk, disk_entries, total_entries, directory_size,
     directory_offset, comment_length) = END_HDR.unpack_from(tail, end_at)
    if magic != END_MAGIC:
        raise zipfile.BadZipFile('bad end of central directory')
    if (disk != 0 or cd_disk != 0 or disk_entries != total_entries):
        raise ValueError('multi-disk ZIP archives are unsupported')
    if (total_entries == 0xFFFF or directory_size == 0xFFFFFFFF
            or directory_offset == 0xFFFFFFFF):
        raise ValueError('ZIP64 central directories are unsupported')
    if total_entries > max_entries:
        raise ValueError(f'archive exceeds max entries ({max_entries})')
    if directory_size > MAX_CENTRAL_DIRECTORY_BYTES:
        raise ValueError('central directory exceeds size limit')
    end_offset = file_size - len(tail) + end_at
    if end_offset >= 20:
        f.seek(end_offset - 20)
        if f.read(4) == b'PK\x06\x07':
            raise ValueError('ZIP64 central directories are unsupported')
    if directory_size > end_offset:
        raise zipfile.BadZipFile('central directory outside archive')
    f.seek(end_offset - directory_size)
    directory = f.read(directory_size)
    if len(directory) != directory_size:
        raise zipfile.BadZipFile('short central directory')
    names = []
    position = 0
    while position < directory_size:
        if position + CENTRAL_HDR.size > directory_size:
            raise zipfile.BadZipFile('short central directory entry')
        fields = CENTRAL_HDR.unpack_from(directory, position)
        if fields[0] != CENTRAL_MAGIC:
            raise zipfile.BadZipFile('bad central directory entry')
        name_length, extra_length, comment_length = fields[10:13]
        name_start = position + CENTRAL_HDR.size
        next_position = name_start + name_length + extra_length + comment_length
        if next_position > directory_size:
            raise zipfile.BadZipFile('central directory entry outside directory')
        name = directory[name_start:name_start + name_length]
        if b'\x00' in name:
            raise ValueError('central directory filename contains NUL')
        names.append(name)
        if len(names) > max_entries:
            raise ValueError(f'archive exceeds max entries ({max_entries})')
        position = next_position
    if len(names) != total_entries:
        raise zipfile.BadZipFile('central directory entry count mismatch')
    return names


def audit(path: Path, max_entries: int = DEFAULT_MAX_ENTRIES) -> dict:
    """Inspect Central Directory and Local File Header metadata read-only."""
    path = Path(path)
    file_size = path.stat().st_size
    result = {'file': str(path), 'size_bytes': file_size,
              'entries_checked': 0, 'findings': [], 'status': 'ok'}
    with open(path, 'rb') as f:
        central_names = _preflight_directory(f, file_size, max_entries)
    with zipfile.ZipFile(path, 'r') as zf, open(path, 'rb') as f:
        infos = zf.infolist()
        if len(infos) != len(central_names):
            raise zipfile.BadZipFile('central directory changed during audit')
        cd_start = zf.start_dir
        if cd_start < 0 or cd_start > file_size:
            raise ValueError('central directory location outside archive')
        for info, central_name in zip(infos, central_names):
            result['entries_checked'] += 1
            entry_name = info.filename
            issues = []
            data_offset: Optional[int] = None
            local = None
            try:
                local = _read_local_header(f, info.header_offset, file_size)
                data_offset = local['data_offset']
                if data_offset > file_size or data_offset > cd_start:
                    issues.append('DATA_OFFSET_OUT_OF_RANGE')
                if local['method'] != info.compress_type:
                    issues.append('LOCAL_CENTRAL_METHOD_MISMATCH')
                if local['flags'] != info.flag_bits:
                    issues.append('LOCAL_CENTRAL_FLAGS_MISMATCH')
                if local['filename'] != central_name:
                    issues.append('LOCAL_CENTRAL_NAME_MISMATCH')
                # A data-descriptor entry (bit 3) may carry zero placeholders in
                # its local header. ZIP64 placeholders are a contradiction here
                # because _preflight_directory already rejected ZIP64 end
                # records, so they are reported rather than treated as unknown.
                descriptor = bool(info.flag_bits & 0x8)
                for local_value, central_value in (
                        (local['compressed_length'], info.compress_size),
                        (local['uncompressed_length'], info.file_size)):
                    if local_value == 0xFFFFFFFF:
                        issues.append('LOCAL_ZIP64_PLACEHOLDER')
                        break
                    if local_value != central_value and not (
                            descriptor and local_value == 0):
                        issues.append('LOCAL_CENTRAL_SIZE_MISMATCH')
                        break
            except ValueError as exc:
                issues.append('LOCAL_HEADER_INVALID: ' + str(exc))

            if info.compress_type not in (ZIP_STORED, ZIP_DEFLATED):
                issues.append('UNSUPPORTED_COMPRESSION_METHOD')
            if info.compress_type == ZIP_STORED and info.file_size != info.compress_size:
                issues.append('STORED_LENGTHS_DIFFER')
            model = None
            if data_offset is not None and 0 <= data_offset <= min(cd_start, file_size):
                model = analyze_rules(
                    method=info.compress_type,
                    compressed_length=info.compress_size,
                    uncompressed_length=info.file_size,
                    bytes_before_cd=cd_start - data_offset,
                    bytes_to_eof=file_size - data_offset,
                )
                if info.compress_size > cd_start - data_offset:
                    issues.append('COMPRESSED_LENGTH_OVER_DIRECTORY')
                if model.over_central_directory:
                    issues.append('MAPPED_LENGTH_OVER_DIRECTORY')
                if model.map_beyond_eof:
                    issues.append('MAPPED_LENGTH_BEYOND_EOF')
                if model.ghostmap_candidate:
                    issues.append('GHOSTMAP_PARSER_DIFFERENTIAL_CANDIDATE')

            if issues:
                result['findings'].append({
                    'entry': entry_name,
                    'compression_method': info.compress_type,
                    'compressed_length': info.compress_size,
                    'uncompressed_length': info.file_size,
                    'data_offset': data_offset,
                    'issues': issues,
                    'model': asdict(model) if model else None,
                })
    if result['findings']:
        result['status'] = 'review_required'
    return result


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description='Read-only GhostMap APK/ZIP metadata audit.'
    )
    parser.add_argument('file', type=Path, help='path to APK or ZIP (read only)')
    parser.add_argument('--json', action='store_true', help='JSON output')
    parser.add_argument('--max-file-size', type=int, default=DEFAULT_MAX_FILE_SIZE,
                        help='maximum size in bytes (default 2 GiB)')
    args = parser.parse_args(argv)
    try:
        if not args.file.is_file():
            raise ValueError('not a regular file')
        if os.path.getsize(args.file) > args.max_file_size:
            raise ValueError('file exceeds configured maximum size')
        result = audit(args.file)
    except (ValueError, OSError, zipfile.BadZipFile,
            zipfile.LargeZipFile, RuntimeError) as exc:
        print(f'ERROR: {exc}', file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print(f"{result['file']}: {result['entries_checked']} entries, "
              f"{len(result['findings'])} suspicious, status={result['status']}")
        for finding in result['findings']:
            print(f"  {finding['entry']}: method={finding['compression_method']}, "
                  f"{', '.join(finding['issues'])}")
        if result['status'] == 'ok':
            print('No known GhostMap metadata pattern found; this is not a security guarantee.')
    return 1 if result['findings'] else 0


if __name__ == '__main__':
    sys.exit(main())
