#!/usr/bin/env python3
"""Validate an unsigned device IPA without extracting or executing its contents."""
import argparse
import hashlib
import json
import plistlib
from pathlib import Path, PurePosixPath
import stat
import struct
import zipfile


class VerificationError(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise VerificationError(message)


def inspect_macho(data, *, executable=True):
    require(len(data) >= 32, "Truncated Mach-O header")
    magic, cpu, subtype, kind, count, commands_size, flags, reserved = struct.unpack_from("<8I", data)
    require(magic == 0xFEEDFACF, "Expected a thin 64-bit little-endian Mach-O")
    require(cpu == 0x0100000C, "Expected ARM64 device architecture")
    if executable:
        require(kind == 2, "Main binary is not MH_EXECUTE")
    end = 32 + commands_size
    require(end <= len(data) and count <= commands_size // 8, "Invalid Mach-O command table")
    cursor = 32
    ios = False
    for _ in range(count):
        require(cursor + 8 <= end, "Truncated load command")
        command, size = struct.unpack_from("<II", data, cursor)
        require(size >= 8 and size % 8 == 0 and cursor + size <= end, "Invalid load command size")
        require(command != 0x1D, "LC_CODE_SIGNATURE found: binary is signed")
        if command == 0x32:  # LC_BUILD_VERSION
            require(size >= 24, "Truncated LC_BUILD_VERSION")
            platform = struct.unpack_from("<I", data, cursor + 8)[0]
            require(platform == 2, "Mach-O was not built for iOS devices")
            ios = True
        elif command == 0x25:  # LC_VERSION_MIN_IPHONEOS, older linkers
            require(size >= 16, "Truncated LC_VERSION_MIN_IPHONEOS")
            ios = True
        elif command in (0x24, 0x2F, 0x30):
            raise VerificationError("Non-iOS minimum-version command")
        cursor += size
    require(cursor == end, "Load command sizes do not match header")
    require(ios, "Missing iOS platform load command")
    return {"architecture": "arm64", "platform": "iOS device", "codeSignature": "absent"}


def verify(path):
    with zipfile.ZipFile(path) as archive:
        entries = archive.infolist()
        names = [entry.filename for entry in entries]
        require(len(names) == len(set(names)), "Duplicate ZIP member")
        require(sum(entry.file_size for entry in entries) < 256 * 1024 * 1024, "Unexpectedly large IPA")
        for entry in entries:
            name = entry.filename
            parts = PurePosixPath(name).parts
            require(not name.startswith('/') and '..' not in parts and '\\' not in name,
                    "Unsafe ZIP path")
            require(parts and parts[0] == 'Payload', "Unexpected top-level ZIP member")
            require(len(parts) == 1 or parts[1] == 'A16Probe.app', "Unexpected application bundle")
            mode = entry.external_attr >> 16
            require(not stat.S_ISLNK(mode), "Symlinks are not expected in this IPA")
            require('_CodeSignature' not in parts and parts[-1] != 'embedded.mobileprovision',
                    "Signing material found in unsigned IPA")
        require(archive.testzip() is None, "ZIP CRC verification failed")
        root = 'Payload/A16Probe.app/'
        require(root + 'Info.plist' in names, "Missing Info.plist")
        info = plistlib.loads(archive.read(root + 'Info.plist'))
        require(info.get('CFBundlePackageType') == 'APPL', "Invalid bundle type")
        require(info.get('CFBundleIdentifier') == 'org.a16probe.research', "Unexpected bundle identifier")
        require(info.get('CFBundleExecutable') == 'A16Probe', "Unexpected executable name")
        require(info.get('CFBundleSupportedPlatforms') == ['iPhoneOS'], "Not an iPhoneOS bundle")
        require(info.get('UIDeviceFamily') == [1], "Expected an iPhone application")
        minimum = info.get('MinimumOSVersion', '')
        require(isinstance(minimum, str) and minimum == '16.0', "Unexpected minimum OS version")
        for key in ('CFBundleVersion', 'CFBundleShortVersionString'):
            require(isinstance(info.get(key), str) and info[key] and '$(' not in info[key],
                    f"Missing or unresolved {key}")
        executable = root + info['CFBundleExecutable']
        require(executable in names, "Missing executable")
        mode = archive.getinfo(executable).external_attr >> 16
        require(mode & 0o111, "Main executable has no executable permission")
        binary = inspect_macho(archive.read(executable))
        for entry in entries:
            if entry.is_dir() or entry.filename == executable:
                continue
            with archive.open(entry) as stream:
                magic = stream.read(4)
            if magic in (b'\xcf\xfa\xed\xfe', b'\xca\xfe\xba\xbe', b'\xbe\xba\xfe\xca',
                         b'\xce\xfa\xed\xfe', b'\xfe\xed\xfa\xcf', b'\xca\xfe\xba\xbf'):
                inspect_macho(archive.read(entry), executable=False)
    return {
        "status": "passed", "sha256": hashlib.sha256(Path(path).read_bytes()).hexdigest(),
        "bundleIdentifier": info['CFBundleIdentifier'], "minimumOSVersion": minimum,
        "binary": binary, "zipCRC": "passed",
        "limitations": "Static artifact checks only; installation, launch and target device behavior are not tested."
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('ipa', type=Path)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    try:
        result = verify(args.ipa)
    except (VerificationError, OSError, ValueError, zipfile.BadZipFile, KeyError, struct.error) as error:
        parser.exit(1, f'IPA verification failed: {error}\n')
    rendered = json.dumps(result, indent=2) + '\n'
    if args.output:
        args.output.write_text(rendered)
    print(rendered, end='')


if __name__ == '__main__':
    main()
