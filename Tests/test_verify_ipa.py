"""Synthetic fixtures test the validator, not the actual app or its compilation."""
import importlib.util
from pathlib import Path
import plistlib
import struct
import tempfile
import unittest
import zipfile

spec = importlib.util.spec_from_file_location('verify_ipa', Path(__file__).parents[1] / 'scripts/verify_ipa.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def macho(platform=2, signed=False, cpu=0x0100000C):
    commands = struct.pack('<6I', 0x32, 24, platform, 0x100000, 0x1A0000, 0)
    if signed:
        commands += struct.pack('<4I', 0x1D, 16, 0, 0)
    return struct.pack('<8I', 0xFEEDFACF, cpu, 0, 2, 1 + signed, len(commands), 0, 0) + commands


class IPAValidationTests(unittest.TestCase):
    def fixture(self, directory, binary=None, extra=None, override=None, mode=0o100755):
        path = Path(directory) / 'fixture.ipa'
        info = {'CFBundleIdentifier': 'org.a16probe.research', 'CFBundleExecutable': 'A16Probe',
                'CFBundlePackageType': 'APPL', 'CFBundleSupportedPlatforms': ['iPhoneOS'],
                'UIDeviceFamily': [1], 'MinimumOSVersion': '16.0',
                'CFBundleVersion': '1', 'CFBundleShortVersionString': '1.0.0'}
        info.update(override or {})
        with zipfile.ZipFile(path, 'w') as archive:
            archive.writestr('Payload/A16Probe.app/Info.plist', plistlib.dumps(info))
            entry = zipfile.ZipInfo('Payload/A16Probe.app/A16Probe')
            entry.create_system = 3
            entry.external_attr = mode << 16
            archive.writestr(entry, macho() if binary is None else binary)
            if extra:
                archive.writestr(*extra)
        return path

    def test_valid_unsigned_fixture(self):
        with tempfile.TemporaryDirectory() as directory:
            result = module.verify(self.fixture(directory))
            self.assertEqual(result['status'], 'passed')
            self.assertEqual(len(result['sha256']), 64)

    def test_rejects_invalid_artifacts(self):
        variants = [
            {'binary': macho(platform=7)},  # arm64 simulator is not an iPhone binary
            {'binary': macho(signed=True)},
            {'binary': macho(cpu=0x01000007)},
            {'binary': b'not a binary'},
            {'binary': macho()[:-1]},
            {'mode': 0o100644},
            {'mode': 0o120777},
            {'extra': ('Payload/../outside', b'')},
            {'extra': ('Payload/A16Probe.app/_CodeSignature/CodeResources', b'')},
            {'extra': ('Payload/A16Probe.app/embedded.mobileprovision', b'')},
            {'extra': ('Payload/Other.app/file', b'')},
            {'extra': ('Payload/A16Probe.app/Frameworks/Bad', macho(signed=True))},
            {'override': {'CFBundleSupportedPlatforms': ['iPhoneSimulator']}},
            {'override': {'CFBundleExecutable': '../escape'}},
            {'override': {'CFBundleVersion': '$(CURRENT_PROJECT_VERSION)'}},
        ]
        for variant in variants:
            with self.subTest(variant=variant), tempfile.TemporaryDirectory() as directory:
                with self.assertRaises(module.VerificationError):
                    module.verify(self.fixture(directory, **variant))

    def test_malformed_command_size(self):
        data = bytearray(macho())
        struct.pack_into('<I', data, 36, 0)
        with self.assertRaises(module.VerificationError):
            module.inspect_macho(data)


if __name__ == '__main__':
    unittest.main()
