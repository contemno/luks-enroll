#!/usr/bin/env python3
"""Test suite for the LUKS Enroll Wizard.

Tests pure logic, data parsing, D-Bus interface invariants, and helper functions
without requiring root, hardware tokens, or real LUKS devices.

Run: python3 -m pytest test_luks_enroll.py -v
"""

import ast
import base64
import configparser
import importlib
import os
import re
import struct
import sys
import tempfile
import unittest
from unittest import mock
from xml.etree import ElementTree


# ---------------------------------------------------------------------------
# Import helpers — mock heavy system deps so modules can be imported
# ---------------------------------------------------------------------------


def _import_service():
    """Import luks-enroll-service.py as a module, mocking native libs."""
    mod_name = "luks_enroll_service"
    spec = importlib.util.spec_from_file_location(
        mod_name,
        os.path.join(os.path.dirname(__file__), "..", "src", "luks-enroll-service.py"),
    )
    fake_gi = mock.MagicMock()
    mod = importlib.util.module_from_spec(spec)
    with mock.patch.dict(
        sys.modules,
        {
            "gi": fake_gi,
            "gi.repository": fake_gi.repository,
            mod_name: mod,
        },
    ):
        spec.loader.exec_module(mod)
    return mod


def _import_gui():
    """Import luks-enroll.py as a module, mocking GTK/Adw."""
    mod_name = "luks_enroll"
    spec = importlib.util.spec_from_file_location(
        mod_name,
        os.path.join(os.path.dirname(__file__), "..", "src", "luks-enroll.py"),
    )
    fake_gi = mock.MagicMock()
    mod = importlib.util.module_from_spec(spec)
    # Register the module before exec so dataclass can resolve __module__
    with mock.patch.dict(
        sys.modules,
        {
            "gi": fake_gi,
            "gi.repository": fake_gi.repository,
            mod_name: mod,
        },
    ):
        spec.loader.exec_module(mod)
    return mod


# Import both modules once at module scope
svc = _import_service()
gui = _import_gui()


# ===========================================================================
# Syntax checks
# ===========================================================================


class TestSyntax(unittest.TestCase):
    """Verify both files parse without syntax errors."""

    def test_service_syntax(self):
        path = os.path.join(
            os.path.dirname(__file__), "..", "src", "luks-enroll-service.py"
        )
        with open(path) as f:
            ast.parse(f.read(), filename=path)

    def test_gui_syntax(self):
        path = os.path.join(os.path.dirname(__file__), "..", "src", "luks-enroll.py")
        with open(path) as f:
            ast.parse(f.read(), filename=path)


# ===========================================================================
# D-Bus interface invariants
# ===========================================================================


class TestDBusInvariant(unittest.TestCase):
    """D-Bus introspection XML <-> _handle_* methods must match 1:1."""

    def setUp(self):
        self.xml_methods = set()
        root = ElementTree.fromstring(svc.INTROSPECTION_XML)
        for method in root.iter("method"):
            self.xml_methods.add(method.attrib["name"])

        self.handler_methods = set()
        for name in dir(svc.LuksEnrollService):
            if name.startswith("_handle_"):
                self.handler_methods.add(name[len("_handle_") :])

    def test_every_xml_method_has_handler(self):
        missing = self.xml_methods - self.handler_methods
        self.assertEqual(missing, set(), f"XML methods without handlers: {missing}")

    def test_every_handler_has_xml_method(self):
        extra = self.handler_methods - self.xml_methods
        self.assertEqual(extra, set(), f"Handlers without XML methods: {extra}")

    def test_xml_parses_cleanly(self):
        """The introspection XML must be valid XML."""
        ElementTree.fromstring(svc.INTROSPECTION_XML)


class TestProxyServiceConsistency(unittest.TestCase):
    """Verify proxy method names correspond to D-Bus interface methods."""

    def test_proxy_calls_match_xml_methods(self):
        """Every proxy.call/call_sync method name string must exist in the XML."""
        xml_methods = set()
        root = ElementTree.fromstring(svc.INTROSPECTION_XML)
        for method in root.iter("method"):
            xml_methods.add(method.attrib["name"])

        # Parse GUI source: .call_sync("MethodName" and .call("MethodName"
        gui_path = os.path.join(
            os.path.dirname(__file__), "..", "src", "luks-enroll.py"
        )
        with open(gui_path) as f:
            source = f.read()

        # Find all D-Bus method name strings used in proxy calls
        called_methods = set(re.findall(r'\.(?:call_sync|call)\(\s*"(\w+)"', source))

        missing = called_methods - xml_methods
        self.assertEqual(missing, set(), f"Proxy calls methods not in XML: {missing}")


# ===========================================================================
# Recovery key generation
# ===========================================================================


class TestRecoveryKey(unittest.TestCase):
    """Test modhex recovery key generation."""

    def test_format_8_groups_of_8(self):
        key = svc._make_recovery_key()
        groups = key.split("-")
        self.assertEqual(len(groups), 8, f"Expected 8 groups, got {len(groups)}")
        for g in groups:
            self.assertEqual(len(g), 8, f"Group '{g}' is not 8 chars")

    def test_modhex_chars_only(self):
        key = svc._make_recovery_key()
        allowed = set(svc._MODHEX)
        allowed.add("-")
        for ch in key:
            self.assertIn(ch, allowed, f"Invalid modhex char: '{ch}'")

    def test_unique_keys(self):
        keys = {svc._make_recovery_key() for _ in range(50)}
        self.assertGreater(len(keys), 45, "Recovery keys should be unique")

    def test_total_length(self):
        key = svc._make_recovery_key()
        # 64 modhex chars + 7 dashes = 71
        self.assertEqual(len(key), 71)


# ===========================================================================
# _format_size helper
# ===========================================================================


class TestFormatSize(unittest.TestCase):
    def test_bytes(self):
        self.assertEqual(svc._format_size(500), "500 B")

    def test_kilobytes(self):
        self.assertEqual(svc._format_size(1_500), "1.5 KB")

    def test_megabytes(self):
        self.assertEqual(svc._format_size(256_000_000), "256.0 MB")

    def test_gigabytes(self):
        self.assertEqual(svc._format_size(32_000_000_000), "32.0 GB")

    def test_terabytes(self):
        self.assertEqual(svc._format_size(2_000_000_000_000), "2.0 TB")

    def test_zero(self):
        self.assertEqual(svc._format_size(0), "0 B")


# ===========================================================================
# _get_parent_device helper
# ===========================================================================


class TestGetParentDevice(unittest.TestCase):
    def test_sd_partition(self):
        self.assertEqual(svc._get_parent_device("/dev/sdb1"), "sdb")

    def test_sd_whole(self):
        self.assertEqual(svc._get_parent_device("/dev/sdb"), "sdb")

    def test_nvme_partition(self):
        self.assertEqual(svc._get_parent_device("/dev/nvme0n1p2"), "nvme0n1")

    def test_nvme_whole(self):
        self.assertEqual(svc._get_parent_device("/dev/nvme0n1"), "nvme0n1")

    def test_vd_partition(self):
        self.assertEqual(svc._get_parent_device("/dev/vda3"), "vda")


# ===========================================================================
# TPM2 PCR selection building
# ===========================================================================


class TestTpm2PcrSelection(unittest.TestCase):
    def test_single_pcr_7(self):
        result = svc._tpm2_build_pcr_selection("7")
        # count=1 (u32 BE), hash=SHA256=0x000B (u16 BE), sizeofSelect=3 (u8), pcrSelect
        count, hash_alg, size_sel = struct.unpack_from(">IHB", result, 0)
        self.assertEqual(count, 1)
        self.assertEqual(hash_alg, svc.TPM2_ALG_SHA256)
        self.assertEqual(size_sel, 3)
        # PCR 7 -> byte 0, bit 7
        pcr_bytes = result[7:10]
        self.assertEqual(pcr_bytes[0], 1 << 7)

    def test_multiple_pcrs(self):
        result = svc._tpm2_build_pcr_selection("7+11")
        pcr_bytes = result[7:10]
        # PCR 7 -> byte 0 bit 7, PCR 11 -> byte 1 bit 3
        self.assertTrue(pcr_bytes[0] & (1 << 7))
        self.assertTrue(pcr_bytes[1] & (1 << 3))

    def test_empty_string(self):
        with self.assertRaises(ValueError):
            svc._tpm2_build_pcr_selection("")


# ===========================================================================
# TPM2 structure building helpers
# ===========================================================================


class TestTpm2Structures(unittest.TestCase):
    def test_ecc_srk_template_is_tpm2b_public(self):
        template = svc._tpm2_build_ecc_srk_template()
        # First 2 bytes are uint16 size (big-endian) of the public area
        size = struct.unpack(">H", template[:2])[0]
        self.assertEqual(len(template), size + 2)

    def test_seal_template_without_pin(self):
        policy = b"\x00" * 32
        template = svc._tpm2_build_seal_template(policy, use_pin=False)
        size = struct.unpack(">H", template[:2])[0]
        self.assertEqual(len(template), size + 2)

    def test_seal_template_with_pin(self):
        policy = b"\x00" * 32
        template = svc._tpm2_build_seal_template(policy, use_pin=True)
        size = struct.unpack(">H", template[:2])[0]
        self.assertEqual(len(template), size + 2)
        # Verify USERWITHAUTH flag is set in objectAttributes
        # objectAttributes starts at offset 2 (tpm2b size) + 2 (type) + 2 (nameAlg) = 6
        obj_attrs = struct.unpack_from(">I", template, 6)[0]
        self.assertTrue(obj_attrs & svc.TPMA_OBJECT_USERWITHAUTH)

    def test_seal_template_without_pin_no_userwithauth(self):
        policy = b"\x00" * 32
        template = svc._tpm2_build_seal_template(policy, use_pin=False)
        obj_attrs = struct.unpack_from(">I", template, 6)[0]
        self.assertFalse(obj_attrs & svc.TPMA_OBJECT_USERWITHAUTH)

    def test_sensitive_create_no_pin(self):
        secret = os.urandom(32)
        result = svc._tpm2_build_sensitive_create(secret, pin="")
        outer_size = struct.unpack(">H", result[:2])[0]
        self.assertEqual(len(result), outer_size + 2)

    def test_sensitive_create_with_pin(self):
        secret = os.urandom(32)
        result = svc._tpm2_build_sensitive_create(secret, pin="1234")
        outer_size = struct.unpack(">H", result[:2])[0]
        self.assertEqual(len(result), outer_size + 2)
        # With PIN, inner auth is SHA256 of pin = 32 bytes
        # offset 2 = inner start, auth_size at inner[0:2]
        auth_size = struct.unpack(">H", result[2:4])[0]
        self.assertEqual(auth_size, 32)  # SHA256 digest length

    def test_empty_sensitive_create(self):
        result = svc._tpm2_build_empty_sensitive_create()
        outer_size = struct.unpack(">H", result[:2])[0]
        self.assertEqual(len(result), outer_size + 2)

    def test_empty_data(self):
        result = svc._tpm2_build_empty_data()
        size = struct.unpack(">H", result[:2])[0]
        self.assertEqual(size, 0)

    def test_empty_pcr_selection(self):
        result = svc._tpm2_build_empty_pcr_selection()
        count = struct.unpack(">I", result[:4])[0]
        self.assertEqual(count, 0)

    def test_empty_digest(self):
        result = svc._tpm2_build_empty_digest()
        size = struct.unpack(">H", result[:2])[0]
        self.assertEqual(size, 0)

    def test_sym_def_null(self):
        result = svc._tpm2_build_sym_def_null()
        alg = struct.unpack(">H", result[:2])[0]
        self.assertEqual(alg, svc.TPM2_ALG_NULL)


# ===========================================================================
# LUKS metadata parsing (with mocked _get_luks_json)
# ===========================================================================

SAMPLE_LUKS_JSON = {
    "keyslots": {
        "0": {"type": "luks2", "key_size": 64},
        "1": {"type": "luks2", "key_size": 64},
        "2": {"type": "luks2", "key_size": 64},
    },
    "tokens": {
        "0": {
            "type": "systemd-tpm2",
            "keyslots": ["1"],
            "tpm2-pcrs": [7],
        },
        "1": {
            "type": "systemd-fido2",
            "keyslots": ["2"],
            "fido2-credential": base64.b64encode(b"cred").decode(),
            "fido2-salt": base64.b64encode(b"salt").decode(),
            "fido2-rp": "io.systemd.cryptsetup",
        },
    },
}


class TestListLuksKeyslots(unittest.TestCase):
    @mock.patch.object(svc, "_get_luks_json", return_value=SAMPLE_LUKS_JSON)
    def test_returns_all_slots(self, _mock):
        result = svc.list_luks_keyslots("/dev/fake")
        self.assertEqual(result, {0: "luks2", 1: "luks2", 2: "luks2"})

    @mock.patch.object(svc, "_get_luks_json", return_value=None)
    def test_returns_empty_on_failure(self, _mock):
        result = svc.list_luks_keyslots("/dev/fake")
        self.assertEqual(result, {})


class TestFindTokensByType(unittest.TestCase):
    @mock.patch.object(svc, "_get_luks_json", return_value=SAMPLE_LUKS_JSON)
    def test_find_tpm2_tokens(self, _mock):
        result = svc.find_tokens_by_type("/dev/fake", "systemd-tpm2")
        self.assertEqual(len(result), 1)
        tid, slots = result[0]
        self.assertEqual(tid, 0)
        self.assertEqual(slots, [1])

    @mock.patch.object(svc, "_get_luks_json", return_value=SAMPLE_LUKS_JSON)
    def test_find_fido2_tokens(self, _mock):
        result = svc.find_tokens_by_type("/dev/fake", "systemd-fido2")
        self.assertEqual(len(result), 1)
        tid, slots = result[0]
        self.assertEqual(tid, 1)
        self.assertEqual(slots, [2])

    @mock.patch.object(svc, "_get_luks_json", return_value=SAMPLE_LUKS_JSON)
    def test_find_nonexistent_type(self, _mock):
        result = svc.find_tokens_by_type("/dev/fake", "systemd-recovery")
        self.assertEqual(result, [])

    @mock.patch.object(svc, "_get_luks_json", return_value=None)
    def test_returns_empty_on_failure(self, _mock):
        result = svc.find_tokens_by_type("/dev/fake", "systemd-tpm2")
        self.assertEqual(result, [])


class TestFindPasswordKeyslots(unittest.TestCase):
    @mock.patch.object(svc, "_get_luks_json", return_value=SAMPLE_LUKS_JSON)
    def test_finds_unmanaged_slots(self, _mock):
        """Slot 0 is not referenced by any token, so it's a password slot."""
        result = svc.find_password_keyslots("/dev/fake")
        self.assertEqual(result, [0])

    @mock.patch.object(
        svc,
        "_get_luks_json",
        return_value={
            "keyslots": {"0": {"type": "luks2"}, "1": {"type": "luks2"}},
            "tokens": {},
        },
    )
    def test_all_slots_are_password_when_no_tokens(self, _mock):
        result = svc.find_password_keyslots("/dev/fake")
        self.assertEqual(result, [0, 1])

    @mock.patch.object(svc, "_get_luks_json", return_value=None)
    def test_returns_empty_on_failure(self, _mock):
        result = svc.find_password_keyslots("/dev/fake")
        self.assertEqual(result, [])


class TestFindTokenForKeyslot(unittest.TestCase):
    @mock.patch.object(svc, "_get_luks_json", return_value=SAMPLE_LUKS_JSON)
    def test_finds_token_for_managed_slot(self, _mock):
        self.assertEqual(svc._find_token_for_keyslot("/dev/fake", 1), 0)
        self.assertEqual(svc._find_token_for_keyslot("/dev/fake", 2), 1)

    @mock.patch.object(svc, "_get_luks_json", return_value=SAMPLE_LUKS_JSON)
    def test_returns_neg1_for_unmanaged_slot(self, _mock):
        self.assertEqual(svc._find_token_for_keyslot("/dev/fake", 0), -1)

    @mock.patch.object(svc, "_get_luks_json", return_value=None)
    def test_returns_neg1_on_failure(self, _mock):
        self.assertEqual(svc._find_token_for_keyslot("/dev/fake", 0), -1)


# ===========================================================================
# Settings load/save
# ===========================================================================


class TestSettings(unittest.TestCase):
    def test_load_missing_file(self):
        with mock.patch.object(svc, "SETTINGS_FILE", "/nonexistent/path.conf"):
            result = svc._load_setting("some_key")
            self.assertEqual(result, "")

    def test_save_and_load_roundtrip(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".conf", delete=False) as f:
            tmppath = f.name

        try:
            with (
                mock.patch.object(svc, "SETTINGS_FILE", tmppath),
                mock.patch.object(svc, "SETTINGS_ALLOWED_KEYS", {"test_key"}),
            ):
                self.assertTrue(svc._save_setting("test_key", "test_value"))
                result = svc._load_setting("test_key")
                self.assertEqual(result, "test_value")
        finally:
            os.unlink(tmppath)

    def test_save_creates_section(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".conf", delete=False) as f:
            tmppath = f.name

        try:
            with (
                mock.patch.object(svc, "SETTINGS_FILE", tmppath),
                mock.patch.object(svc, "SETTINGS_ALLOWED_KEYS", {"mykey"}),
            ):
                svc._save_setting("mykey", "myval")
                cp = configparser.ConfigParser()
                cp.read(tmppath)
                self.assertTrue(cp.has_section("defaults"))
                self.assertEqual(cp.get("defaults", "mykey"), "myval")
        finally:
            os.unlink(tmppath)

    def test_save_rejects_unknown_key(self):
        self.assertFalse(svc._save_setting("unknown_key", "value"))

    def test_load_rejects_unknown_key(self):
        self.assertEqual(svc._load_setting("unknown_key"), "")


# ===========================================================================
# detect_luks_devices (mocked filesystem)
# ===========================================================================


class TestDetectLuksDevices(unittest.TestCase):
    @mock.patch.object(svc, "_blkid_find_luks_devices", return_value=[])
    @mock.patch("builtins.open", side_effect=FileNotFoundError)
    def test_no_crypttab_no_blkid(self, _open, _blkid):
        result = svc.detect_luks_devices()
        self.assertEqual(result, [])

    @mock.patch.object(svc, "_blkid_find_luks_devices", return_value=["/dev/sda3"])
    @mock.patch("builtins.open", side_effect=FileNotFoundError)
    @mock.patch("os.path.realpath", side_effect=lambda x: x)
    def test_blkid_only(self, _real, _open, _blkid):
        result = svc.detect_luks_devices()
        self.assertEqual(result, ["/dev/sda3"])

    @mock.patch.object(svc, "_blkid_find_luks_devices", return_value=["/dev/sda3"])
    @mock.patch("os.path.realpath", side_effect=lambda x: x)
    @mock.patch("os.path.exists", return_value=True)
    def test_crypttab_uuid_entry(self, _exists, _real, _blkid):
        crypttab = "rootfs UUID=abc-123 none luks\n"
        m = mock.mock_open(read_data=crypttab)
        with mock.patch("builtins.open", m):
            result = svc.detect_luks_devices()
        # Should have the UUID-resolved device + blkid device (deduped)
        self.assertIn("/dev/disk/by-uuid/abc-123", result)

    @mock.patch.object(
        svc, "_blkid_find_luks_devices", return_value=["/dev/sda3", "/dev/sda3"]
    )
    @mock.patch("builtins.open", side_effect=FileNotFoundError)
    @mock.patch("os.path.realpath", side_effect=lambda x: x)
    def test_deduplication(self, _real, _open, _blkid):
        result = svc.detect_luks_devices()
        self.assertEqual(len(result), 1)


# ===========================================================================
# GUI-side hardware detection helpers
# ===========================================================================


class TestDetectFido2Devices(unittest.TestCase):
    def _make_uevent(self, hid_name, hid_phys="usb-0000:00:14.0-1/input0"):
        return f"HID_NAME={hid_name}\nHID_PHYS={hid_phys}\n"

    @mock.patch("glob.glob", return_value=[])
    def test_no_hidraw_devices(self, _glob):
        result = gui.detect_fido2_devices()
        self.assertEqual(result, [])

    @mock.patch("glob.glob", return_value=["/sys/class/hidraw/hidraw0"])
    @mock.patch("os.path.basename", return_value="hidraw0")
    def test_yubikey_detected(self, _base, _glob):
        uevent = self._make_uevent("Yubico YubiKey FIDO")
        with mock.patch("builtins.open", mock.mock_open(read_data=uevent)):
            result = gui.detect_fido2_devices()
        self.assertEqual(len(result), 1)
        self.assertIn("Yubico YubiKey FIDO", result[0][1])

    @mock.patch("glob.glob", return_value=["/sys/class/hidraw/hidraw0"])
    @mock.patch("os.path.basename", return_value="hidraw0")
    def test_non_fido_device_ignored(self, _base, _glob):
        uevent = self._make_uevent("Logitech Mouse")
        with mock.patch("builtins.open", mock.mock_open(read_data=uevent)):
            result = gui.detect_fido2_devices()
        self.assertEqual(result, [])


class TestDetectTpm2Device(unittest.TestCase):
    @mock.patch("os.path.isdir", return_value=False)
    def test_no_tpm_sysfs(self, _isdir):
        result = gui.detect_tpm2_device()
        self.assertIsNone(result)

    @mock.patch("os.path.isdir", return_value=True)
    @mock.patch("os.path.isfile", side_effect=lambda p: "tpm_version_major" in p)
    def test_tpm2_detected(self, _isfile, _isdir):
        with mock.patch("builtins.open", mock.mock_open(read_data="2\n")):
            result = gui.detect_tpm2_device()
        self.assertIsNotNone(result)
        self.assertIn("TPM 2.0", result)

    @mock.patch("os.path.isdir", return_value=True)
    @mock.patch("os.path.isfile", side_effect=lambda p: "tpm_version_major" in p)
    def test_tpm1_ignored(self, _isfile, _isdir):
        with mock.patch("builtins.open", mock.mock_open(read_data="1\n")):
            result = gui.detect_tpm2_device()
        self.assertIsNone(result)


# ===========================================================================
# DeviceContext dataclass
# ===========================================================================


class TestDeviceContext(unittest.TestCase):
    def test_default_values(self):
        ctx = gui.DeviceContext()
        self.assertIsNone(ctx.svc)
        self.assertIsNone(ctx.device)
        self.assertIsNone(ctx.passphrase)
        self.assertIsNone(ctx.auth_keyslot)

    def test_field_assignment(self):
        ctx = gui.DeviceContext()
        ctx.device = "/dev/sda3"
        ctx.passphrase = "test"
        ctx.auth_keyslot = 0
        self.assertEqual(ctx.device, "/dev/sda3")
        self.assertEqual(ctx.passphrase, "test")
        self.assertEqual(ctx.auth_keyslot, 0)


# ===========================================================================
# _is_removable and _is_partition (mocked sysfs)
# ===========================================================================


class TestIsRemovable(unittest.TestCase):
    @mock.patch.object(svc, "_read_sysfs", return_value="1")
    def test_removable_device(self, _read):
        self.assertTrue(svc._is_removable("/dev/sdb"))

    @mock.patch.object(svc, "_read_sysfs", return_value="0")
    def test_non_removable_device(self, _read):
        self.assertFalse(svc._is_removable("/dev/sda"))

    @mock.patch.object(svc, "_read_sysfs", return_value="1")
    def test_removable_partition(self, _read):
        """Partition removability is determined by parent device."""
        self.assertTrue(svc._is_removable("/dev/sdb1"))
        _read.assert_called_with("/sys/block/sdb/removable")


class TestIsPartition(unittest.TestCase):
    @mock.patch("os.path.exists", return_value=True)
    def test_partition(self, _exists):
        self.assertTrue(svc._is_partition("/dev/sdb1"))
        _exists.assert_called_with("/sys/class/block/sdb1/partition")

    @mock.patch("os.path.exists", return_value=False)
    def test_whole_disk(self, _exists):
        self.assertFalse(svc._is_partition("/dev/sdb"))


# ===========================================================================
# _derive_passphrase_from_token (token type dispatch)
# ===========================================================================


class TestDerivePassphraseFromToken(unittest.TestCase):
    @mock.patch.object(svc, "_fido2_unlock_from_token", return_value=b"raw_secret")
    def test_fido2_base64_encodes(self, _fido2):
        result = svc._derive_passphrase_from_token("/dev/fake", "systemd-fido2", "1234")
        self.assertEqual(result, base64.b64encode(b"raw_secret"))
        _fido2.assert_called_once_with("/dev/fake", "1234")

    @mock.patch.object(svc, "_tpm2_unseal_from_token", return_value=b"tpm_secret")
    def test_tpm2_base64_encodes(self, _tpm2):
        result = svc._derive_passphrase_from_token("/dev/fake", "systemd-tpm2", "")
        self.assertEqual(result, base64.b64encode(b"tpm_secret"))

    def test_unknown_type_raises(self):
        with self.assertRaises(RuntimeError):
            svc._derive_passphrase_from_token("/dev/fake", "unknown-type")


# ===========================================================================
# Modhex encoding
# ===========================================================================


class TestModhex(unittest.TestCase):
    def test_modhex_alphabet_length(self):
        self.assertEqual(len(svc._MODHEX), 16)

    def test_modhex_all_unique(self):
        self.assertEqual(len(set(svc._MODHEX)), 16)

    def test_modhex_chars_are_lowercase_alpha(self):
        for ch in svc._MODHEX:
            self.assertTrue(
                ch.isalpha() and ch.islower(),
                f"Modhex char '{ch}' is not lowercase alpha",
            )


# ===========================================================================
# Constants and invariants
# ===========================================================================


class TestConstants(unittest.TestCase):
    def test_bus_name(self):
        self.assertEqual(svc.BUS_NAME, "com.contemno.LuksEnroll")

    def test_object_path(self):
        self.assertEqual(svc.OBJECT_PATH, "/com/contemno/LuksEnroll")

    def test_interface_name(self):
        self.assertEqual(svc.INTERFACE_NAME, "com.contemno.LuksEnroll1")

    def test_polkit_actions(self):
        self.assertEqual(svc.POLKIT_ACTION_READ, "com.contemno.luks-enroll.read")
        self.assertEqual(svc.POLKIT_ACTION_MANAGE, "com.contemno.luks-enroll.manage")

    def test_idle_timeout(self):
        self.assertEqual(svc.IDLE_TIMEOUT, 300)

    def test_fido2_rp_id(self):
        self.assertEqual(svc._FIDO2_RP_ID, "io.systemd.cryptsetup")

    def test_luks_partition_type_guid(self):
        # Standard LUKS partition type GUID (sgdisk 8309)
        self.assertEqual(
            svc._LUKS_PARTITION_TYPE_GUID,
            "CA7D7CCB-63ED-4C53-861C-1742536059CC",
        )


# ===========================================================================
# Handler method signature checks
# ===========================================================================


class TestHandlerSignatures(unittest.TestCase):
    """Verify all _handle_* methods take (self, parameters, invocation)."""

    def test_handler_signatures(self):
        import inspect

        for name in dir(svc.LuksEnrollService):
            if not name.startswith("_handle_"):
                continue
            method = getattr(svc.LuksEnrollService, name)
            sig = inspect.signature(method)
            params = list(sig.parameters.keys())
            self.assertEqual(
                params,
                ["self", "parameters", "invocation"],
                f"{name} has unexpected signature: {params}",
            )


# ===========================================================================
# Privileged / blocking method sets
# ===========================================================================


class TestMethodSets(unittest.TestCase):
    """Verify the privileged and blocking method sets in handle_method_call
    are consistent with handlers that exist."""

    def _get_method_sets(self):
        """Extract method sets from handle_method_call source."""
        import inspect

        source = inspect.getsource(svc.LuksEnrollService.handle_method_call)

        sets = {}
        for match in re.finditer(r"(\w+_methods)\s*=\s*\{([^}]+)\}", source):
            name = match.group(1)
            methods = set(re.findall(r'"(\w+)"', match.group(2)))
            sets[name] = methods
        return sets

    def test_privileged_methods_have_handlers(self):
        sets = self._get_method_sets()
        # privileged_methods = read_methods | write_methods
        if "read_methods" not in sets or "write_methods" not in sets:
            self.skipTest("Could not extract read_methods/write_methods sets")
        privileged = sets["read_methods"] | sets["write_methods"]
        xml_methods = set()
        root = ElementTree.fromstring(svc.INTROSPECTION_XML)
        for method in root.iter("method"):
            xml_methods.add(method.attrib["name"])
        for m in privileged:
            self.assertIn(
                m, xml_methods, f"Privileged method '{m}' not in XML interface"
            )

    def test_blocking_methods_have_handlers(self):
        sets = self._get_method_sets()
        if "blocking_methods" not in sets:
            self.skipTest("Could not extract blocking_methods set")
        for m in sets["blocking_methods"]:
            handler = f"_handle_{m}"
            self.assertTrue(
                hasattr(svc.LuksEnrollService, handler),
                f"Blocking method '{m}' has no handler",
            )


# ===========================================================================
# Volume key cache
# ===========================================================================


class TestVolumeKeyCache(unittest.TestCase):
    def test_cache_is_dict(self):
        self.assertIsInstance(svc._volume_key_cache, dict)


# ===========================================================================
# _CryptPbkdfType structure
# ===========================================================================


class TestCryptPbkdfType(unittest.TestCase):
    def test_structure_fields(self):
        pbkdf = svc._CryptPbkdfType(
            type=b"pbkdf2",
            hash=b"sha512",
            time_ms=1,
            iterations=1000,
            max_memory_kb=0,
            parallel_threads=0,
            flags=0,
        )
        self.assertEqual(pbkdf.type, b"pbkdf2")
        self.assertEqual(pbkdf.hash, b"sha512")
        self.assertEqual(pbkdf.iterations, 1000)


# ===========================================================================
# Proxy class method existence
# ===========================================================================


class TestProxyMethods(unittest.TestCase):
    """Verify LuksEnrollProxy has methods for all D-Bus operations."""

    def test_proxy_has_all_dbus_methods(self):
        """Each D-Bus method in the XML should have a corresponding proxy method
        (either exact snake_case or a known alias)."""
        xml_methods = set()
        root = ElementTree.fromstring(svc.INTROSPECTION_XML)
        for method in root.iter("method"):
            xml_methods.add(method.attrib["name"])

        # Build the set of D-Bus method names that the proxy calls
        gui_path = os.path.join(
            os.path.dirname(__file__), "..", "src", "luks-enroll.py"
        )
        with open(gui_path) as f:
            source = f.read()

        called = set(re.findall(r'\.(?:call_sync|call)\(\s*"(\w+)"', source))

        # Every XML method should either be called directly by the proxy
        # or be an internal-only method (like Authenticate, GetSystemdVersion)
        # At minimum, the core methods must be present
        core_methods = {
            "DetectDevices",
            "GetKeyslots",
            "GetTokensByType",
            "FindPasswordKeyslots",
            "VerifyPassphrase",
            "EnrollFido2",
            "EnrollTpm2",
            "EnrollRecoveryKey",
            "WipeSlot",
        }
        for m in core_methods:
            self.assertIn(m, called, f"Core D-Bus method '{m}' not called by proxy")


if __name__ == "__main__":
    unittest.main()
