#!/usr/bin/env python3
"""Integration workflow tests for LUKS Enroll Wizard.

Simulates the GUI talking to the service without D-Bus, hardware, or root.
A FakeLuksDevice provides in-memory LUKS2 state.  Service handlers operate
on it through mocked crypto/system functions, while the handler orchestration
logic (token JSON construction, keyslot bookkeeping, etc.) runs for real.

Run: python3 -m pytest test_workflows.py -v
"""

import base64
import importlib.util
import json
import os
import re
import sys
import tempfile
import time
import unittest
from unittest import mock


# ---------------------------------------------------------------------------
# Module import — same approach as test_luks_enroll.py
# ---------------------------------------------------------------------------

def _import_service():
    mod_name = "luks_enroll_service"
    spec = importlib.util.spec_from_file_location(
        mod_name,
        os.path.join(os.path.dirname(__file__), "..", "src", "luks-enroll-service.py"),
    )
    fake_gi = mock.MagicMock()
    mod = importlib.util.module_from_spec(spec)
    with mock.patch.dict(sys.modules, {
        "gi": fake_gi,
        "gi.repository": fake_gi.repository,
        mod_name: mod,
    }):
        spec.loader.exec_module(mod)
    return mod


svc = _import_service()


# ---------------------------------------------------------------------------
# Lightweight GLib.Variant replacement
# ---------------------------------------------------------------------------

class SimpleVariant:
    """Drop-in for GLib.Variant that just stores the data tuple."""

    def __init__(self, type_str, data):
        self.type_str = type_str
        self.data = data

    def unpack(self):
        return self.data


# ---------------------------------------------------------------------------
# In-memory LUKS2 device
# ---------------------------------------------------------------------------

class FakeLuksDevice:
    """Simulates LUKS2 header state in memory: keyslots, tokens, volume key."""

    def __init__(self, passphrase="test"):
        self.volume_key = os.urandom(64)
        self.vk_size = 64
        self.keyslots = {}          # int slot -> bytes passphrase
        self.tokens = {}            # int tid  -> dict (parsed token JSON)
        self._next_slot = 0
        self._next_token = 0
        if passphrase is not None:
            pw = passphrase.encode() if isinstance(passphrase, str) else passphrase
            self._add_slot(pw)

    def _add_slot(self, passphrase_bytes):
        slot = self._next_slot
        self._next_slot += 1
        self.keyslots[slot] = passphrase_bytes
        return slot

    def _add_token(self, token_dict):
        tid = self._next_token
        self._next_token += 1
        self.tokens[tid] = token_dict
        return tid

    def get_json(self):
        """Return LUKS2 JSON metadata matching _get_luks_json() format."""
        return {
            "keyslots": {
                str(s): {"type": "luks2", "key_size": 64}
                for s in self.keyslots
            },
            "tokens": {
                str(t): tinfo
                for t, tinfo in self.tokens.items()
            },
        }


# ---------------------------------------------------------------------------
# Service test harness
# ---------------------------------------------------------------------------

class ServiceHarness:
    """Patches the service module so handlers operate on FakeLuksDevices.

    Usage::

        with ServiceHarness() as h:
            h.create_device("/dev/sda3", passphrase="secret")
            result = h.call("VerifyPassphrase", ("/dev/sda3", "secret"))
            assert result == (True, 0)
    """

    def __init__(self):
        self.devices = {}       # path -> FakeLuksDevice
        self.service = None
        self._patches = []
        self._settings_file = None

    # -- public API --

    def create_device(self, path="/dev/fake0", passphrase="test"):
        dev = FakeLuksDevice(passphrase)
        self.devices[path] = dev
        return dev

    def call(self, method_name, args=None):
        """Call a _handle_* method directly.  Returns the unpacked result tuple."""
        params = mock.MagicMock()
        params.unpack.return_value = args if args is not None else ()

        inv = mock.MagicMock()
        captured = {}

        def capture_return(variant):
            captured["result"] = variant.data

        def capture_error(name, msg):
            captured["error"] = (name, msg)

        inv.return_value = capture_return
        inv.return_dbus_error = capture_error
        inv.get_message.return_value.get_sender.return_value = ":1.42"
        inv.get_connection.return_value = mock.MagicMock()

        handler = getattr(self.service, f"_handle_{method_name}")
        handler(params, inv)

        if "error" in captured:
            raise RuntimeError(captured["error"][1])
        return captured.get("result")

    # -- context manager --

    def __enter__(self):
        svc.GLib.Variant = SimpleVariant
        self.service = svc.LuksEnrollService(mock.MagicMock())
        self.service._get_caller_uid = mock.MagicMock(return_value=1000)

        # Temp file for settings tests
        self._settings_file = tempfile.NamedTemporaryFile(
            suffix=".conf", delete=False
        )
        self._settings_file.close()

        self._patch_all()
        return self

    def __exit__(self, *exc):
        for p in self._patches:
            p.stop()
        self._patches.clear()
        svc._volume_key_cache.clear()
        if self._settings_file:
            try:
                os.unlink(self._settings_file.name)
            except OSError:
                pass

    # -- mock wiring --

    def _patch_all(self):
        def _get_dev(path):
            if path not in self.devices:
                raise RuntimeError(f"Device not found: {path}")
            return self.devices[path]

        def mock_detect():
            return list(self.devices.keys())

        def mock_get_luks_json(device):
            return self.devices[device].get_json() if device in self.devices else None

        def mock_verify_passphrase(device, passphrase):
            dev = _get_dev(device)
            pw = passphrase.encode() if isinstance(passphrase, str) else passphrase
            for slot, stored in dev.keyslots.items():
                if stored == pw:
                    return True, slot
            return False, "Incorrect passphrase or recovery key"

        def mock_verify_token(device, token_type, pin=""):
            dev = _get_dev(device)
            for _tid, tinfo in dev.tokens.items():
                if tinfo.get("type") == token_type:
                    slots = [int(s) for s in tinfo.get("keyslots", [])]
                    if slots and slots[0] in dev.keyslots:
                        real_dev = os.path.realpath(device)
                        svc._volume_key_cache[real_dev] = (
                            dev.volume_key, dev.vk_size, time.monotonic()
                        )
                        return True, slots[0]
            return False, "Token unlock failed"

        def mock_get_volume_key(device, unlock_method, passphrase, unlock_pin=""):
            dev = _get_dev(device)
            if unlock_method in ("systemd-fido2", "systemd-tpm2"):
                real_dev = os.path.realpath(device)
                cached = svc._volume_key_cache.get(real_dev)
                if cached:
                    vk, vk_size = cached[0], cached[1]
                    return vk, vk_size
            pw = passphrase.encode() if isinstance(passphrase, str) else passphrase
            for _slot, stored in dev.keyslots.items():
                if stored == pw:
                    return dev.volume_key, dev.vk_size
            raise RuntimeError("Failed to get volume key")

        def mock_add_keyslot(device, vk, vk_size, new_pw, minimal_pbkdf=False):
            dev = _get_dev(device)
            pw = new_pw if isinstance(new_pw, bytes) else new_pw.encode()
            return dev._add_slot(pw)

        def mock_set_token(device, token_id, token_json):
            dev = _get_dev(device)
            if token_json is None:
                if token_id in dev.tokens:
                    del dev.tokens[token_id]
                return token_id
            parsed = json.loads(token_json) if isinstance(token_json, str) else token_json
            if token_id < 0:
                return dev._add_token(parsed)
            dev.tokens[token_id] = parsed
            return token_id

        def mock_destroy_keyslot(device, slot):
            dev = _get_dev(device)
            if slot in dev.keyslots:
                del dev.keyslots[slot]

        def mock_fido2_enroll(fido2_device, pin):
            return os.urandom(32), os.urandom(32), os.urandom(32)

        def mock_tpm2_seal(secret, pcrs, pin=""):
            return os.urandom(64), os.urandom(32), "ecc", os.urandom(64)

        def mock_format_image(path, size_mb=256, passphrase="test"):
            dev = FakeLuksDevice(passphrase)
            self.devices[path] = dev
            return 0

        def mock_detect_removable():
            return [
                {"device": "/dev/sdb", "size": "16.0 GB", "label": "USB",
                 "partitions": []},
            ]

        def mock_get_device_info(device):
            return {"device": device, "size": "16.0 GB", "label": "",
                    "removable": True, "mount_point": "", "filesystem": ""}

        def mock_format_partition(device, passphrase):
            part = f"{device}1"
            dev = FakeLuksDevice(passphrase)
            self.devices[part] = dev
            return True, part, ""

        patch_map = {
            "detect_luks_devices": mock_detect,
            "_get_luks_json": mock_get_luks_json,
            "verify_luks_passphrase": mock_verify_passphrase,
            "verify_luks_token": mock_verify_token,
            "_get_volume_key": mock_get_volume_key,
            "_add_keyslot_by_volume_key": mock_add_keyslot,
            "_set_luks_token": mock_set_token,
            "_destroy_keyslot": mock_destroy_keyslot,
            "_fido2_enroll": mock_fido2_enroll,
            "_tpm2_seal": mock_tpm2_seal,
            "format_luks_image": mock_format_image,
            "detect_removable_devices": mock_detect_removable,
            "get_device_info": mock_get_device_info,
            "_format_removable_partition": mock_format_partition,
            "SETTINGS_FILE": self._settings_file.name,
            "SETTINGS_ALLOWED_KEYS": {"my_key", "key", "mykey", "nonexistent_key"},
        }

        for name, replacement in patch_map.items():
            if callable(replacement):
                p = mock.patch.object(svc, name, side_effect=replacement)
            else:
                p = mock.patch.object(svc, name, replacement)
            self._patches.append(p)
            p.start()

        # os.chown is called in CreateEncryptedImage — no-op it
        p = mock.patch("os.chown")
        self._patches.append(p)
        p.start()

        # pwd.getpwuid is called for GID lookup
        pw_entry = mock.MagicMock()
        pw_entry.pw_gid = 1000
        p = mock.patch.object(svc.pwd, "getpwuid", return_value=pw_entry)
        self._patches.append(p)
        p.start()


# ===========================================================================
# Workflow tests
# ===========================================================================


class TestDeviceDetection(unittest.TestCase):
    """Detect → list keyslots → find password slots."""

    def test_detect_returns_created_devices(self):
        with ServiceHarness() as h:
            h.create_device("/dev/sda3")
            h.create_device("/dev/nvme0n1p3")
            devices = h.call("DetectDevices")
            self.assertEqual(set(devices[0]), {"/dev/sda3", "/dev/nvme0n1p3"})

    def test_keyslots_after_creation(self):
        with ServiceHarness() as h:
            h.create_device("/dev/sda3", passphrase="hello")
            raw = h.call("GetKeyslots", ("/dev/sda3",))
            slots = json.loads(raw[0])
            # One keyslot (the initial passphrase)
            self.assertEqual(len(slots), 1)
            self.assertIn("0", slots)

    def test_password_keyslots_initial(self):
        with ServiceHarness() as h:
            h.create_device("/dev/sda3")
            slots = h.call("FindPasswordKeyslots", ("/dev/sda3",))
            self.assertEqual(slots[0], [0])


class TestPassphraseVerification(unittest.TestCase):

    def test_correct_passphrase(self):
        with ServiceHarness() as h:
            h.create_device("/dev/sda3", passphrase="secret")
            ok, keyslot = h.call("VerifyPassphrase", ("/dev/sda3", "secret"))
            self.assertTrue(ok)
            self.assertEqual(keyslot, 0)

    def test_wrong_passphrase(self):
        with ServiceHarness() as h:
            h.create_device("/dev/sda3", passphrase="secret")
            ok, keyslot = h.call("VerifyPassphrase", ("/dev/sda3", "wrong"))
            self.assertFalse(ok)
            self.assertEqual(keyslot, -1)

    def test_empty_passphrase_unlock(self):
        with ServiceHarness() as h:
            h.create_device("/dev/sda3", passphrase="")
            ok, keyslot = h.call("VerifyPassphrase", ("/dev/sda3", ""))
            self.assertTrue(ok)
            self.assertEqual(keyslot, 0)


class TestRecoveryKeyWorkflow(unittest.TestCase):

    def test_enroll_recovery_key(self):
        with ServiceHarness() as h:
            h.create_device("/dev/sda3", passphrase="pw")
            ok, recovery_key, err = h.call(
                "EnrollRecoveryKey",
                ("/dev/sda3", "pw", "passphrase", ""),
            )
            self.assertTrue(ok)
            self.assertEqual(err, "")
            # Verify modhex format
            groups = recovery_key.split("-")
            self.assertEqual(len(groups), 8)
            for g in groups:
                self.assertEqual(len(g), 8)

    def test_recovery_key_unlocks_device(self):
        with ServiceHarness() as h:
            h.create_device("/dev/sda3", passphrase="pw")
            ok, recovery_key, _ = h.call(
                "EnrollRecoveryKey",
                ("/dev/sda3", "pw", "passphrase", ""),
            )
            self.assertTrue(ok)
            # Verify the recovery key works as a passphrase
            ok2, slot = h.call(
                "VerifyPassphrase", ("/dev/sda3", recovery_key)
            )
            self.assertTrue(ok2)
            self.assertEqual(slot, 1)  # slot 0 is the original passphrase

    def test_recovery_token_in_metadata(self):
        with ServiceHarness() as h:
            h.create_device("/dev/sda3", passphrase="pw")
            h.call("EnrollRecoveryKey",
                   ("/dev/sda3", "pw", "passphrase", ""))
            tokens_json = h.call(
                "GetTokensByType", ("/dev/sda3", "systemd-recovery")
            )
            tokens = json.loads(tokens_json[0])
            self.assertEqual(len(tokens), 1)
            tid, slots = tokens[0]
            self.assertEqual(slots, [1])

    def test_password_slots_excludes_recovery(self):
        with ServiceHarness() as h:
            h.create_device("/dev/sda3", passphrase="pw")
            h.call("EnrollRecoveryKey",
                   ("/dev/sda3", "pw", "passphrase", ""))
            # Slot 0 is password, slot 1 is managed by recovery token
            pw_slots = h.call("FindPasswordKeyslots", ("/dev/sda3",))
            self.assertEqual(pw_slots[0], [0])


class TestTpm2Workflow(unittest.TestCase):

    def test_enroll_tpm2(self):
        with ServiceHarness() as h:
            h.create_device("/dev/sda3", passphrase="pw")
            ok, stdout, err = h.call(
                "EnrollTpm2",
                ("/dev/sda3", "pw", "", "7", "passphrase", ""),
            )
            self.assertTrue(ok, f"EnrollTpm2 failed: {err}")
            self.assertEqual(err, "")

    def test_tpm2_token_metadata(self):
        with ServiceHarness() as h:
            h.create_device("/dev/sda3", passphrase="pw")
            h.call("EnrollTpm2",
                   ("/dev/sda3", "pw", "", "7+11", "passphrase", ""))
            tokens_json = h.call(
                "GetTokensByType", ("/dev/sda3", "systemd-tpm2")
            )
            tokens = json.loads(tokens_json[0])
            self.assertEqual(len(tokens), 1)
            tid, slots = tokens[0]
            self.assertEqual(slots, [1])

    def test_tpm2_token_fields(self):
        """Verify all required systemd-compat fields are present."""
        with ServiceHarness() as h:
            dev = h.create_device("/dev/sda3", passphrase="pw")
            h.call("EnrollTpm2",
                   ("/dev/sda3", "pw", "1234", "7", "passphrase", ""))
            token = dev.tokens[0]
            self.assertEqual(token["type"], "systemd-tpm2")
            self.assertIn("tpm2-blob", token)
            self.assertIn("tpm2_blob", token)  # dual-field compat
            self.assertEqual(token["tpm2-pcrs"], [7])
            self.assertEqual(token["tpm2-pcr-bank"], "sha256")
            self.assertEqual(token["tpm2-primary-alg"], "ecc")
            self.assertTrue(token["tpm2-pin"])  # PIN was provided
            self.assertIn("tpm2_srk", token)

    def test_tpm2_no_pin(self):
        with ServiceHarness() as h:
            dev = h.create_device("/dev/sda3", passphrase="pw")
            h.call("EnrollTpm2",
                   ("/dev/sda3", "pw", "", "7", "passphrase", ""))
            token = dev.tokens[0]
            self.assertFalse(token["tpm2-pin"])

    def test_tpm2_token_unlock(self):
        with ServiceHarness() as h:
            h.create_device("/dev/sda3", passphrase="pw")
            h.call("EnrollTpm2",
                   ("/dev/sda3", "pw", "", "7", "passphrase", ""))
            ok, keyslot = h.call(
                "UnlockWithToken", ("/dev/sda3", "systemd-tpm2", "")
            )
            self.assertTrue(ok)
            self.assertEqual(keyslot, 1)

    def test_tpm2_unlock_fails_when_not_enrolled(self):
        with ServiceHarness() as h:
            h.create_device("/dev/sda3", passphrase="pw")
            ok, keyslot = h.call(
                "UnlockWithToken", ("/dev/sda3", "systemd-tpm2", "")
            )
            self.assertFalse(ok)
            self.assertEqual(keyslot, -1)


class TestFido2Workflow(unittest.TestCase):

    def test_enroll_fido2(self):
        with ServiceHarness() as h:
            h.create_device("/dev/sda3", passphrase="pw")
            ok, stdout, err = h.call(
                "EnrollFido2",
                ("/dev/sda3", "pw", "", "/dev/hidraw0",
                 "passphrase", ""),
            )
            self.assertTrue(ok, f"EnrollFido2 failed: {err}")

    def test_fido2_token_metadata(self):
        with ServiceHarness() as h:
            dev = h.create_device("/dev/sda3", passphrase="pw")
            h.call("EnrollFido2",
                   ("/dev/sda3", "pw", "1234", "/dev/hidraw0",
                    "passphrase", ""))
            token = dev.tokens[0]
            self.assertEqual(token["type"], "systemd-fido2")
            self.assertIn("fido2-credential", token)
            self.assertIn("fido2-salt", token)
            self.assertEqual(token["fido2-rp"], "io.systemd.cryptsetup")
            self.assertTrue(token["fido2-clientPin-required"])
            self.assertTrue(token["fido2-up-required"])
            self.assertFalse(token["fido2-uv-required"])

    def test_fido2_no_pin(self):
        with ServiceHarness() as h:
            dev = h.create_device("/dev/sda3", passphrase="pw")
            h.call("EnrollFido2",
                   ("/dev/sda3", "pw", "", "/dev/hidraw0",
                    "passphrase", ""))
            token = dev.tokens[0]
            self.assertFalse(token["fido2-clientPin-required"])

    def test_fido2_credential_is_valid_base64(self):
        with ServiceHarness() as h:
            dev = h.create_device("/dev/sda3", passphrase="pw")
            h.call("EnrollFido2",
                   ("/dev/sda3", "pw", "", "/dev/hidraw0",
                    "passphrase", ""))
            token = dev.tokens[0]
            # Should not raise
            cred = base64.b64decode(token["fido2-credential"])
            salt = base64.b64decode(token["fido2-salt"])
            self.assertEqual(len(cred), 32)
            self.assertEqual(len(salt), 32)

    def test_fido2_keyslot_uses_base64_passphrase(self):
        """Systemd convention: FIDO2 keyslot passphrase is base64(hmac_secret)."""
        with ServiceHarness() as h:
            dev = h.create_device("/dev/sda3", passphrase="pw")
            h.call("EnrollFido2",
                   ("/dev/sda3", "pw", "", "/dev/hidraw0",
                    "passphrase", ""))
            # Slot 1 is the FIDO2 slot; its passphrase must be valid base64
            slot1_pw = dev.keyslots[1]
            decoded = base64.b64decode(slot1_pw)
            self.assertEqual(len(decoded), 32)  # hmac-secret is 32 bytes


class TestPassphraseEnrollment(unittest.TestCase):

    def test_add_new_passphrase(self):
        with ServiceHarness() as h:
            h.create_device("/dev/sda3", passphrase="old")
            ok, _, err = h.call(
                "EnrollPassphrase",
                ("/dev/sda3", "old", "new", "passphrase", ""),
            )
            self.assertTrue(ok, f"EnrollPassphrase failed: {err}")

    def test_both_passphrases_work(self):
        with ServiceHarness() as h:
            h.create_device("/dev/sda3", passphrase="old")
            h.call("EnrollPassphrase",
                   ("/dev/sda3", "old", "new", "passphrase", ""))
            ok_old, _ = h.call("VerifyPassphrase", ("/dev/sda3", "old"))
            ok_new, _ = h.call("VerifyPassphrase", ("/dev/sda3", "new"))
            self.assertTrue(ok_old)
            self.assertTrue(ok_new)

    def test_wrong_existing_passphrase_fails(self):
        with ServiceHarness() as h:
            h.create_device("/dev/sda3", passphrase="real")
            ok, _, err = h.call(
                "EnrollPassphrase",
                ("/dev/sda3", "wrong", "new", "passphrase", ""),
            )
            self.assertFalse(ok)
            self.assertTrue(err)  # error message is returned

    def test_password_slots_count_increases(self):
        with ServiceHarness() as h:
            h.create_device("/dev/sda3", passphrase="pw")
            h.call("EnrollPassphrase",
                   ("/dev/sda3", "pw", "pw2", "passphrase", ""))
            pw_slots = h.call("FindPasswordKeyslots", ("/dev/sda3",))
            # Both slots are unmanaged by tokens → both are password slots
            self.assertEqual(pw_slots[0], [0, 1])


class TestSlotWiping(unittest.TestCase):

    def test_wipe_recovery_removes_slot_and_token(self):
        with ServiceHarness() as h:
            dev = h.create_device("/dev/sda3", passphrase="pw")
            h.call("EnrollRecoveryKey",
                   ("/dev/sda3", "pw", "passphrase", ""))
            # Verify slot 1 and token exist
            self.assertIn(1, dev.keyslots)
            self.assertEqual(len(dev.tokens), 1)

            # Wipe slot 1
            ok, _, err = h.call(
                "WipeSlot",
                ("/dev/sda3", "pw", "passphrase", "", 1),
            )
            self.assertTrue(ok, f"WipeSlot failed: {err}")
            self.assertNotIn(1, dev.keyslots)
            self.assertEqual(len(dev.tokens), 0)

    def test_wipe_password_slot_no_token(self):
        """Wiping a password slot (no associated token) should not error."""
        with ServiceHarness() as h:
            dev = h.create_device("/dev/sda3", passphrase="pw")
            # Add a second password slot
            h.call("EnrollPassphrase",
                   ("/dev/sda3", "pw", "pw2", "passphrase", ""))
            # Wipe slot 1 (second passphrase, no token)
            ok, _, err = h.call(
                "WipeSlot",
                ("/dev/sda3", "pw", "passphrase", "", 1),
            )
            self.assertTrue(ok)
            self.assertNotIn(1, dev.keyslots)
            self.assertIn(0, dev.keyslots)  # original still there

    def test_wipe_tpm2_cleans_token(self):
        with ServiceHarness() as h:
            dev = h.create_device("/dev/sda3", passphrase="pw")
            h.call("EnrollTpm2",
                   ("/dev/sda3", "pw", "", "7", "passphrase", ""))
            self.assertEqual(len(dev.tokens), 1)
            h.call("WipeSlot",
                   ("/dev/sda3", "pw", "passphrase", "", 1))
            self.assertEqual(len(dev.tokens), 0)
            self.assertNotIn(1, dev.keyslots)

    def test_keyslots_consistent_after_wipe(self):
        with ServiceHarness() as h:
            h.create_device("/dev/sda3", passphrase="pw")
            h.call("EnrollRecoveryKey",
                   ("/dev/sda3", "pw", "passphrase", ""))
            h.call("WipeSlot",
                   ("/dev/sda3", "pw", "passphrase", "", 1))
            raw = h.call("GetKeyslots", ("/dev/sda3",))
            slots = json.loads(raw[0])
            self.assertEqual(list(slots.keys()), ["0"])


class TestEncryptedImageCreation(unittest.TestCase):

    def test_create_encrypted_image(self):
        with ServiceHarness() as h:
            ok, keyslot, err = h.call(
                "CreateEncryptedImage",
                ("/tmp/test.img", 256, "secret"),
            )
            self.assertTrue(ok, f"CreateEncryptedImage failed: {err}")
            self.assertEqual(keyslot, 0)
            # The fake device should now exist
            self.assertIn("/tmp/test.img", h.devices)

    def test_image_is_functional(self):
        """After creation, keyslots and passphrase should work."""
        with ServiceHarness() as h:
            h.call("CreateEncryptedImage",
                   ("/tmp/test.img", 256, "secret"))
            ok, slot = h.call(
                "VerifyPassphrase", ("/tmp/test.img", "secret")
            )
            self.assertTrue(ok)

    def test_image_appears_in_detect(self):
        with ServiceHarness() as h:
            h.call("CreateEncryptedImage",
                   ("/tmp/test.img", 256, "pw"))
            devices = h.call("DetectDevices")
            self.assertIn("/tmp/test.img", devices[0])


class TestRemovableDevices(unittest.TestCase):

    def test_detect_removable(self):
        with ServiceHarness() as h:
            raw = h.call("DetectRemovableDevices")
            devices = json.loads(raw[0])
            self.assertEqual(len(devices), 1)
            self.assertEqual(devices[0]["device"], "/dev/sdb")

    def test_get_device_info(self):
        with ServiceHarness() as h:
            raw = h.call("GetDeviceInfo", ("/dev/sdb",))
            info = json.loads(raw[0])
            self.assertEqual(info["device"], "/dev/sdb")

    def test_format_partition(self):
        with ServiceHarness() as h:
            ok, partition, err = h.call(
                "FormatPartition", ("/dev/sdb", "pw")
            )
            self.assertTrue(ok)
            self.assertEqual(partition, "/dev/sdb1")
            # Formatted partition is now a LUKS device
            self.assertIn("/dev/sdb1", h.devices)


class TestSettingsWorkflow(unittest.TestCase):

    def test_get_unset_returns_empty(self):
        with ServiceHarness() as h:
            value = h.call("GetSetting", ("nonexistent_key",))
            self.assertEqual(value[0], "")

    def test_set_and_get_roundtrip(self):
        with ServiceHarness() as h:
            ok = h.call("SetSetting", ("my_key", "my_value"))
            self.assertTrue(ok[0])
            value = h.call("GetSetting", ("my_key",))
            self.assertEqual(value[0], "my_value")

    def test_overwrite_setting(self):
        with ServiceHarness() as h:
            h.call("SetSetting", ("key", "val1"))
            h.call("SetSetting", ("key", "val2"))
            value = h.call("GetSetting", ("key",))
            self.assertEqual(value[0], "val2")


class TestAuthentication(unittest.TestCase):

    def test_authenticate_returns_true(self):
        with ServiceHarness() as h:
            result = h.call("Authenticate")
            self.assertTrue(result[0])

    def test_get_systemd_version(self):
        with ServiceHarness() as h:
            result = h.call("GetSystemdVersion")
            self.assertEqual(result[0], 999)


class TestTokenUnlockBasedEnrollment(unittest.TestCase):
    """Enroll via one token, then enroll another using the first token's
    unlock method — exercises the volume key cache path."""

    def test_enroll_tpm2_then_recovery_via_token(self):
        with ServiceHarness() as h:
            h.create_device("/dev/sda3", passphrase="pw")
            # Enroll TPM2 first
            h.call("EnrollTpm2",
                   ("/dev/sda3", "pw", "", "7", "passphrase", ""))
            # Simulate token unlock (populates volume key cache)
            ok, _ = h.call(
                "UnlockWithToken", ("/dev/sda3", "systemd-tpm2", "")
            )
            self.assertTrue(ok)
            # Now enroll recovery key using token-based unlock
            ok, recovery_key, err = h.call(
                "EnrollRecoveryKey",
                ("/dev/sda3", "", "systemd-tpm2", ""),
            )
            self.assertTrue(ok, f"Recovery enrollment via token failed: {err}")
            # Verify recovery key works
            ok2, _ = h.call(
                "VerifyPassphrase", ("/dev/sda3", recovery_key)
            )
            self.assertTrue(ok2)

    def test_enroll_fido2_then_tpm2_via_token(self):
        with ServiceHarness() as h:
            h.create_device("/dev/sda3", passphrase="pw")
            # Enroll FIDO2
            h.call("EnrollFido2",
                   ("/dev/sda3", "pw", "", "/dev/hidraw0",
                    "passphrase", ""))
            # Token unlock populates VK cache
            h.call("UnlockWithToken",
                   ("/dev/sda3", "systemd-fido2", ""))
            # Enroll TPM2 using FIDO2 token
            ok, _, err = h.call(
                "EnrollTpm2",
                ("/dev/sda3", "", "", "7", "systemd-fido2", ""),
            )
            self.assertTrue(ok, f"TPM2 enrollment via FIDO2 failed: {err}")


class TestFullWizardFlow(unittest.TestCase):
    """End-to-end wizard: detect → unlock → enroll everything → wipe password."""

    def test_complete_flow(self):
        with ServiceHarness() as h:
            dev = h.create_device("/dev/sda3", passphrase="installer-pw")

            # Step 1: Detect devices
            devices = h.call("DetectDevices")[0]
            self.assertIn("/dev/sda3", devices)

            # Step 2: Verify passphrase (unlock)
            ok, keyslot = h.call(
                "VerifyPassphrase", ("/dev/sda3", "installer-pw")
            )
            self.assertTrue(ok)
            self.assertEqual(keyslot, 0)

            # Step 3: Enroll TPM2
            ok, _, err = h.call(
                "EnrollTpm2",
                ("/dev/sda3", "installer-pw", "", "7",
                 "passphrase", ""),
            )
            self.assertTrue(ok, err)

            # Step 4: Enroll recovery key
            ok, recovery_key, err = h.call(
                "EnrollRecoveryKey",
                ("/dev/sda3", "installer-pw", "passphrase", ""),
            )
            self.assertTrue(ok, err)

            # Step 5: Verify state — 3 keyslots, 2 tokens
            raw = h.call("GetKeyslots", ("/dev/sda3",))
            slots = json.loads(raw[0])
            self.assertEqual(len(slots), 3)

            tpm2_tokens = json.loads(
                h.call("GetTokensByType",
                       ("/dev/sda3", "systemd-tpm2"))[0]
            )
            self.assertEqual(len(tpm2_tokens), 1)

            recovery_tokens = json.loads(
                h.call("GetTokensByType",
                       ("/dev/sda3", "systemd-recovery"))[0]
            )
            self.assertEqual(len(recovery_tokens), 1)

            # Step 6: Password slot should be only slot 0
            pw_slots = h.call("FindPasswordKeyslots", ("/dev/sda3",))[0]
            self.assertEqual(pw_slots, [0])

            # Step 7: Wipe the password slot
            ok, _, err = h.call(
                "WipeSlot",
                ("/dev/sda3", "installer-pw", "passphrase", "", 0),
            )
            self.assertTrue(ok, err)

            # Step 8: Verify password no longer works
            ok, _ = h.call(
                "VerifyPassphrase", ("/dev/sda3", "installer-pw")
            )
            self.assertFalse(ok)

            # Step 9: Recovery key still works
            ok, _ = h.call(
                "VerifyPassphrase", ("/dev/sda3", recovery_key)
            )
            self.assertTrue(ok)

            # Step 10: TPM2 token unlock still works
            ok, _ = h.call(
                "UnlockWithToken", ("/dev/sda3", "systemd-tpm2", "")
            )
            self.assertTrue(ok)

            # Step 11: Final state — 2 keyslots, 0 password slots
            raw = h.call("GetKeyslots", ("/dev/sda3",))
            slots = json.loads(raw[0])
            self.assertEqual(len(slots), 2)
            pw_slots = h.call("FindPasswordKeyslots", ("/dev/sda3",))[0]
            self.assertEqual(pw_slots, [])


class TestMultipleDevices(unittest.TestCase):
    """Test operating on multiple devices independently."""

    def test_independent_devices(self):
        with ServiceHarness() as h:
            h.create_device("/dev/sda3", passphrase="pw1")
            h.create_device("/dev/sdb1", passphrase="pw2")

            # Enroll recovery on first device only
            h.call("EnrollRecoveryKey",
                   ("/dev/sda3", "pw1", "passphrase", ""))

            # First device: 2 keyslots, 1 token
            slots1 = json.loads(
                h.call("GetKeyslots", ("/dev/sda3",))[0]
            )
            self.assertEqual(len(slots1), 2)

            # Second device: 1 keyslot, 0 tokens
            slots2 = json.loads(
                h.call("GetKeyslots", ("/dev/sdb1",))[0]
            )
            self.assertEqual(len(slots2), 1)

            tokens2 = json.loads(
                h.call("GetTokensByType",
                       ("/dev/sdb1", "systemd-recovery"))[0]
            )
            self.assertEqual(len(tokens2), 0)


class TestMultipleEnrollments(unittest.TestCase):
    """Multiple tokens of the same type on one device."""

    def test_two_recovery_keys(self):
        with ServiceHarness() as h:
            h.create_device("/dev/sda3", passphrase="pw")
            ok1, key1, _ = h.call(
                "EnrollRecoveryKey",
                ("/dev/sda3", "pw", "passphrase", ""),
            )
            ok2, key2, _ = h.call(
                "EnrollRecoveryKey",
                ("/dev/sda3", "pw", "passphrase", ""),
            )
            self.assertTrue(ok1)
            self.assertTrue(ok2)
            self.assertNotEqual(key1, key2)

            # Both work
            ok, _ = h.call("VerifyPassphrase", ("/dev/sda3", key1))
            self.assertTrue(ok)
            ok, _ = h.call("VerifyPassphrase", ("/dev/sda3", key2))
            self.assertTrue(ok)

            tokens = json.loads(
                h.call("GetTokensByType",
                       ("/dev/sda3", "systemd-recovery"))[0]
            )
            self.assertEqual(len(tokens), 2)

    def test_tpm2_and_fido2_coexist(self):
        with ServiceHarness() as h:
            h.create_device("/dev/sda3", passphrase="pw")
            h.call("EnrollTpm2",
                   ("/dev/sda3", "pw", "", "7", "passphrase", ""))
            h.call("EnrollFido2",
                   ("/dev/sda3", "pw", "", "/dev/hidraw0",
                    "passphrase", ""))
            tpm2 = json.loads(
                h.call("GetTokensByType",
                       ("/dev/sda3", "systemd-tpm2"))[0]
            )
            fido2 = json.loads(
                h.call("GetTokensByType",
                       ("/dev/sda3", "systemd-fido2"))[0]
            )
            self.assertEqual(len(tpm2), 1)
            self.assertEqual(len(fido2), 1)

            # Each has its own keyslot
            self.assertNotEqual(tpm2[0][1], fido2[0][1])


class TestErrorPaths(unittest.TestCase):

    def test_enroll_with_wrong_passphrase(self):
        with ServiceHarness() as h:
            h.create_device("/dev/sda3", passphrase="correct")
            ok, _, err = h.call(
                "EnrollRecoveryKey",
                ("/dev/sda3", "wrong", "passphrase", ""),
            )
            self.assertFalse(ok)
            self.assertTrue(err)  # error message is returned

    def test_enroll_tpm2_wrong_passphrase(self):
        with ServiceHarness() as h:
            h.create_device("/dev/sda3", passphrase="correct")
            ok, _, err = h.call(
                "EnrollTpm2",
                ("/dev/sda3", "wrong", "", "7", "passphrase", ""),
            )
            self.assertFalse(ok)

    def test_enroll_fido2_wrong_passphrase(self):
        with ServiceHarness() as h:
            h.create_device("/dev/sda3", passphrase="correct")
            ok, _, err = h.call(
                "EnrollFido2",
                ("/dev/sda3", "wrong", "", "/dev/hidraw0",
                 "passphrase", ""),
            )
            self.assertFalse(ok)

    def test_enroll_passphrase_wrong_existing(self):
        with ServiceHarness() as h:
            h.create_device("/dev/sda3", passphrase="correct")
            ok, _, err = h.call(
                "EnrollPassphrase",
                ("/dev/sda3", "wrong", "new", "passphrase", ""),
            )
            self.assertFalse(ok)


class TestTPM2TokenDualFieldCompat(unittest.TestCase):
    """Verify systemd/libcryptsetup compatibility in TPM2 token JSON."""

    def test_blob_fields_match(self):
        with ServiceHarness() as h:
            dev = h.create_device("/dev/sda3", passphrase="pw")
            h.call("EnrollTpm2",
                   ("/dev/sda3", "pw", "", "7", "passphrase", ""))
            token = dev.tokens[0]
            self.assertEqual(token["tpm2-blob"], token["tpm2_blob"])

    def test_pcr_hash_fields(self):
        with ServiceHarness() as h:
            dev = h.create_device("/dev/sda3", passphrase="pw")
            h.call("EnrollTpm2",
                   ("/dev/sda3", "pw", "", "7", "passphrase", ""))
            token = dev.tokens[0]
            self.assertEqual(token["tpm2-pcr-bank"], "sha256")
            self.assertEqual(token["tpm2_pcr_hash"], "sha256")


if __name__ == "__main__":
    unittest.main()
