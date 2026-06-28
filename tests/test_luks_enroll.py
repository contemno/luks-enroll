#!/usr/bin/env python3
"""Test suite for the LUKS Enroll Wizard GUI client.

Tests pure logic, enrollment-spec/proxy consistency, and hardware-detection
helpers in the GUI client without requiring root, hardware tokens, or real
LUKS devices. The privileged service is now the Rust binary under `rust/` and
is covered by `cargo test`.

Run: python3 -m pytest test_luks_enroll.py -v
"""

import ast
import glob  # noqa: F401  pre-import so sys.modules patching doesn't evict it
import os
import unittest
from unittest import mock

from conftest import GUI_PATH, load_module


# Import the GUI module once at module scope
gui = load_module("luks_enroll", GUI_PATH)


# ===========================================================================
# Syntax checks
# ===========================================================================


class TestSyntax(unittest.TestCase):
    """Verify the GUI client parses without syntax errors."""

    def test_gui_syntax(self):
        with open(GUI_PATH) as f:
            ast.parse(f.read(), filename=GUI_PATH)


# ===========================================================================
# Enrollment spec / proxy consistency
# ===========================================================================


class TestEnrollSpecConsistency(unittest.TestCase):
    """Every enrollment spec must point at a real proxy method."""

    def test_specs_cover_all_four_enrollment_types(self):
        names = {s.name for s in gui.ENROLL_SPECS}
        self.assertEqual(names, {"fido2", "tpm2", "recovery", "passphrase"})

    def test_tpm2_pcr_constants_present(self):
        # Regression: TPM2_PCRS / TPM2_DEFAULT_PCRS were defined inside the
        # wizard block deleted in Phase 2; the management TPM2 page needs
        # them and would crash with NameError on click otherwise.
        self.assertIsInstance(gui.TPM2_PCRS, dict)
        self.assertGreater(len(gui.TPM2_PCRS), 0)
        self.assertIsInstance(gui.TPM2_DEFAULT_PCRS, set)
        self.assertTrue(
            gui.TPM2_DEFAULT_PCRS.issubset(gui.TPM2_PCRS.keys()),
            "every default PCR must be a key in TPM2_PCRS",
        )

    def test_each_spec_has_proxy_method(self):
        for spec in gui.ENROLL_SPECS:
            method = getattr(gui.LuksEnrollProxy, spec.service_method, None)
            self.assertTrue(
                callable(method),
                f"spec {spec.name!r} references "
                f"missing proxy method {spec.service_method!r}",
            )

    def test_each_spec_required_attrs_are_strings(self):
        required = (
            "name",
            "title",
            "group_title",
            "group_description",
            "button_label",
            "enrolling_label",
            "success_label",
            "failure_default",
            "service_method",
        )
        for spec in gui.ENROLL_SPECS:
            for attr in required:
                self.assertIsInstance(
                    getattr(spec, attr),
                    str,
                    f"spec {spec.name!r} attr {attr!r} must be a str",
                )


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
# Token-type constants + run_async helper
# ===========================================================================


class TestTokenTypeConstants(unittest.TestCase):
    """Client token-type constants must match systemd-cryptenroll's on-disk
    values (and the Rust service's constants::TOKEN_TYPE_*)."""

    def test_token_type_constants(self):
        self.assertEqual(gui.TOKEN_FIDO2, "systemd-fido2")
        self.assertEqual(gui.TOKEN_TPM2, "systemd-tpm2")
        self.assertEqual(gui.TOKEN_RECOVERY, "systemd-recovery")


class TestAppVersion(unittest.TestCase):
    """The footer version resolves to the build-time-substituted __version__,
    else the repo VERSION floor, else 'dev' — never the raw placeholder."""

    def test_source_checkout_falls_back_to_version_file(self):
        # Imported from the repo the @VERSION@ placeholder is unsubstituted, so
        # APP_VERSION mirrors the VERSION floor and never leaks the placeholder.
        version_file = os.path.join(
            os.path.dirname(GUI_PATH), "..", "..", "..", "VERSION"
        )
        with open(version_file) as f:
            expected = f.read().strip()
        self.assertEqual(gui.APP_VERSION, expected)
        self.assertFalse(gui.APP_VERSION.startswith("@"))

    def test_substituted_version_is_used_verbatim(self):
        with mock.patch.object(gui, "__version__", "0.3.0-dev.20260627.deadbee"):
            self.assertEqual(gui._resolve_version(), "0.3.0-dev.20260627.deadbee")

    def test_unreadable_version_file_falls_back_to_dev(self):
        with (
            mock.patch.object(gui, "__version__", "@VERSION@"),
            mock.patch("builtins.open", side_effect=OSError),
        ):
            self.assertEqual(gui._resolve_version(), "dev")


class TestRunAsync(unittest.TestCase):
    """run_async runs the call off-thread and routes the result (or a
    synthesized D-Bus error triple) to the callback via GLib.idle_add."""

    @staticmethod
    def _sync_thread(target=None, daemon=None):
        # Invoke the worker synchronously when .start() is called.
        runner = mock.MagicMock()
        runner.start = target
        return runner

    def test_success_routes_result_to_callback(self):
        captured = []
        with (
            mock.patch.object(gui.threading, "Thread", side_effect=self._sync_thread),
            mock.patch.object(
                gui.GLib, "idle_add", side_effect=lambda *a: captured.append(a)
            ),
        ):
            cb = object()
            gui.run_async(lambda: (True, "out", ""), cb)
        self.assertEqual(captured, [(cb, True, "out", "")])

    def test_glib_error_becomes_failure_triple(self):
        class FakeGError(Exception):
            def __init__(self, message):
                super().__init__(message)
                self.message = message

        def boom():
            raise FakeGError("nope")

        captured = []
        with (
            mock.patch.object(gui.threading, "Thread", side_effect=self._sync_thread),
            mock.patch.object(gui.GLib, "Error", FakeGError),
            mock.patch.object(
                gui.GLib, "idle_add", side_effect=lambda *a: captured.append(a)
            ),
        ):
            cb = object()
            gui.run_async(boom, cb)
        self.assertEqual(captured, [(cb, False, "", "D-Bus error: nope")])


if __name__ == "__main__":
    unittest.main()
