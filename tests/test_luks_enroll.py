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
import tempfile
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


class TestKeylessImageCreation(unittest.TestCase):
    """Issue #58 (image files) and #82 (block devices): creating/encrypting a
    container needs no passphrase. The service formats it with a cached
    volume key and the detail page opens already unlocked, so the first
    enrollment wraps that key directly.

    The GUI page classes subclass mocked GTK bases (so they're MagicMocks at
    import), hence these assert on the parsed source of each class body."""

    @classmethod
    def setUpClass(cls):
        with open(GUI_PATH) as f:
            source = f.read()
        cls.classes = {
            node.name: ast.get_source_segment(source, node)
            for node in ast.walk(ast.parse(source, filename=GUI_PATH))
            if isinstance(node, ast.ClassDef)
        }

    def test_detail_page_accepts_volume_key_cached(self):
        # DeviceDetailPage gained a volume_key_cached hand-off (default off).
        self.assertIn("volume_key_cached=False", self.classes["DeviceDetailPage"])

    def test_create_page_drops_passphrase_fields(self):
        create = self.classes["CreateImagePage"]
        # The passphrase entry rows and their validation are gone — the user
        # is never asked for a throwaway passphrase on create.
        self.assertNotIn("PasswordEntryRow", create)
        self.assertNotIn("Passphrases do not match", create)
        self.assertNotIn("Passphrase cannot be empty", create)

    def test_create_uses_empty_passphrase_and_cached_handoff(self):
        create = self.classes["CreateImagePage"]
        # Create with an empty passphrase (keyless format) ...
        self.assertIn('create_encrypted_image_async(path, size_mb, "", ', create)
        # ... then hand off to the shared success tail (FormatDialogBase),
        # which does the volume_key_cached=True detail-page push.
        self.assertIn("self._on_format_success(self._pending_path)", create)

    def test_encrypt_device_page_drops_passphrase_fields(self):
        # Issue #82: extends the keyless format to the block-device path.
        # The passphrase entry rows and their validation are gone — the user
        # is never asked for a throwaway passphrase on encrypt.
        encrypt = self.classes["EncryptDevicePage"]
        self.assertNotIn("PasswordEntryRow", encrypt)
        self.assertNotIn("Passphrases do not match", encrypt)
        self.assertNotIn("Passphrase cannot be empty", encrypt)

    def test_encrypt_device_uses_empty_passphrase_and_cached_handoff(self):
        encrypt = self.classes["EncryptDevicePage"]
        # Encrypt with an empty passphrase (keyless format) ...
        self.assertIn('self.svc.format_partition(self.device, "")', encrypt)
        # ... then hand off to the shared success tail (FormatDialogBase),
        # which does the volume_key_cached=True detail-page push.
        self.assertIn("self._on_format_success(partition or self.device)", encrypt)


class TestFormatDialogConsolidation(unittest.TestCase):
    """Issue #86: EncryptDevicePage/CreateImagePage became Adw.Dialogs (not
    pushed Adw.NavigationPages), so the back button from the detail page that
    opens after a successful format lands on the device list, never on a now-
    stale format page. The two share a FormatDialogBase for their chrome and
    the success/failure hand-off; only the target-specific input widgets and
    the D-Bus dispatch stay in the subclasses.

    Same source-based approach as TestKeylessImageCreation: the page classes
    subclass mocked GTK bases, so real instantiation isn't meaningful here."""

    @classmethod
    def setUpClass(cls):
        with open(GUI_PATH) as f:
            source = f.read()
        tree = ast.parse(source, filename=GUI_PATH)
        cls.classes = {
            node.name: ast.get_source_segment(source, node)
            for node in ast.walk(tree)
            if isinstance(node, ast.ClassDef)
        }
        cls.bases = {
            node.name: [ast.unparse(b) for b in node.bases]
            for node in ast.walk(tree)
            if isinstance(node, ast.ClassDef)
        }

    def test_format_dialogs_subclass_shared_base_not_nav_page(self):
        self.assertEqual(self.bases["FormatDialogBase"], ["Adw.Dialog"])
        self.assertEqual(self.bases["EncryptDevicePage"], ["FormatDialogBase"])
        self.assertEqual(self.bases["CreateImagePage"], ["FormatDialogBase"])

    def test_format_dialog_base_pins_a_non_tiny_content_size(self):
        # Adw.Dialog defaults to its content's natural size, which for a
        # PreferencesPage-based form rendered as ~a quarter of the main
        # window (PR #87 review feedback). Pin an explicit size instead.
        base = self.classes["FormatDialogBase"]
        self.assertIn("self.set_content_width(", base)
        self.assertIn("self.set_content_height(", base)

    def test_list_page_presents_dialogs_instead_of_pushing(self):
        list_page = self.classes["DeviceListPage"]
        self.assertIn("EncryptDevicePage(self.svc, device, size_str, self)", list_page)
        self.assertIn("CreateImagePage(self.svc, self)", list_page)
        self.assertIn("dialog.present(self)", list_page)
        # No more pushing these onto the nav stack.
        self.assertNotIn("nav.push(page)", list_page)

    def test_shared_success_and_failure_tail_lives_in_base_only(self):
        base = self.classes["FormatDialogBase"]
        self.assertIn("self.close()", base)
        self.assertIn("volume_key_cached=True", base)
        self.assertIn("nav.push(detail)", base)
        # Subclasses delegate rather than duplicating the close/push tail.
        for name in ("EncryptDevicePage", "CreateImagePage"):
            cls_src = self.classes[name]
            self.assertNotIn("self.close()", cls_src)
            self.assertNotIn("volume_key_cached=True", cls_src)
            self.assertIn("_on_format_success", cls_src)
            self.assertIn("_on_format_failure", cls_src)


class TestEmptyRemovableReaderRendering(unittest.TestCase):
    """A removable device with size_bytes == 0 and no partitions (e.g. an
    empty SD/TF card reader) must render as a dimmed, non-activatable row
    with no Encrypt button (#89), distinct from a real zero-partition
    device that just hasn't been formatted yet.

    Same AST source-based approach as TestFormatDialogConsolidation: the
    page classes subclass mocked GTK bases, so real instantiation isn't
    meaningful here.
    """

    @classmethod
    def setUpClass(cls):
        with open(GUI_PATH) as f:
            source = f.read()
        tree = ast.parse(source, filename=GUI_PATH)
        cls.classes = {
            node.name: ast.get_source_segment(source, node)
            for node in ast.walk(tree)
            if isinstance(node, ast.ClassDef)
        }

    def test_empty_reader_branch_is_dimmed_and_not_activatable(self):
        list_page = self.classes["DeviceListPage"]
        self.assertIn('rdev.get("size_bytes") == 0', list_page)
        self.assertIn("Empty — insert a memory card to encrypt", list_page)

    def test_empty_reader_branch_precedes_the_no_partitions_fallback(self):
        # The zero-size check must be an elif ahead of the generic
        # no-partitions branch, or every unformatted device (not just
        # empty readers) would lose its Encrypt button.
        list_page = self.classes["DeviceListPage"]
        empty_idx = list_page.index('rdev.get("size_bytes") == 0')
        fallback_idx = list_page.index('subtitle += " — No partitions"')
        self.assertLess(empty_idx, fallback_idx)


class TestReformatStuckVolumes(unittest.TestCase):
    """Issue #88: a removable partition or image file with zero enrolled
    keyslots and no cached volume key can never be unlocked again, so the
    list page offers a reformat/recreate action instead of a dead-end detail
    view. GTK page classes subclass mocked bases (MagicMocks at import, per
    TestKeylessImageCreation's docstring), so this asserts on source."""

    @classmethod
    def setUpClass(cls):
        with open(GUI_PATH) as f:
            source = f.read()
        tree = ast.parse(source, filename=GUI_PATH)
        cls.classes = {
            node.name: ast.get_source_segment(source, node)
            for node in ast.walk(tree)
            if isinstance(node, ast.ClassDef)
        }
        cls.bases = {
            node.name: [ast.unparse(b) for b in node.bases]
            for node in ast.walk(tree)
            if isinstance(node, ast.ClassDef)
        }

    def test_is_reformattable_requires_zero_keyslots_and_uncached_vk(self):
        list_page = self.classes["DeviceListPage"]
        self.assertIn('summary != "No keyslots"', list_page)
        self.assertIn("self.svc.is_volume_key_cached(path)", list_page)

    def test_removable_and_image_rows_gate_on_reformattable_set(self):
        list_page = self.classes["DeviceListPage"]
        self.assertIn("if part_path in reformattable:", list_page)
        self.assertIn("if img_path in reformattable:", list_page)
        # Internal (non-removable) volumes are deliberately never offered a
        # reformat: this is a recovery path for removable media and
        # containers, not a way to nuke an in-use system volume.
        internal_render_loop = list_page.split("for dev in devices:")[1].split(
            "for rdev in removable_devs:"
        )[0]
        self.assertNotIn("reformattable", internal_render_loop)

    def test_reformat_image_page_subclasses_shared_base(self):
        self.assertEqual(self.bases["ReformatImagePage"], ["FormatDialogBase"])

    def test_reformat_image_page_drops_passphrase_fields(self):
        reformat = self.classes["ReformatImagePage"]
        self.assertNotIn("PasswordEntryRow", reformat)
        self.assertNotIn("Passphrases do not match", reformat)
        self.assertNotIn("Passphrase cannot be empty", reformat)

    def test_reformat_image_page_removes_then_recreates_keylessly(self):
        reformat = self.classes["ReformatImagePage"]
        self.assertIn("os.remove(self.path)", reformat)
        self.assertIn('self.path, self.size_mb, "", self._on_create_finish', reformat)
        # ... then hand off to the shared success tail (FormatDialogBase),
        # which does the volume_key_cached=True detail-page push.
        self.assertIn("self._on_format_success(self.path)", reformat)

    def test_proxy_is_volume_key_cached_dispatches_by_path_or_fd(self):
        proxy = gui.LuksEnrollProxy.__new__(gui.LuksEnrollProxy)
        proxy.proxy = mock.MagicMock()
        proxy.proxy.call_sync.return_value.unpack.return_value = (True,)
        captured = {}

        def fake_dispatch(
            path_call, method_fd, fd_sig, device, extra_args, timeout, read_only=False
        ):
            captured.update(
                method_fd=method_fd,
                fd_sig=fd_sig,
                device=device,
                read_only=read_only,
            )
            return path_call().unpack()

        proxy._call_path_or_fd_sync = fake_dispatch
        result = proxy.is_volume_key_cached("/dev/sdx1")

        self.assertTrue(result)
        self.assertEqual(captured["method_fd"], "IsVolumeKeyCachedFd")
        self.assertEqual(captured["fd_sig"], "(h)")
        self.assertEqual(captured["device"], "/dev/sdx1")
        self.assertTrue(captured["read_only"])
        proxy.proxy.call_sync.assert_called_once_with(
            "IsVolumeKeyCached", mock.ANY, gui.Gio.DBusCallFlags.NONE, 30000, None
        )


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


class TestVolumeMappingProxy(unittest.TestCase):
    """OpenVolume/CloseVolume proxy wrappers (issue #69): correct D-Bus method
    names, signatures, and path-vs-fd dispatch."""

    @staticmethod
    def _proxy():
        # Build a proxy instance without running __init__ (which would try to
        # connect to the bus); the wrappers only touch .proxy / helpers.
        return gui.LuksEnrollProxy.__new__(gui.LuksEnrollProxy)

    def test_open_volume_uses_fd_variant_and_signature(self):
        proxy = self._proxy()
        captured = {}

        def fake_dispatch(path_call, method_fd, fd_sig, device, extra_args, timeout):
            captured.update(
                method_fd=method_fd, fd_sig=fd_sig, device=device, extra_args=extra_args
            )
            return (True, "luks-uuid", "")

        proxy._call_path_or_fd_sync = fake_dispatch
        ok, mapper, err = proxy.open_volume(
            "/dev/sdb1", "luks-uuid", "pw", "systemd-fido2", "1234"
        )
        self.assertEqual((ok, mapper, err), (True, "luks-uuid", ""))
        self.assertEqual(captured["method_fd"], "OpenVolumeFd")
        # fd path: index + name + passphrase + unlock_method + unlock_pin.
        self.assertEqual(captured["fd_sig"], "(hssss)")
        self.assertEqual(captured["device"], "/dev/sdb1")
        self.assertEqual(
            captured["extra_args"], ("luks-uuid", "pw", "systemd-fido2", "1234")
        )

    def test_close_volume_block_device_uses_polkit_gated_close(self):
        proxy = self._proxy()

        class FakeResult:
            def unpack(self):
                return (True, "")

        class FakeProxy:
            def __init__(self):
                self.calls = []

            def call_sync(self, method, *args, **kwargs):
                self.calls.append(method)
                return FakeResult()

        proxy.proxy = FakeProxy()
        # A block device is not a regular file, so the fd path is skipped.
        self.assertEqual(proxy.close_volume("/dev/sdb1", "luks-uuid"), (True, ""))
        self.assertEqual(proxy.proxy.calls, ["CloseVolume"])

    def test_close_volume_container_file_uses_fd_discovery(self):
        # A container file routes to CloseVolumeFd: fd-only signature, no
        # mapper name crosses the boundary, and the (ok, closed, stderr)
        # triple collapses to the (ok, stderr) pair callers expect.
        proxy = self._proxy()
        captured = {}

        def fake_fd_sync(method_fd, signature, fd, extra_args, timeout):
            os.fstat(fd)  # the fd must be open and valid at call time
            captured.update(
                method_fd=method_fd, signature=signature, fd=fd, extra_args=extra_args
            )
            return (True, "luks-uuid", "")

        proxy._call_fd_sync = fake_fd_sync
        with tempfile.NamedTemporaryFile() as img:
            self.assertEqual(proxy.close_volume(img.name, "luks-uuid"), (True, ""))
            # close_volume owns the fd lifecycle (_call_fd_sync must not
            # close it): after returning, the fd is closed exactly once.
            with self.assertRaises(OSError):
                os.fstat(captured["fd"])
        self.assertEqual(captured["method_fd"], "CloseVolumeFd")
        self.assertEqual(captured["signature"], "(h)")
        self.assertEqual(captured["extra_args"], ())

    def test_close_volume_falls_back_when_service_lacks_the_method(self):
        # An installed service older than CloseVolumeFd raises UnknownMethod;
        # the client must fall back to the polkit-gated CloseVolume rather
        # than surface an error (service/client version skew).
        proxy = self._proxy()

        class FakeGError(Exception):
            pass

        class FakeResult:
            def unpack(self):
                return (True, "")

        class FakeProxy:
            def __init__(self):
                self.calls = []

            def call_sync(self, method, *args, **kwargs):
                self.calls.append(method)
                return FakeResult()

        def raise_unknown(*args, **kwargs):
            raise FakeGError("no such method")

        proxy.proxy = FakeProxy()
        proxy._call_fd_sync = raise_unknown
        with (
            mock.patch.object(gui.GLib, "Error", FakeGError),
            mock.patch.object(
                gui.Gio.DBusError,
                "get_remote_error",
                return_value="org.freedesktop.DBus.Error.UnknownMethod",
            ),
            tempfile.NamedTemporaryFile() as img,
        ):
            self.assertEqual(proxy.close_volume(img.name, "luks-uuid"), (True, ""))
        self.assertEqual(proxy.proxy.calls, ["CloseVolume"])

    def test_close_volume_reraises_other_dbus_errors(self):
        # Only UnknownMethod triggers the fallback; a real failure (denied,
        # timeout, ...) must propagate, not silently retry with polkit.
        proxy = self._proxy()

        class FakeGError(Exception):
            pass

        def raise_failure(*args, **kwargs):
            raise FakeGError("operation failed")

        proxy._call_fd_sync = raise_failure
        with (
            mock.patch.object(gui.GLib, "Error", FakeGError),
            mock.patch.object(
                gui.Gio.DBusError,
                "get_remote_error",
                return_value="org.freedesktop.DBus.Error.Failed",
            ),
            tempfile.NamedTemporaryFile() as img,
        ):
            with self.assertRaises(FakeGError):
                proxy.close_volume(img.name, "luks-uuid")

    def test_is_unknown_method_matches_only_the_dbus_unknown_method_name(self):
        self.assertTrue(
            gui.is_unknown_method("org.freedesktop.DBus.Error.UnknownMethod")
        )
        self.assertFalse(gui.is_unknown_method("org.freedesktop.DBus.Error.Failed"))
        self.assertFalse(gui.is_unknown_method(None))


class TestMapperNameDerivation(unittest.TestCase):
    """The Volume Mapping button must appear even when the service reports no
    UUID (older service build), so the name derivation falls back to the
    device path instead of disabling the control (PR #70 review)."""

    @staticmethod
    def _derive(device, uuid):
        return gui.derive_mapper_name(device, uuid)

    def test_prefers_uuid(self):
        self.assertEqual(self._derive("/dev/sdb1", "1b6e-2c3d"), "luks-1b6e-2c3d")

    def test_falls_back_to_device_basename_when_no_uuid(self):
        # No UUID -> still a valid, non-None name so the button shows.
        self.assertEqual(self._derive("/dev/sdb1", ""), "luks-sdb1")

    def test_fallback_sanitizes_to_dm_name_charset(self):
        name = self._derive("/home/user/My Secret.img", "")
        self.assertTrue(name.startswith("luks-"))
        # Only the dm-crypt charset the service's valid_mapper_name accepts.
        self.assertTrue(all(c.isalnum() or c in "-_" for c in name))


class TestMountReferences(unittest.TestCase):
    """The client's mounted-state hint mirrors the service's data-loss guard:
    a mapping with a mounted filesystem must be recognized so it can be flagged
    (and the service refuses to close it)."""

    MOUNTS = (
        "proc /proc proc rw 0 0\n"
        "/dev/sda1 /boot ext4 rw 0 0\n"
        "/dev/mapper/luks-abc /mnt/secret ext4 rw 0 0\n"
    )

    def test_matches_mapper_spelling(self):
        self.assertTrue(
            gui.mount_references(self.MOUNTS, "/dev/mapper/luks-abc", "/dev/dm-3")
        )

    def test_matches_resolved_dm_node(self):
        mounts = "/dev/dm-3 /mnt/secret ext4 rw 0 0\n"
        self.assertTrue(
            gui.mount_references(mounts, "/dev/mapper/luks-abc", "/dev/dm-3")
        )

    def test_no_match_when_not_mounted(self):
        self.assertFalse(
            gui.mount_references(self.MOUNTS, "/dev/mapper/luks-other", "/dev/dm-9")
        )

    def test_substring_device_does_not_false_match(self):
        mounts = "/dev/mapper/luks-abc-data /mnt/x ext4 rw 0 0\n"
        self.assertFalse(
            gui.mount_references(mounts, "/dev/mapper/luks-abc", "/dev/dm-3")
        )


# ===========================================================================
# Issue #98 — drop-in takeover of Ubuntu's passphrase-only unlock flow
# ===========================================================================


class TestFetchEnrolledMethods(unittest.TestCase):
    """fetch_enrolled_methods (extracted from DeviceDetailPage's in-page
    unlock prompt so UnlockVolumeDialog can share it, issue #98) aggregates
    enrolled-method data on a background thread and hands the result dict to
    on_done via GLib.idle_add. Same sync-thread pattern as TestRunAsync."""

    @staticmethod
    def _sync_thread(target=None, daemon=None):
        runner = mock.MagicMock()
        runner.start = target
        return runner

    def test_aggregates_all_fields_from_the_service(self):
        svc = mock.MagicMock()
        svc.get_tokens_by_type.side_effect = lambda device, t: {
            gui.TOKEN_FIDO2: [("id1", [1])],
            gui.TOKEN_TPM2: [],
            gui.TOKEN_RECOVERY: [("id2", [2])],
        }[t]
        svc.find_password_keyslots.return_value = [0]
        svc.get_systemd_version.return_value = 256

        captured = []
        with (
            mock.patch.object(gui.threading, "Thread", side_effect=self._sync_thread),
            mock.patch.object(
                gui.GLib, "idle_add", side_effect=lambda *a: captured.append(a)
            ),
        ):
            cb = object()
            gui.fetch_enrolled_methods(svc, "/dev/sdb1", cb)

        self.assertEqual(len(captured), 1)
        cb_arg, data = captured[0]
        self.assertIs(cb_arg, cb)
        self.assertEqual(data["fido2"], [("id1", [1])])
        self.assertEqual(data["tpm2"], [])
        self.assertEqual(data["recovery"], [("id2", [2])])
        self.assertEqual(data["pw_slots"], [0])
        self.assertEqual(data["systemd_version"], 256)

    def test_a_glib_error_on_one_field_does_not_lose_the_others(self):
        class FakeGError(Exception):
            pass

        def raise_for_fido2(device, t):
            if t == gui.TOKEN_FIDO2:
                raise FakeGError("no fido2")
            return []

        svc = mock.MagicMock()
        svc.get_tokens_by_type.side_effect = raise_for_fido2
        svc.find_password_keyslots.return_value = [3]
        svc.get_systemd_version.return_value = 255

        captured = []
        with (
            mock.patch.object(gui.threading, "Thread", side_effect=self._sync_thread),
            mock.patch.object(gui.GLib, "Error", FakeGError),
            mock.patch.object(
                gui.GLib, "idle_add", side_effect=lambda *a: captured.append(a)
            ),
        ):
            gui.fetch_enrolled_methods(svc, "/dev/sdb1", object())

        self.assertEqual(len(captured), 1)
        _cb, data = captured[0]
        self.assertEqual(data["fido2"], [])  # swallowed by the except clause
        self.assertEqual(data["pw_slots"], [3])
        self.assertEqual(data["systemd_version"], 255)


class TestUdisks2PickNewLuksDevice(unittest.TestCase):
    """udisks2_pick_new_luks_device parses a udisks2 InterfacesAdded signal's
    (already GVariant-unpacked) interfaces dict to find newly-appeared
    crypto_LUKS block devices for the --watch listener (issue #98). Pure
    function, no gi dependency, so it's tested directly."""

    @staticmethod
    def _interfaces(id_type="crypto_LUKS", device=b"/dev/sdb1\x00"):
        return {
            "org.freedesktop.UDisks2.Block": {
                "IdType": id_type,
                "Device": device,
            }
        }

    def test_picks_up_a_new_luks_block_device(self):
        self.assertEqual(
            gui.udisks2_pick_new_luks_device(self._interfaces()), "/dev/sdb1"
        )

    def test_device_as_list_of_ints_also_decodes(self):
        # GVariant 'ay' can unpack to a list[int] depending on binding
        # version; the helper must handle either representation.
        raw = list(b"/dev/sdc1\x00")
        self.assertEqual(
            gui.udisks2_pick_new_luks_device(self._interfaces(device=raw)),
            "/dev/sdc1",
        )

    def test_ignores_non_luks_filesystems(self):
        self.assertIsNone(
            gui.udisks2_pick_new_luks_device(self._interfaces(id_type="ext4"))
        )

    def test_ignores_objects_without_a_block_interface(self):
        self.assertIsNone(
            gui.udisks2_pick_new_luks_device({"org.freedesktop.UDisks2.Partition": {}})
        )

    def test_ignores_missing_or_empty_device_path(self):
        self.assertIsNone(
            gui.udisks2_pick_new_luks_device(self._interfaces(device=b""))
        )
        interfaces = self._interfaces()
        del interfaces["org.freedesktop.UDisks2.Block"]["Device"]
        self.assertIsNone(gui.udisks2_pick_new_luks_device(interfaces))


class TestUdisks2PendingBlockDevice(unittest.TestCase):
    """udisks2_pending_block_device feeds --watch's probe-race fallback (the
    PR #100 "no unlock dialog" report): udisks2 can export a Block object
    before its filesystem probe finishes, so InterfacesAdded may carry an
    empty IdType for a volume that is in fact crypto_LUKS — the real type
    only arrives via a later PropertiesChanged. Pure function, tested
    directly like udisks2_pick_new_luks_device above."""

    @staticmethod
    def _interfaces(id_type="", device=b"/dev/sdb1\x00"):
        return {
            "org.freedesktop.UDisks2.Block": {
                "IdType": id_type,
                "Device": device,
            }
        }

    def test_returns_device_when_idtype_is_still_empty(self):
        self.assertEqual(
            gui.udisks2_pending_block_device(self._interfaces()), "/dev/sdb1"
        )

    def test_missing_idtype_key_also_counts_as_unprobed(self):
        interfaces = self._interfaces()
        del interfaces["org.freedesktop.UDisks2.Block"]["IdType"]
        self.assertEqual(gui.udisks2_pending_block_device(interfaces), "/dev/sdb1")

    def test_already_probed_devices_are_never_pending(self):
        # crypto_LUKS at add time is the immediate-launch path
        # (udisks2_pick_new_luks_device); any other concrete filesystem was
        # classified, not raced, and can't become LUKS later.
        self.assertIsNone(
            gui.udisks2_pending_block_device(self._interfaces(id_type="crypto_LUKS"))
        )
        self.assertIsNone(
            gui.udisks2_pending_block_device(self._interfaces(id_type="ext4"))
        )

    def test_ignores_objects_without_a_block_interface_or_device(self):
        self.assertIsNone(
            gui.udisks2_pending_block_device({"org.freedesktop.UDisks2.Partition": {}})
        )
        self.assertIsNone(
            gui.udisks2_pending_block_device(self._interfaces(device=b""))
        )


class TestWatchProbeRaceFallback(unittest.TestCase):
    """Behavioral coverage for the --watch probe-race fallback (PR #100): a
    LUKS volume whose udisks2 filesystem probe finishes *after* the Block
    object is exported must still get an unlock dialog when IdType arrives
    via PropertiesChanged. The decision logic lives in the pure, GTK-free
    Udisks2LuksWatcher (LuksEnrollApp's GTK bases are import-time mocks, so
    the app class itself isn't instantiable here — its handlers just unpack
    the GVariant and delegate)."""

    OBJ = "/org/freedesktop/UDisks2/block_devices/sdb1"

    def _watcher(self, **kwargs):
        launched = []
        watcher = gui.Udisks2LuksWatcher(
            launched.append, log=lambda _msg: None, **kwargs
        )
        return watcher, launched

    def _added(self, watcher, obj_path=OBJ, id_type="", device=b"/dev/sdb1\x00"):
        watcher.interfaces_added(
            obj_path,
            {"org.freedesktop.UDisks2.Block": {"IdType": id_type, "Device": device}},
        )

    def test_late_crypto_luks_probe_launches_the_unlock_dialog(self):
        watcher, launched = self._watcher()
        self._added(watcher)  # IdType still empty at InterfacesAdded time
        self.assertEqual(launched, [])
        self.assertEqual(watcher._pending, {self.OBJ: "/dev/sdb1"})
        watcher.block_properties_changed(self.OBJ, {"IdType": "crypto_LUKS"})
        self.assertEqual(launched, ["/dev/sdb1"])
        self.assertEqual(watcher._pending, {})

    def test_luks_at_add_time_still_launches_immediately(self):
        watcher, launched = self._watcher()
        self._added(watcher, id_type="crypto_LUKS")
        self.assertEqual(launched, ["/dev/sdb1"])
        self.assertEqual(watcher._pending, {})

    def test_probe_resolving_to_another_filesystem_forgets_the_device(self):
        watcher, launched = self._watcher()
        self._added(watcher)
        watcher.block_properties_changed(self.OBJ, {"IdType": "ext4"})
        self.assertEqual(launched, [])
        self.assertEqual(watcher._pending, {})

    def test_properties_changed_for_unknown_paths_is_ignored(self):
        watcher, launched = self._watcher()
        watcher.block_properties_changed(
            "/org/freedesktop/UDisks2/block_devices/zzz",
            {"IdType": "crypto_LUKS"},
        )
        self.assertEqual(launched, [])

    def test_unrelated_property_changes_keep_the_device_pending(self):
        watcher, launched = self._watcher()
        self._added(watcher)
        watcher.block_properties_changed(self.OBJ, {"Size": 4096})
        self.assertEqual(launched, [])
        self.assertEqual(watcher._pending, {self.OBJ: "/dev/sdb1"})

    def test_pending_set_is_capped_and_evicts_oldest_first(self):
        watcher, _launched = self._watcher(max_pending=4)
        for i in range(6):
            self._added(
                watcher,
                obj_path=f"/org/freedesktop/UDisks2/block_devices/sd{i}",
                device=f"/dev/sd{i}\x00".encode(),
            )
        self.assertEqual(len(watcher._pending), 4)
        self.assertNotIn("/org/freedesktop/UDisks2/block_devices/sd0", watcher._pending)
        self.assertIn("/org/freedesktop/UDisks2/block_devices/sd5", watcher._pending)

    def test_default_cap_and_logger_come_from_the_module(self):
        watcher = gui.Udisks2LuksWatcher(lambda _d: None)
        self.assertEqual(watcher._max_pending, gui.WATCH_PENDING_BLOCKS_MAX)
        self.assertIs(watcher._log, gui.journal_log)


class TestUnlockVolumeDialogAndCli(unittest.TestCase):
    """Issue #98: the enrolled-methods unlock prompt is extracted into a
    reusable UnlockVolumeDialog, driven by a new --unlock/--watch CLI
    surface on LuksEnrollApp. GTK page/dialog classes subclass mocked bases
    (MagicMocks at import, per TestKeylessImageCreation's docstring), so
    this asserts on parsed source, the same approach as the other
    structural tests in this file."""

    @classmethod
    def setUpClass(cls):
        with open(GUI_PATH) as f:
            source = f.read()
        tree = ast.parse(source, filename=GUI_PATH)
        cls.classes = {
            node.name: ast.get_source_segment(source, node)
            for node in ast.walk(tree)
            if isinstance(node, ast.ClassDef)
        }
        cls.bases = {
            node.name: [ast.unparse(b) for b in node.bases]
            for node in ast.walk(tree)
            if isinstance(node, ast.ClassDef)
        }
        cls.methods = {
            node.name: {
                n.name: ast.get_source_segment(source, n)
                for n in node.body
                if isinstance(n, ast.FunctionDef)
            }
            for node in ast.walk(tree)
            if isinstance(node, ast.ClassDef)
        }
        cls.top_functions = {
            n.name: ast.get_source_segment(source, n)
            for n in tree.body
            if isinstance(n, ast.FunctionDef)
        }

    # -- UnlockVolumeDialog ------------------------------------------------

    def test_unlock_dialog_subclasses_adw_dialog(self):
        self.assertEqual(self.bases["UnlockVolumeDialog"], ["Adw.Dialog"])

    def test_unlock_dialog_pins_a_content_size_like_format_dialog_base(self):
        dialog = self.classes["UnlockVolumeDialog"]
        self.assertIn("self.set_content_width(", dialog)
        self.assertIn("self.set_content_height(", dialog)

    def test_unlock_dialog_uses_the_shared_enrolled_methods_fetch(self):
        dialog = self.classes["UnlockVolumeDialog"]
        self.assertIn(
            "fetch_enrolled_methods(self.svc, self.device, "
            "self._apply_enrolled_methods)",
            dialog,
        )

    def test_device_detail_page_delegates_to_the_same_shared_helper(self):
        # DeviceDetailPage's in-page prompt was refactored to call the same
        # helper instead of keeping its own duplicate background-fetch
        # code, so the two authentication flows can't drift apart.
        detail = self.classes["DeviceDetailPage"]
        self.assertIn(
            "fetch_enrolled_methods(self.svc, self.device, "
            "self._apply_enrolled_methods)",
            detail,
        )

    def test_unlock_dialog_maps_the_volume_via_open_volume_on_success(self):
        dialog = self.classes["UnlockVolumeDialog"]
        self.assertIn('derive_mapper_name(self.device, info.get("uuid") or "")', dialog)
        self.assertIn("self.svc.open_volume(", dialog)
        self.assertIn('self.device, mapper_name, self.passphrase or ""', dialog)
        self.assertIn("self.unlock_method, self.unlock_pin,", dialog)

    def test_unlock_dialog_reports_mapped_result_and_closes_on_success(self):
        method = self.methods["UnlockVolumeDialog"]["_on_map_done"]
        self.assertIn("self._on_mapped(self.device, mapper)", method)
        self.assertIn("self.close()", method)

    # -- CLI: --unlock / --watch -------------------------------------------

    def test_app_uses_handles_command_line_flag(self):
        app = self.classes["LuksEnrollApp"]
        self.assertIn("Gio.ApplicationFlags.HANDLES_COMMAND_LINE", app)

    def test_do_command_line_parses_unlock_and_watch_switches(self):
        method = self.methods["LuksEnrollApp"]["do_command_line"]
        self.assertIn('"--unlock"', method)
        self.assertIn('"--watch"', method)
        self.assertIn("self._start_watch_mode()", method)
        self.assertIn("self._present_unlock_dialog(ns.unlock)", method)
        # A plain launch (neither switch) falls back to the normal GUI.
        self.assertIn("self.activate()", method)

    def test_present_unlock_dialog_skips_the_management_window(self):
        method = self.methods["LuksEnrollApp"]["_present_unlock_dialog"]
        self.assertIn("UnlockVolumeDialog(svc, device", method)
        # ManagementWindow may be *mentioned* in a docstring/comment
        # explaining what this path deliberately skips, but must never be
        # constructed.
        self.assertNotIn("ManagementWindow(", method)

    def test_present_unlock_dialog_guards_against_a_double_release(self):
        # on_mapped and the dialog's own "closed" signal can both fire on a
        # successful unlock; release() must not be called twice (it would
        # underflow the GApplication hold count).
        method = self.methods["LuksEnrollApp"]["_present_unlock_dialog"]
        self.assertIn("released", method)
        self.assertIn('dialog.connect("closed"', method)

    def test_watch_mode_subscribes_to_udisks2_interfaces_added(self):
        method = self.methods["LuksEnrollApp"]["_start_watch_mode"]
        self.assertIn("UDISKS2_BUS_NAME", method)
        self.assertIn("UDISKS2_OBJECT_MANAGER_PATH", method)
        self.assertIn('"InterfacesAdded"', method)
        self.assertIn("signal_subscribe", method)

    def test_watch_mode_is_idempotent_against_a_repeat_invocation(self):
        method = self.methods["LuksEnrollApp"]["_start_watch_mode"]
        self.assertIn("if self._watch_subscription is not None:", method)

    def test_interfaces_added_handler_delegates_to_the_pure_watcher(self):
        # The classification/bookkeeping logic (including the pure
        # udisks2_pick_new_luks_device picker) lives in Udisks2LuksWatcher
        # so it stays behaviorally testable; the GTK-side handler only
        # unpacks the GVariant and delegates.
        method = self.methods["LuksEnrollApp"]["_on_udisks2_interfaces_added"]
        self.assertIn("self._watcher.interfaces_added(obj_path, interfaces)", method)
        watcher = self.classes["Udisks2LuksWatcher"]
        self.assertIn("udisks2_pick_new_luks_device(interfaces)", watcher)

    def test_watch_mode_also_subscribes_to_block_properties_changed(self):
        # Probe-race fallback (PR #100): a second subscription catches
        # IdType arriving after InterfacesAdded, arg0-filtered to the
        # udisks2 Block interface with no fixed object path (each block
        # object emits from its own path).
        method = self.methods["LuksEnrollApp"]["_start_watch_mode"]
        self.assertIn('"PropertiesChanged"', method)
        self.assertIn('"org.freedesktop.DBus.Properties"', method)
        self.assertIn("UDISKS2_BLOCK_IFACE", method)
        self.assertIn("self._on_udisks2_block_properties_changed", method)

    def test_properties_changed_handler_delegates_to_the_pure_watcher(self):
        method = self.methods["LuksEnrollApp"]["_on_udisks2_block_properties_changed"]
        self.assertIn("self._watcher.block_properties_changed(path, changed)", method)
        watcher = self.classes["Udisks2LuksWatcher"]
        self.assertIn("udisks2_pending_block_device(interfaces)", watcher)

    def test_watch_mode_creates_the_watcher_wired_to_launch_unlock(self):
        method = self.methods["LuksEnrollApp"]["_start_watch_mode"]
        self.assertIn(
            "self._watcher = Udisks2LuksWatcher(self._launch_unlock_for)", method
        )

    def test_every_watch_and_unlock_decision_point_logs_to_the_journal(self):
        # The PR #100 "no unlock dialog" report was undebuggable because
        # failures only whispered to stderr without a stable prefix. Each
        # step of the chain must emit a greppable `luks-enroll:` journal
        # line via journal_log (autostart stderr lands in `journalctl
        # --user`), so the journal always shows *why* nothing appeared.
        for name in (
            "_present_unlock_dialog",
            "_start_watch_mode",
            "_launch_unlock_for",
        ):
            self.assertIn(
                "journal_log(",
                self.methods["LuksEnrollApp"][name],
                f"{name} must journal_log its outcome",
            )
        # The udisks2 signal handlers log through the watcher's injected
        # logger, which defaults to journal_log (pinned behaviorally by
        # TestWatchProbeRaceFallback.test_default_cap_and_logger_come_from
        # _the_module); every decision branch in the watcher logs too.
        watcher = self.classes["Udisks2LuksWatcher"]
        self.assertIn("log=journal_log", watcher)
        self.assertIn(
            "self._log(", self.methods["Udisks2LuksWatcher"]["interfaces_added"]
        )
        self.assertIn(
            "self._log(",
            self.methods["Udisks2LuksWatcher"]["block_properties_changed"],
        )

    def test_journal_log_prefixes_and_flushes(self):
        src = self.top_functions["journal_log"]
        self.assertIn('f"luks-enroll: {message}"', src)
        self.assertIn("file=sys.stderr", src)
        self.assertIn("flush=True", src)

    def test_launch_unlock_for_spawns_the_unlock_subprocess(self):
        method = self.methods["LuksEnrollApp"]["_launch_unlock_for"]
        self.assertIn('["luks-enroll", "--unlock", device]', method)

    def test_main_delegates_argv_parsing_to_do_command_line(self):
        main_src = self.top_functions["main"]
        self.assertIn("app.run(sys.argv)", main_src)
        # Now that HANDLES_COMMAND_LINE routes everything through
        # do_command_line, main() no longer needs its own argparse pre-parse.
        self.assertNotIn("parse_known_args()", main_src)


class TestDropInUnlockTakeoverAssets(unittest.TestCase):
    """Issue #98 ships two non-Python assets alongside the CLI/dialog work:
    a udev rule suppressing the stock GNOME auto-unlock prompt for
    removable LUKS volumes, and an XDG autostart entry launching the
    --watch listener. Pinned directly from disk since there's no Python
    module to import for either."""

    DIST_ROOT = os.path.join(os.path.dirname(GUI_PATH), "..", "..")
    UDEV_RULE = os.path.join(
        DIST_ROOT,
        "usr",
        "lib",
        "udev",
        "rules.d",
        "71-luks-enroll-suppress-auto-unlock.rules",
    )
    AUTOSTART = os.path.join(
        DIST_ROOT,
        "etc",
        "xdg",
        "autostart",
        "net.contemno.luks-enroll-watch.desktop",
    )

    def test_udev_rule_files_exist(self):
        self.assertTrue(os.path.isfile(self.UDEV_RULE))
        self.assertTrue(os.path.isfile(self.AUTOSTART))

    def test_udev_rule_targets_crypto_luks_and_sets_udisks_auto(self):
        with open(self.UDEV_RULE) as f:
            rule = f.read()
        self.assertIn('ENV{ID_FS_TYPE}=="crypto_LUKS"', rule)
        self.assertIn("ENV{UDISKS_AUTO}=", rule)
        # UDISKS_IGNORE hides the device from udisksctl/Disks/Nautilus
        # entirely — not what a "suppress just the auto-unlock prompt" rule
        # should use. UDISKS_IGNORE may appear in the explanatory comment
        # header (documenting why it was rejected), but the active rule
        # line itself must not set it.
        active_lines = [
            line
            for line in rule.splitlines()
            if line.strip() and not line.strip().startswith("#")
        ]
        self.assertTrue(active_lines)
        for line in active_lines:
            self.assertNotIn("UDISKS_IGNORE", line)

    def test_udev_rule_is_gated_to_removable_media_on_every_active_line(self):
        with open(self.UDEV_RULE) as f:
            rule = f.read()
        active_lines = [
            line
            for line in rule.splitlines()
            if line.strip() and not line.strip().startswith("#")
        ]
        # Exactly one active rule line, shipped enabled (not commented out —
        # the maintainer's explicit instruction on issue #98 was to ship it
        # enabled by default, with no opt-in gate).
        self.assertEqual(len(active_lines), 1)
        # The hard safety requirement: every occurrence of the crypto_LUKS
        # match must be paired with the removable gate on the same line, so
        # this can never suppress the prompt for an internal root/home
        # volume, only hot-pluggable media.
        for line in active_lines:
            if 'ID_FS_TYPE}=="crypto_LUKS"' in line:
                self.assertIn('ATTRS{removable}=="1"', line)

    def test_autostart_entry_launches_the_watch_switch_enabled_by_default(self):
        with open(self.AUTOSTART) as f:
            entry = f.read()
        self.assertIn("Exec=/usr/bin/luks-enroll --watch", entry)
        self.assertIn("X-GNOME-Autostart-enabled=true", entry)
        self.assertIn("Type=Application", entry)


if __name__ == "__main__":
    unittest.main()
