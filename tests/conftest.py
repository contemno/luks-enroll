"""Shared test fixtures and module-loading shim.

Both test_luks_enroll.py and test_workflows.py need to import the GUI/service
scripts directly from `dist/`. They aren't real Python modules — they're
shebang-style scripts that pull in `gi` for GTK at the top, which we don't
have available in the test environment. This module provides one importer
shared by all test files.
"""

import importlib
import importlib.util
import os
import sys
from importlib.machinery import SourceFileLoader
from unittest import mock


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SERVICE_PATH = os.path.join(ROOT, "dist", "usr", "sbin", "luks-enroll-service")
GUI_PATH = os.path.join(ROOT, "dist", "usr", "bin", "luks-enroll")


def load_module(mod_name, path):
    """Load a script as a Python module with `gi` mocked out."""
    loader = SourceFileLoader(mod_name, path)
    spec = importlib.util.spec_from_loader(mod_name, loader)
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
