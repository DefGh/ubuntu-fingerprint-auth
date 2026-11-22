import importlib.util
import json
import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


source = Path(__file__).resolve().parent.parent / "src" / "configure.py"
spec = importlib.util.spec_from_file_location("fingerprint_configuration", source)
configuration = importlib.util.module_from_spec(spec)
spec.loader.exec_module(configuration)

SUDO = "#%PAM-1.0\n\nauth sufficient pam_fprintd.so max-tries=3 timeout=10\n@include common-auth\n@include common-account\n"
POLKIT = "#%PAM-1.0\n\n@include common-auth\n@include common-account\n"


class PackageConfigurationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        self.pam = root / "pam.d"
        self.pam.mkdir()
        self.vendor = root / "vendor-polkit"
        self.vendor.write_text(POLKIT)
        self.state = root / "saved" / "originals.json"
        for name in ("sudo", "sudo-i"):
            service = self.pam / name
            service.write_text(SUDO)
            service.chmod(0o644)
        self.vendor.chmod(0o644)
        paths = patch.multiple(configuration, PAM=self.pam, VENDOR_POLKIT=self.vendor, STATE=self.state)
        paths.start()
        self.addCleanup(paths.stop)

    def read(self, service):
        return (self.pam / service).read_text()

    def assert_restored(self):
        self.assertEqual(self.read("sudo"), SUDO)
        self.assertEqual(self.read("sudo-i"), SUDO)
        self.assertEqual(self.vendor.read_text(), POLKIT)
        self.assertFalse((self.pam / "polkit-1").exists())
        self.assertFalse(self.state.exists())

    def test_install_reinstall_and_remove(self):
        configuration.install()
        for service in configuration.SERVICES:
            contents = self.read(service)
            self.assertEqual(contents.count(configuration.RULE), 1)
            self.assertNotIn("auth sufficient pam_fprintd.so", contents)
            self.assertLess(contents.index(configuration.RULE), contents.index("@include common-auth"))
        self.assertEqual(stat.S_IMODE(self.state.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE((self.pam / "sudo").stat().st_mode), 0o644)

        original_snapshot = self.state.read_text()
        configuration.install()
        self.assertEqual(self.state.read_text(), original_snapshot)
        configuration.uninstall()
        self.assert_restored()

    def test_upgrade_from_menu_version_restores_original_files(self):
        configuration.install()
        snapshot = json.loads(self.state.read_text())
        for service, data in snapshot.items():
            legacy = data["installed"].replace(configuration.RULE, configuration.LEGACY_RULE)
            (self.pam / service).write_text(legacy)
            data["installed"] = legacy
        self.state.write_text(json.dumps(snapshot))

        configuration.install()
        self.assertNotIn(configuration.LEGACY_RULE, self.read("polkit-1"))
        self.assertIn(configuration.RULE, self.read("polkit-1"))
        configuration.uninstall()
        self.assert_restored()

    def test_remove_preserves_local_edits(self):
        configuration.install()
        changed = self.read("sudo") + "# Added by the local administrator\n"
        (self.pam / "sudo").write_text(changed)
        configuration.uninstall()
        self.assertEqual(self.read("sudo"), changed.replace(configuration.RULE, ""))
        self.assertEqual(self.read("sudo-i"), SUDO)
        self.assertFalse((self.pam / "polkit-1").exists())

    def test_rejects_mandatory_auth_rule_after_common_auth(self):
        custom = POLKIT + "auth required pam_example.so\n"
        (self.pam / "polkit-1").write_text(custom)
        with self.assertRaisesRegex(ValueError, "Unexpected auth rule after common-auth"):
            configuration.install()
        self.assertEqual(self.read("polkit-1"), custom)
        self.assertEqual(self.read("sudo"), SUDO)
        self.assertEqual(self.read("sudo-i"), SUDO)
        self.assertFalse(self.state.exists())


if __name__ == "__main__":
    unittest.main()
