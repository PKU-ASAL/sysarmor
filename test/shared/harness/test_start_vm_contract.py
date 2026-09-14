import os
import subprocess
import tempfile
import unittest
from pathlib import Path


class StartVMContractTest(unittest.TestCase):
    def test_topology_offline_bundle_includes_ui_images(self):
        script = (Path(__file__).resolve().parent / "start-vm.sh").read_text()

        self.assertIn("nginx:alpine", script)
        self.assertIn("node:24-alpine", script)

    def test_topology_initializes_manager_ui_secrets(self):
        script = (Path(__file__).resolve().parent / "start-vm.sh").read_text()

        self.assertIn(
            '"$REPO/tools/auth/init-bootstrap-admin.sh" "$PKI_DIR"', script
        )

    def test_topology_initializes_content_signing_key(self):
        script = (Path(__file__).resolve().parent / "start-vm.sh").read_text()

        self.assertIn(
            'openssl genpkey -algorithm ED25519 -out "$PKI_DIR/content-signing-key.pem"',
            script,
        )

    def test_topology_waits_for_all_streaming_jobs(self):
        script = (Path(__file__).resolve().parent / "start-vm.sh").read_text()

        self.assertIn("Flink jobs did not become RUNNING", script)
        for job in ("sysarmor-normalize-v1", "sysarmor-detection-v1", "sysarmor-projection-v1"):
            self.assertIn(job, script)

    def test_topology_uploads_platform_as_archive(self):
        script = (Path(__file__).resolve().parent / "start-vm.sh").read_text()

        self.assertIn('tar -C "$PLATFORM_UPLOAD_DIR" -cf "$PLATFORM_SOURCE_BUNDLE" .', script)
        self.assertIn(
            'vm_upload "$PLATFORM_SOURCE_BUNDLE" /tmp/sysarmor-platform.tar mgr',
            script,
        )
        self.assertNotIn(
            'vagrant upload "$PLATFORM_UPLOAD_DIR" /tmp/sysarmor-platform.upload mgr',
            script,
        )

    def test_topology_excludes_local_working_state_from_platform_archive(self):
        script = (Path(__file__).resolve().parent / "start-vm.sh").read_text()

        for directory in (
            ".agents/",
            ".codex/",
            ".run/",
            ".scratchpad/",
            ".superpowers/",
            "**/.venv/",
            "**/.pytest_cache/",
            "**/__pycache__/",
            "**/node_modules/",
        ):
            with self.subTest(directory=directory):
                self.assertIn(f"--exclude '{directory}'", script)

    def test_topology_logs_large_upload_and_readiness_progress(self):
        script = (Path(__file__).resolve().parent / "start-vm.sh").read_text()

        self.assertIn("uploading platform source", script)
        self.assertIn("uploading VM image bundle", script)
        self.assertIn("waiting for manager/gateway health", script)
        self.assertIn("waiting for Flink jobs", script)

    def test_topology_rebuilds_staging_directory_before_rsync(self):
        script = (Path(__file__).resolve().parent / "start-vm.sh").read_text()

        reset = script.index('rm -rf "$PLATFORM_UPLOAD_DIR"')
        rsync = script.index("rsync -a --delete", reset)
        self.assertLess(reset, rsync)

    def test_topology_platform_archive_is_ignored(self):
        repo = Path(__file__).resolve().parents[3]
        gitignore = (repo / ".gitignore").read_text().splitlines()

        self.assertIn("test/environments/vm-topology/deploy/platform.tar", gitignore)

    def test_builds_all_binaries_before_starting_endpoint_vm(self):
        harness_dir = Path(__file__).resolve().parent
        repo = harness_dir.parents[2]

        with tempfile.TemporaryDirectory() as temp_dir:
            bin_dir = Path(temp_dir)
            calls = bin_dir / "make.calls"
            self._write_executable(
                bin_dir / "make",
                f'#!/usr/bin/env bash\nprintf "%s\\n" "$*" >> "{calls}"\n',
            )
            self._write_executable(bin_dir / "vagrant", "#!/usr/bin/env bash\nexit 0\n")

            env = os.environ.copy()
            env["PATH"] = f"{bin_dir}:{env['PATH']}"
            subprocess.run(
                ["bash", str(harness_dir / "start-vm.sh"), "vm-endpoint"],
                check=True,
                env=env,
                capture_output=True,
                text=True,
            )

            self.assertEqual(calls.read_text().strip(), f"-C {repo} build-binary")

    @staticmethod
    def _write_executable(path: Path, content: str):
        path.write_text(content)
        path.chmod(0o755)


if __name__ == "__main__":
    unittest.main()
