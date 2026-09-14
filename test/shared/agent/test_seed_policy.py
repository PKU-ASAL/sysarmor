import importlib.util
import io
import json
import subprocess
from pathlib import Path
from urllib.error import HTTPError
from unittest.mock import patch

import pytest


def load_helper():
    path = Path(__file__).with_name("seed_policy.py")
    assert path.is_file(), "idempotent seed helper is missing"
    spec = importlib.util.spec_from_file_location("seed_policy", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def desired():
    return {"tenant_id": "default", "policy_id": "standalone-default", "version": 1,
            "published": False, "collection": {"behaviors": ["process.exec"], "observe_only": True}}


class Manager:
    def __init__(self, stored=None, error=None):
        self.stored, self.error, self.methods = stored, error, []

    def open(self, request, timeout):
        self.methods.append(request.get_method())
        if self.error or (request.get_method() == "GET" and self.stored is None):
            status = self.error or 404
            raise HTTPError(request.full_url, status, "failed", {},
                            io.BytesIO(b'{"error":{"message":"policy request failed"}}'))
        if request.get_method() == "POST":
            self.stored = json.loads(request.data)
        return io.BytesIO(json.dumps(self.stored).encode())


def test_second_seed_reuses_published_policy_without_post():
    helper, manager = load_helper(), Manager()
    with patch.object(helper, "urlopen", manager.open):
        first = helper.ensure_policy(desired(), "test-token")
        assert first["published"] is False
        manager.stored["published"] = True
        manager.stored["created_at"] = "2026-09-14T00:00:00Z"
        manager.stored["collection"].pop("observe_only")
        second = helper.ensure_policy(desired(), "test-token")
    assert second["published"] is True
    assert manager.methods == ["GET", "POST", "GET"]


def test_existing_unpublished_policy_is_returned_for_publication():
    helper, manager = load_helper(), Manager(desired())
    with patch.object(helper, "urlopen", manager.open):
        assert helper.ensure_policy(desired(), "test-token")["published"] is False
    assert manager.methods == ["GET"]


def test_conflicting_content_is_not_overwritten():
    helper = load_helper()
    stored = desired()
    stored["collection"]["behaviors"] = ["file.write"]
    manager = Manager(stored)
    with patch.object(helper, "urlopen", manager.open):
        with pytest.raises(ValueError, match="content conflict"):
            helper.ensure_policy(desired(), "test-token")
    assert manager.methods == ["GET"]


@pytest.mark.parametrize("status", [401, 409, 502])
def test_http_failures_keep_status_and_body_without_creating(status):
    helper, manager = load_helper(), Manager(error=status)
    with patch.object(helper, "urlopen", manager.open):
        with pytest.raises(RuntimeError, match=f"HTTP {status}.*policy request failed"):
            helper.ensure_policy(desired(), "test-token")
    assert manager.methods == ["GET"]


def test_managed_agent_is_not_enrolled_twice(tmp_path):
    (tmp_path / "manager-jwt-private.pem").touch()
    script = Path(__file__).with_name("managed_enrollment.sh")
    command = '''
source "$1"
sa_manager_seed_policy_history() { return 0; }
vagrant() {
  case "$*" in
    *"agent health"*) printf '%s\\n' '{"agentId":"agent-a","tenantId":"default","localStore":{"mode":"managed"}}' ;;
    *"rm -f"*) return 0 ;;
    *) echo "unexpected enrollment command" >&2; return 99 ;;
  esac
}
sa_agent_enroll_managed_topology "$2" "$2" "$2" /run/agent.sock agent-a
'''
    result = subprocess.run(["bash", "-c", command, "test", str(script), str(tmp_path)],
                            capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert "reusing managed Agent" in result.stdout
