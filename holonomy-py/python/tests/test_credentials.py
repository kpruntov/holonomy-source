import pytest
import os
import holonomy
from unittest.mock import patch
from pathlib import Path

def test_implicit_credentials_env():
    # We expect `holonomy.read` to resolve user_context from environment if not provided
    with patch.dict(os.environ, {"HOLONOMY_JWT": "env_jwt_token"}):
        try:
            # We don't want to actually run the Rust engine, we just want to verify Python passes the string.
            # But the Rust engine will throw "Invalid JWT" or "MissingIdentityError".
            # If it throws MissingIdentityError, it means our Python wrapper didn't pass the env var.
            # If it throws JWT validation failed, it means it *did* pass the env var.
            holonomy.read("file:///tmp/dummy")
        except Exception as e:
            err_msg = str(e)
            assert "MissingIdentityError" not in err_msg, "Python layer failed to inject credentials from environment"

def test_implicit_credentials_file(tmp_path):
    cred_dir = tmp_path / ".holonomy"
    cred_dir.mkdir()
    cred_file = cred_dir / "credentials"
    cred_file.write_text("file_jwt_token")
    
    with patch.dict(os.environ, {}, clear=True):
        with patch.object(Path, 'home', return_value=tmp_path):
            try:
                holonomy.read("file:///tmp/dummy")
            except Exception as e:
                err_msg = str(e)
                assert "MissingIdentityError" not in err_msg, "Python layer failed to inject credentials from file"
