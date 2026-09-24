# @trace TASK-029
# @trace TASK-030
# @trace TASK-075
import pytest
import sys
import subprocess
import textwrap

def run_isolated_python_code(code_str, cwd=None):
    """Run python code in a fully isolated subprocess to prevent Rust OnceLock contamination."""
    try:
        subprocess.run(
            [sys.executable, "-c", textwrap.dedent(code_str)],
            check=True,
            capture_output=True,
            text=True,
            cwd=cwd
        )
    except subprocess.CalledProcessError as e:
        pytest.fail(f"Isolated test failed.\nSTDOUT:\n{e.stdout}\nSTDERR:\n{e.stderr}")

def test_init_programmatic_overrides():
    """Test that holonomy.init() correctly sets programmatic overrides."""
    code = """
        import holonomy
        import os
        os.environ["HOLONOMY_PUBLIC_KEY"] = "0" * 64
        os.environ["HOLONOMY_JWKS_URL"] = "file:///home/pruntoff/projects/holonomy/test_fixtures/dummy_jwks.json"
        os.environ["HOLONOMY_ISSUER"] = "holonomy-test-issuer"
        os.environ["HOLONOMY_AUDIENCE"] = "holonomy-test-audience"
        os.environ["HOLONOMY_POLICY_BUCKET"] = "mock"
        os.environ["HOLONOMY_KMS_PROVIDER"] = "mock"
        holonomy.init(
            kms_endpoint="https://custom.kms.local", 
            kms_region="us-east-1",
            policy_bucket="my-policies",
            cache_ttl_hours=42
        )
        
        endpoint, region, bucket, ttl = holonomy._get_active_config()
        assert endpoint == "https://custom.kms.local"
        assert region == "us-east-1"
        assert bucket == "my-policies"
        assert ttl == 42
        
        # Test read() handles missing S3 URL gracefully (Integration Gate)
        try:
            token = open("/home/pruntoff/projects/holonomy/test_fixtures/dummy_token.txt").read().strip()
            result = holonomy.read("dummy_target", user_context=token, columns_to_read=["dummy"])
        except RuntimeError as e:
            assert "Missing purpose metadata" in str(e) or "Ingestion error: Http" in str(e) or "relative URL without a base" in str(e)
    """
    run_isolated_python_code(code)

def test_read_without_init_implicitly_resolves():
    """Test that read() works even if init() wasn't called explicitly."""
    code = """
        import holonomy
        import os
        os.environ["HOLONOMY_PUBLIC_KEY"] = "0" * 64
        os.environ["HOLONOMY_JWKS_URL"] = "file:///home/pruntoff/projects/holonomy/test_fixtures/dummy_jwks.json"
        os.environ["HOLONOMY_ISSUER"] = "holonomy-test-issuer"
        os.environ["HOLONOMY_AUDIENCE"] = "holonomy-test-audience"
        os.environ["HOLONOMY_POLICY_BUCKET"] = "mock"
        os.environ["HOLONOMY_CACHE_TTL_HOURS"] = "99"
        
        try:
            token = open("/home/pruntoff/projects/holonomy/test_fixtures/dummy_token.txt").read().strip()
            result = holonomy.read("another_target", user_context=token, columns_to_read=["dummy"])
        except RuntimeError as e:
            assert "Missing purpose metadata" in str(e) or "Ingestion error: Http" in str(e) or "relative URL without a base" in str(e)
        
        # Verify implicit resolution happened
        endpoint, region, bucket, ttl = holonomy._get_active_config()
        assert ttl == 99
    """
    run_isolated_python_code(code)

def test_reinitialization_fails():
    """Test that calling init() multiple times fails explicitly."""
    code = """
        import holonomy
        
        holonomy.init(cache_ttl_hours=10)
        
        try:
            holonomy.init(cache_ttl_hours=20)
        except RuntimeError as e:
            assert "already initialized" in str(e)
        else:
            raise AssertionError("Expected RuntimeError when initializing twice")
    """
    run_isolated_python_code(code)

def test_missing_jwks_url_fails():
    code = """
        import holonomy
        import os
        os.environ["HOLONOMY_PUBLIC_KEY"] = "0" * 64
        os.environ["HOLONOMY_POLICY_BUCKET"] = "mock"
        if "HOLONOMY_JWKS_URL" in os.environ:
            del os.environ["HOLONOMY_JWKS_URL"]
        try:
            holonomy.read("dummy", user_context='{"sub": "test", "groups": []}', columns_to_read=["dummy"])
        except RuntimeError as e:
            assert "environment variable is required" in str(e) or "MissingIdentityConfigurationError" in str(e)
        else:
            raise AssertionError("Expected error")
    """
    run_isolated_python_code(code, cwd="/tmp")
