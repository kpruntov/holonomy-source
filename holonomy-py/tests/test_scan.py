# @trace TASK-052
import pytest
import pyarrow as pa
import polars as pl
import holonomy


import os
TEST_DIR = os.path.dirname(os.path.abspath(__file__))
SAMPLE_PATH = os.path.abspath(os.path.join(TEST_DIR, "../../holonomy-core/tests/sample.parquet"))

def test_lazy_scan_returns_valid_reader():
    os.environ["HOLONOMY_PUBLIC_KEY"] = "0" * 64
    os.environ["HOLONOMY_JWKS_URL"] = "file:///home/pruntoff/projects/holonomy/test_fixtures/dummy_jwks.json"
    os.environ["HOLONOMY_ISSUER"] = "holonomy-test-issuer"
    os.environ["HOLONOMY_AUDIENCE"] = "holonomy-test-audience"
    os.environ["HOLONOMY_POLICY_BUCKET"] = "mock"
    os.environ["AWS_SECRET_ACCESS_KEY"] = "test"
    # Call scan (our mock implementation returns an empty stream with empty schema)
    reader = holonomy.scan(f"file://{SAMPLE_PATH}", columns_to_read=["id"], user_context="eyJhbGciOiJSUzI1NiIsImtpZCI6InRlc3Qta2V5LWlkIiwidHlwIjoiSldUIn0.eyJzdWIiOiJ0ZXN0X3VzZXIiLCJncm91cHMiOltdLCJpc3MiOiJob2xvbm9teS10ZXN0LWlzc3VlciIsImF1ZCI6ImhvbG9ub215LXRlc3QtYXVkaWVuY2UiLCJleHAiOjI1MzQwMjMwMDc5OX0.MmCKgnm8epv4yGXQR6xD7FVBoa3O7dV6hpy62qLKUVC4gY7ev-xVtsBwn6zeZTuJxnnAcNwtCfI7P_hOUQ8p-oOUuNfdWMefWoU6KyAcYIk1_oLW86yvfmuTksg7cZnO9M6YGl_I7yaMGcJMZKEWvSviigS_CBPl6OTLfKid0GzeK4wxPjacdfQ7HGrQUowySyb0C5Q3ZOE80O5n6OlVjpUhbc8RuWlOs6PwWjCYosQgQpMVKB2swpJdo0x7TnIwvxoFooLT71f4jCvEfPGj3m0tVMBVBomKAGQWJgveWvbPJkLPE86NgBt8T40RT7xbZnroWhZdT33192wNahz3WA", purpose="test")
    
    # Check that it's a PyArrow RecordBatchReader
    assert hasattr(reader, 'schema')
    
    # Read all batches
    table = reader.read_all()
    assert table.num_rows == 3
    assert table.num_columns == 1

def test_lazy_scan_polars_integration():
    os.environ["HOLONOMY_PUBLIC_KEY"] = "0" * 64
    os.environ["HOLONOMY_JWKS_URL"] = "file:///home/pruntoff/projects/holonomy/test_fixtures/dummy_jwks.json"
    os.environ["HOLONOMY_ISSUER"] = "holonomy-test-issuer"
    os.environ["HOLONOMY_AUDIENCE"] = "holonomy-test-audience"
    os.environ["HOLONOMY_POLICY_BUCKET"] = "mock"
    os.environ["AWS_REGION"] = "us-east-1"
    os.environ["AWS_ACCESS_KEY_ID"] = "test"
    os.environ["AWS_SECRET_ACCESS_KEY"] = "test"
    reader = holonomy.scan(f"file://{SAMPLE_PATH}", columns_to_read=["id"], user_context="eyJhbGciOiJSUzI1NiIsImtpZCI6InRlc3Qta2V5LWlkIiwidHlwIjoiSldUIn0.eyJzdWIiOiJ0ZXN0X3VzZXIiLCJncm91cHMiOltdLCJpc3MiOiJob2xvbm9teS10ZXN0LWlzc3VlciIsImF1ZCI6ImhvbG9ub215LXRlc3QtYXVkaWVuY2UiLCJleHAiOjI1MzQwMjMwMDc5OX0.MmCKgnm8epv4yGXQR6xD7FVBoa3O7dV6hpy62qLKUVC4gY7ev-xVtsBwn6zeZTuJxnnAcNwtCfI7P_hOUQ8p-oOUuNfdWMefWoU6KyAcYIk1_oLW86yvfmuTksg7cZnO9M6YGl_I7yaMGcJMZKEWvSviigS_CBPl6OTLfKid0GzeK4wxPjacdfQ7HGrQUowySyb0C5Q3ZOE80O5n6OlVjpUhbc8RuWlOs6PwWjCYosQgQpMVKB2swpJdo0x7TnIwvxoFooLT71f4jCvEfPGj3m0tVMBVBomKAGQWJgveWvbPJkLPE86NgBt8T40RT7xbZnroWhZdT33192wNahz3WA", purpose="test")
    
    # Polars can ingest PyArrow RecordBatchReaders natively
    # Using `scan_pyarrow_dataset` or `from_arrow`
    df = pl.from_arrow(reader)
    
    assert df.height == 3
    assert df.width == 1
