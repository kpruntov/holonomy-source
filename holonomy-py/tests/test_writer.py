import pyarrow as pa
import pytest
import holonomy
import json
import os
from pathlib import Path

def test_writer_context_manager():
    os.environ["HOLONOMY_JWKS_URL"] = "file:///home/pruntoff/projects/holonomy/test_fixtures/dummy_jwks.json"
    os.environ["HOLONOMY_ISSUER"] = "holonomy-test-issuer"
    os.environ["HOLONOMY_AUDIENCE"] = "holonomy-test-audience"
    os.environ["HOLONOMY_ISSUER"] = "mock"
    os.environ["HOLONOMY_PUBLIC_KEY"] = "0000000000000000000000000000000000000000000000000000000000000000"
    os.environ["HOLONOMY_KMS_PROVIDER"] = "mock"
    os.environ["HOLONOMY_POLICY_BUCKET"] = "mock"
    
    # Setup dummy data
    schema = pa.schema([
        ('id', pa.int32()),
        ('name', pa.string())
    ])
    batch1 = pa.RecordBatch.from_arrays([
        pa.array([1, 2]),
        pa.array(['alice', 'bob'])
    ], schema=schema)
    batch2 = pa.RecordBatch.from_arrays([
        pa.array([3, 4]),
        pa.array(['charlie', 'david'])
    ], schema=schema)

    contract = {
        "name": "test_contract",
        "domain": "test",
        "dataset": "users",
        "version": "1.0",
        "columns": [
            {"name": "id", "type": "int32", "nullable": False, "required": True},
            {"name": "name", "type": "string", "nullable": False, "required": True}
        ]
    }
    
    target = "file:///tmp/test_writer_output.parquet"
    if os.path.exists("/tmp/test_writer_output.parquet"):
        os.remove("/tmp/test_writer_output.parquet")
    
    # Write iteratively
    with holonomy.Writer(
        target=target,
        user_context='{"sub": "test-user", "roles": ["admin"]}',
        purpose="testing context manager",
        contract_json=json.dumps(contract)
    ) as writer:
        writer.write_batch(batch1)
        writer.write_batch(batch2)
        
    assert os.path.exists("/tmp/test_writer_output.parquet")
    assert os.path.exists("/tmp/test_writer_output.parquet")
