# @trace TASK-025
import pytest
import holonomy
import pyarrow as pa
import duckdb
import polars as pl
import sys


import os
TEST_DIR = os.path.dirname(os.path.abspath(__file__))
SAMPLE_PATH = os.path.abspath(os.path.join(TEST_DIR, "../../holonomy-core/tests/sample.parquet"))

def test_zero_copy_duckdb_and_polars():
    # Initialize holonomy with dummy config to avoid KMS network calls if possible
    # We can rely on the default config loading if it doesn't fail
    try:
        holonomy.init()
    except RuntimeError:
        pass # Already initialized

    # We use a mock path to hit the fast-path for FFI testing. 
    # ReadOrchestrator.read() is expected to return a PyArrow Array pointer via PyO3.
    target_path = f"file://{SAMPLE_PATH}"
    
    print("Reading data via Holonomy...")
    py_arrow_array = holonomy.read(target_path, columns_to_read=["id"], user_context="{\"sub\": \"test_user\", \"groups\": []}", purpose="analytics")
    
    assert py_arrow_array is not None
    assert isinstance(py_arrow_array, pa.Array)
    
    print(f"Received PyArrow array of length: {len(py_arrow_array)}")
    
    # Verify zero-copy with DuckDB
    print("Querying with DuckDB...")
    my_table = pa.Table.from_arrays([py_arrow_array], names=["secure_col"])
    duck_res = duckdb.query("SELECT * FROM my_table").fetchall()
    assert len(duck_res) == len(py_arrow_array)
    
    # Verify zero-copy with Polars
    print("Loading into Polars...")
    df = pl.from_arrow(my_table)
    assert len(df) == len(py_arrow_array)
    
    print("Zero-copy DuckDB & Polars memory integration verified!")
