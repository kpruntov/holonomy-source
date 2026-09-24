import pytest
import pyarrow.compute as pc
import json
import sys
import os

# Import the Python wrapper from our new python structure
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../python')))
from holonomy import serialize_filters

class MockExpr:
    def __init__(self, op, args=None):
        self._op = op
        self._args = args or []
    
    @property
    def op(self):
        return self._op
        
    @property
    def args(self):
        return self._args

def test_ast_translation_to_json():
    # Example pyarrow filter: pc.field("age") == 25
    # Since PyArrow Expression internals (op/args) are opaque in some versions,
    # we mock the AST structure the wrapper expects.
    expr = MockExpr("equal", [
        MockExpr("field_ref", ["age"]),
        25
    ])
    
    json_str = serialize_filters(expr)
    assert json_str is not None
    
    parsed = json.loads(json_str)
    assert len(parsed) == 1
    assert parsed[0]["op"] == "Eq"
    assert parsed[0]["column"] == "age"
    assert "Int64" in parsed[0]["value"]
    assert parsed[0]["value"]["Int64"] == 25

def test_ast_translation_string():
    expr = MockExpr("equal", [
        MockExpr("field_ref", ["name"]),
        "Alice"
    ])
    
    json_str = serialize_filters(expr)
    parsed = json.loads(json_str)
    assert len(parsed) == 1
    assert parsed[0]["op"] == "Eq"
    assert parsed[0]["column"] == "name"
    assert parsed[0]["value"]["String"] == "Alice"

def test_ast_translation_compound_and():
    # (age > 10) & (age < 50)
    left = MockExpr("greater", [MockExpr("field_ref", ["age"]), 10])
    right = MockExpr("less", [MockExpr("field_ref", ["age"]), 50])
    expr = MockExpr("and_kleene", [left, right])
    
    json_str = serialize_filters(expr)
    parsed = json.loads(json_str)
    assert len(parsed) == 2
    assert parsed[0]["op"] == "Gt"
    assert parsed[0]["value"]["Int64"] == 10
    assert parsed[1]["op"] == "Lt"
    assert parsed[1]["value"]["Int64"] == 50

def test_ast_translation_unsupported():
    # Unsupported operator
    expr = MockExpr("some_weird_unsupported_op", [MockExpr("field_ref", ["age"]), 10])
    json_str = serialize_filters(expr)
    assert json.loads(json_str) == []
    
    # Unsupported type
    expr2 = MockExpr("equal", [MockExpr("field_ref", ["age"]), 10.5])
    assert json.loads(serialize_filters(expr2)) == []
