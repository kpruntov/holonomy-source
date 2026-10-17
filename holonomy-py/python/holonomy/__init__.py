# @trace TASK-084
from ._holonomy import read as _rust_read, write as _rust_write, init, _get_active_config, Writer as _rust_Writer
from ._holonomy import scan as _rust_scan
import json
import os
from pathlib import Path

def _resolve_credentials():
    # 1. Explicit override: HOLONOMY_CREDENTIAL_FILE
    cred_file_path = os.environ.get("HOLONOMY_CREDENTIAL_FILE")
    if cred_file_path:
        # Expand ~ and $HOME for robust UX
        path = Path(os.path.expandvars(cred_file_path)).expanduser()
        if path.is_file():
            try:
                return path.read_text().strip()
            except Exception:
                pass
                
    # 2. Explicit override: HOLONOMY_JWT
    jwt = os.environ.get("HOLONOMY_JWT")
    if jwt:
        return jwt
        
    # 3. Standard Cloud Providers: AWS EKS / IAM OIDC
    aws_token_file = os.environ.get("AWS_WEB_IDENTITY_TOKEN_FILE")
    if aws_token_file:
        path = Path(aws_token_file)
        if path.is_file():
            try:
                return path.read_text().strip()
            except Exception:
                pass

    # 4. Standard Cloud Providers: Azure AKS / Workload Identity
    azure_token_file = os.environ.get("AZURE_FEDERATED_TOKEN_FILE")
    if azure_token_file:
        path = Path(azure_token_file)
        if path.is_file():
            try:
                return path.read_text().strip()
            except Exception:
                pass
                
    # 5. Zero-Config Kubernetes Default Path
    k8s_token = Path("/var/run/secrets/kubernetes.io/serviceaccount/token")
    if k8s_token.is_file():
        try:
            return k8s_token.read_text().strip()
        except Exception:
            pass
            
    # 6. Local Developer DX (holonomy auth login)
    cred_file = Path.home() / ".holonomy" / "credentials"
    if cred_file.is_file():
        try:
            return cred_file.read_text().strip()
        except Exception:
            pass
            
    return None

def _extract_op(expr):
    op = getattr(expr, "op", None)
    if callable(op):
        return op()
    return op

def _extract_args(expr):
    args = getattr(expr, "args", None)
    if callable(args):
        return args()
    return args

def _extract_scalar_value(arg):
    # PyArrow scalars have an as_py() method
    if hasattr(arg, "as_py"):
        return arg.as_py()
    return arg

def _traverse(expr):
    if expr is None:
        return []
    
    op = _extract_op(expr)
    args = _extract_args(expr)
    
    if op is None or args is None:
        return []
        
    if op in ("and", "and_kleene"):
        left_preds = _traverse(args[0])
        right_preds = _traverse(args[1])
        return left_preds + right_preds
        
    op_map = {
        "equal": "Eq",
        "not_equal": "Neq",
        "greater": "Gt",
        "less": "Lt",
        "==": "Eq",
        "!=": "Neq",
        ">": "Gt",
        "<": "Lt"
    }
    
    rust_op = op_map.get(op)
    if rust_op:
        # Assuming args[0] is FieldRef, args[1] is Scalar
        left_arg = args[0]
        right_arg = args[1]
        
        # Extract column name
        col_name = None
        left_op = _extract_op(left_arg)
        left_args = _extract_args(left_arg)
        
        if left_op == "field_ref" and left_args:
            col_name = left_args[0]
        elif hasattr(left_arg, "_name"): # polars/pyarrow fallback
            col_name = left_arg._name
        elif isinstance(left_arg, str):
            col_name = left_arg
            
        if not col_name:
            return []
            
        # Extract value
        val_py = _extract_scalar_value(right_arg)
        
        if isinstance(val_py, str):
            val_obj = {"String": val_py}
        elif isinstance(val_py, int):
            val_obj = {"Int64": val_py}
        else:
            return [] # Unsupported type
            
        return [{
            "op": rust_op,
            "column": col_name,
            "value": val_obj
        }]
        
    return []

def serialize_filters(expr):
    """
    Translates a boolean expression into a JSON string of Predicates
    expected by the holonomy rust core.
    """
    if expr is None:
        return None
        
    predicates = _traverse(expr)
    return json.dumps(predicates)

def scan(target, user_context=None, columns_to_read=None, purpose=None, filters=None, contract_json=None, assumed_role=None):
    """
    Scans data lazily from the target URI using the globally resolved configuration.
    
    Parameters
    ----------
    target : str
        The target URI (e.g., s3://bucket/dataset).
    user_context : str
        The identity/context of the caller.
    columns_to_read : list of str, optional
        Specific columns to fetch.
    purpose : str, optional
        The business purpose of the read request (used for data governance).
    filters : pyarrow.compute.Expression, optional
        Predicate expression to prune data partitions before decryption.
    contract_json : str, optional
        Data contract JSON string.
        
    Returns
    -------
    pyarrow.RecordBatchReader
    """
    if user_context is None:
        user_context = _resolve_credentials()
    filters_json = serialize_filters(filters) if filters is not None else None
    return _rust_scan(target, user_context, columns_to_read, purpose, filters_json, contract_json, assumed_role)

def read(target, user_context=None, columns_to_read=None, purpose=None, filters_json=None, contract_json=None, assumed_role=None):
    if user_context is None:
        user_context = _resolve_credentials()
    return _rust_read(target, user_context, columns_to_read, purpose, filters_json, contract_json, assumed_role)

import base64
import warnings

def _extract_identity_from_jwt(token):
    try:
        parts = str(token).split('.')
        if len(parts) == 3:
            payload_b64 = parts[1]
            payload_b64 += "=" * ((4 - len(payload_b64) % 4) % 4)
            payload = json.loads(base64.urlsafe_b64decode(payload_b64))
            
            if 'sub' in payload:
                return payload['sub'], True
            elif 'client_id' in payload:
                return payload['client_id'], False
            elif 'azp' in payload:
                return payload['azp'], False
    except Exception:
        pass
    return None, False

def _resolve_write_identity(user_context):
    env_token = _resolve_credentials()
    
    if user_context is not None:
        provided_ident, _ = _extract_identity_from_jwt(user_context)
        if provided_ident is not None:
            user_context = provided_ident
            
        if env_token:
            env_ident, env_is_id = _extract_identity_from_jwt(env_token)
            if env_is_id and env_ident:
                warnings.warn(f"Explicit user_context overridden by active ID token sub: '{env_ident}'")
                user_context = env_ident
    else:
        if env_token:
            env_ident, env_is_id = _extract_identity_from_jwt(env_token)
            if env_ident:
                user_context = env_ident
                if not env_is_id:
                    warnings.warn(f"Access token used for write. Simulating identity with client claim: '{env_ident}'")
            else:
                warnings.warn("Active token lacks identity claims. Defaulting to 'undefined'.")
                user_context = "undefined"
        else:
            user_context = "undefined"
            
    return user_context

def write(batch, target, user_context=None, purpose=None, contract_json=None):
    user_context = _resolve_write_identity(user_context)
    return _rust_write(batch, target, user_context, purpose, contract_json)

class Writer:
    def __init__(self, target, user_context=None, purpose=None, contract_json=None):
        user_context = _resolve_write_identity(user_context)
        self._writer = _rust_Writer(target, user_context, purpose, contract_json)
        
    def __enter__(self):
        self._writer.__enter__()
        return self
        
    def __exit__(self, exc_type, exc_val, exc_tb):
        return self._writer.__exit__(exc_type, exc_val, exc_tb)
        
    def write_batch(self, batch):
        return self._writer.write_batch(batch)

__all__ = ["read", "write", "init", "scan", "_get_active_config", "Writer"]
