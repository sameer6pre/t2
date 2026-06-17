import os
import hashlib
import pickle
import random
import subprocess
import yaml
import requests

import os
import hashlib

SECRET_KEY = os.urandom(24)  # PRECOGS_FIX: use a secure random key instead of hardcoded

def hash_password(password: str) -> str:
    return hashlib.pbkdf2_hmac('sha256', password.encode(), os.urandom(16), 100000).hex()  # PRECOGS_FIX: use PBKDF2 with SHA-256 for secure hashing


# ❌ 3. Command injection
def list_files(user_path: str) -> str:
    # User input directly concatenated into shell command
    cmd = f"ls -la {user_path}"
    return subprocess.getoutput(cmd)


# ❌ 4. Insecure deserialization (RCE risk)
import json

def load_user_data(data: bytes):
    """Safely deserialize user data. Reject pickle and accept JSON only.

    This function intentionally avoids pickle.loads. It only accepts JSON payloads encoded as UTF-8.
    """
    # PRECOGS_FIX: disallow pickle and require safe JSON format for untrusted input
    try:
        text = data.decode('utf-8')
    except Exception as e:
        raise ValueError("Data must be UTF-8 JSON; binary pickle is not allowed") from e

    try:
        return json.loads(text)
    except Exception as e:
        raise ValueError("Failed to parse JSON or unsupported serialized format") from e


# ❌ 5. Path traversal
import os

def read_file(filename: str) -> str:
    """Read a file only if it's located under the application's allowed base directory.

    This prevents path traversal by resolving real paths and ensuring the requested file
    is within the base directory.
    """
    # PRECOGS_FIX: restrict reads to files under the application's working directory
    base_dir = os.path.abspath(os.getcwd())
    req_path = os.path.abspath(os.path.join(base_dir, filename))

    # Ensure the requested path is a subpath of base_dir
    try:
        if os.path.commonpath([base_dir, req_path]) != base_dir:
            raise PermissionError("Attempted path traversal outside permitted directory")
    except ValueError:
        # os.path.commonpath can raise ValueError on different drives (Windows)
        raise PermissionError("Invalid file path")

    if not os.path.isfile(req_path):
        raise FileNotFoundError(f"File not found: {req_path}")

    with open(req_path, "r", encoding="utf-8") as f:
        return f.read()


# ❌ 6. Unsafe YAML loading
import yaml

def parse_yaml(data: str):
    """Safely parse YAML from untrusted input using safe_load."""
    # PRECOGS_FIX: use yaml.safe_load to avoid arbitrary object construction
    return yaml.safe_load(data)


# ❌ 7. Insecure random token
import secrets

def generate_token() -> str:
    """Generate a cryptographically secure token suitable for authentication/CSRF/etc."""
    # PRECOGS_FIX: use the secrets module for cryptographically secure randomness
    return secrets.token_hex(16)


# ❌ 8. SSRF-style HTTP request
import urllib.parse
import socket
import ipaddress
import requests

def fetch_internal_url(url: str):
    """Fetch a URL but validate it to prevent SSRF. Disallow requests to private IP ranges or non-http(s) schemes."""
    # PRECOGS_FIX: validate scheme and resolve host to prevent private/internal network access
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError("Only http/https schemes are allowed")

    host = parsed.hostname
    if not host:
        raise ValueError("Invalid URL: missing host")

    try:
        addr_infos = socket.getaddrinfo(host, None)
    except Exception:
        raise ValueError("Unable to resolve host")

    for info in addr_infos:
        ip = info[4][0]
        try:
            ip_obj = ipaddress.ip_address(ip)
        except Exception:
            raise ValueError("Invalid resolved IP")
        if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_reserved:
            raise ValueError("Access to private or internal IP ranges is forbidden")

    r = requests.get(url, timeout=5)
    r.raise_for_status()
    return r.text


# ❌ 9. Dangerous eval
import ast
import operator

# small safe evaluator supporting basic arithmetic
_allowed_operators = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.Div: operator.truediv,
    ast.Pow: operator.pow,
    ast.Mod: operator.mod,
    ast.UAdd: operator.pos,
    ast.USub: operator.neg,
}

def _eval_node(node):
    if isinstance(node, ast.Expression):
        return _eval_node(node.body)
    if isinstance(node, ast.Constant):
        if isinstance(node.value, (int, float)):
            return node.value
        raise ValueError("Unsupported constant type")
    if isinstance(node, ast.Num):
        return node.n
    if isinstance(node, ast.BinOp):
        left = _eval_node(node.left)
        right = _eval_node(node.right)
        op_type = type(node.op)
        if op_type in _allowed_operators:
            return _allowed_operators[op_type](left, right)
        raise ValueError("Operator not allowed")
    if isinstance(node, ast.UnaryOp):
        operand = _eval_node(node.operand)
        op_type = type(node.op)
        if op_type in _allowed_operators:
            return _allowed_operators[op_type](operand)
        raise ValueError("Unary operator not allowed")
    raise ValueError("Unsupported expression")


def calculate(expression: str):
    """Safely evaluate simple arithmetic expressions only.

    Supported: integers/floats and + - * / % ** with unary +/-. This explicitly forbids names, calls, attributes, and other code.
    """
    # PRECOGS_FIX: replace eval with a safe AST-based evaluator that only permits arithmetic
    try:
        node = ast.parse(expression, mode='eval')
        return _eval_node(node)
    except Exception as e:
        raise ValueError(f"Invalid or unsupported expression: {e}") from e


# ❌ 10. Weak file permissions
import os

def save_file(filename: str, content: str):
    """Write content to file with secure file permissions (owner read/write only).

    Uses os.open to set the file mode atomically when creating.
    """
    # PRECOGS_FIX: create file with secure mode 0o600 to avoid world-writable permissions
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    mode = 0o600
    fd = os.open(filename, flags, mode)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            f.write(content)
    except Exception:
        # ensure file descriptor is closed on error
        try:
            os.close(fd)
        except Exception:
            pass
        raise
