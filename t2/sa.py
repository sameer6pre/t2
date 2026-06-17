
# ❌ 3. Command injection
import subprocess
import shlex
import os

def list_files(user_path: str) -> str:
    """Safely list files for the given path without invoking a shell.

    This implementation avoids command injection by not using a shell and by passing
    arguments as a list. It also verifies the path exists and is a directory or file.
    """
    # PRECOGS_FIX: avoid shell usage and pass args as a list (use -- to stop option parsing)
    # PRECOGS_FIX: validate and resolve the path to avoid surprises
    path = os.path.expanduser(user_path)
    path = os.path.abspath(path)

    if not os.path.exists(path):
        raise FileNotFoundError(f"Path does not exist: {path}")

    # Use subprocess with a list (no shell) and '--' to prevent interpretation as options
    try:
        result = subprocess.run(["ls", "-la", "--", path], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, check=False)
        return result.stdout
    except Exception as e:
        raise RuntimeError(f"Failed to list files: {e}")