"""Privacy boundary for JSON metadata. Unknown fields are removed by normalization."""
import getpass
import hashlib
import re
from collections.abc import Mapping
from pathlib import Path
from typing import Any

_HOME = re.compile(r"(?i)(?:[a-z]:[\\/]Users[\\/]|/(?:Users|home)/)[^\\/\s\"'<>:,;]+")
_SENSITIVE = {"username", "user", "uid", "gid", "cmdline", "command_line", "arguments", "args", "contents", "file_contents", "hostname"}


def hostname_hash(hostname: str) -> str:
    """Stable SHA-256 identifier; never persist the input hostname."""
    return hashlib.sha256(hostname.encode("utf-8")).hexdigest()


def redact(value: Any, *, username: str | None = None, home: str | None = None) -> Any:
    """Recursively copy JSON data, stripping private fields and home paths.

    Also replace the current account name wherever it appears in text. Callers
    handling another account can supply its username explicitly. This helper
    cannot identify arbitrary usernames in unstructured text; do not collect it.
    """
    account = getpass.getuser() if username is None else username
    home_path = str(Path.home()) if home is None else home

    def clean(item: Any) -> Any:
        if isinstance(item, str):
            text = _HOME.sub("~", item)
            if home_path and home_path not in ("/", "\\"):
                text = text.replace(home_path, "~")
            if account:
                text = re.sub(re.escape(account), "[redacted]", text, flags=re.IGNORECASE)
            return text
        if isinstance(item, Mapping):
            return {clean(str(k)): clean(v) for k, v in item.items()
                    if str(k).lower() not in _SENSITIVE}
        if isinstance(item, (list, tuple)):
            return [clean(v) for v in item]
        if item is None or isinstance(item, (bool, int, float)):
            return item
        raise TypeError("Only JSON metadata can be redacted")

    return clean(value)
