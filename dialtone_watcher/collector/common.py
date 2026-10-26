"""OS-independent bounded executable hashing, shared by local collectors."""
import hashlib
import os
import stat


class ExecutableHasher:
    def __init__(self, note, *, max_bytes=200 * 1024 * 1024, max_binaries=100):
        self.note = note
        self.max_bytes = max_bytes
        self.max_binaries = max_binaries
        self.cache = {}

    def hash(self, path):
        if not path:
            return None
        if path in self.cache:
            return self.cache[path]
        self.cache[path] = None
        if len(self.cache) > self.max_binaries:
            self.note('executable hashing', 'snapshot binary budget exceeded')
            return None
        try:
            # Opening nonblocking before fstat closes the stat/open FIFO race.
            descriptor = os.open(path, os.O_RDONLY | getattr(os, 'O_NONBLOCK', 0) | getattr(os, 'O_BINARY', 0))
            with os.fdopen(descriptor, 'rb') as stream:
                info = os.fstat(stream.fileno())
                if not stat.S_ISREG(info.st_mode):
                    self.note('executable hashing', 'not a regular file')
                    return None
                if info.st_size > self.max_bytes:
                    self.note('executable hashing', 'file exceeds size limit')
                    return None
                digest = hashlib.sha256()
                size = 0
                while chunk := stream.read(1024 * 1024):
                    size += len(chunk)
                    if size > self.max_bytes:
                        self.note('executable hashing', 'file exceeds size limit')
                        return None
                    digest.update(chunk)
                self.cache[path] = digest.hexdigest()
        except OSError:
            self.note('executable hashing', 'file unreadable or disappeared')
        return self.cache[path]
