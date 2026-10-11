"""Rotation/truncation/partial-line safe tail of the kube-apiserver audit file (binary, byte offsets)."""
from __future__ import annotations

import glob
import hashlib
import os
from dataclasses import asdict, dataclass

FP_BYTES, MIN_FP = 256, 64


@dataclass
class Position:
    inode: int
    dev: int
    offset: int
    head_fp: str

    def to_dict(self):
        return asdict(self)


@dataclass
class Batch:
    lines: list
    position: Position | None
    segment_ref: str
    at_eof: bool
    notices: list


class Tailer:
    def __init__(self, path: str, source_id: str, chunk: int = 4 << 20):
        self.path, self.source_id, self.chunk = path, source_id, chunk
        self.fh = None
        self.inode = self.dev = self.offset = 0
        self.head_fp = ''
        self.queue: list[str] = []      # rotated files still to drain after a resume, oldest first

    # ---- file helpers
    def _fp_of(self, fh) -> str:
        pos = fh.tell()
        fh.seek(0)
        head = fh.read(FP_BYTES)
        fh.seek(pos)
        return hashlib.sha1(head).hexdigest() if len(head) >= MIN_FP else ''

    def _open(self, path: str, offset: int = 0, head_fp: str = ''):
        if self.fh:
            self.fh.close()
        self.fh = open(path, 'rb')
        st = os.fstat(self.fh.fileno())
        self.inode, self.dev, self.offset, self.head_fp = st.st_ino, st.st_dev, offset, head_fp

    def _rotated(self) -> list[str]:
        stem, ext = os.path.splitext(self.path)       # lumberjack: audit-<ts>.log (.gz is skipped)
        files = [p for p in glob.glob(f'{stem}-*{ext}') if os.path.isfile(p)]
        return sorted(files, key=lambda p: os.stat(p).st_mtime)

    def _ensure_fp(self):
        if not self.head_fp and self.fh:
            self.head_fp = self._fp_of(self.fh)

    def position(self) -> Position:
        self._ensure_fp()
        return Position(self.inode, self.dev, self.offset, self.head_fp)

    def segment_ref(self) -> str:
        self._ensure_fp()
        return f'rawlog:{self.source_id}:{self.inode}:{self.head_fp[:12] or "nofp"}'

    # ---- start / resume
    def start(self, saved: Position | None) -> str:
        """'resumed' (contiguous), 'fresh' (no checkpoint), or 'lost' (checkpoint file is gone)."""
        if saved:
            cands = self._rotated() + ([self.path] if os.path.exists(self.path) else [])
            for i, p in enumerate(cands):
                try:
                    st = os.stat(p)
                except FileNotFoundError:
                    continue
                if (st.st_ino, st.st_dev) != (saved.inode, saved.dev) or st.st_size < saved.offset:
                    continue
                with open(p, 'rb') as probe:
                    if saved.head_fp and self._fp_of(probe) != saved.head_fp:
                        continue                       # inode reused by a different file
                self._open(p, saved.offset, saved.head_fp)
                self.queue = [q for q in cands[i + 1:] if q != self.path]
                return 'resumed'
        if os.path.exists(self.path):
            self._open(self.path)
        return 'lost' if saved else 'fresh'

    # ---- reading
    def _read_lines(self) -> list:
        self.fh.seek(self.offset)
        data = self.fh.read(self.chunk)
        cut = data.rfind(b'\n')
        if cut < 0:
            return []                                  # nothing, or a partial line: wait for the rest
        self.offset += cut + 1
        return data[:cut].split(b'\n')

    def _batch(self, lines, at_eof=False, notices=()):
        return Batch(lines, self.position(), self.segment_ref(), at_eof, list(notices))

    def read_batch(self) -> Batch:
        if self.fh is None:
            if not os.path.exists(self.path):
                return Batch([], None, '', True, [])
            self._open(self.path)
        lines = self._read_lines()
        if lines:
            return self._batch(lines)
        try:
            st = os.stat(self.path)
        except FileNotFoundError:
            return self._batch([], at_eof=True)        # mid-rotation; keep draining the old fd
        if (st.st_ino, st.st_dev) != (self.inode, self.dev):
            lines = self._read_lines()                 # final drain AFTER seeing the rename
            if lines:
                return self._batch(lines)
            nxt = self.queue.pop(0) if self.queue else self.path
            self._open(nxt)
            return self._batch([], notices=['rotated'])
        if os.fstat(self.fh.fileno()).st_size < self.offset:
            self.offset, self.head_fp = 0, ''
            return self._batch([], notices=['truncated'])
        return self._batch([], at_eof=True)
