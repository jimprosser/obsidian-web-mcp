"""A stand-in for sentence-transformers, so semantic-search tests run without the model.

The one seam the tests use: install() puts this module where `import sentence_transformers`
finds it, and the index loads it exactly as it loads the real one. Everything else (the
SQLite index, the read guard, the tool, the extension lifecycle, serve()) is the real code.

The encoder is a normalized bag of words. Hashing with crc32 rather than hash() keeps it
identical across processes, so a child server embeds exactly what the test expects.
"""

import re
import sys
import types
import zlib

import numpy as np

DIM = 256

# Every text handed to the encoder, in order: what the index actually read. Tests clear it.
ENCODED: list[str] = []


class WordEncoder:
    def __init__(self, *args, **kwargs):
        pass

    def encode(self, texts, show_progress_bar=False, normalize_embeddings=True):
        single = isinstance(texts, str)
        items = [texts] if single else list(texts)
        ENCODED.extend(items)
        out = np.zeros((len(items), DIM), dtype=np.float32)
        for row, text in enumerate(items):
            for word in re.findall(r"[a-z0-9]+", text.lower()):
                out[row, zlib.crc32(word.encode()) % DIM] += 1.0
            norm = np.linalg.norm(out[row])
            if norm:
                out[row] /= norm
        return out[0] if single else out


def module() -> types.ModuleType:
    mod = types.ModuleType("sentence_transformers")
    mod.SentenceTransformer = WordEncoder
    return mod


def install() -> None:
    """For a child process: make `import sentence_transformers` return the stand-in."""
    sys.modules["sentence_transformers"] = module()
