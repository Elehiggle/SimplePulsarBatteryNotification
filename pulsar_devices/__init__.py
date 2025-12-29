from __future__ import annotations

from . import x2cl, x2v1

BACKENDS = {
    x2cl.NAME: x2cl,
    x2v1.NAME: x2v1,
}

BACKEND_ORDER = [x2cl, x2v1]
