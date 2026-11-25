"""moto is not safe under many threads: its S3 put sometimes fails ("I/O operation on closed file") and its DynamoDB
conditional write is a check THEN a write, not atomic, so two threads can both pass the same version check (a lost update
that real DynamoDB cannot produce). Real S3 and DynamoDB do both atomically. These tests therefore serialise the *single
write call* (put_object, put_item, update_item) with a lock, which stands in for AWS's atomicity. The retry and
conditional-check LOGIC in core and handlers is still what is being tested; deploy/load_aws.py tests the real thing."""
import threading
import boto3
import pytest
from tourniquet_slice import core

_lock = threading.Lock()
_real_resource, _real_c = boto3.resource, core._c


class _Table:
    def __init__(self, t):
        self._t = t

    def __getattr__(self, n):
        a = getattr(self._t, n)
        if n in ("put_item", "update_item", "delete_item"):
            def locked(*args, **kw):
                with _lock:
                    return a(*args, **kw)
            return locked
        return a


class _Res:
    def __init__(self, r):
        self._r = r

    def Table(self, name):
        return _Table(self._r.Table(name))

    def __getattr__(self, n):
        return getattr(self._r, n)


@pytest.fixture(autouse=True)
def atomic_writes_like_aws(monkeypatch):
    monkeypatch.setattr(boto3, "resource", lambda svc, *a, **k: _Res(_real_resource(svc, *a, **k)) if svc == "dynamodb" else _real_resource(svc, *a, **k))

    def patched(kind, svc):
        c = _real_c(kind, svc)
        if svc == "s3":
            orig = c.put_object

            def locked(**kw):
                with _lock:
                    return orig(**kw)
            c.put_object = locked
        return c
    monkeypatch.setattr(core, "_c", patched)
