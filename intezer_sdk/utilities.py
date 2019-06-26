import contextlib
from typing import Any


@contextlib.contextmanager
def dummy_context_manager(resource: Any):
    yield resource
