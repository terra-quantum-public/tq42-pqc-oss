from types import ModuleType

import pytest


@pytest.fixture
def pqc() -> ModuleType:
    import pqc

    return pqc
