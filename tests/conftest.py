import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "fixtures"


def server_target(filename: str):
    from mcplens.transport import Target
    return Target.from_command([sys.executable, str(FIXTURES / filename)])


@pytest.fixture(scope="module")
def benign_target():
    return server_target("benign_server.py")


@pytest.fixture(scope="module")
def vulnerable_target():
    return server_target("vulnerable_server.py")
