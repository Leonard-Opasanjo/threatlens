from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SAMPLES = ROOT / "threatlens" / "samples"
FEEDS = ROOT / "threatlens" / "feeds"


@pytest.fixture
def client(tmp_path):
    from fastapi.testclient import TestClient

    from threatlens import web
    from threatlens.db import Store

    web.app.state.store = Store(tmp_path / "t.db")
    with TestClient(web.app) as c:
        yield c
    del web.app.state.store
