import json
from pathlib import Path
import pytest
from app.schemas import Dataset


@pytest.fixture
def data():
    return Dataset.model_validate(
        json.loads((Path(__file__).resolve().parents[2] / "datasets/synthetic/aurora.json").read_text())
    )
