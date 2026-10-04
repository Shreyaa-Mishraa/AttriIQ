"""Pytest fixtures: load the digit-prefixed pipeline modules by path.

``src/01_preprocess.py`` and friends are not importable as normal modules because
their names start with a digit, so each is loaded from its file location once per
session and shared across tests.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"


def _load(filename: str):
    name = "pipe_" + filename.replace(".py", "").replace("-", "_")
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, SRC / filename)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load {filename}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="session")
def preprocess():
    return _load("01_preprocess.py")


@pytest.fixture(scope="session")
def features():
    return _load("02_features.py")


@pytest.fixture(scope="session")
def clustering():
    return _load("03_clustering.py")


@pytest.fixture(scope="session")
def dashboard():
    return _load("05_dashboard.py")


@pytest.fixture(scope="session")
def attribution():
    return _load("06_attribution.py")


@pytest.fixture(scope="session")
def graph():
    return _load("07_graph.py")


@pytest.fixture(scope="session")
def iot_labels():
    return _load("09_iot_labels.py")


@pytest.fixture(scope="session")
def project_root() -> Path:
    return ROOT
