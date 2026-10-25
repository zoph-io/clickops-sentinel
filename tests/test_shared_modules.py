# SPDX-License-Identifier: Apache-2.0
"""Modules duplicated across Lambda packages must stay identical, and the
published catalog document must match the code."""

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SHARED = (
    "client.py",
    "criticality.py",
    "email_render.py",
    "email_secret.py",
    "email_send.py",
    "ip_intel.py",
)


@pytest.mark.parametrize("name", SHARED)
def test_duplicated_module_copies_are_identical(name):
    detector = (ROOT / "src" / "detector" / name).read_text()
    investigator = (ROOT / "src" / "investigator" / name).read_text()
    assert detector == investigator, f"src/detector/{name} and src/investigator/{name} differ"


def test_catalog_document_is_up_to_date():
    sys.path.insert(0, str(ROOT / "scripts"))
    import render_catalog

    published = (ROOT / "docs" / "criticality-catalog.md").read_text()
    assert published == render_catalog.render(), "run make catalog-doc"
