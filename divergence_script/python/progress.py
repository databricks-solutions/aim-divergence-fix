"""
Crash-resilient progress tracking.

Stores completed principal types and the current SCIM ``startIndex`` in a
JSON file so the checker can resume after a crash without re-processing
already-finished pages.
"""

import json

from .constants import PROGRESS_LOG, RESULTS_DIR

_PROGRESS_PATH = RESULTS_DIR / PROGRESS_LOG


def load_progress():
    if _PROGRESS_PATH.exists():
        with open(_PROGRESS_PATH) as f:
            data = json.load(f)
        data.setdefault("finished_gathering_identities", False)
        data.setdefault("completed_types", [])
        data.setdefault("current_type", None)
        data.setdefault("start_index", 0)
        data.setdefault("totals", {})
        return data
    return {
        "finished_gathering_identities": False,
        "completed_types": [],
        "current_type": None,
        "start_index": 0,
        "totals": {},
    }


def save_progress(progress):
    with open(_PROGRESS_PATH, "w") as f:
        json.dump(progress, f, indent=2)


def clear_progress():
    _PROGRESS_PATH.unlink(missing_ok=True)
