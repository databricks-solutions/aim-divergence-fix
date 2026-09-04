"""
Identity-IDP Divergence Checker – entry point.

Phase 1: List account workspaces and record divergent ones.
Phase 2: Gather all SCIM identities into intermediate CSVs.
Phase 3: Match each identity against the IDP and report divergences.

Usage:
    python3 -m divergence
"""

import asyncio
import csv
import sys

from .analyzers import analyze_group, analyze_sp, analyze_user
from .config import (
    ACCOUNT_ID,
    ACCOUNTS_HOST,
    INCLUDE_GROUPS,
    INCLUDE_SERVICE_PRINCIPALS,
    INCLUDE_USERS,
    SECRET_SCOPE,
)
from .constants import RESULTS_DIR, logger
from .csv_io import divergence_output_path, failures_output_path
from .gatherer import gather
from .auth import access_token_refresher
from .input_validation_utils import (
    validate_account_id,
    validate_accounts_host,
    validate_secret_scope,
)
from .principal_processor import match
from .progress import clear_progress, load_progress, save_progress
from .workspace_processor import list_divergent_workspaces

ALL_ANALYZERS = {
    "USER": analyze_user,
    "GROUP": analyze_group,
    "SERVICE_PRINCIPAL": analyze_sp,
}

_INCLUDE_FLAGS = {
    "USER": INCLUDE_USERS,
    "GROUP": INCLUDE_GROUPS,
    "SERVICE_PRINCIPAL": INCLUDE_SERVICE_PRINCIPALS,
}

ANALYZERS = {k: v for k, v in ALL_ANALYZERS.items() if _INCLUDE_FLAGS[k]}


async def _run():
    try:
        validate_account_id(ACCOUNT_ID)
        validate_secret_scope(SECRET_SCOPE)
        validate_accounts_host(ACCOUNTS_HOST)
    except ValueError as e:
        logger.error("Invalid config.py: %s", e)
        sys.exit(1)

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    logger.info("Writing outputs to %s", RESULTS_DIR)

    async with access_token_refresher():
        # Phase 1: list workspaces and record those that diverge on any criterion.
        await list_divergent_workspaces()

        progress = load_progress()

        # Phase 2: gather identity IDs (skipped if already completed).
        if not progress.get("finished_gathering_identities"):
            await gather(list(ANALYZERS), progress)
            progress["finished_gathering_identities"] = True
            save_progress(progress)

        # Phase 3: match each identity against the IDP.
        await match(ANALYZERS, progress)
        # All done — remove the progress file and notify for failures.
        clear_progress()
        output_files = [divergence_output_path(principal_type) for principal_type in ANALYZERS]
        logger.info("Done – reports written to %s", ", ".join(output_files))

        failures_path = failures_output_path()
        with open(failures_path, newline="") as f:
            reader = csv.reader(f)
            next(reader, None)  # Skip header row.
            has_failures = next(reader, None) is not None
        if has_failures:
            logger.warning(
                "Some identities failed after all retries – see %s", failures_path,
            )


def main():
    asyncio.run(_run())


if __name__ == "__main__":
    main()
