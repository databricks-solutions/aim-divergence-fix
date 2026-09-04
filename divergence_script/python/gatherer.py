"""
Gather identity IDs from SCIM (or config) into intermediate CSVs.

No crash recovery — if interrupted gathering restarts from scratch.
"""

from .config import TARGET_IDENTITIES
from .constants import SCIM_PAGE_SIZE, logger
from .csv_io import (
    count_gathered_identities,
    open_gather_identity_files,
    remove_gathered_identities,
)
from .http_client import AsyncAccountsClient


async def _gather_from_scim(principal_types, identity_writers, identity_file_handles):
    """Paginate through SCIM for each principal type and write IDs to CSVs."""
    async with AsyncAccountsClient() as client:
        for principal_type in principal_types:
            start_index = 1
            logger.info("Gathering %ss ...", principal_type)

            while True:
                # Fetch the next page of identities from SCIM.
                resources, total = await client.scim_list(
                    principal_type, start_index=start_index, count=SCIM_PAGE_SIZE
                )
                if not resources:
                    break

                logger.info(
                    "  Fetched %d %ss  (startIndex=%d, totalResults=%d)",
                    len(resources),
                    principal_type,
                    start_index,
                    total,
                )

                # Write each identity's ID to the CSV.
                for resource in resources:
                    identity_writers[principal_type].writerow(
                        {"id": resource.get("id", "")}
                    )

                identity_file_handles[principal_type].flush()

                # Advance past this page; stop if we've consumed all resources.
                fetched = len(resources)
                start_index += fetched
                if start_index > total:
                    break

            logger.info("Finished gathering %ss.", principal_type)


def _gather_from_config(identity_writers, principal_types):
    """Write user-specified target IDs directly to identity CSVs.

    Entries whose principal_type is not in *principal_types* (disabled via
    INCLUDE_* or an unrecognized label) are skipped with a warning.
    """
    enabled = set(principal_types)
    skipped_counts = {}
    for principal_type, identity_id in TARGET_IDENTITIES:
        if principal_type not in enabled:
            skipped_counts[principal_type] = skipped_counts.get(principal_type, 0) + 1
            continue
        identity_writers[principal_type].writerow({"id": str(identity_id)})
    if skipped_counts:
        summary = ", ".join(
            f"{count} {ptype}" for ptype, count in sorted(skipped_counts.items())
        )
        logger.warning(
            "Skipped TARGET_IDENTITIES entries for disabled or unknown "
            "principal types: %s",
            summary,
        )


async def gather(principal_types, progress):
    """Gather identity IDs into per-type CSVs.

    Uses TARGET_IDENTITIES if set, otherwise paginates SCIM.
    """
    # Clean up any existing CSVs
    remove_gathered_identities(principal_types)

    with open_gather_identity_files(principal_types) as (identity_file_handles, identity_writers):
        if TARGET_IDENTITIES:
            # Write user-specified target IDs directly to identity CSVs.
            _gather_from_config(identity_writers, principal_types)
        else:
            # Paginate through SCIM to discover all identities.
            await _gather_from_scim(
                principal_types, identity_writers, identity_file_handles
            )

    # Tally totals from the just-written CSVs so progress can reflect what we'll process.
    totals = {ptype: count_gathered_identities(ptype) for ptype in principal_types}
    progress["totals"] = totals
    logger.info("Identity gathering complete – identity CSVs written.")
