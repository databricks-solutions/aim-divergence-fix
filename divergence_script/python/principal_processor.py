"""
Match gathered identities against the IDP.

Reads identity IDs from the gathered listing CSVs, fans out MatchWithIdp calls in batches,
writes divergent rows, and persists progress for crash recovery.
"""

import asyncio

from .constants import BATCH_SIZE, logger
from .csv_io import load_gathered_identity_ids, open_divergence_output, open_failures_output
from .http_client import AsyncAccountsClient
from .progress import save_progress


async def _process_batch(
    client, identity_ids, principal_type, analyze_fn, failures_writer, position_base, total,
):
    """Call MatchWithIdp concurrently for one batch; log each outcome; return divergent rows."""
    tasks = [client.match_with_idp(principal_type, id) for id in identity_ids]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    rows = []
    for i, (id, result) in enumerate(zip(identity_ids, results)):
        current = position_base + i + 1
        if isinstance(result, BaseException):
            logger.warning(
                "  [%d/%d] Failed after retries: %s id=%s – %s",
                current, total, principal_type, id, result,
            )
            failures_writer.writerow({
                "id": id,
                "type": principal_type,
                "error": str(result),
            })
            continue

        row = analyze_fn(result)
        if row:
            logger.info(
                "  [%d/%d] Divergence found: %s id=%s",
                current, total, principal_type, row["id"],
            )
            rows.append(row)
        else:
            logger.info("  [%d/%d] No divergence: %s id=%s", current, total, principal_type, id)

    return rows


async def _match_principal_type(
    principal_type, identity_ids, analyze_fn,
    csv_writer, output_file, failures_writer, failures_file, progress,
):
    """Call MatchWithIdp for each identity, analyze, and write divergent rows.
    Supports crash recovery via *progress*.
    """
    # Resume from the last saved position if this type was in progress.
    start_index = 0
    if progress.get("current_type") == principal_type:
        start_index = progress.get("start_index", 0)

    total = len(identity_ids)
    remaining = identity_ids[start_index:]
    logger.info(
        "Matching %ss from index=%d (%d remaining) ...",
        principal_type, start_index, len(remaining),
    )

    async with AsyncAccountsClient() as client:
        for batch_start in range(0, len(remaining), BATCH_SIZE):
            batch = remaining[batch_start : batch_start + BATCH_SIZE]
            rows = await _process_batch(
                client, batch, principal_type, analyze_fn, failures_writer,
                start_index + batch_start, total,
            )
            for row in rows:
                csv_writer.writerow(row)

            # Flush to disk before saving progress so data is durable.
            output_file.flush()
            failures_file.flush()

            # Persist progress for crash recovery after each batch.
            progress["current_type"] = principal_type
            progress["start_index"] = start_index + batch_start + len(batch)
            save_progress(progress)

    # Mark this principal type as fully processed.
    progress["completed_types"].append(principal_type)
    progress["current_type"] = None
    progress["start_index"] = 0
    save_progress(progress)
    logger.info("Finished matching %ss.", principal_type)


async def match(analyzers, progress):
    """Match all gathered identities against the IDP.
    Opens each output CSV with the correct mode based on crash-recovery state.
    Failures (after all retries) are logged to a separate CSV instead of crashing.
    """
    completed = set(progress.get("completed_types", []))
    current_type = progress.get("current_type")

    # Append to the failures file when resuming; start fresh on a new run.
    resuming = completed or current_type is not None
    with open_failures_output("a" if resuming else "w") as (failures_file, failures_writer):
        for principal_type, analyze_fn in analyzers.items():
            if principal_type in completed:
                logger.info("Skipping %ss (already completed).", principal_type)
                continue

            # Append to the in-progress type's CSV; start fresh for unstarted types.
            mode = "a" if principal_type == current_type else "w"
            with open_divergence_output(principal_type, mode) as (file_handle, csv_writer):
                # Load all IDs previously gathered for this type.
                identity_ids = load_gathered_identity_ids(principal_type)
                await _match_principal_type(
                    principal_type, identity_ids, analyze_fn,
                    csv_writer, file_handle, failures_writer, failures_file, progress,
                )
