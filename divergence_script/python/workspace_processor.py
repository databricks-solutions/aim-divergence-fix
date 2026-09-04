"""
List account workspaces and write the ones that diverge on any criterion to
``divergence_workspaces.csv``.
"""

from .constants import ERROR_IDENTITY_FEDERATION_DISABLED, logger
from .csv_io import open_workspaces_output, workspaces_output_path
from .http_client import AsyncAccountsClient


def _fmt_errors(errors):
    return ";".join(str(e) for e in errors)


def _is_identity_federation_enabled(workspace):
    """Return True iff the workspace has identity federation explicitly enabled."""
    info = workspace.get("identity_federation_info") or {}
    return bool(info.get("enable_identity_federation"))


def _analyze_workspace(workspace):
    """Analyze a workspace for divergence errors.

    Returns a CSV-row dict if at least one error applies, or None otherwise.
    """
    errors = []
    if not _is_identity_federation_enabled(workspace):
        errors.append(ERROR_IDENTITY_FEDERATION_DISABLED)

    if not errors:
        return None
    return {
        "workspaceId": str(workspace.get("workspace_id", "")),
        "errorCategories": _fmt_errors(errors),
    }


async def list_divergent_workspaces():
    """List all account workspaces and write divergent ones to a CSV.

    Returns the number of divergent workspaces written.
    """
    logger.info("Listing workspaces to find divergences ...")
    divergent_written = 0

    with open_workspaces_output() as (_file_handle, writer):
        async with AsyncAccountsClient() as client:
            workspaces = await client.list_workspaces()

            for workspace in workspaces:
                row = _analyze_workspace(workspace)
                if row is None:
                    continue
                writer.writerow(row)
                divergent_written += 1

    logger.info(
        "Found %d divergent workspaces out of %d total – wrote %s",
        divergent_written,
        len(workspaces),
        workspaces_output_path(),
    )
    return divergent_written
