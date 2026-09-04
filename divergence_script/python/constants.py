"""
Internal constants — not intended for customer modification.
"""

import logging
from pathlib import Path

# ── Performance / retry tuning ───────────────────────────────────────
# Number of MatchWithIdp calls to execute concurrently per batch.
BATCH_SIZE = 3

# Number of identities to fetch from SCIM per page.
SCIM_PAGE_SIZE = 100

# Number of times to retry a 429 or 5xx response before giving up.
MAX_RETRIES = 5

# Maximum seconds to wait between retries. Exponential back-off is capped at this value.
MAX_RETRY_WAIT_SECS = 60

# Per-request HTTP timeout. Guards against indefinite stalls when a server hangs.
HTTP_TIMEOUT_SECS = 300

# How often to refresh the OAuth access token in the background (30 minutes).
TOKEN_REFRESH_INTERVAL_SECS = 1800

# ── Secret scope keys ─────────────────────────────────────────────────

CLIENT_ID_KEY = "client_id"
CLIENT_SECRET_KEY = "client_secret"

# ── Error categories ──────────────────────────────────────────────────

ERROR_EXTERNAL_ID_NOT_IN_IDP = "EXTERNAL_ID_NOT_IN_IDP"
ERROR_EXTERNAL_ID_MATCH_NAME_MISMATCH = "EXTERNAL_ID_MATCH_NAME_MISMATCH"
ERROR_NAME_MATCH_EXTERNAL_ID_MISMATCH = "NAME_MATCH_EXTERNAL_ID_MISMATCH"
ERROR_GROUP_HAS_LOCAL_MEMBERS_WITHOUT_EXTERNAL_ID = "GROUP_HAS_LOCAL_MEMBERS_WITHOUT_EXTERNAL_ID"
ERROR_GROUP_HAS_LOCAL_MEMBERS_WITH_EXTERNAL_ID = "GROUP_HAS_LOCAL_MEMBERS_WITH_EXTERNAL_ID"
ERROR_IDENTITY_FEDERATION_DISABLED = "IDENTITY_FEDERATION_DISABLED"

# ── Principal type mappings ───────────────────────────────────────────
# Maps principal type label → URL path segment for each API.

SCIM_RESOURCES = {
    "USER": "Users",
    "GROUP": "Groups",
    "SERVICE_PRINCIPAL": "ServicePrincipals",
}

MATCH_RESOURCES = {
    "USER": "users",
    "GROUP": "groups",
    "SERVICE_PRINCIPAL": "servicePrincipals",
}

# ── Per-type CSV schemas ─────────────────────────────────────────────────

USER_CSV_HEADERS = [
    "id",
    "username",
    "externalId",
    "externalIdWithUsernameMatch",
    "errorCategories",
]

GROUP_CSV_HEADERS = [
    "id",
    "groupName",
    "externalId",
    "externalIdsWithGroupnameMatch",
    "localMembersNotInIdpInternalIds",
    "externalMembersNotInIdpInternalIds",
    "errorCategories",
]

SP_CSV_HEADERS = [
    "id",
    "applicationId",
    "externalId",
    "externalIdWithAppIdMatch",
    "errorCategories",
]

CSV_HEADERS = {
    "USER": USER_CSV_HEADERS,
    "GROUP": GROUP_CSV_HEADERS,
    "SERVICE_PRINCIPAL": SP_CSV_HEADERS,
}

GATHER_CSV_HEADERS = ["id"]

FAILURES_CSV_HEADERS = ["id", "type", "error"]
FAILURES_CSV_PREFIX = "idp_divergence_failures"

WORKSPACES_CSV_NAME = "divergence_workspaces.csv"
WORKSPACES_CSV_HEADERS = [
    "workspaceId",
    "errorCategories",
]

# ── File paths and prefixes ───────────────────────────────────────────────

RESULTS_DIR = Path(__file__).resolve().parent.parent / "results"
OUTPUT_CSV_PREFIX = "idp_divergence"
IDENTITY_CSV_PREFIX = "identities_to_process"
PROGRESS_LOG = "idp_divergence_progress.json"

# ── Output file suffixes ─────────────────────────────────────────────────

OUTPUT_SUFFIXES = {
    "USER": "users",
    "GROUP": "groups",
    "SERVICE_PRINCIPAL": "service_principals",
}

# ── Logging ──────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
)
logger = logging.getLogger("divergence")
