"""
Customer-facing configuration for the Identity-IDP Divergence Checker.

Fill in the values below before running.
"""

# ── Databricks Account Credentials ──────────────────────────────────────────────────

ACCOUNTS_HOST = ""
ACCOUNT_ID = ""
SECRET_SCOPE = "divergence"

# ── Optional: Principal Type Selection ───────────────────────────────────
# Set to False to skip gathering and processing a principal type entirely.

INCLUDE_USERS = True
INCLUDE_GROUPS = True
INCLUDE_SERVICE_PRINCIPALS = True

# ── Optional: Run Only for Specific Identities ───────────────────────────
# When non-empty, SCIM listing is skipped and only these identities are checked.
# Each entry should be formatted as follows: (principal_type, internal_id)

# Example:
#   TARGET_IDENTITIES = [
#       ("USER", 12345),
#       ("USER", 67890),
#       ("GROUP", 11111),
#       ("SERVICE_PRINCIPAL", 22222),
#   ]
TARGET_IDENTITIES = []
