"""
Validators for customer-supplied config values.
"""

def validate_account_id(account_id: str) -> None:
    if not account_id:
        raise ValueError("Set ACCOUNT_ID in config.py before running.")

def validate_secret_scope(secret_scope: str) -> None:
    if not secret_scope:
        raise ValueError(
            "Set SECRET_SCOPE in config.py to a Databricks secret scope "
            "containing `client_id` and `client_secret` before running."
        )

def validate_accounts_host(host: str) -> None:
    """Reject obviously unsafe ACCOUNTS_HOST values.

    Rules: must use ``https://`` (so OAuth credentials aren't sent in clear),
    must not have a trailing slash, and must not include a query string.
    """
    if not host.startswith("https://"):
        raise ValueError(f"ACCOUNTS_HOST must use https:// (got {host!r}).")
    if host.endswith("/"):
        raise ValueError(f"ACCOUNTS_HOST must not have a trailing slash (got {host!r}).")
    if "?" in host:
        raise ValueError(f"ACCOUNTS_HOST must not include URL parameters (got {host!r}).")
