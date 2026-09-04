"""
OAuth client-credential lookup via Databricks Secrets.

Secrets are read from a Databricks secret scope at runtime so they never live
in ``config.py`` or the notebook source. The scope name is configured via
``SECRET_SCOPE`` in ``config.py``; the scope must contain two secrets named
``client_id`` and ``client_secret``.

This module only works when executed on a Databricks cluster.
"""

from .config import SECRET_SCOPE
from .constants import CLIENT_ID_KEY, CLIENT_SECRET_KEY


def _dbutils():
    # Imported lazily so that importing this module outside a Databricks
    # runtime does not fail at import time.
    from databricks.sdk.runtime import dbutils
    return dbutils


def _require_scope():
    if not SECRET_SCOPE:
        raise RuntimeError(
            "SECRET_SCOPE is not set in config.py. Create a Databricks secret "
            "scope containing `client_id` and `client_secret`, then set "
            "SECRET_SCOPE to its name."
        )


def get_client_id() -> str:
    _require_scope()
    return _dbutils().secrets.get(scope=SECRET_SCOPE, key=CLIENT_ID_KEY)


def get_client_secret() -> str:
    _require_scope()
    return _dbutils().secrets.get(scope=SECRET_SCOPE, key=CLIENT_SECRET_KEY)
