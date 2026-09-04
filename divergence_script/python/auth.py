"""
OAuth access-token management for the Databricks Accounts API.

The script authenticates using the ``client_credentials`` grant. Tokens are
short-lived, so we mint one at startup and refresh it in the background to
keep long-running scans alive.
"""

import asyncio
import contextlib
import threading

import requests

from .config import ACCOUNTS_HOST, ACCOUNT_ID
from .constants import TOKEN_REFRESH_INTERVAL_SECS, logger
from .secrets import get_client_id, get_client_secret

# Mutable holder for the current OAuth access token. Updated by the background
# refresher and read by every outgoing request, so the lock guards a torn read
# while a refresh is in flight on another thread.
_token_lock = threading.Lock()
_access_token = ""


def _set_access_token(token):
    global _access_token
    with _token_lock:
        _access_token = token


def _get_access_token():
    with _token_lock:
        return _access_token


def auth_headers():
    """Headers for an authenticated Databricks Accounts API request."""
    return {
        "Authorization": f"Bearer {_get_access_token()}",
        "Content-Type": "application/json",
    }


def fetch_access_token():
    """Mint a fresh OAuth access token via the client_credentials grant."""
    url = f"{ACCOUNTS_HOST}/oidc/accounts/{ACCOUNT_ID}/v1/token"
    resp = requests.post(
        url,
        auth=(get_client_id(), get_client_secret()),
        data={"grant_type": "client_credentials", "scope": "all-apis"},
    )
    resp.raise_for_status()
    return resp.json()["access_token"]


def refresh_access_token():
    """Fetch a fresh OAuth access token and store it for future requests."""
    _set_access_token(fetch_access_token())
    logger.info("Refreshed account access token")


async def run_token_refresher(interval_secs=TOKEN_REFRESH_INTERVAL_SECS):
    """Refresh the OAuth access token every ``interval_secs`` until cancelled.

    A failed refresh is logged but does not stop the loop — the previous token
    keeps being used until it either succeeds on the next cycle or expires.
    """
    while True:
        await asyncio.sleep(interval_secs)
        try:
            await asyncio.to_thread(refresh_access_token)
        except Exception as e:
            logger.warning("Failed to refresh access token: %s; will retry", e)


@contextlib.asynccontextmanager
async def access_token_refresher(interval_secs=TOKEN_REFRESH_INTERVAL_SECS):
    """Mint an initial token and keep it fresh for the lifetime of the block."""
    await asyncio.to_thread(refresh_access_token)
    task = asyncio.create_task(run_token_refresher(interval_secs))
    try:
        yield
    finally:
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
