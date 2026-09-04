"""
Low-level HTTP helpers: auth headers and retry logic.
"""

import asyncio
import time

import requests

from .auth import auth_headers
from .config import ACCOUNTS_HOST, ACCOUNT_ID
from .constants import (
    HTTP_TIMEOUT_SECS,
    MATCH_RESOURCES,
    MAX_RETRIES,
    MAX_RETRY_WAIT_SECS,
    SCIM_RESOURCES,
    logger,
)


def _request_with_retries(method, url, **kwargs):
    """Fire an HTTP request with exponential back-off on 429 / 5xx."""
    resp = None
    for attempt in range(MAX_RETRIES):
        resp = requests.request(method, url, timeout=HTTP_TIMEOUT_SECS, **kwargs)

        # Retry on rate-limit or server errors with exponential back-off.
        if resp.status_code == 429 or resp.status_code >= 500:
            # Skip the sleep on the last attempt — we're about to give up.
            if attempt == MAX_RETRIES - 1:
                break
            wait = min(2**attempt, MAX_RETRY_WAIT_SECS)
            logger.warning(
                "Retryable %s from %s – waiting %ds (attempt %d/%d)",
                resp.status_code,
                url,
                wait,
                attempt + 1,
                MAX_RETRIES,
            )
            time.sleep(wait)
            continue

        resp.raise_for_status()
        return resp

    # All retries exhausted — raise the last error.
    if resp is not None:
        resp.raise_for_status()
    raise RuntimeError(f"No retries attempted for {method} {url}")


def _scim_list(principal_type, start_index=1, count=100):
    """Return (Resources list, totalResults) from the Account SCIM 2.1 API."""
    resource = SCIM_RESOURCES[principal_type]
    url = f"{ACCOUNTS_HOST}/api/2.1/accounts/{ACCOUNT_ID}/scim/v2/{resource}"
    resp = _request_with_retries(
        "GET",
        url,
        headers=auth_headers(),
        params={"startIndex": start_index, "count": count},
    )
    data = resp.json()
    return data.get("Resources", []), data.get("totalResults", 0)


def _match_with_idp(principal_type, identity_id):
    """Trigger a sync and compare local vs IDP for a single identity."""
    resource = MATCH_RESOURCES[principal_type]
    url = (
        f"{ACCOUNTS_HOST}/api/2.0/identity/accounts/{ACCOUNT_ID}"
        f"/{resource}/{identity_id}/matchWithIdp"
    )
    return _request_with_retries("POST", url, headers=auth_headers()).json()


def _list_workspaces():
    """Return the full list of workspaces from the Account API."""
    url = f"{ACCOUNTS_HOST}/api/2.0/accounts/{ACCOUNT_ID}/workspaces"
    resp = _request_with_retries("GET", url, headers=auth_headers())
    return resp.json()


class AsyncAccountsClient:
    """Async wrapper around the Databricks Accounts API.
    """

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        pass

    async def scim_list(self, principal_type, start_index=1, count=100):
        """Return (Resources list, totalResults) from the Account SCIM 2.1 API."""
        return await asyncio.to_thread(_scim_list, principal_type, start_index, count)

    async def match_with_idp(self, principal_type, identity_id):
        """Trigger a sync and compare local vs IDP for a single identity."""
        return await asyncio.to_thread(_match_with_idp, principal_type, identity_id)

    async def list_workspaces(self):
        """Return the full list of workspaces from the Account API."""
        return await asyncio.to_thread(_list_workspaces)
