# Databricks notebook source
# MAGIC %md
# MAGIC # AIM Remediation Executor
# MAGIC
# MAGIC This notebook fixes the identity divergences that block a migration to **Automatic Identity Management (AIM)**
# MAGIC on Databricks. It reads the output of the AIM enablement prep script, sorts every divergence into a bucket by
# MAGIC its error category, applies the one fix that category allows, and records every action for rollback.
# MAGIC
# MAGIC **Who should run this:** a Databricks **account admin** performing the migration from account SCIM to AIM. You
# MAGIC do not need prior knowledge of the prep script. The next two cells teach the concepts and the workflow.
# MAGIC
# MAGIC **Safety model — three rules:**
# MAGIC 1. Nothing writes to an identity until you set `ENABLE_REMEDIATION = True`. The default is analysis-only.
# MAGIC 2. Even then, `DRY_RUN = True` logs intended changes without making them. You go live by setting `DRY_RUN = False`.
# MAGIC 3. Every planned or executed change lands in an audit log with its previous value, so any live write can be reversed.
# MAGIC
# MAGIC **Grounded in:**
# MAGIC - Databricks KB — *Automatic identity management (AIM) enablement prep script*
# MAGIC - Microsoft Learn — *Migrate to automatic identity management*
# MAGIC
# MAGIC **New here?** Read the next two cells — "How AIM identity matching works" and "How to run this notebook" — before you run anything.
# MAGIC
# MAGIC A condensed version history is in the appendix at the end of the notebook.

# COMMAND ----------

# MAGIC %md
# MAGIC ## How AIM identity matching works (read this first)
# MAGIC
# MAGIC **The situation.** You provision Databricks users, groups, and service principals from Microsoft Entra ID
# MAGIC through account SCIM. Today it works.
# MAGIC
# MAGIC **The complication.** AIM matches each Databricks identity to its Entra identity by Entra's `objectId`, which
# MAGIC Databricks stores as that identity's `externalId`. When the two agree, AIM treats them as the same principal.
# MAGIC When the `externalId` is missing, wrong, or points at a deleted Entra object, AIM cannot match. On the next
# MAGIC login it then provisions a **duplicate** principal, and the duplicate splits permissions, group membership,
# MAGIC and history across two records.
# MAGIC
# MAGIC **The resolution.** Fix the divergences before you enable AIM. This is not a single fix. Each error category
# MAGIC the prep script reports allows exactly one correct action, and only three of those actions can be scripted.
# MAGIC This notebook sorts every divergence into a bucket, applies the fix that bucket allows, and records the result.
# MAGIC
# MAGIC Three principles govern everything below:
# MAGIC 1. **One category, one fix.** The fix for a wrong link is not the fix for a deleted object. Apply the wrong one and you create the duplicate you set out to prevent.
# MAGIC 2. **Review before you write.** The notebook runs analysis-only by default and shows you the whole plan first.
# MAGIC 3. **Everything is recorded.** Each action lands in an audit log with its previous value, so a live run can be reversed.
# MAGIC
# MAGIC **Terms used throughout:**
# MAGIC - **Microsoft Entra ID (Entra)** — your identity provider (IdP), formerly Azure AD.
# MAGIC - **`objectId`** — Entra's permanent ID for an identity. This is the authoritative match key.
# MAGIC - **`externalId`** — where Databricks stores that `objectId`. AIM matches on this value.
# MAGIC - **Principal** — any user, group, or service principal.
# MAGIC - **Divergence** — a case where a Databricks identity's `externalId` does not correctly point at its Entra `objectId`.
# MAGIC - **Bucket** — a set of divergences that share one error category, and therefore one fix.
# MAGIC - **Gate** — a flag you must set before the notebook will write. Gates default to the safe position.
# MAGIC - **Link** — to set an identity's `externalId` so that Databricks and Entra agree on the match.

# COMMAND ----------

# MAGIC %md
# MAGIC ## How to run this notebook (execution model)
# MAGIC
# MAGIC This notebook changes identities in your Databricks **account** through the account SCIM API. It is safe by
# MAGIC default and fully auditable. Nothing touches your directory until you deliberately enable remediation **and**
# MAGIC turn off dry-run.
# MAGIC
# MAGIC **Two ways to feed it (Section 4 detects which automatically):**
# MAGIC - **Pre-made worklists** — the five `remediation_*.csv` files in `CSV_DIR`. The notebook loads them as-is.
# MAGIC - **Raw prep-script output** — the raw scan in `RAW_DIR` (`idp_divergence_users.csv`, `idp_divergence_groups.csv`, `divergence_workspaces.csv`). Section 4 sorts the divergences into the buckets in memory and can write the derived worklists back to `CSV_DIR` for your records.
# MAGIC
# MAGIC **Follow this order — analysis first, then remediate:**
# MAGIC 1. Leave `ENABLE_REMEDIATION = False` (the default) and run every cell top to bottom. The notebook classifies the scan, Section 4b presents the full plan, and each intended change prints with a `[DRY]` prefix and logs as `status = "planned"`. No identity write is possible in this state, whatever `DRY_RUN` is set to.
# MAGIC 2. Read Section 4b and the planned audit log. Confirm the buckets and counts match what you expect.
# MAGIC 3. Set `ENABLE_REMEDIATION = True` and re-run with `DRY_RUN = True`. This produces a collision-checked dry-run plan.
# MAGIC 4. Only then set `DRY_RUN = False` and re-run to apply the changes.
# MAGIC
# MAGIC **Re-running:** the bucket sections are independent and you can re-run one at a time. The audit log accumulates every action from the current run and Section 11 writes it out.
# MAGIC
# MAGIC **Why the section numbers and bucket numbers do not line up:** the sections are ordered so the three scriptable
# MAGIC fixes come first, then the no-write actions (Support tickets, escalations, reviews). The bucket numbers follow
# MAGIC the order the prep script reports categories. So Section 5 runs Bucket 1, Section 7 runs Bucket 2, and so on.
# MAGIC The decision map in the next cell lists the pairing.
# MAGIC
# MAGIC **Where files live:** the notebook reads raw inputs from `RAW_DIR`, and reads pre-made worklists and writes all
# MAGIC outputs (derived worklists, the support-ticket draft, the audit log) in `CSV_DIR`. You set both in Section 2. Use
# MAGIC Unity Catalog volume paths.
# MAGIC
# MAGIC **What reads and what writes:**
# MAGIC - **Reads only, in every mode:** the collision index (Section 3b) pages your entire account directory; the classification and presentation (Sections 4 and 4b); the validation query (Section 12).
# MAGIC - **Writes to identities only when `ENABLE_REMEDIATION = True` and `DRY_RUN = False`:** the SCIM `PATCH` calls in the link buckets, and the deactivation path if you fully enable it.
# MAGIC - **Writes local files in every mode, never touching identities:** the derived worklists (Section 4), the support-ticket drafts (Sections 7 and 9b), and the audit log (Section 11).
# MAGIC
# MAGIC ```mermaid
# MAGIC flowchart TD
# MAGIC     Config["Section 2: set flags + RAW_DIR/CSV_DIR"] --> Auth["Section 3: auth + EFFECTIVE_DRY_RUN"]
# MAGIC     Auth --> Index["Section 3b: build externalId index"]
# MAGIC     Index --> Resolve{"Section 4: input mode?"}
# MAGIC     Resolve -->|"premade CSVs present"| LoadPre["load remediation_*.csv"]
# MAGIC     Resolve -->|"raw_results only"| Derive["classify raw into buckets (+write derived CSVs)"]
# MAGIC     LoadPre --> Present["Section 4b: analyze + present summary"]
# MAGIC     Derive --> Present
# MAGIC     Present --> Buckets["Sections 5-9c: process buckets"]
# MAGIC     Buckets --> Gate{"ENABLE_REMEDIATION?"}
# MAGIC     Gate -->|"False (default)"| PlanOnly["forced dry: log planned / review only; no writes"]
# MAGIC     Gate -->|"True"| DryCheck{"DRY_RUN?"}
# MAGIC     DryCheck -->|"True"| PlanOnly
# MAGIC     DryCheck -->|"False"| Writes["PATCH / deactivate via SCIM; log success or error"]
# MAGIC     PlanOnly --> AuditWrite["Section 11: write audit_log CSV"]
# MAGIC     Writes --> AuditWrite
# MAGIC ```

# COMMAND ----------

# MAGIC %md
# MAGIC ## The divergence categories and their fixes (decision map)
# MAGIC
# MAGIC The prep script tags every divergence with an error category. Each category allows exactly one correct fix.
# MAGIC This is the map from category to fix, owner, section, gate, and whether the fix can be reversed. A principal
# MAGIC that matches several categories lands in the first bucket that applies, in the order below.
# MAGIC
# MAGIC **Bucket 1 — the link is wrong or missing, but the name matches.**
# MAGIC - *Category:* `NAME_MATCH_EXTERNAL_ID_MISMATCH` with a populated `externalIdWithUsernameMatch` (users) or `externalIdWithAppIdMatch` (service principals).
# MAGIC - *Meaning:* the name matches exactly one Entra identity, but the `externalId` is empty or points elsewhere.
# MAGIC - *Fix:* link it — set `externalId` to the matched `objectId`. **Scriptable.** Owner: this notebook.
# MAGIC - *Section:* 5 (users), 9a (service principals). *Gate:* `ENABLE_REMEDIATION`, plus `LINK_SERVICE_PRINCIPALS` for service principals. *Reversible:* yes, from the audit log.
# MAGIC
# MAGIC **Bucket 2 — the link is valid but the name drifted.**
# MAGIC - *Category:* `EXTERNAL_ID_MATCH_NAME_MISMATCH`.
# MAGIC - *Meaning:* the `externalId` maps to a real Entra identity, but the Databricks name differs, usually after an email or UPN change.
# MAGIC - *Fix:* first reconcile duplicates in Sections 3c and 3d — a UPN or mail-nickname change often surfaces as two records, which you resolve there, not by a ticket. For a genuine name drift, only **Databricks Support** can correct the name, so the notebook drafts a ticket. **Not scriptable.**
# MAGIC - *Section:* 7 (users), 9b (service principals). *Gate:* none. *Reversible:* not applicable — no identity write.
# MAGIC
# MAGIC **Bucket 3 — a group name collides with an Entra group.**
# MAGIC - *Category:* groups carrying `externalIdsWithGroupnameMatch`.
# MAGIC - *Meaning:* a local group's name matches an Entra group, but they are not linked, so the Entra group cannot provision.
# MAGIC - *Fix:* if there is exactly one candidate, link the group. If there are zero or several, a human decides. **Scriptable when unambiguous.**
# MAGIC - *Section:* 6. *Gate:* `ENABLE_REMEDIATION`, plus `LINK_GROUPS`. *Reversible:* yes, from the audit log.
# MAGIC
# MAGIC **Bucket 4 — the identity belongs to a foreign Entra tenant.**
# MAGIC - *Category:* `EXTERNAL_ID_NOT_IN_IDP` where the username domain is not in `PRIMARY_DOMAINS`.
# MAGIC - *Meaning:* the principal lives in another tenant. AIM is single-tenant and cannot manage it.
# MAGIC - *Fix:* by default, keep it on SCIM — AIM cannot provision it. If you are decommissioning SCIM, coordinate with your Entra admin, confirm it is not needed, then remove or deactivate it in Databricks by hand. **Not scriptable** — the notebook only reports and escalates.
# MAGIC - *Section:* 8. *Gate:* none. *Reversible:* not applicable — no identity write.
# MAGIC
# MAGIC **Bucket 5 — the link points at a deleted or unknown Entra object.**
# MAGIC - *Category:* `EXTERNAL_ID_NOT_IN_IDP` where the domain is in `PRIMARY_DOMAINS`.
# MAGIC - *Meaning:* the `externalId` resolves to nothing in Entra. There is no valid target to link to.
# MAGIC - *Fix:* verify each id is truly deleted in Entra — a changed-email user is not stale, just renamed (Bucket 2). If truly gone, deactivate through the gated path; deletion is an optional manual final step once you are certain. Off by default.
# MAGIC - *Section:* 9. *Gate:* `ENABLE_REMEDIATION`, plus `CONFIRM_DEACTIVATION`. *Reversible:* yes — reactivate from the audit log.
# MAGIC
# MAGIC **Service principals** follow the same three shapes as Buckets 1, 2, and 5, handled in Sections 9a, 9b, and 9c.
# MAGIC Service principals have no email domain, so there is no foreign-tenant split for them.

# COMMAND ----------

# MAGIC %md
# MAGIC ## 1. Prerequisites
# MAGIC
# MAGIC Confirm all four before you run:
# MAGIC - You are a Databricks **account admin**.
# MAGIC - The account service principal and its OAuth secret from the prep script exist in a secret scope (default scope `divergence`, keys `client_id` and `client_secret`).
# MAGIC - **One** of the two input sets sits in a Unity Catalog volume path this notebook can read:
# MAGIC   - the pre-made remediation CSVs (`remediation_1..5_*.csv`) in `CSV_DIR`, **or**
# MAGIC   - the raw prep-script output (`idp_divergence_users.csv`, `idp_divergence_groups.csv`) in `RAW_DIR`.
# MAGIC   - `divergence_workspaces.csv` is read from whichever input folder you use (Section 10).
# MAGIC - The `databricks-sdk` library is available. Run `%pip install databricks-sdk` if it is not.

# COMMAND ----------

# MAGIC %md
# MAGIC ## 2. Configuration
# MAGIC
# MAGIC **What it does:** sets every value the rest of the notebook reads — account and auth coordinates, the input
# MAGIC folders, and the safety flags. Later cells read these values and never change them.
# MAGIC
# MAGIC **Edit these three placeholders before you run:**
# MAGIC - `ACCOUNT_ID` — your Databricks account ID, from the account console URL.
# MAGIC - `CSV_DIR` — the volume folder that holds the pre-made remediation CSVs, if you have them, and receives all outputs (derived worklists, ticket, audit log).
# MAGIC - `RAW_DIR` — the volume folder that holds the raw prep-script output (`idp_divergence_*.csv`). Set it to `CSV_DIR` if both sets live together.
# MAGIC
# MAGIC **Flags reference:**
# MAGIC
# MAGIC | Flag | Default | Effect | What the safe default protects |
# MAGIC |------|---------|--------|---------------|
# MAGIC | `ENABLE_REMEDIATION` | `False` | `False` analyzes and presents only, and no identity write is possible. `True` lets the buckets write, still governed by `DRY_RUN`. | The master gate. Leave it `False` until you have reviewed the Section 4b analysis and a planned audit log. |
# MAGIC | `INPUT_MODE` | `"auto"` | `"auto"` loads pre-made `remediation_*.csv` from `CSV_DIR` if present, else derives buckets from `RAW_DIR`. `"premade"` or `"raw"` force one path. | Controls which input the buckets are built from. |
# MAGIC | `WRITE_DERIVED_WORKLISTS` | `True` | When buckets are derived from raw output, also writes them to `CSV_DIR` as `remediation_*.csv` for your records. | Local file write only. Never touches identities. |
# MAGIC | `DRY_RUN` | `True` | `True` logs intended changes only. `False` runs the SCIM writes, and only when `ENABLE_REMEDIATION=True`. | The second safety switch. Keep it `True` until you have reviewed a dry-run audit log. |
# MAGIC | `COLLISION_PRECHECK` | `True` | Builds the `externalId` index (Section 3b) and checks each target is free before any link. | The KB requires it. If `False`, links are not collision-checked and can create a duplicate identity. |
# MAGIC | `LINK_GROUPS` | `False` | Bucket 3: `True` links the group by setting its `externalId`. `False` leaves it for a console rename. | Group linking is opt-in. |
# MAGIC | `LINK_SERVICE_PRINCIPALS` | `False` | Bucket 6: `True` links the service principal. `False` skips it and logs `LINK_DISABLED`. | Service-principal linking is opt-in. |
# MAGIC | `CONFIRM_DEACTIVATION` | `False` | Bucket 5 second gate: only `True` allows any deactivation to run. | Deactivation is not prescribed by the KB. `False` keeps Bucket 5 review-only. |
# MAGIC | `DEACTIVATION_BATCH_LIMIT` | `25` | The most users deactivated per run, even when confirmed. | Caps how many identities one live Bucket 5 run can touch. |
# MAGIC | `PRIMARY_DOMAINS` | `["example.com"]` | The email domains your tenant owns. | Bucket 5 escalates any non-owned domain instead of deactivating it. Set this to your own domains. |
# MAGIC | `RATE_LIMIT_SLEEP_SEC` | `0.25` | Sleep after each write call. | Avoids SCIM API rate limits. |
# MAGIC | `BATCH_PAUSE_EVERY` | `50` | Take a longer pause every N write calls. | Extra rate-limit protection on large batches. |
# MAGIC | `BATCH_PAUSE_SEC` | `5.0` | The length of that longer pause. | Extra rate-limit protection on large batches. |

# COMMAND ----------

# ---- Account / auth ----
ACCOUNTS_HOST = "https://accounts.azuredatabricks.net"   # accounts console URL, no extra params
# EDIT ME: your Databricks account ID (the UUID in the accounts console URL).
ACCOUNT_ID    = "<YOUR_ACCOUNT_ID>"
# Secret scope holding the account SP's client_id / client_secret (from the prep script).
SECRET_SCOPE  = "divergence"

# ---- Where the files live (UC Volume recommended; see M3) ----
# EDIT ME: folder that holds the pre-made remediation CSVs and receives ALL outputs
# (derived worklists + ticket + audit log).
CSV_DIR = "/Volumes/<catalog>/<schema>/<volume>/aim_remediation"
# EDIT ME: folder that holds the RAW prep-script output (idp_divergence_*.csv).
# Set equal to CSV_DIR if the raw files live alongside everything else.
RAW_DIR = "/Volumes/<catalog>/<schema>/<volume>/aim_remediation/raw_results"

# ---- Input selection (see §4) ----
INPUT_MODE              = "auto"   # "auto" | "premade" | "raw"
WRITE_DERIVED_WORKLISTS = True     # when deriving from raw, also write remediation_*.csv to CSV_DIR

# ---- Execution controls ----
ENABLE_REMEDIATION      = False    # master gate: False = analyze/present only, no writes possible
DRY_RUN                 = True     # True = log intended changes only; False = execute (needs ENABLE_REMEDIATION)
COLLISION_PRECHECK      = True     # H2: verify target externalId is free before each PATCH/link
LINK_GROUPS             = False    # Bucket 3: PATCH group externalId (else rename in console)
LINK_SERVICE_PRINCIPALS = False    # rev.5 Bucket 6: PATCH SP externalId (opt-in, mirrors LINK_GROUPS)
CONFIRM_DEACTIVATION    = False    # H1: second gate for Bucket 5; only True after Entra verification
DEACTIVATION_BATCH_LIMIT = 25      # H1: cap per run even when confirmed
PRIMARY_DOMAINS         = ["example.com"]   # M2: your tenant's owned domains; anything else is treated as cross-tenant
# API throttling (consumed by throttle() in §3): pace SCIM writes to avoid rate limits.
RATE_LIMIT_SLEEP_SEC    = 0.25   # sleep after every write call
BATCH_PAUSE_EVERY       = 50     # ...and take a longer pause every N calls
BATCH_PAUSE_SEC         = 5.0    # length of that longer pause

# COMMAND ----------

# MAGIC %md
# MAGIC ## 3. Authenticate and define the shared helpers
# MAGIC
# MAGIC **What it does:** reads the account service-principal secret, opens an `AccountClient`, stamps a run ID, and
# MAGIC defines every shared helper the buckets use — the audit recorder, the value normalizer, the SCIM paginator, the
# MAGIC link and deactivate calls, the collision guard, and the throttle.
# MAGIC
# MAGIC **Why it matters:** every later cell calls these helpers, so they are defined once, here. Keeping the SCIM
# MAGIC calls in one place also keeps each request payload consistent with the KB.
# MAGIC
# MAGIC This cell also computes the effective mode: `EFFECTIVE_DRY_RUN = DRY_RUN or (not ENABLE_REMEDIATION)`. Every
# MAGIC bucket and the `audit()` helper read it. So with `ENABLE_REMEDIATION=False` (the default) no write can occur,
# MAGIC and once you enable remediation the behavior follows `DRY_RUN` alone.
# MAGIC
# MAGIC **Reads and writes:**
# MAGIC - Identities read: none. This cell only connects and defines functions.
# MAGIC - Identities written: none.
# MAGIC - Files written: none.
# MAGIC
# MAGIC **Gates that govern it:** none. It behaves the same in every mode. Authentication uses OAuth client credentials
# MAGIC through the SDK's `AccountClient`, with secrets from the `SECRET_SCOPE` set in Section 2. No secret is hard-coded.
# MAGIC
# MAGIC **Helpers defined here:**
# MAGIC - `now_iso()` — a UTC timestamp for audit rows.
# MAGIC - `norm(v)` — collapses `(empty)` or whitespace to a true blank.
# MAGIC - `audit(...)` — appends one row to the global `AUDIT` list.
# MAGIC - `_page_scim_list(kind)` — pages an entire account SCIM list, used by Section 3b.
# MAGIC - `scim_patch_external_id(...)` and `scim_set_active(...)` — the two write calls.
# MAGIC - `precheck_free(...)` — the collision guard. It returns `False` when a link is unsafe, so the caller skips it.
# MAGIC - `throttle()` — the rate-limit sleep between write calls.
# MAGIC
# MAGIC **What you'll see:** a one-line banner confirming the connection, the run ID, whether remediation is enabled,
# MAGIC the effective mode, the input mode, and whether the collision precheck is on.
# MAGIC
# MAGIC **Audit rows:** none.
# MAGIC
# MAGIC **If it fails:** a missing or wrong secret is the usual cause. Confirm the `SECRET_SCOPE` and the `client_id` and
# MAGIC `client_secret` keys from Section 2 exist and belong to an account admin service principal. Nothing downstream
# MAGIC can run until this cell connects.

# COMMAND ----------

import time, datetime as dt
import pandas as pd
from databricks.sdk import AccountClient

# Secrets are read at runtime from the secret scope set in §2 — never hard-coded (see §1 prerequisites).
client_id     = dbutils.secrets.get(SECRET_SCOPE, "client_id")
client_secret = dbutils.secrets.get(SECRET_SCOPE, "client_secret")

# Account-level SCIM client (OAuth client-credentials). Every SCIM call below is issued through `a`.
a = AccountClient(host=ACCOUNTS_HOST, account_id=ACCOUNT_ID,
                  client_id=client_id, client_secret=client_secret)

# ---- Run-scoped globals (shared by the helpers and every bucket) ----
RUN_TS = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")   # N1: timezone.utc is 3.2+; dt.UTC is 3.11+ only
AUDIT = []                                  # in-memory action log; serialized to CSV in §11
EXTID_INDEX = {"Users": {}, "Groups": {}, "ServicePrincipals": {}}   # N2 + rev.5: externalId -> [ids]
INDEX_OK = False                            # flipped True only if §3b builds the User/Group index without error
SP_INDEX_OK = False                         # rev.5: independent flag for the ServicePrincipals index (§3b)

# rev.4: the buckets and audit() consult EFFECTIVE_DRY_RUN, not DRY_RUN directly. Unless remediation is
# explicitly enabled we force dry behavior, so analysis-only runs can NEVER write to identities. With
# ENABLE_REMEDIATION=True this collapses to DRY_RUN, i.e. the exact rev. 3 dry-run-then-live behavior.
EFFECTIVE_DRY_RUN = DRY_RUN or (not ENABLE_REMEDIATION)

def now_iso():
    return dt.datetime.now(dt.timezone.utc).isoformat()

def norm(v):
    """M1: treat '(empty)' / whitespace as a true blank."""
    v = (v or "").strip()
    return "" if v == "(empty)" else v

def audit(bucket, action, principal_type, dbx_id, identifier,
          old_external_id="", new_external_id="", status="", error=""):
    # Append one structured row to the global AUDIT list. `mode` is stamped from DRY_RUN so the
    # log shows whether each row was planned or executed. See the §11 dictionary for field meanings.
    AUDIT.append({
        "timestamp_utc": now_iso(), "run_id": RUN_TS,
        "mode": "DRY_RUN" if EFFECTIVE_DRY_RUN else "LIVE",
        "bucket": bucket, "action": action, "principal_type": principal_type,
        "dbx_id": dbx_id, "identifier": identifier,
        "old_externalId": norm(old_external_id), "new_externalId": new_external_id,
        "status": status, "error": error,
    })

def _page_scim_list(principal_kind):
    """N2: yield every resource from an account SCIM list endpoint, paginating.
    No filter is used — the account Users list only supports filtering by userName
    (not externalId), and returns 100 at a time, so we page the whole directory."""
    path = f"/api/2.1/accounts/{ACCOUNT_ID}/scim/v2/{principal_kind}"
    start, count, guard = 1, 100, 0
    while True:
        guard += 1
        if guard > 500:
            raise RuntimeError("pagination guard tripped (>500 pages)")
        resp = a.api_client.do("GET", path,
                               query={"startIndex": str(start), "count": str(count),
                                      "attributes": "id,externalId"})
        res = resp.get("Resources") or []
        for r in res:
            yield r
        got = len(res)
        total = int(resp.get("totalResults") or 0)
        start += got
        if got == 0 or (total and start > total):
            break

def scim_patch_external_id(principal_kind, dbx_id, new_external_id):
    # The one write used by Buckets 1 and 3: replace an identity's externalId.
    # L4: raw api_client.do() mirrors the KB's exact SCIM PatchOp payload (the typed SDK is an alternative).
    path = f"/api/2.1/accounts/{ACCOUNT_ID}/scim/v2/{principal_kind}/{dbx_id}"
    body = {"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
            "Operations": [{"op": "replace", "path": "externalId", "value": new_external_id}]}
    return a.api_client.do("PATCH", path, body=body)

def scim_set_active(dbx_id, active: bool):
    # L5: boolean is per the SCIM RFC. Test on 1-2 users first; switch to "false" if rejected.
    path = f"/api/2.1/accounts/{ACCOUNT_ID}/scim/v2/Users/{dbx_id}"
    body = {"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
            "Operations": [{"op": "replace", "path": "active", "value": active}]}
    return a.api_client.do("PATCH", path, body=body)

def precheck_free(principal_kind, target, self_id, bucket, ptype, ident):
    """H2 guard (index-based). Returns True if safe to write; fails CLOSED."""
    if not COLLISION_PRECHECK:
        return True
    # rev.5: SPs use their own index-readiness flag so an SP-endpoint failure never blocks
    # user/group patches, and a user/group failure never blocks SP patches. Both fail CLOSED.
    index_ready = SP_INDEX_OK if principal_kind == "ServicePrincipals" else INDEX_OK
    if not index_ready:
        audit(bucket, "PRECHECK_ERROR", ptype, self_id, ident, "", target, "skipped", "externalId index unavailable")
        print(f"[SKIP] {ident}: externalId index unavailable — not patching.")
        return False
    holders = [i for i in EXTID_INDEX.get(principal_kind, {}).get(target, []) if i and i != self_id]
    if holders:
        audit(bucket, "COLLISION", ptype, self_id, ident, "", target, "skipped",
              f"externalId already held by {';'.join(map(str, holders))}")
        print(f"[SKIP] {ident}: target {target} already held by {holders} — flagged, not patched.")
        return False
    return True

# Call counter lives in a dict so throttle() can mutate it without a `global` statement.
_calls = {"n": 0}
def throttle():
    # Called after each *live* write to pace requests: a short sleep every call, a longer one every N.
    _calls["n"] += 1
    time.sleep(RATE_LIMIT_SLEEP_SEC)
    if _calls["n"] % BATCH_PAUSE_EVERY == 0:
        time.sleep(BATCH_PAUSE_SEC)

# One-line connection banner so the operator can confirm account, run id, and mode at a glance.
_eff_mode = "DRY_RUN" if EFFECTIVE_DRY_RUN else "LIVE"
print(f"Connected. Run ID {RUN_TS}. Remediation={'ENABLED' if ENABLE_REMEDIATION else 'DISABLED (analysis only)'}. "
      f"Effective mode={_eff_mode}. Input mode={INPUT_MODE}. Collision precheck={COLLISION_PRECHECK}.")
if not ENABLE_REMEDIATION:
    print("ENABLE_REMEDIATION=False → analysis + presentation only; no identity writes are possible this run.")

# COMMAND ----------

# MAGIC %md
# MAGIC ## 3b. Build the externalId collision index
# MAGIC
# MAGIC **What it does:** pages the entire account Users, Groups, and ServicePrincipals directory once and builds an
# MAGIC in-memory index of `externalId -> [ids]` (`EXTID_INDEX`). It then sets `INDEX_OK` for Users and Groups, and
# MAGIC `SP_INDEX_OK` for service principals.
# MAGIC
# MAGIC **Why it matters:** before you link an identity, you must confirm no other principal already holds the target
# MAGIC `externalId`. Two principals with the same `externalId` is the duplicate this whole notebook exists to prevent.
# MAGIC The check has to be local because the account Users list filters only by `userName`, not by `externalId`, and
# MAGIC returns 100 rows at a time. So a per-target filter is unreliable. Paging the whole directory once and indexing
# MAGIC it in memory sidesteps that limit and lets you check every principal, including the ones that did not diverge.
# MAGIC
# MAGIC **Reads and writes:**
# MAGIC - Identities read: the whole account directory, through repeated `GET .../scim/v2/{Users,Groups,ServicePrincipals}` via `_page_scim_list`. Expect 30 or more GETs, which can take a minute.
# MAGIC - Identities written: none. This cell is read-only.
# MAGIC - Files written: none.
# MAGIC
# MAGIC **Gates that govern it:** `COLLISION_PRECHECK`. When `False`, the notebook builds no index and later links are
# MAGIC not collision-checked. The Users and Groups index is one unit, governed by `INDEX_OK`. The ServicePrincipals
# MAGIC index is built separately, governed by `SP_INDEX_OK`, so a failure on one path never blocks the other.
# MAGIC
# MAGIC **What you'll see:** one summary line per principal kind — the number indexed, the count of distinct
# MAGIC `externalId` values, and how many are already shared by more than one principal. A shared count above zero is a
# MAGIC pre-existing duplicate that Section 3c will list for you.
# MAGIC
# MAGIC **Audit rows:** none.
# MAGIC
# MAGIC **If it fails:** the build fails closed. If the Users and Groups index cannot be built, `INDEX_OK` stays
# MAGIC `False` and every collision-checked link is skipped rather than risked. If only the ServicePrincipals endpoint
# MAGIC fails, `SP_INDEX_OK` stays `False` and only service-principal links are skipped. Resolve the SCIM error and
# MAGIC re-run before you link anything.

# COMMAND ----------

def _build_extid_index(kind):
    """Page the WHOLE directory for one principal kind, bucket ids under their externalId into
    EXTID_INDEX[kind], and print a one-line summary. Raises on any SCIM error (the caller decides
    the fail-closed policy)."""
    idx = EXTID_INDEX[kind]; total = 0
    for r in _page_scim_list(kind):
        total += 1
        # Only index non-blank externalIds; blanks can't collide.
        ext = (r.get("externalId") or "").strip()
        if ext:
            idx.setdefault(ext, []).append(r.get("id"))
    # A count > 1 here means that externalId is already shared before we touch anything.
    dups = sum(1 for v in idx.values() if len(v) > 1)
    print(f"Indexed {total} {kind}: {len(idx)} distinct externalIds, {dups} already shared by >1 principal.")

if COLLISION_PRECHECK:
    # Users + Groups: unchanged rev.3/4 behavior — a single fail-closed unit governed by INDEX_OK.
    try:
        for kind in ("Users", "Groups"):
            _build_extid_index(kind)
        INDEX_OK = True   # only now is precheck_free() allowed to clear User/Group PATCHes
    except Exception as e:
        # Fail CLOSED: if the index can't be built, INDEX_OK stays False and every User/Group PATCH is skipped (H2).
        INDEX_OK = False
        print(f"!! Could not build User/Group externalId index: {e}")
        print("!! Collision pre-check cannot run — every User/Group PATCH will be SKIPPED until this is resolved.")
        print("!! (Set COLLISION_PRECHECK=False only if you accept the KB's duplicate-identity risk.)")

    # rev.5: ServicePrincipals are indexed independently so an SP-endpoint failure can NEVER block the
    # user/group path (and vice-versa). SP PATCHes (Bucket 6) fail closed on SP_INDEX_OK alone.
    try:
        _build_extid_index("ServicePrincipals")
        SP_INDEX_OK = True
    except Exception as e:
        SP_INDEX_OK = False
        print(f"!! Could not build ServicePrincipals externalId index: {e}")
        print("!! SP collision pre-check cannot run — every SP PATCH (Bucket 6) will be SKIPPED until resolved.")
else:
    print("COLLISION_PRECHECK=False — no collision index built; patches will NOT be collision-checked.")

# COMMAND ----------

# MAGIC %md
# MAGIC ## 3c. Diagnostic (read-only) — duplicate externalId clusters
# MAGIC
# MAGIC **What it does:** expands the "already shared by more than one principal" count from Section 3b into the actual
# MAGIC clusters — every `externalId` held by more than one principal — using the in-memory `EXTID_INDEX`. It can
# MAGIC resolve each duplicate id to its `userName` or `displayName` and write a triage CSV.
# MAGIC
# MAGIC **Why it matters:** a shared `externalId` means two Databricks identities claim the same Entra object. AIM
# MAGIC cannot tell them apart, so you must resolve each cluster by hand before enabling AIM. This cell gives you the
# MAGIC worklist to decide, per cluster, which record to keep and which to migrate then remove.
# MAGIC
# MAGIC **Reads and writes:**
# MAGIC - Identities read: `EXTID_INDEX` in memory, plus one read-only `GET .../scim/v2/{kind}/{id}` per duplicate id when `DUP_RESOLVE_NAMES=True`.
# MAGIC - Identities written: none.
# MAGIC - Files written: `CSV_DIR/duplicate_externalids_<run>.csv` when `DUP_REPORT_CSV=True`.
# MAGIC
# MAGIC **Gates that govern it:** it needs `INDEX_OK=True`, which means `COLLISION_PRECHECK=True` and Section 3b
# MAGIC succeeded. `DUP_RESOLVE_NAMES` and `DUP_REPORT_CSV` are local toggles in the cell.
# MAGIC
# MAGIC **What you'll see:** a duplicate count per principal kind, one block per cluster showing the `externalId` and
# MAGIC its ids (with names when resolved), and the report path.
# MAGIC
# MAGIC **Audit rows:** none.
# MAGIC
# MAGIC **If it fails:** if `INDEX_OK` is `False`, the cell prints a note and stops — run Section 3b with
# MAGIC `COLLISION_PRECHECK=True` first. A per-id name lookup that fails is recorded inline and does not stop the cell.

# COMMAND ----------

# ---- Read-only diagnostic: enumerate duplicate externalId clusters (uses the §3b index) ----
DUP_RESOLVE_NAMES = True    # best-effort userName/displayName per duplicate id (extra read-only GETs)
DUP_REPORT_CSV    = True    # also write the clusters to CSV_DIR for triage

def _scim_get(principal_kind, dbx_id):
    # Read-only fetch of a single principal's attributes (name / active / externalId).
    return a.api_client.do("GET", f"/api/2.1/accounts/{ACCOUNT_ID}/scim/v2/{principal_kind}/{dbx_id}")

if not INDEX_OK:
    # The index is what tells us who shares an externalId; without it there is nothing to enumerate.
    print("externalId index not built (INDEX_OK=False) — run §3b with COLLISION_PRECHECK=True first.")
else:
    dup_rows = []
    for kind in ("Users", "Groups"):
        # A cluster = one externalId mapped to >1 principal id (the duplicates).
        dups = {ext: ids for ext, ids in EXTID_INDEX[kind].items() if len(ids) > 1}
        involved = sum(len(v) for v in dups.values())
        print(f"\n{kind}: {len(dups)} externalIds shared by >1 principal ({involved} records involved).")
        for ext, ids in sorted(dups.items(), key=lambda kv: -len(kv[1])):
            print(f"  externalId {ext}  <-  {len(ids)} ids")
            for pid in ids:
                name, active = "", ""
                if DUP_RESOLVE_NAMES:
                    # One read-only GET per duplicate id; failures are recorded, never raised.
                    try:
                        rec = _scim_get(kind, pid)
                        name = rec.get("userName") or rec.get("displayName") or ""
                        active = rec.get("active", "")
                    except Exception as e:
                        name = f"(lookup failed: {e})"
                    print(f"       - {pid}  {name}  active={active}")
                dup_rows.append({"principal_kind": kind, "externalId": ext,
                                 "dbx_id": pid, "identifier": name, "active": active})
    if DUP_REPORT_CSV and dup_rows:
        # Report file only — this is not an identity write.
        dup_path = f"{CSV_DIR}/duplicate_externalids_{RUN_TS}.csv"
        try:
            pd.DataFrame(dup_rows).to_csv(dup_path, index=False)
            print(f"\nDuplicate-externalId report written to: {dup_path}")
        except Exception as e:
            print(f"\n(Could not write duplicate report: {e})")
    print("\nREAD-ONLY diagnostic complete — no identities were modified.")

# COMMAND ----------

# MAGIC %md
# MAGIC ## 3d. Diagnostic (read-only) — duplicate triage sheet with a suggested keeper
# MAGIC
# MAGIC **What it does:** turns the raw duplicate clusters from Section 3c into a review-ready sheet. For each user
# MAGIC record that shares an `externalId` it adds `active`, `meta.created`, and the group-membership count, and can add
# MAGIC the Entra UPN and `accountEnabled` from Microsoft Graph. It then marks a suggested keeper per cluster.
# MAGIC
# MAGIC **Why it matters:** a raw list of ids is not actionable. The triage sheet lets you confirm which record to keep
# MAGIC and which to migrate then remove, following the duplicate-resolution playbook.
# MAGIC
# MAGIC **Reads and writes:**
# MAGIC - Identities read: one read-only `GET .../scim/v2/Users/{id}` per duplicate id, plus one Graph `GET /users/{objectId}` per cluster when `GRAPH_ENABLED=True`.
# MAGIC - Identities written: none.
# MAGIC - Files written: `CSV_DIR/duplicate_triage_<run>.csv` when `TRIAGE_REPORT_CSV=True`.
# MAGIC
# MAGIC **Gates that govern it:** it needs `INDEX_OK=True`, which needs Section 3b. `GRAPH_ENABLED`, with
# MAGIC `GRAPH_TENANT_ID` and the `graph_client_id` and `graph_client_secret` secret keys, adds the Entra columns. Leave
# MAGIC it `False` if you have no Graph credentials — the sheet still ranks by `active`, group count, and creation date.
# MAGIC
# MAGIC **The suggested keeper is a hint, not a decision.** It ranks each record by `active`, then UPN match if Graph is
# MAGIC on, then group-membership count, then the most recent `meta.created`. The top record is flagged `KEEP` and the
# MAGIC rest `REVIEW_REMOVE`. Always confirm the choice, and migrate assets and memberships to the keeper, before you
# MAGIC remove anything.
# MAGIC
# MAGIC **What you'll see:** the enriched triage table and the report path.
# MAGIC
# MAGIC **Audit rows:** none.
# MAGIC
# MAGIC **If it fails:** if `INDEX_OK` is `False`, run Section 3b first. If Graph credentials are missing or wrong, set
# MAGIC `GRAPH_ENABLED=False` and use the sheet without the Entra columns.

# COMMAND ----------

# ---- Read-only diagnostic: enrich duplicate clusters into a triage sheet (uses the §3b index) ----
GRAPH_ENABLED      = False           # True = resolve Entra UPN/accountEnabled via Microsoft Graph
GRAPH_TENANT_ID    = "<tenant-id>"   # required only if GRAPH_ENABLED
GRAPH_SECRET_SCOPE = SECRET_SCOPE    # scope holding graph_client_id / graph_client_secret
TRIAGE_REPORT_CSV  = True

import json

def _graph_token():
    # Client-credentials token for Graph; only called when GRAPH_ENABLED.
    import urllib.request, urllib.parse
    data = urllib.parse.urlencode({
        "client_id": dbutils.secrets.get(GRAPH_SECRET_SCOPE, "graph_client_id"),
        "client_secret": dbutils.secrets.get(GRAPH_SECRET_SCOPE, "graph_client_secret"),
        "scope": "https://graph.microsoft.com/.default",
        "grant_type": "client_credentials"}).encode()
    url = f"https://login.microsoftonline.com/{GRAPH_TENANT_ID}/oauth2/v2.0/token"
    with urllib.request.urlopen(urllib.request.Request(url, data=data)) as resp:
        return json.loads(resp.read())["access_token"]

def _graph_user(token, object_id):
    import urllib.request
    url = f"https://graph.microsoft.com/v1.0/users/{object_id}?$select=userPrincipalName,accountEnabled,displayName"
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"})
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read())

def _is_active(v):
    return v in (True, "true", "True")

if not INDEX_OK:
    print("externalId index not built (INDEX_OK=False) — run §3b with COLLISION_PRECHECK=True first.")
else:
    # Reuse §3c's helper if present; otherwise define an equivalent read-only GET locally.
    _get = globals().get("_scim_get",
                         lambda k, i: a.api_client.do("GET", f"/api/2.1/accounts/{ACCOUNT_ID}/scim/v2/{k}/{i}"))

    _gtok = None
    if GRAPH_ENABLED:
        try:
            _gtok = _graph_token()
        except Exception as e:
            print(f"(Graph enrichment disabled — token fetch failed: {e})")

    dup_users = {ext: ids for ext, ids in EXTID_INDEX["Users"].items() if len(ids) > 1}
    print(f"Enriching {len(dup_users)} duplicate clusters ({sum(len(v) for v in dup_users.values())} records)...")

    triage = []
    for ext, ids in dup_users.items():
        # Entra truth for the cluster (one lookup per objectId, if Graph is on).
        upn, enabled = "", ""
        if _gtok:
            try:
                g = _graph_user(_gtok, ext)
                upn, enabled = g.get("userPrincipalName", "") or "", g.get("accountEnabled", "")
            except Exception as e:
                upn = f"(graph lookup failed: {e})"

        # Per-record SCIM detail: active, created, group-membership count.
        recs = []
        for pid in ids:
            try:
                r = _get("Users", pid)
                recs.append({"dbx_id": pid, "userName": r.get("userName", ""),
                             "active": r.get("active", ""),
                             "created": (r.get("meta") or {}).get("created", "") or "",
                             "groups": len(r.get("groups") or [])})
            except Exception as e:
                recs.append({"dbx_id": pid, "userName": f"(lookup failed: {e})",
                             "active": "", "created": "", "groups": 0})

        # Rank keeper: active, then UPN match (if Graph), then #groups, then newest created.
        def _rank(rec):
            match = 1 if (upn and rec["userName"].lower() == upn.lower()) else 0
            return (1 if _is_active(rec["active"]) else 0, match, rec["groups"], rec["created"])
        keeper_id = sorted(recs, key=_rank, reverse=True)[0]["dbx_id"] if recs else None

        for rec in recs:
            signals = []
            if _is_active(rec["active"]): signals.append("active")
            if upn and rec["userName"].lower() == upn.lower(): signals.append("UPN match")
            if rec["groups"]: signals.append(f"{rec['groups']} groups")
            is_keeper = rec["dbx_id"] == keeper_id
            triage.append({
                "externalId": ext, "shared_by": len(ids), "dbx_id": rec["dbx_id"],
                "userName": rec["userName"], "active": rec["active"],
                "meta_created": rec["created"], "group_count": rec["groups"],
                "entra_upn": upn, "entra_enabled": enabled,
                "suggested_keeper": "Y" if is_keeper else "N",
                "suggested_action": "KEEP" if is_keeper else "REVIEW_REMOVE (migrate assets, then deactivate)",
                "keeper_signals": ";".join(signals)})

    triage_df = pd.DataFrame(triage)
    if len(triage_df):
        triage_df = triage_df.sort_values(["shared_by", "externalId", "suggested_keeper"],
                                          ascending=[False, True, False]).reset_index(drop=True)
        print(triage_df.to_string(index=False))
        if TRIAGE_REPORT_CSV:
            tpath = f"{CSV_DIR}/duplicate_triage_{RUN_TS}.csv"
            try:
                triage_df.to_csv(tpath, index=False)
                print(f"\nTriage sheet written to: {tpath}")
            except Exception as e:
                print(f"\n(Could not write triage sheet: {e})")
        try:
            display(triage_df)
        except Exception:
            pass
    else:
        print("No duplicate user clusters to triage.")
    print("\nSUGGESTED keeper is a heuristic — confirm (and migrate assets) before removing any record. READ-ONLY: nothing modified.")

# COMMAND ----------

# MAGIC %md
# MAGIC ## 4. Build the remediation worklists (from pre-made CSVs or raw scan output)
# MAGIC
# MAGIC **What it does:** builds the in-memory tables (`b1` through `b5`, plus `b6` through `b8` for service
# MAGIC principals) that the buckets consume. It reads either the pre-segmented `remediation_*.csv` in `CSV_DIR` or the
# MAGIC raw prep-script output in `RAW_DIR`. Every column is a string and blanks are preserved.
# MAGIC
# MAGIC **Why it matters:** this is where each divergence is sorted into its bucket, which decides its fix. The sort
# MAGIC order is deliberate. A user that matches several categories lands in the first bucket that applies.
# MAGIC
# MAGIC **How the input is chosen (`INPUT_MODE`):**
# MAGIC - `"auto"` (default): if all five `remediation_*.csv` exist in `CSV_DIR`, load them. Otherwise derive the buckets from the raw files in `RAW_DIR`.
# MAGIC - `"premade"`: always load the `remediation_*.csv`, and error if any is missing.
# MAGIC - `"raw"`: always classify from `RAW_DIR`.
# MAGIC
# MAGIC **How users are classified**, from `idp_divergence_users.csv`, in this precedence order:
# MAGIC - **Bucket 1:** `errorCategories` contains `NAME_MATCH_EXTERNAL_ID_MISMATCH` and `externalIdWithUsernameMatch` is set. The target is that match. This precedence deliberately absorbs rows that are also `EXTERNAL_ID_NOT_IN_IDP`, because a valid name-match target still exists.
# MAGIC - **Bucket 2:** otherwise `EXTERNAL_ID_MATCH_NAME_MISMATCH`.
# MAGIC - **Bucket 4:** otherwise `EXTERNAL_ID_NOT_IN_IDP` and the username domain is not in `PRIMARY_DOMAINS`.
# MAGIC - **Bucket 5:** otherwise `EXTERNAL_ID_NOT_IN_IDP` and the domain is in `PRIMARY_DOMAINS`.
# MAGIC - Any row that matches none of these is collected in `b_unclassified` and shown in Section 4b. Nothing is dropped silently.
# MAGIC
# MAGIC **Groups**, from `idp_divergence_groups.csv`, form Bucket 3: the candidate Entra groups come from
# MAGIC `externalIdsWithGroupnameMatch`, and `candidateCount` is how many there are.
# MAGIC
# MAGIC **Service principals**, from `idp_divergence_service_principals.csv`, keyed on `applicationId`:
# MAGIC - **Bucket 6:** `NAME_MATCH_EXTERNAL_ID_MISMATCH` with `externalIdWithAppIdMatch` set. The target is that match. Governed by `LINK_SERVICE_PRINCIPALS`.
# MAGIC - **Bucket 7:** otherwise `EXTERNAL_ID_MATCH_NAME_MISMATCH`, a Support-only name fix with no identity write.
# MAGIC - **Bucket 8:** otherwise `EXTERNAL_ID_NOT_IN_IDP`. Service principals have no email domain, so there is no foreign-tenant split, and clearing `externalId` is groups-only. So this is review-only.
# MAGIC - Any unmatched service principal is collected in `sp_unclassified` and shown in Section 4b.
# MAGIC
# MAGIC **Read the domain split carefully.** The Bucket 4 versus Bucket 5 decision is a heuristic keyed on
# MAGIC `PRIMARY_DOMAINS`, not on the authoritative Entra home tenant. Review the Section 4b domain breakdown before you
# MAGIC enable remediation, and set `PRIMARY_DOMAINS` to your own owned domains.
# MAGIC
# MAGIC **Reads and writes:**
# MAGIC - Identities read: none. This cell reads local CSVs only.
# MAGIC - Identities written: none.
# MAGIC - Files written: the derived worklists `remediation_*.csv` in `CSV_DIR`, when the input is raw and `WRITE_DERIVED_WORKLISTS=True`.
# MAGIC
# MAGIC **Gates that govern it:** `INPUT_MODE` chooses the input, and `WRITE_DERIVED_WORKLISTS` controls whether derived
# MAGIC worklists are saved. Neither touches identities.
# MAGIC
# MAGIC **What you'll see:** a line naming the resolved input mode, one line per bucket with its row count, and a
# MAGIC "derived worklists written" note when the input is raw.
# MAGIC
# MAGIC **Audit rows:** none.
# MAGIC
# MAGIC **If it fails:** in `"premade"` mode a missing `remediation_*.csv` raises. Confirm the five files are in
# MAGIC `CSV_DIR`, or switch `INPUT_MODE` to `"raw"` or `"auto"`. If the buckets look wrong, read `b_unclassified` and
# MAGIC the domain breakdown in Section 4b before going further.

# COMMAND ----------

# The five pre-made worklist filenames (rev. 3 layout), keyed by bucket handle.
PREMADE_FILES = {
    "b1": "remediation_1_users_PATCH_externalid.csv",
    "b2": "remediation_2_users_SUPPORT_ticket.csv",
    "b3": "remediation_3_groups_name_collision.csv",
    "b4": "remediation_4_users_CROSS_TENANT_escalate.csv",
    "b5": "remediation_5_users_STALE_deactivate.csv",
}

# Column order each bucket expects — used for both raw derivation and writing derived worklists.
BUCKET_COLUMNS = {
    "b1": ["id", "username", "currentExternalId", "targetExternalId"],
    "b2": ["id", "username", "externalId"],
    "b3": ["id", "groupName", "currentExternalId", "candidateCount", "candidateExternalIds"],
    "b4": ["id", "username", "externalId"],
    "b5": ["id", "username", "externalId"],
}

# rev.5: SP worklist columns (identifier is applicationId; target is externalIdWithAppIdMatch).
BUCKET_COLUMNS.update({
    "b6": ["id", "applicationId", "currentExternalId", "targetExternalId"],
    "b7": ["id", "applicationId", "externalId"],
    "b8": ["id", "applicationId", "externalId"],
})

# Kept separate from PREMADE_FILES so _premade_present() still requires only the original five —
# older premade drops without SP files stay valid and SP files are loaded best-effort.
SP_PREMADE_FILES = {
    "b6": "remediation_6_sps_PATCH_externalid.csv",
    "b7": "remediation_7_sps_SUPPORT_ticket.csv",
    "b8": "remediation_8_sps_STALE_review.csv",
}


def load_csv(name, base_dir):
    # dtype=str keeps IDs/externalIds as text (no numeric coercion); fillna("") makes empty cells
    # true blanks so norm() and the guards behave predictably.
    df = pd.read_csv(f"{base_dir}/{name}", dtype=str).fillna("")
    print(f"{name}: {len(df)} rows")
    return df


def _premade_present():
    # True only if EVERY pre-made worklist exists in CSV_DIR (so "auto" can trust the rev. 3 path).
    import os
    return all(os.path.exists(f"{CSV_DIR}/{f}") for f in PREMADE_FILES.values())


def _domain_of(u):
    # Email domain, lowercased; "" if there is no '@'. Mirrors §9's domain_of for the b4/b5 split.
    return u.split("@")[-1].lower() if "@" in u else ""


def derive_from_raw(raw_dir):
    """Classify the raw prep-script output into the five bucket DataFrames (see the §4 markdown for rules)."""
    raw_users = load_csv("idp_divergence_users.csv", raw_dir)
    raw_groups = load_csv("idp_divergence_groups.csv", raw_dir)
    primary = [d.lower() for d in PRIMARY_DOMAINS]

    b1_rows, b2_rows, b4_rows, b5_rows, unclassified = [], [], [], [], []
    for _, r in raw_users.iterrows():
        cats = {c for c in (r.get("errorCategories", "") or "").split(";") if c}
        uname = r.get("username", "")
        ext = r.get("externalId", "")
        name_match_target = r.get("externalIdWithUsernameMatch", "")
        # Precedence: a usable name-match target (b1) wins over a stale/cross-tenant classification.
        if "NAME_MATCH_EXTERNAL_ID_MISMATCH" in cats and name_match_target:
            b1_rows.append({"id": r.get("id", ""), "username": uname,
                            "currentExternalId": ext, "targetExternalId": name_match_target})
        elif "EXTERNAL_ID_MATCH_NAME_MISMATCH" in cats:
            b2_rows.append({"id": r.get("id", ""), "username": uname, "externalId": ext})
        elif "EXTERNAL_ID_NOT_IN_IDP" in cats:
            dest = b4_rows if _domain_of(uname) not in primary else b5_rows
            dest.append({"id": r.get("id", ""), "username": uname, "externalId": ext})
        else:
            unclassified.append({"id": r.get("id", ""), "username": uname, "externalId": ext,
                                 "errorCategories": r.get("errorCategories", "")})

    b3_rows = []
    for _, r in raw_groups.iterrows():
        cands = [c for c in (r.get("externalIdsWithGroupnameMatch", "") or "").split(";") if c.strip()]
        b3_rows.append({"id": r.get("id", ""), "groupName": r.get("groupName", ""),
                        "currentExternalId": r.get("externalId", ""),
                        "candidateCount": str(len(cands)),
                        "candidateExternalIds": r.get("externalIdsWithGroupnameMatch", "")})

    out = {
        "b1": pd.DataFrame(b1_rows, columns=BUCKET_COLUMNS["b1"]),
        "b2": pd.DataFrame(b2_rows, columns=BUCKET_COLUMNS["b2"]),
        "b3": pd.DataFrame(b3_rows, columns=BUCKET_COLUMNS["b3"]),
        "b4": pd.DataFrame(b4_rows, columns=BUCKET_COLUMNS["b4"]),
        "b5": pd.DataFrame(b5_rows, columns=BUCKET_COLUMNS["b5"]),
        "unclassified": pd.DataFrame(unclassified,
                                     columns=["id", "username", "externalId", "errorCategories"]),
    }
    return out


def derive_sps_from_raw(raw_dir):
    """Classify idp_divergence_service_principals.csv into the SP buckets (b6/b7/b8).
    SPs are keyed by applicationId and have NO email domain, so the b4/b5 cross-tenant-vs-stale
    split does not apply — EXTERNAL_ID_NOT_IN_IDP is routed to review-only (b8)."""
    try:
        raw_sps = load_csv("idp_divergence_service_principals.csv", raw_dir)
    except Exception as e:
        print(f"(no service-principal divergences to classify: {e})")
        return {
            "b6": pd.DataFrame(columns=BUCKET_COLUMNS["b6"]),
            "b7": pd.DataFrame(columns=BUCKET_COLUMNS["b7"]),
            "b8": pd.DataFrame(columns=BUCKET_COLUMNS["b8"]),
            "sp_unclassified": pd.DataFrame(columns=["id", "applicationId", "externalId", "errorCategories"]),
        }

    b6_rows, b7_rows, b8_rows, sp_unclassified = [], [], [], []
    for _, r in raw_sps.iterrows():
        cats = {c for c in (r.get("errorCategories", "") or "").split(";") if c}
        appid = r.get("applicationId", "")
        ext = r.get("externalId", "")
        appid_match_target = r.get("externalIdWithAppIdMatch", "")   # scalar, per KB
        # Precedence mirrors the user path: a usable appId-match target (b6) wins.
        if "NAME_MATCH_EXTERNAL_ID_MISMATCH" in cats and appid_match_target:
            b6_rows.append({"id": r.get("id", ""), "applicationId": appid,
                            "currentExternalId": ext, "targetExternalId": appid_match_target})
        elif "EXTERNAL_ID_MATCH_NAME_MISMATCH" in cats:
            b7_rows.append({"id": r.get("id", ""), "applicationId": appid, "externalId": ext})
        elif "EXTERNAL_ID_NOT_IN_IDP" in cats:
            b8_rows.append({"id": r.get("id", ""), "applicationId": appid, "externalId": ext})
        else:
            sp_unclassified.append({"id": r.get("id", ""), "applicationId": appid, "externalId": ext,
                                    "errorCategories": r.get("errorCategories", "")})

    return {
        "b6": pd.DataFrame(b6_rows, columns=BUCKET_COLUMNS["b6"]),
        "b7": pd.DataFrame(b7_rows, columns=BUCKET_COLUMNS["b7"]),
        "b8": pd.DataFrame(b8_rows, columns=BUCKET_COLUMNS["b8"]),
        "sp_unclassified": pd.DataFrame(sp_unclassified,
                                        columns=["id", "applicationId", "externalId", "errorCategories"]),
    }


# ---- Resolve the input mode (auto-detect unless forced) ----
if INPUT_MODE == "premade":
    resolved_mode = "premade"
elif INPUT_MODE == "raw":
    resolved_mode = "raw"
else:  # "auto"
    resolved_mode = "premade" if _premade_present() else "raw"
print(f"Resolved input mode: {resolved_mode} (INPUT_MODE={INPUT_MODE}).")

# Populated only in raw mode; §4b surfaces any rows here.
b_unclassified = pd.DataFrame(columns=["id", "username", "externalId", "errorCategories"])

if resolved_mode == "premade":
    # rev. 3 path — load the segmentation CSVs exactly as before.
    b1 = load_csv(PREMADE_FILES["b1"], CSV_DIR)
    b2 = load_csv(PREMADE_FILES["b2"], CSV_DIR)
    b3 = load_csv(PREMADE_FILES["b3"], CSV_DIR)
    b4 = load_csv(PREMADE_FILES["b4"], CSV_DIR)
    b5 = load_csv(PREMADE_FILES["b5"], CSV_DIR)
else:
    # Raw path — classify in memory, then (optionally) persist the derived worklists for review/audit.
    derived = derive_from_raw(RAW_DIR)
    b1, b2, b3, b4, b5 = derived["b1"], derived["b2"], derived["b3"], derived["b4"], derived["b5"]
    b_unclassified = derived["unclassified"]
    if WRITE_DERIVED_WORKLISTS:
        for handle, fname in PREMADE_FILES.items():
            out_path = f"{CSV_DIR}/{fname}"
            try:
                derived[handle].to_csv(out_path, index=False)
                print(f"Derived worklist written to: {out_path}")
            except Exception as e:
                print(f"(Could not write derived worklist {fname}: {e})")

# Consistent per-bucket count summary for either path.
for _h, _df in (("b1", b1), ("b2", b2), ("b3", b3), ("b4", b4), ("b5", b5)):
    print(f"{_h}: {len(_df)} rows")
if len(b_unclassified):
    print(f"b_unclassified: {len(b_unclassified)} rows (see §4b — not actioned by any bucket)")

# ---- Service principals (rev.5): populate b6/b7/b8 alongside the user/group buckets ----
sp_unclassified = pd.DataFrame(columns=["id", "applicationId", "externalId", "errorCategories"])
if resolved_mode == "premade":
    import os
    def _load_sp_premade(handle):
        # SP worklists are optional in premade mode — older drops may not include them.
        fp = f"{CSV_DIR}/{SP_PREMADE_FILES[handle]}"
        if os.path.exists(fp):
            return load_csv(SP_PREMADE_FILES[handle], CSV_DIR)
        print(f"(SP worklist {SP_PREMADE_FILES[handle]} not present — treating as 0 rows)")
        return pd.DataFrame(columns=BUCKET_COLUMNS[handle])
    b6, b7, b8 = _load_sp_premade("b6"), _load_sp_premade("b7"), _load_sp_premade("b8")
else:
    sp_derived = derive_sps_from_raw(RAW_DIR)
    b6, b7, b8 = sp_derived["b6"], sp_derived["b7"], sp_derived["b8"]
    sp_unclassified = sp_derived["sp_unclassified"]
    if WRITE_DERIVED_WORKLISTS:
        for handle, fname in SP_PREMADE_FILES.items():
            out_path = f"{CSV_DIR}/{fname}"
            try:
                sp_derived[handle].to_csv(out_path, index=False)
                print(f"Derived SP worklist written to: {out_path}")
            except Exception as e:
                print(f"(Could not write derived SP worklist {fname}: {e})")

for _h, _df in (("b6", b6), ("b7", b7), ("b8", b8)):
    print(f"{_h}: {len(_df)} rows")
if len(sp_unclassified):
    print(f"sp_unclassified: {len(sp_unclassified)} rows (see §4b — not actioned by any bucket)")

# COMMAND ----------

# MAGIC %md
# MAGIC ## 4b. Analyze and present the plan (read-only) — the review checkpoint
# MAGIC
# MAGIC **What it does:** summarizes the worklists from Section 4 so you can review the plan before enabling
# MAGIC remediation. It prints a per-bucket summary with each bucket's count, fix, and gate; the error-category
# MAGIC distribution; the domain split that decides Bucket 4 versus Bucket 5; the group candidate-count breakdown; the
# MAGIC federation-disabled workspace count; the full service-principal plan; and any scan failures or unclassified rows.
# MAGIC
# MAGIC **Why it matters:** this is the checkpoint. Read it, confirm the buckets and counts match what you expect, then
# MAGIC decide whether to set `ENABLE_REMEDIATION=True`. Do not skip it — this is your last look before any write.
# MAGIC
# MAGIC **Reads and writes:**
# MAGIC - Identities read: none. The cell reads `b1` through `b5` and `b_unclassified` in memory, plus the raw `idp_divergence_service_principals.csv`, `idp_divergence_failures.csv`, and `divergence_workspaces.csv` when present.
# MAGIC - Identities written: none.
# MAGIC - Files written: none.
# MAGIC
# MAGIC **Gates that govern it:** none. It is read-only in every mode.
# MAGIC
# MAGIC **What you'll see:** a plan-summary table with one row per bucket, the error-category distribution, the domain
# MAGIC breakdown, the group candidate breakdown, the service-principal plan, and a workspace count. Compare these
# MAGIC counts against your own expectation of the account.
# MAGIC
# MAGIC **Audit rows:** none.
# MAGIC
# MAGIC **If it fails:** a missing service-principal, failures, or workspaces file is non-fatal — the cell notes it and
# MAGIC continues. If any bucket count surprises you, or `b_unclassified` is non-empty, stop and investigate before you
# MAGIC enable remediation.

# COMMAND ----------

# ---- Read-only analysis / presentation of the §4 worklists (no identity writes) ----
# Input dir the raw diagnostic files live in (raw mode reads RAW_DIR; premade reads CSV_DIR).
_input_dir = RAW_DIR if resolved_mode == "raw" else CSV_DIR

# 1) Per-bucket summary: count + mechanism + which gate governs it.
plan_summary = pd.DataFrame([
    {"bucket": "1_users_patch",   "count": len(b1),
     "mechanism": "PATCH externalId via Account SCIM (Users)",
     "gate": "writes when ENABLE_REMEDIATION and not DRY_RUN"},
    {"bucket": "2_support_ticket", "count": len(b2),
     "mechanism": "Databricks Support ticket (no SCIM write)",
     "gate": "always drafted (read-only)"},
    {"bucket": "3_groups",         "count": len(b3),
     "mechanism": "PATCH group externalId / rename in console",
     "gate": "writes when ENABLE_REMEDIATION, not DRY_RUN, LINK_GROUPS"},
    {"bucket": "4_cross_tenant",   "count": len(b4),
     "mechanism": "Escalate to InfoSec (out of AIM scope)",
     "gate": "always report-only"},
    {"bucket": "5_stale",          "count": len(b5),
     "mechanism": "Review/quarantine; deactivate only if confirmed",
     "gate": "writes when ENABLE_REMEDIATION, not DRY_RUN, CONFIRM_DEACTIVATION"},
])
print("Remediation plan summary:")
print(plan_summary.to_string(index=False))
print(f"\nTotal user rows across buckets 1/2/4/5: {len(b1) + len(b2) + len(b4) + len(b5)}; "
      f"group rows (bucket 3): {len(b3)}.")
print(f"Effective mode this run: {'DRY_RUN' if EFFECTIVE_DRY_RUN else 'LIVE'} "
      f"(ENABLE_REMEDIATION={ENABLE_REMEDIATION}, DRY_RUN={DRY_RUN}).")

# 2) Raw error-category distribution (only available when we derived from raw output).
if resolved_mode == "raw":
    try:
        _ru = load_csv("idp_divergence_users.csv", RAW_DIR)
        print("\nRaw user error-category distribution:")
        print(_ru["errorCategories"].value_counts().to_string())
    except Exception as e:
        print(f"\n(Could not read raw users for category distribution: {e})")

# 3) Domain split behind the b4 (cross-tenant) vs. b5 (stale) decision — this is a heuristic (M2).
print(f"\nDomain split for the EXTERNAL_ID_NOT_IN_IDP users (PRIMARY_DOMAINS={PRIMARY_DOMAINS}):")
for _label, _df in (("b4_cross_tenant", b4), ("b5_stale", b5)):
    if len(_df):
        _doms = _df["username"].map(_domain_of).value_counts()
        print(f"  {_label} ({len(_df)}): " + ", ".join(f"{d}={n}" for d, n in _doms.items()))
    else:
        print(f"  {_label} (0): none")

# 4) Group candidate-count breakdown (1 = linkable/renameable; !=1 = manual decision).
if len(b3):
    print("\nGroup collision candidate-count breakdown (bucket 3):")
    print(b3["candidateCount"].value_counts().to_string())

# 5) Federation-disabled workspaces (informational; acted on in §10).
try:
    _ws = pd.read_csv(f"{_input_dir}/divergence_workspaces.csv", dtype=str).fillna("")
    print(f"\nWorkspaces IDENTITY_FEDERATION_DISABLED: {len(_ws)} (detailed in §10).")
except Exception as e:
    print(f"\n(divergence_workspaces.csv not found in {_input_dir} — {e})")

# 6) Surface scan failures + unclassified rows (SPs get a full per-bucket summary below in §4b-SP).
for _fname, _what in (("idp_divergence_failures.csv", "scan failures"),):
    try:
        _df = pd.read_csv(f"{_input_dir}/{_fname}", dtype=str).fillna("")
        note = "clean (no rows)" if len(_df) == 0 else f"{len(_df)} rows — REVIEW"
        print(f"{_what}: {note} ({_fname}).")
    except Exception:
        print(f"{_what}: file not present ({_fname}).")
if len(b_unclassified):
    print(f"\n!! {len(b_unclassified)} raw user rows matched no bucket rule — NOT actioned. Sample:")
    print(b_unclassified.head(20).to_string(index=False))

# ---- Service-principal plan summary (rev.5) ----
sp_plan_summary = pd.DataFrame([
    {"bucket": "6_sps_patch",          "count": len(b6),
     "mechanism": "PATCH externalId via Account SCIM (ServicePrincipals)",
     "gate": "writes when ENABLE_REMEDIATION, not DRY_RUN, LINK_SERVICE_PRINCIPALS"},
    {"bucket": "7_sps_support_ticket", "count": len(b7),
     "mechanism": "Databricks Support ticket (no SCIM write)",
     "gate": "always drafted (read-only)"},
    {"bucket": "8_sps_review",         "count": len(b8),
     "mechanism": "Review only — no KB-prescribed SP fix (externalId clear is groups-only)",
     "gate": "always review-only"},
])
print("\nService-principal plan summary:")
print(sp_plan_summary.to_string(index=False))

if resolved_mode == "raw":
    try:
        _rsp = load_csv("idp_divergence_service_principals.csv", RAW_DIR)
        print("\nRaw service-principal error-category distribution:")
        print(_rsp["errorCategories"].value_counts().to_string())
    except Exception as e:
        print(f"\n(No SP divergences / could not read SP file: {e})")

if len(sp_unclassified):
    print(f"\n!! {len(sp_unclassified)} raw SP rows matched no bucket rule — NOT actioned. Sample:")
    print(sp_unclassified.head(20).to_string(index=False))

# Render the headline tables in the notebook UI when available.
try:
    display(plan_summary)
    display(sp_plan_summary)
except Exception:
    pass
print("\nREAD-ONLY analysis complete. Review the above, then set ENABLE_REMEDIATION=True to allow writes.")

# COMMAND ----------

# MAGIC %md
# MAGIC ## 5. Bucket 1 — link users whose name matches exactly one Entra identity
# MAGIC
# MAGIC **What it does:** for each user in `b1`, sets the Databricks `externalId` to the target from the worklist. This
# MAGIC links the Databricks user to its Entra identity.
# MAGIC
# MAGIC **Why it matters:** `NAME_MATCH_EXTERNAL_ID_MISMATCH` means the name matches exactly one Entra identity, but
# MAGIC the `externalId` is missing or wrong. Setting it to the matched `objectId` is the documented fix. Skip it and
# MAGIC AIM provisions that Entra identity as a second, duplicate principal on the next login.
# MAGIC
# MAGIC **Your action:** no per-identity work — the notebook applies the fix. Your job is to review and confirm:
# MAGIC 1. Read the Section 4b plan and spot-check that the name-to-`objectId` matches look right. The KB notes a name match is usually, but not always, the correct link.
# MAGIC 2. Enable remediation and run live (see Section 2).
# MAGIC 3. After the run, confirm no duplicates remain — re-run the scan, or check Section 12 once AIM is on.
# MAGIC
# MAGIC **Reads and writes:**
# MAGIC - Identities read: none beyond the collision precheck.
# MAGIC - Identities written: one `PATCH .../scim/v2/Users/{id}` per user, and only on a live run. Consumes `id`, `username`, `currentExternalId`, and `targetExternalId`.
# MAGIC - Files written: none.
# MAGIC
# MAGIC **Gates that govern it:** `ENABLE_REMEDIATION` must be on for any write, and `DRY_RUN=False` to go live. In the
# MAGIC default analysis-only mode the cell prints each intended change with a `[DRY]` prefix and logs it as `planned`.
# MAGIC Before each link, the target passes through the collision guard: if the index is down the user is skipped and
# MAGIC logged `PRECHECK_ERROR`, and if another principal already holds the target the user is skipped and logged
# MAGIC `COLLISION`. A row with no target is logged `SKIP_no_target`.
# MAGIC
# MAGIC **What you'll see:** one `[DRY]` line per linkable user in analysis-only or dry-run mode, or one `[OK ]` line per
# MAGIC user on a live run, then `Bucket 1 complete.`
# MAGIC
# MAGIC **Audit rows:** `PATCH_externalId` (`planned`, `success`, or `error`), `SKIP_no_target` (`skipped`), and
# MAGIC `COLLISION` or `PRECHECK_ERROR` from the guard.
# MAGIC
# MAGIC **If it fails:** a `COLLISION` means another principal already holds that `externalId` — resolve it as a
# MAGIC duplicate in Section 3c before you retry. A `PRECHECK_ERROR` means the collision index is down, so re-run
# MAGIC Section 3b. An `error` status carries the SCIM exception in the audit log; the row can be re-run once fixed.

# COMMAND ----------

for _, r in b1.iterrows():
    dbx_id, uname = r["id"], r["username"]
    # old_ext is normalized (M1) so the audit records a true blank for rollback; new_ext is the target.
    old_ext, new_ext = norm(r.get("currentExternalId", "")), r["targetExternalId"].strip()
    # Guard 1: nothing to set -> record and skip.
    if not new_ext:
        audit("1_users_patch", "SKIP_no_target", "User", dbx_id, uname, old_ext, "", "skipped", "no targetExternalId")
        continue
    # Guard 2 (H2): only proceed if no other principal already holds new_ext (fails closed if index is down).
    if not precheck_free("Users", new_ext, dbx_id, "1_users_patch", "User", uname):
        continue
    if EFFECTIVE_DRY_RUN:
        # Dry run (or remediation disabled): log the intended change only; no SCIM write.
        audit("1_users_patch", "PATCH_externalId", "User", dbx_id, uname, old_ext, new_ext, "planned")
        print(f"[DRY] User {uname}: externalId {old_ext or '(empty)'} -> {new_ext}")
    else:
        # Live run: execute the PATCH and record success/error, then throttle.
        try:
            scim_patch_external_id("Users", dbx_id, new_ext)
            audit("1_users_patch", "PATCH_externalId", "User", dbx_id, uname, old_ext, new_ext, "success")
            print(f"[OK ] User {uname}: -> {new_ext}")
        except Exception as e:
            audit("1_users_patch", "PATCH_externalId", "User", dbx_id, uname, old_ext, new_ext, "error", str(e))
            print(f"[ERR] User {uname}: {e}")
        throttle()

print("Bucket 1 complete.")

# COMMAND ----------

# MAGIC %md
# MAGIC ## 6. Bucket 3 — resolve group name collisions by linking or renaming
# MAGIC
# MAGIC **What it does:** for each group in `b3` that has exactly one candidate Entra group, it links the group by
# MAGIC setting its `externalId`, but only when you opt in. Otherwise it flags the group for a manual decision or a
# MAGIC console rename.
# MAGIC
# MAGIC **Why it matters:** a local group name that matches an Entra group blocks that Entra group from provisioning,
# MAGIC because the name is already taken. Linking the two by `objectId` resolves the collision. When there are zero or
# MAGIC several candidates, the match is ambiguous and a human must choose.
# MAGIC
# MAGIC **Your action:** partly scripted, partly yours.
# MAGIC 1. Decide whether to auto-link: set `LINK_GROUPS = True` to let the notebook link every group with exactly one candidate. Leave it `False` to rename each local group in the account console instead.
# MAGIC 2. For any group logged `MANUAL_DECISION` (zero or several candidates), you resolve it by hand — pick the correct Entra group and link it, or rename the local group — in the account console. The notebook never guesses these.
# MAGIC 3. Enable remediation and run live if you chose to auto-link.
# MAGIC
# MAGIC **Reads and writes:**
# MAGIC - Identities read: none beyond the collision precheck.
# MAGIC - Identities written: one `PATCH .../scim/v2/Groups/{id}` per linkable group, on a live run only. Consumes `id`, `groupName`, `currentExternalId`, `candidateCount`, and `candidateExternalIds` (semicolon-separated).
# MAGIC - Files written: none.
# MAGIC
# MAGIC **Gates that govern it:** `ENABLE_REMEDIATION` must be on for any write, and `LINK_GROUPS=True` to link at all.
# MAGIC The default leaves each group for a console rename and logs `LINK_DISABLED`. A group with more than one or no
# MAGIC candidate logs `MANUAL_DECISION` and is skipped. When linking is on, the target still passes through the
# MAGIC collision guard first.
# MAGIC
# MAGIC **What you'll see:** with the default flags, one `[SKIP] Group ...` line per group and a final `Bucket 3
# MAGIC complete.` With `LINK_GROUPS=True`, one `[DRY]` or `[OK ]` line per linked group.
# MAGIC
# MAGIC **Audit rows:** `PATCH_externalId` (`planned`, `success`, or `error`), `MANUAL_DECISION` or `LINK_DISABLED`
# MAGIC (`skipped`), and `COLLISION` or `PRECHECK_ERROR` from the guard.
# MAGIC
# MAGIC **If it fails:** a `MANUAL_DECISION` means the group has zero or several candidate Entra groups — decide in the
# MAGIC account console, then rename or link by hand. A `COLLISION` means the target `externalId` is already taken;
# MAGIC resolve that duplicate first. Clearing a group's `externalId` is supported, unlike for users.

# COMMAND ----------

for _, r in b3.iterrows():
    dbx_id, gname = r["id"], r["groupName"]
    # candidateExternalIds is a ';'-separated list; count how many IdP groups this local group could map to.
    cand_count = int(r.get("candidateCount", "0") or 0)
    candidates = [c for c in r.get("candidateExternalIds", "").split(";") if c.strip()]
    old_ext = norm(r.get("currentExternalId", ""))   # M1: normalize for a clean rollback record
    # Guard 1: 0 or many candidates is ambiguous -> a human must decide; never auto-link.
    if cand_count != 1:
        audit("3_groups", "MANUAL_DECISION", "Group", dbx_id, gname, old_ext, "", "skipped",
              f"{cand_count} candidate IdP groups — resolve manually")
        print(f"[MANUAL] Group '{gname}': {cand_count} candidates — decide manually (likely delete/rename).")
        continue
    target = candidates[0]   # exactly one candidate: the link target
    # Guard 2: linking is opt-in. Default (False) leaves the group for a console rename.
    if not LINK_GROUPS:
        audit("3_groups", "LINK_DISABLED", "Group", dbx_id, gname, old_ext, target, "skipped",
              "LINK_GROUPS=False — rename local group in console instead")
        print(f"[SKIP] Group '{gname}': candidate {target}. LINK_GROUPS=False → rename in console, or set True to link.")
        continue
    # Guard 3 (H2): same collision check as users, on the Groups index.
    if not precheck_free("Groups", target, dbx_id, "3_groups", "Group", gname):
        continue
    # Same dry-run vs. live split as Bucket 1, but PATCHing the Groups endpoint.
    if EFFECTIVE_DRY_RUN:
        audit("3_groups", "PATCH_externalId", "Group", dbx_id, gname, old_ext, target, "planned")
        print(f"[DRY] Group '{gname}': externalId -> {target}")
    else:
        try:
            scim_patch_external_id("Groups", dbx_id, target)
            audit("3_groups", "PATCH_externalId", "Group", dbx_id, gname, old_ext, target, "success")
            print(f"[OK ] Group '{gname}': -> {target}")
        except Exception as e:
            audit("3_groups", "PATCH_externalId", "Group", dbx_id, gname, old_ext, target, "error", str(e))
            print(f"[ERR] Group '{gname}': {e}")
        throttle()

print("Bucket 3 complete.")

# COMMAND ----------

# MAGIC %md
# MAGIC ## 6b. Diagnostic (read-only) — group membership triage
# MAGIC
# MAGIC **What it does:** turns the two membership-divergence categories that no bucket fixes —
# MAGIC `GROUP_HAS_LOCAL_MEMBERS_WITHOUT_EXTERNAL_ID` and `GROUP_HAS_LOCAL_MEMBERS_WITH_EXTERNAL_ID` — into a
# MAGIC review-ready sheet. For each flagged group it lists the member ids, classifies each as a user, service
# MAGIC principal, or nested group, and prints a suggested Entra-side action.
# MAGIC
# MAGIC **Why it matters:** you resolve these two categories in Entra, not through a Databricks write. External groups
# MAGIC are read-only in Databricks, and AIM drives their membership from Entra. No bucket patches membership, so this
# MAGIC sheet is your worklist for the Entra-side fix. The common case is a nested group: the fix is to add and link the
# MAGIC child group in Entra, not to flatten its members.
# MAGIC
# MAGIC **Reads and writes:**
# MAGIC - Identities read: the membership columns from `idp_divergence_groups.csv` (raw input only — the pre-made `remediation_3_*.csv` does not carry them), plus one read-only `GET .../scim/v2/Groups/{id}` per flagged group when `RESOLVE_MEMBER_NAMES=True`.
# MAGIC - Identities written: none.
# MAGIC - Files written: `CSV_DIR/group_membership_triage_<run>.csv` when `MEMBERSHIP_REPORT_CSV=True`.
# MAGIC
# MAGIC **Gates that govern it:** none for the core sheet. `RESOLVE_MEMBER_NAMES` adds the per-group name lookup, and
# MAGIC `MEMBERSHIP_REPORT_CSV` writes the report file.
# MAGIC
# MAGIC **What you'll see:** one block per flagged group listing each member with its type and suggested Entra action, a
# MAGIC nested-group count, and the report path.
# MAGIC
# MAGIC **Audit rows:** one `MEMBERSHIP_REVIEW / review` per flagged member, in bucket `6b_group_membership`. The
# MAGIC suggested Entra action is stored in the reason column, and these rows flow into the Section 11 log and summary.
# MAGIC
# MAGIC **If it fails:** the sheet needs the raw `idp_divergence_groups.csv`, so run in `"raw"` or `"auto"` input mode.
# MAGIC A per-group name lookup that fails is recorded inline and does not stop the cell. Every fix here is applied in
# MAGIC Entra by hand — the cell only tells you what to change.

# COMMAND ----------

# ---- Read-only diagnostic: group membership triage (no identity writes) ----
RESOLVE_MEMBER_NAMES  = True    # one read-only GET per flagged group to resolve member id -> type/display
MEMBERSHIP_REPORT_CSV = True    # also write the triage sheet to CSV_DIR

# The two membership-divergence categories, keyed by the raw column that carries the offending member IDs.
# The source column already encodes linked-ness, so no per-member externalId lookup is needed.
_MEMBERSHIP_CATS = {
    "localMembersNotInIdpInternalIds":    ("local_not_in_idp",    "GROUP_HAS_LOCAL_MEMBERS_WITHOUT_EXTERNAL_ID"),
    "externalMembersNotInIdpInternalIds": ("external_not_in_idp", "GROUP_HAS_LOCAL_MEMBERS_WITH_EXTERNAL_ID"),
}

# Self-contained read-only GET: reuse §3c's helper if that cell ran, else define an equivalent locally.
_get_scim = globals().get("_scim_get",
                          lambda k, i: a.api_client.do("GET", f"/api/2.1/accounts/{ACCOUNT_ID}/scim/v2/{k}/{i}"))


def _member_type_from_ref(ref, fallback=""):
    # Classify a group member by its SCIM `type` field (when present), else by its $ref — which may be
    # an absolute URL (".../scim/v2/Users/123") or a relative reference ("Users/123"), so match either.
    t = (fallback or "").strip().lower()
    if t in ("user", "users"):
        return "User"
    if t in ("group", "groups"):
        return "Group"
    if t in ("serviceprincipal", "serviceprincipals"):
        return "ServicePrincipal"
    ref = ref or ""
    if "ServicePrincipals/" in ref:
        return "ServicePrincipal"
    if "Users/" in ref:
        return "User"
    if "Groups/" in ref:
        return "Group"
    return "unknown"


def _resolve_members(gid):
    """Read-only: map member internal id -> (type, display) from the group's SCIM record.
    The flagged members are LOCAL members of the group, so they appear in members[]."""
    try:
        rec = _get_scim("Groups", gid)
    except Exception:
        return {}
    out = {}
    for m in (rec.get("members") or []):
        mtype = _member_type_from_ref(m.get("$ref", ""), m.get("type", ""))
        out[str(m.get("value", ""))] = (mtype, m.get("display", "") or "")
    return out


def _suggest_membership_action(member_type, side, group_linked):
    # A nested child group is fixed by adding & linking the child, never by flattening its members.
    if member_type == "Group":
        base = ("NESTED GROUP: add & link this child group in Databricks (set its externalId = child's Entra "
                "objectId). AIM resolves nesting transitively. Do NOT flatten its members into the parent.")
    elif side == "local_not_in_idp":   # member has no externalId — not IdP-linked
        base = ("Member is not IdP-linked: link it in Entra (externalId = objectId) and add it to the Entra "
                "group, OR remove it locally if it should not be a member.")
    else:                              # external_not_in_idp — member has an externalId
        base = ("Member is IdP-linked but absent from the Entra group: add it to the group in Entra, OR remove "
                "it locally. AIM drives membership from Entra.")
    if not group_linked:
        base += " (Prerequisite: link the PARENT group first — Bucket 3 — before membership can converge.)"
    return base


# Membership columns exist only in the RAW groups file (premade remediation_3_*.csv omits them).
_grp_dir = RAW_DIR if resolved_mode == "raw" else CSV_DIR
try:
    _rg = pd.read_csv(f"{_grp_dir}/idp_divergence_groups.csv", dtype=str).fillna("")
except Exception as e:
    _rg = None
    print(f"(idp_divergence_groups.csv not found in {_grp_dir} — membership triage skipped: {e})")

mt_rows = []
if _rg is not None:
    _member_cache = {}
    for _, g in _rg.iterrows():
        cats = {c for c in (g.get("errorCategories", "") or "").split(";") if c}
        # Only groups carrying at least one membership-divergence category are in scope here.
        if not ({"GROUP_HAS_LOCAL_MEMBERS_WITHOUT_EXTERNAL_ID",
                 "GROUP_HAS_LOCAL_MEMBERS_WITH_EXTERNAL_ID"} & cats):
            continue
        gid = g.get("id", "")
        gname = g.get("groupName", "")
        gext = norm(g.get("externalId", ""))
        group_linked = bool(gext)
        # One read-only GET per group (cached) resolves every flagged member's type/name at once.
        resolved = {}
        if RESOLVE_MEMBER_NAMES and gid:
            if gid not in _member_cache:
                _member_cache[gid] = _resolve_members(gid)
            resolved = _member_cache[gid]
        for _col, (_side, _cat) in _MEMBERSHIP_CATS.items():
            if _cat not in cats:
                continue
            for mid in [m for m in (g.get(_col, "") or "").split(";") if m.strip()]:
                mtype, mdisp = resolved.get(mid, ("", ""))
                mtype = mtype or "unknown"
                suggestion = _suggest_membership_action(mtype, _side, group_linked)
                mt_rows.append({
                    "groupInternalId": gid, "groupName": gname,
                    "groupExternalId": gext, "groupLinked": "Y" if group_linked else "N",
                    "memberInternalId": mid, "memberType": mtype, "memberDisplay": mdisp,
                    "divergenceSide": _side, "membershipCategory": _cat,
                    "isNestedGroup": "Y" if mtype == "Group" else "N",
                    "suggestedEntraAction": suggestion,
                })
                # Read-only audit row: surfaces in §11 as MEMBERSHIP_REVIEW / review; action stored in the reason.
                audit("6b_group_membership", "MEMBERSHIP_REVIEW", mtype, mid,
                      f"{gname} <- {mdisp or mid}", "", "", "review", f"{_cat}; {suggestion}")

mt_df = pd.DataFrame(mt_rows, columns=[
    "groupInternalId", "groupName", "groupExternalId", "groupLinked",
    "memberInternalId", "memberType", "memberDisplay",
    "divergenceSide", "membershipCategory", "isNestedGroup", "suggestedEntraAction"])

if len(mt_df):
    nested = int((mt_df["isNestedGroup"] == "Y").sum())
    print(f"{mt_df['groupInternalId'].nunique()} groups have membership divergence "
          f"({len(mt_df)} flagged member rows; {nested} are nested child groups).\n")
    for gid, grp in mt_df.groupby("groupInternalId", sort=False):
        gname = grp.iloc[0]["groupName"]
        linked = grp.iloc[0]["groupLinked"]
        print(f"Group '{gname}' (id={gid}, linked={linked}):")
        for _, m in grp.iterrows():
            tag = "[NESTED GROUP] " if m["isNestedGroup"] == "Y" else ""
            print(f"   - {tag}{m['memberType']:<16} {m['memberInternalId']}  {m['memberDisplay']}")
            print(f"       {m['divergenceSide']}: {m['suggestedEntraAction']}")
        print()
    if MEMBERSHIP_REPORT_CSV:
        mpath = f"{CSV_DIR}/group_membership_triage_{RUN_TS}.csv"
        try:
            mt_df.to_csv(mpath, index=False)
            print(f"Membership triage sheet written to: {mpath}")
        except Exception as e:
            print(f"(Could not write membership triage sheet: {e})")
    try:
        display(mt_df)
    except Exception:
        pass
else:
    print("No group membership divergences to triage.")
print("\nREAD-ONLY diagnostic — resolve these in Entra (or add & link nested child groups). Nothing modified.")

# COMMAND ----------

# MAGIC %md
# MAGIC ## 7. Bucket 2 — draft a Support ticket for users whose name drifted
# MAGIC
# MAGIC **What it does:** builds a ready-to-send Support-ticket draft listing the `b2` users, writes it to
# MAGIC `CSV_DIR/support_ticket_<run_id>.txt`, prints it, and logs one audit row per user.
# MAGIC
# MAGIC **Why it matters:** `EXTERNAL_ID_MATCH_NAME_MISMATCH` means the `externalId` maps to a real Entra user, but the
# MAGIC Databricks username differs, usually after an email or UPN change. The API cannot correct the username. Only
# MAGIC Databricks Support can. Until it is corrected, keep these users from logging in, because the new name reads as a
# MAGIC new person and creates a duplicate against the same `externalId`.
# MAGIC
# MAGIC **Your action — in this order:**
# MAGIC 1. **Reconcile duplicates first.** Run Sections 3c and 3d before filing anything. A UPN or mail-nickname change in Entra often shows up as two Databricks records for one person. If a flagged user is part of a duplicate cluster, resolve it there — link the keeper's `externalId`, migrate resources and memberships, remove the other — and drop that user from the ticket. A ticket cannot fix a duplicate.
# MAGIC 2. **File the ticket** (the draft below) only for genuine name-drift users that are not duplicates.
# MAGIC 3. **Hold those users out of Databricks** until Support confirms the correction, so no duplicate is created on login.
# MAGIC 4. Follow the process and verification in Section 7b.
# MAGIC
# MAGIC **Reads and writes:**
# MAGIC - Identities read: none.
# MAGIC - Identities written: none. This cell makes no SCIM call.
# MAGIC - Files written: the ticket draft `CSV_DIR/support_ticket_<run_id>.txt`. The draft lists each user's Entra `objectId` so Support can resolve the correct UPN quickly.
# MAGIC
# MAGIC **Gates that govern it:** none. It behaves the same in every mode and always writes the ticket file.
# MAGIC
# MAGIC **What you'll see:** a "Support-ticket draft written to" line, then the full ticket text.
# MAGIC
# MAGIC **Audit rows:** one `SUPPORT_TICKET / action_required` per user in `b2`.
# MAGIC
# MAGIC **If it fails:** a file-write error still prints the ticket text below, so you can copy it by hand. Open the
# MAGIC ticket with Databricks Support and hold these users out of Databricks until the name is fixed. The next cell
# MAGIC describes what the correction involves and what to tell the affected users.

# COMMAND ----------

# Build the ticket body line by line (header, then one row per user, then a Graph hint).
lines = [
    "Subject: Correct usernames for AIM migration (EXTERNAL_ID_MATCH_NAME_MISMATCH)",
    f"Account ID: {ACCOUNT_ID}",
    "",
    "Context: Migrating from account-level SCIM to Automatic Identity Management. The prep script flagged the",
    "users below as EXTERNAL_ID_MATCH_NAME_MISMATCH — externalId maps to a valid Entra user but the Databricks",
    "username differs (email/UPN change). Requesting username correction to prevent duplicate users on login.",
    "",
    f"{'databricks_id':<40}  {'current_username':<45}  entra_objectId (externalId)",
    f"{'-'*40}  {'-'*45}  {'-'*36}",
]
for _, r in b2.iterrows():
    lines.append(f"{r['id']:<40}  {r['username']:<45}  {r['externalId']}")
lines += ["",
    "Optional: the correct Entra UPN for each objectId can be resolved via Microsoft Graph",
    "(GET /users/{objectId}) if Graph credentials are available; omitted here."]
ticket_text = "\n".join(lines)

# Write the draft next to the CSVs (best-effort: a write failure still prints the ticket below).
ticket_path = f"{CSV_DIR}/support_ticket_{RUN_TS}.txt"
try:
    with open(ticket_path, "w") as fh:
        fh.write(ticket_text)
    print(f"Support-ticket draft written to: {ticket_path}\n")
except Exception as e:
    print(f"(Could not write ticket file: {e})\n")
print(ticket_text)
# Record every ticket user as action_required (no SCIM change is made here — Support fixes the username).
for _, r in b2.iterrows():
    audit("2_support_ticket", "SUPPORT_TICKET", "User", r["id"], r["username"], r["externalId"], "", "action_required")

# COMMAND ----------

# MAGIC %md
# MAGIC ## 7b. What a name or email correction involves (share with the affected users)
# MAGIC
# MAGIC First make sure these are genuine name drifts, not duplicates: reconcile the affected users in Sections 3c and
# MAGIC 3d before you file anything (see Section 7). A correction only applies to a user who has a single record with a
# MAGIC drifted name.
# MAGIC
# MAGIC A Bucket 2 correction is a coordinated change, not an instant fix. Support renames the users, and you make the
# MAGIC matching change in your identity provider. Plan a maintenance window and set expectations with the affected
# MAGIC users before you start.
# MAGIC
# MAGIC **The process:**
# MAGIC 1. Open the Support ticket with the affected users and their Entra `objectId`s (the draft from Section 7).
# MAGIC 2. Agree a maintenance window with Support. A large batch takes longer to schedule.
# MAGIC 3. During the change, pause identity sync: turn off just-in-time (JIT) provisioning and AIM in Databricks, and pause SCIM provisioning in your identity provider.
# MAGIC 4. Support renames the users. For a large batch, a dry run may run first.
# MAGIC 5. Make the matching rename in your identity provider.
# MAGIC 6. Verify, using the checklist below.
# MAGIC
# MAGIC **What to tell the affected users before the change:**
# MAGIC - An email or username change applies to every account and workspace in the same cloud that the user belongs to. A per-account change is not supported.
# MAGIC - The new email must not already exist anywhere in Databricks. Two records cannot be merged. If the new email already exists, either keep the new record and move resources to it before deleting the old one, or have the existing new email renamed aside first — in which case resources on the set-aside record are lost unless home-folder content is moved to shared folders beforehand.
# MAGIC - Casing matters. Addresses that differ only in case are treated as different users. On Azure, the old and new addresses must both be lowercase.
# MAGIC - Home folders are renamed to the new name, but path references inside jobs, repos, and notebooks are not rewritten. Home-folder updates can take up to a day.
# MAGIC - Existing personal compute clusters are orphaned. Create new ones under the new name after the change.
# MAGIC - Repos keep their old names and are not migrated automatically.
# MAGIC
# MAGIC **Verification (confirm each user):**
# MAGIC - The user can log in.
# MAGIC - The user can reach their home folder and every saved notebook, query, and dashboard.
# MAGIC - The user has the same permissions and access as before the change.

# COMMAND ----------

# MAGIC %md
# MAGIC ## 8. Bucket 4 — escalate foreign-tenant identities (out of AIM scope)
# MAGIC
# MAGIC **What it does:** prints the `b4` foreign-tenant users and logs each as a security escalation. It makes no
# MAGIC change.
# MAGIC
# MAGIC **Why it matters:** these principals live in another Entra tenant, for example a partner domain. AIM is
# MAGIC single-tenant, so it cannot manage them at all. The notebook never changes them — you decide their disposition.
# MAGIC
# MAGIC **Your action — depends on your migration:**
# MAGIC - **If you keep SCIM running (the default):** do nothing here. Keep provisioning these identities through SCIM. AIM cannot take them over, so leave them as they are.
# MAGIC - **If you are decommissioning SCIM:** these identities lose their only provisioning path. Coordinate with your Entra admin, confirm each one is genuinely no longer needed, then remove or deactivate it in Databricks by hand. Do this only after confirmation — a still-active partner identity must not be removed.
# MAGIC - Either way, treat the list as a heuristic (see Section 9): confirm the Entra home tenant before you act on a borderline row.
# MAGIC
# MAGIC **Reads and writes:**
# MAGIC - Identities read: none. The list comes from `b4` in memory.
# MAGIC - Identities written: none.
# MAGIC - Files written: none.
# MAGIC
# MAGIC **Gates that govern it:** none. It prints and logs only, in every mode.
# MAGIC
# MAGIC **What you'll see:** an "out of AIM scope" header and one line per user.
# MAGIC
# MAGIC **Audit rows:** one `ESCALATE_INFOSEC / action_required` per user in `b4`.
# MAGIC
# MAGIC **If it fails:** nothing here writes, so there is no failure mode to recover from. One caveat on the list
# MAGIC itself: membership is decided by a domain heuristic, not the authoritative Entra home tenant (see the note in
# MAGIC Section 9). Confirm the home tenant before you act on any borderline row.

# COMMAND ----------

# Report + audit only; these foreign-tenant identities are out of AIM scope and are never patched here.
print(f"{len(b4)} cross-tenant identities — OUT OF AIM SCOPE. Escalate for disposition:\n")
for _, r in b4.iterrows():
    print(f"  {r['username']:<45}  externalId={r['externalId']}")
    audit("4_cross_tenant", "ESCALATE_INFOSEC", "User", r["id"], r["username"], r["externalId"], "", "action_required",
          "cross-tenant; AIM unsupported")

# COMMAND ----------

# MAGIC %md
# MAGIC ## 9. Bucket 5 — review users whose link points at a deleted Entra object
# MAGIC
# MAGIC `EXTERNAL_ID_NOT_IN_IDP` with no name match: the `externalId` resolves to nothing in Entra.
# MAGIC
# MAGIC **This is not a migration blocker, and deactivation is not prescribed by the KB.** The KB actions for this
# MAGIC category are to update the `externalId` to a valid target — but none exists here — or to remove it, which is
# MAGIC supported for groups only. So there is no documented user fix. These records cannot log in, and AIM reconciles
# MAGIC `externalId` to the Entra `objectId` on its own daily flow. The safe default is to leave them.
# MAGIC
# MAGIC **If you deactivate for hygiene, do it carefully.** An active user whose email changed looks identical to a
# MAGIC deleted user here, so deactivating that user locks them out. Set `CONFIRM_DEACTIVATION=True` only after you
# MAGIC verify each id is genuinely deleted in Entra, work in small batches with `DEACTIVATION_BATCH_LIMIT`, and
# MAGIC reactivate from the audit log if you get it wrong.
# MAGIC
# MAGIC **Your action — verify, then decide:**
# MAGIC 1. **Verify each id in Entra.** Confirm the object is truly deleted, not renamed. A changed-email user is not stale — that is Bucket 2. If you are not sure, leave it; AIM will never provision a dead `externalId`.
# MAGIC 2. **For the ones you confirm are gone:** deactivate through the gated path (`ENABLE_REMEDIATION` plus `CONFIRM_DEACTIVATION`). This is reversible from the audit log.
# MAGIC 3. **Deleting is optional and manual.** Once you are certain a record is dead and no longer needed, you can delete it by hand in the account console. Deletion is not reversible, so keep deactivation as the default step.
# MAGIC
# MAGIC **What it does:** with the safe default (`CONFIRM_DEACTIVATION=False`) it lists the stale records and logs them
# MAGIC as review-only. Only when fully gated on does it deactivate owned-domain users in capped batches. Any username
# MAGIC whose domain is not in `PRIMARY_DOMAINS` is escalated, never deactivated.
# MAGIC
# MAGIC **Reads and writes:**
# MAGIC - Identities read: none. The list comes from `b5` in memory.
# MAGIC - Identities written: on the confirmed path only, one `PATCH .../scim/v2/Users/{id}` with `active=False` per user, up to the batch limit.
# MAGIC - Files written: none.
# MAGIC
# MAGIC **Gates that govern it:** `ENABLE_REMEDIATION` (master), `CONFIRM_DEACTIVATION` (this bucket's second gate),
# MAGIC `DRY_RUN`, `DEACTIVATION_BATCH_LIMIT`, and `PRIMARY_DOMAINS`. All must align before any user is deactivated.
# MAGIC
# MAGIC **What you'll see:** with the default, a "review only" line, a sample of the stale records, then `Bucket 5
# MAGIC complete.` On the confirmed dry-run path, a `[DRY] Deactivate ...` line per owned-domain user.
# MAGIC
# MAGIC **Audit rows:** `REVIEW_ONLY / review` on the default path. On the confirmed path, `DEACTIVATE` (`planned`,
# MAGIC `success`, or `error`), `ESCALATE_INFOSEC / action_required` for a non-owned domain, and `BATCH_LIMIT /
# MAGIC deferred` for rows past the cap.
# MAGIC
# MAGIC **If it fails:** the most costly failure is a wrong deactivation, not an exception. If you deactivate an active
# MAGIC user by mistake, filter the audit log to `action == "DEACTIVATE"` and `status == "success"` and reactivate, as
# MAGIC shown in Section 13. When in doubt, leave the record and let AIM reconcile it.

# COMMAND ----------

def domain_of(u):
    # Email domain, lowercased; "" if there is no '@' (used by the M2 primary-domain guard below).
    return u.split("@")[-1].lower() if "@" in u else ""

# Default, safe path: no deactivation at all. Just list a sample and log everything as review-only.
if not CONFIRM_DEACTIVATION:
    print(f"CONFIRM_DEACTIVATION=False → review only. {len(b5)} stale records, no changes.\n")
    for _, r in b5.head(20).iterrows():
        print(f"  {r['username']:<45}  externalId={r['externalId']}")
    if len(b5) > 20:
        print(f"  ... and {len(b5)-20} more.")
    for _, r in b5.iterrows():
        audit("5_stale", "REVIEW_ONLY", "User", r["id"], r["username"], r["externalId"], "", "review",
              "verify deleted in Entra before any deactivation")
else:
    # Confirmed path (only reached with CONFIRM_DEACTIVATION=True). Still bounded and domain-guarded.
    done = 0
    for _, r in b5.iterrows():
        dbx_id, uname = r["id"], r["username"]
        # M2 guard: never deactivate a non-primary-domain account here — escalate instead.
        if domain_of(uname) not in [d.lower() for d in PRIMARY_DOMAINS]:
            audit("5_stale", "ESCALATE_INFOSEC", "User", dbx_id, uname, r["externalId"], "", "action_required",
                  "non-primary domain in bucket 5 — do not deactivate; escalate")
            print(f"[ESCALATE] {uname}: non-primary domain — not deactivating.")
            continue
        # Blast-radius cap: stop actually acting once the per-run limit is hit (remaining rows are deferred).
        if done >= DEACTIVATION_BATCH_LIMIT:
            audit("5_stale", "BATCH_LIMIT", "User", dbx_id, uname, r["externalId"], "", "deferred",
                  f"exceeds DEACTIVATION_BATCH_LIMIT={DEACTIVATION_BATCH_LIMIT}")
            continue
        # Dry-run vs. live, exactly as the other buckets; the write is scim_set_active(..., False).
        if EFFECTIVE_DRY_RUN:
            audit("5_stale", "DEACTIVATE", "User", dbx_id, uname, r["externalId"], "", "planned")
            print(f"[DRY] Deactivate {uname}")
        else:
            try:
                scim_set_active(dbx_id, False)
                audit("5_stale", "DEACTIVATE", "User", dbx_id, uname, r["externalId"], "", "success")
                print(f"[OK ] Deactivated {uname}")
            except Exception as e:
                audit("5_stale", "DEACTIVATE", "User", dbx_id, uname, r["externalId"], "", "error", str(e))
                print(f"[ERR] {uname}: {e}")
            throttle()
        done += 1
    print(f"Bucket 5: processed {done} (limit {DEACTIVATION_BATCH_LIMIT}).")

print("Bucket 5 complete.")

# COMMAND ----------

# MAGIC %md
# MAGIC ## 9a. Bucket 6 — link service principals that match one Entra application
# MAGIC
# MAGIC **What it does:** for each service principal in `b6`, sets its Databricks `externalId` to the target — the
# MAGIC Entra service principal matched by application ID. This is the service-principal form of Bucket 1.
# MAGIC
# MAGIC **Why it matters:** `NAME_MATCH_EXTERNAL_ID_MISMATCH` on a service principal means exactly one Entra
# MAGIC application-ID match exists. The prescribed fix is to set the `externalId` to that match. Skip it and AIM
# MAGIC creates a duplicate service principal on the next use.
# MAGIC
# MAGIC **Your action:** the same as Bucket 1, with one extra switch. No per-identity work — the notebook applies the fix.
# MAGIC 1. Set `LINK_SERVICE_PRINCIPALS = True` to allow the links. The default is off, so nothing is linked until you opt in.
# MAGIC 2. Review the Section 4b plan and confirm the application-ID matches look right.
# MAGIC 3. Enable remediation and run live, then confirm no duplicate service principals remain.
# MAGIC
# MAGIC **Reads and writes:**
# MAGIC - Identities read: none beyond the collision precheck.
# MAGIC - Identities written: one `PATCH .../scim/v2/ServicePrincipals/{id}` per service principal, on a live run only. Consumes `id`, `applicationId`, `currentExternalId`, and `targetExternalId`.
# MAGIC - Files written: none.
# MAGIC
# MAGIC **Gates that govern it:** `ENABLE_REMEDIATION` must be on for any write, and `LINK_SERVICE_PRINCIPALS=True` to
# MAGIC link at all. The default skips each service principal and logs `LINK_DISABLED`. A row with no target logs
# MAGIC `SKIP_no_target`. When linking is on, the target passes through the collision guard on the ServicePrincipals
# MAGIC index first.
# MAGIC
# MAGIC **What you'll see:** with the default flags, one `[SKIP] SP ...` line per service principal and a final `Bucket 6
# MAGIC (service principals) complete.` With `LINK_SERVICE_PRINCIPALS=True`, one `[DRY]` or `[OK ]` line per link.
# MAGIC
# MAGIC **Audit rows:** `PATCH_externalId` (`planned`, `success`, or `error`), `SKIP_no_target`, `LINK_DISABLED`, and
# MAGIC `COLLISION` or `PRECHECK_ERROR` from the guard.
# MAGIC
# MAGIC **If it fails:** a `COLLISION` means another principal already holds that `externalId` — resolve the duplicate
# MAGIC first. A `PRECHECK_ERROR` means the ServicePrincipals index is down, so re-run Section 3b. Clearing a service
# MAGIC principal's `externalId` is not supported, only setting it.

# COMMAND ----------

for _, r in b6.iterrows():
    dbx_id, appid = r["id"], r["applicationId"]
    # old_ext is normalized (M1) so the audit records a true blank for rollback; new_ext is the target.
    old_ext, new_ext = norm(r.get("currentExternalId", "")), r["targetExternalId"].strip()
    # Guard 1: nothing to set -> record and skip.
    if not new_ext:
        audit("6_sps_patch", "SKIP_no_target", "ServicePrincipal", dbx_id, appid, old_ext, "", "skipped", "no targetExternalId")
        continue
    # Guard 2: SP linking is opt-in, same conservative stance as LINK_GROUPS.
    if not LINK_SERVICE_PRINCIPALS:
        audit("6_sps_patch", "LINK_DISABLED", "ServicePrincipal", dbx_id, appid, old_ext, new_ext, "skipped",
              "LINK_SERVICE_PRINCIPALS=False — set True to PATCH SP externalId")
        print(f"[SKIP] SP {appid}: candidate {new_ext}. LINK_SERVICE_PRINCIPALS=False → set True to link.")
        continue
    # Guard 3 (H2): only proceed if no other principal already holds new_ext (fails closed if index is down).
    if not precheck_free("ServicePrincipals", new_ext, dbx_id, "6_sps_patch", "ServicePrincipal", appid):
        continue
    if EFFECTIVE_DRY_RUN:
        # Dry run (or remediation disabled): log the intended change only; no SCIM write.
        audit("6_sps_patch", "PATCH_externalId", "ServicePrincipal", dbx_id, appid, old_ext, new_ext, "planned")
        print(f"[DRY] SP {appid}: externalId {old_ext or '(empty)'} -> {new_ext}")
    else:
        # Live run: execute the PATCH and record success/error, then throttle.
        try:
            scim_patch_external_id("ServicePrincipals", dbx_id, new_ext)
            audit("6_sps_patch", "PATCH_externalId", "ServicePrincipal", dbx_id, appid, old_ext, new_ext, "success")
            print(f"[OK ] SP {appid}: -> {new_ext}")
        except Exception as e:
            audit("6_sps_patch", "PATCH_externalId", "ServicePrincipal", dbx_id, appid, old_ext, new_ext, "error", str(e))
            print(f"[ERR] SP {appid}: {e}")
        throttle()

print("Bucket 6 (service principals) complete.")

# COMMAND ----------

# MAGIC %md
# MAGIC ## 9b. Bucket 7 — draft a Support ticket for service principals whose name drifted
# MAGIC
# MAGIC **What it does:** builds a ready-to-send Support-ticket draft listing the `b7` service principals, writes it to
# MAGIC `CSV_DIR/support_ticket_sps_<run_id>.txt`, prints it, and logs one audit row per service principal. This is the
# MAGIC service-principal form of Bucket 2.
# MAGIC
# MAGIC **Why it matters:** `EXTERNAL_ID_MATCH_NAME_MISMATCH` means the `externalId` maps to a real Entra service
# MAGIC principal, but the Databricks name differs. For both users and service principals, only Databricks Support can
# MAGIC correct the name.
# MAGIC
# MAGIC **Your action — in this order:** same as Bucket 2.
# MAGIC 1. **Reconcile duplicates first** in Sections 3c and 3d. If a flagged service principal is part of a duplicate cluster, resolve it there and drop it from the ticket.
# MAGIC 2. **File the ticket** (the draft below) only for genuine name-drift service principals.
# MAGIC 3. Keep those service principals from authenticating until Support confirms the correction.
# MAGIC
# MAGIC **Reads and writes:**
# MAGIC - Identities read: none.
# MAGIC - Identities written: none. This cell makes no SCIM call.
# MAGIC - Files written: the ticket draft `CSV_DIR/support_ticket_sps_<run_id>.txt`. It lists each Entra `objectId` and `applicationId` so Support can resolve the correct service principal.
# MAGIC
# MAGIC **Gates that govern it:** none. It always writes the ticket file.
# MAGIC
# MAGIC **What you'll see:** a "SP support-ticket draft written to" line, then the ticket text.
# MAGIC
# MAGIC **Audit rows:** one `SUPPORT_TICKET / action_required` per service principal in `b7`.
# MAGIC
# MAGIC **If it fails:** a file-write error still prints the ticket text below, so you can copy it by hand. Send it
# MAGIC through the same Support process as the Bucket 2 user ticket.

# COMMAND ----------

# Build the SP ticket body line by line (header, then one row per SP).
sp_lines = [
    "Subject: Correct service-principal names for AIM migration (EXTERNAL_ID_MATCH_NAME_MISMATCH)",
    f"Account ID: {ACCOUNT_ID}",
    "",
    "Context: Migrating to Automatic Identity Management. The prep script flagged the service principals",
    "below as EXTERNAL_ID_MATCH_NAME_MISMATCH — externalId maps to a valid Entra service principal but the",
    "Databricks name differs. Per the AIM KB, the name must be corrected by Databricks Support.",
    "",
    f"{'databricks_id':<40}  {'applicationId':<40}  entra_objectId (externalId)",
    f"{'-'*40}  {'-'*40}  {'-'*36}",
]
for _, r in b7.iterrows():
    sp_lines.append(f"{r['id']:<40}  {r['applicationId']:<40}  {r['externalId']}")
sp_ticket_text = "\n".join(sp_lines)

# Write the draft next to the CSVs (best-effort: a write failure still prints the ticket below).
sp_ticket_path = f"{CSV_DIR}/support_ticket_sps_{RUN_TS}.txt"
try:
    with open(sp_ticket_path, "w") as fh:
        fh.write(sp_ticket_text)
    print(f"SP support-ticket draft written to: {sp_ticket_path}\n")
except Exception as e:
    print(f"(Could not write SP ticket file: {e})\n")
print(sp_ticket_text)
# Record every ticket SP as action_required (no SCIM change is made here — Support fixes the name).
for _, r in b7.iterrows():
    audit("7_sps_support_ticket", "SUPPORT_TICKET", "ServicePrincipal", r["id"], r["applicationId"], r["externalId"], "", "action_required")

# COMMAND ----------

# MAGIC %md
# MAGIC ## 9c. Bucket 8 — review service principals whose link points at nothing in Entra
# MAGIC
# MAGIC **What it does:** lists the `b8` service principals whose `externalId` resolves to nothing in Entra and logs
# MAGIC each as review-only. It makes no change. This is the service-principal counterpart to Bucket 5.
# MAGIC
# MAGIC **Why it matters:** the KB prescribes no service-principal fix for this category. Clearing `externalId` is
# MAGIC groups-only, and service principals have no email domain, so there is no owned-versus-foreign split. Review each
# MAGIC one in Entra before any manual action.
# MAGIC
# MAGIC **Your action — verify, then decide:** the counterpart to Bucket 5, but there is no scripted deactivation.
# MAGIC 1. **Verify each in Entra.** Confirm the service principal is truly gone, not renamed. If you are not sure, leave it — AIM will not provision a dead `externalId`.
# MAGIC 2. **For the ones you confirm are gone:** deactivate or remove the service principal in the account console by hand. There is no gated path for this bucket.
# MAGIC 3. If in doubt, leave it as review-only and let AIM reconcile.
# MAGIC
# MAGIC **Reads and writes:**
# MAGIC - Identities read: none. The list comes from `b8` in memory.
# MAGIC - Identities written: none.
# MAGIC - Files written: none.
# MAGIC
# MAGIC **Gates that govern it:** none. It is always review-only.
# MAGIC
# MAGIC **What you'll see:** a review-only header, a sample of the records, then `Bucket 8 (service principals)
# MAGIC complete.`
# MAGIC
# MAGIC **If it fails:** nothing here writes, so there is no failure to recover from. Resolve each record in Entra, or
# MAGIC leave it and let AIM reconcile.

# COMMAND ----------

# EXTERNAL_ID_NOT_IN_IDP for SPs: no KB-prescribed SP fix (clearing externalId is groups-only, and SPs have
# no email domain to route on). Review-only — verify in Entra before any manual action.
print(f"{len(b8)} service principals with EXTERNAL_ID_NOT_IN_IDP — REVIEW ONLY (no KB-prescribed SP fix).\n")
for _, r in b8.head(20).iterrows():
    print(f"  {r['applicationId']:<40}  externalId={r['externalId']}")
if len(b8) > 20:
    print(f"  ... and {len(b8)-20} more.")
for _, r in b8.iterrows():
    audit("8_sps_review", "REVIEW_ONLY", "ServicePrincipal", r["id"], r["applicationId"], r["externalId"], "", "review",
          "verify in Entra; externalId clear unsupported for SPs")
print("Bucket 8 (service principals) complete.")

# COMMAND ----------

# MAGIC %md
# MAGIC ## 10. Workspaces with identity federation disabled
# MAGIC
# MAGIC **What it does:** reads `divergence_workspaces.csv` and prints the workspaces that have identity federation
# MAGIC disabled.
# MAGIC
# MAGIC **Why it matters:** AIM works only in identity-federated workspaces. Enable federation on each of these from the
# MAGIC account console, or AIM will not apply there.
# MAGIC
# MAGIC **Your action:** for each workspace listed, enable identity federation in the account console. The notebook only
# MAGIC reports them — it cannot change a workspace setting.
# MAGIC
# MAGIC **Reads and writes:**
# MAGIC - Identities read: none.
# MAGIC - Identities written: none.
# MAGIC - Files written: none. This is a local CSV read and print.
# MAGIC
# MAGIC **Gates that govern it:** none.
# MAGIC
# MAGIC **What you'll see:** a count of federation-disabled workspaces, then the table.
# MAGIC
# MAGIC **Audit rows:** none.
# MAGIC
# MAGIC **If it fails:** a missing `divergence_workspaces.csv` is non-fatal — the cell notes it and continues. Confirm
# MAGIC the file is in your input folder if you expected workspaces here.

# COMMAND ----------

# Informational only: list workspaces needing federation enabled. Missing file is non-fatal.
# Read from the resolved input dir (RAW_DIR in raw mode, else CSV_DIR).
_ws_dir = RAW_DIR if resolved_mode == "raw" else CSV_DIR
try:
    ws = pd.read_csv(f"{_ws_dir}/divergence_workspaces.csv", dtype=str).fillna("")
    print(f"{len(ws)} workspaces are IDENTITY_FEDERATION_DISABLED:\n")
    print(ws.to_string(index=False))
except Exception as e:
    print(f"(divergence_workspaces.csv not found in {_ws_dir} — {e})")

# COMMAND ----------

# MAGIC %md
# MAGIC ## 11. Write the audit log (the rollback record)
# MAGIC
# MAGIC **What it does:** turns the in-memory `AUDIT` list, which every bucket appends to, into a table, writes it to
# MAGIC `CSV_DIR/audit_log_<run_id>.csv`, and prints a grouped summary.
# MAGIC
# MAGIC **Why it matters:** this CSV is the single record of what the run did or planned, and it is the input to the
# MAGIC rollback in Section 13. The notebook writes it in both dry-run and live mode, so you always have a record.
# MAGIC
# MAGIC **If it fails:** the cell first tries a plain file write and falls back to the Databricks filesystem API, so a
# MAGIC volume path and a workspace path both work. If neither can write, check that `CSV_DIR` exists and you can write
# MAGIC to it. Never run live without a working audit log — it is your only way back.
# MAGIC
# MAGIC **Audit column dictionary:**
# MAGIC - `timestamp_utc` — when the row was recorded (UTC ISO-8601).
# MAGIC - `run_id` — the `RUN_TS` for this execution; ties every row and the output filename together.
# MAGIC - `mode` — `DRY_RUN` or `LIVE`.
# MAGIC - `bucket` — which section produced the row (e.g. `1_users_patch`, `3_groups`, `5_stale`, `6_sps_patch`, `7_sps_support_ticket`, `8_sps_review`, `6b_group_membership`).
# MAGIC - `action` — see action values below.
# MAGIC - `principal_type` — `User`, `Group`, or `ServicePrincipal`.
# MAGIC - `dbx_id` — the Databricks identity ID acted on (the SCIM resource id).
# MAGIC - `identifier` — the human-readable username / group name.
# MAGIC - `old_externalId` — the value **before** the change (normalized; blank means "was empty"). This is what rollback restores.
# MAGIC - `new_externalId` — the value the PATCH set (or would set).
# MAGIC - `status` — see status values below.
# MAGIC - `error` — the exception text when `status = error`, else the reason/skip note.
# MAGIC
# MAGIC **`action` values:**
# MAGIC - `PATCH_externalId` — set an identity's `externalId` (Buckets 1, 3, and 6).
# MAGIC - `SKIP_no_target` — a Bucket 1 or 6 row had no `targetExternalId`, so there was nothing to set.
# MAGIC - `COLLISION` — the target `externalId` is already held by a different principal, so the link was skipped.
# MAGIC - `PRECHECK_ERROR` — the collision index was unavailable, so the link was skipped rather than risked.
# MAGIC - `MANUAL_DECISION` — a Bucket 3 group had zero or several candidate Entra groups, so a human must resolve it.
# MAGIC - `LINK_DISABLED` — a Bucket 3 group (`LINK_GROUPS=False`) or Bucket 6 service principal (`LINK_SERVICE_PRINCIPALS=False`) had a candidate, but linking is off.
# MAGIC - `SUPPORT_TICKET` — a Bucket 2 user or Bucket 7 service principal needs a Databricks Support name correction.
# MAGIC - `ESCALATE_INFOSEC` — a foreign-tenant user (Bucket 4) or a non-owned-domain Bucket 5 user, out of AIM scope.
# MAGIC - `REVIEW_ONLY` — a Bucket 5 user or Bucket 8 service principal left as-is for human review, the default safe path.
# MAGIC - `DEACTIVATE` — a Bucket 5 user deactivation, only when fully gated on.
# MAGIC - `BATCH_LIMIT` — a Bucket 5 user deferred because `DEACTIVATION_BATCH_LIMIT` was reached.
# MAGIC - `MEMBERSHIP_REVIEW` — a read-only Section 6b row: a group member diverges from the Entra group (a nested child group, a local-only member, or a linked member missing from Entra). The suggested Entra action is in the reason column. Resolve it in Entra — no bucket patches membership.
# MAGIC
# MAGIC **`status` values:**
# MAGIC - `planned` — dry-run; the action would run on a live run.
# MAGIC - `success` — live; the SCIM call succeeded.
# MAGIC - `error` — live; the SCIM call raised, and the exception is in the `error` column.
# MAGIC - `skipped` — deliberately not done: a collision, a precheck error, no target, linking off, or an ambiguous group.
# MAGIC - `review` — a Bucket 5 or Bucket 8 review-only record, or a Section 6b membership-review row. Verify in Entra before any action.
# MAGIC - `action_required` — needs an action outside this notebook: a Support ticket or a security escalation.
# MAGIC - `deferred` — valid to act on, but held back this run by the batch limit.
# MAGIC
# MAGIC **Rollback:** filter to `status == "success"` and `action == "PATCH_externalId"`, then PATCH each `dbx_id` back to its `old_externalId` (a blank clears it — supported for groups only). See Section 13.

# COMMAND ----------

# Serialize the accumulated AUDIT rows to CSV — this is the rollback record (see §13).
audit_df = pd.DataFrame(AUDIT)
audit_path = f"{CSV_DIR}/audit_log_{RUN_TS}.csv"
csv_str = audit_df.to_csv(index=False)
try:
    with open(audit_path, "w") as fh:      # works for UC Volumes and Workspace files
        fh.write(csv_str)
    print(f"Audit log written to: {audit_path}")
except Exception:
    # M3: fall back to the dbutils FS API if a plain open() isn't supported for this path.
    dbutils.fs.put(audit_path, csv_str, overwrite=True)
    print(f"Audit log written to: {audit_path}")

# Print a grouped tally so the operator can sanity-check counts per bucket/action/status.
if len(audit_df):
    summary = audit_df.groupby(["bucket", "action", "status"]).size().reset_index(name="count")
    print("\nSummary:")
    print(summary.to_string(index=False))
    try:
        display(audit_df)
    except Exception:
        pass
else:
    print("(no operations recorded)")

# COMMAND ----------

# MAGIC %md
# MAGIC ## 12. Confirm AIM is provisioning identities (run after you enable AIM)
# MAGIC
# MAGIC **What it does:** counts `autoUserCreation` events in the system audit table over the last two days, grouped by
# MAGIC action.
# MAGIC
# MAGIC **Why it matters:** once AIM is enabled, it auto-provisions users and groups on first access. A non-zero count
# MAGIC confirms AIM is actively creating identities, which tells you the migration is working.
# MAGIC
# MAGIC **Reads and writes:**
# MAGIC - Identities read: none. This is a `%sql` query against `system.access.audit`, unrelated to the remediation above.
# MAGIC - Identities written: none.
# MAGIC - Files written: none.
# MAGIC
# MAGIC **Gates that govern it:** none. It ignores `DRY_RUN` because it is a read-only query.
# MAGIC
# MAGIC **When to run it:** only after you enable AIM. It returns nothing beforehand. You also need the `system.access`
# MAGIC schema enabled and query access to it.
# MAGIC
# MAGIC **What you'll see:** after enablement, one or more rows with an `action_name` and a non-zero count.
# MAGIC
# MAGIC **If it fails:** an empty result before enablement is expected. After enablement, an empty result or a
# MAGIC permission error usually means the `system.access` schema is not enabled or you lack access — grant it and
# MAGIC re-run.

# COMMAND ----------

# MAGIC %sql
# MAGIC SELECT action_name, count(*) AS n
# MAGIC FROM system.access.audit
# MAGIC WHERE request_params.endpoint = 'autoUserCreation'
# MAGIC   AND event_time > current_timestamp() - INTERVAL 2 DAYS
# MAGIC GROUP BY action_name
# MAGIC ORDER BY n DESC;

# COMMAND ----------

# MAGIC %md
# MAGIC ## 13. Rollback
# MAGIC
# MAGIC **What this section is for:** undoing a live run. It is manual reference guidance, not an executable cell. Use
# MAGIC it when a live batch needs reversing.
# MAGIC
# MAGIC **When to use it:** only after a `DRY_RUN=False` run whose audit log shows `status == "success"` rows you want
# MAGIC to reverse.
# MAGIC
# MAGIC **How rollback works:** the audit log records the previous `externalId` for every link, normalized so a blank
# MAGIC means "was empty". To reverse a link in Bucket 1, 3, or 6, set the `dbx_id` back to its `old_externalId`. A blank
# MAGIC clears it, which is supported for groups only.
# MAGIC
# MAGIC **Step by step:**
# MAGIC 1. Confirm you ran live (`DRY_RUN=False`) and something needs reverting.
# MAGIC 2. Find the audit CSV for that run: `CSV_DIR/audit_log_<RUN_ID>.csv`. Sections 3 and 11 print the `<RUN_ID>`.
# MAGIC 3. Copy the code block below into a new cell. It is shown here as text, not run automatically.
# MAGIC 4. Set `ROLLBACK_AUDIT_CSV` to that file, keep `ROLLBACK_DRY_RUN=True`, and run it to preview the reverts.
# MAGIC 5. Review the `[DRY]` output. Only when it looks right, set `ROLLBACK_DRY_RUN=False` and `CONFIRM_ROLLBACK=True`, then re-run.
# MAGIC 6. A blank `old_externalId` means "was empty". Clearing is supported for groups only, so user rows with a blank prior value are skipped and you handle them by hand.
# MAGIC
# MAGIC **Rollback snippet** (reuses the helpers from Section 3 — `norm`, `scim_patch_external_id`, `scim_set_active`, `throttle`):
# MAGIC
# MAGIC ```python
# MAGIC # --- ROLLBACK (manual): reverse bucket-1/3/6 externalId PATCHes from a prior run ---
# MAGIC ROLLBACK_AUDIT_CSV = f"{CSV_DIR}/audit_log_<RUN_ID>.csv"   # EDIT ME: the run to undo
# MAGIC
# MAGIC ROLLBACK_DRY_RUN = True     # True = preview only
# MAGIC CONFIRM_ROLLBACK = False    # must ALSO be True to actually write
# MAGIC
# MAGIC execute = (not ROLLBACK_DRY_RUN) and CONFIRM_ROLLBACK   # both gates required
# MAGIC
# MAGIC rb = pd.read_csv(ROLLBACK_AUDIT_CSV, dtype=str).fillna("")
# MAGIC rb = rb[(rb["action"] == "PATCH_externalId") & (rb["status"] == "success")]
# MAGIC print(f"{len(rb)} successful PATCH rows eligible for rollback. execute={execute}")
# MAGIC
# MAGIC _KIND = {"User": "Users", "Group": "Groups", "ServicePrincipal": "ServicePrincipals"}
# MAGIC for _, r in rb.iterrows():
# MAGIC     kind      = _KIND.get(r["principal_type"])
# MAGIC     revert_to = norm(r["old_externalId"])        # blank = "was empty"
# MAGIC     # Blank externalId can only be cleared for GROUPS (per KB) — skip blank-on-user and blank-on-SP.
# MAGIC     if revert_to == "" and kind in ("Users", "ServicePrincipals"):
# MAGIC         print(f"[SKIP] {r['identifier']}: prior externalId empty; only groups can be cleared — revert manually.")
# MAGIC         continue
# MAGIC     if not execute:
# MAGIC         print(f"[DRY] {kind[:-1]} {r['identifier']}: {r['new_externalId']} -> {revert_to or '(empty)'}")
# MAGIC         continue
# MAGIC     try:
# MAGIC         scim_patch_external_id(kind, r["dbx_id"], revert_to)
# MAGIC         print(f"[OK ] {r['identifier']}: reverted to {revert_to or '(empty)'}")
# MAGIC     except Exception as e:
# MAGIC         print(f"[ERR] {r['identifier']}: {e}")
# MAGIC     throttle()
# MAGIC ```
# MAGIC
# MAGIC **Bucket 5 (deactivations) reverse differently** — reactivate instead of re-PATCHing externalId:
# MAGIC
# MAGIC ```python
# MAGIC # To reactivate users deactivated in Bucket 5, filter that run's audit log to
# MAGIC # action == "DEACTIVATE" and status == "success", then (behind the same two gates):
# MAGIC #     scim_set_active(r["dbx_id"], True)
# MAGIC ```
# MAGIC
# MAGIC ### Notes
# MAGIC - This notebook uses raw `api_client.do(...)` calls to mirror the KB's exact PATCH payload. The typed SDK
# MAGIC   methods (`a.users.patch` and `a.groups.patch` with `Patch`, `PatchOp`, `PatchSchema`) are an alternative that
# MAGIC   returns typed errors.
# MAGIC - `active` is sent as a boolean, per the SCIM RFC. Test on one or two users before any batch, and switch to the
# MAGIC   string `"false"` if the endpoint rejects the boolean.
# MAGIC
# MAGIC ### References
# MAGIC - Databricks KB: `https://kb.databricks.com/automatic-identity-management-aim-enablement-prep-script`
# MAGIC - Microsoft Learn: `https://learn.microsoft.com/en-us/azure/databricks/admin/users-groups/automatic-identity-management/migrate-to-aim`

# COMMAND ----------

# MAGIC %md
# MAGIC ## Appendix — version history
# MAGIC
# MAGIC The notebook is safe to run top to bottom regardless of this history. It is kept for context only.
# MAGIC
# MAGIC - **Service principals remediated, not just reported.** The scan covers users, groups, and service principals. Service principals now flow through the same collision-checked, gated, audited engine as users and groups, in Buckets 6, 7, and 8. The collision index, the analysis, the audit log, and the rollback all cover service principals.
# MAGIC - **Dual input, auto-detected.** The notebook accepts either the pre-segmented `remediation_*.csv` worklists or the raw prep-script output. When fed raw output, it sorts the divergences into the same buckets in memory, so no separate segmentation step is needed.
# MAGIC - **Analysis-first, with a master gate.** `ENABLE_REMEDIATION` defaults to `False`. Analysis, the read-only diagnostics, the ticket drafts, the escalation report, and the audit log all run in that state, and no identity write is possible. The buckets read `EFFECTIVE_DRY_RUN = DRY_RUN or (not ENABLE_REMEDIATION)`, so enabling remediation returns to the plain dry-run-then-live workflow.
# MAGIC - **Collision pre-check before every link.** The KB requires confirming no other identity uses the target `externalId`. The check is built as a full directory index, because the account Users list cannot filter by `externalId` and pages at 100 rows.
# MAGIC - **Bucket 5 is review-first.** Deactivation is not prescribed by the KB, so it is off by default, double-gated, batch-capped, and requires per-id Entra verification. A non-owned domain is escalated, never deactivated.
# MAGIC - **Portability and correctness fixes.** Timestamps use `datetime.now(dt.timezone.utc)` for compatibility with older runtimes. The audit-log write path is standardized. Blank `externalId` values are normalized on load and in rollback. Tickets surface the Entra `objectId` for faster Support resolution.
