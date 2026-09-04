"""
Response analyzers for each principal type.

Each ``analyze_*`` function receives the JSON dict returned by the
corresponding MatchWithIdp endpoint and returns a CSV-row dict when at
least one error category applies, or ``None`` otherwise.
"""

from .constants import (
    ERROR_EXTERNAL_ID_MATCH_NAME_MISMATCH,
    ERROR_EXTERNAL_ID_NOT_IN_IDP,
    ERROR_GROUP_HAS_LOCAL_MEMBERS_WITH_EXTERNAL_ID,
    ERROR_GROUP_HAS_LOCAL_MEMBERS_WITHOUT_EXTERNAL_ID,
    ERROR_NAME_MATCH_EXTERNAL_ID_MISMATCH,
)


def _fmt_errors(errors):
    return ";".join(str(e) for e in errors)


def analyze_user(match_resp):
    """Analyze a user MatchWithIdp response for divergence errors.

    Returns a CSV-row dict if at least one error applies, or None otherwise.
    """
    db_user = match_resp.get("databricks_user", {})
    idp_by_ext = match_resp.get("idp_match_by_external_id")
    idp_by_name = match_resp.get("idp_match_by_username")
    idp_by_name_ext_id = (idp_by_name or {}).get("external_id", "")

    internal_id = db_user.get("internal_id", "")
    external_id = db_user.get("external_id", "")
    username = db_user.get("username", "")

    errors = []

    # User has an externalId locally but nothing came back from the IDP.
    if external_id and not idp_by_ext:
        errors.append(ERROR_EXTERNAL_ID_NOT_IN_IDP)

    # IDP found a match by external_id, but the usernames differ.
    if idp_by_ext:
        idp_by_ext_username = idp_by_ext.get("username", "")
        if username != idp_by_ext_username:
            errors.append(ERROR_EXTERNAL_ID_MATCH_NAME_MISMATCH)

    # IDP found a match by username, but the externalIds differ.
    if idp_by_name_ext_id and idp_by_name_ext_id != external_id:
        errors.append(ERROR_NAME_MATCH_EXTERNAL_ID_MISMATCH)

    if not errors:
        return None
    return {
        "id": str(internal_id),
        "username": username,
        "externalId": external_id,
        "externalIdWithUsernameMatch": idp_by_name_ext_id,
        "errorCategories": _fmt_errors(errors),
    }


def analyze_group(match_resp):
    """Analyze a group MatchWithIdp response for divergence errors.

    Also checks membership differences between the local and IDP group.
    Returns a CSV-row dict if at least one error applies, or None otherwise.
    """
    db_group = match_resp.get("databricks_group", {})
    idp_by_ext = match_resp.get("idp_match_by_external_id")
    idp_by_name_list = match_resp.get("idp_matches_by_group_name", [])
    idp_by_name_ext_ids = [
        g.get("external_id", "") for g in idp_by_name_list
        if g.get("external_id")
    ]
    internal_id = db_group.get("internal_id", "")
    external_id = db_group.get("external_id", "")
    group_name = db_group.get("group_name", "")

    # Extract the membership differences between the local and IDP group.
    local_members_not_idp = match_resp.get("local_members_not_in_idp", [])
    external_members_not_idp = match_resp.get("external_members_not_in_idp", [])
    local_ids = [str(m.get("principal_id", "")) for m in local_members_not_idp]
    ext_ids = [str(m.get("principal_id", "")) for m in external_members_not_idp]

    errors = []

    # Group has an externalId locally but nothing came back from the IDP.
    if external_id and not idp_by_ext:
        errors.append(ERROR_EXTERNAL_ID_NOT_IN_IDP)

    # IDP found a match by external_id, but the group names differ.
    if idp_by_ext:
        idp_by_ext_group_name = idp_by_ext.get("group_name", "")
        if group_name != idp_by_ext_group_name:
            errors.append(ERROR_EXTERNAL_ID_MATCH_NAME_MISMATCH)

    # IDP groups matched by name, but none share the same externalId.
    if idp_by_name_ext_ids and not any(eid == external_id for eid in idp_by_name_ext_ids):
        errors.append(ERROR_NAME_MATCH_EXTERNAL_ID_MISMATCH)

    # Members that exist only in Databricks with no externalId.
    if local_members_not_idp:
        errors.append(ERROR_GROUP_HAS_LOCAL_MEMBERS_WITHOUT_EXTERNAL_ID)

    # Members that have an externalId but aren't in the IDP group.
    if external_members_not_idp:
        errors.append(ERROR_GROUP_HAS_LOCAL_MEMBERS_WITH_EXTERNAL_ID)

    if not errors:
        return None

    return {
        "id": str(internal_id),
        "groupName": group_name,
        "externalId": external_id,
        "externalIdsWithGroupnameMatch": ";".join(idp_by_name_ext_ids),
        "localMembersNotInIdpInternalIds": ";".join(local_ids),
        "externalMembersNotInIdpInternalIds": ";".join(ext_ids),
        "errorCategories": _fmt_errors(errors),
    }


def analyze_sp(match_resp):
    """Analyze a service principal MatchWithIdp response for divergence errors.

    Returns a CSV-row dict if at least one error applies, or None otherwise.
    """
    db_sp = match_resp.get("databricks_service_principal", {})
    idp_by_ext = match_resp.get("idp_match_by_external_id")
    idp_by_app = match_resp.get("idp_match_by_app_id")

    internal_id = db_sp.get("internal_id", "")
    external_id = db_sp.get("external_id", "")
    application_id = db_sp.get("application_id", "")

    errors = []

    # SP has an externalId locally but nothing came back from the IDP.
    if external_id and not idp_by_ext:
        errors.append(ERROR_EXTERNAL_ID_NOT_IN_IDP)

    # IDP found a match by external_id, but the application_ids differ.
    if idp_by_ext:
        idp_by_ext_app_id = idp_by_ext.get("application_id", "")
        if application_id != idp_by_ext_app_id:
            errors.append(ERROR_EXTERNAL_ID_MATCH_NAME_MISMATCH)

    # IDP found a match by application_id, but the external_ids differ.
    idp_by_app_ext_id = (idp_by_app or {}).get("external_id", "")
    if idp_by_app_ext_id and idp_by_app_ext_id != external_id:
        errors.append(ERROR_NAME_MATCH_EXTERNAL_ID_MISMATCH)

    if not errors:
        return None
    return {
        "id": str(internal_id),
        "applicationId": application_id,
        "externalId": external_id,
        "externalIdWithAppIdMatch": idp_by_app_ext_id,
        "errorCategories": _fmt_errors(errors),
    }
