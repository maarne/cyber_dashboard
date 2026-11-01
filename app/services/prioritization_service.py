"""Explainable v1 ranking, using local facts only; never guesses applicability."""

from datetime import datetime, timezone
import math

from app.config import ASSET_INTEL_STALE_HOURS
from app.database import get_connection


def utc_time(value):
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed.astimezone(timezone.utc)
    except (ValueError, TypeError):
        return None


def known_number(value, maximum):
    return value if isinstance(value, (int, float)) and math.isfinite(value) and 0 <= value <= maximum else None


def explain(row, source_state, now):
    cvss = known_number(row["cvss_score"], 10)
    epss = known_number(row["epss_score"], 1)
    kev = True if row["kev_present"] else False if source_state["kev_last_success"] else None
    exposure = row["exposure"]
    inputs = {"cvss": cvss, "epss": epss, "kev": kev, "criticality": row["criticality"], "exposure": exposure}
    components = {"cvss": cvss * 4 if cvss is not None else None,
                  "epss": epss * 20 if epss is not None else None,
                  "kev": 20 if kev else 0 if kev is False else None,
                  "criticality": (row["criticality"] - 1) * 5,
                  "exposure": 5 if exposure == "internet" else 0 if exposure == "internal" else None}
    missing = [key for key, value in components.items() if value is None]
    subtotal = round(sum(value for value in components.values() if value is not None), 2)
    warnings = []
    timestamps = {"epss": row["epss_fetched_at"], "kev": source_state["kev_last_success"]}
    for source, timestamp in timestamps.items():
        parsed = utc_time(timestamp)
        if parsed is None:
            warnings.append(f"{source}_freshness_unknown")
        elif (now - parsed).total_seconds() > ASSET_INTEL_STALE_HOURS * 3600:
            warnings.append(f"{source}_stale")
    if source_state["kev_latest_status"] not in (None, "success"):
        warnings.append("kev_latest_refresh_failed")
    expiry = utc_time(row["accepted_risk_expires_at"])
    expired = row["status"] == "accepted_risk" and (expiry is None or expiry <= now)
    effective = "open" if expired else row["status"]
    return {**row, "formula_version": "v1", "inputs": inputs, "components": components,
            "score": None if missing else min(100, subtotal), "known_subtotal": subtotal,
            "missing_inputs": missing, "freshness_warnings": warnings,
            "intelligence": {**source_state, "epss_fetched_at": row["epss_fetched_at"], "nvd_record_modified": row["last_modified"]},
            "urgent_kev": kev is True, "risk_acceptance_expired": expired, "effective_status": effective,
            "actionable": effective in ("open", "in_progress")}


def list_priorities(*, asset_id=None, search="", environment="", tag="", status="actionable", exposure="",
                    confidence="", urgent_only=False, include_archived=False, limit=50, offset=0):
    clauses, params = ["1=1"], []
    if not include_archived:
        clauses.append("a.is_archived=0")
    for value, clause in ((asset_id, "a.id=?"), (environment.casefold(), "a.environment=?"),
                          (exposure, "a.exposure=?"), (confidence, "v.confidence=?")):
        if value:
            clauses.append(clause)
            params.append(value)
    if tag:
        clauses.append("EXISTS(SELECT 1 FROM asset_tags t WHERE t.asset_id=a.id AND t.tag=?)")
        params.append(tag.casefold())
    with get_connection() as conn:
        # One read snapshot for inventory, scores and feed state.
        conn.execute("BEGIN")
        fetches = {r["source_name"]: dict(r) for r in conn.execute("SELECT source_name,status,last_fetch,last_success FROM fetch_log WHERE source_name IN ('cisa_kev','nvd_cves')")}
        kev_latest, nvd_latest = fetches.get("cisa_kev"), fetches.get("nvd_cves")
        source_state = {"kev_last_success": kev_latest["last_success"] if kev_latest else None,
                        "kev_latest_status": kev_latest["status"] if kev_latest else None,
                        "nvd_latest_sync": nvd_latest}
        # Do not load every 4,000-character evidence/reason field to rank 10,000
        # findings. Hydrate only the requested page in the same read snapshot.
        rows = conn.execute("""SELECT v.id,v.asset_id,v.cve_id,v.status,v.confidence,v.accepted_risk_expires_at,
            a.name AS asset_name,a.external_id,a.environment,a.owner_team,
            a.criticality,a.exposure,a.is_archived,c.cvss_score,c.epss_score,c.epss_fetched_at,c.severity,c.last_modified,
            EXISTS(SELECT 1 FROM cisa_exploits k WHERE k.cve_id=v.cve_id) AS kev_present
            FROM asset_cve_assessments v JOIN assets a ON a.id=v.asset_id LEFT JOIN cves c ON c.cve_id=v.cve_id
            WHERE """ + " AND ".join(clauses), params).fetchall()
        now = datetime.now(timezone.utc)
        items = [explain(dict(row), source_state, now) for row in rows]
        if search:
            term = search.casefold()
            items = [r for r in items if any(term in str(r[k]).casefold() for k in ("asset_name", "external_id", "cve_id", "owner_team"))]
        if status == "actionable":
            items = [r for r in items if r["actionable"]]
        elif status != "all":
            items = [r for r in items if r["effective_status"] == status]
        if urgent_only:
            items = [r for r in items if r["urgent_kev"]]
        items.sort(key=lambda r: (not r["urgent_kev"], -(r["score"] if r["score"] is not None else r["known_subtotal"]), r["id"]))
        selected = items[offset:offset + limit]
        if selected:
            placeholders = ",".join("?" for _ in selected)
            records = {r["id"]: dict(r) for r in conn.execute("SELECT * FROM asset_cve_assessments WHERE id IN (" + placeholders + ")", [r["id"] for r in selected])}
            selected = [{**r, **records[r["id"]]} for r in selected]
        return {"items": selected, "total": len(items), "limit": limit, "offset": offset, "formula_version": "v1"}
