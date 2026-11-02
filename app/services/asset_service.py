"""Private inventory operations. Domain writes and audit appends share a transaction."""

import csv
import hashlib
import io
import json
import secrets
import sqlite3
import time
from contextlib import contextmanager
from datetime import datetime, timezone

from fastapi import HTTPException
from pydantic import ValidationError

from app.database import get_connection
from app.models.asset_schemas import AssetCreate, AssessmentCreate, SoftwareCreate
from app.services.audit_service import log_audit_event

MAX_ASSETS = 500
MAX_SOFTWARE = 5000
MAX_ASSESSMENTS = 10000
MAX_IMPORT_BYTES = 1048576
ASSET_FIELDS = tuple(AssetCreate.model_fields)
SOFTWARE_FIELDS = tuple(SoftwareCreate.model_fields)
ASSESSMENT_FIELDS = tuple(AssessmentCreate.model_fields)
CSV_FIELDS = ["schema_version", "external_id", "name", "environment", "owner_team", "criticality", "exposure", "tags",
              "software_vendor", "software_product", "software_version", "cpe", "cve_ids", "cve_evidence"]


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def validate(model, data):
    try:
        return model.model_validate(data).model_dump(mode="json")
    except ValidationError as exc:
        raise HTTPException(422, exc.errors(include_context=False, include_url=False)) from exc


def actor_key(actor):
    return f"token:{actor['token_id']}" if actor.get("is_api_token") else f"user:{actor['user_id']}"


def audit(conn, actor, action, resource_id, details=None):
    return log_audit_event(
        actor["username"], actor["role"], action, resource_type="ASSET", resource_id=str(resource_id),
        details=canonical({"actor_user_id": actor.get("user_id"), "actor_token_id": actor.get("token_id"), **(details or {})}),
        ip_address=actor.get("ip_address", "unknown"), connection=conn,
    )


@contextmanager
def write_transaction():
    try:
        with get_connection() as conn:
            conn.execute("BEGIN IMMEDIATE")
            yield conn
    except sqlite3.IntegrityError as exc:
        raise HTTPException(409, "A duplicate identifier/software/CVE association or linked-record constraint prevents this change.") from exc


def bump_inventory(conn):
    conn.execute("UPDATE asset_inventory_state SET revision=revision+1 WHERE id=1")


def check_version(row, expected):
    if row["row_version"] != expected:
        raise HTTPException(409, "This record changed. Reload it before saving.")


def get_asset_record(conn, asset_id, *, writable=False):
    row = conn.execute("SELECT * FROM assets WHERE id=?", (asset_id,)).fetchone()
    if not row:
        raise HTTPException(404, "Asset not found.")
    if writable and row["is_archived"]:
        raise HTTPException(409, "Restore the archived asset before editing it.")
    result = dict(row)
    result["tags"] = [r[0] for r in conn.execute("SELECT tag FROM asset_tags WHERE asset_id=? ORDER BY tag", (asset_id,))]
    return result


def get_asset(asset_id):
    with get_connection() as conn:
        return get_asset_record(conn, asset_id)


def literal_like(value):
    return "%" + value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"


def list_assets(*, search="", environment="", tag="", archived=False, availability='', limit=50, offset=0):
    where, params = ["is_archived=?"], [int(archived)]
    if search:
        where.append("(name LIKE ? ESCAPE '\\' OR external_id LIKE ? ESCAPE '\\' OR owner_team LIKE ? ESCAPE '\\')")
        params.extend([literal_like(search)] * 3)
    if environment:
        where.append("environment=?")
        params.append(environment.casefold())
    if tag:
        where.append("EXISTS(SELECT 1 FROM asset_tags t WHERE t.asset_id=assets.id AND t.tag=?)")
        params.append(tag.casefold())
    with get_connection() as conn:
        if availability:
            from app.services.asset_network_service import availability_map
            states = availability_map(conn)
            ids = [key for key, value in states.items() if value['availability'] == availability] if availability != 'disabled' else list(states)
            if availability == 'disabled':
                where.append('id NOT IN (' + ','.join('?' for _ in ids) + ')' if ids else '1=1')
            else:
                where.append('id IN (' + ','.join('?' for _ in ids) + ')' if ids else '1=0')
            params.extend(ids)
        clause = " AND ".join(where)
        total = conn.execute("SELECT COUNT(*) FROM assets WHERE " + clause, params).fetchone()[0]
        ids = conn.execute("SELECT id FROM assets WHERE " + clause + " ORDER BY id DESC LIMIT ? OFFSET ?", (*params, limit, offset)).fetchall()
        items = [get_asset_record(conn, row[0]) for row in ids]
    return {"items": items, "total": total, "limit": limit, "offset": offset}


def _set_tags(conn, asset_id, tags):
    conn.execute("DELETE FROM asset_tags WHERE asset_id=?", (asset_id,))
    conn.executemany("INSERT INTO asset_tags VALUES (?, ?)", [(asset_id, tag) for tag in tags])


def _create_asset(conn, data, actor):
    if conn.execute("SELECT COUNT(*) FROM assets WHERE is_archived=0").fetchone()[0] >= MAX_ASSETS:
        raise HTTPException(409, f"The active inventory limit is {MAX_ASSETS}. Archive unused assets first.")
    cursor = conn.execute("""INSERT INTO assets(external_id,name,environment,owner_team,criticality,exposure,
        created_by_user_id,created_by_token_id,created_by,updated_by) VALUES (?,?,?,?,?,?,?,?,?,?)""",
                          tuple(data[k] for k in ASSET_FIELDS if k != "tags") +
                          (actor.get("user_id"), actor.get("token_id"), actor["username"], actor["username"]))
    asset_id = cursor.lastrowid
    _set_tags(conn, asset_id, data["tags"])
    audit(conn, actor, "ASSET_CREATED", asset_id)
    bump_inventory(conn)
    return asset_id


def create_asset(data, actor):
    data = validate(AssetCreate, data)
    with write_transaction() as conn:
        asset_id = _create_asset(conn, data, actor)
        return get_asset_record(conn, asset_id)


def _update_asset(conn, row, data, actor):
    conn.execute("""UPDATE assets SET external_id=?,name=?,environment=?,owner_team=?,criticality=?,exposure=?,
        updated_by=?,updated_at=CURRENT_TIMESTAMP,row_version=row_version+1 WHERE id=?""",
                 tuple(data[k] for k in ASSET_FIELDS if k != "tags") + (actor["username"], row["id"]))
    _set_tags(conn, row["id"], data["tags"])
    audit(conn, actor, "ASSET_UPDATED", row["id"], {"changed_fields": [k for k in ASSET_FIELDS if row[k] != data[k]]})
    bump_inventory(conn)


def update_asset(asset_id, changes, actor):
    with write_transaction() as conn:
        row = get_asset_record(conn, asset_id, writable=True)
        check_version(row, changes["expected_version"])
        data = validate(AssetCreate, {**{k: row[k] for k in ASSET_FIELDS}, **{k: v for k, v in changes.items() if k != "expected_version"}})
        _update_asset(conn, row, data, actor)
        return get_asset_record(conn, asset_id)


def archive_asset(asset_id, payload, actor):
    with write_transaction() as conn:
        row = get_asset_record(conn, asset_id)
        check_version(row, payload["expected_version"])
        if not payload["archived"] and row["is_archived"]:
            if conn.execute("SELECT COUNT(*) FROM assets WHERE is_archived=0").fetchone()[0] >= MAX_ASSETS:
                raise HTTPException(409, "Active asset limit reached.")
        conn.execute("UPDATE assets SET is_archived=?,row_version=row_version+1,updated_by=?,updated_at=CURRENT_TIMESTAMP WHERE id=?",
                     (int(payload["archived"]), actor["username"], asset_id))
        audit(conn, actor, "ASSET_ARCHIVED" if payload["archived"] else "ASSET_RESTORED", asset_id)
        if payload['archived']:
            from app.services.asset_network_service import archive_monitors
            archive_monitors(conn, asset_id, actor)
        bump_inventory(conn)
        return get_asset_record(conn, asset_id)


def list_software(asset_id, *, limit=100, offset=0):
    with get_connection() as conn:
        get_asset_record(conn, asset_id)
        total = conn.execute("SELECT COUNT(*) FROM asset_software WHERE asset_id=?", (asset_id,)).fetchone()[0]
        items = [dict(r) for r in conn.execute("SELECT * FROM asset_software WHERE asset_id=? ORDER BY id DESC LIMIT ? OFFSET ?", (asset_id, limit, offset))]
    return {"items": items, "total": total, "limit": limit, "offset": offset}


def _create_software(conn, asset_id, data, actor):
    if conn.execute("SELECT COUNT(*) FROM asset_software").fetchone()[0] >= MAX_SOFTWARE:
        raise HTTPException(409, "Software record limit reached (5000).")
    cursor = conn.execute("""INSERT INTO asset_software(asset_id,vendor,product,version,vendor_key,product_key,version_key,
        cpe,source,observed_at,created_by,updated_by) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
                          (asset_id, data["vendor"], data["product"], data["version"], data["vendor"].casefold(),
                           data["product"].casefold(), data["version"].casefold(), data["cpe"], data["source"],
                           data["observed_at"] or datetime.now(timezone.utc).isoformat(), actor["username"], actor["username"]))
    audit(conn, actor, "ASSET_SOFTWARE_CREATED", asset_id, {"software_id": cursor.lastrowid})
    bump_inventory(conn)
    return cursor.lastrowid


def create_software(asset_id, data, actor):
    data = validate(SoftwareCreate, data)
    with write_transaction() as conn:
        get_asset_record(conn, asset_id, writable=True)
        software_id = _create_software(conn, asset_id, data, actor)
        return dict(conn.execute("SELECT * FROM asset_software WHERE id=?", (software_id,)).fetchone())


def change_software(asset_id, software_id, changes, actor, *, delete=False):
    with write_transaction() as conn:
        get_asset_record(conn, asset_id, writable=True)
        row = conn.execute("SELECT * FROM asset_software WHERE asset_id=? AND id=?", (asset_id, software_id)).fetchone()
        if not row:
            raise HTTPException(404, "Software record not found on this asset.")
        check_version(row, changes["expected_version"])
        if delete:
            if conn.execute("SELECT 1 FROM asset_cve_assessments WHERE software_id=?", (software_id,)).fetchone():
                raise HTTPException(409, "Detach linked CVE associations before deleting this software record.")
            conn.execute("DELETE FROM asset_software WHERE id=?", (software_id,))
        else:
            data = validate(SoftwareCreate, {**{k: row[k] for k in SOFTWARE_FIELDS}, **{k: v for k, v in changes.items() if k != "expected_version"}})
            conn.execute("""UPDATE asset_software SET vendor=?,product=?,version=?,vendor_key=?,product_key=?,version_key=?,
                cpe=?,source=?,observed_at=?,updated_by=?,updated_at=CURRENT_TIMESTAMP,row_version=row_version+1 WHERE id=?""",
                         (data["vendor"], data["product"], data["version"], data["vendor"].casefold(), data["product"].casefold(),
                          data["version"].casefold(), data["cpe"], data["source"], data["observed_at"] or row["observed_at"], actor["username"], software_id))
        audit(conn, actor, "ASSET_SOFTWARE_DELETED" if delete else "ASSET_SOFTWARE_UPDATED", asset_id, {"software_id": software_id})
        bump_inventory(conn)
        return {"deleted": True} if delete else dict(conn.execute("SELECT * FROM asset_software WHERE id=?", (software_id,)).fetchone())


def _check_software_link(conn, asset_id, software_id):
    if software_id and not conn.execute("SELECT 1 FROM asset_software WHERE id=? AND asset_id=?", (software_id, asset_id)).fetchone():
        raise HTTPException(422, "Linked software must belong to this asset.")


def _assessment_event(conn, actor, row, before=None):
    event_id = audit(conn, actor, "ASSET_CVE_UPDATED" if before else "ASSET_CVE_ASSOCIATED", row["asset_id"],
                     {"assessment_id": row["id"], "cve_id": row["cve_id"], "status": row["status"]})
    conn.execute("""INSERT INTO asset_assessment_events(assessment_id,actor_user_id,actor_token_id,actor_name,
        before_json,after_json,audit_event_id) VALUES (?,?,?,?,?,?,?)""",
                 (row["id"], actor.get("user_id"), actor.get("token_id"), actor["username"],
                  canonical(before) if before else None, canonical(row), event_id))


def _create_assessment(conn, asset_id, data, actor):
    _check_software_link(conn, asset_id, data["software_id"])
    if conn.execute("SELECT COUNT(*) FROM asset_cve_assessments").fetchone()[0] >= MAX_ASSESSMENTS:
        raise HTTPException(409, "Assessment limit reached (10000).")
    cursor = conn.execute("""INSERT INTO asset_cve_assessments(asset_id,cve_id,software_id,source,confidence,evidence_note,
        status,reason,accepted_risk_expires_at,created_by,updated_by) VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                          (asset_id,) + tuple(data[k] for k in ASSESSMENT_FIELDS) + (actor["username"], actor["username"]))
    row = dict(conn.execute("SELECT * FROM asset_cve_assessments WHERE id=?", (cursor.lastrowid,)).fetchone())
    _assessment_event(conn, actor, row)
    bump_inventory(conn)
    return row


def create_assessment(asset_id, data, actor):
    data = validate(AssessmentCreate, data)
    with write_transaction() as conn:
        get_asset_record(conn, asset_id, writable=True)
        return _create_assessment(conn, asset_id, data, actor)


def update_assessment(assessment_id, changes, actor):
    with write_transaction() as conn:
        row = conn.execute("SELECT * FROM asset_cve_assessments WHERE id=?", (assessment_id,)).fetchone()
        if not row:
            raise HTTPException(404, "Assessment not found.")
        before = dict(row)
        get_asset_record(conn, row["asset_id"], writable=True)
        check_version(row, changes["expected_version"])
        data = validate(AssessmentCreate, {**{k: row[k] for k in ASSESSMENT_FIELDS}, **{k: v for k, v in changes.items() if k != "expected_version"}})
        _check_software_link(conn, row["asset_id"], data["software_id"])
        conn.execute("""UPDATE asset_cve_assessments SET software_id=?,source=?,confidence=?,evidence_note=?,status=?,reason=?,
            accepted_risk_expires_at=?,updated_by=?,updated_at=CURRENT_TIMESTAMP,row_version=row_version+1 WHERE id=?""",
                     tuple(data[k] for k in ASSESSMENT_FIELDS if k != "cve_id") + (actor["username"], assessment_id))
        result = dict(conn.execute("SELECT * FROM asset_cve_assessments WHERE id=?", (assessment_id,)).fetchone())
        _assessment_event(conn, actor, result, before)
        bump_inventory(conn)
        return result


def assessment_events(asset_id, *, limit=100, offset=0):
    with get_connection() as conn:
        get_asset_record(conn, asset_id)
        return [dict(row) for row in conn.execute("""SELECT e.* FROM asset_assessment_events e
            JOIN asset_cve_assessments a ON a.id=e.assessment_id WHERE a.asset_id=? ORDER BY e.id DESC LIMIT ? OFFSET ?""", (asset_id, limit, offset))]


def parse_import(content):
    if len(content.encode("utf-8")) > MAX_IMPORT_BYTES:
        raise HTTPException(413, "CSV imports are limited to 1 MiB.")
    errors, groups = [], {}
    try:
        reader = csv.DictReader(io.StringIO(content.lstrip("\ufeff")), strict=True)
        if reader.fieldnames != CSV_FIELDS:
            raise HTTPException(422, {"errors": [{"row": 1, "message": "Use the CSV template headers in their original order."}]})
        for number, row in enumerate(reader, 2):
            if number > 1001:
                raise HTTPException(413, "CSV imports are limited to 1000 data rows.")
            try:
                if None in row or any(value is None for value in row.values()):
                    raise ValueError("Incorrect number of columns.")
                if row["schema_version"] != "1":
                    raise ValueError("Unsupported CSV schema_version (expected 1).")
                asset = AssetCreate.model_validate({k: row[k] for k in ASSET_FIELDS if k not in ("criticality", "tags")} |
                                                  {"criticality": int(row["criticality"]), "tags": [t.strip() for t in row["tags"].split(";") if t.strip()]}).model_dump(mode="json")
                software = None
                if any(row[k].strip() for k in ("software_vendor", "software_product", "software_version", "cpe")):
                    software = SoftwareCreate(vendor=row["software_vendor"], product=row["software_product"], version=row["software_version"],
                                              cpe=row["cpe"] or None, source="csv import").model_dump(mode="json")
                assessments = [AssessmentCreate(cve_id=cve.strip(), evidence_note=row["cve_evidence"], source="csv import").model_dump(mode="json")
                               for cve in row["cve_ids"].split(";") if cve.strip()]
                key = asset["external_id"]
                group = groups.setdefault(key, {"asset": asset, "software": [], "assessments": []})
                if group["asset"] != asset:
                    raise ValueError("Conflicting asset fields for repeated external_id.")
                if software:
                    previous_software = next((s for s in group["software"] if all(s[k].casefold() == software[k].casefold()
                                             for k in ("vendor", "product", "version"))), None)
                    if previous_software and previous_software["cpe"] != software["cpe"]:
                        raise ValueError("Conflicting CPE for repeated software tuple.")
                    if not previous_software:
                        group["software"].append(software)
                for assessment in assessments:
                    previous = next((a for a in group["assessments"] if a["cve_id"] == assessment["cve_id"]), None)
                    if previous and previous != assessment:
                        raise ValueError("Conflicting evidence for repeated asset/CVE pair.")
                    if not previous:
                        group["assessments"].append(assessment)
            except (ValidationError, ValueError) as exc:
                message = str(exc)[:500]
                errors.append({"row": number, "message": message})
    except csv.Error as exc:
        errors.append({"row": reader.line_num, "message": str(exc)[:200]})
    if errors or not groups:
        raise HTTPException(422, {"errors": errors or [{"row": 2, "message": "CSV has no data rows."}]})
    return list(groups.values())


def preview_import(content, actor):
    groups = parse_import(content)
    payload = canonical(groups)
    token = secrets.token_urlsafe(32)
    now = int(time.time())
    with write_transaction() as conn:
        conn.execute("DELETE FROM asset_import_previews WHERE expires_at < ? OR consumed_at IS NOT NULL", (now,))
        # Keep bounded transient storage even when callers repeatedly preview large files.
        conn.execute("DELETE FROM asset_import_previews WHERE actor_key=?", (actor_key(actor),))
        if conn.execute("SELECT COUNT(*) FROM asset_import_previews").fetchone()[0] >= 20:
            raise HTTPException(409, "Too many pending inventory previews. Retry after they expire.")
        revision = conn.execute("SELECT revision FROM asset_inventory_state WHERE id=1").fetchone()[0]
        created, merged, software_new, cves_new = 0, 0, 0, 0
        for group in groups:
            row = conn.execute("SELECT id,is_archived FROM assets WHERE external_id=?", (group["asset"]["external_id"],)).fetchone()
            if row and row["is_archived"]:
                raise HTTPException(409, "An imported identifier belongs to an archived asset. Restore it explicitly first.")
            created += int(row is None)
            merged += int(row is not None)
            for software in group["software"]:
                exists = row and conn.execute("SELECT 1 FROM asset_software WHERE asset_id=? AND vendor_key=? AND product_key=? AND version_key=?",
                                              (row["id"], *(software[k].casefold() for k in ("vendor", "product", "version")))).fetchone()
                software_new += int(not exists)
            for assessment in group["assessments"]:
                exists = row and conn.execute("SELECT 1 FROM asset_cve_assessments WHERE asset_id=? AND cve_id=?", (row["id"], assessment["cve_id"])).fetchone()
                cves_new += int(not exists)
        if conn.execute("SELECT COUNT(*) FROM assets WHERE is_archived=0").fetchone()[0] + created > MAX_ASSETS:
            raise HTTPException(409, "Import would exceed the active asset limit.")
        if conn.execute("SELECT COUNT(*) FROM asset_software").fetchone()[0] + software_new > MAX_SOFTWARE:
            raise HTTPException(409, "Import would exceed the software record limit.")
        if conn.execute("SELECT COUNT(*) FROM asset_cve_assessments").fetchone()[0] + cves_new > MAX_ASSESSMENTS:
            raise HTTPException(409, "Import would exceed the CVE association limit.")
        conn.execute("INSERT INTO asset_import_previews(token_hash,actor_key,inventory_revision,payload_json,payload_hash,expires_at) VALUES (?,?,?,?,?,?)",
                     (hashlib.sha256(token.encode()).hexdigest(), actor_key(actor), revision, payload, hashlib.sha256(payload.encode()).hexdigest(), now + 600))
        audit(conn, actor, "ASSET_IMPORT_PREVIEWED", "inventory", {"assets": len(groups)})
    return {"schema_version": 1, "preview_token": token, "expires_in_seconds": 600, "inventory_revision": revision,
            "summary": {"assets_created": created, "assets_merged": merged, "software_added": software_new, "cves_added": cves_new},
            "items": groups, "policy": "Merge by external ID; add missing software/CVEs; existing assessment evidence and states are preserved."}


def commit_import(token, actor):
    with write_transaction() as conn:
        row = conn.execute("SELECT * FROM asset_import_previews WHERE token_hash=?", (hashlib.sha256(token.encode()).hexdigest(),)).fetchone()
        if not row or row["actor_key"] != actor_key(actor):
            raise HTTPException(404, "Import preview not found for this caller.")
        if row["consumed_at"] or row["expires_at"] <= int(time.time()):
            raise HTTPException(409, "Preview already committed or expired. Preview the CSV again.")
        if conn.execute("SELECT revision FROM asset_inventory_state WHERE id=1").fetchone()[0] != row["inventory_revision"]:
            raise HTTPException(409, "Inventory changed since preview. Preview the CSV again.")
        if hashlib.sha256(row["payload_json"].encode()).hexdigest() != row["payload_hash"]:
            raise HTTPException(409, "Preview integrity mismatch. Preview the CSV again.")
        groups = json.loads(row["payload_json"])
        result = {"assets_created": 0, "assets_merged": 0, "software_added": 0, "cves_added": 0}
        for group in groups:
            asset = conn.execute("SELECT id FROM assets WHERE external_id=?", (group["asset"]["external_id"],)).fetchone()
            if asset:
                asset_id = asset[0]
                current = get_asset_record(conn, asset_id, writable=True)
                _update_asset(conn, current, group["asset"], actor)
                result["assets_merged"] += 1
            else:
                asset_id = _create_asset(conn, group["asset"], actor)
                result["assets_created"] += 1
            for software in group["software"]:
                if not conn.execute("SELECT 1 FROM asset_software WHERE asset_id=? AND vendor_key=? AND product_key=? AND version_key=?",
                                    (asset_id, *(software[k].casefold() for k in ("vendor", "product", "version")))).fetchone():
                    _create_software(conn, asset_id, software, actor)
                    result["software_added"] += 1
            for assessment in group["assessments"]:
                if not conn.execute("SELECT 1 FROM asset_cve_assessments WHERE asset_id=? AND cve_id=?", (asset_id, assessment["cve_id"])).fetchone():
                    _create_assessment(conn, asset_id, assessment, actor)
                    result["cves_added"] += 1
        conn.execute("UPDATE asset_import_previews SET consumed_at=?,payload_json=NULL WHERE token_hash=?", (int(time.time()), row["token_hash"]))
        audit(conn, actor, "ASSET_IMPORT_COMMITTED", "inventory", result)
        return result


def safe_csv_cell(value):
    text = "" if value is None else str(value)
    return "'" + text if text.lstrip().startswith(("=", "+", "-", "@")) else text


def csv_template():
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(CSV_FIELDS)
    writer.writerow(["1", "demo-server-01", "Example server", "development", "SOC", "2", "unknown", "demo;lab",
                     "Example Vendor", "Example Product", "1.0", "", "CVE-2026-10000", "Example only: confirm applicability before use."])
    return output.getvalue()


def export_inventory(actor):
    with write_transaction() as conn:
        assets = [get_asset_record(conn, r[0]) for r in conn.execute("SELECT id FROM assets ORDER BY id")]
        software = [dict(r) for r in conn.execute("SELECT * FROM asset_software ORDER BY id")]
        assessments = [dict(r) for r in conn.execute("SELECT * FROM asset_cve_assessments ORDER BY id")]
        # All lists are read in one snapshot; only actor display names, never credentials.
        audit(conn, actor, "ASSET_INVENTORY_EXPORTED", "inventory", {"assets": len(assets)})
    return {"schema_version": 1, "exported_at": datetime.now(timezone.utc).isoformat(),
            "assets": assets, "software": software, "assessments": assessments,
            "notice": "This is an inventory export, not a complete application database backup."}


def inventory_csv(data):
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(CSV_FIELDS + ["archived"])
    for asset in data["assets"]:
        software = [s for s in data["software"] if s["asset_id"] == asset["id"]] or [None]
        assessments = [a for a in data["assessments"] if a["asset_id"] == asset["id"]]
        for item in software:
            values = [1, *(asset[k] for k in ASSET_FIELDS if k != "tags"), ";".join(asset["tags"]),
                      *(item[k] if item else "" for k in ("vendor", "product", "version", "cpe")),
                      ";".join(a["cve_id"] for a in assessments), "See versioned JSON export for original evidence and assessment states.", asset["is_archived"]]
            writer.writerow([safe_csv_cell(v) for v in values])
    return output.getvalue()
