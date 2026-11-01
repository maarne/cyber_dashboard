"""Ingest the complete CISA KEV catalog, independent of upstream ordering."""

from app.config import CISA_KEV_URL
from app.database import get_connection
from app.services.cve_service import fetch_json, record_fetch


def fetch_and_store_cisa_kev():
    saved = 0
    try:
        data = fetch_json(CISA_KEV_URL)
        vulnerabilities = data.get("vulnerabilities")
        if not isinstance(vulnerabilities, list) or not vulnerabilities:
            raise ValueError("CISA returned an empty or invalid catalog.")
        with get_connection() as conn:
            for vuln in vulnerabilities:
                cve_id = vuln.get("cveID")
                if not cve_id:
                    continue
                exists = conn.execute("SELECT 1 FROM cisa_exploits WHERE cve_id=?", (cve_id,)).fetchone()
                conn.execute("""INSERT INTO cisa_exploits(cve_id, vulnerability_name, vendor_project, product,
                    date_added, short_description, required_action, due_date) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(cve_id) DO UPDATE SET vulnerability_name=excluded.vulnerability_name,
                    vendor_project=excluded.vendor_project, product=excluded.product, date_added=excluded.date_added,
                    short_description=excluded.short_description, required_action=excluded.required_action,
                    due_date=excluded.due_date, fetched_at=datetime('now')""",
                             tuple(vuln.get(k, "") for k in ("cveID", "vulnerabilityName", "vendorProject", "product",
                                                             "dateAdded", "shortDescription", "requiredAction", "dueDate")))
                saved += int(not exists)
        record_fetch("cisa_kev", saved)
        return saved
    except Exception:
        record_fetch("cisa_kev", saved, "failed")
        raise
