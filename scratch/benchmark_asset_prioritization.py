"""Repeatable bounded-data measurements, always in an isolated test database."""
from scratch import test_support

import json
import statistics
import time
import tracemalloc
from pathlib import Path

from app.database import initialize_database, get_connection
from app.services.prioritization_service import list_priorities
from app.services.asset_service import parse_import, csv_template


def main():
    initialize_database()
    with get_connection() as conn:
        conn.executemany("""INSERT INTO assets(id,external_id,name,environment,owner_team,criticality,exposure,created_by,updated_by)
            VALUES (?,?,?,'development','SOC',4,'internet','fixture','fixture')""",
                         [(i, f"fixture-{i}", f"Fixture {i}") for i in range(1, 501)])
        conn.executemany("""INSERT INTO asset_cve_assessments(asset_id,cve_id,source,confidence,evidence_note,status,created_by,updated_by)
            VALUES (?,?,'fixture','suspected',?,'open','fixture','fixture')""",
                         [(i, f"CVE-2026-{10000 + j}", "E" * 4000) for i in range(1, 501) for j in range(20)])
        conn.executemany("INSERT INTO cves(cve_id,cvss_score,epss_score,epss_fetched_at) VALUES (?,9.8,0.5,datetime('now'))",
                         [(f"CVE-2026-{10000 + j}",) for j in range(20)])
    durations = []
    for _ in range(5):
        start = time.perf_counter(); result = list_priorities(); durations.append(time.perf_counter() - start)
        assert result["total"] == 10000 and len(result["items"]) == 50
    rss = next(line.split()[1] for line in Path('/proc/self/status').read_text().splitlines() if line.startswith('VmRSS:'))
    tracemalloc.start(); list_priorities(); _, peak = tracemalloc.get_traced_memory(); tracemalloc.stop()
    template = csv_template().splitlines()
    content = template[0] + "\n" + "\n".join(template[1:] * 1000)
    start = time.perf_counter(); parse_import(content); import_seconds = time.perf_counter() - start
    print(json.dumps({"assets": 500, "assessments": 10000, "evidence_characters_per_row": 4000,
                      "queue_median_seconds": round(statistics.median(durations), 3),
                      "queue_peak_python_mib": round(peak / 1048576, 2),
                      "process_rss_before_tracing_mib": round(int(rss) / 1024, 2),
                      "csv_1000_rows_parse_seconds": round(import_seconds, 3)}, indent=2))


if __name__ == "__main__":
    main()
