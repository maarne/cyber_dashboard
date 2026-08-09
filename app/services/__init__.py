# ============================================================
# app/services/__init__.py — Services Package Initializer
# ============================================================
#
# This file makes the "services" folder a Python package.
#
# The "services" package contains modules that fetch data
# from external APIs and websites, then store the results
# in our SQLite database. Each service handles one data source:
#
#   - cve_service.py:    NVD vulnerability data
#   - cisa_service.py:   CISA active exploit catalog
#   - rss_service.py:    Security news RSS feeds
#   - threat_service.py: Abuse.ch malicious URL/IP data
#   - db_service.py:     Database query helper functions
# ============================================================
