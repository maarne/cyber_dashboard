# ============================================================
# app/__init__.py — Package Initializer
# ============================================================
#
# WHAT IS THIS FILE?
# ------------------
# In Python, a folder becomes a "package" (a collection of
# related modules) when it contains a file named __init__.py.
#
# Without this file, Python would NOT recognize the "app/"
# folder as a package, and you would not be able to write
# import statements like:
#
#   from app.config import settings
#   from app.database import get_db
#
# HOW DOES IT WORK?
# -----------------
# When Python encounters "from app import ..." it looks for
# this __init__.py file first. The file can be empty (like
# this one), or it can contain code that runs when the
# package is first imported.
#
# For our project, we keep it empty and simple — its only
# job is to tell Python "yes, this folder is a package".
# ============================================================
