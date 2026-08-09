# ============================================================
# app/services/rss_service.py — RSS Feed Parser & Aggregator
# ============================================================
#
# WHAT IS THIS FILE?
# ------------------
# This service reads RSS feeds from cybersecurity news sites
# and stores the articles in our SQLite database.
#
# WHAT IS RSS?
# ------------
# RSS (Really Simple Syndication) is a standardized XML format
# that websites use to publish a list of their latest articles.
# Instead of visiting 5 different news sites manually, an RSS
# reader can pull all their feeds into one place.
#
# HOW DOES feedparser WORK?
# -------------------------
# The "feedparser" library takes an RSS feed URL, downloads
# the XML content, and converts it into easy-to-use Python
# dictionaries. We don't have to parse XML manually!
#
# PYTHON CONCEPTS COVERED:
# - Importing and using third-party libraries
# - Working with the "re" module (regular expressions)
# - Nested for loops
# - String methods (.strip(), slicing)
# ============================================================

# "feedparser" is a third-party library that parses RSS and
# Atom feeds. We installed it with: pip install feedparser
import feedparser

# "re" is Python's built-in Regular Expression module.
# Regular expressions are patterns for searching and
# manipulating text. We use it here to strip HTML tags
# from article summaries.
import re

# "html" is a built-in module for handling HTML entities
# like &amp; (which should become &) and &lt; (which
# should become <).
import html

from app.config import RSS_FEEDS
from app.database import get_connection


def strip_html_tags(text):
    """
    Remove HTML tags from a string, leaving only plain text.

    WHY DO WE NEED THIS?
    ---------------------
    RSS feed summaries often contain HTML markup like:
      "<p>A <b>critical</b> vulnerability was found...</p>"
    We want to display clean text without the HTML tags:
      "A critical vulnerability was found..."

    HOW IT WORKS:
    -------------
    re.sub(pattern, replacement, text) finds all matches of
    "pattern" in "text" and replaces them with "replacement".

    The pattern "<[^>]+>" means:
      <      → Match a literal < character
      [^>]+  → Match one or more characters that are NOT >
      >      → Match a literal > character

    This matches any HTML tag like <p>, </p>, <br/>, etc.
    We replace each match with "" (empty string) to remove it.

    Args:
        text: A string that may contain HTML tags.

    Returns:
        str: The text with all HTML tags removed.
    """
    # If the text is None or empty, return an empty string.
    # This prevents errors when processing missing data.
    if not text:
        return ""

    # re.sub() replaces all matches of the pattern with "".
    # The pattern "<[^>]+>" matches anything between < and >.
    clean_text = re.sub(r"<[^>]+>", "", text)

    # html.unescape() converts HTML entities to normal characters:
    #   "&amp;"  → "&"
    #   "&lt;"   → "<"
    #   "&#39;"  → "'"
    clean_text = html.unescape(clean_text)

    # .strip() removes leading and trailing whitespace
    # (spaces, tabs, newlines) from both ends of the string.
    clean_text = clean_text.strip()

    return clean_text


def fetch_and_store_rss():
    """
    Fetch articles from all configured RSS feeds and save them
    to the database.

    HOW THIS FUNCTION WORKS:
    ------------------------
    1. Loop through each RSS feed in our RSS_FEEDS config list
    2. Use feedparser to download and parse the feed
    3. Extract article title, link, summary, and publish date
    4. Clean up HTML from summaries
    5. Insert each article into the rss_articles database table

    Returns:
        int: Total number of new articles saved across all feeds.
    """
    total_saved = 0

    # ----------------------------------------------------------
    # PYTHON CONCEPT — Nested for loop:
    #   The outer loop iterates over feeds (5 feeds).
    #   The inner loop iterates over articles within each feed.
    #   If each feed has 10 articles, the inner loop runs 50 times.
    # ----------------------------------------------------------

    # Outer loop: iterate over each RSS feed configuration
    for feed_config in RSS_FEEDS:
        # Each feed_config is a dictionary with "name" and "url" keys.
        feed_name = feed_config["name"]
        feed_url = feed_config["url"]

        print(f"📡 Fetching RSS feed: {feed_name}...")

        try:
            # feedparser.parse() downloads and parses the RSS feed.
            # It returns a special object with an "entries" attribute
            # containing a list of articles.
            parsed_feed = feedparser.parse(feed_url)

            # Check if the feed was parsed successfully.
            # "bozo" is feedparser's quirky name for "error flag".
            # If bozo is 1 (True), something went wrong with parsing.
            if parsed_feed.bozo and not parsed_feed.entries:
                print(f"⚠️  Could not parse feed: {feed_name}")
                continue

        except Exception as error:
            print(f"❌ Error fetching RSS feed {feed_name}: {error}")
            # "continue" skips the rest of THIS loop iteration
            # and moves on to the next feed. Without "continue",
            # an error in one feed would stop all feeds from
            # being processed.
            continue

        # Inner loop: iterate over each article in this feed
        # We limit to the first 15 articles per feed using [:15]
        saved_count = 0

        with get_connection() as conn:
            cursor = conn.cursor()

            for entry in parsed_feed.entries[:15]:
                # Extract article fields from the parsed entry.
                # feedparser normalizes field names, but some feeds
                # may be missing certain fields, so we use .get()
                # with default values.
                title = entry.get("title", "No Title")
                link = entry.get("link", "")

                # Skip articles without a link (our UNIQUE constraint
                # requires a link to prevent duplicates)
                if not link:
                    continue

                # Extract the publish date.
                # feedparser provides "published" as a string.
                published = entry.get("published", "")

                # Extract and clean the summary.
                # RSS summaries often contain HTML tags that we
                # need to strip out for clean display.
                raw_summary = entry.get("summary", "")
                summary = strip_html_tags(raw_summary)

                # Truncate very long summaries to 500 characters.
                # PYTHON CONCEPT — String Slicing:
                #   text[:500] takes the first 500 characters.
                #   If the text is shorter than 500, it returns
                #   the whole string (no error).
                if len(summary) > 500:
                    summary = summary[:500] + "..."

                try:
                    cursor.execute("""
                        INSERT OR IGNORE INTO rss_articles
                        (title, link, source, published, summary)
                        VALUES (?, ?, ?, ?, ?)
                    """, (title, link, feed_name, published, summary))

                    if cursor.rowcount > 0:
                        saved_count += 1

                except Exception as db_error:
                    print(f"⚠️  Error saving article '{title}': {db_error}")

            conn.commit()

        total_saved += saved_count
        print(f"   ✅ Saved {saved_count} new articles from {feed_name}")

    # Update the fetch log
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT OR REPLACE INTO fetch_log (source_name, last_fetch, status, record_count)
            VALUES (?, datetime('now'), 'success', ?)
        """, ("rss_feeds", total_saved))
        conn.commit()

    print(f"✅ Total: Saved {total_saved} new RSS articles to the database.")
    return total_saved
