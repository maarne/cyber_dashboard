# ============================================================
# scratch/test_themes.py — Multi-Theme Engine Test Suite
# ============================================================

import os
import sys
import unittest
import tempfile

# Ensure workspace root is in sys.path
sys.path.insert(0, "/home/maarne/apps/antigravity/cyber_dashboard")

# Use isolated temporary test database so live database is NEVER modified
_temp_test_db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
os.environ["DATABASE_PATH"] = _temp_test_db.name
_temp_test_db.close()

from fastapi.testclient import TestClient
from app.main import app
from app.database import initialize_database
from app.services.auth_service import create_user, create_access_token


class TestMultiThemeEngine(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        initialize_database()
        if not os.path.exists(_temp_test_db.name):
            initialize_database()
        create_user("admin", "AdminPass1234!", "admin")
        cls.client = TestClient(app)
        cls.admin_token = create_access_token("admin", "admin")
        cls.headers = {"Cookie": f"access_token={cls.admin_token}"}

    @classmethod
    def tearDownClass(cls):
        try:
            if os.path.exists(_temp_test_db.name):
                os.remove(_temp_test_db.name)
        except Exception:
            pass

    def test_01_css_themes_defined(self):
        """Verify all 6 themes have CSS variables in style.css."""
        css_path = "/home/maarne/apps/antigravity/cyber_dashboard/app/static/css/style.css"
        self.assertTrue(os.path.exists(css_path))
        with open(css_path, "r", encoding="utf-8") as f:
            content = f.read()

        required_themes = ["dark", "light", "matrix", "cyberpunk", "midnight", "oled"]
        for t in required_themes:
            if t == "dark":
                self.assertIn('html[data-theme="dark"]', content)
            else:
                self.assertIn(f'html[data-theme="{t}"]', content)

        required_vars = [
            "--color-bg-primary",
            "--color-bg-secondary",
            "--color-bg-card",
            "--color-accent",
            "--color-text-primary",
            "--color-text-secondary",
            "--color-border",
        ]
        for v in required_vars:
            self.assertIn(v, content)

    def test_02_theme_js_controller(self):
        """Verify theme.js is structured with all 6 themes and exports."""
        js_path = "/home/maarne/apps/antigravity/cyber_dashboard/app/static/js/theme.js"
        self.assertTrue(os.path.exists(js_path))
        with open(js_path, "r", encoding="utf-8") as f:
            content = f.read()

        self.assertIn("CyberDashTheme", content)
        self.assertIn("setTheme", content)
        self.assertIn("cyberdash_theme", content)
        for t in ["dark", "light", "matrix", "cyberpunk", "midnight", "oled"]:
            self.assertIn(f"id: '{t}'", content)

    def test_03_base_template_header_and_fout_protection(self):
        """Verify base.html contains head blocking script and header theme switcher dropdown."""
        res = self.client.get("/", headers=self.headers)
        self.assertEqual(res.status_code, 200)
        html = res.text

        # Check blocking FOUT script
        self.assertIn("localStorage.getItem('cyberdash_theme')", html)
        self.assertIn("data-theme", html)

        # Check header theme dropdown container and button
        self.assertIn("theme-dropdown-container", html)
        self.assertIn("theme-dropdown-btn", html)
        self.assertIn("Cyber Night", html)

        # Check script inclusion
        self.assertIn("/static/js/theme.js", html)

    def test_04_settings_appearance_tab_and_gallery(self):
        """Verify settings.html includes Appearance tab and theme gallery grid with 6 cards."""
        res = self.client.get("/settings", headers=self.headers)
        self.assertEqual(res.status_code, 200)
        html = res.text

        # Check Appearance tab button
        self.assertIn('data-tab="appearance"', html)
        self.assertIn("Appearance &amp; Themes", html)

        # Check panel-appearance and theme cards
        self.assertIn('id="panel-appearance"', html)
        self.assertIn('class="theme-gallery-grid"', html)

        for t in ["dark", "light", "matrix", "cyberpunk", "midnight", "oled"]:
            self.assertIn(f'data-theme-id="{t}"', html)

    def test_05_all_pages_render_with_theme_support(self):
        """Verify all application routes include theme switcher and scripts."""
        routes = ["/", "/actors", "/rules", "/investigate", "/settings"]
        for route in routes:
            res = self.client.get(route, headers=self.headers)
            self.assertEqual(res.status_code, 200, f"Route {route} failed")
            self.assertIn("theme-dropdown-container", res.text, f"Route {route} missing theme dropdown")
            self.assertIn("/static/js/theme.js", res.text, f"Route {route} missing theme.js")


if __name__ == "__main__":
    unittest.main()
