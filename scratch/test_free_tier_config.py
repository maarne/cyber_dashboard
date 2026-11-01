"""Keep the development deployment on F1; never silently select a paid tier."""

import json
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class FreeTierConfiguration(unittest.TestCase):
    def test_both_templates_allow_only_free_f1(self):
        for name in ("infra/main.bicep", "infra/modules/appservice.bicep"):
            text = (ROOT / name).read_text()
            allowed = re.search(r"@allowed\(\[([^\]]*)\]\)\s*param skuName string = 'F1'", text, re.S)
            self.assertIsNotNone(allowed, name)
            self.assertEqual(re.findall(r"'([^']+)'", allowed.group(1)), ["F1"], name)
            self.assertRegex(text, r"@allowed\(\[false\]\)\s*param enablePersistentStorage bool = false")

    def test_module_disables_paid_features(self):
        text = (ROOT / "infra/modules/appservice.bicep").read_text()
        self.assertIn("tier: 'Free'", text)
        self.assertIn("capacity: 0", text)
        self.assertIn("alwaysOn: false", text)
        self.assertIn("value: '/app/data/cyber_dashboard.db'", text)
        self.assertNotIn("/home/data/cyber_dashboard.db", text)

    def test_parameters_request_f1_and_ephemeral_storage(self):
        params = json.loads((ROOT / "infra/parameters.prod.json").read_text())["parameters"]
        self.assertEqual(params["skuName"]["value"], "F1")
        self.assertIs(params["enablePersistentStorage"]["value"], False)

    def test_pipeline_has_no_paid_sku_or_persistent_storage_override(self):
        text = (ROOT / "azure-pipelines.yml").read_text()
        self.assertIn("skuName=F1", text)
        self.assertNotRegex(text, r"skuName=(?:B\d|S\d|P\d)")
        self.assertIn("enablePersistentStorage=false", text)
        self.assertIn('WEBSITES_ENABLE_APP_SERVICE_STORAGE=false DATABASE_PATH="/app/data/cyber_dashboard.db"', text)
        self.assertNotIn("enablePersistentStorage=true", text)
        self.assertNotIn("WEBSITES_ENABLE_APP_SERVICE_STORAGE=true", text)
        self.assertIn('jwtSecretKey="$JWT_SECRET_KEY"', text)


if __name__ == "__main__":
    unittest.main(verbosity=2)
