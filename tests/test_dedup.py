import tempfile
import unittest
from pathlib import Path
from soc_l1.dedup import Deduplicator

class DedupTests(unittest.TestCase):
    def test_repeat_alert_is_flagged(self):
        with tempfile.TemporaryDirectory() as tmp:
            dedup = Deduplicator(Path(tmp) / "test.db")
            alert = {"title":"Test","event_type":"login","src_ip":"192.0.2.1","dest_ip":"192.0.2.2","user":"alice","host":"host1","timestamp":"2026-01-01"}
            self.assertFalse(dedup.register(alert)["is_duplicate"])
            result = dedup.register(alert)
            self.assertTrue(result["is_duplicate"])
            self.assertEqual(result["occurrences"], 2)

if __name__ == "__main__":
    unittest.main()
