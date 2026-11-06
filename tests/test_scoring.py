import unittest
from soc_l1.scoring import score_alert
from soc_l1.mitre import map_technique

class ScoringTests(unittest.TestCase):
    def test_critical_credential_dumping_escalates(self):
        result = score_alert({"severity":"critical","urgency":"high","event_type":"credential_dumping"})
        self.assertEqual(result["recommendation"], "ESCALATE")
        self.assertGreaterEqual(result["risk_score"], 70)

    def test_known_good_is_not_escalated(self):
        result = score_alert({"severity":"critical","urgency":"critical","disposition":"known_good"})
        self.assertEqual(result["recommendation"], "MONITOR")
        self.assertEqual(result["risk_score"], 0)

    def test_low_severity_monitors(self):
        result = score_alert({"severity":"low","urgency":"low","event_type":"unknown"})
        self.assertEqual(result["recommendation"], "MONITOR")

    def test_attack_mapping(self):
        self.assertEqual(map_technique("credential_dumping")["technique"], "T1003")

if __name__ == "__main__":
    unittest.main()
