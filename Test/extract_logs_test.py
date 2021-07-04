"""
@authors: Kfir Ram, Hen Dahan, Shir Bar
@date: 30.6.2021
"""

import unittest
import sys


class MyTestCase(unittest.TestCase):
    def test_extract_logs_valid_folder(self):
        sys.path.append("../TTPs Detection by Windows Event Ids/")
        from Util.ExtractLogs import extract_event_ids
        event_ids = []
        self.assertFalse(extract_event_ids(event_ids, ""))
        event_ids = []
        self.assertFalse(extract_event_ids(event_ids, "D:/Projects"))
        event_ids = []
        self.assertTrue(
            extract_event_ids(event_ids, "D:/Projects/MITRE-ATT-CK/TTPs Detection by Windows Event Ids/TestLogsFolder"))
        event_ids = []
        self.assertFalse(extract_event_ids(event_ids, "C:/"))
        event_ids = []
        self.assertFalse(extract_event_ids(event_ids, "D:/NOT_REAL_DIRECTORY"))


if __name__ == '__main__':
    unittest.main()
