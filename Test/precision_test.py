"""
@authors: Kfir Ram, Hen Dahan, Shir Bar
@date: 30.6.2021
"""

import unittest
import sqlite3


class MyTestCase(unittest.TestCase):
    def test_mitre_cti_precision(self):
        event_id = 4624
        mitreCTIHashMap = {}
        try:
            sqliteConnection = sqlite3.connect("../Databases/Mitre_CTI.db")
            cursor = sqliteConnection.cursor()
            sqlite_select_Query = "select event_id, ttp from mitre_cti"
            cursor.execute(sqlite_select_Query)
            record = cursor.fetchall()
            # print(mitreCTIHashMap)
            for rec in record:
                if rec[0] in mitreCTIHashMap.keys():
                    mitreCTIHashMap[int(rec[0])].append(rec[1])
                else:
                    # print(rec[0])
                    mitreCTIHashMap[int(rec[0])] = [rec[1]]
            cursor.close()
            sqliteConnection.close()
            print(set(mitreCTIHashMap[event_id]))
            # print(mitreCTIHashMap)
            self.assertTrue(True)
        except sqlite3.Error as error:
            print("error while connecting to sqlite ", error)
            self.assertTrue(False)

    def test_event_list_precision(self):
        event_id = 4688
        EventListHashMap = {}
        try:
            sqliteConnection = sqlite3.connect("../Databases/EventList.db")
            cursor = sqliteConnection.cursor()
            sqlite_select_Query = "select E.event_id, T.technique_id from mitre_events E, mitre_techniques T where " \
                                  "E.technique_id = T.id; "
            cursor.execute(sqlite_select_Query)
            record = cursor.fetchall()
            for rec in record:
                print(rec[0])
                if rec[0] in EventListHashMap.keys():
                    EventListHashMap[rec[0]].append(rec[1])
                else:
                    EventListHashMap[rec[0]] = [rec[1]]
            cursor.close()
            sqliteConnection.close()
            print("\nSearching TTPs of event id: " + str(event_id))
            print(EventListHashMap[event_id]) if event_id in EventListHashMap.keys() else print("nothing was found")

            # print(EventListHashMap)
            self.assertTrue(True)
        except sqlite3.Error as error:
            print("error while connecting to sqlite ", error)
            self.assertTrue(False)


if __name__ == '__main__':
    unittest.main()
