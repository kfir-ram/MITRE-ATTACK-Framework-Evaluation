"""
@authors: Kfir Ram, Hen Dahan, Shir Bar
@date: 30.6.2021
"""

import urllib.request
import sqlite3
import os.path


def update_event_list_db():
    if os.path.exists("Databases/EventList.db"):
        os.remove("Databases/EventList.db")
    url = "https://raw.githubusercontent.com/miriamxyra/EventList/master/EventList/internal/data/EventList.db"
    urllib.request.urlretrieve(url, 'Databases/EventList.db')


# This function return the hash map of EventList from the db file
def get_event_list_hash_map():
    EventListHashMap = {}
    if not os.path.exists("Databases/EventList.db"):
        update_event_list_db()
    try:
        sqliteConnection = sqlite3.connect("Databases/EventList.db")
        cursor = sqliteConnection.cursor()
        sqlite_select_Query = "select E.event_id, T.technique_id from mitre_events E, mitre_techniques T where " \
                              "E.technique_id = T.id; "
        cursor.execute(sqlite_select_Query)
        record = cursor.fetchall()
        for rec in record:
            if rec[0] in EventListHashMap.keys():
                EventListHashMap[rec[0]].append(rec[1])
            else:
                EventListHashMap[rec[0]] = [rec[1]]
        cursor.close()
        sqliteConnection.close()
        return EventListHashMap
    except sqlite3.Error as error:
        print("error while connecting to sqlite ", error)


# for the purpose of checking for update (there must be a better way to check for update)
def get_event_list_hash_map_for_check():
    EventListHashMap = {}
    if not os.path.exists("Databases/EventList2.db"):
        update_event_list_db()
    try:
        sqliteConnection = sqlite3.connect("Databases/EventList2.db")
        cursor = sqliteConnection.cursor()
        sqlite_select_Query = "select E.event_id, T.technique_id from mitre_events E, mitre_techniques T where " \
                              "E.technique_id = T.id; "
        cursor.execute(sqlite_select_Query)
        record = cursor.fetchall()
        for rec in record:
            if rec[0] in EventListHashMap.keys():
                EventListHashMap[rec[0]].append(rec[1])
            else:
                EventListHashMap[rec[0]] = [rec[1]]
        cursor.close()
        sqliteConnection.close()
        return EventListHashMap
    except sqlite3.Error as error:
        print("error while connecting to sqlite ", error)


# this function print the data inside EventList.db
def show_db():
    conn = sqlite3.connect("Databases/EventList.db")
    cur = conn.cursor()
    cur.execute("SELECT name FROM sqlite_master WHERE type='table';")  # show all the tables in the .db file
    print("mitre_events_table__________________________________________________________________________________")
    print(cur.fetchall())
    cur.execute("SELECT * FROM mitre_events")  # show all the data inside mitre_cti table/
    print(cur.fetchall())
    names = list(map(lambda x: x[0], cur.description))  # show all the columns names
    print(names)
    print("mitre_techniques_table______________________________________________________________________________")
    print(cur.fetchall())
    cur.execute("SELECT * FROM mitre_techniques")  # show all the data inside mitre_cti table/
    print(cur.fetchall())
    names = list(map(lambda x: x[0], cur.description))  # show all the columns names
    print(names)


# This function invert the hash map from (event ID: [TTPs]) to (TTP: [event IDs])
def invert_hash_map(mitre_hash_map):
    new_dic = {}
    for k, v in mitre_hash_map.items():
        for x in v:
            new_dic.setdefault(str(x), []).append(k)
    return new_dic


# this function compere the old list from the db with new one from the internet
# returns true if update is needed else return false
def check_for_update():
    # download a new db from github
    if os.path.exists("Databases/EventList2.db"):
        os.remove("Databases/EventList2.db")
    url = "https://raw.githubusercontent.com/miriamxyra/EventList/master/EventList/internal/data/EventList.db"
    urllib.request.urlretrieve(url, 'Databases/EventList2.db')

    # get the old and the new list
    event_list_from_db = get_event_list_hash_map()
    event_list_from_git = get_event_list_hash_map_for_check()
    os.remove("Databases/EventList2.db")

    # compere the lists to check if the db has changed
    for item in event_list_from_db:
        if item not in event_list_from_git:
            return True
    return False
