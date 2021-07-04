"""
@authors: Kfir Ram, Hen Dahan, Shir Bar
@date: 30.6.2021
"""

import Methods.EventList as EventList
import Methods.MITRECti as MITRECti
import Methods.Malware as Malware
from Util.GetTTPs import get_ttp_from_event_ids


def get_mitre_cti_result(event_id):
    mitreMap = MITRECti.get_mitre_cti_hash_map_from_db()
    event_ids = [event_id]
    return get_ttp_from_event_ids(mitreMap, event_ids)


def get_event_list_result(event_id):
    eventListMap = EventList.get_event_list_hash_map()
    return get_ttp_from_event_ids(eventListMap, event_id)


def get_malware_result(event_id):
    malwareMap = Malware.get_malware_hash_map()
    return get_ttp_from_event_ids(malwareMap, event_id)


# Compares the result of MITRE CTI to the result of the other two methods.
def get_mitre_cti_measure():
    mitre_cti_res = {}
    event_list_res = {}
    malware_res = {}
    count_mite_to_event_list = []
    count_mite_to_malware = []

    mitreMap = MITRECti.get_mitre_cti_hash_map_from_db()
    for event in mitreMap:
        mitre_cti_res[event] = get_mitre_cti_result(event)
        event_list_res[event] = get_event_list_result(event)
        malware_res[event] = get_malware_result(event)

    for event in mitre_cti_res:

        if if_in(mitre_cti_res[event], event_list_res[event]):
            count_mite_to_event_list.append(1)
        else:
            count_mite_to_event_list.append(0)

        if if_in(mitre_cti_res[event], malware_res[event]):
            count_mite_to_malware.append(1)
        else:
            count_mite_to_malware.append(0)

    length_mite_to_event_list = len(count_mite_to_event_list)
    in_mite_to_event_list = sum(count_mite_to_event_list)
    out_mite_to_event_list = length_mite_to_event_list - in_mite_to_event_list

    length_mite_to_malware = len(count_mite_to_malware)
    in_mitre_to_malware = sum(count_mite_to_malware)
    out_mitre_to_malware = length_mite_to_malware - in_mitre_to_malware

    print("length_mite_to_event_list = " + str(length_mite_to_event_list))
    print("in_mite_to_event_list = " + str(in_mite_to_event_list))
    print("out_mite_to_event_list = " + str(out_mite_to_event_list))

    print("------------------------------")

    print("length_mite_to_malware = " + str(length_mite_to_malware))
    print("in_mitre_to_malware = " + str(in_mitre_to_malware))
    print("out_mitre_to_malware = " + str(out_mitre_to_malware))


# Compares the result of Event List to the result of the other two methods.
def get_event_list_measure():
    mitre_cti_res = {}
    event_list_res = {}
    malware_res = {}
    count_event_list_to_mite = []
    count_event_list_malware = []

    eventListMap = EventList.get_event_list_hash_map()

    for event in eventListMap:
        mitre_cti_res[event] = get_mitre_cti_result(event)
        event_list_res[event] = get_event_list_result(event)
        malware_res[event] = get_malware_result(event)

    for event in event_list_res:

        if if_in(event_list_res[event], mitre_cti_res[event]):  # if mitre_cti_res[event] in event_list_res[event]:
            count_event_list_to_mite.append(1)
        else:
            count_event_list_to_mite.append(0)

        if if_in(event_list_res[event], malware_res[event]):  # if mitre_cti_res[event] in malware_res[event]:
            count_event_list_malware.append(1)
        else:
            count_event_list_malware.append(0)

    length_event_list_to_mite = len(count_event_list_to_mite)
    in_event_list_to_mitre = sum(count_event_list_to_mite)
    out_event_list_to_mite = length_event_list_to_mite - in_event_list_to_mitre

    length_event_list_to_malware = len(count_event_list_malware)
    in_event_list_to_malware = sum(count_event_list_malware)
    out_event_list_to_malware = length_event_list_to_malware - in_event_list_to_malware

    print("length_event_list_to_mite = " + str(length_event_list_to_mite))
    print("in_event_list_to_mitre = " + str(in_event_list_to_mitre))
    print("out_event_list_to_mite = " + str(out_event_list_to_mite))

    print("------------------------------")

    print("length_mite_to_malware = " + str(length_event_list_to_malware))
    print("in_mitre_to_malware = " + str(in_event_list_to_malware))
    print("out_mitre_to_malware = " + str(out_event_list_to_malware))


# Compares the result of Malware Archeology to the result of the other two methods.
def get_malware_measure():
    mitre_cti_res = {}
    event_list_res = {}
    malware_res = {}
    count_malware_to_mite = []
    count_malware_to_event_list = []

    malwareMap = Malware.get_malware_hash_map()
    for event in malwareMap:
        mitre_cti_res[event] = get_mitre_cti_result(event)
        event_list_res[event] = get_event_list_result(event)
        malware_res[event] = get_malware_result(event)

    for event in malware_res:

        if if_in(malware_res[event], mitre_cti_res[event]):
            count_malware_to_mite.append(1)
        else:
            count_malware_to_mite.append(0)

        if if_in(malware_res[event], event_list_res[event]):
            count_malware_to_event_list.append(1)
        else:
            count_malware_to_event_list.append(0)

    length_malware_to_mite = len(count_malware_to_mite)
    in_malware_to_mitre = sum(count_malware_to_mite)
    out_malware_to_mite = length_malware_to_mite - in_malware_to_mitre

    length_malware_to_event_list = len(count_malware_to_event_list)
    in_malware_to_event_list = sum(count_malware_to_event_list)
    out_malware_to_event_list = length_malware_to_event_list - in_malware_to_event_list

    print("length_event_list_to_mite = " + str(length_malware_to_mite))
    print("in_event_list_to_mitre = " + str(in_malware_to_mitre))
    print("out_event_list_to_mite = " + str(out_malware_to_mite))

    print("------------------------------")

    print("length_mite_to_malware = " + str(length_malware_to_event_list))
    print("in_mitre_to_malware = " + str(in_malware_to_event_list))
    print("out_mitre_to_malware = " + str(out_malware_to_event_list))


# returns the number of values located inside in_event that are also located inside out_event
def if_in(in_event, out_event):
    count = 0
    for ttp in in_event:
        if len(out_event) != 0:
            for item in out_event:
                if len(item) > 1 and type(item) != str:
                    for i in item:
                        if i == ttp[2:len(ttp) - 2]:
                            count = count + 1
                elif item == ttp[2:len(ttp) - 2]:
                    count = count + 1
                elif item in ttp or ttp in item:
                    count = count + 1
    if count > 0:
        return True
    else:
        return False


print("\nMitre CTI measure: +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
get_mitre_cti_measure()
print("\nEvent List +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
get_event_list_measure()
print("\nMalware ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
get_malware_measure()
