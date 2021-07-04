"""
@authors: Kfir Ram, Hen Dahan, Shir Bar
@date: 30.6.2021
"""

import ctypes
import os
import shutil
import time
import PySimpleGUI as Sg
import urllib.request
import threading
from datetime import datetime
from Util.ExtractLogs import extract_event_ids, terminate_threads
from Util.MergeHashMaps import merge_hash_maps
from Util.GetTTPs import get_ttp_from_event_ids
from Output import create_output_as_matrix

# The three methods that we are basing on
import Methods.EventList as EventList
import Methods.MITRECti as MITRECti
import Methods.Malware as Malware


Sg.theme('DarkBlue13')
MAX_THREADS = os.cpu_count()*2

# GUI layouts
dirIn_list = [
    [
        Sg.Text("Enter the input directory:\t"),
        Sg.In(size=(40, 1), enable_events=True, key="-FOLDER-IN-"),
        Sg.FolderBrowse(),
    ],

]

dirOut_list = [
    [
        Sg.Text("Enter the output directory:\t"),
        Sg.In(size=(40, 1), enable_events=True, key='-FOLDER-OUT-'),
        Sg.FolderBrowse(),
    ],
]

thread_list = [
    [
        Sg.Text("Number of Threads:\t"),
        Sg.In(size=(3, 1), enable_events=True, key='threads_key', default_text="2"),
        Sg.Text("/  " + str(MAX_THREADS)),
        Sg.Button("Max", key='max_threads'),
    ],
]

button_list = [
    [
        Sg.Button("SCAN", key='Scan_Button'),
        Sg.Exit(),
        Sg.Text("\t\t", key="Status", size=(45, 1), text_color='yellow'),
        Sg.Text("", key="Files", size=(4, 1), text_color='yellow'),
        Sg.Text("", key="Percent", size=(4, 1), text_color='yellow'),
    ]
]

EventList_checkBox = [
    [
        Sg.Checkbox('EventList by Miriam Wiesner\t', key='EventListCB'),
        Sg.Button("Update EventList DB", key='EventList_Update_Button', size=(25, 1)),
        Sg.Text("", key="EventList", size=(15, 1), text_color='yellow')
    ]
]

Malware_Archeology_checkBox = [
    [
        Sg.Checkbox('Malware Archeology\t', key='MalwareArcheologyCB'),
        Sg.Button("Update MalwareArcheology DB", key='MalwareArcheology_Update_Button', size=(25, 1)),
        Sg.Text("", key="Malware", size=(15, 1), text_color='yellow')
    ]
]

MITRE_cti_checkBox = [
    [
        Sg.Checkbox('MITRE/cti\t\t', key='MITRE/ctiCB'),
        Sg.Button("Update MITRE/cti DB", key='MITRE_CTI_Update_Button', size=(25, 1)),
        Sg.Text("", key="MITRE/CTI", size=(15, 1), text_color='yellow')
    ]
]

checkBox_list = [
    [Sg.Column(EventList_checkBox)],
    [Sg.Column(Malware_Archeology_checkBox)],
    [Sg.Column(MITRE_cti_checkBox)]
]

layout = [
    [Sg.Column(dirIn_list)],
    [Sg.Column(dirOut_list)],
    [Sg.Column(thread_list)],
    [Sg.Column(checkBox_list)],
    [Sg.Column(button_list)],
]

original_files = ["EventList", "Malware", "MITRE/CTI"]


# This function disable the update buttons if there no update available.
# method values: (0: EventList, 1: Malware Archeology, 2: MITRE/CTI, 3: all of the methods)
def disable_buttons(method):
    global window
    if method == 0:
        window.FindElement('EventList_Update_Button').Update(disabled=True)
    elif method == 1:
        window.FindElement('MalwareArcheology_Update_Button').Update(disabled=True)
    elif method == 2:
        window.FindElement('MITRE_CTI_Update_Button').Update(disabled=True)
    else:
        window.FindElement('EventList_Update_Button').Update(disabled=True)
        window.FindElement('MalwareArcheology_Update_Button').Update(disabled=True)
        window.FindElement('MITRE_CTI_Update_Button').Update(disabled=True)
    window.Refresh()


# This function enable the update buttons if there is a update available.
# method values: (0: EventList, 1: Malware Archeology, 2: MITRE/CTI)
def enable_button(method):
    global window
    if method == 0:
        window.FindElement('EventList_Update_Button').Update(disabled=False)
    elif method == 1:
        window.FindElement('MalwareArcheology_Update_Button').Update(disabled=False)
    else:
        window.FindElement('MITRE_CTI_Update_Button').Update(disabled=False)


# This function extracts the event ids from the files inside the input folder and then running them on the main hash map and then display the output.
def extract_event_thread(user_ids):
    global window
    start_time = time.time()
    window.FindElement("Status").Update("\t\tParsing the XML files...")
    window.FindElement("Files").Update("0/0")
    window.FindElement("Percent").Update("0%")
    thread_number = int(values['threads_key']) if (0 < int(values['threads_key']) <= MAX_THREADS) else 2
    extract_event_ids(user_ids, values['-FOLDER-IN-'], window, thread_number, extract_thread)
    user_ids = set(user_ids)
    TTPs = get_ttp_from_event_ids(mainHashMap, user_ids)
    """
    print("\nThe user event ids:")
    print(user_ids)
    print("\nThe end result TTPs:")
    print(convert_output(TTPs))
    """
    result_time = (time.time() - start_time)
    window.FindElement("Status").Update("\t\tFinished in " + str("{:.2f}".format(result_time)) + " seconds.")
    window.FindElement('Scan_Button').Update(disabled=False)
    window.Refresh()
    create_output_as_matrix(convert_output(TTPs))
    if values['-FOLDER-OUT-'] != "":
        copy_file_to_out_dir(values['-FOLDER-OUT-'])


# Copy the output file to the output dir
def copy_file_to_out_dir(out_dir):
    cwd = os.getcwd()
    original = r'' + cwd + '\\Mapping_Res_to_MitreAttack.xlsx'
    target = r''+out_dir + '/Mapping_Res_to_MitreAttack.xlsx'
    shutil.copyfile(original, target)


# This function check if there is an update
def update_checker():
    try:
        # Check if there is an internet connection
        if urllib.request.urlopen('https://www.google.com/', timeout=2):
            for j in range(0, 3):
                window.FindElement(original_files[j]).Update("Checking for update...")
                if check_for_update(j):
                    enable_button(j)
                    window.FindElement(original_files[j]).Update("Expired", text_color='red')
                else:
                    window.FindElement(original_files[j]).Update("Up to Date: " + str(datetime.now().strftime("%d/%m/%y")), text_color="white")
        else:
            Sg.popup_notify("No internet Connection, Couldn't check for updates.", title="Warning")
    except Exception as e:
        print(e)
        for j in range(0, 3):
            window.FindElement(original_files[j]).Update("Update Error")


# Method values: (0: EventList, 1: Malware Archeology, 2: MITRE/CTI)
def check_for_update(method):
    if method == 0:
        return EventList.check_for_update()
    elif method == 1:
        return Malware.check_for_update()
    else:
        return MITRECti.check_for_update()


def update_event_list_db():
    EventList.update_event_list_db()
    window.FindElement(original_files[0]).Update(
        "Up to Date: " + str(datetime.now().strftime("%d/%m/%y")), text_color="white")


def update_malware_db():
    Malware.get_malware_hash_map()
    window.FindElement(original_files[1]).Update(
        "Up to Date: " + str(datetime.now().strftime("%d/%m/%y")), text_color="white")


def update_mitre_cti_db():
    MITRECti.save_mitre_cti_to_db()
    window.FindElement(original_files[2]).Update(
        "Up to Date: " + str(datetime.now().strftime("%d/%m/%y")), text_color="white")


window = Sg.Window("TTP Detection", layout).Finalize()
extract_thread = threading.Thread()

disable_buttons(3)
check_update_thread = threading.Thread(target=update_checker)
check_update_thread.start()


# Change the end result form
def convert_output(list_):
    newList = []

    for item in list_:
        if len(item) > 1 and item[0] != 'T':
            item = item.split("'")
            for x in item:
                if ("[" not in x) and ("]" not in x) and ("'" not in x) and ("," not in x):
                    newList.append(x)
        else:
            newList.append(item)
    return set(newList)


def terminate_thread(thread):
    global stopped
    if not thread.is_alive():
        return
    exc = ctypes.py_object(SystemExit)
    res = ctypes.pythonapi.PyThreadState_SetAsyncExc(
        ctypes.c_long(thread.ident), exc)
    stopped = True
    if res == 0:
        raise ValueError("nonexistent thread id")
    elif res > 1:
        ctypes.pythonapi.PyThreadState_SetAsyncExc(thread.ident, None)
        raise SystemError("PyThreadState_SetAsyncExc failed")


# The GUI
while True:
    event, values = window.read()
    stopped = False
    # close the program if the user closes the window or click on the Exit button
    if event in (None, 'Exit'):
        terminate_thread(check_update_thread)
        terminate_thread(extract_thread)
        terminate_threads()
        break
    if event == 'Scan_Button':
        checkBoxes = [False] * 3
        if window.FindElement('EventListCB').Get():
            checkBoxes[0] = True
        if window.FindElement('MalwareArcheologyCB').Get():
            checkBoxes[1] = True
        if window.FindElement('MITRE/ctiCB').Get():
            checkBoxes[2] = True
        # making sure that the input folder is not empty
        if values['-FOLDER-IN-'] == "":
            Sg.popup_ok("Input Error", "Please browse and specify the directory of the windows logs.")
        # checking if any of the check boxes are checked
        elif True in checkBoxes:
            # creating a main hash map based on the selection of the user
            mainHashMap = {}
            if checkBoxes[0]:
                merge_hash_maps(mainHashMap, EventList.get_event_list_hash_map())
            if checkBoxes[1]:
                merge_hash_maps(mainHashMap, Malware.get_malware_archaeology_hashmap_from_db())
            if checkBoxes[2]:
                merge_hash_maps(mainHashMap, MITRECti.get_mitre_cti_hash_map_from_db())

            window.FindElement('Scan_Button').Update(disabled=True)
            # Extracting the event ids from the files inside the input folder and then running them on the main hash map.
            user_event_ids = []
            extract_thread = threading.Thread(target=extract_event_thread, args=(user_event_ids,))
            extract_thread.start()

        else:
            Sg.popup_ok("Selection Error", "please select at least one check box method.")

        # Resetting the check boxes to False.
        checkBoxes = False * 3

    elif event == 'EventList_Update_Button':
        event_thread = threading.Thread(target=update_event_list_db)
        event_thread.start()
        window.FindElement(original_files[0]).Update("Updating...", text_color='yellow')
        disable_buttons(0)

    elif event == 'MalwareArcheology_Update_Button':
        malware_thread = threading.Thread(target=update_malware_db)
        malware_thread.start()
        window.FindElement(original_files[1]).Update("Updating...", text_color='yellow')
        disable_buttons(1)

    elif event == 'MITRE_CTI_Update_Button':
        mitre_thread = threading.Thread(target=update_mitre_cti_db)
        mitre_thread.start()
        window.FindElement(original_files[2]).Update("Updating...", text_color='yellow')
        disable_buttons(2)
    elif event == 'max_threads':
        window.FindElement("threads_key").Update(str(MAX_THREADS))

window.close()
