# MITRE-ATTACK-Framework-Evaluation
A system to evaluate the implementation of MITRE ATT&amp;CK framework using a given set of logs.

## Created by:
####Kfir Ram
####Shir Bar
####Hen Dahan

## How to Run:
1. Download & Install PyCharm : https://www.jetbrains.com/pycharm/download
2. In PyCharm : File > Open > Select the project folder.
3. Install Virtual Environment:
###### Option 1 - Automatically by pycharm: 
  ![Creating Virtual Environment](https://user-images.githubusercontent.com/45327886/124458349-866ba800-dd95-11eb-86dd-8c9265634410.png)
  
###### Option 2 - Manual:
  * CTRL+ALT+S > Project: [project name] > Python Interpreter > click on the setting icon on the top right > add > OK
  ####
  ![image](https://user-images.githubusercontent.com/45327886/124458680-efebb680-dd95-11eb-9a6c-e97fb2278cab.png)
  ####
  * Install the packages inside the file "requirmenets.txt".
  ####
  ![requirmenets.txt](https://user-images.githubusercontent.com/45327886/124458988-57096b00-dd96-11eb-9310-ea5eb4221ac2.png)

4. Right click on GUI.py > Run 'GUI'.

## How to use:
1. Select the input folder (a folder that contains at least one XML file of you windows event logs).
2. Select the checkboxes that you want to use to analys your windows event logs (you can select between one methods to three methods - it will merge the output of the selected methods).
3. Click on 'Scan' to get the MITRE ATT&amp;CK Tactics, Techniques, and Procedures (TTP).

#### Optional:
1. Select the Output folder to decide where the output .xlsx file will be saved (default - current project directory).
2. Thread Pool - Select the number of threads that will extract your windows event logs XML files (Max = number of CPUs * 2).
3. Update - In case there is an Update available, the update button will be enabled, then you can decide if you want to download the new file available by one of the mehods.
4. Util/windows-event-ids.txt - this file contains the title of each event id seperated by two \t [tabs] - when running the MITRE/CTI checkbox, it loads the titles and search for special words from the title inside the mitre/cti detection section (in case of an update, make sure it is seperated by two \t [tabs] between the 'windows', '[event-id]' and the [title of the event id]).


## How to export windows event logs XML:
1. Open Event Viewer (Click Start > Control Panel > System and Security > Administrative Tools. Double-click Event Viewer).
2. On the left window select 'Windows Logs' folder > Security.
####
![Windows Logs > Security](https://user-images.githubusercontent.com/45327886/124449335-07be3d00-dd8c-11eb-901b-56155c4d515c.png)
####
3. On the right windows select 'Save All Events As...', type a name and select as an XML file. 
####
![Save All Events As...](https://user-images.githubusercontent.com/45327886/124449242-ea896e80-dd8b-11eb-9d91-5a0b9a6ed44f.png)

####
####
####

## Pictures of The System:

![The GUI](https://user-images.githubusercontent.com/45327886/124459162-89b36380-dd96-11eb-8e0f-58a1a1fa6755.png)

![Extracting Event IDs from the XML files](https://user-images.githubusercontent.com/45327886/124459441-cb440e80-dd96-11eb-9880-53fab08df932.png)

![Quick Output](https://user-images.githubusercontent.com/45327886/124459543-e9117380-dd96-11eb-8235-b1f39930e73e.png)

![Output as an .xlsx file](https://user-images.githubusercontent.com/45327886/124459695-165e2180-dd97-11eb-9155-26c723d6aa5c.png)
