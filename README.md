# MITRE-ATTACK-Framework-Evaluation
A system to evaluate the implementation of MITRE ATT&amp;CK framework using a given set of logs.

## How to Run:
1. Download & Install PyCharm : https://www.jetbrains.com/pycharm/download
2. In PyCharm : File -> Open -> Select the project folder.
3. Install the packages inside the file "requirmenets.txt".
4. Run GUI.py.

## How to use:
1. Select the input folder (a folder that contains at least one XML file of you windows event logs).
2. Select the checkboxes that you want to use to analys your windows event logs (you can select between one methods to three methods - it will merge the output of the selected methods).
3. Click on 'Scan' to get the MITRE ATT&amp;CK Tactics, Techniques, and Procedures (TTP).

#### Optional:
1. Select the Output folder to decide where the output .xlsx file will be saved (default - current project directory).
2. Thread Pool - Select the number of threads that will extract your windows event logs XML files (Max = number of CPU * 2).
3. Update - In case there is an Update available, the update button will be enabled, then you can decide if you want to download the new file available by one of the mehods.


## How to export windows event logs XML:
1. Open Event Viewer (Click Start > Control Panel > System and Security > Administrative Tools. Double-click Event Viewer).
2. On the left window select 'Windows Logs' folder -> Security.
3. Then on the right windows select 'Save All Events As...' then type a name and select as XML file. 


