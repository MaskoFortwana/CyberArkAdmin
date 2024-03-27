# CyberArkAdmin
powershell script that makes troubleshooting CyberArk servers a lot easier, more effective and faster. Just run the script and make your choice, you will surely finde useful options here.


Currently supported functions:

------------COMMON--------------
Type 0 verify current .net version on this machine
Type 9 to GET status of all CyberArk services on this server
Type 994 to copy files from \\tsclient\z\
Type 995 to test connectivity to any IP
Type 996 to open hosts file in notepad as admin
Type 990 to RESTART ALL CyberArk services on this server
Type 998 to STOP ALL CyberArk services on this server
Type 997 to START ALL CyberArk services on this server
-------Vault Operations---------
Type 1 to open dbparm.ini in notepad
Type 2 to open tsparm.ini in notepad
Type 3 to tail padr.log (in new window)
Type 4 to tail italog (in new window)
Type 5 to open \server\conf
Type 6 to open \server\logs
Type 7 to open \padr\conf
Type 8 to open \padr\logs
Type 01 to collect vault logs (cavaultmanager collectlogs)
-------------PSM----------------
Type 10 to open PSM Components folder
Type 11 to open PSM Logs folder
Type 12 to get PSM last connection component log
Type 13 to tail PSM logs
Type 14 to open PSMConfigureAppLocker.xml in notepad
Type 15 to RUN PSMConfigureAppLocker.ps1
Type 16 to GET Windows App Locker error logs
Type 17 to GET Windows App Locker logs - ALL unfiltered
Type 18 to Upgrade PSM
Type 19 to Get user logs PSM (choose user in next step)
Type 20 to get PSM last connection component dispatcher log
Type 21 to get PSM last connection component dispatcher log INFO only
Type 22 to get PSM last connection component dispatcher log trace
Type 23 to GET Windows App Locker logs for specific user (choose user in next step)
Type 24 to GET ALL Windows logs for specific user (choose user in next step)
-------------CPM----------------
Type 30 to open CPM bin folder
Type 31 to open CPM Logs folder
Type 32 to tail PMTrace.log in new window
Type 33 to tail pm_error.log in new window
Type 34 to tail Casos.Debug.log in new window
Type 34 to tail Casos.Error.log in new window
-------------PVWA---------------
--------------------------------

Type the number and press enter...
