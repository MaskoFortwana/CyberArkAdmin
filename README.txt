# CyberArkAdmin
powershell script that makes troubleshooting CyberArk servers a lot easier, more effective and faster. Just run the script and make your choice, you will surely find useful options here.

## requirements: to make sure every function works as suposed to, create folders c:\install and c:\scripts on your windows. Otherwise some functions will not work.


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
-------------Vault--------------
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
Type 25 to identify PSM-XYZ12345678 user by name
-------------CPM----------------
Type 30 to open CPM bin folder
Type 31 to open CPM Logs folder
Type 32 to tail PMTrace.log in new window
Type 33 to tail pm_error.log in new window
Type 34 to tail Casos.Debug.log in new window
Type 34 to tail Casos.Error.log in new window
-------------PVWA---------------
Type 40 to analyze w3svc1 logs (more choices in next step)
Type 41 to analyze CyberArk.WebConsole.log (more choices in next step)
Type 42 to analyze PVWA.App.log (more choices in next step)
Type 43 to analyze PVWA.Console.log (more choices in next step)
Type 44 to analyze PVWA.Reports.log logs (more choices in next step)
Type 45 to analyze all PVWA logs at once (more choices in next step)
Type 46 to open PVWA Logs folder
Type 47 to open PVWA Conf folder
Type 48 to open IIS Logs folder
Type 49 to open RESTART IIS
--------------------------------

Type the number and press enter...
