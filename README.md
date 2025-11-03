# CyberArk Quick Commands Reference

## COMMON
- **Type 0** - Verify current .NET version on this machine  
- **Type 9** - GET status of all CyberArk services on this server  
- **Type 990** - Import certificate to the server  
- **Type 991** - Show CyberArk Application logs in past 24 hours  
- **Type 993** - Set/unset proxy server using registry  
- **Type 994** - Copy files from `\\tsclient\z\`  
- **Type 995** - Test connectivity to any IP  
- **Type 996** - Open hosts file in Notepad as admin  
- **Type 997** - Allow using cached credentials upon RDP connection  
- **Type 999** - Enable/disable/check clipboard and drive mapping in regedit  
- **Type 1000** - RESTART ALL CyberArk services on this server  
- **Type 1001** - START ALL CyberArk services on this server  
- **Type 1002** - STOP ALL CyberArk services on this server  

---

## Vault
- **Type 1** - Open `dbparm.ini` in Notepad  
- **Type 111** - Open `padr.ini` in Notepad  
- **Type 2** - Open `tsparm.ini` in Notepad  
- **Type 3** - Tail `padr.log` (in new window)  
- **Type 4** - Tail `italog` (in new window)  
- **Type 5** - Open `\server\conf`  
- **Type 6** - Open `\server\logs`  
- **Type 7** - Open `\padr\conf`  
- **Type 8** - Open `\padr\logs`  
- **Type 01** - Collect vault logs (`cavaultmanager collectlogs`)

---

## PSM (Privileged Session Manager)
- **Type 10** - Open PSM Components folder  
- **Type 11** - Open PSM Logs folder  
- **Type 12** - Get PSM last connection component log  
- **Type 13** - Tail PSM logs  
- **Type 14** - Open `PSMConfigureAppLocker.xml` in Notepad  
- **Type 15** - RUN `PSMConfigureAppLocker.ps1`  
- **Type 16** - GET Windows App Locker error logs  
- **Type 17** - GET Windows App Locker logs (ALL unfiltered)  
- **Type 18** - Upgrade PSM  
- **Type 19** - Get user logs PSM (choose user in next step)  
- **Type 20** - Get PSM last connection component dispatcher log  
- **Type 21** - Get PSM last connection component dispatcher log (INFO only)  
- **Type 22** - Get PSM last connection component dispatcher log (trace)  
- **Type 23** - GET Windows App Locker logs for specific user (choose user in next step)  
- **Type 24** - GET ALL Windows logs for specific user (choose user in next step)  
- **Type 25** - Identify `PSM-XYZ12345678` user by name  
- **Type 26** - Schedule PSM reboot when nobody is connected  
- **Type 27** - Schedule PSM service stop when nobody is connected

---

## CPM (Central Policy Manager)
- **Type 30** - Open CPM bin folder  
- **Type 31** - Open CPM Logs folder  
- **Type 32** - Tail `PMTrace.log` (in new window)  
- **Type 33** - Tail `pm_error.log` (in new window)  
- **Type 34** - Tail `Casos.Debug.log` (in new window)  
- **Type 35** - Tail `Casos.Error.log` (in new window)  

---

## PVWA (Privileged Vault Web Access)
- **Type 40** - Analyze `w3svc1` logs (more choices in next step)  
- **Type 41** - Analyze `CyberArk.WebConsole.log` (more choices in next step)  
- **Type 42** - Analyze `PVWA.App.log` (more choices in next step)  
- **Type 43** - Analyze `PVWA.Console.log` (more choices in next step)  
- **Type 44** - Analyze `PVWA.Reports.log` (more choices in next step)  
- **Type 45** - Analyze all PVWA logs at once (more choices in next step)  
- **Type 46** - Open PVWA Logs folder  
- **Type 47** - Open PVWA Conf folder  
- **Type 48** - Open IIS Logs folder  
- **Type 49** - RESTART IIS  
