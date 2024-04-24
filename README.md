# CyberArk Command Guide

This guide provides a list of commands for managing and troubleshooting CyberArk services.

## General Commands

- `994`: Copy files from `\\tsclient\z\`
- `995`: Test connectivity to any IP
- `996`: Open hosts file in notepad as admin
- `990`: Restart all CyberArk services on this server
- `998`: Stop all CyberArk services on this server
- `997`: Start all CyberArk services on this server

## Vault Commands

- `1`: Open `dbparm.ini` in notepad
- `2`: Open `tsparm.ini` in notepad
- `3`: Tail `padr.log` (in new window)
- `4`: Tail `italog` (in new window)
- `5`: Open `\server\conf`
- `6`: Open `\server\logs`
- `7`: Open `\padr\conf`
- `8`: Open `\padr\logs`
- `01`: Collect vault logs (`cavaultmanager collectlogs`)

## PSM Commands

- `10`: Open PSM Components folder
- `11`: Open PSM Logs folder
- `12`: Get PSM last connection component log
- `13`: Tail PSM logs
- `14`: Open `PSMConfigureAppLocker.xml` in notepad
- `15`: Run `PSMConfigureAppLocker.ps1`
- `16`: Get Windows App Locker error logs
- `17`: Get Windows App Locker logs - All unfiltered
- `18`: Upgrade PSM
- `19`: Get user logs PSM (choose user in next step)
- `20`: Get PSM last connection component dispatcher log
- `21`: Get PSM last connection component dispatcher log INFO only
- `22`: Get PSM last connection component dispatcher log trace
- `23`: Get Windows App Locker logs for specific user (choose user in next step)
- `24`: Get all Windows logs for specific user (choose user in next step)
- `25`: Identify PSM-XYZ12345678 user by name

## CPM Commands

- `30`: Open CPM bin folder
- `31`: Open CPM Logs folder
- `32`: Tail `PMTrace.log` in new window
- `33`: Tail `pm_error.log` in new window
- `34`: Tail `Casos.Debug.log` in new window
- `34`: Tail `Casos.Error.log` in new window

## PVWA Commands

- `40`: Analyze `w3svc1` logs (more choices in next step)
- `41`: Analyze `CyberArk.WebConsole.log` (more choices in next step)
- `42`: Analyze `PVWA.App.log` (more choices in next step)
- `43`: Analyze `PVWA.Console.log` (more choices in next step)
- `44`: Analyze `PVWA.Reports.log` logs (more choices in next step)
- `45`: Analyze all PVWA logs at once (more choices in next step)
- `46`: Open PVWA Logs folder
- `47`: Open PVWA Conf folder
- `48`: Open IIS Logs folder
- `49`: Restart IIS

To use these commands, type the number and press enter.