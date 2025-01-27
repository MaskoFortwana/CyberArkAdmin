# Introduction and Menu Display
function Display-Menu {
    cls
    Write-Host -ForegroundColor Yellow "                        
                              ,(#%.                                     
                          ((((((#%%%%%(                                 
                      ((((((((((#%%%%%%%%%%                             
                  ((((((((((((((#%%%%%%%%%%%%%%                         
              ((((((((((((((((((#%%%%%%%%%%%%%%%%%%                     
          ((((((((((((((((((((((#%%%%%%%%%%%%%%%%%%%%%%.                
     *((((((((((((((((((((((((((#%%%%%%%%%%%%%%%%%%%%%%%%%%#            
 (((((((((((((((((((((((((((((((%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%        
 %%%%((((((((((((((((((((((((###/***#%%%%%%%%%%%%%%%%%%%%%%(            
 %%%%%%%%(((((((((((((((########/*******/%%%%%%%%%%%%%%.                
 %%%%%%%%%%%%(((((((############/************%%%%%%                     
 %%%%%%%%%%%%%%%%###############/***************                        
 %%%%%%%%%%%%%%%%###############/***************                        
 %%%%%%%%%%%%%%%%###############/***************                        
 %%%%%%%%%%%%%%%%###############/***************                        
 %%%%%%%%%%%%%%%%############       ************           #%%%%        
 %%%%%%%%%%%%%%%%#######.                *******       %%%%%%%%%        
 %%%%%%%%%%%%%%%%###                         .**  /%%%%%%%%%%%%%        
 %%%%%%%%%%%%%%%((                            %%%%%%%%%%%%%%%%%%        
 %%%%%%%%%%#(((((((((((                  .%%%%%%%%%%%%%%%%%%%%%%        
 %%%%%%((((((((((((((((((((          %%%%%%%%%%%%%%%%%%%%%%%%%%%        
 %%((((((((((((((((((((((((((((( %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%        
   (((((((((((((((((((((((((((((#%%%%%%%%%%%%%%%%%%%%%%%%%%%#           
        ((((((((((((((((((((((((#%%%%%%%%%%%%%%%%%%%%%%%                
            /(((((((((((((((((((#%%%%%%%%%%%%%%%%%%%                    
                 (((((((((((((((#%%%%%%%%%%%%%%,                        
                     ,((((((((((#%%%%%%%%%%                             
                          ((((((#%%%%%#                                 
                              .(#%"
    Write-Host ' '                                                     
    Write-Host -ForegroundColor Red 'Welcome to CyberArk admin script, choose one of the options below'
    Write-Host ' '
    Write-Host "------------COMMON--------------" -ForegroundColor White
    Write-Host -ForegroundColor Green 'Type 0 verify current .net version on this machine'
    Write-Host -ForegroundColor Yellow 'Type 9 to GET status of all CyberArk services on this server'
    Write-Host -ForegroundColor Green 'Type 993 to set/unset proxy server using registry'
    Write-Host -ForegroundColor Yellow 'Type 994 to copy files from \\tsclient\z\'
    Write-Host -ForegroundColor Green 'Type 995 to test connectivity to any IP'
    Write-Host -ForegroundColor Yellow 'Type 996 to open hosts file in notepad as admin'
    Write-Host -ForegroundColor Green 'Type 997 to allow using cached credentials upon RDP connection'
    Write-Host -ForegroundColor Yellow 'Type 999 to enable/disable/check clipboard and drive mapping in regedit'
    Write-Host -ForegroundColor Red 'Type 1000 to RESTART ALL CyberArk services on this server'
    Write-Host -ForegroundColor Red 'Type 1001 to START ALL CyberArk services on this server'
    Write-Host -ForegroundColor Red 'Type 1002 to STOP ALL CyberArk services on this server'
    Write-Host "-------------Vault--------------" -ForegroundColor White
    Write-Host -ForegroundColor Green 'Type 1 to open dbparm.ini in notepad'
    Write-Host -ForegroundColor Yellow 'Type 2 to open tsparm.ini in notepad'
    Write-Host -ForegroundColor Green 'Type 3 to tail padr.log (in new window)'
    Write-Host -ForegroundColor Yellow 'Type 4 to tail italog (in new window)'
    Write-Host -ForegroundColor Green 'Type 5 to open \server\conf'
    Write-Host -ForegroundColor Yellow 'Type 6 to open \server\logs'
    Write-Host -ForegroundColor Green 'Type 7 to open \padr\conf'
    Write-Host -ForegroundColor Yellow 'Type 8 to open \padr\logs'
    Write-Host -ForegroundColor Green 'Type 01 to collect vault logs (cavaultmanager collectlogs)'
    Write-Host "-------------PSM----------------" -ForegroundColor White
    Write-Host -ForegroundColor Green 'Type 10 to open PSM Components folder'
    Write-Host -ForegroundColor Yellow 'Type 11 to open PSM Logs folder'
    Write-Host -ForegroundColor Green 'Type 12 to get PSM last connection component log'
    Write-Host -ForegroundColor Yellow 'Type 13 to tail PSM logs'
    Write-Host -ForegroundColor Green 'Type 14 to open PSMConfigureAppLocker.xml in notepad'
    Write-Host -ForegroundColor Yellow 'Type 15 to RUN PSMConfigureAppLocker.ps1'
    Write-Host -ForegroundColor Green 'Type 16 to GET Windows App Locker error logs'
    Write-Host -ForegroundColor Yellow 'Type 17 to GET Windows App Locker logs - ALL unfiltered'
    Write-Host -ForegroundColor Green 'Type 18 to Upgrade PSM'
    Write-Host -ForegroundColor Yellow 'Type 19 to Get user logs PSM (choose user in next step)'
    Write-Host -ForegroundColor Green 'Type 20 to get PSM last connection component dispatcher log'
    Write-Host -ForegroundColor Yellow 'Type 21 to get PSM last connection component dispatcher log INFO only'
    Write-Host -ForegroundColor Green 'Type 22 to get PSM last connection component dispatcher log trace'
    Write-Host -ForegroundColor Yellow 'Type 23 to GET Windows App Locker logs for specific user (choose user in next step)'
    Write-Host -ForegroundColor Green 'Type 24 to GET ALL Windows logs for specific user (choose user in next step)'
    Write-Host -ForegroundColor Yellow 'Type 25 to identify PSM-XYZ12345678 user by name'
    Write-Host "-------------CPM----------------" -ForegroundColor White
    Write-Host -ForegroundColor Green 'Type 30 to open CPM bin folder'
    Write-Host -ForegroundColor Yellow 'Type 31 to open CPM Logs folder'
    Write-Host -ForegroundColor Green 'Type 32 to tail PMTrace.log in new window'
    Write-Host -ForegroundColor Yellow 'Type 33 to tail pm_error.log in new window'
    Write-Host -ForegroundColor Green 'Type 34 to tail Casos.Debug.log in new window'
    Write-Host -ForegroundColor Yellow 'Type 34 to tail Casos.Error.log in new window'
    Write-Host "-------------PVWA---------------" -ForegroundColor White
    Write-Host -ForegroundColor Green 'Type 40 to analyze w3svc1 logs (more choices in next step)'
    Write-Host -ForegroundColor Yellow 'Type 41 to analyze CyberArk.WebConsole.log (more choices in next step)'
    Write-Host -ForegroundColor Green 'Type 42 to analyze PVWA.App.log (more choices in next step)'
    Write-Host -ForegroundColor Yellow 'Type 43 to analyze PVWA.Console.log (more choices in next step)'
    Write-Host -ForegroundColor Green 'Type 44 to analyze PVWA.Reports.log logs (more choices in next step)'
    Write-Host -ForegroundColor Yellow 'Type 45 to analyze all PVWA logs at once (more choices in next step)'
    Write-Host -ForegroundColor Green 'Type 46 to open PVWA Logs folder'
    Write-Host -ForegroundColor Yellow 'Type 47 to open PVWA Conf folder'
    Write-Host -ForegroundColor Green 'Type 48 to open IIS Logs folder'
    Write-Host -ForegroundColor Red 'Type 49 to RESTART IIS'
    Write-Host "--------------------------------" -ForegroundColor White
    Write-Host ' '
}

# Define the registry path for Internet Settings
function Set-ProxyServer {
    $regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings"

    # Check current proxy settings
    $currentProxyEnable = (Get-ItemProperty -Path $regPath -Name ProxyEnable -ErrorAction SilentlyContinue).ProxyEnable
    $currentProxyServer = (Get-ItemProperty -Path $regPath -Name ProxyServer -ErrorAction SilentlyContinue).ProxyServer

    # Output current settings
    if ($currentProxyEnable -eq 1) {
        Write-Host "Current proxy settings are enabled."
        Write-Host "Proxy server: $currentProxyServer"
    } else {
        Write-Host "Proxy settings are currently disabled."
    }

    # Ask user for desired action
    $action = Read-Host "Do you want to set up a proxy server or clear current settings? (Enter 'set' or 'clear')"

    if ($action -eq "set") {
        # Ask user for proxy server and port
        $proxyIP = Read-Host "Enter the proxy server IP"
        $proxyPort = Read-Host "Enter the proxy server port"
        $proxyServer = "$($proxyIP):$($proxyPort)"  # Corrected line using subexpression

        # Set the proxy server
        Set-ItemProperty -Path $regPath -Name ProxyEnable -Value 1
        Set-ItemProperty -Path $regPath -Name ProxyServer -Value $proxyServer

        Write-Host "Proxy server has been set to $proxyServer."
    } elseif ($action -eq "clear") {
        # Clear the proxy settings
        Set-ItemProperty -Path $regPath -Name ProxyEnable -Value 0
        Remove-ItemProperty -Path $regPath -Name ProxyServer -ErrorAction SilentlyContinue

        Write-Host "Proxy settings have been cleared."
    } else {
        Write-Host "Invalid choice. Please run the script again and choose 'set' or 'clear'."
    }
}

# Function to check .NET version
function Get-DotNetVersions {
    Write-Host -ForegroundColor Yellow "Fetching .NET Framework versions..."
    Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP' -Recurse |
    Get-ItemProperty -Name version -ErrorAction SilentlyContinue |
    Where-Object { $_.PSChildName -Match '^(?!S)\p{L}'} |
    Select-Object PSChildName, version |
    ForEach-Object {
        Write-Host "$($_.PSChildName): $($_.version)" -ForegroundColor Green
    }
}

function Open-DbParm {
    Write-Host -ForegroundColor Yellow "Opening dbparm.ini with Notepad"
    Start-Process notepad.exe -ArgumentList 'C:\Program Files (x86)\PrivateArk\Server\Conf\dbparm.ini'
}

function Open-TsParm {
    Write-Host -ForegroundColor Yellow "Opening tsparm.ini with Notepad"
    Start-Process notepad.exe -ArgumentList 'C:\Program Files (x86)\PrivateArk\Server\Conf\tsparm.ini'
}

function Tail-PadrLog {
    Write-Host -ForegroundColor Yellow "Tailing padr.log"
    Invoke-Expression 'cmd /c start powershell -Command { Get-Content "C:\Program Files (x86)\PrivateArk\PADR\Logs\padr.log" -Wait -Tail 200 }'
}

function Tail-ItaLog {
    Write-Host -ForegroundColor Yellow "Tailing italog.log"
    Invoke-Expression 'cmd /c start powershell -Command { Get-Content "C:\Program Files (x86)\PrivateArk\Server\Logs\italog.log" -Wait -Tail 200 }'
}

function Get-CyberArkServicesStatus {
    Write-Host -ForegroundColor Yellow "Getting CyberArk services status"
    Get-Service *ark* | Select-Object Name, StartType, Status
}

function Open-ServerConf {
    Write-Host -ForegroundColor Yellow "Opening Server Conf Folder"
    Invoke-Item "C:\Program Files (x86)\PrivateArk\Server\Conf\"
}

function Open-ServerLogs {
    Write-Host -ForegroundColor Yellow "Opening Server Logs Folder"
    Invoke-Item "C:\Program Files (x86)\PrivateArk\Server\Logs\"
}

function Open-PadrConf {
    Write-Host -ForegroundColor Yellow "Opening PADR Conf Folder"
    Invoke-Item "C:\Program Files (x86)\PrivateArk\PADR\Conf\"
}

function Open-PadrLogs {
    Write-Host -ForegroundColor Yellow "Opening PADR Logs Folder"
    Invoke-Item "C:\Program Files (x86)\PrivateArk\PADR\Logs\"
}

function Open-PSMComponents {
    Write-Host -ForegroundColor Yellow "Opening PSM Components Folder"
    Invoke-Item "C:\Program Files (x86)\CyberArk\PSM\Components"
}

function Open-PSMLogs {
    Write-Host -ForegroundColor Yellow "Opening PSM Logs Folder"
    Invoke-Item "C:\Program Files (x86)\CyberArk\PSM\Logs"
}

function Get-LastPSMComponentLog {
    Write-Host -ForegroundColor Yellow "Fetching the last PSM component log..."
    $lastLog = Get-ChildItem 'C:\Program Files (x86)\CyberArk\PSM\Logs\Components\' | Sort-Object LastWriteTime | Select-Object -Last 1 | Select-Object Name
    $name = $lastLog.Name
    $logs = $name.Substring(0, [Math]::Min($name.Length, 8))
    Write-Host "These are logs from the last CyberArk session - unfiltered" -ForegroundColor Green
    Get-Content "C:\Program Files (x86)\CyberArk\PSM\Logs\Components\$logs*.*"
    Write-Host "These are logs from the last CyberArk session - filtered for Dispatcher trace messages" -ForegroundColor Green
    Get-Content "C:\Program Files (x86)\CyberArk\PSM\Logs\Components\$logs*.*" | Select-String -Pattern "Dispatcher trace message"
}

function Tail-PSMTraceLog {
    Write-Host -ForegroundColor Yellow "Tailing PSMTrace.log"
    Invoke-Expression 'cmd /c start powershell -Command { Get-Content "C:\Program Files (x86)\CyberArk\PSM\Logs\PSMTrace.log" -Wait -Tail 200 }'
}

function Open-PSMConfigureAppLockerXml {
    Write-Host -ForegroundColor Yellow "Opening PSMConfigureAppLocker.xml with Notepad"
    Start-Process notepad.exe -ArgumentList 'C:\Program Files (x86)\CyberArk\PSM\Hardening\PSMConfigureAppLocker.xml'
}

function Run-PSMConfigureAppLocker {
    Write-Host -ForegroundColor Yellow "Running PSMConfigureAppLocker.ps1"
    Set-Location 'C:\Program Files (x86)\CyberArk\PSM\Hardening\'

    # Check CyberArk version
    $version = (Get-Item "C:\Program Files (x86)\CyberArk\PSM\CAPSM.exe").VersionInfo.ProductVersion.Split('.')[0]
    if ([int]$version -lt 14) {
        Write-Host -ForegroundColor Yellow "Version check: CyberArk version is lower than 14. Running the applocker the old way..."
        Write-Host -ForegroundColor Yellow "Command preview: .\PSMConfigureAppLocker.ps1"
        Write-Host "CyberArk version is lower than 14, may I run the applocker the old way? - If you are using PSMConnect and PSMAdminConnect in domain, it needs to be configured in PSMConfigureAppLocker.ps1 script. (Y/N)"
        $confirmation = Read-Host
        if ($confirmation -ne 'Y') {
            Write-Host "Aborting..."
            return
        }
        .\PSMConfigureAppLocker.ps1
        Set-Location C:\scripts\
        return
    }
    elseif ([int]$version -ge 14) {
        Write-Host -ForegroundColor Yellow "Version check: CyberArk version is higher than 14. Running the applocker the new way..."
    }

    # Get the hostname
    $hostname = $env:COMPUTERNAME
    
    # Check if the users exist in the Remote Desktop Users group
    $rdUsers = Get-LocalGroupMember -Group "Remote Desktop Users" | Select-Object -ExpandProperty Name
    $domainUserPattern = '^(.+?)\\(PSMConnect|PSMAdminConnect)$'
    $plainUserPattern = '^(PSMConnect|PSMAdminConnect)$'
    $hostnameUserPattern = "^$hostname\\(PSMConnect|PSMAdminConnect)$"

    # Collect domain users and their corresponding prefixes
    $domainUserMatches = $rdUsers | Where-Object { $_ -match $domainUserPattern }
    $domainUsers = $domainUserMatches | ForEach-Object { $_ -replace $domainUserPattern, '$2' } | Select-Object -Unique
    $domainPrefixes = $domainUserMatches | ForEach-Object { $_ -replace $domainUserPattern, '$1' } | Where-Object { $_ -ne $hostname } | Select-Object -Unique

    if ($domainUsers.Count -gt 0 -and $domainPrefixes.Count -gt 0) {
        $uniqueDomainPrefix = $domainPrefixes # Take the first unique domain prefix
        Write-Host -ForegroundColor Yellow "Command preview: .\PSMConfigureAppLocker.ps1 -connectionUserName PSMConnect -connectionUserDomain $uniqueDomainPrefix -connectionAdminUserName PSMAdminConnect -connectionAdminUserDomain $uniqueDomainPrefix"
        Write-Host "Found domain users: $($domainUsers -join ', ') with domain prefix: $uniqueDomainPrefix. Do you want to continue - run applocker using domain users? (Y/N)"
        $confirmation = Read-Host
        if ($confirmation -ne 'Y') {
            Write-Host "Aborting..."
            return
        }
        .\PSMConfigureAppLocker.ps1 -connectionUserName PSMConnect -connectionUserDomain $uniqueDomainPrefix -connectionAdminUserName PSMAdminConnect -connectionAdminUserDomain $uniqueDomainPrefix
    } elseif ($rdUsers | Where-Object { $_ -match $plainUserPattern -or $_ -match $hostnameUserPattern }) {
        Write-Host -ForegroundColor Yellow "Command preview: .\PSMConfigureAppLocker.ps1"
        Write-Host "Found local PSMConnect and PSMAdminConnect users. Do you want to continue - run applocker using local users? (Y/N)"
        $confirmation = Read-Host
        if ($confirmation -ne 'Y') {
            Write-Host "Aborting..."
            return
        }
        .\PSMConfigureAppLocker.ps1
    } else {
        Write-Host "No users found. Aborting..."
        return
    }

    Set-Location C:\scripts\
}

function Get-NonInfoAppLockerLogs {
    Write-Host -ForegroundColor Yellow "Getting non-informational AppLocker Logs"
    $properties = @(
        'TimeCreated',
        'Message',
        @{n='UserName';e={$_.Properties[7].Value}}
    )
    Get-WinEvent -LogName 'Microsoft-Windows-AppLocker/EXE and DLL' | Where-Object {$_.LevelDisplayName -ne 'Information'} | Select-Object $properties
    Start-Sleep -s 2 | Out-Null
    Write-Host -ForegroundColor Green "Run command below to identify users SIDs"
    Write-Host -ForegroundColor Green "Get-LocalUser | Select-Object Name,FullName,Sid"
}

function Get-AllAppLockerLogs {
    Write-Host -ForegroundColor Yellow "Getting all AppLocker Logs"
    Get-WinEvent -LogName 'Microsoft-Windows-AppLocker/EXE and DLL' -Oldest
}

function Restart-CyberArkServices {
    Write-Host -ForegroundColor Yellow "Restarting all CyberArk services..."
    Restart-Service *ark*
}

function Stop-CyberArkServices {
    Write-Host -ForegroundColor Yellow "Stopping all CyberArk services..."
    Write-Host -ForegroundColor Red "WARNING - ALL CyberArk Services will be stopped in 5 sec. Press ctrl-c to cancel"
    Start-Sleep -Seconds 6
    Stop-Service *ark* -Force
}

function Start-CyberArkServices {
    Write-Host -ForegroundColor Yellow "Starting all CyberArk services..."
    Start-Service *ark*
}

function Collect-VaultLogs {
    Write-Host -ForegroundColor Yellow "Collecting Vault logs..."
    Set-Location 'C:\Program Files (x86)\PrivateArk\Server\'
    Invoke-Expression 'cmd /c CAVaultManager collectlogs'
    $lastLog = Get-ChildItem 'C:\Program Files (x86)\PrivateArk\Server\Collected Logs\*.zip' | Sort-Object LastWriteTime | Select-Object -Last 1 | Select-Object Name
    $timestamp = Get-Date -UFormat "%Y%m%d-%H%M%S"
    $logPath = "C:\install\$timestamp-logs"
    New-Item -Path $logPath -Type Directory | Out-Null
    $itemName = $lastLog.Name
    $item = "C:\Program Files (x86)\PrivateArk\Server\Collected Logs\$itemName"
    Copy-Item -Path $item -Destination $logPath
    Set-Location 'C:\scripts'
}

function Upgrade-PSM {
    Write-Host -ForegroundColor Yellow "This command will upgrade PSM with installer that you provide"
    Stop-Service *ark* -Force
    Write-Host "Specify full path to installer setup.exe: " -ForegroundColor Yellow -NoNewline
    $installer = Read-Host
    & $installer
}

function Open-HostsFile {
    Write-Host -ForegroundColor Yellow "Opening hosts file with Notepad"
    Start-Process notepad.exe -ArgumentList "C:\Windows\System32\drivers\etc\hosts"
}

function Test-Connectivity {
    Write-Host "Specify IP that you want to test " -ForegroundColor Yellow -NoNewline
    $testIp = Read-Host
    Write-Host "Specify PORT that you want to test " -ForegroundColor Yellow -NoNewline
    $testPort = Read-Host
    Write-Host -ForegroundColor Yellow "Testing connectivity..."
    Test-NetConnection -ComputerName $testIp -Port $testPort | Select-Object SourceAddress,ComputerName,RemotePort,TcpTestSucceeded
}

function Open-CPMBin {
    Write-Host -ForegroundColor Yellow "Opening CPM bin folder"
    Invoke-Item "C:\Program Files (x86)\CyberArk\Password Manager\bin"
}

function Open-CPMLogs {
    Write-Host -ForegroundColor Yellow "Opening CPM Logs folder"
    Invoke-Item "C:\Program Files (x86)\CyberArk\Password Manager\Logs"
}

# Functions for tailing CPM logs are similar, create one function for each log type as needed
function Tail-CPMLog {
    param (
        [string]$LogType
    )
    $logPath = "C:\Program Files (x86)\CyberArk\Password Manager\Logs\$LogType.log"
    Write-Host -ForegroundColor Yellow "Tailing $LogType log"
    Invoke-Expression "cmd /c start powershell -Command { Get-Content '$logPath' -Wait -Tail 200 }"
}

function Search-UserLogs {
    $fullName = Read-Host "Enter the full name of the user - search is performed as *username*"

    try {
        $username = Get-LocalUser | Where-Object { $_.FullName -like "*$fullName*" } | Select-Object -ExpandProperty Name
        if (-not $username) {
            throw "User not found."
        }
    } catch {
        Write-Host "Error: $_"
        return
    }

    $dateInput = Read-Host "Enter the date or date range (DD/MM/YYYY or DD/MM/YYYY-DD/MM/YYYY), press Enter for today"

    if ([string]::IsNullOrWhiteSpace($dateInput)) {
        $startDate = Get-Date
        $endDate = Get-Date
    } else {
        if ($dateInput -match '-') {
            $dates = $dateInput -split '-'
            try {
                $startDate = [DateTime]::ParseExact($dates[0].Trim(), 'dd/MM/yyyy', $null)
                $endDate = [DateTime]::ParseExact($dates[1].Trim(), 'dd/MM/yyyy', $null)
            } catch {
                Write-Host "Invalid date range format. Please use DD/MM/YYYY-DD/MM/YYYY."
                return
            }
        } else {
            try {
                $startDate = [DateTime]::ParseExact($dateInput, 'dd/MM/yyyy', $null)
                $endDate = $startDate
            } catch {
                Write-Host "Invalid date format. Please use DD/MM/YYYY."
                return
            }
        }
    }

    $logFiles = Get-ChildItem "C:\Program Files (x86)\CyberArk\PSM\Logs\Components\*.log"
    $matchedFiles = @()

    $idStrings = @()

    # First loop: find files that match the username
    foreach ($file in $logFiles) {
        if ($file.CreationTime.Date -ge $startDate.Date -and $file.CreationTime.Date -le $endDate.Date -and (Select-String -Path $file.FullName -Pattern $username -Quiet)) {
            # Extract the identification string from the filename
            $idString = $file.Name.Split('.')[0]
            $idStrings += $idString
        }
    }

    if ($idStrings.Count -eq 0) {
        Write-Host "No matching log files found."
        return
    }

    # Second loop: add all files that start with any of the identification strings to the $matchedFiles array
    foreach ($idString in $idStrings) {
        foreach ($file in $logFiles) {
            if ($file.Name.StartsWith($idString)) {
                $matchedFiles += $file
                Write-Output ("File: " + $file.FullName + " | Created on: " + $file.CreationTime)
            }
        }
    }

    if ($matchedFiles.Count -gt 0) {
        $prefixes = $matchedFiles | ForEach-Object { $_.Name.Substring(0, [math]::Min(36, $_.Name.Length)) } | Sort-Object -Unique

        $readLogs = Read-Host "Do you want to read the newest log file? (no/all/debug/info/specific/trace)"
        switch ($readLogs) {
            "all" {
                foreach ($file in $matchedFiles) {
                    Write-Output ("Contents of $($file.Name):")
                    Get-Content $file.FullName
                }
            }
            "debug" {
                foreach ($prefix in $prefixes) {
                    $filter = "*ClientDispatcher*"
                    $allRelatedFiles = Get-ChildItem "C:\Program Files (x86)\CyberArk\PSM\Logs\Components\$prefix$filter.log"
                    foreach ($file in $allRelatedFiles) {
                        Write-Output ("Contents of $($file.Name):")
                        Get-Content $file.FullName | Where-Object { $_ -match "DEBUG:" }
                    }
                }
            }
            "info" {
                foreach ($prefix in $prefixes) {
                    $filter = "*ClientDispatcher*"
                    $allRelatedFiles = Get-ChildItem "C:\Program Files (x86)\CyberArk\PSM\Logs\Components\$prefix$filter.log"
                    foreach ($file in $allRelatedFiles) {
                        Write-Output ("Contents of $($file.Name):")
                        Get-Content $file.FullName | Where-Object { $_ -match "INFO:" -or $_ -match "ERROR:" }
                    }
                }
            }
            "specific" {
                $i = 0
                foreach ($file in $matchedFiles) {
                    $i++
                    Write-Output ("[$i] File: " + $file.FullName + " | Created on: " + $file.CreationTime)
                }
                $fileChoice = Read-Host "Enter the number of the file you want to read"
                if ($fileChoice -match '^\d+$' -and $fileChoice -le $matchedFiles.Count -and $fileChoice -gt 0) {
                    $selectedFile = $matchedFiles[$fileChoice - 1]
                    Write-Output ("Contents of $($selectedFile.Name):")
                    Get-Content $selectedFile.FullName
                } else {
                    Write-Host "Invalid selection."
                }
            }
            "trace" {
                foreach ($file in $matchedFiles) {
                    Write-Output ("Tracing messages in $($file.Name):")
                    Get-Content $file.FullName | Where-Object { $_ -match "Dispatcher trace message:" }
                }
            }
            default {
                Write-Host "No action selected."
            }
        }
    } else {
        Write-Host "No matching log files found."
    }
}

function Read-LatestDispatcherLogs {
    Write-Host -ForegroundColor Yellow "Reading latest dispatcher logs..."
    $lastLog = Get-ChildItem 'C:\Program Files (x86)\CyberArk\PSM\Logs\Components\' | Sort-Object LastWriteTime | Select-Object -Last 1
    $name = $lastLog.Name
    $logs = $name.Substring(0, [Math]::Min($name.Length, 8))
    $filePaths = Get-ChildItem "C:\Program Files (x86)\CyberArk\PSM\Logs\Components\" | Where-Object { $_.Name -like "$logs*ClientDispatcher*.*" }

    Foreach ($filePath in $filePaths) {
        If ($filePath) {
            Get-Content $filePath.FullName
        }
    }
}

function Read-LatestInfoLogs {
    Write-Host -ForegroundColor Yellow "Reading latest INFO logs from dispatcher..."
    $lastLog = Get-ChildItem 'C:\Program Files (x86)\CyberArk\PSM\Logs\Components\' | Sort-Object LastWriteTime | Select-Object -Last 1
    $name = $lastLog.Name
    $logs = $name.Substring(0, [Math]::Min($name.Length, 8))
    $filePaths = Get-ChildItem "C:\Program Files (x86)\CyberArk\PSM\Logs\Components\" | Where-Object { $_.Name -like "$logs*ClientDispatcher*.*" }

    Foreach ($filePath in $filePaths) {
        If ($filePath) {
            Get-Content $filePath.FullName | Select-String "INFO:"
        }
    }
}

function Read-DispatcherTraceMessages {
    Write-Host -ForegroundColor Yellow "Reading dispatcher trace messages..."
    $lastLog = Get-ChildItem 'C:\Program Files (x86)\CyberArk\PSM\Logs\Components\' | Sort-Object LastWriteTime | Select-Object -Last 1
    $name = $lastLog.Name
    $logs = $name.Substring(0, [Math]::Min($name.Length, 8))
    $filePaths = Get-ChildItem "C:\Program Files (x86)\CyberArk\PSM\Logs\Components\" | Where-Object { $_.Name -like "$logs*.*" }

    Foreach ($filePath in $filePaths) {
        If ($filePath) {
            Get-Content $filePath.FullName | Select-String "Dispatcher trace message:"
        }
    }
}

function Search-AppLockerLogsForUser {
    $username = Read-Host "Type username to search for in logs - search is performed as *username*"
    $psmuser = Get-LocalUser | Where-Object {$_.FullName -like "*$username*"} | Select-Object SID
    $searchuser = $psmuser.SID.Value
    $LogNames = @(
        'Microsoft-Windows-AppLocker/EXE and DLL',
        'Microsoft-Windows-AppLocker/MSI and Script',
        'Microsoft-Windows-AppLocker/Packaged app-Deployment',
        'Microsoft-Windows-AppLocker/Packaged app-Execution'
    )

    $searchType = Read-Host "Enter search type (1 for first 10 events, 2 for keyword search, 3 for all error logs)"
    switch ($searchType) {
        "1" {
            foreach ($LogName in $LogNames) {
                Write-Host -ForegroundColor Green "Searching in $LogName for first 10 events for user with SID: $searchuser"
                Get-WinEvent -LogName "$LogName" | Where-Object { $_.UserId -match $searchuser } | Select-Object TimeCreated, Message -First 10
            }
        }
        "2" {
            $keyword = Read-Host "Type a keyword to search in the message field"
            $level = Read-Host "Search for 'error/critical only' or 'all' levels? (Type 'error' for error/critical, 'all' for all levels)"
            $levelFilter = if ($level -eq 'error') { 'Error', 'Critical' } else { 'Error', 'Critical', 'Information', 'Warning'}

            foreach ($LogName in $LogNames) {
                Write-Host -ForegroundColor Green "Searching in $LogName for messages containing '$keyword' for user with SID: $searchuser"
                Get-WinEvent -LogName "$LogName" | Where-Object { $_.UserId -match $searchuser -and $_.Message -like "*$keyword*" -and $_.LevelDisplayName -in $levelFilter } | Select-Object TimeCreated, Message
            }
        }
        "3" {
            foreach ($LogName in $LogNames) {
                Write-Host -ForegroundColor Green "Searching in $LogName for all error logs for user with SID: $searchuser"
                Get-WinEvent -LogName "$LogName" | Where-Object { $_.UserId -match $searchuser -and $_.LevelDisplayName -eq 'Error' } | Select-Object TimeCreated, Message
            }
        }
    }
}

function Search-AllWindowsLogsForUser {
    $username = Read-Host "Type username to search for in logs - search is performed as *username*"
    $psmuser = Get-LocalUser | Where-Object {$_.FullName -like "*$username*"} 
    $searchuser = $psmuser.Name

    Write-Host -ForegroundColor Green "Searching all Windows logs for messages related to user: $searchuser"
    Get-WinEvent -ListLog * | Where-Object { $_.RecordCount -gt 0 } | ForEach-Object {
        Get-WinEvent -LogName $_.LogName | Where-Object { $_.Message -match $searchuser }
    }
}

function Get-PSMUserName {
    Write-Host -ForegroundColor Yellow "I will help you to identify that strange PSM-XYZ12345678 user by name"
    $username = Read-Host "Type username to get his PSM-XYZ12345678 string"
    get-localuser | where {$_.Fullname -like "*$username*"} | Select-Object name,fullname,enabled,description
}

function Tail-W3SVC1 {
    $logPath = "C:\inetpub\logs\LogFiles\W3SVC1"
    $latestFile = Get-ChildItem -Path $logPath | Sort-Object LastAccessTime -Descending | Select-Object -First 1

    # Ask the user for their choice
    Write-Host "Do you want to:" -ForegroundColor Yellow
    Write-Host "1. Tail the log file in a new window" -ForegroundColor Yellow
    Write-Host "2. Display the last 100 lines in the current window" -ForegroundColor Yellow
    Write-Host "3. Find a specific keyword in the log file" -ForegroundColor Yellow
    Write-Host "Enter 1, 2 or 3:" -ForegroundColor Yellow
    $userChoice = Read-Host

    if ($userChoice -eq 1) {
        # Tail the log file in a new window
        $psCommand = 'cmd /c start powershell -Command { Get-Content "' + $latestFile.FullName + '" -Wait -Tail 200 }'
        Invoke-Expression $psCommand
    } elseif ($userChoice -eq 2) {
        # Display the last 100 lines in the current window
        Get-Content $latestFile.FullName -Tail 100
    } elseif ($userChoice -eq 3) {
        # Find a specific keyword in the log file
        $keyword = Read-Host "Enter the keyword to search for"
        Select-String -Path $latestFile.FullName -Pattern $keyword
    } else {
        Write-Host "Invalid choice. Please enter 1, 2 or 3." -ForegroundColor Red
    }
}

function Search-PVWAWebConsoleLog {
    $logPath = "C:\Windows\Temp\PVWA\CyberArk.WebConsole.log"

    # Ask the user for their choice
    Write-Host "Do you want to:" -ForegroundColor Yellow
    Write-Host "1. Tail the log file in a new window" -ForegroundColor Yellow
    Write-Host "2. Display the last 100 lines in the current window" -ForegroundColor Yellow
    Write-Host "3. Find a specific keyword in the log file" -ForegroundColor Yellow
    Write-Host "4. Search for specific log levels (INFO, ERROR, TRACE, CRITICAL)" -ForegroundColor Yellow
    Write-Host "Enter 1, 2, 3 or 4:" -ForegroundColor Yellow
    $userChoice = Read-Host

    if ($userChoice -eq 1) {
        # Tail the log file in a new window
        $psCommand = 'cmd /c start powershell -Command { Get-Content "' + $logPath + '" -Wait -Tail 200 }'
        Invoke-Expression $psCommand
    } elseif ($userChoice -eq 2) {
        # Display the last 100 lines in the current window
        Get-Content $logPath -Tail 100
    } elseif ($userChoice -eq 3) {
        # Find a specific keyword in the log file
        $keyword = Read-Host "Enter the keyword to search for"
        Select-String -Path $logPath -Pattern $keyword
    } elseif ($userChoice -eq 4) {
        # Search for specific log levels
        $logLevels = @("INFO", "ERROR", "TRACE", "CRITICAL")
        $choice = Read-Host "Enter the number for the log level to search for (1: INFO, 2: ERROR, 3: TRACE, 4: CRITICAL)"
        if ($choice -ge 1 -and $choice -le 4) {
            $logLevel = $logLevels[$choice - 1]
            Select-String -Path $logPath -Pattern $logLevel -CaseSensitive
        } else {
            Write-Host "Invalid choice. Please enter a number between 1 and 4." -ForegroundColor Red
        }
    } else {
        Write-Host "Invalid choice. Please enter 1, 2, 3 or 4." -ForegroundColor Red
    }
}

function Search-PVWAAppLog {
    $logPath = "C:\Windows\Temp\PVWA\PVWA.App.log"

    # Ask the user for their choice
    Write-Host "Do you want to:" -ForegroundColor Yellow
    Write-Host "1. Tail the log file in a new window" -ForegroundColor Yellow
    Write-Host "2. Display the last 100 lines in the current window" -ForegroundColor Yellow
    Write-Host "3. Find a specific keyword in the log file" -ForegroundColor Yellow
    Write-Host "4. Search for specific log levels (INFO, ERROR, TRACE, CRITICAL)" -ForegroundColor Yellow
    Write-Host "Enter 1, 2, 3 or 4:" -ForegroundColor Yellow
    $userChoice = Read-Host

    if ($userChoice -eq 1) {
        # Tail the log file in a new window
        $psCommand = 'cmd /c start powershell -Command { Get-Content "' + $logPath + '" -Wait -Tail 200 }'
        Invoke-Expression $psCommand
    } elseif ($userChoice -eq 2) {
        # Display the last 100 lines in the current window
        Get-Content $logPath -Tail 100
    } elseif ($userChoice -eq 3) {
        # Find a specific keyword in the log file
        $keyword = Read-Host "Enter the keyword to search for"
        Select-String -Path $logPath -Pattern $keyword
    } elseif ($userChoice -eq 4) {
        # Search for specific log levels
        $logLevels = @("INFO", "ERROR", "TRACE", "CRITICAL")
        $choice = Read-Host "Enter the number for the log level to search for (1: INFO, 2: ERROR, 3: TRACE, 4: CRITICAL)"
        if ($choice -ge 1 -and $choice -le 4) {
            $logLevel = $logLevels[$choice - 1]
            Select-String -Path $logPath -Pattern $logLevel -CaseSensitive
        } else {
            Write-Host "Invalid choice. Please enter a number between 1 and 4." -ForegroundColor Red
        }
    } else {
        Write-Host "Invalid choice. Please enter 1, 2, 3 or 4." -ForegroundColor Red
    }
}


function Search-PVWAConsoleLog {
    $logPath = "C:\Windows\Temp\PVWA\PVWA.Console.log"

    # Ask the user for their choice
    Write-Host "Do you want to:" -ForegroundColor Yellow
    Write-Host "1. Tail the log file in a new window" -ForegroundColor Yellow
    Write-Host "2. Display the last 100 lines in the current window" -ForegroundColor Yellow
    Write-Host "3. Find a specific keyword in the log file" -ForegroundColor Yellow
    Write-Host "4. Search for specific log levels (INFO, ERROR, TRACE, CRITICAL)" -ForegroundColor Yellow
    Write-Host "Enter 1, 2, 3 or 4:" -ForegroundColor Yellow
    $userChoice = Read-Host

    if ($userChoice -eq 1) {
        # Tail the log file in a new window
        $psCommand = 'cmd /c start powershell -Command { Get-Content "' + $logPath + '" -Wait -Tail 200 }'
        Invoke-Expression $psCommand
    } elseif ($userChoice -eq 2) {
        # Display the last 100 lines in the current window
        Get-Content $logPath -Tail 100
    } elseif ($userChoice -eq 3) {
        # Find a specific keyword in the log file
        $keyword = Read-Host "Enter the keyword to search for"
        Select-String -Path $logPath -Pattern $keyword
    } elseif ($userChoice -eq 4) {
        # Search for specific log levels
        $logLevels = @("INFO", "ERROR", "TRACE", "CRITICAL")
        $choice = Read-Host "Enter the number for the log level to search for (1: INFO, 2: ERROR, 3: TRACE, 4: CRITICAL)"
        if ($choice -ge 1 -and $choice -le 4) {
            $logLevel = $logLevels[$choice - 1]
            Select-String -Path $logPath -Pattern $logLevel -CaseSensitive
        } else {
            Write-Host "Invalid choice. Please enter a number between 1 and 4." -ForegroundColor Red
        }
    } else {
        Write-Host "Invalid choice. Please enter 1, 2, 3 or 4." -ForegroundColor Red
    }
}
function Search-PVWAReportsLog {
    $logPath = "C:\Windows\Temp\PVWA\PVWA.Reports.log"

    # Ask the user for their choice
    Write-Host "Do you want to:" -ForegroundColor Yellow
    Write-Host "1. Tail the log file in a new window" -ForegroundColor Yellow
    Write-Host "2. Display the last 100 lines in the current window" -ForegroundColor Yellow
    Write-Host "3. Find a specific keyword in the log file" -ForegroundColor Yellow
    Write-Host "4. Search for specific log levels (INFO, ERROR, TRACE, CRITICAL)" -ForegroundColor Yellow
    Write-Host "Enter 1, 2, 3 or 4:" -ForegroundColor Yellow
    $userChoice = Read-Host

    if ($userChoice -eq 1) {
        # Tail the log file in a new window
        $psCommand = 'cmd /c start powershell -Command { Get-Content "' + $logPath + '" -Wait -Tail 200 }'
        Invoke-Expression $psCommand
    } elseif ($userChoice -eq 2) {
        # Display the last 100 lines in the current window
        Get-Content $logPath -Tail 100
    } elseif ($userChoice -eq 3) {
        # Find a specific keyword in the log file
        $keyword = Read-Host "Enter the keyword to search for"
        Select-String -Path $logPath -Pattern $keyword
    } elseif ($userChoice -eq 4) {
        # Search for specific log levels
        $logLevels = @("INFO", "ERROR", "TRACE", "CRITICAL")
        $choice = Read-Host "Enter the number for the log level to search for (1: INFO, 2: ERROR, 3: TRACE, 4: CRITICAL)"
        if ($choice -ge 1 -and $choice -le 4) {
            $logLevel = $logLevels[$choice - 1]
            Select-String -Path $logPath -Pattern $logLevel -CaseSensitive
        } else {
            Write-Host "Invalid choice. Please enter a number between 1 and 4." -ForegroundColor Red
        }
    } else {
        Write-Host "Invalid choice. Please enter 1, 2, 3 or 4." -ForegroundColor Red
    }
}

function Search-AllPVWALogs {
    $logPaths = @(
        "C:\inetpub\logs\LogFiles\W3SVC1",
        "C:\Windows\Temp\PVWA\CyberArk.WebConsole.log",
        "C:\Windows\Temp\PVWA\PVWA.App.log",
        "C:\Windows\Temp\PVWA\PVWA.Console.log",
        "C:\Windows\Temp\PVWA\PVWA.Reports.log"
    )

    # Ask the user for their choice
    Write-Host "Do you want to:" -ForegroundColor Yellow
    Write-Host "1. Tail the log files in new windows" -ForegroundColor Yellow
    Write-Host "2. Display the last 100 lines in the current windows" -ForegroundColor Yellow
    Write-Host "3. Find a specific keyword in the log files" -ForegroundColor Yellow
    Write-Host "4. Search for specific log levels (INFO, ERROR, TRACE, CRITICAL)" -ForegroundColor Yellow
    Write-Host "Enter 1, 2, 3 or 4:" -ForegroundColor Yellow
    $userChoice = Read-Host

    $keyword = $null
    if ($userChoice -eq 3) {
        $keyword = Read-Host "Enter the keyword to search for"
    }

    $logLevel = $null
    if ($userChoice -eq 4) {
        $logLevels = @("INFO", "ERROR", "TRACE", "CRITICAL")
        $choice = Read-Host "Enter the number for the log level to search for (1: INFO, 2: ERROR, 3: TRACE, 4: CRITICAL)"
        if ($choice -ge 1 -and $choice -le 4) {
            $logLevel = $logLevels[$choice - 1]
        } else {
            Write-Host "Invalid choice. Please enter a number between 1 and 4." -ForegroundColor Red
            return
        }
    }

    foreach ($logPath in $logPaths) {
        if ($userChoice -eq 1) {
            # Tail the log file in a new window
            $psCommand = 'cmd /c start powershell -Command { Get-Content "' + $logPath + '" -Wait -Tail 200 }'
            Invoke-Expression $psCommand
        } elseif ($userChoice -eq 2) {
            # Display the last 100 lines in the current window
            Write-Host "File: $logPath" -ForegroundColor Green
            Get-Content $logPath -Tail 100
        } elseif ($userChoice -eq 3) {
            # Find a specific keyword in the log file
            Write-Host "File: $logPath" -ForegroundColor Green
            Select-String -Path $logPath -Pattern $keyword
        } elseif ($userChoice -eq 4) {
            # Search for specific log levels
            Write-Host "File: $logPath" -ForegroundColor Green
            Select-String -Path $logPath -Pattern $logLevel -CaseSensitive
        } else {
            Write-Host "Invalid choice. Please enter 1, 2, 3 or 4." -ForegroundColor Red
        }
    }
}

function Open-PVWATempFolder {
    # Open the folder C:\Windows\Temp\PVWA
    Start-Process "explorer.exe" -ArgumentList "/e,C:\Windows\Temp\PVWA"
}

function Open-CyberArkFolder {
    # Open the folder C:\CyberArk\Password Vault Web Access
    Start-Process "explorer.exe" -ArgumentList "/e,C:\CyberArk\Password Vault Web Access"
}

function Open-InetpubLogsFolder {
    # Open the folder C:\inetpub\logs
    Start-Process "explorer.exe" -ArgumentList "/e,C:\inetpub\logs"
}

function Restart-IIS {
    # Run command iisreset /restart and then iisreset /status
    Invoke-Expression "cmd.exe /c iisreset /restart"
    Start-Sleep -Seconds 2
    Invoke-Expression "cmd.exe /c iisreset /status"
}

function Enable-ClipboardAndDriveMapping {
    $path = "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services"
    $disableCdmExists = (Get-ItemProperty -Path $path).PSObject.Properties.Name -contains "fDisableCdm"
    $disableClipboardExists = (Get-ItemProperty -Path $path).PSObject.Properties.Name -contains "fDisableClip"

    if ($disableCdmExists) {
        $disableCdm = Get-ItemProperty -Path $path -Name "fDisableCdm"
        if ($disableCdm -eq 1) {
            Write-Host -ForegroundColor Red "Drive mapping is currently disabled."
        } else {
            Write-Host -ForegroundColor Green "Drive mapping is currently enabled."
        }
    } else {
        Write-Host -ForegroundColor Yellow "Drive mapping key does not exist."
    }

    if ($disableClipboardExists) {
        $disableClipboard = Get-ItemProperty -Path $path -Name "fDisableClip"
        if ($disableClipboard -eq 1) {
            Write-Host -ForegroundColor Red "Clipboard is currently disabled."
        } else {
            Write-Host -ForegroundColor Green "Clipboard is currently enabled."
        }
    } else {
        Write-Host -ForegroundColor Yellow "Clipboard key does not exist."
    }

    Write-Host "Do you want to: 1) Allow all, 2) Allow clipboard only, 3) Allow disk only, 4) Disable all?"
    $choice = Read-Host

    if ($choice -eq '1') {
        if (-not $disableCdmExists) {
            New-ItemProperty -Path $path -Name "fDisableCdm" -Value 0 -PropertyType "DWord"
        } else {
            Set-ItemProperty -Path $path -Name "fDisableCdm" -Value 0
        }
        if (-not $disableClipboardExists) {
            New-ItemProperty -Path $path -Name "fDisableClip" -Value 0 -PropertyType "DWord"
        } else {
            Set-ItemProperty -Path $path -Name "fDisableClip" -Value 0
        }
        Write-Host "Both clipboard and drive mapping have been enabled."
    } elseif ($choice -eq '2') {
        if (-not $disableClipboardExists) {
            New-ItemProperty -Path $path -Name "fDisableClip" -Value 0 -PropertyType "DWord"
        } else {
            Set-ItemProperty -Path $path -Name "fDisableClip" -Value 0
        }
        Write-Host "Clipboard has been enabled."
    } elseif ($choice -eq '3') {
        if (-not $disableCdmExists) {
            New-ItemProperty -Path $path -Name "fDisableCdm" -Value 0 -PropertyType "DWord"
        } else {
            Set-ItemProperty -Path $path -Name "fDisableCdm" -Value 0
        }
        Write-Host "Drive mapping has been enabled."
    } elseif ($choice -eq '4') {
        if ($disableCdmExists) {
            Set-ItemProperty -Path $path -Name "fDisableCdm" -Value 1
        }
        if ($disableClipboardExists) {
            Set-ItemProperty -Path $path -Name "fDisableClip" -Value 1
        }
        Write-Host "Both clipboard and drive mapping have been disabled."
    } else {
        Write-Host "Invalid choice. Aborting..."
    }
}

function Enable-RDPSavedCredentials {
# Define the registry path and value
$regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"
$valueName = "fPromptForPassword"

# Check if the registry value exists and retrieve the current value
try {
    $regKey = Get-Item -Path $regPath
    $currentValue = Get-ItemProperty -Path $regPath -Name $valueName | Select-Object -ExpandProperty $valueName

    # Display the current setting
    if ($currentValue -eq 1) {
        Write-Host "The setting 'Always prompt for password upon connection' is currently ENABLED."
    } else {
        Write-Host "The setting 'Always prompt for password upon connection' is currently DISABLED."
    }

    # Ask the user for confirmation to change the setting
    $confirmation = Read-Host "Do you want to toggle the setting? (Y/N)"

    if ($confirmation -eq "Y") {
        # Toggle the setting
        $newValue = if ($currentValue -eq 1) { 0 } else { 1 }
        Set-ItemProperty -Path $regPath -Name $valueName -Value $newValue

        # Confirm the change
        if ($newValue -eq 1) {
            Write-Host "The setting has been ENABLED."
        } else {
            Write-Host "The setting has been DISABLED."
        }
    } else {
        Write-Host "No changes were made."
    }
} catch {
    Write-Host "An error occurred while accessing the registry: $_"
}
}

# Display Menu and Capture User Input
Display-Menu
Write-Host "Type the number and press enter..." -ForegroundColor Yellow -nonewline; $action = Read-Host
Write-Host -ForegroundColor Yellow "You have chosen no.$action, im running that command now..."

# Decision Logic to Execute Based on User Input
switch ($action) {
    '0' { Get-DotNetVersions }
    '1' { Open-DbParm }
    '2' { Open-TsParm }
    '3' { Tail-PadrLog }
    '4' { Tail-ItaLog }
    '5' { Open-ServerConf }
    '6' { Open-ServerLogs }
    '7' { Open-PadrConf }
    '8' { Open-PadrLogs }
    '9' { Get-CyberArkServicesStatus }
    '10' { Open-PSMComponents }    
    '11' { Open-PSMLogs }
    '12' { Get-LastPSMComponentLog }
    '13' { Tail-PSMTraceLog }
    '14' { Open-PSMConfigureAppLockerXml }
    '15' { Run-PSMConfigureAppLocker }
    '16' { Get-NonInfoAppLockerLogs }
    '17' { Get-AllAppLockerLogs }
    '19' { Search-UserLogs }
    '20' { Read-LatestDispatcherLogs }
    '21' { Read-LatestInfoLogs }
    '22' { Read-DispatcherTraceMessages }
    '23' { Search-AppLockerLogsForUser }
    '24' { Search-AllWindowsLogsForUser }
    '25' { Get-PSMUserName }
    '1000' { Restart-CyberArkServices }
    '1002' { Stop-CyberArkServices }
    '999' { Enable-ClipboardAndDriveMapping }
    '1001' { Start-CyberArkServices }
    '01' { Collect-VaultLogs }
    '18' { Upgrade-PSM }
    '996' { Open-HostsFile }
    '995' { Test-Connectivity }
    '997' { Enable-RDPSavedCredentials }
    '30' { Open-CPMBin }
    '31' { Open-CPMLogs }
    '32' { Tail-CPMLog -LogType "PMTrace" }
    '33' { Tail-CPMLog -LogType "pm_error" }
    '34' { Tail-CPMLog -LogType "Casos.Debug" }
    '35' { Tail-CPMLog -LogType "Casos.Error" }
    '40' { Tail-W3SVC1 }
    '41' { Search-PVWAWebConsoleLog }
    '42' { Search-PVWAAppLog }
    '43' { Search-PVWAConsoleLog }
    '44' { Search-PVWAReportsLog }
    '45' { Search-AllPVWALogs }
    '46' { Open-PVWATempFolder }
    '47' { Open-CyberArkFolder }
    '48' { Open-InetpubLogsFolder }
    '49' { Restart-IIS }
    '993' { Set-ProxyServer }
    default {
        Write-Host "Invalid option selected. Please try again." -ForegroundColor Red
    }
}