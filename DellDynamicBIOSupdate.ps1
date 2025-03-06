##*=============================================
##* START VARIABLE LISTINGS
##*=============================================

$Date = Get-Date -Format 'MMMdd_HHMMttss'

# Application Details - Modify Script Details
[string]$appVendor = 'Company'
[string]$appName = 'DellBIOSUpdatesDynamic' ## Update Me
[string]$appNameWithSpaces = "Dell BIOS Update - Dynamic" ## Update Me
[string]$appVersion = '1.0.0.0' ## Update Me
[string]$appTitle = "$appVendor $appName $appVersion"
[string]$appArch = 'x64x86' ## Update Me (If Needed)
[string]$appLang = 'EN'
[string]$appRevision = '01'
[string]$appScriptVersion = '1.0.0.0' ## Update Me
[string]$appScriptDate = '04/12/2024' ## Update Me
[string]$appScriptAuthor = 'Nathan C. Hoy and Tyler Siniff' ## Update Me
[string]$runtime = '5'

#region DONOTMODIfY

#declare env variable
$tsenv = New-Object -COMObject Microsoft.SMS.TSEnvironment
$tsenv.Value("BIOSinstalled") = $false

# Log File Info 
$LogPath = "$PSScriptRoot\Logs"

$LogName = "$appName" + "_" + "$appScriptVersion" + "_" + "PS.log"
$LogFile = Join-Path -Path $LogPath -ChildPath $LogName

$FolderCheckLeaf = Test-Path -Path $LogPath -PathType Leaf
$FolderCheckContainer = Test-Path -Path $LogPath -PathType Container

# Specs and Details
$PackageName = (Get-Process -Id $PID).ProcessName
$SerialNumber = (Get-WmiObject win32_bios).serialnumber
$Manufacturer = (Get-WmiObject win32_bios).Manufacturer
$BIOsVerison = (Get-WmiObject win32_bios).SMBIOSBIOSVersion
$Model = (Get-WmiObject win32_computersystem).Model
$Name = (Get-WmiObject win32_computersystem).Name
$GB = Get-WmiObject win32_LogicalDisk | Measure-Object -Sum Size
$GB2 = Get-WmiObject win32_LogicalDisk | Measure-Object -Sum freespace
$Disk = "{0:N2}" -f ($GB.Sum / 1GB) + " GB"
$FreeSpace = "{0:N2}" -f ($gb2.sum / 1GB) + " GB"
[psobject]$envOS = Get-WmiObject -Class 'Win32_OperatingSystem' -ErrorAction 'SilentlyContinue'
[string]$envOSName = $envOS.Caption.Trim()
[string]$envOSServicePack = $envOS.CSDVersion
[version]$envOSVersion = $envOS.Version
[string]$envOSVersionMajor = $envOSVersion.Major
[string]$envOSVersionMinor = $envOSVersion.Minor
[string]$envOSVersionBuild = $envOSVersion.Build
[string]$envOSVersionRevision = ,((Get-ItemProperty -Path 'HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name 'BuildLabEx' -ErrorAction 'SilentlyContinue').BuildLabEx -split '\.') | ForEach-Object { $_[1] }
If ($envOSVersionRevision -notmatch '^[\d\.]+$') { $envOSVersionRevision = '' }
If ($envOSVersionRevision) { [string]$envOSVersion = "$($envOSVersion.ToString()).$envOSVersionRevision" }
Else { "$($envOSVersion.ToString())" }

#endregion

# Custom Items
$FlagSingle = $false
$FlagMultiple = $false
$DownloadPath = "$PSScriptRoot\Repo"
$FlashExe = "$PSScriptRoot\Flash64W.exe"
$BIOSUpdate = "$DownloadPath\biosupdate.exe"
$BIOSUpdateLog = "$LogPath\biosupdatelog.txt"

#*=============================================
##* END VARIABLE LISTINGS
##*=============================================

##*=============================================
##* START FUNCTION LISTINGS
##*=============================================

#region Log Functions

Function Start-Log
{
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$LogPath,
        [Parameter(Mandatory = $true, Position = 1)]
        [string]$LogName,
        [Parameter(Mandatory = $true, Position = 2)]
        [string]$ScriptVersion
    )
    
    Process
    {
        #Create file and start logging
        If (!(Test-Path -Path $LogFile))
        {
            New-Item -Path $LogFile -ItemType File
        }
        Add-Content -Path $LogFile -Value "***************************************************************************************************"
        Add-Content -Path $LogFile -Value "Started processing at [$([DateTime]::Now)]."
        Add-Content -Path $LogFile -Value "***************************************************************************************************"
        Add-Content -Path $LogFile -Value ""
        Add-Content -Path $LogFile -Value "Running script version [$ScriptVersion]."
        Add-Content -Path $LogFile -Value ""
        Add-Content -Path $LogFile -Value "***************************************************************************************************"
        Add-Content -Path $LogFile -Value "                                                               Package Information"
        Add-Content -Path $LogFile -Value "***************************************************************************************************"
        Add-Content -Path $LogFile -Value ""
        Add-Content -Path $LogFile -Value "Package Name = [$appNameWithSpaces]"
        Add-Content -Path $LogFile -Value "App Version = [$appVersion]"
        Add-Content -Path $LogFile -Value "Script Version = [$appScriptVersion]"
        Add-Content -Path $LogFile -Value ""
        Add-Content -Path $LogFile -Value "***************************************************************************************************"
        Add-Content -Path $LogFile -Value "                                                               System Information"
        Add-Content -Path $LogFile -Value "***************************************************************************************************"
        Add-Content -Path $LogFile -Value ""
        Add-Content -Path $LogFile -Value "Name = [$Name]"
        Add-Content -Path $LogFile -Value "OS Name= [$envOSName]"
        Add-Content -Path $LogFile -Value "OS Version= [$envOSVersion]"
        Add-Content -Path $LogFile -Value "Serial Number= [$SerialNumber]"
        Add-Content -Path $LogFile -Value "BIOS Version = [$BIOsVerison]"
        Add-Content -Path $LogFile -Value "Manufacturer = [$Manufacturer]"
        Add-Content -Path $LogFile -Value "Model = [$Model]"
        Add-Content -Path $LogFile -Value "Total Disk Size = [$Disk]"
        Add-Content -Path $LogFile -Value "Free Disk Space = [$FreeSpace]"
        Add-Content -Path $LogFile -Value ""
        Add-Content -Path $LogFile -Value "***************************************************************************************************"
    }
}

Function Write-PoShLog
{
    [CmdletBinding()]
    [OutputType([object[]])]
    Param (
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        $Message
    )
    
    Process
    {
        $Message = "$Message  [$([DateTime]::Now)]"
        $LogPath = $LogFile
        
        #Write Content to Log
        Add-Content  $LogPath -Value $Message
    }
}

Function Stop-Log
{
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$LogPath,
        [Parameter(Mandatory = $false, Position = 1)]
        [switch]$NoExit
        
    )
    Process
    {
        Add-Content -Path $LogPath -Value ""
        Add-Content -Path $LogPath -Value "***************************************************************************************************"
        Add-Content -Path $LogPath -Value "Finished processing at [$([DateTime]::Now)]."
        Add-Content -Path $LogPath -Value "***************************************************************************************************"
        
        #Exit calling script If NoExit has not been specIfied or is set to False
        If (!($NoExit) -or ($NoExit -eq $False))
        {
            Exit
        }
    }
}

#endregion

Function Get-DellCatalogPC
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false, Position = 0)]
        [ValidateSet('Application', 'BIOS', 'Driver', 'Firmware')]
        [string]$Component,
        [Parameter(Mandatory = $false, Position = 1)]
        [switch]$Compatible
    )
    $VerbosePreference = "Continue"
    
    #=======================================================================
    # Compatibility
    #=======================================================================
    
    $SystemSKU = $((Get-WmiObject -Class Win32_ComputerSystem).SystemSKUNumber).Trim()
    $BIOSVersion = $((Get-WmiObject -Class Win32_BIOS).SMBIOSBIOSVersion).Trim()
    
    #=======================================================================
    # Variables
    #=======================================================================
    $DellDownloadsUrl = "http://downloads.dell.com/"
    $CatalogPcUrl = "http://downloads.dell.com/catalog/CatalogPC.cab"
    
    $RepoFolderCheckLeaf = Test-Path -Path $DownloadPath -PathType Leaf
    $RepoFolderCheckContainer = Test-Path -Path $DownloadPath -PathType Container
    
    
    $OfflineCatalogPcFullName = Join-Path $DownloadPath "Get-DellCatalogPC.xml"
    $CatalogPcCabName = [string]($CatalogPcUrl | Split-Path -Leaf)
    $CatalogPcCabFullName = Join-Path $DownloadPath $CatalogPcCabName
    $CatalogPcXmlName = "CatalogPC.xml"
    $CatalogPCXmlFullName = Join-Path $DownloadPath $CatalogPcXmlName
    
    #=======================================================================
    # Offline Catalog
    #=======================================================================
    
    If (($RepoFolderCheckLeaf -eq $true) -or ($RepoFolderCheckContainer -eq $false))
    {
        Remove-Item -Path $DownloadPath -Force -ErrorAction SilentlyContinue | Out-Null
        New-Item -ItemType Directory -Path $DownloadPath -Force
        
        $RepoFolderCheckLeaf = Test-Path -Path $LogPath -PathType Leaf
        $RepoFolderCheckContainer = Test-Path -Path $LogPath -PathType Container
    }
    
    If ($RepoFolderCheckContainer -eq $true)
    {
        If (Test-Path $OfflineCatalogPcFullName)
        {
            $ExistingFile = Get-Item $OfflineCatalogPcFullName
            
            If (((Get-Date) - $ExistingFile.CreationTime).TotalDays -gt 14)
            {
                Remove-Item -Path $OfflineCatalogPcFullName -Force -ErrorAction SilentlyContinue
            }
        }
        
        If (Test-Path $OfflineCatalogPcFullName)
        {
            $DellCatalogPc = Import-Clixml -Path $OfflineCatalogPcFullName
        }
        Else
        {
            If (Test-Path $CatalogPcCabFullName)
            {
                $ExistingFile = Get-Item $CatalogPcCabFullName
                
                If (((Get-Date) - $ExistingFile.CreationTime).TotalDays -gt 1)
                {
                    Remove-Item -Path $CatalogPcCabFullName -Force -ErrorAction SilentlyContinue
                }
            }
            
            If (-NOT (Test-Path $CatalogPcCabFullName))
            {
                (New-Object System.Net.WebClient).DownloadFile($CatalogPcUrl, "$CatalogPcCabFullName")
            }
            
            If (-NOT (Test-Path $CatalogPcCabFullName))
            {
                Write-PoShLog "[ERROR] Could not download the Dell CatalogPC.cab"
                Break
            }
            
            Expand "$CatalogPcCabFullName" "$CatalogPCXmlFullName" | Out-Null
            
            If (-NOT (Test-Path $CatalogPCXmlFullName))
            {
                Add-Content -Path $LogFile "Could Not Expand the Dell CatalogPC.xml"
                
                Break
            }
            
            [xml]$XMLCatalogPcUrl = Get-Content "$CatalogPCXmlFullName" -ErrorAction Stop
            
            $DellCatalogPc = $XMLCatalogPcUrl.ManIfest.SoftwareComponent
            
            $DellCatalogPc = $DellCatalogPc | `
            Select-Object @{ Label = "Component"; Expression = { ($_.ComponentType.Display.'#cdata-section'.Trim()) }; },
                          @{ Label = "ReleaseDate"; Expression = { [datetime] ($_.dateTime) }; },
                          @{ Label = "Name"; Expression = { ($_.Name.Display.'#cdata-section'.Trim()) }; },
                          #@{Label="Description";Expression={($_.Description.Display.'#cdata-section'.Trim())};},
                          @{ Label = "DellVersion"; Expression = { $_.dellVersion }; },
                          @{ Label = "Url"; Expression = { -join ($DellDownloadsUrl, $_.path) }; },
                          @{ Label = "VendorVersion"; Expression = { $_.vendorVersion }; },
                          @{ Label = "Criticality"; Expression = { ($_.Criticality.Display.'#cdata-section'.Trim()) }; },
                          @{ Label = "FileName"; Expression = { (split-path -leaf $_.path) }; },
                          @{ Label = "SizeMB"; Expression = { '{0:f2}' -f ($_.size/1MB) }; },
                          @{ Label = "PackageID"; Expression = { $_.packageID }; },
                          @{ Label = "PackageType"; Expression = { $_.packageType }; },
                          @{ Label = "ReleaseID"; Expression = { $_.ReleaseID }; },
                          @{ Label = "Category"; Expression = { ($_.Category.Display.'#cdata-section'.Trim()) }; },
                          @{ Label = "SupportedDevices"; Expression = { ($_.SupportedDevices.Device.Display.'#cdata-section'.Trim()) }; },
                          @{ Label = "SupportedBrand"; Expression = { ($_.SupportedSystems.Brand.Display.'#cdata-section'.Trim()) }; },
                          @{ Label = "SupportedModel"; Expression = { ($_.SupportedSystems.Brand.Model.Display.'#cdata-section'.Trim()) }; },
                          @{ Label = "SupportedSystemID"; Expression = { ($_.SupportedSystems.Brand.Model.systemID) }; },
                          @{ Label = "SupportedOperatingSystems"; Expression = { ($_.SupportedOperatingSystems.OperatingSystem.Display.'#cdata-section'.Trim()) }; },
                          @{ Label = "SupportedArchitecture"; Expression = { ($_.SupportedOperatingSystems.OperatingSystem.osArch) }; },
                          @{ Label = "HashMD5"; Expression = { $_.HashMD5 }; }
            
            $DellCatalogPc = $DellCatalogPc | Sort-Object ReleaseDate -Descending
            $DellCatalogPc | Export-Clixml -Path $OfflineCatalogPcFullName
        }
        #=======================================================================
        # Filter Compatible
        #=======================================================================
        
        If ($Compatible)
        {
            $DellCatalogPc = $DellCatalogPc | Where-Object { $_.SupportedSystemID -contains $SystemSKU }
        }
        
        #=======================================================================
        # Filter Component
        #=======================================================================
        If ($Component)
        {
            $DellCatalogPc = $DellCatalogPc | Where-Object { $_.Component -eq $Component }
        }
        
        $DellCatalogPc
    }
}

##*=============================================
##* END FUNCTION LISTINGS
##*=============================================
##*=============================================
##* START SCRIPT BODY
##*=============================================

# Log Path

If (($FolderCheckLeaf -eq $true) -or ($FolderCheckContainer -eq $false))
{
    Remove-Item -Path $LogPath -Force -ErrorAction SilentlyContinue | Out-Null
    New-Item -ItemType Directory -Path $LogPath -Force | Out-Null;
    
    $FolderCheckLeaf = Test-Path -Path $LogPath -PathType Leaf
    $FolderCheckContainer = Test-Path -Path $LogPath -PathType Container
}

# Repo Path

If (($RepoCheckLeaf -eq $true) -or ($RepoCheckContainer -eq $false))
{
    Remove-Item -Path $RepoPath -Force -ErrorAction SilentlyContinue | Out-Null
    New-Item -ItemType Directory -Path $RepoPath -Force | Out-Null;
    
    $RepoCheckLeaf = Test-Path -Path $RepoPath -PathType Leaf
    $RepoCheckContainer = Test-Path -Path $RepoPath -PathType Container
}

If ($FolderCheckContainer -eq $true)
{
    Start-Log -LogPath $LogPath -LogName $LogName -ScriptVersion $appScriptVersion | Out-Null
    
    If (Test-Path -Path $LogPath)
    {
        #=======================================================================
        # Gather BIOS Information
        #=======================================================================
        
        $BIOSresults = Get-DellCatalogPC -Compatible -Component BIOS
        
        #region log results
        If ($BIOSresults.Component.Count -eq 1)
        {
            $FlagSingle = $true
            
            Add-Content -Path $LogFile "***************************************************************************************************"
            Add-Content -Path $LogFile "                                                               BIOS Details | 1 of 1"
            Add-Content -Path $LogFile "***************************************************************************************************"
            
            ForEach ($item in $BIOSresults.PSObject.Get_Properties())
            {
                $Name = $($item).Name
                $Value = $($item).Value
                Add-Content -Path $LogFile "$Name = [$Value]"
            }
            
            Add-Content -Path $LogFile "***************************************************************************************************"
        }
        ElseIf ($BIOSresults.Component.Count -gt 1)
        {
            $FlagMultiple = $true
            
            Add-Content -Path $LogFile "***************************************************************************************************"
            
            ForEach ($item in $BIOSresults)
            {
                $MultipleCount++
                Add-Content -Path $LogFile "                                                               BIOS Details | $MultipleCount of $($BIOSresults.Component.Count)"
                Add-Content -Path $LogFile "***************************************************************************************************"
                
                ForEach ($subitem in $item.PSObject.Get_Properties())
                {
                    $Name = $($subitem).Name
                    $Value = $($subitem).Value
                    Add-Content -Path $LogFile "$Name = [$Value]"
                }
                
                Add-Content -Path $LogFile "***************************************************************************************************"
            }
        }
        
        #endregion
        
        #region Download/initiate BIOS update
        
        #=======================================================================
        # Single Update
        #=======================================================================
        
        If ($FlagSingle -eq $true)
        {
            If ($BIOSresults.VendorVersion)
            {
                If ([version]$BIOsVerison -ge [version]$($BIOSresults.VendorVersion))
                {
                    $BIOsCurrent = "Yes"
                }
                Else
                {
                    $BIOsCurrent = "No"
                }
                
                #download update
                
                If ($biosCurrent -eq "no")
                {
                    Add-Content -Path $LogFile "BIOS Current? | [No]"
                    Try
                    {
                        Invoke-WebRequest -Uri $($BIOSresults.Url) -OutFile $BIOSUpdate
                        Add-Content -Path $LogFile "Downloadubg Bios Update | [Complete]"
                    }
                    Catch
                    {
                        Add-Content -Path $LogFile "Downloading Bios Update | [Failed]"
                        Stop-Log -LogPath $LogFile
                        [Environment]::Exit
                    }
                }
                Else
                {
                    Add-Content -Path $LogFile "BIOS Current | [Yes]"
                    Add-Content -Path $LogFile "No BIOS update needed, stopping script"
                    Stop-Log -LogPath $LogFile
                    [Environment]::Exit
                }
                
                #check that the file exists
                
                $biosUpdateExists = Test-Path -Path $BIOSUpdate -ErrorAction SilentlyContinue
                
                If ($biosUpdateExists -eq $true)
                {
                    Try
                    {
                        Start-Process -FilePath $FlashExe -ArgumentList "/b=$BIOSUpdate", "/s", "/l=$BIOSUpdateLog"
                        
                        If ($?)
                        {
                            Add-Content -Path $LogFile "Running Bios Update | [Complete]"
                            #change env variable to true to tell TS to reboot
                            $tsenv.Value("BIOSinstalled") = $true
                        }
                        Else
                        {
                            Add-Content -Path $LogFile "Running Bios Update | [Failed]"
                            Stop-Log -LogPath $LogFile
                            [Environment]::Exit
                        }
                    }
                    Catch
                    {
                        Add-Content -Path $LogFile "Starting Bios Update | [Failed]"
                        Stop-Log -LogPath $LogFile
                        [Environment]::Exit
                    }
                }
                Else
                {
                    Add-Content -Path $LogFile "Bios Update Exists Check | [Failed]"
                    Stop-Log -LogPath $LogFile
                    [Environment]::Exit
                }
            }
        }
        
        #=======================================================================
        # Multiple - Search for Latest
        #=======================================================================
        
        ElseIf ($FlagMultiple -eq $true)
        {
            $Sort = $BIOSresults | Sort-Object -Property ReleaseDate -Descending
            $MostRecent = $Sort[0]
            
            If ([version]$BIOsVerison -ge [version]$($MostRecent.VendorVersion))
            {
                $BIOsCurrent = "Yes"
            }
            Else
            {
                $BIOsCurrent = "No"
            }
            
            #Download Update
            
            If ($biosCurrent -eq "no")
            {
                Add-Content -Path $LogFile "BIOS Current? | [No]"
                Try
                {
                    Invoke-WebRequest -Uri $($MostRecent.Url) -OutFile $BIOSUpdate
                    Add-Content -Path $LogFile "Downloading Bios Update | [Complete]"
                }
                Catch
                {
                    Add-Content -Path $LogFile "Downloadubg Bios Update | [Failed]"
                    Stop-Log -LogPath $LogFile
                    [Environment]::Exit
                }
            }
            Else
            {
                Add-Content -Path $LogFile "BIOS Current | [Yes]"
                Add-Content -Path $LogFile "No BIOS update needed, stopping script"
                
                Stop-Log -LogPath $LogFile
                [Environment]::Exit
            }
            #check that the file exists
            
            $biosUpdateExists = Test-Path -Path $BIOSUpdate -ErrorAction SilentlyContinue
            
            If ($biosUpdateExists -eq $true)
            {
                Try
                {
                    Start-Process -FilePath $FlashExe -ArgumentList "/b=$BIOSUpdate", "/s", "/l=$BIOSUpdateLog"
                    
                    If ($?)
                    {
                        Add-Content -Path $LogFile "Running Bios Update | [Complete]"
                        
                        #change env variable to true to tell TS to reboot
                        $tsenv.Value("BIOSinstalled") = $true
                    }
                    Else
                    {
                        Add-Content -Path $LogFile "Running Bios Update | [Failed]"
                        
                        Stop-Log -LogPath $LogFile
                        [Environment]::Exit
                    }
                }
                Catch
                {
                    Add-Content -Path $LogFile "Starting Bios Update | [Failed]"
                }
            }
            Else
            {
                Add-Content -Path $LogFile "Bios Update Exists Check | [Failed]"
                Stop-Log -LogPath $LogFile
                
                [Environment]::Exit
            }
        }
        #endregion  
    }
    Else
    {
        Add-Content -Path $LogFile "Failed to Start Log"
        Stop-Log -LogPath $LogFile
        
        [Environment]::Exit
    }
    
    Stop-Log -LogPath $LogFile
    [Environment]::Exit
}

##*=============================================
##* END INSTALLATION
##*=============================================
##*=============================================
##* END SCRIPT BODY
##*=============================================