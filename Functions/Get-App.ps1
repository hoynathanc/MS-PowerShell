Function Get-App
{
 <#
.SYNOPSIS
    Retrieves information about installed applications.  
.DESCRIPTION
    Retrieves information about installed applications by querying the registry.
    Returns information about application publisher, name & version, product code, uninstall string, install source, location, date, application architecture, etc.
.PARAMETER Product  
    The name of the application to retrieve information for. Performs a contains match on the application display name by default.
.PARAMETER Exact
    Specifies that the named application must be matched using the exact name.
.PARAMETER WildCard
    Specifies that the named application must be matched using a wildcard search.
.PARAMETER RegEx
    Specifies that the named application must be matched using a regular expression search.
.PARAMETER Excludes  
    Performs a -notmatch (!($Object.DisplayName -match $Exclude) comparison against applications found and excludes them from the results. 
.PARAMETER Computer  
    The host name of the device you are querying. Default is: $env:COMPUTERNAME
.PARAMETER Hive 
    Specifies the registry hive to search for applications. Default is: HKLM 32-Bit and 64-Bit
.EXAMPLE
    Get-App -Product Firefox
.EXAMPLE  
    Get-App -Product "Mozilla Firefox 60.0 ESR (x86 en-US)" -Exact
.EXAMPLE  
    Get-App -Product Firefox -Excludes plugin,walkme
.EXAMPLE  
    Get-App -Product Kindle -Hive HKCU
    NOTE: This will only retrieve information for the current logged-on user.
.EXAMPLE  
    Get-App -Computer NW159106 -Product Firefox -Exclude plugin,walkme      
.NOTES
    Author:         Nathan C. Hoy (nchoy)

#>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullorEmpty()]
        [string]$Product,
        [Parameter(Mandatory = $false)]
        [switch]$Exact = $false,
        [Parameter(Mandatory = $false)]
        [switch]$WildCard = $false,
        [Parameter(Mandatory = $false)]
        [switch]$RegEx = $false,
        [Parameter(Mandatory = $false)]
        [ValidateNotNullorEmpty()]
        [String[]]$Excludes,
        [Parameter(Mandatory = $false)]
        [string]$Computer = $env:COMPUTERNAME,
        [Parameter(Mandatory = $false)]
        [ValidateSet("HKLM-X86X64", "HKLM-X86", "HKLM-X64", "HKCU", "ALL", IgnoreCase)]
        [string]$Hive = "HKLM-X86X64"
    )
    
    $All_Objects = @()
    $SIDS = @("S-1-5-18", "S-1-5-19", "S-1-5-20")
    [string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
    
    If (($Hive -eq "HKLM-X86X64") -or ($Hive -eq "HKLM-X86") -or ($Hive -eq "HKLM-X64") -or ($Hive -eq "ALL"))
    {
        If (($Hive -eq "HKLM-X86X64") -or ($Hive -eq "ALL"))
        {
            $REGPATHS = @("SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall")
        }
        If ($Hive -eq "HKLM-X86")
        {
            $REGPATHS = "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
        }
        If ($Hive -eq "HKLM-X64")
        {
            $REGPATHS = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
        }
        
        ForEach ($RegPath in $RegPaths)
        {
            $HKLM = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $Computer, 'Registry64')
            $HKLM_SUBKEY = $HKLM.OpenSubKey($RegPath)
            $HKLM_SUBKEY.GetSubKeyNames() | ForEach-Object {
                $SubKey = $HKLM_SUBKEY.OpenSubKey($_)
                If ($SubKey.GetValue("DisplayName"))
                {
                    $Object = New-Object PsObject
                    $Object | Add-Member NoteProperty MachineName $Computer
                    $Object | Add-Member NoteProperty RegLocation $SubKey.Name
                    $Object | Add-Member NoteProperty PSChildName ($SubKey.Name -split '\\')[-1] ## GUID
                    
                    ForEach ($Name in $subkey.GetValueNames())
                    {
                        If ($Name -ne [string]:: Empty) <# Error Handle for Empty Values #> { $Object | Add-Member NoteProperty "$Name" $subkey.GetValue("$Name") }
                    }
                    If ($Object -ne $null) { $All_Objects += $Object }
                }
                $SubKey.Close()
            }
            $HKLM_SUBKEY.Close()
            $HKLM.Close()
        }
    }
    If (($Hive -eq "ALL") -or ($Hive -eq "HKCU"))
    {
        $HKEYUSERS = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('USERS', $Computer)
        $HKEYUSERS_ALL = $HKEYUSERS.GetSubKeyNames() | Where-Object { $_ -notin $SIDS }
        $HKEYUSERS_ALL | ForEach-Object {
            $UNINSTALL_KEY = "$_\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
            Try
            {
                $UNINSTALL_SUBKEY = $HKEYUSERS.OpenSubKey($UNINSTALL_KEY)
                If ($UNINSTALL_SUBKEY)
                {
                    $UNINSTALL_SUBKEY.GetSubKeyNames() | ForEach-Object {
                        $SUBKEY = $UNINSTALL_SUBKEY.OpenSubKey($_)
                        
                        If ($SubKey.GetValue("DisplayName"))
                        {
                            $Object = New-Object PsObject
                            $Object | Add-Member NoteProperty MachineName $Computer
                            $Object | Add-Member NoteProperty RegLocation $SubKey.Name
                            $Object | Add-Member NoteProperty PSChildName ($SubKey.Name -split '\\')[-1] ## GUID
                            
                            ForEach ($Name in $subkey.GetValueNames())
                            {
                                If ($Name -ne [string]:: Empty) <# Error Handle for Empty Values #> { $Object | Add-Member NoteProperty "$Name" $subkey.GetValue("$Name") }
                            }
                            If ($Object -ne $null) { $All_Objects += $Object }
                        }
                        $SUBKEY.Close()
                    }
                    $UNINSTALL_SUBKEY.Close()
                }
            }
            Catch ## Search was not performed with administrative/elevated rights.
            {
                If (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))
                {
                    
                }
            }
        }
        $HKEYUSERS.Close()
    }
    
    If ($All_Objects -ne $null)
    {
        ForEach ($Object in $All_Objects)
        {
            If (-not $Excludes)
            {
                If ($Exact) ## Check for an exact application name match
                {
                    If (($Object.DisplayName -eq $Product) -or ($Object.Publisher -eq $Product))
                    {
                        $Object
                    }
                }
                ElseIf ($Wildcard) ## Check for wildcard application name match
                {
                    If (($Object.DisplayName -like $Product) -or ($Object.Publisher -like $Product))
                    {
                        $Object
                    }
                }
                ElseIf ($RegEx) ## Check for a regex application name match
                {
                    If (($Object.DisplayName -match $Product) -or ($Object.Publisher -match $Product))
                    {
                        $Object
                    }
                }
                ElseIf (($Object.DisplayName -match [regex]::Escape($Product)) -or ($Object.Publisher -match [regex]::Escape($Product))) ## No Switch Parameter Specified
                {
                    $Object
                }
            }
            If ($Excludes)
            {
                [string[]]$ExcludesArray = $Excludes -Split ','
                
                If ($Exact) ## Check for an exact application name match
                {
                    If (($Object.DisplayName -eq $Product) -or ($Object.Publisher -eq $Product))
                    {
                        $ObjectPass = @()
                        ForEach ($Exclude in $ExcludesArray)
                        {
                            If (!($Object.DisplayName -match $Exclude)) { $ObjectPass += "True" }
                            ElseIf ($Object.DisplayName -match $Exclude) { $ObjectPass += "False" }
                        }
                        If ($ObjectPass -notcontains 'False')
                        {
                            $Object
                        }
                    }
                }
                ElseIf ($Wildcard) ## Check for wildcard application name match
                {
                    If (($Object.DisplayName -like $Product) -or ($Object.Publisher -like $Product))
                    {
                        $ObjectPass = @()
                        ForEach ($Exclude in $ExcludesArray)
                        {
                            If (!($Object.DisplayName -match $Exclude)) { $ObjectPass += "True" }
                            ElseIf ($Object.DisplayName -match $Exclude) { $ObjectPass += "False" }
                        }
                        If ($ObjectPass -notcontains 'False')
                        {
                            $Object
                        }
                    }
                }
                ElseIf ($RegEx) ## Check for a regex application name match
                {
                    If (($Object.DisplayName -match $Product) -or ($Object.Publisher -match $Product))
                    {
                        $ObjectPass = @()
                        ForEach ($Exclude in $ExcludesArray)
                        {
                            If (!($Object.DisplayName -match $Exclude)) { $ObjectPass += "True" }
                            ElseIf ($Object.DisplayName -match $Exclude) { $ObjectPass += "False" }
                        }
                        If ($ObjectPass -notcontains 'False')
                        {
                            $OBject
                        }
                    }
                }
                ElseIf (($Object.DisplayName -match [regex]::Escape($Product)) -or ($Object.Publisher -match [regex]::Escape($Product))) ## No Switch Parameter Specified
                {
                    $ObjectPass = @()
                    ForEach ($Exclude in $ExcludesArray)
                    {
                        If (!($Object.DisplayName -match $Exclude)) { $ObjectPass += "True" }
                        ElseIf ($Object.DisplayName -match $Exclude) { $ObjectPass += "False" }
                    }
                    If ($ObjectPass -notcontains 'False')
                    {
                        $Object
                    }
                }
            }
        }
    }
}