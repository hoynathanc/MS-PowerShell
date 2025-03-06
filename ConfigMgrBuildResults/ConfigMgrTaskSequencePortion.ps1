$Time = Get-Date -Format 'MMMdd_HHMMtt'
$Name = (Get-WmiObject Win32_OperatingSystem).CSName
$Make = (Get-WmiObject Win32_Bios).Manufacturer
$Model = (Get-WmiObject Win32_ComputerSystem).Model

$OSName = (Get-WmiObject Win32_OperatingSystem).Caption
$OSVersion = (Get-WmiObject Win32_OperatingSystem).Version

$BIOS_Serial = (Get-WmiObject Win32_Bios).SerialNumber
$BIOS_Version = (Get-WmiObject Win32_Bios).SMBIOSBIOSVersion

$Start_Time = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\MPSD\OSD" -Name OSDStartTime -ErrorAction SilentlyContinue
$End_Time = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\MPSD\OSD" -Name OSDEndTime -ErrorAction SilentlyContinue

$Run_Time = (NEW-TIMESPAN -Start $Start_Time -End $End_Time -ErrorAction SilentlyContinue).ToString('hh\hmm\mss\s')

$OSDUserAuth = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\MPSD\OSD" -Name OSDUserAuth -ErrorAction SilentlyContinue

Out-File -FilePath "\\FilesShare\BuildResults\$($Name)_$($Time).txt" -InputObject $Name, $Make, $Model, $OSName, $OSVersion, $BIOS_Serial, $BIOS_Version, $Run_Time, $OSDUserAuth -ErrorAction SilentlyContinue