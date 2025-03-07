# Port Query Part 1 - Checking for PortQryUI.exe  
$portqrypt1 = Test-Path .\PortQryUI.exe
If ($portqrypt1 -ne $true)
{
    Invoke-WebRequest -Uri "https://download.microsoft.com/download/3/f/4/3f4c6a54-65f0-4164-bdec-a3411ba24d3a/PortQryUI.exe" -OutFile ".\PortQryUI.exe"
    Write-Host "PortQryUI.exe has been downloaded succesfully" -ForegroundColor Yellow
}
Else
{
    Write-Host "PortQryUI.exe already exist" -ForegroundColor Yellow
}
# Create Folder to Store Self Extracting ZIP  
$temptest = Test-Path .\Temp
If ($temptest -ne $true)
{
    New-Item -Path . -Name "Temp" -ItemType directory -Force | Out-Null
    Write-Host "Temp folder has been generated" -ForegroundColor Yellow
}
Else
{
    Write-Host "Temp folder already exist" -ForegroundColor Yellow
}
# Port Query Part 2 - Perform Process to Generate Self Extracting ZIP  
$portqrypt2 = Test-Path .\Temp\PORTQR~1.EXE
$currentdir = Get-Location
If ($portqrypt2 -ne $true)
{
    Start-Process .\PortQryUI.exe "/C /Q /T:$currentdir\Temp" -Wait
    Write-Host "PORTQR~1.EXE has been generated" -ForegroundColor Yellow
}
Else
{
    Write-Host "PORTQR~1.EXE already exist" -ForegroundColor Yellow
}
# Port Query Part 3 - Unzip Files  
$portqrypt3 = Test-Path .\PortQry.exe
If ($portqrypt3 -ne $true)
{
    & .\Temp\PORTQR~1.EXE '/auto' $currentdir
    Write-Host "PortQry.exe has been generated" -ForegroundColor Yellow
    # Wait for Unzip to Complete  
    Start-Sleep -s 5
    # Process Stays Open, Force Closing  
    Stop-Process -Name PORTQR~1
}
Else
{
    Write-Host "PortQry.exe already exist" -ForegroundColor Yellow
}
###############################################################################################  
$choices = [System.Management.Automation.Host.ChoiceDescription[]] @("&Yes", "&No")
while ($true)
{
    # IP/FQDN of the Server  
    $destination = Read-Host "Enter destination IP or FQDN to query"
    # Specify Port or Ports  
    $ports = Read-Host "Please Enter Port(s) (ex. 80 or 80,443)"
    # Specify Protocol  
    Do
    {
        $protocol = Read-Host "Please Enter a Transport Protocol"
        If ($protocol -eq 'TCP' -or $protocol -eq 'UDP' -or $protocol -eq 'BOTH') { }
        Else { Write-Host "Invalid Protocol: Please Enter UDP, TCP or BOTH" -ForegroundColor Red }
    }
    Until ($protocol -eq 'TCP' -or $protocol -eq 'UDP' -or $protocol -eq 'BOTH')
    Write-Host "`n"
    # File Used to Store Results  
    $results = ".\logfile.txt"
    # Remove Current File to Avoid Duplication  
    If (Test-Path $results)
    {
        Remove-Item $results
    }
    # Port Query  
    (.\PortQry.exe '-n' $destination '-e' $ports '-p' $protocol | Out-String) -replace "`n" | Out-File $results -Append
    # Results of Queries Performed  
    $output = Get-Content $results | Where-Object { $_ -like '*TCP*port*' -or $_ -like '*UDP*port*' }
    # Color Coding the Results  
    # Provided by Jeff Hicks at https://www.petri.com/color-coding-with-powershell  
    foreach ($line in $output)
    {
        $params = @{ Object = $line }
        switch -Regex ($line)
        {
            "NOT LISTENING" { $params.BackgroundColor = "Red" }
            "LISTENING OR FILTERED" { $params.BackgroundColor = "DarkCyan" }
        }
        Write-Host @params
    }
    $choice = $Host.UI.PromptForChoice("Check another port?", "", $choices, 0)
    If ($choice -ne 0)
    {
        break
    }
}  