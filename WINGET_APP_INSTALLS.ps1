##*=============================================
##* ABOUT
##*=============================================

<#
.SYNOPSIS
    Installs Microsoft Store applications leveraging winget.  
.DESCRIPTION
    Installs Microsoft Store applications leveraging winget.
    The install logs can be found here - %LOCALAPPDATA%\Packages\Microsoft.DesktopAppInstaller_8wekyb3d8bbwe\LocalState\DiagOutputDir    
.NOTES
    Author:         Nathan C. Hoy (nchoy)
#>

##*=============================================
##* END ABOUT
##*=============================================

##*=============================================
##* FUNCTION LISTINGS
##*=============================================

##*=============================================
##* END FUNCTION LISTINGS
##*=============================================

##*=============================================
##* VARIABLE LISTINGS
##*=============================================

$AppName = "`"HP Smart`""

##*=============================================
##* END VARIABLE LISTINGS
##*=============================================

##*=============================================
##* SCRIPT BODY
##*=============================================

######################################
## Install Application via MS Store ##
######################################

winget install $AppName --silent --accept-package-agreements --accept-source-agreements | Out-Null

##*=============================================
##* END SCRIPT BODY
##*=============================================