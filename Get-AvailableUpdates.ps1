function Get-AvailableUpdates
{
<#
.Synopsis
   Initiates a "scan for updates" action and lists available patches from the configured WSUS server.
.Description
   Initiates a "scan for updates" action and lists available patches from the configured WSUS server. Result is shown in a user friendly way using color codes:
   RED | Connection / Authentication problem
   YELLOW | There is at least one available important patch
   GREEN | There isn't any available important patch
   Using the "PatchReport" switch parameter, the available patches will be shown in a popup gridview window.
.PARAMETER ComputerName
	System.Array type parameter. It accepts array of target machines stored in variables/serverlist.txt files / or it accepts lists.
    Default value is $env:computername (localhost)
.PARAMETER RAW
	Boolean type. If this switch parameter defined, then the whole object will be returned. This parameter is reserved for future use (eg: pipeing) and testing
	Default value: $false
.PARAMETER ThreadLimit
	Int type, between 1-64. This parameter specifies how many RunSpaceJobs (threads) can run paralell.
	Default value: 10.
.EXAMPLE
 C:\PS> Get-AvailableUpdates
 Description
 -----------
 This command will search for updates on the calling machine (localhost)
.EXAMPLE
 C:\PS> Get-AvailableUpdates -ComputerName $servers
 C:\PS> Get-AvailableUpdates -ComputerName (gc serverlist.txt)
 C:\PS> Get-AvailableUpdates -ComputerName "server1","server2","server3"
 Description
 -----------
 These commands will search for updates on each of the array element in the input variable, the color coded summary sheet will be shown. 
.EXAMPLE
 C:\PS> Get-AvailableUpdates -ComputerName $servers -ThreadLimit 30 -PatchReport
 Description
 -----------
 This command will search for updates on the specified target systems using 30 paralell runspaces at max. Output will be presented in a gridview window with all collected details.
.NOTES
 You need to run this function from a system with PS version 3+.
 https://msdn.microsoft.com/en-us/library/windows/desktop/aa386907(v=vs.85).aspx
 https://www.vmware.com/pdf/vmware-tools-cli.pdf
#>
[CMDletbinding()]
param (
		[Parameter(Mandatory = $false, Position = 1)]
        [alias("CN")]
		[System.Array]$ComputerName = $env:computername,

		[Parameter(Mandatory = $false)]
		[switch]$RAW = $false,
        
        [Parameter(Mandatory = $false)]
		[switch]$PatchReport = $false,

        [Parameter(Mandatory = $false)]
        [ValidateRange(1,64)]
		[int]$ThreadLimit = 10 
)

#############################################################
#PREREQUISITIES
#############################################################
$Error.clear()
$scriptstart = Get-Date

if ($PSVersionTable.psversion.major -lt 3){
    Write-Error "PowerShell version 3+ is a must to run this function. Please try using the function from a machine with the minimum supported PS version"
    break
    }

#run as admin on local?
if ($ComputerName -eq $env:computername){
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal( [Security.Principal.WindowsIdentity]::GetCurrent() )
    if (-not $currentPrincipal.IsInRole( [Security.Principal.WindowsBuiltInRole]::Administrator )) {
        Write-Error "PowerShell was not started with elevated rights, please run the function as Administrator."
        break
        }
}	

#computerlist input parameter cleanup - #uppercase servernames + space and TAB cleanup + remove empty lines + remove duplicates
Write-Verbose "Input contains $($computername.count) target systems."
$ComputerName = $ComputerName | ? {$_ -ne ""}  | % {$_.toupper().trimstart().trimend()} | select -Unique
Write-Verbose "Input contains $($ComputerName.count) valid target systems after pre-validation."

#Increasing the size of the PS console a bit, so all output can fit nicely
try{
    if ($host.UI.RawUI.BufferSize.Width -lt 150) {
        $host.UI.RawUI.BufferSize = New-Object System.Management.Automation.Host.Size(150,5000) #default 120,300
        $host.UI.RawUI.WindowSize = New-Object System.Management.Automation.Host.Size(150,60)   #default 120,50
        Write-Verbose "Powershell console Buffer and Window width increased to 150"
    }   
}
catch{ #if run from ISE it would throw an exception
    Write-Verbose "Powershell console Buffer and Window width does not need resizing."
    continue
    } 


#############################################################
#SCRIPTBLOCK which will run remotely within runspaces
##############################################################
$ScriptBlock = {
   Param (
      [string]$CompName
   )
   #PRECHECK    #Initialization + check Server remote manageability
   $error.Clear()
   $starttime = Get-Date
   $shorterr = ""
   $errcount = 0

   #Checking connection prerequisities in order (DNS -> PING -> WSMAN -> WMI -> Invoke-Command) and stop processing at the first error
   #DNS 
   try {
        [System.Net.DNS]::GetHostEntry($CompName) | Out-Null
   }
   catch {$errcount++; $shorterr = "DNS"}
   
   #PING
   if ($errcount -eq 0) {
        try {Test-Connection -ComputerName $CompName -Count 2 -ErrorAction stop | Out-Null; $mgmt += "PING - OK"}
        catch {$errcount++; $shorterr = "PING"}
   }
   
   #WSMAN
   if ($errcount -eq 0) {
        try {Test-wsman -ComputerName $CompName -ErrorAction Stop | Out-Null; $mgmt += "WSMAN - OK"}
        catch {$errcount++; $shorterr = "WSMAN"}
   }

   #WMI
   if ($errcount -eq 0) {
        try {$os = Get-WmiObject win32_operatingsystem -ComputerName $CompName -ErrorAction Stop; $mgmt += "WMI - OK"}
        catch {$errcount++; $shorterr ="WMI"}
   }

   #INVOKE-COMMAND (in case of IP address, invoke-command is not possible just with trusted hosts + https
   if ($errcount -eq 0) {
        try {Invoke-Command -ComputerName $CompName -ScriptBlock {;} -ErrorAction Stop}
        catch {$errcount++; $shorterr ="INVOKE"}
   }
   


   #Collecting error messages and skipping problematic servers from further processing
   if ($errcount -gt 0) {
     
     $RunResult = New-Object PSObject -Property @{
        ServerName = $CompName
        Manageable = $shorterr
        OS = "-"
        Important = "-"
        Optional = "-"
        Hidden = "-"
        WSUS = "-"
        PatchDetails = "-"
        PendingRestart = "-"
        Uptime = "-"
        LastPatchInstalled = "-"
        ActiveRDP = "-"
        LastSync = "-"
        VMTools = "-"
        ErrorDetails = $Error
        Runtime = ((Get-Date) - $starttime).ToString("mm\:ss\,fff").Split(",")[0]
      }
      return $RunResult
      break 
   }

   
   #if target managable, get OS version in a short form
   $osversion = $null
   switch -wildcard ($os.caption) {
            "*2003*" {$osversion += "W2003"}
            "*2008*" {$osversion += "W2008"}
            "*2012*" {$osversion += "W2012"}
            "*2016*" {$osversion += "W2016"}
   }
        
   if ($os.caption -like "*R2*") {$osversion += "R2"}
        
   switch -wildcard ($os.caption){
            "*Standard*"   {$osversion += " STD"}
            "*Enterprise*" {$osversion += " ENT"}
            "*Datacenter*" {$osversion += " DC"}
            "*Web*"        {$osversion += " WEB"}
            "*Small*"      {$osversion += " SBS"}
            "*Essential*"  {$osversion += " ESS"}
            "*Foundation*" {$osversion += " FND"}
   }

   switch -wildcard ($os.CSDVersion){
            "*1*" {$osversion += " SP1"}
            "*2*" {$osversion += " SP2"}
   }

   switch -wildcard ($os.OSArchitecture){
            "*32*" {$osversion += " x86"}
            "*64*" {$osversion += " x64"}
   }

    
    #BOOT TIME
    [datetime]$boottime = $os.ConvertToDateTime($os.lastbootuptime)
    #because servers are in different timezones, uptime is much more useful than boot time
    $uptime = (Get-Date) - $boottime
    if ($uptime.Days -gt 0) {$uptime = ($uptime.Days.ToString() + "+ days")} elseif ($uptime.TotalHours -lt 1){$uptime = $($uptime.Minutes.ToString() + "+ mins")} else {$uptime = $($uptime.Hours.ToString() + "+ hours")}

    
    #PATCH STATUS
    #Get All applicable, notinstalled updates in $SearchResult
    
    $SearchResult = Invoke-Command -ComputerName  $CompName -ScriptBlock {
        $UpdateSession = New-Object -ComObject Microsoft.Update.Session
        $UpdateSearcher = $UpdateSession.CreateUpdateSearcher()
        $SR = $UpdateSearcher.Search("IsInstalled=0")
  
        return $SR.Updates | Select `
                    @{Name="MachineName";Expression={$env:computername.ToUpper()}},`
                    @{Name='KbArticleIds';Expression={"KB" + $_.KbArticleIds}},`
                    @{Name='Title';Expression={$_.title.Split("(")[0]}},`
                    @{Name='Category';Expression={$(if (!$_.MsrcSeverity){"Optional"} else{"Important"})}},`
                    ishidden,MsrcSeverity, isdownloaded,`
                    @{Name='PublishDate';Expression={$_.LastDeploymentChangeTime.tostring("yyyy-MM-dd")}},`
                    RebootRequired,`  
                    @{Name='MoreInfoUrls';Expression={$($_.MoreInfoUrls)}},`
                    @{Name='Size';Expression={[math]::truncate($_.MaxDownloadSize / 1MB)}}
    }


    #PENDING REBOOT
    $pending = Invoke-Command -ComputerName $CompName -ScriptBlock {
        if (Get-Item "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired" -ea SilentlyContinue) {return $true} else {return $false}
    }

    #WSUS
    $wsus = Invoke-Command -ComputerName $CompName -ScriptBlock {
      (Get-ItemProperty -ea SilentlyContinue HKLM:\SOFTWARE\Policies\Microsoft\windows\WindowsUpdate -Name wuserver).wuserver
    }
      
    #LAST SUCCESSFULL PATCH INSTALLED
    $LastPatch = Invoke-Command -ComputerName $CompName -ScriptBlock {
        $LP = (Get-Content -ea SilentlyContinue "c:\windows\SoftwareDistribution\ReportingEvents.log" | findstr "Successful" | select -last 1).split("`t")[1]
        return $LP.substring(0,$LP.LastIndexOf(":"))
    }

    #LAST WSUS Sync time
    $LastSync = Invoke-Command -ComputerName $compname -ScriptBlock {
        sleep -Seconds 3 #script too fast, log is not written fast enough. Read must be delayed a bit to get uptodate info
        $wsuslog = Get-Content -LiteralPath "C:\windows\SoftwareDistribution\ReportingEvents.log" -ea SilentlyContinue | select -last 20
        $regex = "((\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2}))(.+?)Windows Update Client successfully detected (.+?)updates"
        return $(($wsuslog | Select-String -Pattern $regex)[-1].matches).groups[1].value
    }
    
    #ACTIVE RDP SESSIONS | in format: Active/Disconnected users 
    $rdp_active = 0
    $rdp_disc = 0
    try {
        query user /server:$CompName 2>&1 | select -skip 1 | foreach {
            if (($_ -split "\s+")[4] -like "Active"){$rdp_active++} else {$rdp_disc++}
        }
        $RDPsessions = "" + $rdp_active + "/" + $rdp_disc
    }
    catch {$RDPsessions = "???"}
    
    #VMTOOLS version (if applicable)
    $vmtools = Invoke-Command -ComputerName $CompName -ScriptBlock {
        if ((gwmi win32_computersystem).model -like "*VMware*") {
            if (gsv -Name vmtools){
                switch -Wildcard (& 'C:\Program Files\VMware\VMware Tools\VMwareToolboxCmd.exe' upgrade status){
                "*new*"          {"outdated"}
                "*neue *"        {"outdated"} #german
                "*up-to-date*"   {"current"}
                "*neuesten*"     {"current"} #german
                #unsupported?
                #3rd party?
                default       {return "???"}
                }
            }
            else {return "not inst"}
            }
        else {return "physical"}
    }



    #RESULT object
    $RunResult = New-Object PSObject -Property @{
      ServerName = $CompName
      Manageable = $true
      OS = $osversion
      Important = @($SearchResult | ? {$_.category -eq "Important"}).count
      Optional = @($SearchResult | ? {$_.category -eq "Optional"}).count
      Hidden = @($SearchResult | ? {$_.ishidden}).count
      WSUS = $wsus
      PatchDetails = $SearchResult
      PendingRestart = $pending
      Uptime = $uptime
      LastPatchInstalled = $LastPatch
      RDPsessions = $RDPsessions
      LastSync = $LastSync 
      VMTools = $vmtools
      ErrorDetails = $Error
      Runtime = ((Get-Date) - $starttime).ToString("mm\:ss\,fff").Split(",")[0]
      }
   Return $RunResult
}
 

#############################################################
#RUNSPACE POOL creation
#############################################################
$RunspacePool = [RunspaceFactory]::CreateRunspacePool(1, $ThreadLimit)
$RunspacePool.Open()
$Jobs = @()

foreach ($computer in $ComputerName) {
   $Job = [powershell]::Create().AddScript($ScriptBlock).AddArgument($computer)
   $Job.RunspacePool = $RunspacePool
   $Jobs += New-Object PSObject -Property @{
      Computer = $computer
      Pipe = $Job
      Result = $Job.BeginInvoke()
   }
}

#PROGRESS
Do {
   $Duration = ((get-date) - $scriptstart).ToString("mm\:ss\,fff").Split(",")[0]
   Write-Progress -Activity "Searching for updates on maximum $($ThreadLimit) parallel runspace sessions... ($($Duration))" -Status "Completed: $(($Jobs.result | Where-Object iscompleted).count) / $($ComputerName.count) servers" -PercentComplete ((($Jobs.result | Where-Object iscompleted).count + 0.001)/$ComputerName.Count*100)
   Start-Sleep -Seconds 1
} While ($Jobs.Result.IsCompleted -contains $false)

#############################################################
#Collecting results of RS jobs
#############################################################

$Results = @()
ForEach ($Job in $Jobs){
   $Results += $Job.Pipe.EndInvoke($Job.Result)
   $Job.Pipe.dispose()
}


#############################################################
#OUTPUT
#############################################################

#RAW switch parameter. Returns the whole object (for future use, eg pipe-ing and testing)
if ($RAW) {
    return $Results
}

#shorter color coded output, with an ugly workaround, shown always
$coloumnW = @(18,8,22,4,4,4,8,10,22,21,10,5,8) #width of the coloumns

#Header (yes, manually...)
Write-Host $((" "*18) + "Remote") -NoNewline
Write-Host $((" "*36) + "Pending") -NoNewline
Write-Host $((" "*33) + "Last Successful") -NoNewline
Write-Host $((" "*16) + "RDP")

Write-Host $(("ServerName" + $(" "*$coloumnW[0])).substring(0,$coloumnW[0])) -NoNewline
Write-Host $(("MGMT" + $(" "*$coloumnW[1])).Substring(0,$coloumnW[1])) -NoNewline
Write-Host $(("OSversion" + $(" "*$coloumnW[2])).Substring(0,$coloumnW[2])) -NoNewline
Write-Host $(("IMP" + $(" "*$coloumnW[3])).Substring(0,$coloumnW[3])) -NoNewline
Write-Host $(("OPT" + $(" "*$coloumnW[4])).Substring(0,$coloumnW[4])) -NoNewline
Write-Host $(("HID" + $(" "*$coloumnW[5])).Substring(0,$coloumnW[5])) -NoNewline
Write-Host $(("Restart" + $(" "*$coloumnW[6])).Substring(0,$coloumnW[6])) -NoNewline
Write-Host $(("UpTime"  + $(" "*$coloumnW[7])).Substring(0,$coloumnW[7])) -NoNewline
Write-Host $(("WSUS Server"  + $(" "*$coloumnW[8])).Substring(0,$coloumnW[8])) -NoNewline
Write-Host $(("Patch Installation" + $(" "*$coloumnW[9])).Substring(0,$coloumnW[9]))-NoNewline
Write-Host $(("VMTools" + $(" "*$coloumnW[10])).Substring(0,$coloumnW[10])) -NoNewline
Write-Host $(("A/D" + $(" "*$coloumnW[11])).Substring(0,$coloumnW[11])) -NoNewline
Write-Host $(("Runtime" + $(" "*$coloumnW[12])).Substring(0,$coloumnW[12]))
Write-Host $("-"*144) #headline separator


foreach ($result in $Results) {
    #unmanageable red servers
    if ($result.manageable -ne $true) {
        Write-Host $((($result.servername) + $(" "*$coloumnW[0])).substring(0,$coloumnW[0])) -ForegroundColor Red -NoNewline
        Write-Host $((([string]$result.manageable) + $(" "*$coloumnW[1])).substring(0,$coloumnW[1])) -ForegroundColor Red -NoNewline
        Write-Host $((($result.os) + $(" "*$coloumnW[2])).substring(0,$coloumnW[2])) -NoNewline
        Write-Host $((([string]$result.important) + $(" "*$coloumnW[3])).substring(0,$coloumnW[3])) -NoNewline
        Write-Host $((([string]$result.optional) + $(" "*$coloumnW[4])).substring(0,$coloumnW[4])) -NoNewline
        Write-Host $((([string]$result.hidden) + $(" "*$coloumnW[5])).substring(0,$coloumnW[5])) -NoNewline
        Write-Host $((([string]$result.pendingrestart) + $(" "*$coloumnW[6])).substring(0,$coloumnW[6])) -NoNewline
        Write-Host $((($result.uptime)  + $(" "*$coloumnW[7])).substring(0,$coloumnW[7])) -NoNewline
        Write-Host $((($result.wsus)  + $(" "*$coloumnW[8])).substring(0,$coloumnW[8])) -NoNewline
        Write-Host $((($result.lastpatchinstalled) + $(" "*$coloumnW[9])).substring(0,$coloumnW[9])) -NoNewline
        Write-Host $((($result.vmtools) + $(" "*$coloumnW[10])).substring(0,$coloumnW[10])) -NoNewline
        Write-Host $((($result.rdpsessions) + $(" "*$coloumnW[11])).substring(0,$coloumnW[11])) -NoNewline
        Write-Host $((($result.runtime) + $(" "*$coloumnW[12])).substring(0,$coloumnW[12]))
    }
    #Managable servers with availabe updates
    elseif ($result.important -gt 0){
        Write-Host $((($result.servername) + $(" "*$coloumnW[0])).substring(0,$coloumnW[0])) -ForegroundColor yellow -NoNewline
        Write-Host $((([string]$result.manageable) + $(" "*$coloumnW[1])).substring(0,$coloumnW[1])) -NoNewline
        Write-Host $((($result.os) + $(" "*$coloumnW[2])).substring(0,$coloumnW[2])) -NoNewline
        Write-Host $((([string]$result.important) + $(" "*$coloumnW[3])).substring(0,$coloumnW[3])) -ForegroundColor Yellow -NoNewline
        Write-Host $((([string]$result.optional) + $(" "*$coloumnW[4])).substring(0,$coloumnW[4])) -NoNewline
        Write-Host $((([string]$result.hidden) + $(" "*$coloumnW[5])).substring(0,$coloumnW[5])) -NoNewline
        Write-Host $((([string]$result.pendingrestart) + $(" "*$coloumnW[6])).substring(0,$coloumnW[6])) -NoNewline
        Write-Host $((($result.uptime)  + $(" "*$coloumnW[7])).substring(0,$coloumnW[7])) -NoNewline
        Write-Host $((($result.wsus)  + $(" "*$coloumnW[8])).substring(0,$coloumnW[8])) -NoNewline
        Write-Host $((($result.lastpatchinstalled) + $(" "*$coloumnW[9])).substring(0,$coloumnW[9])) -NoNewline
        Write-Host $((($result.vmtools) + $(" "*$coloumnW[10])).substring(0,$coloumnW[10])) -NoNewline
        Write-Host $((($result.rdpsessions) + $(" "*$coloumnW[11])).substring(0,$coloumnW[11])) -NoNewline
        Write-Host $((($result.runtime) + $(" "*$coloumnW[12])).substring(0,$coloumnW[12]))
    }
    #Managable and up-to-date servers
    else {
        Write-Host $((($result.servername) + $(" "*$coloumnW[0])).substring(0,$coloumnW[0])) -ForegroundColor Green -NoNewline
        Write-Host $((([string]$result.manageable) + $(" "*$coloumnW[1])).substring(0,$coloumnW[1])) -NoNewline
        Write-Host $((($result.os) + $(" "*$coloumnW[2])).substring(0,$coloumnW[2])) -NoNewline
        Write-Host $((([string]$result.important) + $(" "*$coloumnW[3])).substring(0,$coloumnW[3])) -ForegroundColor Green -NoNewline
        Write-Host $((([string]$result.optional) + $(" "*$coloumnW[4])).substring(0,$coloumnW[4])) -NoNewline
        Write-Host $((([string]$result.hidden) + $(" "*$coloumnW[5])).substring(0,$coloumnW[5])) -NoNewline
        Write-Host $((([string]$result.pendingrestart) + $(" "*$coloumnW[6])).substring(0,$coloumnW[6])) -NoNewline
        Write-Host $((($result.uptime)  + $(" "*$coloumnW[7])).substring(0,$coloumnW[7])) -NoNewline
        Write-Host $((($result.wsus)  + $(" "*$coloumnW[8])).substring(0,$coloumnW[8])) -NoNewline
        Write-Host $((($result.lastpatchinstalled) + $(" "*$coloumnW[9])).substring(0,$coloumnW[9])) -NoNewline
        Write-Host $((($result.vmtools) + $(" "*$coloumnW[10])).substring(0,$coloumnW[10])) -NoNewline
        Write-Host $((($result.rdpsessions) + $(" "*$coloumnW[11])).substring(0,$coloumnW[11])) -NoNewline
        Write-Host $((($result.runtime) + $(" "*$coloumnW[12])).substring(0,$coloumnW[12]))
    }
}
Write-Host $("-"*144) #bottomline separator

#Patchreport switch parameter
if ($PatchReport) {
    if (($Results | ? {$_.Manageable -ne $true}).count -gt 0) {
        Write-Host "`n$("#"*47)`nExcluded unmanageable servers from PatchReport:`n$("#"*47)"  -ForegroundColor Red
        $Results | ? {$_.Manageable -ne $true} | % { Write-Host $($_.servername) -ForegroundColor Red}
        }
    if ($Results | ? {(($_.Manageable -eq $true) -and ($_.Important -eq 0) -and ($_.Optional -eq 0) -and ($_.hidden -eq 0))}) {
        Write-Host "`n$("#"*66)`nExcluded managable servers where there isn't any available update:`n$("#"*66)" -ForegroundColor Green
        $Results | ? {(($_.Manageable -eq $true) -and ($_.Important -eq 0) -and ($_.Optional -eq 0) -and ($_.hidden -eq 0))} | %  {Write-Host $($_.servername) -ForegroundColor Green}
    }
return $($Results | ? {$_.Manageable -eq $true} | select -ExpandProperty PatchDetails) | select -ExcludeProperty PSComputerName, RunspaceId | Out-GridView -Title "Available Patch Report"
}


}#end function

