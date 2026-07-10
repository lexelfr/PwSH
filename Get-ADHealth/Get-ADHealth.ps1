<#
    .SYNOPSIS
    Get-ADHealth.ps1 - Active Directory Health Check Script.

    .DESCRIPTION
    This script performs a comprehensive health check of all domain controllers in a specified domain or in the entire forest.
    The results are compiled into a detailed and color-coded HTML report that can optionally be saved to file or sent via email.

    It checks the following aspects of each Domain Controller:
      - IPv4 address and site membership
      - Operation Master Roles (FSMO)
      - Operating System information and version
      - DNS resolution via Resolve-DnsName
      - ICMP Ping reachability
      - Uptime (in hours and human-readable format)
      - Free disk space on OS volume and all logical disks (in % and GB)
      - RAM: total, free (in GB), and free percentage
      - CPU: total cores, number of logical CPUs, and CPU usage (free %)
      - AD Time Synchronization offset using 'w32tm'
      - NTP time source using 'w32tm'
      - VMIC Time Provider status (VM time sync should be disabled on DCs)
      - Critical Services: DNS, Netlogon, KDC, ADWS
      - SYSVOL and NETLOGON share availability
      - Last installed hotfixes (top 5)
      - Event Log summary (Warnings, Errors, Critical in last 8h)
      - KCC events (IDs 1311 and 1566 in last 8h)
      - Replication health (pending replication count, delay, replication summary errors)
      - DCDIAG tests (full battery including FSMO check)
      - AD functional levels (forest/domain)
      - SYSVOL replication method (FRS/DFSR)
      - Tombstone lifetime value
      - Active Directory Recycle Bin status (enabled/disabled)
      - KRBTGT password age (days)
      - LDAP (port 389) and LDAPS (port 636) bind time in milliseconds
      - IPv6 status
      - DNS servers (NIC configuration)
      - DNS scavenging status
      - Pending reboot
      - NTLMv1 status
      - DNS forwarders

    .OUTPUTS
    HTML file with tabular and color-coded results, optionally saved as CSV, or sent as HTML email.

    .PARAMETER DomainName
    Specifies a single domain to test. If omitted, all domains in the forest are tested.

    .PARAMETER Server
    Specifies one or more domain controllers to test by name. If omitted, all domain controllers in the domain or forest are tested.

    .PARAMETER Report
    Saves the generated report as a local HTML file.

    .PARAMETER CSV
    Saves the generated report as a CSV file.

    .PARAMETER Email
    Sends the report as an HTML email with optional attachment.

    .EXAMPLE
    .\Get-ADHealth.ps1 -Report
    Runs the health check against all domains and domain controllers in the forest and saves a local HTML report.

    .EXAMPLE
    .\Get-ADHealth.ps1 -DomainName "mydomain.local" -Report
    Runs the health check against domain controllers in "mydomain.local" and saves a local HTML report.

    .EXAMPLE
    .\Get-ADHealth.ps1 -Server "DC01-2025" -Report
    Runs the health check against a single domain controller and saves a local HTML report.

    .EXAMPLE
    .\Get-ADHealth.ps1 -Server "DC01-2025", "DC02-2025" -Report
    Runs the health check against two specific domain controllers and saves a local HTML report.

    .EXAMPLE
    .\Get-ADHealth.ps1 -DomainName "mydomain.local" -Server "DC01-2025" -Report
    Runs the health check against a specific domain controller in the specified domain and saves a local HTML report.

    .EXAMPLEs
    .\Get-ADHealth.ps1 -CSV
    Runs the health check and saves results as a CSV file.

    .EXAMPLE
    .\Get-ADHealth.ps1 -Report -CSV
    Runs the health check and saves both HTML and CSV reports.

    .EXAMPLE
    .\Get-ADHealth.ps1 -DomainName "mydomain.local" -Email
    Runs the health check against domain controllers in "mydomain.local" and sends the report via email.

    .EXAMPLE
    .\Get-ADHealth.ps1 -Report -CSV -Email
    Runs the health check and saves both HTML and CSV reports and sends the report via email.

    .LINK
    https://www.alitajran.com/active-directory-health-check-powershell-script/

    .NOTES
    Original Author: Ali Tajran
    Website:         www.alitajran.com
    LinkedIn:        linkedin.com/in/alitajran
    X:               x.com/alitajran

    CHANGELOG
    V3.16 05/26/2026 - Major update with new tests and clear HTML report formatting.
#>

[CmdletBinding()]
Param(
    [Parameter( Mandatory = $false)]
    [string]$DomainName,

    [Parameter(Mandatory = $false)]
    [string[]]$Server,

    [Parameter( Mandatory = $false)]
    [switch]$Report,

    [Parameter( Mandatory = $false)]
    [switch]$CSV,

    [Parameter( Mandatory = $false)]
    [switch]$Email
)

# =============================================================================
# DCDIAG LANGUAGE PATTERNS
# If your DCs output DCDiag results in a language not listed below, add a new
# entry with the pass and fail strings that DCDiag outputs on your system.
#
# To find the correct strings, run this on one of your DCs:
# dcdiag
# and look for the pass/fail lines in the output, then add them below.
# =============================================================================
$dcdiagLanguages = @(
    @{ Pass = "passed test"; Fail = "failed test"; Start = "Starting test:" }                    # English
    @{ Pass = "de \S+ a r\S*ussi"; Fail = "de \S+ a \S*chou\S*"; Start = "D\S*(?:but|marrage) du test\s*:" }                 # French
    @{ Pass = "bestanden"; Fail = "nicht bestanden"; Start = "Starting test:" }                  # German
    @{ Pass = "super. la prueba"; Fail = "no super. la prueba"; Start = "Starting test:" }       # Spanish
    @{ Pass = "geslaagd voor"; Fail = "mislukt voor"; Start = "Starting test:" }                 # Dutch
    @{ Pass = "superato"; Fail = "non superato"; Start = "Starting test:" }                      # Italian
    @{ Pass = "aprovado"; Fail = "reprovado"; Start = "Starting test:" }                         # Portuguese
)
# =============================================================================

#...................................
# Global Variables
#...................................

$allTestedDomainControllers = [System.Collections.Generic.List[Object]]::new()
$now = Get-Date
$date = $now.ToShortDateString()
$reportTime = $now
$reportNameTime = $now.ToString("yyyyMMdd_HHmmss")
$localDomainName = (Get-ADDomain).DNSRoot
$reportemailsubject = "DC and AD Health Report $localDomainName"

# Script-wide counters for Dashboard
$script:totalFailCount = 0
$script:totalWarnCount = 0
$script:totalPassCount = 0
$script:totalOfflineDCs = 0

$smtpsettings = @{
    To         = 'email@domain.com'
    From       = 'adhealth@yourdomain.com'
    Subject    = "$reportemailsubject - $date"
    SmtpServer = "mail.domain.com"
    Port       = "25"
    #Credential = (Get-Credential)
    #UseSsl     = $true
}

#...................................
# Functions
#...................................

# This function gets all the domains in the forest.
Function Get-AllDomains() {
    $allDomains = (Get-ADForest).Domains
    return $allDomains
}

# This function gets all the domain controllers in a specified domain.
Function Get-AllDomainControllers ($ComputerName) {
    $allDomainControllers = Get-ADDomainController -Filter * -Server $ComputerName | Sort-Object HostName
    return $allDomainControllers
}

# This function tests the domain controller against DNS.
Function Get-DomainControllerNSLookup($ComputerName) {
    try {
        $null = Resolve-DnsName $ComputerName -Type A -ErrorAction Stop
        return "Passed"
    }
    catch {
        return "Failed"
    }
}

# This function tests the connectivity to the domain controller.
Function Get-DomainControllerPingStatus($ComputerName) {
    if ((Test-Connection $ComputerName -Count 1 -quiet) -eq $True) {
        $domainControllerPingStatus = "Passed"
    }
    else {
        $domainControllerPingStatus = "Failed"
    }
    return $domainControllerPingStatus
}

# This function tests the domain controller uptime.
Function Get-DomainControllerUpTime($ComputerName, $IsReachable) {
    $result = @{
        Hours    = "Unreachable"
        Friendly = "Unreachable"
    }

    if ($IsReachable) {
        try {
            $W32OS = Get-CimInstance -ClassName Win32_OperatingSystem -ComputerName $ComputerName -ErrorAction Stop
            $bootTime = $W32OS.LastBootUpTime
            $uptime = (Get-Date) - $bootTime
            $result.Hours = [math]::Round($uptime.TotalHours)
            $result.Friendly = "{0} days, {1} hours" -f $uptime.Days, $uptime.Hours
        }
        catch {
            $result.Hours = "CIM Error"
            $result.Friendly = "CIM Error"
        }
    }
    return $result
}

# This function checks the time synchronization offset.
function Get-TimeDifference($ComputerName, $IsReachable) {
    if ($IsReachable) {
        try {
            $output = & w32tm /stripchart /computer:$ComputerName /samples:1 /dataonly 2>$null
            if ($output -and $output.Count -gt 0 -and $output[-1] -match ',') {
                $currentTime, $timeDifference = $output[-1].Trim("s") -split ',\s*'
                $diff = [Math]::Abs([double]$timeDifference)
                $diffRounded = [Math]::Round($diff, 1, [MidPointRounding]::AwayFromZero)
            }
            else {
                $diffRounded = "Error"
            }
        }
        catch {
            $diffRounded = "Error"
        }
    }
    else {
        $diffRounded = "Unreachable"
    }
    return $diffRounded
}

# This function checks the NTP time source configured on the domain controller
Function Get-NTPSource($ComputerName, $IsReachable) {
    if (-not $IsReachable) { return "Unreachable" }
    try {
        $output = & w32tm /query /computer:$ComputerName /source 2>$null
        if ($output) {
            $source = $output.Trim()
            return $source
        }
        else {
            return "No Data"
        }
    }
    catch {
        return "Failed"
    }
}

# This function checks VMICTimeProvider status on the domain controller
Function Get-VMICTimeProviderStatus($ComputerName, $IsReachable) {
    if (-not $IsReachable) { return "Unreachable" }
    try {
        $output = & w32tm /query /computer:$ComputerName /configuration 2>$null
        if (-not $output) { return "No Data" }

        $foundVMIC = $false
        foreach ($line in $output) {
            if ($line -match "VMICTimeProvider") {
                $foundVMIC = $true
                continue
            }
            if ($foundVMIC -and $line -match "Enabled:\s+(\d+)") {
                $enabled = [int]$matches[1]
                if ($enabled -eq 0) { return "Disabled" } else { return "Enabled" }
            }
        }
        return "No Data"
    }
    catch {
        return "Error"
    }
}

# This function checks the DNS and Netlogon service status and the domain role of the domain controller
Function Get-DomainControllerServices($ComputerName, $IsReachable) {
    $thisDomainControllerServicesTestResult = [PSCustomObject]@{
        DNSService      = "Unreachable"
        DCRole          = "Unreachable"
        NETLOGONService = "Unreachable"
    }

    if ($IsReachable) {
        # DNS Service check
        try {
            $dnsService = Get-CimInstance -ClassName Win32_Service -ComputerName $ComputerName -Filter "Name='DNS'" -ErrorAction Stop
            if ($dnsService -and $dnsService.State -eq 'Running') {
                $thisDomainControllerServicesTestResult.DNSService = "Passed"
            }
            elseif ($dnsService) {
                $thisDomainControllerServicesTestResult.DNSService = "Failed"
            }
            else {
                $thisDomainControllerServicesTestResult.DNSService = "Not Installed"
            }
        }
        catch {
            $thisDomainControllerServicesTestResult.DNSService = "CIM Error"
        }

        # Domain Role
        try {
            $domainRoleNum = (Get-CimInstance -ClassName Win32_ComputerSystem -ComputerName $ComputerName -ErrorAction Stop).DomainRole
            $thisDomainControllerServicesTestResult.DCRole = switch ($domainRoleNum) {
                0 { 'Standalone Workstation' }
                1 { 'Member Workstation' }
                2 { 'Standalone Server' }
                3 { 'Member Server' }
                4 { 'Backup Domain Controller' }
                5 { 'Primary Domain Controller' }
                default { 'Unknown' }
            }
        }
        catch {
            $thisDomainControllerServicesTestResult.DCRole = 'Unknown'
        }

        # Netlogon
        try {
            $netlogon = Get-CimInstance -ClassName Win32_Service -ComputerName $ComputerName -Filter "Name='Netlogon'" -ErrorAction Stop
            $thisDomainControllerServicesTestResult.NETLOGONService = if ($netlogon -and $netlogon.State -eq 'Running') { 'Passed' } else { 'Failed' }
        }
        catch {
            $thisDomainControllerServicesTestResult.NETLOGONService = 'CIM Error'
        }
    }
    return $thisDomainControllerServicesTestResult
}

# This function runs the DCDiag tests against a domain controller and returns the results.
Function Get-DomainControllerDCDiagTestResults($ComputerName, $IsReachable, $Languages) {
    $DCDiagTestResults = [PSCustomObject]@{
        "DCDIAG: Connectivity"            = $null
        "DCDIAG: Advertising"             = $null
        "DCDIAG: FrsEvent"                = $null
        "DCDIAG: DFSREvent"               = $null
        "DCDIAG: SysVolCheck"             = $null
        "DCDIAG: KccEvent"                = $null
        "DCDIAG: FSMO KnowsOfRoleHolders" = $null
        "DCDIAG: MachineAccount"          = $null
        "DCDIAG: NCSecDesc"               = $null
        "DCDIAG: NetLogons"               = $null
        "DCDIAG: ObjectsReplicated"       = $null
        "DCDIAG: Replications"            = $null
        "DCDIAG: RidManager"              = $null
        "DCDIAG: Services"                = $null
        "DCDIAG: SystemLog"               = $null
        "DCDIAG: VerifyReferences"        = $null
        "DCDIAG: CheckSDRefDom"           = $null
        "DCDIAG: CrossRefValidation"      = $null
        "DCDIAG: LocatorCheck"            = $null
        "DCDIAG: Intersite"               = $null
        "DCDIAG: FSMO Check"              = $null
    }

    if (-not $IsReachable) {
        foreach ($property in $DCDiagTestResults.PSObject.Properties.Name) {
            $DCDiagTestResults.$property = "Unreachable"
        }
        return $DCDiagTestResults
    }

    try {
        $job = Start-Job -ScriptBlock {
            param($dc)
            # Set console output encoding to the system's OEM code page
            $oemPage = [System.Globalization.CultureInfo]::CurrentCulture.TextInfo.OEMCodePage
            if ($oemPage) {
                [Console]::OutputEncoding = [System.Text.Encoding]::GetEncoding($oemPage)
            }
            $params = @(
                "/s:$dc",
                "/test:Connectivity",
                "/test:Advertising",
                "/test:FrsEvent",
                "/test:DFSREvent",
                "/test:SysVolCheck",
                "/test:KccEvent",
                "/test:KnowsOfRoleHolders",
                "/test:MachineAccount",
                "/test:NCSecDesc",
                "/test:NetLogons",
                "/test:ObjectsReplicated",
                "/test:Replications",
                "/test:RidManager",
                "/test:Services",
                "/test:SystemLog",
                "/test:VerifyReferences",
                "/test:CheckSDRefDom",
                "/test:CrossRefValidation",
                "/test:LocatorCheck",
                "/test:Intersite",
                "/test:FSMOCheck"
            )
            Dcdiag.exe @params 2>&1
        } -ArgumentList $ComputerName

        if (Wait-Job $job -Timeout 60) {
            $outputLines = Receive-Job $job
            Remove-Job $job -Force

            $TestName = $null
            $TestStatus = $null

            # Auto-detect language from output
            $detectedPattern = $Languages | Where-Object {
                $outputLines | Select-String -Pattern $_.Pass -Quiet
            } | Select-Object -First 1

            # Fallback to English if nothing detected
            if (-not $detectedPattern) {
                $detectedPattern = $Languages[0]
            }

            $passPattern = $detectedPattern.Pass
            $failPattern = $detectedPattern.Fail
            $startPattern = if ($detectedPattern.Start) { $detectedPattern.Start } else { "Starting test:" }

            $outputLines -split '[\r\n]' | ForEach-Object {
                switch -Regex ($_) {
                    "$startPattern" {
                        $TestName = ($_ -replace ".*$startPattern").Trim()
                    }
                    "$failPattern" {
                        $TestStatus = "Failed"
                    }
                    "$passPattern" {
                        $TestStatus = "Passed"
                    }
                }
                if ($TestName -and $TestStatus) {
                    $property = switch ($TestName) {
                        "KnowsOfRoleHolders" { "DCDIAG: FSMO KnowsOfRoleHolders" }
                        "FSMOCheck" { "DCDIAG: FSMO Check" }
                        default { "DCDIAG: $TestName" }
                    }
                    if ($DCDiagTestResults.PSObject.Properties.Name -contains $property) {
                        $DCDiagTestResults.$property = $TestStatus
                    }
                    $TestName = $null
                    $TestStatus = $null
                }
            }

            # If all results are null, dcdiag likely failed to start or run tests
            $allNull = $true
            foreach ($prop in $DCDiagTestResults.PSObject.Properties.Name) {
                if ($null -ne $DCDiagTestResults.$prop) {
                    $allNull = $false
                    break
                }
            }
            if ($allNull) {
                try {
                    $debugDir = $PSScriptRoot
                    if (-not $debugDir) { $debugDir = $pwd.Path }
                    $debugFilePath = Join-Path $debugDir "dcdiag_debug_$ComputerName.txt"
                    $outputLines | Out-File -FilePath $debugFilePath -Encoding utf8 -Force
                    Write-Host "  [!] DCDIAG parsing failed for $ComputerName. Raw output written to: $debugFilePath" -ForegroundColor Yellow
                }
                catch {}

                $err = ($outputLines | Where-Object { $_.ToString().Trim() } | Select-Object -First 1)
                $errMsg = if ($err) { $err.ToString().Trim() } else { "No Output" }
                if ($errMsg -match "not recognized|command not found") {
                    $errMsg = "DCDIAG not found (RSAT missing)"
                }
                elseif ($errMsg -match "Access is denied") {
                    $errMsg = "Access Denied"
                }
                foreach ($property in $DCDiagTestResults.PSObject.Properties.Name) {
                    $DCDiagTestResults.$property = "Error: $errMsg"
                }
            }
        }
        else {
            Stop-Job $job | Out-Null
            Remove-Job $job -Force
            foreach ($property in $DCDiagTestResults.PSObject.Properties.Name) {
                $DCDiagTestResults.$property = "Timeout"
            }
        }
    }
    catch {
        foreach ($property in $DCDiagTestResults.PSObject.Properties.Name) {
            $DCDiagTestResults.$property = "Error"
        }
    }

    return $DCDiagTestResults
}

# This function checks whether IPv6 is enabled on the DC network adapters
Function Get-IPv6Status($ComputerName, $IsReachable) {
    if (-not $IsReachable) { return "Unreachable" }
    try {
        $adapters = Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration `
            -ComputerName $ComputerName -ErrorAction Stop |
        Where-Object { $_.IPEnabled -eq $true }
        $hasIPv6 = $adapters | Where-Object { $_.IPAddress -match ":" }
        if ($hasIPv6) { return "Enabled" } else { return "Disabled" }
    }
    catch { return "Error" }
}

# This function checks whether DNS scavenging is enabled on the DC
Function Get-DNSScavengingStatus($ComputerName, $IsReachable) {
    if (-not $IsReachable) { return "Unreachable" }
    try {
        $dns = Get-CimInstance -Namespace root\MicrosoftDNS -ClassName MicrosoftDNS_Server `
            -ComputerName $ComputerName -ErrorAction Stop
        if ($null -eq $dns) { return "No DNS Role" }
        if ($dns.ScavengingInterval -gt 0) {
            return "Enabled ($($dns.ScavengingInterval)h)"
        }
        else {
            return "Disabled"
        }
    }
    catch {
        $msg = $_.Exception.Message
        if ($msg -match "Invalid namespace") { return "Error: Invalid Namespace" }
        elseif ($msg -match "Access denied") { return "Error: Access Denied" }
        elseif ($msg -match "RPC server is unavailable") { return "Error: RPC Unavailable" }
        else { return "Error: $($msg)" }
    }
}

# This function checks whether the DC has a pending reboot
Function Get-PendingReboot($ComputerName, $IsReachable) {
    if (-not $IsReachable) { return "Unreachable" }
    try {
        $rebootKeys = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            $keys = @(
                "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending",
                "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired",
                "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\PendingFileRenameOperations"
            )
            $pending = $false
            foreach ($key in $keys) {
                if (Test-Path $key) { $pending = $true; break }
            }
            return $pending
        } -ErrorAction Stop
        if ($rebootKeys) { return "Pending" } else { return "No" }
    }
    catch { return "Error" }
}

# This function checks whether NTLMv1 is enabled on the DC (should be disabled)
Function Get-NTLMv1Status($ComputerName, $IsReachable) {
    if (-not $IsReachable) { return "Unreachable" }
    try {
        $val = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
            (Get-ItemProperty -Path $regPath -Name "LmCompatibilityLevel" -ErrorAction SilentlyContinue).LmCompatibilityLevel
        } -ErrorAction Stop

        # If not configured, Server 2008+ defaults to level 3
        if ($null -eq $val) { $val = 3 }

        if ($val -le 2) { return "Enabled (Level $val)" }
        elseif ($val -eq 3) { return "Partial (Level 3)" }
        else { return "Disabled (Level $val)" }
    }
    catch { return "Error" }
}

# This function retrieves the DNS forwarders configured on the DC
Function Get-DNSForwarders($ComputerName, $IsReachable) {
    if (-not $IsReachable) { return "Unreachable" }
    try {
        $dns = Get-CimInstance -Namespace root\MicrosoftDNS -ClassName MicrosoftDNS_Server `
            -ComputerName $ComputerName -ErrorAction Stop
        if ($dns.Forwarders -and $dns.Forwarders.Count -gt 0) {
            return ($dns.Forwarders -join "<br>")
        }
        else {
            return "None configured"
        }
    }
    catch { return "Error" }
}

# This function retrieves the DNS servers configured on the DCs network adapters
Function Get-NICDNSServers($ComputerName, $IsReachable) {
    if (-not $IsReachable) { return "Unreachable" }
    try {
        $adapters = Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration `
            -ComputerName $ComputerName -ErrorAction Stop |
        Where-Object { $_.IPEnabled -eq $true -and $_.DNSServerSearchOrder }

        if ($adapters) {
            $ips = $adapters | ForEach-Object { $_.DNSServerSearchOrder } | Select-Object -Unique
            return ($ips -join "<br>")
        }
        else {
            return "None configured"
        }
    }
    catch { return "Error" }
}

# This function returns free space on the OS drive as a percentage
Function Get-DomainControllerOSDriveFreeSpace ($ComputerName, $IsReachable) {
    $percentFree = 'Unreachable'
    if ($IsReachable) {
        try {
            $os = Get-CimInstance -ClassName Win32_OperatingSystem -ComputerName $ComputerName -ErrorAction Stop
            $driveLetter = $os.SystemDrive
            $disk = Get-CimInstance -ClassName Win32_LogicalDisk -ComputerName $ComputerName -Filter "DeviceID='$driveLetter'" -ErrorAction Stop
            if ($disk.Size -gt 0) {
                $percentFree = [math]::Round($disk.FreeSpace / $disk.Size * 100, 1)
            }
        }
        catch {
            $percentFree = 'CIM Error'
        }
    }
    return $percentFree
}

# This function returns free space on the OS drive in GB
Function Get-DomainControllerOSDriveFreeSpaceGB ($ComputerName, $IsReachable) {
    $freeGB = 'Unreachable'
    if ($IsReachable) {
        try {
            $os = Get-CimInstance -ClassName Win32_OperatingSystem -ComputerName $ComputerName -ErrorAction Stop
            $driveLetter = $os.SystemDrive
            $disk = Get-CimInstance -ClassName Win32_LogicalDisk -ComputerName $ComputerName -Filter "DeviceID='$driveLetter'" -ErrorAction Stop
            if ($disk.FreeSpace -gt 0) {
                $freeGB = [math]::Round($disk.FreeSpace / 1GB, 2)
            }
        }
        catch {
            $freeGB = 'CIM Error'
        }
    }
    return $freeGB
}

# This function retrieves total RAM, free RAM in GB, and free RAM percentage
Function Get-DomainControllerMemoryInfo($ComputerName, $IsReachable) {
    $memInfo = @{
        TotalGB     = "Unreachable"
        FreeGB      = "Unreachable"
        FreePercent = "Unreachable"
    }

    if ($IsReachable) {
        try {
            $os = Get-CimInstance -ClassName Win32_OperatingSystem -ComputerName $ComputerName -ErrorAction Stop
            # TotalVisibleMemorySize and FreePhysicalMemory are in KB; convert to GB.
            # FreePhysicalMemory can include standby cache and exceed TotalVisibleMemorySize,
            # so cap it to avoid reporting more than 100% free.
            $totalKB = $os.TotalVisibleMemorySize
            $freeKB = [math]::Min($os.FreePhysicalMemory, $totalKB)
            $total = [math]::Round($totalKB / 1MB, 1)
            $free = [math]::Round($freeKB / 1MB, 1)
            $percent = if ($totalKB -gt 0) { [math]::Round(($freeKB / $totalKB) * 100, 1) } else { 0 }

            $memInfo.TotalGB = $total
            $memInfo.FreeGB = $free
            $memInfo.FreePercent = $percent
        }
        catch {
            $memInfo.TotalGB = "CIM Error"
            $memInfo.FreeGB = "CIM Error"
            $memInfo.FreePercent = "CIM Error"
        }
    }

    return $memInfo
}

# Helper function to generate cell HTML and update status counters
Function Get-CellHtml($class, $content) {
    if ($class -eq "fail") { $script:totalFailCount++ }
    elseif ($class -eq "warn") { $script:totalWarnCount++ }
    elseif ($class -eq "pass") { $script:totalPassCount++ }
    
    if ($class) {
        return "<td class='$class'>$content</td>"
    } else {
        return "<td>$content</td>"
    }
}

# This function returns a color-coded HTML table cell based on the value and field name
Function New-ServerHealthHTMLTableCell($lineitem, $reportline) {
    $value = $reportline."$lineitem"

    if ($null -eq $value) { return (Get-CellHtml "info" "N/A") }

    $valueStr = "$value".Trim()

    # Specific handling for "Replication Summary (num errors)"
    if ($lineitem -eq "Replication Summary (num errors)") {
        if ([int]::TryParse($valueStr, [ref]$null)) {
            $cls = if ([int]$valueStr -gt 0) { 'fail' } else { 'pass' }
            return (Get-CellHtml $cls $valueStr)
        }
        else {
            return (Get-CellHtml "info" $valueStr)
        }
    }
    if ($lineitem -eq "Replication Pending") {
        if ([int]::TryParse($valueStr, [ref]$null)) {
            $cls = if ([int]$valueStr -gt 0) { 'warn' } else { 'pass' }
            return (Get-CellHtml $cls $valueStr)
        }
        else {
            return (Get-CellHtml "info" $valueStr)
        }
    }
    if ($lineitem -eq "SYSVOL Replication Method") {
        switch ($valueStr.ToUpper()) {
            "FRS" { return (Get-CellHtml "warn" "FRS") }
            "DFSR" { return (Get-CellHtml "pass" "DFSR") }
            default { return (Get-CellHtml "info" $valueStr) }
        }
    }

    switch ($valueStr) {
        "passed" { return (Get-CellHtml "pass" "Passed") }
        "failed" { return (Get-CellHtml "fail" "Failed") }
        "warning" { return (Get-CellHtml "warn" "Warning") }
        "not installed" { return (Get-CellHtml "info" "Not Installed") }
        "n/a" { return (Get-CellHtml "info" "N/A") }
        "no data" { return (Get-CellHtml "info" "No Data") }
        "unreachable" { return (Get-CellHtml "info" "Unreachable") }
        "cim error" { return (Get-CellHtml "fail" "CIM Error") }
        "error" { return (Get-CellHtml "fail" "Error") }
        "timeout" { return (Get-CellHtml "info" "Timeout") }
    }

    # Handle generic numeric values
    if ([double]::TryParse($valueStr, [System.Globalization.NumberStyles]::Any, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$null)) {
        $numVal = [double]$valueStr
        switch -regex ($lineitem) {
            "RAM Free \(\%\)" { $cls = if ($numVal -lt 10) { 'fail' } elseif ($numVal -lt 20) { 'warn' } else { 'pass' } }
            "RAM Free \(GB\)" { $cls = if ($numVal -lt 2) { 'fail' } elseif ($numVal -lt 4) { 'warn' } else { 'pass' } }
            "RAM Total \(GB\)" { $cls = if ($numVal -lt 4) { 'fail' } elseif ($numVal -lt 8) { 'warn' } else { 'pass' } }
            "CPU Free \(\%\)" { $cls = if ($numVal -lt 10) { 'fail' } elseif ($numVal -lt 30) { 'warn' } else { 'pass' } }
            "CPU Total Cores" { $cls = if ($numVal -lt 2) { 'fail' } elseif ($numVal -lt 4) { 'warn' } else { 'pass' } }
            "CPU Total CPUs" { $cls = if ($numVal -lt 2) { 'fail' } elseif ($numVal -lt 4) { 'warn' } else { 'pass' } }
            "Events Warning" { $cls = if ($numVal -gt 100) { 'fail' } elseif ($numVal -gt 10) { 'warn' } else { 'pass' } }
            "Events Error" { $cls = if ($numVal -gt 50) { 'fail' } elseif ($numVal -gt 5) { 'warn' } else { 'pass' } }
            "Events Critical" { $cls = if ($numVal -gt 10) { 'fail' } elseif ($numVal -gt 1) { 'warn' } else { 'pass' } }
            "KCC Events" { $cls = if ($numVal -gt 12) { 'fail' } elseif ($numVal -gt 0) { 'warn' } else { 'pass' } }
            "Max Replication Delay" { $cls = if ($numVal -gt 12) { 'fail' } elseif ($numVal -gt 1) { 'warn' } else { 'pass' } }
            default { $cls = "info" }
        }
        return (Get-CellHtml $cls $valueStr)
    }

    if ($lineitem -eq "NTP Source") {
        $lower = $valueStr.ToLower()
        if ($lower -eq "unreachable") { return (Get-CellHtml "info" "Unreachable") }
        if ($lower -eq "fail") { return (Get-CellHtml "fail" "Fail") }
        if ($lower -match "local cmos|free-running") { return (Get-CellHtml "fail" $valueStr) }
        if ($lower -match "vm ic time") { return (Get-CellHtml "warn" $valueStr) }
        return (Get-CellHtml "pass" $valueStr)
    }

    if ($lineitem -eq "Tombstone Lifetime") {
        if ($valueStr -match "(\d+)") {
            $days = [int]$matches[1]
            $cls = if ($days -gt 180) { 'warn' } else { 'pass' }
            return (Get-CellHtml $cls $valueStr)
        }
        elseif ($valueStr -like "Not Defined*") {
            return (Get-CellHtml "info" $valueStr)
        }
        elseif ($valueStr -like "Error*") {
            return (Get-CellHtml "fail" $valueStr)
        }
        else {
            return (Get-CellHtml "" $valueStr)
        }
    }
    return (Get-CellHtml "" $valueStr)
}

# This function retrieves free space (GB and %) for all fixed logical disks
Function Get-DomainControllerAllDisksInfo($ComputerName, $IsReachable) {
    $result = @()

    if ($IsReachable) {
        try {
            $logicalDisks = Get-CimInstance -ClassName Win32_LogicalDisk -ComputerName $ComputerName -Filter "DriveType=3" -ErrorAction Stop
            foreach ($disk in $logicalDisks) {
                $device = $disk.DeviceID
                $freeGB = [math]::Round($disk.FreeSpace / 1GB, 2)
                $percentFree = if ($disk.Size -gt 0) { [math]::Round(($disk.FreeSpace / $disk.Size) * 100, 1) } else { 0 }
                $result += "$device - ${freeGB}GB (${percentFree}%)"
            }
        }
        catch {
            $result = @("CIM Error")
        }
    }
    else {
        $result = @("Unreachable")
    }

    return ($result -join '<br>')
}

# This function checks the CPU information
Function Get-DomainControllerCPUInfo($ComputerName, $IsReachable) {
    $cpuInfo = @{
        TotalCores     = "Unreachable"
        TotalCPUs      = "Unreachable"
        CPUFreePercent = "Unreachable"
    }

    if ($IsReachable) {
        try {
            $cpuList = @(Get-CimInstance -ClassName Win32_Processor -ComputerName $ComputerName -ErrorAction Stop)
            $totalCores = ($cpuList | Measure-Object -Property NumberOfCores -Sum).Sum
            $totalCPUs = ($cpuList | Measure-Object -Property NumberOfLogicalProcessors -Sum).Sum
            $avgLoad = ($cpuList | Measure-Object -Property LoadPercentage -Average).Average
            $freePercent = [math]::Round(100 - $avgLoad, 1)

            $cpuInfo.TotalCores = $totalCores
            $cpuInfo.TotalCPUs = $totalCPUs
            $cpuInfo.CPUFreePercent = $freePercent
        }
        catch {
            $cpuInfo.TotalCores = "CIM Error"
            $cpuInfo.TotalCPUs = "CIM Error"
            $cpuInfo.CPUFreePercent = "CIM Error"
        }
    }

    return $cpuInfo
}

# This function measures LDAP and LDAPS bind time in milliseconds
Function Get-LDAPBindTime($ComputerName, $IsReachable) {
    $result = @{
        LDAP  = "Unreachable"
        LDAPS = "Unreachable"
    }

    if (-not $IsReachable) {
        return $result
    }

    # LDAP (389)
    try {
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $entry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$ComputerName")
        $null = $entry.NativeObject
        $sw.Stop()
        $entry.Dispose()
        $result.LDAP = [int]$sw.ElapsedMilliseconds
    }
    catch {
        $result.LDAP = "Error"
    }

    # LDAPS (636)
    try {
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $entry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://${ComputerName}:636")
        $null = $entry.NativeObject
        $sw.Stop()
        $entry.Dispose()
        $result.LDAPS = [int]$sw.ElapsedMilliseconds
    }
    catch {
        $result.LDAPS = "Error"
    }

    return $result
}

# This function returns a count of Warning, Error, and Critical events from the System log in the last 8 hours
Function Get-EventSummaryLast8h($ComputerName, $IsReachable) {
    # Check if computer is unreachable
    if (-not $IsReachable) {
        return @{ Warning = "Unreachable"; Error = "Unreachable"; Critical = "Unreachable" }
    }

    # Initialize empty hashtable without default 0s
    $result = @{}

    # Computer is reachable, query events
    try {
        $result.Warning = (Get-WinEvent -ComputerName $ComputerName -FilterHashtable @{
                LogName = 'System'; Level = 3; StartTime = (Get-Date).AddHours(-8)
            } -ErrorAction SilentlyContinue | Measure-Object).Count

        $result.Error = (Get-WinEvent -ComputerName $ComputerName -FilterHashtable @{
                LogName = 'System'; Level = 2; StartTime = (Get-Date).AddHours(-8)
            } -ErrorAction SilentlyContinue | Measure-Object).Count

        $result.Critical = (Get-WinEvent -ComputerName $ComputerName -FilterHashtable @{
                LogName = 'System'; Level = 1; StartTime = (Get-Date).AddHours(-8)
            } -ErrorAction SilentlyContinue | Measure-Object).Count
    }
    catch {
        return @{ Warning = "Error"; Error = "Error"; Critical = "Error" }
    }

    return $result
}

# This function returns the number of pending inbound replication operations using repadmin
Function Get-PendingReplicationCount($ComputerName, $IsReachable) {
    if ($IsReachable) {
        try {
            $pending = repadmin /queue /server:$ComputerName | Select-String "pending" | ForEach-Object {
                if ($_ -match "\s+(\d+)\s+pending") { return [int]$matches[1] }
            }
            return ($pending | Measure-Object -Sum).Sum
        }
        catch {
            return "Error"
        }
    }
    else {
        return "Unreachable"
    }
}

# This function retrieves the last 5 installed hotfixes with their installation dates
Function Get-LastInstalledHotFix($ComputerName, $IsReachable) {
    $latest = "Unreachable"
    if ($IsReachable) {
        try {
            $latestFixes = Get-HotFix -ComputerName $ComputerName | Sort-Object -Property InstalledOn -Descending | Select-Object -First 5
            $latest = ($latestFixes | ForEach-Object {
                    $dateStr = if ($_.InstalledOn) { $_.InstalledOn.ToShortDateString() } else { 'N/A' }
                    "$($_.HotFixID) - $dateStr"
                }) -join "<br>"
        }
        catch {
            $latest = "CIM Error"
        }
    }
    return $latest
}

# This function checks SYSVOL and NETLOGON share accessibility over SMB
Function Test-SysvolNetlogonShare($ComputerName, $IsReachable) {
    $result = @{
        SYSVOL   = "Unreachable"
        NETLOGON = "Unreachable"
    }
    if ($IsReachable) {
        $result.SYSVOL = if (Test-Path "\\$ComputerName\SYSVOL") { "Passed" } else { "Failed" }
        $result.NETLOGON = if (Test-Path "\\$ComputerName\NETLOGON") { "Passed" } else { "Failed" }
    }
    return $result
}

# This function returns the replication summary error count using repadmin
Function Get-ReplicationSummaryStatus($ComputerName, $IsReachable) {
    if ($IsReachable) {
        try {
            $repl = repadmin /replsummary /bydest /errorsonly /server:$ComputerName 2>$null

            # Find lines with errors and count them
            $errors = $repl | Where-Object { $_ -match "^\s*\S+\s+\S+\s+(\d+)\s*/\s*(\d+)" } |
            ForEach-Object {
                if ($_ -match "^\s*\S+\s+\S+\s+(\d+)\s*/\s*(\d+)") {
                    [int]$matches[1]
                }
            }

            return ($errors | Measure-Object -Sum).Sum
        }
        catch {
            return "Error"
        }
    }
    else {
        return "Unreachable"
    }
}

# This function checks the KDC service status
Function Get-KDCServiceStatus($ComputerName, $IsReachable) {
    if ($IsReachable) {
        try {
            $svc = Get-CimInstance -ClassName Win32_Service -ComputerName $ComputerName -Filter "Name='KDC'" -ErrorAction Stop
            if ($svc.State -eq 'Running') {
                return "Passed"
            }
            else {
                return "Failed"
            }
        }
        catch {
            return "CIM Error"
        }
    }
    else {
        return "Unreachable"
    }
}

# This function detects whether SYSVOL is replicated via DFSR or the legacy FRS service
Function Get-SYSVOLReplicationMethod($ComputerName, $IsReachable) {
    # The most reliable indicator is which replication service is actually running.
    # DFSR (Distributed File System Replication) replaced FRS (File Replication Service)
    # starting with Windows Server 2008. Both services can exist on the same DC during
    # migration, so we check DFSR first as the preferred state.
    if ($IsReachable) {
        try {
            $services = Get-CimInstance -ClassName Win32_Service -ComputerName $ComputerName `
                -Filter "Name='DFSR' OR Name='NtFrs'" -ErrorAction Stop

            $dfsr = $services | Where-Object { $_.Name -eq 'DFSR' }
            $ntfrs = $services | Where-Object { $_.Name -eq 'NtFrs' }

            if ($dfsr -and $dfsr.State -eq 'Running') {
                return "DFSR"
            }
            elseif ($ntfrs -and $ntfrs.State -eq 'Running') {
                return "FRS"
            }
            elseif ($dfsr) {
                # DFSR exists but not running - likely stopped post-migration
                return "DFSR"
            }
            elseif ($ntfrs) {
                return "FRS"
            }
            else {
                return "No Data"
            }
        }
        catch {
            return "Error"
        }
    }
    else {
        return "Unreachable"
    }
}

# This function retrieves the tombstone lifetime value in days from the AD configuration partition
Function Get-TombstoneLifetime {
    try {
        # Use the same AD cmdlet path that returns expected values in this environment
        $configNC = (Get-ADRootDSE -ErrorAction Stop).configurationNamingContext
        $configDN = "CN=Directory Service,CN=Windows NT,CN=Services,$configNC"

        # Retrieve the object containing the tombstoneLifetime attribute
        $obj = Get-ADObject -Identity $configDN -Properties tombstoneLifetime -ErrorAction Stop

        if ($obj.tombstoneLifetime) {
            return "$($obj.tombstoneLifetime) days"
        }
        else {
            return "Not Defined (default 180)"
        }
    }
    catch {
        return "Error"
    }
}

# This function checks whether Active Directory Recycle Bin is enabled in the forest
Function Get-ADRecycleBinStatus {
    try {
        $feature = Get-ADOptionalFeature -Identity 'Recycle Bin Feature' -ErrorAction Stop
        if ($feature.EnabledScopes -and $feature.EnabledScopes.Count -gt 0) {
            return 'Enabled'
        }
        else {
            return 'Disabled'
        }
    }
    catch {
        return 'Error'
    }
}

# This function returns KRBTGT password age in days for a given domain
Function Get-KRBTGTPasswordAge($DomainFqdn) {
    try {
        $krbtgt = Get-ADUser -Server $DomainFqdn -Identity 'krbtgt' -Properties PasswordLastSet -ErrorAction Stop
        if ($krbtgt.PasswordLastSet) {
            $ageDays = [math]::Round(((Get-Date) - $krbtgt.PasswordLastSet).TotalDays, 0)
            return "$ageDays days"
        }
        else {
            return 'Never Set'
        }
    }
    catch {
        return 'Error'
    }
}

# This function checks whether the Active Directory Web Services (ADWS) service is running
Function Get-ADWSStatus($ComputerName, $IsReachable) {
    if ($IsReachable) {
        try {
            $svc = Get-CimInstance -ComputerName $ComputerName -ClassName Win32_Service -Filter "Name = 'ADWS'" -ErrorAction Stop
            if ($null -eq $svc) {
                return 'Not Installed'
            }
            elseif ($svc.State -eq 'Running') {
                return 'Passed'
            }
            else {
                return "Failed"
            }
        }
        catch {
            return 'CIM Error'
        }
    }
    else {
        return 'Unreachable'
    }
}

# This function counts KCC error events (IDs 1311 and 1566) in the Directory Service log in the last 8 hours
Function Get-KCCEvents($ComputerName, $IsReachable) {
    if (-not $IsReachable) { return "Unreachable" }
    try {
        $count = (Get-WinEvent -ComputerName $ComputerName -FilterHashtable @{
                LogName   = 'Directory Service'
                Id        = 1311, 1566
                StartTime = (Get-Date).AddHours(-8)
            } -ErrorAction SilentlyContinue | Measure-Object).Count
        return $count
    }
    catch {
        return "Error"
    }
}

# This function returns the maximum replication delay in hours across all replication partners using repadmin
Function Get-ReplicationDelays($ComputerName, $IsReachable) {
    if (-not $IsReachable) { return "Unreachable" }

    try {
        # Check if repadmin is available
        if (-not (Get-Command repadmin -ErrorAction SilentlyContinue)) {
            return "Error: repadmin missing"
        }

        $repl = repadmin /showrepl $ComputerName /csv 2>$null | ConvertFrom-Csv
        if (-not $repl) { return "No Data" }

        $delays = [System.Collections.Generic.List[double]]::new()
        foreach ($row in $repl) {
            $lastSuccessStr = $row.'Last Success Time'
            if ($lastSuccessStr -and $lastSuccessStr.Trim() -ne "") {
                try {
                    # Attempt culture-flexible cast first (handles local/PowerShell system dates)
                    $lastSuccess = [datetime]$lastSuccessStr
                    $hours = [math]::Round(((Get-Date) - $lastSuccess).TotalHours, 1)
                    $delays.Add($hours)
                }
                catch {
                    try {
                        # Fallback to Invariant Culture parse (handles ISO/US date strings)
                        $lastSuccess = [datetime]::Parse($lastSuccessStr, [System.Globalization.CultureInfo]::InvariantCulture)
                        $hours = [math]::Round(((Get-Date) - $lastSuccess).TotalHours, 1)
                        $delays.Add($hours)
                    }
                    catch {
                        # Skip row if date is completely unparseable
                    }
                }
            }
        }

        if ($delays.Count -gt 0) {
            return ($delays | Sort-Object -Descending | Select-Object -First 1)
        }

        return "No Data"
    }
    catch {
        return "Error: $($_.Exception.Message)"
    }
}

# This function returns a CSS color class (pass/warn/fail/info) based on the AD functional level string
Function Get-FunctionalLevelClass($level) {
    switch ($level) {
        "Windows2003Forest" { return "fail" }
        "Windows2003Domain" { return "fail" }
        "Windows2008Forest" { return "warn" }
        "Windows2008Domain" { return "warn" }
        "Windows2008R2Forest" { return "warn" }
        "Windows2008R2Domain" { return "warn" }
        "Windows2012Forest" { return "pass" }
        "Windows2012Domain" { return "pass" }
        "Windows2012R2Forest" { return "pass" }
        "Windows2012R2Domain" { return "pass" }
        "Windows2016Forest" { return "pass" }
        "Windows2016Domain" { return "pass" }
        "Windows2019Forest" { return "pass" }
        "Windows2019Domain" { return "pass" }
        "Windows2022Forest" { return "pass" }
        "Windows2022Domain" { return "pass" }
        default { return "info" }
    }
}

if (!($DomainName)) {
    Write-Host "No domain specified, using all domains in forest" -ForegroundColor Cyan
    $allDomains = Get-AllDomains
    $reportName = 'forest_health_report_' + (Get-ADForest).name + '_' + $reportNameTime + '.html'
}
else {
    Write-Host "Domain name specified on cmdline" -ForegroundColor Cyan
    $allDomains = $DomainName
    $reportName = 'dc_health_report_' + $DomainName + '_' + $reportNameTime + '.html'
}

Write-Host "Checking tombstone lifetime (forest-wide)...." -ForegroundColor Cyan
$tombstoneLifetime = Get-TombstoneLifetime

Write-Host "Checking AD Recycle Bin status (forest-wide)...." -ForegroundColor Cyan
$recycleBinStatus = Get-ADRecycleBinStatus

foreach ($domain in $allDomains) {
    Write-Host "Testing domain" $domain -ForegroundColor Green
    $allDomainControllers = Get-AllDomainControllers $domain
    Write-Host "Checking KRBTGT password age for domain $domain..." -ForegroundColor Cyan
    $krbtgtPasswordAge = Get-KRBTGTPasswordAge -DomainFqdn $domain

    # Force array first, then get count
    $allDomainControllers = @($allDomainControllers)

    # Filter to specific DCs if -Server parameter was provided
    if ($Server) {
        $allDomainControllers = $allDomainControllers | Where-Object {
            $hn = $_.HostName
            $Server | Where-Object { $hn -like "*$_*" }
        }
        if ($allDomainControllers.Count -eq 0) {
            Write-Host "ERROR: No domain controllers found matching: $($Server -join ', ')" -ForegroundColor Red
            Write-Host "Please check the server name(s) and try again." -ForegroundColor Red
            exit
        }
    }

    $totalDCs = $allDomainControllers.Count

    # Initialize counter for display
    $currentDCNumber = 0

    foreach ($domainController in $allDomainControllers) {
        $currentDCNumber++
        $stopWatch = [system.diagnostics.stopwatch]::StartNew()
        $dcReachable = (Test-Connection $domainController.HostName -Count 1 -Quiet)
        if (-not $dcReachable) {
            $script:totalOfflineDCs++
        }
        Write-Host "Testing domain controller ($currentDCNumber of $totalDCs) $($domainController.HostName)" -ForegroundColor Cyan

        # Connectivity
        Write-Host "[$($domainController.HostName)] Checking IPv6 status..." -ForegroundColor Cyan
        $ipv6Status = Get-IPv6Status $domainController.HostName $dcReachable

        Write-Host "[$($domainController.HostName)] Checking DNS servers..." -ForegroundColor Cyan
        $nicDNS = Get-NICDNSServers $domainController.HostName $dcReachable

        Write-Host "[$($domainController.HostName)] Checking DNS forwarders..." -ForegroundColor Cyan
        $dnsForwarders = Get-DNSForwarders $domainController.HostName $dcReachable

        Write-Host "[$($domainController.HostName)] Checking DNS scavenging..." -ForegroundColor Cyan
        $dnsScavenging = Get-DNSScavengingStatus $domainController.HostName $dcReachable

        Write-Host "[$($domainController.HostName)] Checking pending reboot..." -ForegroundColor Cyan
        $pendingReboot = Get-PendingReboot $domainController.HostName $dcReachable

        Write-Host "[$($domainController.HostName)] Checking NTP source..." -ForegroundColor Cyan
        $ntpSource = Get-NTPSource $domainController.HostName $dcReachable

        Write-Host "[$($domainController.HostName)] Checking VMIC time provider..." -ForegroundColor Cyan
        $vmicStatus = Get-VMICTimeProviderStatus $domainController.HostName $dcReachable

        Write-Host "[$($domainController.HostName)] Checking LDAP and LDAPS bind time..." -ForegroundColor Cyan
        $ldapBind = Get-LDAPBindTime $domainController.HostName $dcReachable

        Write-Host "[$($domainController.HostName)] Checking NTLMv1 status..." -ForegroundColor Cyan
        $ntlmv1Status = Get-NTLMv1Status $domainController.HostName $dcReachable

        # Hardware / OS
        Write-Host "[$($domainController.HostName)] Checking uptime..." -ForegroundColor Cyan
        $uptimeResult = Get-DomainControllerUpTime $domainController.HostName $dcReachable

        Write-Host "[$($domainController.HostName)] Checking memory info..." -ForegroundColor Cyan
        $mem = Get-DomainControllerMemoryInfo $domainController.HostName $dcReachable

        Write-Host "[$($domainController.HostName)] Checking CPU info..." -ForegroundColor Cyan
        $cpu = Get-DomainControllerCPUInfo $domainController.HostName $dcReachable

        # Services
        Write-Host "[$($domainController.HostName)] Checking services (DNS, NetLogon, Domain Role)..." -ForegroundColor Cyan
        $svcResult = Get-DomainControllerServices $domainController.HostName $dcReachable

        Write-Host "[$($domainController.HostName)] Checking KDC service..." -ForegroundColor Cyan
        $kdcStatus = Get-KDCServiceStatus $domainController.HostName $dcReachable

        Write-Host "[$($domainController.HostName)] Checking ADWS service..." -ForegroundColor Cyan
        $adwsStatus = Get-ADWSStatus $domainController.HostName $dcReachable

        # DCDIAG
        Write-Host "[$($domainController.HostName)] Running DCDiag tests..." -ForegroundColor Cyan
        $DCDiagTestResults = Get-DomainControllerDCDiagTestResults $domainController.HostName $dcReachable $dcdiagLanguages

        # Events
        Write-Host "[$($domainController.HostName)] Checking event summary (last 8h)..." -ForegroundColor Cyan
        $eventSummary = Get-EventSummaryLast8h $domainController.HostName $dcReachable

        Write-Host "[$($domainController.HostName)] Checking KCC events (1311, 1566) in last 8h..." -ForegroundColor Cyan
        $kccEvents = Get-KCCEvents $domainController.HostName $dcReachable

        # Replication
        Write-Host "[$($domainController.HostName)] Checking pending replication..." -ForegroundColor Cyan
        $replicationPending = Get-PendingReplicationCount $domainController.HostName $dcReachable

        Write-Host "[$($domainController.HostName)] Checking accessibility to SYSVOL and NETLOGON..." -ForegroundColor Cyan
        $tempShares = Test-SysvolNetlogonShare $domainController.HostName $dcReachable

        Write-Host "[$($domainController.HostName)] Checking replication summary (num errors)..." -ForegroundColor Cyan
        $replSummary = Get-ReplicationSummaryStatus $domainController.HostName $dcReachable

        Write-Host "[$($domainController.HostName)] Checking max replication delay..." -ForegroundColor Cyan
        $maxDelay = Get-ReplicationDelays $domainController.HostName $dcReachable

        Write-Host "[$($domainController.HostName)] Checking SYSVOL replication method..." -ForegroundColor Cyan
        $sysvolMethod = Get-SYSVOLReplicationMethod $domainController.HostName $dcReachable

        # Info
        Write-Host "[$($domainController.HostName)] Checking latest hotfixes..." -ForegroundColor Cyan
        $latestHotfix = Get-LastInstalledHotFix $domainController.HostName $dcReachable

        $thisDomainController = [PSCustomObject]@{
            # Identity
            Server                             = ($domainController.HostName).ToLower()
            Site                               = $domainController.Site
            "OS Version"                       = $domainController.OperatingSystem
            "OS Build"                         = "Build $($domainController.OperatingSystemVersion)"
            "IPv4 Address"                     = $domainController.IPv4Address
            "Operation Master Roles"           = ($domainController.OperationMasterRoles | ForEach-Object { $_ }) -join '<br>'
            # Connectivity
            "Ping"                             = Get-DomainControllerPingStatus $domainController.HostName
            "IPv6 Status"                      = $ipv6Status
            "DNS Servers"                      = $nicDNS
            "DNS Forwarders"                   = $dnsForwarders
            "DNS Resolution"                   = Get-DomainControllerNSLookup $domainController.HostName
            "DNS Scavenging"                   = $dnsScavenging
            "Pending Reboot"                   = $pendingReboot
            "Time Offset (seconds)"            = Get-TimeDifference $domainController.HostName $dcReachable
            "NTP Source"                       = $ntpSource
            "VMIC Time Provider"               = $vmicStatus
            "LDAP Bind (ms)"                   = $ldapBind["LDAP"]
            "LDAPS Bind (ms)"                  = $ldapBind["LDAPS"]
            # Hardware / OS
            "Uptime (hours)"                   = $uptimeResult.Hours
            "Uptime (friendly)"                = $uptimeResult.Friendly
            "OS Free Space (%)"                = Get-DomainControllerOSDriveFreeSpace $domainController.HostName $dcReachable
            "OS Free Space (GB)"               = Get-DomainControllerOSDriveFreeSpaceGB $domainController.HostName $dcReachable
            "RAM Total (GB)"                   = $mem["TotalGB"]
            "RAM Free (GB)"                    = $mem["FreeGB"]
            "RAM Free (%)"                     = $mem["FreePercent"]
            "CPU Total Cores"                  = $cpu["TotalCores"]
            "CPU Total CPUs"                   = $cpu["TotalCPUs"]
            "CPU Free (%)"                     = $cpu["CPUFreePercent"]
            "Disks Info"                       = Get-DomainControllerAllDisksInfo $domainController.HostName $dcReachable
            # Services
            "DNS Service"                      = $svcResult.DNSService
            "Domain Role"                      = $svcResult.DCRole
            "NetLogon Service"                 = $svcResult.NETLOGONService
            "KDC Service"                      = $kdcStatus
            "ADWS Service"                     = $adwsStatus
            # DCDIAG
            "DCDIAG: Connectivity"             = $DCDiagTestResults."DCDIAG: Connectivity"
            "DCDIAG: Advertising"              = $DCDiagTestResults."DCDIAG: Advertising"
            "DCDIAG: FrsEvent"                 = $DCDiagTestResults."DCDIAG: FrsEvent"
            "DCDIAG: DFSREvent"                = $DCDiagTestResults."DCDIAG: DFSREvent"
            "DCDIAG: SysVolCheck"              = $DCDiagTestResults."DCDIAG: SysVolCheck"
            "DCDIAG: KccEvent"                 = $DCDiagTestResults."DCDIAG: KccEvent"
            "DCDIAG: FSMO KnowsOfRoleHolders"  = $DCDiagTestResults."DCDIAG: FSMO KnowsOfRoleHolders"
            "DCDIAG: MachineAccount"           = $DCDiagTestResults."DCDIAG: MachineAccount"
            "DCDIAG: NCSecDesc"                = $DCDiagTestResults."DCDIAG: NCSecDesc"
            "DCDIAG: NetLogons"                = $DCDiagTestResults."DCDIAG: NetLogons"
            "DCDIAG: ObjectsReplicated"        = $DCDiagTestResults."DCDIAG: ObjectsReplicated"
            "DCDIAG: Replications"             = $DCDiagTestResults."DCDIAG: Replications"
            "DCDIAG: RidManager"               = $DCDiagTestResults."DCDIAG: RidManager"
            "DCDIAG: Services"                 = $DCDiagTestResults."DCDIAG: Services"
            "DCDIAG: SystemLog"                = $DCDiagTestResults."DCDIAG: SystemLog"
            "DCDIAG: VerifyReferences"         = $DCDiagTestResults."DCDIAG: VerifyReferences"
            "DCDIAG: CheckSDRefDom"            = $DCDiagTestResults."DCDIAG: CheckSDRefDom"
            "DCDIAG: CrossRefValidation"       = $DCDiagTestResults."DCDIAG: CrossRefValidation"
            "DCDIAG: LocatorCheck"             = $DCDiagTestResults."DCDIAG: LocatorCheck"
            "DCDIAG: Intersite"                = $DCDiagTestResults."DCDIAG: Intersite"
            "DCDIAG: FSMO Check"               = $DCDiagTestResults."DCDIAG: FSMO Check"
            # Events
            "Events Warning (8h)"              = $eventSummary.Warning
            "Events Error (8h)"                = $eventSummary.Error
            "Events Critical (8h)"             = $eventSummary.Critical
            "KCC Events (8h)"                  = $kccEvents
            # Replication
            "Replication Pending"              = $replicationPending
            "SYSVOL Share"                     = $tempShares.SYSVOL
            "NETLOGON Share"                   = $tempShares.NETLOGON
            "Replication Summary (num errors)" = $replSummary
            "Max Replication Delay (h)"        = $maxDelay
            # AD Health
            "SYSVOL Replication Method"        = $sysvolMethod
            "Tombstone Lifetime"               = $tombstoneLifetime
            "AD Recycle Bin"                   = $recycleBinStatus
            "KRBTGT Password Age"              = $krbtgtPasswordAge
            "NTLMv1 Status"                    = $ntlmv1Status
            # Info
            "Latest Hotfix"                    = $latestHotfix
            "Processing Time (seconds)"        = [math]::Round($stopWatch.Elapsed.TotalSeconds)
        }

        $allTestedDomainControllers.Add($thisDomainController)
    }
}

$htmlhead = @"
<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<title>Rapport d'Etat Active Directory</title>
<style>
:root {
  --bg-color: #f8f9fa;
  --text-color: #212529;
  --card-bg: #ffffff;
  --border-color: #dee2e6;
  --header-bg: #f1f3f5;
  --color-pass: #d4edda;
  --color-pass-text: #155724;
  --color-warn: #fff3cd;
  --color-warn-text: #856404;
  --color-fail: #f8d7da;
  --color-fail-text: #721c24;
  --color-info: #e2e3e5;
  --color-info-text: #383d41;
}

@media (prefers-color-scheme: dark) {
  :root {
    --bg-color: #121212;
    --text-color: #e0e0e0;
    --card-bg: #1e1e1e;
    --border-color: #333333;
    --header-bg: #2d2d2d;
    --color-pass: #1b4d22;
    --color-pass-text: #a3e635;
    --color-warn: #5c4d0f;
    --color-warn-text: #fbbf24;
    --color-fail: #6b1d1d;
    --color-fail-text: #fca5a5;
    --color-info: #2d3748;
    --color-info-text: #cbd5e0;
  }
}

body {
  font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
  background-color: var(--bg-color);
  color: var(--text-color);
  margin: 0;
  padding: 24px;
  line-height: 1.5;
}

h1 { font-size: 24px; font-weight: 700; margin: 0 0 6px 0; }
h2 { font-size: 18px; font-weight: 600; margin: 24px 0 12px 0; border-bottom: 2px solid var(--border-color); padding-bottom: 6px; }
h3 { font-size: 14px; font-weight: 600; color: #6c757d; margin: 0 0 24px 0; }

/* Dashboard Cards Layout */
.dashboard {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: 16px;
  margin-bottom: 24px;
}
.card {
  background: var(--card-bg);
  border: 1px solid var(--border-color);
  border-radius: 8px;
  padding: 16px;
  box-shadow: 0 2px 4px rgba(0,0,0,0.02);
}
.card-title { font-size: 11px; text-transform: uppercase; color: #868e96; font-weight: 700; letter-spacing: 0.5px; }
.card-value { font-size: 26px; font-weight: 700; margin-top: 4px; }

/* Table Wrapper for Horizontal Scroll */
.table-container {
  overflow-x: auto;
  border: 1px solid var(--border-color);
  border-radius: 8px;
  background: var(--card-bg);
  margin-bottom: 24px;
  box-shadow: 0 4px 6px rgba(0,0,0,0.02);
}

table {
  width: 100%;
  border-collapse: collapse;
  font-size: 13px;
  text-align: left;
}

th, td {
  padding: 10px 14px;
  border-bottom: 1px solid var(--border-color);
  border-right: 1px solid var(--border-color);
  word-wrap: break-word;
  overflow-wrap: break-word;
}

th {
  background-color: var(--header-bg);
  font-weight: 600;
}

/* Sticky Headers and Columns for Browser view */
thead th {
  position: sticky;
  top: 0;
  z-index: 10;
}

tr.section-header td {
  background-color: var(--header-bg);
  font-weight: 700;
  text-transform: uppercase;
  font-size: 11px;
  letter-spacing: 0.8px;
  color: #868e96;
  border-bottom: 2px solid var(--border-color);
  padding: 12px 14px;
}

/* First column: field name */
td:first-child, th:first-child {
  position: sticky;
  left: 0;
  background: var(--card-bg);
  font-weight: 600;
  z-index: 5;
  min-width: 240px;
  border-right: 2px solid var(--border-color);
}

tr:hover td { background-color: rgba(0,0,0,0.02); }

/* Color statuses */
td.pass { background-color: var(--color-pass) !important; color: var(--color-pass-text) !important; }
td.warn { background-color: var(--color-warn) !important; color: var(--color-warn-text) !important; }
td.fail { background-color: var(--color-fail) !important; color: var(--color-fail-text) !important; }
td.info { background-color: var(--color-info) !important; color: var(--color-info-text) !important; }

/* Sub-badges for nested metrics (e.g. disks) */
.badge-pass { background-color: var(--color-pass); color: var(--color-pass-text); font-weight: 600; border-radius: 4px; padding: 2px 6px; display: inline-block; }
.badge-warn { background-color: var(--color-warn); color: var(--color-warn-text); font-weight: 600; border-radius: 4px; padding: 2px 6px; display: inline-block; }
.badge-fail { background-color: var(--color-fail); color: var(--color-fail-text); font-weight: 600; border-radius: 4px; padding: 2px 6px; display: inline-block; }
.badge-info { background-color: var(--color-info); color: var(--color-info-text); font-weight: 600; border-radius: 4px; padding: 2px 6px; display: inline-block; }

/* Legend Table styling */
.legend-table {
  margin-top: 15px;
  width: 100%;
}
.legend-table td {
  padding: 8px 12px;
}
</style>
</head>
<body>
<h1>Rapport d'Etat de Sant&eacute; Active Directory</h1>
<h3>G&eacute;n&eacute;r&eacute; le : $reportTime</h3>
"@

$forest = Get-ADForest
$domain = Get-ADDomain

$forestLevel = $forest.ForestMode.ToString()
$domainLevel = $domain.DomainMode.ToString()

$forestClass = Get-FunctionalLevelClass $forestLevel
$domainClass = Get-FunctionalLevelClass $domainLevel

$htmlFunctionalLevels = @"
<h2>Niveau Fonctionnel de l'Environnement</h2>
<div style="max-width: 500px; margin-bottom: 24px; border: 1px solid var(--border-color); border-radius: 8px; overflow: hidden; background: var(--card-bg);">
  <table style="width: 100%; border-collapse: collapse; margin: 0;">
    <thead>
      <tr style="background-color: var(--header-bg); border-bottom: 1px solid var(--border-color);">
        <th style="padding: 10px 14px; text-align: left; font-weight: 600;">Description</th>
        <th style="padding: 10px 14px; text-align: left; font-weight: 600;">Niveau</th>
      </tr>
    </thead>
    <tbody>
      <tr style="border-bottom: 1px solid var(--border-color);">
        <td style="padding: 10px 14px;">Forest Functional Level</td>
        <td class="$forestClass" style="padding: 10px 14px;">$forestLevel</td>
      </tr>
      <tr>
        <td style="padding: 10px 14px;">Domain Functional Level</td>
        <td class="$domainClass" style="padding: 10px 14px;">$domainLevel</td>
      </tr>
    </tbody>
  </table>
</div>
"@

# Build transposed table: fields as rows, DCs as columns
$serverhealthhtmltable = "
<h2>Forest: $($forest.Name)</h2>
<div class='table-container'>
<table>
<thead>
<tr><th style='text-align: left;'>Field</th>"


# Table header: server names as columns
foreach ($dc in $allTestedDomainControllers) {
    $serverhealthhtmltable += "<th style='text-align: center;'>$($dc.Server)</th>"
}
$serverhealthhtmltable += "</tr></thead><tbody>"

# Get all field names from the first DC (all DCs share the same property set)
$allFields = $allTestedDomainControllers[0].PSObject.Properties.Name

# Define categories and fields for visual grouping
$categories = @(
    [PSCustomObject]@{
        Name = "Identit&eacute; & Configuration"
        Fields = @("Server", "Site", "OS Version", "OS Build", "IPv4 Address", "Operation Master Roles")
    }
    [PSCustomObject]@{
        Name = "Connectivit&eacute; & R&eacute;seau"
        Fields = @("Ping", "IPv6 Status", "DNS Servers", "DNS Forwarders", "DNS Resolution", "DNS Scavenging", "Pending Reboot", "Time Offset (seconds)", "NTP Source", "VMIC Time Provider", "LDAP Bind (ms)", "LDAPS Bind (ms)")
    }
    [PSCustomObject]@{
        Name = "Performances & Mat&eacute;riel"
        Fields = @("Uptime (hours)", "Uptime (friendly)", "OS Free Space (%)", "OS Free Space (GB)", "RAM Total (GB)", "RAM Free (GB)", "RAM Free (%)", "CPU Total Cores", "CPU Total CPUs", "CPU Free (%)", "Disks Info")
    }
    [PSCustomObject]@{
        Name = "Services de Base AD"
        Fields = @("DNS Service", "Domain Role", "NetLogon Service", "KDC Service", "ADWS Service")
    }
    [PSCustomObject]@{
        Name = "Tests DCDIAG"
        Fields = @(
            "DCDIAG: Connectivity", "DCDIAG: Advertising", "DCDIAG: FrsEvent", "DCDIAG: DFSREvent",
            "DCDIAG: SysVolCheck", "DCDIAG: KccEvent", "DCDIAG: FSMO KnowsOfRoleHolders",
            "DCDIAG: MachineAccount", "DCDIAG: NCSecDesc", "DCDIAG: NetLogons", "DCDIAG: ObjectsReplicated",
            "DCDIAG: Replications", "DCDIAG: RidManager", "DCDIAG: Services", "DCDIAG: SystemLog",
            "DCDIAG: VerifyReferences", "DCDIAG: CheckSDRefDom", "DCDIAG: CrossRefValidation",
            "DCDIAG: LocatorCheck", "DCDIAG: Intersite", "DCDIAG: FSMO Check"
        )
    }
    [PSCustomObject]@{
        Name = "&Eacute;v&eacute;nements & Journaux (8h)"
        Fields = @("Events Warning (8h)", "Events Error (8h)", "Events Critical (8h)", "KCC Events (8h)")
    }
    [PSCustomObject]@{
        Name = "R&eacute;plication & Partages"
        Fields = @("Replication Pending", "SYSVOL Share", "NETLOGON Share", "Replication Summary (num errors)", "Max Replication Delay (h)", "SYSVOL Replication Method")
    }
    [PSCustomObject]@{
        Name = "S&eacute;curit&eacute; & Param&egrave;tres Globaux"
        Fields = @("Tombstone Lifetime", "AD Recycle Bin", "KRBTGT Password Age", "NTLMv1 Status")
    }
    [PSCustomObject]@{
        Name = "Informations Syst&egrave;me"
        Fields = @("Latest Hotfix", "Processing Time (seconds)")
    }
)

foreach ($cat in $categories) {
    # Filter fields to only those present in $allFields
    $fieldsToRender = $cat.Fields | Where-Object { $allFields -contains $_ }
    if ($fieldsToRender.Count -gt 0) {
        $serverhealthhtmltable += "<tr class='section-header'><td colspan='$($allTestedDomainControllers.Count + 1)'>$($cat.Name)</td></tr>"
        foreach ($field in $fieldsToRender) {
            $serverhealthhtmltable += "<tr><td>$field</td>"
            foreach ($dc in $allTestedDomainControllers) {
                switch ($field) {

            "IPv4 Address" {
                $ip = $dc.'IPv4 Address'
                $serverhealthhtmltable += "<td>$ip</td>"
                continue
            }

            "Ping" {
                $val = $dc.'Ping'
                $cls = switch ($val.ToLower()) {
                    "passed" { "pass" }
                    "failed" { "fail" }
                    "unreachable" { "info" }
                    default { "info" }
                }
                $serverhealthhtmltable += "<td class='$cls'>$val</td>"
                continue
            }

            "DNS Resolution" {
                $val = $dc.'DNS Resolution'
                $cls = switch ($val.ToLower()) {
                    "passed" { "pass" }
                    "failed" { "fail" }
                    "unreachable" { "info" }
                    default { "info" }
                }
                $serverhealthhtmltable += "<td class='$cls'>$val</td>"
                continue
            }

            "Uptime (hours)" {
                $hoursStr = ($dc.'Uptime (hours)' -replace ',', '.').Trim()
                [double]$hours = 0
                if ([double]::TryParse($hoursStr, [System.Globalization.NumberStyles]::Any, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$hours)) {
                    $days = [math]::Round($hours / 24)
                    $colorClass = if ($days -gt 60) { 'fail' } elseif ($days -gt 30) { 'warn' } else { 'pass' }
                    $serverhealthhtmltable += "<td class='$colorClass'>$hours</td>"
                }
                else {
                    $serverhealthhtmltable += "<td class='info'>$($dc.'Uptime (hours)')</td>"
                }
                continue
            }

            "Uptime (friendly)" {
                $hoursStr = ($dc.'Uptime (hours)' -replace ',', '.').Trim()
                [double]$hours = 0
                if ([double]::TryParse($hoursStr, [System.Globalization.NumberStyles]::Any, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$hours)) {
                    $days = [math]::Round($hours / 24)
                    $friendly = $dc.'Uptime (friendly)'
                    $colorClass = if ($days -gt 60) { 'fail' } elseif ($days -gt 30) { 'warn' } else { 'pass' }
                    $serverhealthhtmltable += "<td class='$colorClass'>$friendly</td>"
                }
                else {
                    $serverhealthhtmltable += "<td class='info'>$($dc.'Uptime (friendly)')</td>"
                }
                continue
            }

            "OS Free Space (%)" {
                $percentStr = ($dc.'OS Free Space (%)' -replace ',', '.').Trim()
                [double]$percent = 0
                if ([double]::TryParse($percentStr, [System.Globalization.NumberStyles]::Any, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$percent)) {
                    $colorClass = if ($percent -lt 5) { 'fail' } elseif ($percent -lt 15) { 'warn' } else { 'pass' }
                    $serverhealthhtmltable += "<td class='$colorClass'>$percent%</td>"
                }
                else {
                    $serverhealthhtmltable += "<td class='info'>$($dc.'OS Free Space (%)')</td>"
                }
                continue
            }

            "OS Free Space (GB)" {
                $percentStr = ($dc.'OS Free Space (%)' -replace ',', '.').Trim()
                $gbStr = ($dc.'OS Free Space (GB)' -replace ',', '.').Trim()
                [double]$percent = 0
                [double]$gbVal = 0
                if ([double]::TryParse($percentStr, [System.Globalization.NumberStyles]::Any, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$percent) -and [double]::TryParse($gbStr, [System.Globalization.NumberStyles]::Any, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$gbVal)) {
                    $colorClass = if ($percent -lt 5) { 'fail' } elseif ($percent -lt 15) { 'warn' } else { 'pass' }
                    $serverhealthhtmltable += "<td class='$colorClass'>$gbVal GB</td>"
                }
                else {
                    $serverhealthhtmltable += "<td class='info'>$($dc.'OS Free Space (GB)')</td>"
                }
                continue
            }

            "Time offset (seconds)" {
                $offsetStr = ($dc.'Time offset (seconds)' -replace ',', '.').Trim()
                [double]$offset = 0
                $offsetOk = [double]::TryParse($offsetStr, [System.Globalization.NumberStyles]::Any, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$offset)
                if (-not $offsetOk) {
                    $serverhealthhtmltable += "<td class='info'>$($dc.'Time offset (seconds)')</td>"
                }
                else {
                    $colorClass = if ($offset -gt 5) { 'fail' } elseif ($offset -gt 1) { 'warn' } else { 'pass' }
                    $serverhealthhtmltable += "<td class='$colorClass'>$offset sec</td>"
                }
                continue
            }

            "Disks Info" {
                $disksValue = $dc.'Disks Info'
                if ($disksValue.ToLower() -eq "unreachable") {
                    $serverhealthhtmltable += "<td class='info'>Unreachable</td>"
                    continue
                }
                $disksRaw = $disksValue -split '<br>'
                $tdColor = "pass"

                foreach ($disk in $disksRaw) {
                    if ($disk -match "^(\w:)\s*-\s*([\d\.]+)GB\s+\(([\d\.]+)%\)$") {
                        $percent = [double]$matches[3]
                        if ($percent -lt 5) {
                            $tdColor = "fail"
                            break
                        }
                        elseif ($percent -lt 15 -and $tdColor -ne "fail") {
                            $tdColor = "warn"
                        }
                    }
                }

                $diskCells = foreach ($disk in $disksRaw) {
                    if ($disk -match "^(\w:)\s*-\s*([\d\.]+)GB\s+\(([\d\.]+)%\)$") {
                        $unit = $matches[1]
                        $gb = $matches[2]
                        $percent = [double]$matches[3]
                        $colorClass = if ($percent -lt 5) { 'fail' } elseif ($percent -lt 15) { 'warn' } else { 'pass' }
                        $bgColor = switch ($colorClass) {
                            "fail" { "#D9534F" }
                            "warn" { "#FFD966" }
                            "pass" { "#6BBF59" }
                        }
                        "<div style='background-color:$bgColor;padding:2px;'>$unit - ${gb}GB (${percent}%)</div>"
                    }
                    else {
                        "<div class='info'>$disk</div>"
                    }
                }

                $serverhealthhtmltable += "<td class='$tdColor'>" + ($diskCells -join "") + "</td>"
                continue
            }

            "RAM Total (GB)" {
                $gbStr = ($dc.'RAM Total (GB)' -replace ',', '.').Trim()
                $rawVal = ("$($dc.'RAM Total (GB)')").Trim()
                [double]$gb = 0
                if ([double]::TryParse($gbStr, [System.Globalization.NumberStyles]::Any, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$gb)) {
                    $colorClass = if ($gb -lt 4) { 'fail' } elseif ($gb -lt 8) { 'warn' } else { 'pass' }
                    $serverhealthhtmltable += "<td class='$colorClass'>$gb GB</td>"
                }
                else {
                    $display = if ($rawVal) { $rawVal } else { 'N/A' }
                    $serverhealthhtmltable += "<td class='info'>$display</td>"
                }
                continue
            }

            "RAM Free (GB)" {
                $gbStr = ($dc.'RAM Free (GB)' -replace ',', '.').Trim()
                $rawVal = ("$($dc.'RAM Free (GB)')").Trim()
                [double]$gb = 0
                if ([double]::TryParse($gbStr, [System.Globalization.NumberStyles]::Any, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$gb)) {
                    $colorClass = if ($gb -lt 2) { 'fail' } elseif ($gb -lt 4) { 'warn' } else { 'pass' }
                    $serverhealthhtmltable += "<td class='$colorClass'>$gb GB</td>"
                }
                else {
                    $display = if ($rawVal) { $rawVal } else { 'N/A' }
                    $serverhealthhtmltable += "<td class='info'>$display</td>"
                }
                continue
            }

            "RAM Free (%)" {
                $percentStr = ($dc.'RAM Free (%)' -replace ',', '.').Trim()
                $rawVal = ("$($dc.'RAM Free (%)')").Trim()
                [double]$percent = 0
                if ([double]::TryParse($percentStr, [System.Globalization.NumberStyles]::Any, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$percent)) {
                    $rounded = [math]::Round($percent)
                    $colorClass = if ($rounded -lt 10) { 'fail' } elseif ($rounded -lt 20) { 'warn' } else { 'pass' }
                    $serverhealthhtmltable += "<td class='$colorClass'>$rounded%</td>"
                }
                else {
                    $display = if ($rawVal) { $rawVal } else { 'N/A' }
                    $serverhealthhtmltable += "<td class='info'>$display</td>"
                }
                continue
            }

            "CPU Free (%)" {
                $percentStr = ($dc.'CPU Free (%)' -replace ',', '.').Trim()
                $rawVal = ("$($dc.'CPU Free (%)')").Trim()
                [double]$percent = 0
                if ([double]::TryParse($percentStr, [System.Globalization.NumberStyles]::Any, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$percent)) {
                    $rounded = [math]::Round($percent)
                    $colorClass = if ($rounded -lt 10) { 'fail' } elseif ($rounded -lt 30) { 'warn' } else { 'pass' }
                    $serverhealthhtmltable += "<td class='$colorClass'>$rounded%</td>"
                }
                else {
                    $display = if ($rawVal) { $rawVal } else { 'N/A' }
                    $serverhealthhtmltable += "<td class='info'>$display</td>"
                }
                continue
            }

            "LDAP Bind (ms)" {
                $valStr = ("$($dc.'LDAP Bind (ms)')").Trim()
                if ($valStr.ToLower() -eq "unreachable") {
                    $serverhealthhtmltable += "<td class='info'>Unreachable</td>"
                }
                else {
                    [int]$ms = 0
                    if ([int]::TryParse($valStr, [ref]$ms)) {
                        $colorClass = if ($ms -gt 500) { 'fail' } elseif ($ms -gt 150) { 'warn' } else { 'pass' }
                        $serverhealthhtmltable += "<td class='$colorClass'>${ms}ms</td>"
                    }
                    else {
                        $serverhealthhtmltable += "<td class='fail'>$valStr</td>"
                    }
                }
                continue
            }

            "LDAPS Bind (ms)" {
                $valStr = ("$($dc.'LDAPS Bind (ms)')").Trim()
                if ($valStr.ToLower() -eq "unreachable") {
                    $serverhealthhtmltable += "<td class='info'>Unreachable</td>"
                }
                else {
                    [int]$ms = 0
                    if ([int]::TryParse($valStr, [ref]$ms)) {
                        $colorClass = if ($ms -gt 600) { 'fail' } elseif ($ms -gt 200) { 'warn' } else { 'pass' }
                        $serverhealthhtmltable += "<td class='$colorClass'>${ms}ms</td>"
                    }
                    else {
                        $serverhealthhtmltable += "<td class='fail'>$valStr</td>"
                    }
                }
                continue
            }

            "Domain Role" {
                $role = $dc.'Domain Role'
                if ($role.ToLower() -eq "unreachable" -or $role.ToLower() -eq "fail") {
                    $serverhealthhtmltable += "<td class='info'>Unreachable</td>"
                }
                else {
                    $colorClass = switch ($role) {
                        'Primary Domain Controller' { 'pass' }
                        'Backup Domain Controller' { 'pass' }
                        'Member Server' { 'warn' }
                        'Standalone Server' { 'warn' }
                        'Member Workstation' { 'fail' }
                        'Standalone Workstation' { 'fail' }
                        default { 'info' }
                    }
                    $serverhealthhtmltable += "<td class='$colorClass'>$role</td>"
                }
                continue
            }

            "IPv6 Status" {
                $val = $dc.'IPv6 Status'
                $valLower = $val.ToLower()
                $cls = if ($valLower -eq "enabled") { "pass" }
                elseif ($valLower -eq "disabled") { "warn" }
                elseif ($valLower -eq "unreachable") { "info" }
                else { "info" }
                $serverhealthhtmltable += "<td class='$cls'>$val</td>"
                continue
            }

            "DNS Servers" {
                $val = $dc.'DNS Servers'
                $valLower = $val.ToLower()
                $cls = if ($valLower -eq "unreachable") { "info" }
                elseif ($valLower -eq "none configured") { "warn" }
                elseif ($valLower -eq "error") { "fail" }
                else { "pass" }
                $serverhealthhtmltable += "<td class='$cls'>$val</td>"
                continue
            }

            "DNS Forwarders" {
                $val = $dc.'DNS Forwarders'
                $valLower = $val.ToLower()
                $cls = if ($valLower -eq "unreachable") { "info" }
                elseif ($valLower -eq "none configured") { "warn" }
                elseif ($valLower -eq "error") { "fail" }
                else { "pass" }
                $serverhealthhtmltable += "<td class='$cls'>$val</td>"
                continue
            }

            "DNS Scavenging" {
                $val = $dc.'DNS Scavenging'
                $valLower = $val.ToLower()
                $cls = if ($valLower -match "^enabled") { "pass" }
                elseif ($valLower -eq "disabled") { "warn" }
                elseif ($valLower -eq "unreachable") { "info" }
                else { "fail" }
                $serverhealthhtmltable += "<td class='$cls'>$val</td>"
                continue
            }

            "Pending Reboot" {
                $val = $dc.'Pending Reboot'
                $valLower = $val.ToLower()
                $cls = if ($valLower -eq "no") { "pass" }
                elseif ($valLower -eq "pending") { "fail" }
                elseif ($valLower -eq "unreachable") { "info" }
                else { "info" }
                $serverhealthhtmltable += "<td class='$cls'>$val</td>"
                continue
            }

            "NTLMv1 Status" {
                $val = $dc.'NTLMv1 Status'
                $valLower = $val.ToLower()
                $cls = if ($valLower -match "^disabled") { "pass" }
                elseif ($valLower -match "^partial") { "warn" }
                elseif ($valLower -match "^enabled") { "fail" }
                elseif ($valLower -eq "unreachable") { "info" }
                else { "info" }
                $serverhealthhtmltable += "<td class='$cls'>$val</td>"
                continue
            }

            "VMIC Time Provider" {
                $val = $dc.'VMIC Time Provider'
                $valLower = $val.ToLower()
                $cls = if ($valLower -match "disabled") { "pass" }
                elseif ($valLower -match "enabled") { "fail" }
                elseif ($valLower -eq "unreachable") { "info" }
                else { "info" }
                $serverhealthhtmltable += "<td class='$cls'>$val</td>"
                continue
            }

            "AD Recycle Bin" {
                $val = $dc.'AD Recycle Bin'
                $valLower = $val.ToLower()
                $cls = if ($valLower -eq 'enabled') { 'pass' }
                elseif ($valLower -eq 'disabled') { 'fail' }
                else { 'info' }
                $serverhealthhtmltable += "<td class='$cls'>$val</td>"
                continue
            }

            "KRBTGT Password Age" {
                $val = $dc.'KRBTGT Password Age'
                if ($val -match '^(\d+)\s+days$') {
                    $days = [int]$matches[1]
                    $cls = if ($days -le 180) { 'pass' } elseif ($days -le 365) { 'warn' } else { 'fail' }
                    $serverhealthhtmltable += "<td class='$cls'>$val</td>"
                }
                elseif ($val -eq 'Never Set') {
                    $serverhealthhtmltable += "<td class='fail'>$val</td>"
                }
                else {
                    $serverhealthhtmltable += "<td class='info'>$val</td>"
                }
                continue
            }

            default {
                $serverhealthhtmltable += (New-ServerHealthHTMLTableCell -lineitem $field -reportline $dc)
            }
        }
    }
    $serverhealthhtmltable += "</tr>"
}
}
}

$serverhealthhtmltable += "</tbody></table></div>"

$legend = @"
<h2>L&eacute;gende des Couleurs - Rapport Active Directory</h2>
<div class="table-container" style="max-width: 800px;">
<table class="legend-table">
  <thead>
    <tr>
      <th style='text-align: left;'>Champ</th>
      <th class='pass' style='text-align: center;'>Vert (Pass)</th>
      <th class='warn' style='text-align: center;'>Jaune (Warn)</th>
      <th class='fail' style='text-align: center;'>Rouge (Fail)</th>
      <th class='info' style='text-align: center;'>Bleu (Info)</th>
    </tr>
  </thead>
  <tbody>
<tr><td>DNS Resolution</td><td>Passed</td><td>&mdash;</td><td>Failed</td><td>Unreachable</td></tr>
<tr><td>Ping</td><td>Passed</td><td>&mdash;</td><td>Failed</td><td>Unreachable</td></tr>
<tr><td>IPv6 Status</td><td>Enabled</td><td>Disabled</td><td>&mdash;</td><td>Unreachable</td></tr>
<tr><td>DNS Servers</td><td>Configured</td><td>None configured</td><td>Error</td><td>Unreachable</td></tr>
<tr><td>DNS Forwarders</td><td>Configured</td><td>None configured</td><td>Error</td><td>Unreachable</td></tr>
<tr><td>DNS Scavenging</td><td>Enabled</td><td>Disabled</td><td>Error</td><td>Unreachable</td></tr>
<tr><td>Pending Reboot</td><td>No</td><td>&mdash;</td><td>Pending</td><td>Unreachable</td></tr>
<tr><td>Time offset (seconds)</td><td>&le; 1 s</td><td>1&ndash;5 s</td><td>&gt; 5 s</td><td>Unreachable / Error</td></tr>
<tr><td>NTP Source</td><td>Valid NTP server</td><td>VM IC Time</td><td>Local CMOS / Free-Running / Failed</td><td>Unreachable</td></tr>
<tr><td>VMIC Time Provider</td><td>Disabled</td><td>&mdash;</td><td>Enabled</td><td>Unreachable / No Data</td></tr>
<tr><td>LDAP Bind (ms)</td><td>&lt; 150ms</td><td>150&ndash;500ms</td><td>&gt; 500ms / Error</td><td>Unreachable</td></tr>
<tr><td>LDAPS Bind (ms)</td><td>&lt; 200ms</td><td>200&ndash;600ms</td><td>&gt; 600ms / Error</td><td>Unreachable</td></tr>
<tr><td>Uptime</td><td>&lt; 30 days</td><td>30&ndash;60 days</td><td>&gt; 60 days</td><td>Unreachable / CIM Error</td></tr>
<tr><td>OS / Disks Free Space (%)</td><td>&ge; 15%</td><td>5&ndash;15%</td><td>&lt; 5%</td><td>Unreachable / CIM Error</td></tr>
<tr><td>OS Free Space (GB)</td><td colspan='3'>According to percentage (%)</td><td>Unreachable / CIM Error</td></tr>
<tr><td>RAM Total (GB)</td><td>&ge; 8 GB</td><td>4&ndash;8 GB</td><td>&lt; 4 GB</td><td>Unreachable / CIM Error</td></tr>
<tr><td>RAM Free (GB)</td><td>&ge; 4 GB</td><td>2&ndash;4 GB</td><td>&lt; 2 GB</td><td>Unreachable / CIM Error</td></tr>
<tr><td>RAM Free (%)</td><td>&ge; 20%</td><td>10&ndash;20%</td><td>&lt; 10%</td><td>Unreachable / CIM Error</td></tr>
<tr><td>CPU Total Cores / CPUs</td><td>&ge; 4</td><td>2&ndash;4</td><td>&lt; 2</td><td>Unreachable / CIM Error</td></tr>
<tr><td>CPU Free (%)</td><td>&ge; 30%</td><td>10&ndash;30%</td><td>&lt; 10%</td><td>Unreachable / CIM Error</td></tr>
<tr><td>DNS, Netlogon, KDC, ADWS Services</td><td>Passed</td><td>&mdash;</td><td>Failed / CIM Error</td><td>Not Installed / Unreachable</td></tr>
<tr><td>Domain Role</td><td>PDC / BDC</td><td>Member / Standalone Server</td><td>Workstation</td><td>Unknown</td></tr>
<tr><td>DCDIAG Tests</td><td>Passed</td><td>&mdash;</td><td>Failed</td><td>Timeout / Error / Unreachable</td></tr>
<tr><td>Events Warning (8h)</td><td>&le; 10</td><td>11&ndash;100</td><td>&gt; 100</td><td>Unreachable / Error</td></tr>
<tr><td>Events Error (8h)</td><td>&le; 5</td><td>6&ndash;50</td><td>&gt; 50</td><td>Unreachable / Error</td></tr>
<tr><td>Events Critical (8h)</td><td>&le; 1</td><td>2&ndash;10</td><td>&gt; 10</td><td>Unreachable / Error</td></tr>
<tr><td>KCC Events (8h)</td><td>= 0</td><td>1&ndash;12</td><td>&gt; 12</td><td>Unreachable / Error</td></tr>
<tr><td>Replication Pending</td><td>= 0</td><td>&gt; 0</td><td>&mdash;</td><td>Unreachable</td></tr>
<tr><td>SYSVOL / NETLOGON Shares</td><td>Passed</td><td>&mdash;</td><td>Failed</td><td>Unreachable</td></tr>
<tr><td>Replication Summary</td><td>= 0</td><td>&mdash;</td><td>&gt; 0</td><td>Unreachable / Error</td></tr>
<tr><td>Max Replication Delay (h)</td><td>&le; 1h</td><td>&gt; 1h and &le; 12h</td><td>&gt; 12h</td><td>Unreachable / Error</td></tr>
<tr><td>SYSVOL Replication Method</td><td>DFSR</td><td>FRS</td><td>&mdash;</td><td>Unreachable</td></tr>
<tr><td>Functional Levels</td><td>&ge; 2012</td><td>2008 / R2</td><td>2003</td><td>&mdash;</td></tr>
<tr><td>Tombstone Lifetime</td><td>&le; 180 days</td><td>&gt; 180 days</td><td>Error</td><td>Not Defined</td></tr>
<tr><td>AD Recycle Bin</td><td>Enabled</td><td>&mdash;</td><td>Disabled</td><td>Error</td></tr>
<tr><td>KRBTGT Password Age</td><td>&le; 180 days</td><td>181&ndash;365 days</td><td>&gt; 365 days / Never Set</td><td>Error</td></tr>
<tr><td>NTLMv1 Status</td><td>Disabled (Level 4-5)</td><td>Partial (Level 3)</td><td>Enabled (Level 0-2)</td><td>Unreachable</td></tr>
<tr><td>Latest Hotfix</td><td colspan='3'>Informational &mdash; top 5 installed hotfixes</td><td>Unreachable / Error</td></tr>
  </tbody>
</table>
</div>
<br>
"@

$htmltail = "* Le test DNS est effectu&eacute; via la commande Resolve-DnsName (disponible &agrave; partir de Windows Server 2012).
                                    </body>
                                    </html>"

# Count alerts and failures from the generated table using Regex
$script:totalFailCount = [regex]::Matches($serverhealthhtmltable, "class='fail'").Count
$script:totalWarnCount = [regex]::Matches($serverhealthhtmltable, "class='warn'").Count

$activeDCs = $allTestedDomainControllers.Count - $script:totalOfflineDCs

$htmlDashboard = @"
<h2>Synth&egrave;se du Diagnostic</h2>
<div class="dashboard">
  <div class="card" style="border-top: 4px solid #868e96;">
    <div class="card-title">Total Contr&ocirc;leurs de Domaine</div>
    <div class="card-value">$($allTestedDomainControllers.Count)</div>
  </div>
  <div class="card" style="border-top: 4px solid #28a745;">
    <div class="card-title">DCs en Ligne</div>
    <div class="card-value" style="color: #28a745;">$activeDCs</div>
  </div>
  <div class="card" style="border-top: 4px solid #dc3545;">
    <div class="card-title">Erreurs D&eacute;tect&eacute;es</div>
    <div class="card-value" style="color: #dc3545;">$script:totalFailCount</div>
  </div>
  <div class="card" style="border-top: 4px solid #ffc107;">
    <div class="card-title">Avertissements</div>
    <div class="card-value" style="color: #fd7e14;">$script:totalWarnCount</div>
  </div>
</div>
"@

$htmlreport = $htmlhead + $htmlDashboard + $htmlFunctionalLevels + $serverhealthhtmltable + $legend + $htmltail

if ($CSV) {
    $csvFileName = "AD-Health-$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss').csv"
    $allTestedDomainControllers | Export-Csv -Path $csvFileName -NoTypeInformation -Encoding UTF8
    Write-Host "CSV report saved to $csvFileName" -ForegroundColor Green
}

if ($Report) {
    $htmlreport | Out-File $reportName -Encoding UTF8
    Write-Host "Report generated: $reportName" -ForegroundColor Green
}

if ($Email) {
    try {
        # Send email with both inline HTML and attachment
        $htmlreport | Out-File $reportName -Encoding UTF8
        Send-MailMessage @smtpsettings -Body $htmlreport -BodyAsHtml -Attachments $reportName -Encoding ([System.Text.Encoding]::UTF8) -ErrorAction Stop
        Write-Host "Email sent successfully." -ForegroundColor Green
    }
    catch {
        Write-Host "Failed to send email. Error: $_" -ForegroundColor Red
    }
}