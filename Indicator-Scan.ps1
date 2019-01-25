 <#
.SYNOPSIS
    Scans the given hosts for the given file, registry, and network indicators of compromise.

.DESCRIPTION
    Utilizes the Invoke-Command cmdlet to run a script on the remote target, and scan for the indicators given
    in the `ips`, `files`, and `regs` parameters.

.PARAMETER targets
    A list of hosts to scan (hostnames or IP addresses)

.PARAMETER ips
    A file containing IPs to look for on the remote host. Hostnames are not
    supported.

.PARAMETER files
    A file containing file names to look for on the remot host. These should be
    full paths and may contain classical environment references using percent
    (%ENVVAR%) references such as %TEMP%.

.PARAMETER regs
    A file containing registry keys to look for on the remote host. Registry
    keys should be their full names (e.g. HKEY_LOCAL_MACHINE, not HKLM). They
    will be tested using the Powershell "Registry::" provider.

.PARAMETER credentials
    A PSCredential object used to authenticate with the remote targets. If not
    specified, you will be prompted for credentials.

.OUTPUTS
    An array of host objects. Each host object contains the following items:
        - host: the IP address of this host
        - reg: A list of registry keys identified
        - net: A list of IPs this machine is currently connected to.
        - file: A list of files found on the target.

.NOTES
    Name: Indicator-Scan.ps1
    Author: Caleb Stewart
    DateCreated: 25JAN2019

    You should add the given hosts to your trusted hosts, if you are not on a
    domain. This script does not modify the WinRM TrustedHosts configuration.
    You can add the hosts to the trusted hosts like so:

    Set-Item WSMan:\localhost\Client\TrustedHosts -Value "10.10.10.5,10.10.10.38" -Concatenate

.LINK
    https://github.com/Caleb1994/Indicator-Scan

.EXAMPLE
    .\Indicator-Scan.ps1 -targets 10.10.10.5,10.10.10.38 -ips ioc_ips.txt -files ioc_files.txt | Format-Table host,ip,file,reg
    Scans 10.10.10.5 and 10.10.10.38 for the given network and file indicators of compromise.

    .\Indicator-Scan.ps1 -targets 10.10.10.23 -ips ioc_ips.txt -credential $my_creds | Format-Table host,ip,file,reg
    Scan 10.10.10.23 for the given IP indicators using the credentials stored in `$my_creds`.
#>
param (
    [Parameter(Mandatory=$true)][IPAddress[]]$targets,
    [string]$ips,
    [string]$files,
    [string]$regs,
    [System.Management.Automation.PSCredential]$credential = $(
        Get-Credential -Message "Please supply credentials for the remote targets"
    )
)

# The variable holding our results
$report = @()
# The numeric iterator for status updates
$iter = 0

# Read in any specified IP IOCs
$ip_list = @()
if ( $ips -ne "" -and (Test-Path "$ips") ) {
    foreach($line in $(Get-Content "$ips")){
        $ip_list += $line
    }
} elseif ( $ips -ne "" ){
    Write-Error "${ips}: file not found"
    return $null
}

# Read in any specified file IOCs
$file_list = @()
if( $files -ne "" -and (Test-Path "$files") ){
    foreach($line in $(Get-Content "$files")){
        $file_list += $line
    }
} elseif ( $files -ne "" ){
    Write-Error "${files}: file not found"
    return $null
}

# Read in any specified registry IOCs
$reg_list = @()
if( $regs -ne "" -and (Test-Path "$regs") ){
    foreach($line in $(Get-Content "$regs")){
        $reg_list += $line
    }
} elseif ( $regs -ne "" ){
    Write-Error "${regs}: file not found"
    return $null
}

# Iterate over all addresses
foreach( $address in $targets ){

    # Display current progress percentage
    Write-Progress -Activity "[indicator-scan]" -Status "$($address.IPAddressToString): checking for indicators" -PercentComplete (([float]$iter / $targets.Count)*100)

    # Run the check, and add results to the report
    $report += Invoke-Command -ComputerName $address.IPAddressToString -ErrorAction Stop -ScriptBlock {
        param($target, $ip_list, $file_list, $reg_list)

        # Setup result structure
        $result = @{
            "host" = $target;
            "ip" = @();
            "file" = @();
            "reg" = @();
        }

        # Look for matching network connections
        $tcp_conns = Get-NetTcpConnection # We only check currently active TCP connections
        foreach( $ip in $ip_list ){
            # Compare this IOC with all items in active connections
            $tcp_conns | Where-Object { $_.RemoteAddress -eq $ip } | ForEach-Object {
                $result["ip"] += New-Object -TypeName PSObject -Property @{
                    "type" = "tcp";
                    "port" = $_.RemotePort;
                    "address" = $_.RemoteAddress;
                }
            }
        }

        # Look for valid files
        foreach( $file in $file_list ){
            # Expand "%ENVVAR% type of variables in the file path
            $expanded_path = [System.Environment]::ExpandEnvironmentVariables($file);
            if( Test-Path "$expanded_path"  ){
                $result["file"] += $expanded_path
            }
        }

        # Look for valid registry keys
        foreach( $reg in $reg_list ){
            # Use the "Registry::" provider
            if( Test-Path "Registry::$reg" ) {
                $result["reg"] += $reg
            }
        }
        
        # Return the results
        return New-Object -TypeName PSObject -Property $result
    } -ArgumentList @($address.IPAddressToString, $ip_list, $file_list, $reg_list)

    $iter += 1
}

return $report
