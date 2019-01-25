<#
.SYNOPSIS
    Scans the given hosts for the given file, registry, and network indicators of compromise.

.DESCRIPTION
    Utilizes the Invoke-Command cmdlet to run a script on the remote target, and scan for the indicators given
    in the `reg`, `files`, and `network` parameters.

.PARAMETER targets
    A list of IPs to scan.

.PARAMETER net
    A file containing IPs to look for on the remote host.

.PARAMETER file
    A file containing file names to look for on the remot host (this may include "%ENVVAR%" variables).

.PARAMETER reg
    A file containing registry keys to look for on the remote host.

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

    You should add the given hosts to your trusted hosts, if you are not on a domain. This script does not modify the WinRM TrustedHosts configuration.

    You can add the hosts to the trusted hosts like so:

    Set-Item WSMan:\localhost\Client\TrustedHosts -Value "10.10.10.5,10.10.10.38"

    Or, you may add a wild card to enable any hosts (Dangerous)

    Set-Item WSMan:\localhost\Client\TrustedHosts -Value *

.LINK
    https://github.com/Caleb1994/Indicator-Scan

.EXAMPLE
    Indicator-Scan -targets 10.10.10.5,10.10.10.38 -net network-iocs.txt -file file-iocs.txt -reg registry-iocs.txt
    Scans 10.10.10.5 and 10.10.10.38 for the given network, file and registry indicators of compromise.
#>
param (
    [Parameter(Mandatory=$true)][IPAddress[]]$targets,
    [Parameter(Mandatory=$true)][string]$net,
    [Parameter(Mandatory=$true)][string]$file,
    [Parameter(Mandatory=$true)][string]$reg
)

function Test-Port($ip, $port)
{
    try {
        $socket = new-object System.Net.Sockets.TcpClient($ip.IPAddressToString, $port)
        if( $socket.Connected ){
            $socket.Close()
            return $true
        }
    } Catch {}
    return $false    
}

# The variable holding our results
$report = @()
$net_list = @()
$file_list = @()
$reg_list = @()
$iter = 0

# Read IOCs
foreach($line in $(Get-Content $net)){
    $net_list += $line
}
foreach($line in $(Get-Content $file)){
    $file_list += $line
}
foreach($line in $(Get-Content $reg)){
    $reg_list += $line
}

# Iterate over all addresses
foreach( $address in $targets ){

    Write-Progress -Activity "[indicator-scan]" -Status "$($address.IPAddressToString): checking for indicators" -PercentComplete (([float]$iter / $targets.Count)*100)

    # Add the host to the report
    $report += Invoke-Command -ComputerName $address.IPAddressToString -ErrorAction Stop -ScriptBlock {
        param($ip, $net_list, $file_list, $reg_list)

        $result = @{
            "host" = $ip;
            "net" = @();
            "file" = @();
            "reg" = @();
        }

        # Look for matching network connections
        $tcp_conns = Get-NetTcpConnection
        foreach( $net in $net_list ){
            $tcp_conns | Where-Object { $_.RemoteAddress -eq $net } | ForEach-Object {
                $result["net"] += New-Object -TypeName PSObject -Property @{
                    "type" = "tcp";
                    "port" = $_.RemotePort;
                    "address" = $_.RemoteAddress;
                }
            }
        }

        # Look for valid files
        foreach( $file in $file_list ){
            $expanded_path = [System.Environment]::ExpandEnvironmentVariables($file);
            if( Test-Path "$expanded_path"  ){
                $result["file"] += $expanded_path
            }
        }

        # Look for valid registry keys
        foreach( $reg in $reg_list ){
            if( Test-Path "Registry::$reg" ) {
                $result["reg"] += $reg
            }
        }
        
        # Return the results
        return New-Object -TypeName PSObject -Property $result
    } -ArgumentList @($address.IPAddressToString, $net_list, $file_list, $reg_list)

    $iter += 1
}

return $report
