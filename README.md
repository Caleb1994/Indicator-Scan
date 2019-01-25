# Indicator-Scan - Automatically scan a list of targets for indicators of compromise

This is a dumb script which will attempt to use WinRM to connect to each of the given targets, and look for a list of registry, file, and network IOCs. The network IOC detection is primitive, and unreliable. It simply looks at all current TCP connections (using `Get-NetTcpConnection`) for a matching `Remote Address`.

## Usage

```
PS C:\Windows\System32> .\Inidicator-Scan.ps1 -targets 192.168.1.10,10.10.10.32 -reg "registery_iocs.txt" -files "file_iocs.txt" -ips "ip_iocs.txt" | Format-Table host,ip,file,reg

host           ip         file        reg
----           --         ----        ---
192.168.1.10   {}         {}          {HKEY_LOCAL_MACHINE\Software}
10.10.10.32    {8.8.8.8}  {}          {}

```

## This is dumb

This is unsupported, and was created for an exercise in a class. If you like it, feel free to do whatever you want with it, but I'll probably never look at it again or respond to any questions.
