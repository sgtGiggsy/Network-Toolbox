$getLocalMAC = get-wmiobject -class "win32_networkadapterconfiguration" | Where-Object {$_.DefaultIPGateway -Match "10.59.56.1"}
$kimenet = ($getLocalMAC.MACAddress).Split(":")
$LocalMAC = "$($kimenet[0])$($kimenet[1]).$($kimenet[2])$($kimenet[3]).$($kimenet[4])$($kimenet[5])"
$localIP = (($getLocalMAC.IPAddress).Split(","))[0]
Write-Host "ESZKÖZ HELYKERESŐ`n"

do
{
    $keresetteszkoz = Read-Host -Prompt "Keresett eszköz IP címe"
    try
    {
        $ErrorActionPreference = "Stop"
        $eszkoz = Test-Connection $keresetteszkoz -Quiet -Count 1
    }
    catch [System.Net.NetworkInformation.PingException]
    {
        Write-Host "A megadott IP cím jelenleg nem elérhető! Add meg újra az IP címet!" -ForegroundColor Red
        $eszkoz = $false
    }
} while (!$eszkoz)

ping $keresetteszkoz -n 1 | Out-Null
$getRemoteMAC = arp -a | ConvertFrom-String | Where-Object { $_.P2 -eq $keresetteszkoz }
$kimenet = ($getRemoteMAC.P3).Split("-")
$RemoteMAC = "$($kimenet[0])$($kimenet[1]).$($kimenet[2])$($kimenet[3]).$($kimenet[4])$($kimenet[5])"

Clear-Host
Write-Host "ESZKÖZ HELYKERESŐ`n"
Write-Host "Helyi IP cím:           $localIP (ezt kell pingelni a switchről, ha a TraceRoute parancs 'Error: Source Mac address not found.' hibát ad."
Write-Host "Keresett eszköz IP-je:  $keresetteszkoz (ezt kell pingelni a switchről, ha a TraceRoute parancs 'Error: Destination Mac address not found.' hibát ad."
Write-Host "Keresési parancs:       traceroute mac $localMAC $remoteMAC (automatikusan a vágólapra másolva)"
Set-Clipboard "traceroute mac $localMAC $remoteMAC"
