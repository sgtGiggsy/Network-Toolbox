function IfIP
{
    param($bemenet)

    $pattern = "^([1-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])(\.([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])){3}$"

    if($bemenet -match $pattern)
    {
        return $true
    }
    else
    {
        return $false
    }
}

function Get-Telnet
{
    Param($lekerdez, $eredmeny)

    $port = 23
    [String[]]$commands = @($global:felhasznalonev, $global:jelszo, $lekerdez)
    $Waittime = 1000

    $socket = New-Object System.Net.Sockets.TcpClient($global:switch, $port)
    if($socket)
    {
        $stream = $socket.GetStream()
        $writer = New-Object System.IO.StreamWriter($stream)
        $buffer = New-Object System.Byte[] 1024
        $encoding = New-Object System.Text.ASCIIEncoding
    

        foreach ($command in $commands)
        {
            $writer.WriteLine($command)
            $writer.Flush()
            Start-Sleep -Milliseconds $Waittime
        }

        Start-Sleep -Milliseconds ($Waittime * 4)
        $result = ""

        while($stream.DataAvailable -and $eredmeny)
        {
            $read = $Stream.read($buffer, 0, 1024)
            $result += ($encoding.GetString($buffer, 0, $read))
        }
    }
    else
    {
        $result = "Kapcsolódás sikertelen"
    }

    return $result
}

function Switch-Login {
    do
    {
        Write-Host "Switch bejelentkezés`n"
        $global:switch = "10.59.1.252"
        Write-Host "Az alapértelmezett switchet használod ($($global:switch)), vagy megadod kézzel a címet?`nAdd meg a switch IP címét, ha választani szeretnél, vagy üss Entert, ha az alapértelmezettet használnád!"
        do
        {
            $kilep = $true
            $valassz = Read-Host "A switch IP címe"
            if ($valassz)
            {
                if(Test-Connection $valassz -Quiet -Count 1)
                {
                    $global:switch = $valassz
                }
                else
                {
                    Write-Host "A megadott IP címen nem található eszköz, add meg újra a címet, vagy üss Entert az alapértelmezett switch használatához!" -ForegroundColor Red
                    $kilep = $false
                }
            }
        }while(!$kilep)

        $probalkozas = 0

        Clear-Host
        Write-Host "Bejelentkezés a $global:switch switchre`n"
        do
        {
            $global:felhasznalonev = Read-Host -Prompt "Felhasználónév"
            $pwd = Read-Host -AsSecureString -Prompt "Jelszó"
            $global:jelszo = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($pwd))
            $pattern = "failed"

            $logintest = Get-Telnet "" $true
            $loginfail = $logintest | Select-String -Pattern $pattern
            if ($loginfail -and $probalkozas -lt 3)
            {
                $probalkozas++
                $hatravan = 3 - $probalkozas
                Write-Host "A megadott felhasználónév, vagy jelszó nem megfelelő, esetleg a megadott IP címen nincs elérhető switch!`nPróbálkozz újra! (Még $hatravan próbálkozásod van)" -ForegroundColor Red
            }
        }while ($loginfail -and $probalkozas -lt 3)
        if ($loginfail)
        {
            Clear-Host
            Write-Host "Újrapróbálkozol a switch bejelentkezési adatainak megadásával? Üss I-t, ha igen, bármely más billentyű esetén a program kilép" -ForegroundColor Red
            $valassz = Read-Host -Prompt "Válassz"
            if($valassz -ne "I")
            {
                Exit
            }
        }
    }while($loginfail)
}

$getLocalMAC = get-wmiobject -class "win32_networkadapterconfiguration" | Where-Object {$_.DefaultIPGateway -Match "10.59.56.1"}
$kimenet = ($getLocalMAC.MACAddress).Split(":")
$LocalMAC = "$($kimenet[0])$($kimenet[1]).$($kimenet[2])$($kimenet[3]).$($kimenet[4])$($kimenet[5])"
$localIP = (($getLocalMAC.IPAddress).Split(","))[0]
Write-Host "ESZKÖZ HELYKERESŐ`n"

do
{
    $keresetteszkoz = "ohp-36570-59-d" # Read-Host -Prompt "Keresett eszköz IP, vagy neve címe"
    try
    {
        $eszkoz = Test-Connection $keresetteszkoz -Quiet -Count 1
    }
    catch
    {
    }
    if(!$eszkoz)
    {
        Write-Host "A megadott IP cím jelenleg nem elérhető! Add meg újra az IP címet!" -ForegroundColor Red
    }
} while (!$eszkoz)

ping $keresetteszkoz -n 1 | Out-Null
if (!(IfIP $keresetteszkoz))
{
    $keresetteszkoz = [System.Net.Dns]::GetHostAddresses($keresetteszkoz)
}

$getRemoteMAC = arp -a | ConvertFrom-String | Where-Object { $_.P2 -eq $keresetteszkoz }
$kimenet = ($getRemoteMAC.P3).Split("-")
$RemoteMAC = "$($kimenet[0])$($kimenet[1]).$($kimenet[2])$($kimenet[3]).$($kimenet[4])$($kimenet[5])"
$keresesiparancs = "traceroute mac $localMAC $remoteMAC"

Write-Host "Ha csak kiiratnád a switchen futtatandó parancsot, üss I betűt, bármely más billentyű leütésére a program megkísérli automatikusan futtatni egy switchen."
$valassz = Read-Host -Prompt "Valassz"

if ($valassz -ne "I")
{
    Switch-Login
    $pinglocal = "ping $localIP"
    $pingremote = "ping $keresetteszkoz"
    $failcount = 0
    $pingparancs = @($pinglocal, $pingremote)
    do
    {
        Get-Telnet $pingparancs $false
        $result = Get-Telnet $keresesiparancs $true
        $fail = $result | Select-String -Pattern "Error"
        if ($fail -and $failcount -lt 3)
        {
            $failcount++
            $visszamaradt = 3 - $failcount
            Write-Host "A lekérdezés most nem járt sikerrel. Még $visszamaradt alkalommal újrapróbálkozom!" -ForegroundColor Yellow
        }
    }while ($fail -and $failcount -lt 3)
    
    if(!$fail)
    {
        $eszkozhelye = $result | Select-String -Pattern "=>"
        Write-Host $eszkozhelye
    }
}
if($valassz -eq "I" -or $failcount -eq 3)
{
    Clear-Host
    Write-Host "ESZKÖZ HELYKERESŐ`n"
    Write-Host "Helyi IP cím:           $localIP (ezt kell pingelni a switchről, ha a TraceRoute parancs 'Error: Source Mac address not found.' hibát ad."
    Write-Host "Keresett eszköz IP-je:  $keresetteszkoz (ezt kell pingelni a switchről, ha a TraceRoute parancs 'Error: Destination Mac address not found.' hibát ad."
    Write-Host "Keresési parancs:       $keresesiparancs (automatikusan a vágólapra másolva)`n"
    Set-Clipboard $keresesiparancs
}

Write-Host "A folyamat végetért. Egy billentyű leütésére a program kilép."
Read-Host