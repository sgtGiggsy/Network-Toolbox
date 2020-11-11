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
    [String[]]$commands = @($global:felhasznalonev, $global:jelszo)

    foreach ($parancs in $lekerdez)
    {
        $commands += $parancs
    }

    try
    {
        $socket = New-Object System.Net.Sockets.TcpClient($global:switch, $port)
    }
    catch
    {
        Write-Host "Kapcsolódási hiba!" -ForegroundColor Red
    }

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
            Start-Sleep -Milliseconds $global:waittime
        }

        Start-Sleep -Milliseconds $global:waittime
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
        Clear-Host
        Write-Host "Switch bejelentkezés`n"
        $global:switch = "10.59.1.252"
        Write-Host "Az alapértelmezett switchet használod ($($global:switch)), vagy megadod kézzel a címet?`nAdd meg a switch IP címét, ha választani szeretnél, vagy üss Entert, ha az alapértelmezettet használnád!"
        do
        {
            $kilep = $true
            $valassz = Read-Host "A switch IP címe"
            if ($valassz)
            {
                try
                {
                    $ErrorActionPreference = "Stop"
                    Test-Connection $valassz -Count 1
                }
                catch
                {
                    Write-Host "A megadott címen nem található eszköz, add meg újra a címet, vagy üss Entert az alapértelmezett switch használatához!" -ForegroundColor Red
                    $kilep = $false
                }
                if($kilep)
                {
                    $global:switch = $valassz
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

            Write-Host "`nKísérlet bejelentkezésre..."
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

function Get-Eszkoz
{
    do
    {
        $global:keresetteszkoz = Read-Host -Prompt "Keresett eszköz IP címe, vagy neve"
        try
        {
            $eszkoz = Test-Connection $keresetteszkoz -Quiet -Count 1
        }
        catch
        {
            $eszkoz = $false
        }

        if(!$eszkoz)
        {
            Write-Host "A megadott eszköz jelenleg nem elérhető! Add meg újra az IP címet, vagy nevet!" -ForegroundColor Red
        }
        else
        {
            if (!(IfIP $global:keresetteszkoz))
            {
                $global:keresetteszkoz = [System.Net.Dns]::GetHostAddresses($global:keresetteszkoz)
            }

            if($global:keresetteszkoz | Select-String -pattern "10.59.58")
            {
                $eszkoz = $false
                Write-Host "A megadott eszköz másik VLAN-on van, így erről az eszközről nem lehet megkeresni!" -ForegroundColor Red
            }
            else
            {
                if(!($global:keresetteszkoz | Select-String -pattern $localIP))
                {
                    ping $global:keresetteszkoz -n 1 | Out-Null
                    $getRemoteMAC = arp -a | ConvertFrom-String | Where-Object { $_.P2 -eq $global:keresetteszkoz }
                    $kimenet = ($getRemoteMAC.P3).Split("-")
                    $global:RemoteMAC = "$($kimenet[0])$($kimenet[1]).$($kimenet[2])$($kimenet[3]).$($kimenet[4])$($kimenet[5])"
                }
                else
                {
                    Write-Host "A jelenlegi és a keresett eszköz megegyezik! Adj meg másik eszközt!" -ForegroundColor Red
                    $eszkoz = $false
                }
            }
        }
    } while (!$eszkoz)
    $keresesiparancs = "traceroute mac $localMAC $remoteMAC"
    return $keresesiparancs
}

function Get-MACaddress {
    param ($gepnev)
    if (!$gepnev)
    {
        $gepnev = HOSTNAME.EXE
    }
    $getMAC = get-wmiobject -class "win32_networkadapterconfiguration" -ComputerName $gepnev | Where-Object {$_.DefaultIPGateway -Match "10.59."}
    $kimenet = ($getMAC.MACAddress).Split(":")
    $MAC = "$($kimenet[0])$($kimenet[1]).$($kimenet[2])$($kimenet[3]).$($kimenet[4])$($kimenet[5])"
    $IP = (($getMAC.IPAddress).Split(","))[0]
    $result = @($MAC, $IP)
    return $result
}

$local = Get-MACaddress
$LocalMAC = $local[0]
$localIP = $local[1]
$global:waittime = 500 

Write-Host "ESZKÖZ HELYKERESŐ`n"

$keresesiparancs = Get-Eszkoz
$elsofutas = $true

Write-Host "Ha csak kiiratnád a switchen futtatandó parancsot, üss I betűt, bármely más billentyű leütésére az eszköz keresése automatikusan történik."
$valassz = Read-Host -Prompt "Valassz"

if ($valassz -ne "I")
{
    Switch-Login
    do
    {
        Clear-Host
        Write-Host "ESZKÖZ FIZIKAI HELYÉNEK MEGKERESÉSE`n"
        if (!$elsofutas)
        {
            $keresesiparancs = Get-Eszkoz
        }
        $pinglocal = "ping $localIP"
        $pingremote = "ping $keresetteszkoz"
        $failcount = 0
        [String[]]$parancs = @($pinglocal, $pingremote, $keresesiparancs)
        $waittimeorig = $global:waittime
        $maxhiba = 5
        do
        {
            Write-Host "A(z) $keresetteszkoz IP című eszköz helyének lekérdezése folyamatban..."
            $result = Get-Telnet $parancs $true
            $siker = $result | Select-String -Pattern "found on"
            if (!$siker -and $failcount -lt $maxhiba)
            {
                $failcount++
                $visszamaradt = $maxhiba - $failcount
                Write-Host "A lekérdezés most nem járt sikerrel. Még $visszamaradt alkalommal újrapróbálkozom!" -ForegroundColor Yellow
                $global:waittime = $global:waittime + 1000
            }
            if ($failcount -lt 3)
            {
                $global:switch = "10.59.1.252"
            }
            Write-Host $result
        }while (!$siker -and $failcount -lt $maxhiba)
        $global:waittime = $waittimeorig
        
        if($siker)
        {
            Clear-Host
            Write-Host "ESZKÖZ FIZIKAI HELYÉNEK MEGKERESÉSE`n"
            Write-Host "Az adatcsomagok útja erről az eszközről a(z) $keresetteszkoz IP című eszközig:"
            $talalat = 0
            $sortor = $result.Split("`r`n")
            for ($i = 0; $i -lt $sortor.Length; $i++)
            {
                if ($sortor[$i] | Select-String -pattern "=>")
                {
                    Write-Host $sortor[$i]
                    $talalat = $i
                }
            }
            $utolsosor = $sortor[$talalat].Split(" ")
            $switchnev = $utolsosor[1]
            $switchip = $utolsosor[2]
            $eszkozport = $utolsosor[6]
            Write-Host "`nA keresett eszköz a(z) $switchnev $switchip switch $eszkozport portján található." -ForegroundColor Green
        }
        $elsofutas = $false
        Write-Host "`nAmennyiben másik eszköz helyét szeretnéd lekérdezni, üss U betűt, bármely más betű leütésére a program kilép."
        $valassz = Read-Host -Prompt "Válassz"
    }while($valassz -eq "U")
}

if($valassz -eq "I" -or $failcount -eq 3)
{
    Clear-Host
    Write-Host "ESZKÖZ FIZIKAI HELYÉNEK MEGKERESÉSE`n"
    Write-Host "Helyi IP cím:           $localIP (ezt kell pingelni a switchről, ha a TraceRoute parancs 'Error: Source Mac address not found.' hibát ad."
    Write-Host "Keresett eszköz IP-je:  $keresetteszkoz (ezt kell pingelni a switchről, ha a TraceRoute parancs 'Error: Destination Mac address not found.' hibát ad."
    Write-Host "Keresési parancs:       $keresesiparancs (automatikusan a vágólapra másolva)`n"
    Set-Clipboard $keresesiparancs
    Write-Host "A folyamat végetért. Egy billentyű leütésére a program kilép."
    Read-Host
}