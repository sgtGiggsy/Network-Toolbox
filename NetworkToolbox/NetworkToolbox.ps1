# A logok és CSV mentésénél hibát okoz, ha a Logfiles mappa nem létezik,
# ezért ha valamiért nem létezne, itt a futás elején létrehozzuk.
if (!(Test-Path .\Logfiles))
{
    New-Item -Path . -Name "Logfiles" -ItemType "Directory" | Out-Null
}

# A rugalmasabb kezelésért a program külső, szerkeszthető INI fájllal paraméterezhető. Itt kérjük be
# az INI fájlt, és amennyiben azzal valami hiba lenne, folytatjuk az alapértelmezett értékekkel
try
{
    $ErrorActionPreference = "Stop"
    $config = Get-Content ".\config.ini" | Out-String | ConvertFrom-StringData
    $log = $config.log
    $script:aktivnapok = $config.aktivnapok
    $ujraprobalkozas = $config.ujraprobalkozas
    $updater = $config.updater
    $frissitomappanev = $config.frissitomappanev
    $csvnevelotag = $config.csvnevelotag
    $kozeptag = $config.kozeptag
    $celkonyvtar = $config.celkonyvtar
    $script:frissitofajl = $config.frissitofajl
}
catch [System.ArgumentException]
{
    Write-Host "HIBA A KONFIGURÁCIÓS FÁJLBAN!" -ForegroundColor Red
    Write-Host "Valószínűleg hiányzik egy \ jel valahonnan, ahol kettőnek kellene lennie egymás mellett" -ForegroundColor Yellow
    $konfighiba = 1
}
catch [System.Management.Automation.ItemNotFoundException]
{
    Write-Host "A CONFIG.INI FÁJL HIÁNYZIK, VAGY SÉRÜLT!" -ForegroundColor Red
    $konfighiba = 2
}

if ($konfighiba)
{
    #Write-Host "`nA program az alapértelmezett beállításokkal fog futni. A folytatáshoz üss le egy billentyűt!"
    $setting = [Setting]::New()
}



switch ($confighiba) {
    1 { Add-Log "[HIBA] A konfigurációs fájlban hibás érték(ek) szerepel(nek)!" }
    2 { Add-Log "[HIBA] A konfigurációs fájl hiányzik, vagy sérült!" }
    Default {}
}

#####
##
##  Osztályok. Ebben a részben találhatóak a programban használt osztályok
##
#####

class IPcim
{
    $tag1
    $tag2
    $tag3
    $tag4
    $pattern = "^([1-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])(\.([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])){3}$"

    IPcim($bemenet)
    {
        $kimenet = $false
        do
        {
            if($bemenet -match $this.pattern)
            {
                $kimenet = $bemenet.Split(".")
                [int32]$this.tag1 = $kimenet[0]
                [int32]$this.tag2 = $kimenet[1]
                [int32]$this.tag3 = $kimenet[2]
                [int32]$this.tag4 = $kimenet[3]
            }
            else
            {
                Write-Host "Nem érvényes IP címet adtál meg! Próbálkozz újra!" -ForegroundColor Red
                $bemenet = Read-Host -Prompt "IP cím"
            }
        }while (!($kimenet))
    }
    [string]ToString()
    {
        return "$($this.tag1).$($this.tag2).$($this.tag3).$($this.tag4)"
    }
}

Class Setting
{
    static $IPpattern = "^([1-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])(\.([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])){3}$"
    static $Switch = "10.59.1.252"
    static $log = 1
    static $port = 23
    static [int32]$waittime = 500
    static [int32]$maxhiba = 2
    static $gateway = "10.59."
    static $frissitomappanev = "HKR tudakozó"
    static $csvnevelotag = "Geplista"
    static $aktivnapok = 180

    Setting()
    {

    }
}

Class Eszkoz
{
    $Eszkoznev
    $IP
    $MAC
    $SwitchNev
    $SwitchIP
    $Port
    $Felhasznalo

    Eszkoz($IP, $eszkoznev)
    {
        $this.IP = $IP
        $this.Eszkoznev = $eszkoznev
    }

    Eszkoz($bemenet)
    {
        if($bemenet -match [Setting]::IPpattern)
        {
            $this.IP = $bemenet
        }
        else
        {
            $this.Eszkoznev = $bemenet
        }
    }

    SetNev($eszkoznev)
    {
        $this.Eszkoznev = $eszkoznev
    }

    SetIP($IP)
    {
        $this.IP = $IP
    }

    SetMAC($MAC)
    {
        $this.MAC = $MAC
    }

    SetSwitchnev($switchnev)
    {
        $this.SwitchNev = $switchnev
    }

    SetSwitchIP($switchIP)
    {
        $this.SwitchIP = $switchIP
    }

    SetPort($port)
    {
        $this.Port = $port
    }

    SetFelhasznalo()
    {
        $this.Felhasznalo = Get-UtolsoUser $this.Eszkoznev
        #$this.Felhasznalo = $felhasznalo
    }
}

Class Telnet
{
    Static Login()
    {
        $login = $false
        do
        {
            [Telnet]::SetSwitch()
            Clear-Host
            Write-Host "Bejelentkezés a $([Setting]::switch) switchre`n"
            [Telnet]::LoginCreds()
            $login = [Telnet]::TestConnection()

            if (!$login)
            {
                Write-Host "Újrapróbálkozol a switch bejelentkezési adatainak megadásával? Üss I-t, ha igen, bármely más billentyű esetén a program kilép" -ForegroundColor Red
                $valassz = Read-Host -Prompt "Válassz"
                if($valassz -ne "I")
                {
                    Exit
                }
            }
        }while(!$login)
    }

    Static SetConnection($switch, $felhasznalonev, $jelszo)
    {
        [Setting]::switch = $switch
        $script:felhasznalonev = $felhasznalonev
        $script:jelszo = $jelszo
    }

    Static LoginCreds()
    {
        $script:felhasznalonev = Read-Host -Prompt "Felhasználónév"
        $pwd = Read-Host -AsSecureString -Prompt "Jelszó"
        $script:jelszo = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($pwd))
    }

    Static SetSwitch()
    {
        Clear-Host
        Write-Host "Switch bejelentkezés`n"
        Write-Host "Az alapértelmezett switchet használod ($([Setting]::switch)), vagy megadod kézzel a címet?`nAdd meg a switch IP címét, ha választani szeretnél, vagy üss Entert, ha az alapértelmezettet használnád!"
        do
        {
            $kilep = $true
            $valassz = Read-Host "A switch IP címe"
            if ($valassz)
            {
                if (!(Test-Ping $valassz))
                {
                    $message = "A(z) $valassz IP címen nem található eszköz"
                    Add-Log "[SWITCH ELÉRHETETLEN] $message"
                    Write-Host "$message, add meg újra a címet, vagy üss Entert az alapértelmezett switch használatához!" -ForegroundColor Red
                    $kilep = $false
                }
                if($kilep)
                {
                    [Setting]::switch = $valassz
                }
            }
        }while(!$kilep)
    }

    Static [bool]TestConnection()
    {
        $login = $false
        Write-Host "`nKísérlet csatlakozásra..."
        $waittimeorig = [Setting]::waittime
        $logintest = [Telnet]::InvokeCommands("")
        $login = $logintest | Select-String -Pattern "#"
        if (!$login -or !$logintest)
        {
            $message = "A megadott felhasználónév: $($script:felhasznalonev), vagy a hozzá tartozó jelszó nem megfelelő, esetleg a(z) $([Setting]::switch) címen nincs elérhető switch"
            Add-Log "[SWITCH KAPCSOLÓDÁSI HIBA] $message"
            Write-Host "$message!" -ForegroundColor Red
            $login = $false
        }
        else
        {
            Add-Log "[SWITCH SIKERES KAPCSOLÓDÁS] A(z) $($script:felhasznalonev) sikeresen kapcsolódott a(z) $([Setting]::switch) switchez"
            $login = $true
        }
        return $login
    }

    Static [Object]InvokeCommands($parancsok)
    {
        $socket = $false
        $result = ""
        [String[]]$commands = @($script:felhasznalonev, $script:jelszo)
    
        foreach ($parancs in $parancsok)
        {
            $commands += $parancs
        }
    
        try
        {
            $socket = New-Object System.Net.Sockets.TcpClient([Setting]::switch, [Setting]::port)
        }
        catch
        {
            $result = $false
        }
    
        if($socket)
        {
            $stream = $socket.GetStream()
            $writer = New-Object System.IO.StreamWriter($stream)
            $buffer = New-Object System.Byte[] 1024
            $encoding = New-Object System.Text.ASCIIEncoding

            $waittime = [Setting]::waittime

            foreach ($command in $commands)
            {
                $writer.WriteLine($command)
                $writer.Flush()
                Start-Sleep -Milliseconds $waittime
            }
    
            Start-Sleep -Milliseconds $waittime
    
            while($stream.DataAvailable)
            {
                $read = $Stream.read($buffer, 0, 1024)
                $result += ($encoding.GetString($buffer, 0, $read))
            }
        }
        else
        {
            $result = $false
        }
    
        return $result
    }
}

Class Local
{
    [string]$Gepnev
    [string]$IPaddress
    [string]$MACaddress

    Local()
    {
        $getMAC = get-wmiobject -class "win32_networkadapterconfiguration" | Where-Object {$_.DefaultIPGateway -Match [Setting]::gateway}
        $kimenet = ($getMAC.MACAddress).Split(":")
        $this.MACaddress = "$($kimenet[0])$($kimenet[1]).$($kimenet[2])$($kimenet[3]).$($kimenet[4])$($kimenet[5])"
        $this.IPaddress = (($getMAC.IPAddress).Split(","))[0]
    }
}

Class Remote
{
    [string]$Gepnev
    [string]$IPaddress
    [string]$MACaddress
    $Online

    Remote()
    {
        $this.GetEszkoz()
    }

    Remote($keresetteszkoz)
    {
        $this.IPaddress = $keresetteszkoz
        if($this.Allapot($keresetteszkoz))
        {
            $this.IfIP()
        }
    }

    Remote($keresetteszkoz, [bool]$dontcheck)
    {
        $this.IPaddress = $keresetteszkoz
    }

    GetEszkoz()
    {
        $this.IPaddress = Read-Host -Prompt "Keresett eszköz IP címe, vagy neve"
        if($this.Allapot($this.IPaddress))
        {
            $this.IfIP()
        }
    }

    [bool]Allapot($ellenorzendo)
    {
        $this.Online = Test-Ping $ellenorzendo
        if(!$this.Online)
        {
            $message = "A(z) $($this.IPaddress) eszköz jelenleg nem elérhető"
            Add-Log "[ESZKOZ OFFLINE] $message"
            Write-Host "$message!" -ForegroundColor Red
        }
        return $this.Online
    }

    IfIP()
    {
        if(!($this.IPaddress -match [Setting]::IPpattern))
        {
            $this.Gepnev = $this.IPaddress
            $addresses = [System.Net.Dns]::GetHostAddresses($this.IPaddress)
            foreach ($address in $addresses)
            {
                if ($address -match [Setting]::gateway)
                {
                    $this.IPaddress = $address
                    Break
                }
            }
        }
    }

    [bool]Elerheto()
    {
        return $this.Online
    }

    [string]EszkozAllapot()
    {
        if($this.Online)
        {
            return "Online"
        }
        else
        {
            return "Offline"
        }
    }
}

Class Parancs
{
    Static [Object]HibaJavitassal($remote)
    {
        $result = $false
        do
        {
            $result = [Parancs]::Elkeszit($remote)
            if(!$result)
            {
                $remote.GetEszkoz()
            }
        }while(!$result)
        return $result
    }
    
    Static [Object]Elkeszit($remote)
    {
        if($remote.IPaddress | Select-String -pattern "10.59.58")
        {
            $result = $false
            $message = "A(z) $($remote.IPaddress) IP című eszköz a jelenlegitől eltérő VLAN-ban található"
            Add-Log "[VLAN ÁTJÁRÓ HIBA] $message"
            Write-Host "$message, így erről az eszközről nem lehet megkeresni!" -ForegroundColor Red
        }
        else
        {
            if(!($remote.IPaddress | Select-String -pattern $($script:local.IPaddress)))
            {
                ping $remote.IPaddress -n 1 | Out-Null
                $getRemoteMAC = arp -a | ConvertFrom-String | Where-Object { $_.P2 -eq $remote.IPaddress }
                try
                {
                    $kimenet = ($getRemoteMAC.P3).Split("-")
                    $remote.MACaddress = "$($kimenet[0])$($kimenet[1]).$($kimenet[2])$($kimenet[3]).$($kimenet[4])$($kimenet[5])"
                    $result = "traceroute mac $($script:local.MACaddress) $($remote.MACaddress)"
                }
                catch
                {
                    $result = $false
                    Add-Log "[ARP HIBA] A(z) $($remote.IPaddress) eszköz MACAdressének bejegyzése az ARP gyorsítótárban hibásan szerepel"
                }
            }
            else
            {
                $message = "A(z) $($remote.IPaddress) eszköz IP címe megegyezik a jelenlegi eszköz IP címével ($($script:local.IPaddress)). A keresés nem hajtható végre"
                Add-Log "[IP CÍM AZONOSSÁG] $message"
                Write-Host $message -ForegroundColor Red
                $result = $false
            }
        }
        
        return $result
    }
}

Class Lekerdezes
{
    $sikeres
    $result
    $switchnev
    $switchip
    $eszkozport
    $sorok

    Lekerdezes($keresesiparancs)
    {
        $failcount = 0
        $pinglocal = "ping $($script:local.IPaddress)"
        $pingremote = "ping $($script:remote.IPaddress)"
        [String[]]$parancs = @($pinglocal, $pingremote, $keresesiparancs)
        $waittimeorig = [Setting]::waittime
        do
        {
            Write-Host "A(z) $($script:remote.IPaddress) IP című eszköz helyének lekérdezése folyamatban..."
            $this.result = [Telnet]::InvokeCommands($parancs)
            if(!$this.result)
            {
                $message = "A(z) $($script:remote.IPaddress) című eszköz lekérdezése során a programnak nem sikerült csatlakozni a(z) $([Setting]::switch) IP című switchhez!"
                Add-Log "[KAPCSOLÓDÁSI HIBA] $message"
                Write-Host $message -ForegroundColor Red
            }
            elseif ($this.result | Select-String -Pattern "found on")
            {
                $this.sikeres = $true
            }
            if (!$this.Siker() -and $failcount -lt [Setting]::maxhiba)
            {
                $failcount++
                $visszamaradt = [Setting]::maxhiba - $failcount
                Write-Host "A(z) $($script:remote.IPaddress) eszköz helyének lekérdezés most nem járt sikerrel. Még $visszamaradt alkalommal újrapróbálkozom!" -ForegroundColor Yellow
                if ($failcount -eq [Setting]::maxhiba)
                {
                    Write-Host $this.result
                    Add-Log "[IDŐTÚLLÉPÉS] A(z) $($script:remote.IPaddress) eszköz helyének lekérdezése a(z) $([Setting]::switch) IP című switchről időtúllépés miatt nem sikerült"
                }
                [Setting]::waittime = [Setting]::waittime + 1000
            }
        }while (!$this.Siker() -and $failcount -lt [Setting]::maxhiba)
        [Setting]::waittime = $waittimeorig
    }

    Feldolgoz()
    {
        $talalat = 0
        $this.sorok = $this.result.Split("`r`n")
        for ($i = 0; $i -lt $this.sorok.Length; $i++)
        {
            if ($this.sorok[$i] | Select-String -pattern "=>")
            {
                $talalat = $i
            }
        }
        $utolsosor = $this.sorok[$talalat].Split(" ")
        $this.switchnev = $utolsosor[1]
        $this.switchip = $utolsosor[2]
        $this.eszkozport = $utolsosor[6]
        $this.Log()
    }

    Kiirat()
    {
        $consolout = $null
        foreach ($sor in $this.sorok)
        {
            if ($sor | Select-String -pattern "=>")
            {
                $consolout += "$sor`n"
            }
        }
        Clear-Host
        Write-Host "ESZKÖZ FIZIKAI HELYÉNEK MEGKERESÉSE`n"
        Write-Host "Az adatcsomagok útja erről az eszközről a(z) $($script:remote.IPaddress) IP című eszközig:"
        Write-Host $consolout
        Write-Host "A keresett eszköz a(z) $($this.switchnev) $($this.switchip) switch $($this.eszkozport) portján található." -ForegroundColor Green
    }

    ObjektumKitolto($eszkoz)
    {
        $eszkoz.SetSwitchNev($this.switchnev)
        $eszkoz.SetSwitchIP($this.switchip)
        $eszkoz.SetPort($this.eszkozport)
        $eszkoz.SetIP($script:remote.IPaddress)
        $eszkoz.SetMAC($script:remote.MACaddress)
        $eszkoz.SetFelhasznalo()
    }

    Log()
    {
        Add-Log "[SIKER] A(z) $($script:remote.IPaddress) IP című eszköz a(z) $($this.switchnev) $($this.switchip) switch $($this.eszkozport) portján található." -ForegroundColor Green
    }

    [bool]Siker()
    {
        return $this.sikeres
    }
}

Class Time
{
    $filetime

    Time()
    {
        [string]$this.filetime = Get-Date -Format "yyyy-MM-dd"
    }
    Static [String]Stamp()
    {
        Return Get-Date -Format "yyyy.MM.dd HH:mm"
    }

    [String]FileName()
    {
        Return $this.filetime
    }
}

Class Import
{
    Static AD($ADgeplista)
    {
        $script:elemszam = $ADgeplista.Length
        $script:eszkoz = New-Object 'object[]' $script:elemszam
        for($i = 0; $i -lt $script:elemszam; $i++)
        {
            $script:eszkoz[$i] = [Eszkoz]::New($ADgeplista[$i].Name)
            # A geplista-OUnev-OLD csv fájlba azonnal kitett gép objektumokkal biztosíthatjuk, hogy ha az első ellenőrzés során a program le is állna,
            # a következő futáskor ne terheljük az AD-t a gépek újboli lekérdezésével.
            $script:eszkoz[$i] | export-csv -encoding UTF8 -path $script:oldcsv -NoTypeInformation -Append -Force -Delimiter ";"
        }
    }

    Static CSV()
    {
        $csvdata = Import-Csv -Path $script:csv -Delimiter ";"
        if($script:csv -ne $script:oldcsv)
        {
            Rename-Item -Path $script:csv -NewName $script:oldcsvnev
        }
        
        $script:elemszam = $csvdata.Length
        $script:eszkoz = New-Object 'object[]' $script:elemszam
        for ($i=0; $i -lt $script:elemszam; $i++)
        {
            if ($csvdata[$i].IP)
            {
                $script:eszkoz[$i] = [Eszkoz]::New($csvdata[$i].IP)
            }
            else
            {
                $script:eszkoz[$i] = [Eszkoz]::New($csvdata[$i].Eszkoznev)
            }
        }
    }
}

function Get-Valasztas
{
## This function is responsible to check if users entered one of the allowed choices
    param($choice) # It receives an array of the possible choices, it's not fixed, so it doesn't matter if we have 2 allowed choices, or 30
    $probalkozottmar = $false
    #Write-Host $choice #For debug purposes
    do
    {        
        if ($probalkozottmar -eq $false) # Here the user enters their choice, if it's their first try
        {
            $valasztas = Read-Host -Prompt "Válassz"
        }
        else
        {
            Write-Host "`n`nKérlek csak a megadott lehetőségek közül válassz!" -ForegroundColor Yellow # This is the error message, the user gets here after every single bad entry
            $valasztas = Read-Host -Prompt "Válassz"
        }
        $teszt = $false
        for ($i=0; $i -lt $choice.Length; $i++) # This loop checks if the user entered an allowed value
        {
            if ($valasztas -eq $choice[$i])
            {
                $teszt = $true
                break # To get out of the loop if there's a match
            }
            $probalkozottmar = $true
        }
    } while ($teszt -ne $true)
    return $valasztas
}

function Get-YesNo
{
    Write-Host "(I) Igen`n(N) Nem"
    $confirm = Valaszt ("I", "N")
    return $confirm    
}

function Get-IPRange
{
    param ($elsoIP, $utolsoIP)

    $eszkoz = New-Object System.Collections.ArrayList($null)
    for($elsotag = $elsoIP.Tag1; $elsotag -le $utolsoIP.Tag1; $elsotag++)
    {
        $zaroIP2 = 255
        if($elsotag -eq $utolsoIP.Tag1)
        {
            $zaroIP2 = $utolsoIP.Tag2
        }
        if($elsotag -eq $elsoIP.Tag1)
        {
            $nyitoIP2 = $elsoIP.Tag2
        }
        else
        {
            $nyitoIP2 = 0
        }

        for ($masodiktag = $nyitoIP2; $masodiktag -le $zaroIP2; $masodiktag++)
        {
            $zaroIP3 = 255
            if(($masodiktag -eq $utolsoIP.Tag2) -and ($elsotag -eq $utolsoIP.Tag1))
            {
                $zaroIP3 = $utolsoIP.Tag3
            }
            if(($masodiktag -eq $elsoIP.Tag2) -and ($elsotag -eq $elsoIP.Tag1))
            {
                $nyitoIP3 = $elsoIP.Tag3
            }
            else
            {
                $nyitoIP3 = 0
            }
            
            for ($harmadiktag = $nyitoIP3; $harmadiktag -le $zaroIP3; $harmadiktag++)
            { 
                $zaroIP4 = 255
                if(($harmadiktag -eq $utolsoIP.Tag3) -and ($masodiktag -eq $utolsoIP.Tag2) -and ($elsotag -eq $utolsoIP.Tag1))
                {
                    $zaroIP4 = $utolsoIP.Tag4
                }
                if(($harmadiktag -eq $elsoIP.Tag3) -and ($masodiktag -eq $elsoIP.Tag2) -and ($elsotag -eq $elsoIP.Tag1))
                {
                    $nyitoIP4 = $elsoIP.Tag4
                }
                else
                {
                    $nyitoIP4 = 0
                }
                for ($negyediktag = $nyitoIP4; $negyediktag -le $zaroIP4; $negyediktag++)
                {
                    $ipstring = "$($elsotag).$($masodiktag).$($harmadiktag).$($negyediktag)"
                    $eszkoz.Add([Remote]::New($ipstring, $false)) > $null
                }
            }
        }
    }
    return $eszkoz
}

# Ez a függvény kérdezi le egy online számítógép esetében a jelenleg bejelentkezett
# user felhasználónevét.
function Get-UtolsoUser
{
    param ($gepnev)
    
    try
    {
        $utolsouserfull = (Get-WmiObject -Class win32_computersystem -ComputerName $gepnev).Username # Bekérjük a user felhasználónevét
        $utolsouser = $utolsouserfull.Split("\") # A név STN\bejelenkezési név formátumban jön. Ezt szétbontjuk, hogy megkapjuk a bejelentkezési nevet
        $user = Get-ADUser $utolsouser[1] # A bejelentkezési névvel lekérjük a felhasználó adatait
        return $user.Name # A felhasználó megjelenő nevét adjuk vissza eredményként
    }
    
    catch [System.Runtime.InteropServices.COMException]
    {
        return "Felhasználónév lekérése megtagadva!"
    }

    catch
    {
        return "Nincs bejelentkezett felhasználó"
    }
}

function Get-IPcount
{
    param ($elsoIP, $utolsoIP)
        
    $elsotag = $utolsoIP.tag1 - $elsoIP.tag1 + 1
    $masodiktag = (256 - $elsoIP.tag2) + ($utolsoIP.tag2+1) + ((($elsotag - 2) * 256))
    $harmadiktag = (256 - $elsoIP.tag3) + ($utolsoIP.tag3+1) + ((($masodiktag - 2) * 256))
    $negyediktag = (256 - $elsoIP.tag4) + ($utolsoIP.tag4+1) + ((($harmadiktag - 2) * 256))

    return $negyediktag
}

function Import-IPaddresses
{
    do
    {
        $endloop = $true
        Clear-Host
        Write-Host "IP TARTOMÁNY ELLENŐRZŐ`n"
        if ($debug -ne 1)
        {
            Write-Host "Kérlek add meg a lekérdezni kívánt IP tartomány első IP címét"
            $script:elsoIP = New-Object IPcim(Read-Host -Prompt "Első IP cím")
            Write-Host "Kérlek add meg a lekérdezni kívánt IP tartomány utolsó IP címét"
            $script:utolsoIP = New-Object IPcim(Read-Host -Prompt "Utolsó IP cím")
        }
        else
        {
            $elsoIP = New-Object IPcim $debugip1
            $utolsoIP = New-Object IPcim $debugip2
        }

        $ipdarab = Get-IPcount $elsoIP $utolsoIP

        if ($elsoIP.ToString() -eq $utolsoIP.ToString())
        {
            Write-Host "A megadott IP címek megegyeznek! Egy billentyű leütését követően add meg újra lekérdezni kívánt tartományt!" -ForegroundColor Red
            Read-Host
            $endloop = $false
        }
        elseif($ipdarab -lt 1)
        {
            Write-Host "A kezdőként megadott IP cím magasabb, mint az utolsóként megadott! Így a lekérdezés nem folytatható le!`nEgy billentyű leütését követően kérlek add meg újra a lekérdezni kívánt tartományt!" -ForegroundColor Red
            Read-Host
            $endloop = $false
        }
        elseif(($ipdarab -gt 254) -and ($debug -ne 1))
        {
            Write-Host "A megadott tartományban $ipdarab darab IP cím található. Egészen biztos vagy benne, hogy ennyi eszközt szeretnél egyszerre lekérdezni?`nAz összes cím lekérdezése hosszú időt vehet igénybe!" -ForegroundColor Yellow
            Write-Host "Amennyiben mégis szeretnéd a lekérdezést futtatni, üss I betűt, amennyiben más tartományt adnál meg, üss N betűt!"
            $valassz = Get-YesNo

            if($valassz -eq "N")
            {
                $endloop = $false
            }
        }
    }while(!$endloop)
    $eszkozok = Get-IPRange $elsoIP $utolsoIP
    
    return $eszkozok
}

function Get-IPaddressesState
{
    $eszkozok = Import-IPaddresses
    $filetime = Get-Date -Format "yyyyMMddHHmm"
    $csvnev = "IP_Címlista_$($elsoIP.ToString())-$($utolsoIP.ToString())_$($filetime).csv"

    Clear-Host
    Write-Host "A(Z) $($elsoIP.ToString()) - $($utolsoIP.ToString()) IP TARTOMÁNY LEKÉRDEZÉSE`n"

    foreach ($eszkoz in $eszkozok)
    {
        Write-Host "$($eszkoz.IPaddress) kapcsolatának ellenőrzése" -NoNewline
        switch ($method)
        {
            1 { $online = Test-Ping $eszkoz.IPaddress }
            2 { $online = (Test-Connection $eszkoz.IPaddress -Quiet -Count 1) }
            Default{ $online = Test-Ping $eszkoz.IPaddress }
        }

        $eszkoz.Online = $online
        $name = ""
        $neve = ""
        if($online -and ($nevgyujtes -eq 1))
        {
            try
            {
                $namesplit = ([System.Net.DNS]::GetHostEntry($eszkoz.IPaddress)).HostName
                $kimenet = $namesplit.Split(".")
                $name = $kimenet[0]
            }
            catch [System.Net.Sockets.SocketException]
            {
                $name = "Nem elérhető"
            }

            $neve = "; Neve: $name"
        }

        if($nevgyujtes -eq 1)
        {
            $eszkoz.Gepnev($name)
        }

        $eszkoz.Online = $eszkoz.EszkozAllapot()
        Write-Host "`r$($eszkoz.IPaddress): Állapota: $($eszkoz.Online)$neve                  "
        $logtime = Get-Date -Format "yyyy.MM.dd HH:mm"
        Add-Log "[ESZKÖZ ÁLLAPOT] $($eszkoz.IPaddress): Állapota: $($eszkoz.Online)$neve Idő: $logtime"
        if(($logonline -eq 1) -and ($logoffline -eq 1))
        {
            $eszkoz | export-csv -encoding UTF8 -path ".\Logfiles\$csvnev" -NoTypeInformation -Append -Force -Delimiter ";"
        }
        elseif(($logonline -eq 1) -and $online)
        {
            $eszkoz | export-csv -encoding UTF8 -path ".\Logfiles\$csvnev" -NoTypeInformation -Append -Force -Delimiter ";"
        }
        elseif(($logoffline -eq 1) -and !$online)
        {
            $eszkoz | export-csv -encoding UTF8 -path ".\Logfiles\$csvnev" -NoTypeInformation -Append -Force -Delimiter ";"
        }
    }
}

function Get-TrueFalse
{
    param($ertek)

    if ($ertek -eq 1)
    {
        Write-Host "Bekapcsolva" -ForegroundColor Green
    }
    else
    {
        Write-Host "Kikapcsolva" -ForegroundColor Red
    }
}


function Test-Ping {
    param ($ipcim)

    $ping = New-Object System.Net.NetworkInformation.Ping
    if (!$script:pingoptions)
    {
        $script:pingoptions = New-Object System.Net.NetworkInformation.PingOptions
        $script:pingoptions.TTL = 64
        $script:pingoptions.DontFragment = $true
    }
    try
    {
        $reply = $ping.Send($ipcim,20,16,$script:pingoptions)
    }
    catch {
    }

    if ($reply.status -eq "Success")
    {
        return $true
    }
    else
    {
        return $false
    }
}

# Ezt a függvényt egy másik programomból emeltem át (amelyet a GitHubra is feltöltöttem),
# így a kommentek angolul vannak benne.
# A feladata, hogy a normál könyvtárjellegű OU nevet lefordítsa a tartományon belüli
# kereséshez használt distinguishedname formátumra.
function Get-DistinguishedName
{
    param($bemenet) #OU name in the form you can find it in ADUC
    $kimenet = $bemenet.Split("/") #Splitting the OU name by slash characters
    
    for ($i = $kimenet.Length-1; $i -gt -1; $i--) #Loop starts from the last section of the string array to put them to the front
    {
        if ($i -ne 0) #Do the conversion until we get to the DC part
        {
            if ($i -eq $kimenet.Length-1) # This conditional is used to get the OU name from the whole path, so we can use it as as folder, or filename
            {
                $Script:ounev = $kimenet[$i]
            }
            $forditott += "OU="+ $kimenet[$i]+","
        }
        else #Here's where we turn DC name into DistinguishedName format too
        {
            $dcnevold = $kimenet[$i]
            $dcnevtemp = $dcnevold.Split(".")
            for ($j = 0; $j -lt $dcnevtemp.Length; $j++)
            {
                if ($j -lt $dcnevtemp.Length-1) #It's needed so there won't be a comma at the end of the output
                    {
                        $dcnev += "DC="+$dcnevtemp[$j]+","
                    }
                else 
                    {
                        $dcnev += "DC="+$dcnevtemp[$j]
                    }    
            }
            $forditott += $dcnev
        }
    }    
    return $forditott #OU name in DistinguishedName form
}

# Hasonlóan az OUnevfordito függvényhez, ez is egy másik programból származik
# Ennek a függvénynek az a feladata, hogy ellenőrzötten bekérje a lekérdezni kívánt OU elérési útját
function Set-OU
{
    param($bemenet)
    $eredetiou = $bemenet
    $time = (Get-Date).Adddays(-([Setting]::aktivnapok)) # Csak azokkal foglalkozunk, amik a megadott időn belül voltak bekapcsolva
    do 
    {
        if(!($bemenet)) # Ez az elágazás csak az első (sikertelen) futást követően lép életbe
        {
            Write-Host "FIGYELMEZTETÉS! A megadott OU nem létezik, vagy nem tartalmaz a kritériumnak megfelelő számítógépeket!" -ForegroundColor Red
            Write-Host "A mellékelt CSV fájl használatához üss Entert, amennyiben pedig másik OU-t használnál, add meg az elérési útját."
            $eredetiou = Read-Host -Prompt "Elérési út"
        }

        $bemenet = $true
        if($eredetiou) # Ebbe az elágazásba akkor lépünk be, ha beírtunk bármit az előző elágazás során
        {
            $ou = Get-DistinguishedName $eredetiou
            $script:usecsv = Test-CSV $Script:ounev # Teszteljük, hogy korábban futtatuk-e már az adott OU-n ugyanezt a folyamatot
            if(!($script:usecsv))
            {
                try
                {
                    $geplista = Get-ADComputer -Filter {LastLogonTimeStamp -gt $time} -SearchBase $ou
                }
                catch
                {
                    $bemenet = $false # Ha a géplistát nemlétező OU-ból kérnénk le, úgy ezt a kivételt kapjuk
                }
                if($geplista.Length -eq 0) # Ebbe az elágazásba akkor lépünk, ha az OU-ban nincsenek gépek
                {
                    $bemenet = $false
                }
            }
        }
    }while(!($bemenet))

    if($eredetiou)
    {
        return $geplista
    }
    else
    {
        return $false
    }
}

Function Test-CSV
{
    Param($kozeptag)
    $script:csvnev = "$csvnevelotag-$kozeptag.csv"
    $script:oldcsvnev = "$csvnevelotag-$kozeptag-OLD.csv"
    $script:csv = ".\Logfiles\$script:csvnev"
    $script:oldcsv = ".\Logfiles\$script:oldcsvnev"
    $script:csvsave = $script:csv

    if (Test-Path $script:oldcsv)
    {
        if (Test-Path $script:csv)
        {
            [string]$leallasideje = (((Get-ChildItem -Path ".\Logfiles" -Filter $script:csvnev -Force).LastWriteTime)).ToString("yyyy.MM.dd HH.mm")
            # Erre az ellenőrzésre azért van szükség, hogy egy véletlenül letörölt CSV fájl ne akassza ki a program működését
            Remove-Item -Path $script:csv
        }
        Add-Log "[FIGYELMEZTETÉS] A program utolsó futása váratlan véget ért: $leallasideje-kor"
        $script:csv = $script:oldcsv
        Return $true
    }
    elseif (Test-Path $script:csv)
    {
        Return $true
    }
    else
    {
        Return $false
    }
}

function Add-Log {
    param ($logtext)

    if($config.log -ne "0") # A config.ini log bejegyzését 0-ra állítva a logolás kikapcsolható
    {
        $logtext | Out-File ".\Logfiles\IP-cim.log" -Append -Force -Encoding unicode
    }
}

function Set-Settings
{
    do
    {
        Clear-Host
        Write-Host "IP TARTOMÁNY ELLENŐRZŐ`n`nBEÁLLÍTÁSOK"

        $csvsavemode = 0
        if (($logonline -eq 1) -and ($logoffline -eq 1))
        {
            $optlogonline = "Az Online és Offline gépek is mentésre kerülnek"
            $csvsavemode = 1
        }
        elseif (($logonline -eq 1) -and ($logoffline -eq 0))
        {
            $optlogonline = "Csak az Online gépek kerülnek mentésre"
            $csvsavemode = 2
        }
        elseif (($logonline -eq 0) -and ($logoffline -eq 1))
        {
            $optlogonline = "Csak az Offline gépek kerülnek mentésre"
            $csvsavemode = 3
        }
        else
        {
            $optlogonline = "Az eredmények nem kerülnek mentésre"
            $csvsavemode = 0
        }

        if ($method -eq 2)
        {
            $optmethod = "Sokkal lassabb, de valamivel megbízhatóbb"
        }
        else
        {
            $optmethod = "Gyors, de néha ad fals negatív eredményt"
        }

        Write-Host "(1) Az online eszközök nevének gyűjtése (bizonyos esetekben jelentősen lassíthatja a folyamatot): " -NoNewline
        Get-TrueFalse $nevgyujtes
        Write-Host "(2) Debug mód: " -NoNewline
        Get-TrueFalse $debug
        Write-Host "(3) Minden eredmény logolása: " -NoNewline
        Get-TrueFalse $log
        Write-Host "(4) A folyamat során készülő CSV fájlba: $optlogonline"
        Write-Host "(5) A lekérdezés módja: $optmethod"
        Write-Host "A beállítások megváltoztatásához használd a mellettük látható számbillentyűket, a folyamatban lévő továbblépéshez üsd le a K betűt!"
        $valasztas = Read-Host -Prompt "Valassz"

        switch ($valasztas)
        {
            1 { if ($nevgyujtes -eq 1) { $global:nevgyujtes = 0} else { $global:nevgyujtes = 1} }
            2 { if ($debug -eq 1) { $global:debug = 0} else { $global:debug = 1} }
            3 { if ($log -eq 1) { $global:log = 0} else { $global:log = 1} }
            4 { if ($csvsavemode -lt 3) { $csvsavemode++ } else { $csvsavemode = 0 } switch ($csvsavemode) { 1 { $global:logonline = 1; $global:logoffline = 1 } 2 { $global:logonline = 1; $global:logoffline = 0 } 3 { $global:logonline = 0; $global:logoffline = 1 } 0 { $global:logonline = 0; $global:logoffline = 0 }}}
            5 { if ($method -eq 1) { $global:method = 2} else { $global:method = 1} }
            default {}
        }
    } while ($valasztas -ne "K")

    Write-Host "Szeretnéd menteni a beállításokat, hogy legközelebb is ezeket használja a program?"
    Write-Host "Üss I-t, ha igen, N-t, ha nem."
    $valasztas = Get-YesNo

    if($valasztas -eq "I")
    {
        Write-Settings
    }
}

function Write-Settings {
    "nevgyujtes = $global:nevgyujtes" | Out-File .\config.ini
    "log = $global:log" | Out-File .\config.ini -Append
    "debug = $global:debug" | Out-File .\config.ini -Append
    "debugip1 = $global:debugip1" | Out-File .\config.ini -Append
    "debugip2 = $global:debugip2" | Out-File .\config.ini -Append
    "logonline = $global:logonline" | Out-File .\config.ini -Append
    "logoffline = $global:logoffline" | Out-File .\config.ini -Append
    "method = $global:method" | Out-File .\config.ini -Append
}
function Get-EgyszeriLekerdezes
{
    do
    {
        $script:remote = [Remote]::New()
        if($script:remote.Elerheto())
        {
            $global:keresesiparancs = [Parancs]::HibaJavitassal($remote)
        }
        else
        {
            Write-Host "Add meg újra az IP címet, vagy nevet!" -ForegroundColor Red
        }
    }while(!$global:keresesiparancs -or !$script:remote.Elerheto())
}

function Set-ParancsKiiratas
{
    Get-EgyszeriLekerdezes
    Clear-Host
    Write-Host "ESZKÖZ FIZIKAI HELYÉNEK MEGKERESÉSE`n"
    Write-Host "Helyi IP cím:           $($script:local.IPaddress) (ezt kell pingelni a switchről, ha a TraceRoute parancs 'Error: Source Mac address not found.' hibát ad."
    Write-Host "Keresett eszköz IP-je:  $($script:remote.IPaddress) (ezt kell pingelni a switchről, ha a TraceRoute parancs 'Error: Destination Mac address not found.' hibát ad."
    Write-Host "Keresési parancs:       $global:keresesiparancs (automatikusan a vágólapra másolva)`n"
    Set-Clipboard $global:keresesiparancs
    Write-Host "A folyamat végetért. Egy billentyű leütésére a program kilép."
    Read-Host
}

function Set-Kiiratas
{
    Get-EgyszeriLekerdezes
    [Telnet]::Login()
    $lekerdezes = [Lekerdezes]::New($global:keresesiparancs)
    if($lekerdezes.Siker())
    {
        $lekerdezes.Feldolgoz()
        $lekerdezes.Kiirat()
    }
}

function Import-ADList
{
    $filetime = [Time]::New()
    $ADgeplista = $false

    Clear-Host
    Write-Host "Kérlek szúrd be a lekérdezni kívánt OU elérési útját!"
    do
    {
        $valaszt = Read-Host -Prompt "Válassz"
        $ADgeplista = Set-OU $valaszt
        if($ADgeplista)
        {
            [Import]::AD($ADgeplista) # Meghívjuk az importáló osztály ADból imortálást végző statikus metódusát
            Add-Log "[LEKÉRDEZÉS MEGKEZDVE] A(z) $($script:ounev) OU gépeinek helyének lekérdezése megkezdődött: $([Time]::Stamp())-kor"
        }
        else
        {
            Write-Host $adgeplista
            Write-Host "Hibás OU-t adtál meg, vagy az OU-ban nincsenek számítógépek! Kérlek add meg a helyes OU elérési utat!" -ForegroundColor Red
        }
    }while(!$ADgeplista)
    [Telnet]::Login()

    # Itt kezdődik a függvény munkaciklusa. Ezen belül történik a lekérdezést végző függvény meghívása
    # és az adatok CSV fájlból való beolvasása (utóbbi akkor is, ha eleve CSV-ből vesszük az adatokat,
    # és akkor is, ha a program a saját maga által, egy korábbi ciklusban készített fájlokat használja)
    do
    {
        $keszdb = 0
        # Ez az elágazás fut le akkor is, ha nem adtunk meg OU-t, és akkor is, ha a ciklus egyszer már lefutott az AD-ból vett adatokkal
        if (!($ADgeplista))
        {
            Test-CSV $Script:ounev | Out-Null
            [Import]::CSV()
        }

        # Ez a ciklus végzi el a munkát
        for($i = 0; $i -lt $script:elemszam; $i++)
        {
            $sorszam = $i + 1
            $fail = $true
            Write-Host "A FOLYAMAT ÁLLAPOTA: $sorszam/$script:elemszam`nA(z) $($eszkoz[$i].Eszkoznev) eszköz lekérdezése folyamatban."
            $script:remote = [Remote]::New($eszkoz[$i].Eszkoznev)
            if($remote.Elerheto())
            {
                $keresesiparancs = [Parancs]::Elkeszit($remote)
                if($keresesiparancs)
                {
                    $lekerdezes = [Lekerdezes]::New($keresesiparancs)
                    if($lekerdezes.Siker())
                    {
                        $lekerdezes.Feldolgoz()
                        $lekerdezes.ObjektumKitolto($eszkoz[$i])
                        $keszdb++
                        $eszkoz[$i] | export-csv -encoding UTF8 -path ".\geplista.csv" -NoTypeInformation -Append -Force -Delimiter ";"
                        $fail = $false
                    }
                }
            }

            if($fail)
            {
                $eszkoz[$i] | export-csv -encoding UTF8 -path $script:csvsave -NoTypeInformation -Append -Force -Delimiter ";"
            }
        }

        foreach($eszk in $eszkoz)
        {
            Write-Host $eszk
            $eszk
        }

        # Mivel eddigre a ciklus végigment az összes gépen, és a kimaradt gépek listája teljes,
        # az előző, backupként használható lista törölhető.
        if (Test-Path $script:oldcsv)
        {
            Remove-Item -Path $script:oldcsv
        }

        # Mivel innentől már nem AD-ból vesszük az adatokat, ezért a ciklus elején lévő elágazásba
        # is be kell majd lépnünk. És mivel az előző futás során készült egy fájl a kimaradt gépekről,
        # így ha CSV-ből vettük eredetileg az adatokat, akkor azt is figyelmen kívül lehet innentől hagyni.
        # Ezért mindkét változó értékét $false-ra állítjuk itt.
        $ADgeplista = $false

        # Mivel itt érezhető teljesítményromlást nem eredményezne, meghívjuk a szemétgyűjtőt.
        # A használt objektumok kis mérete miatt nem valószínű, hogy szükséges, de ártani nem árthat.
        [System.GC]::Collect()

        # Ha nem vagyunk meg minden géppel, belépünk a késleltető ciklusba,
        # ami a fő ciklust pihenteti egy kicsit.
        if ($script:elemszam -ne $keszdb)
        {
            for ($i = 0; $i -lt $ujraprobalkozas; $i++)
            {
                $remaining = $ujraprobalkozas - $i
                Write-Host "`rA folyamat folytatódik $remaining másodperc múlva.    " -NoNewline
                Start-Sleep -s 1
            }
            Write-Host "`r                                                                  "
            Write-Host "A FOLYAMAT FOLYTATÓDIK"
        }
        Read-Host
    }while ($script:elemszam -ne $keszdb) # Ha a lista és kész gépek elemszáma megegyezik, a futás végetért
    $message = "A(z) $($script.OUnev) OU számítógépeinek helyének lekérdezése sikeresen befejeződött $([Time]::Stamp())-kor"
    Add-Log "[FOLYAMAT VÉGE] $message"
    Write-Host "$message`nA program egy billetnyű leütését követőe kilép."
    Read-Host
}

$local = [Local]::New()

Write-Host "Eszközkereső`n"
Write-Host "Válassz az alábbi menüpontok közül:"
Write-Host "(1) Egy eszköz lekérdezése"
Write-Host "(2) Eszköz lekérdezéséhez szükséges parancs vágólapra másolása"
Write-Host "(3) Egy OU minden számítógépének lekérdezése, és fájlba mentése"
Write-Host "(4) Egy IP cím tartomány minden számítógépének lekérdezése, és fájlba mentése"
$valassz = Get-Valasztas ("1", "2", "3", "4")

switch ($valassz) {
    1 { Set-Kiiratas }
    2 { Set-ParancsKiiratas }
    3 { Import-ADList }
    4 { Get-IPaddressesState }
    Default {}
}