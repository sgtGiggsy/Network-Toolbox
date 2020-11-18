#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#
#-#-#                                     OSZTÁLYOK                                           #-#-#
#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#

#####
##
##  Segítő osztályok. Ebben a részben találhatóak a részfeladatokat végző osztályok
##
#####

Class Setting
{
    $log
    $logtime
    $debug
    $nevgyujtes
    $logonline
    $logoffline
    $Switch
    $port
    [int32]$waittime
    [int32]$maxhiba
    [int32]$retrytime
    $csvkonyvtar
    $csvnevelotag
    $aktivnapok
    $logfile = ".\Logfiles\NetworkToolbox.log"
    ## FIX változók
    $IPpattern = "^([1-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])(\.([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])){3}$"
    $hiba
    $admin
    $AD

    Setting()
    {
        if (!(Test-Path .\Logfiles))
        {
            New-Item -Path . -Name "Logfiles" -ItemType "Directory" | Out-Null
        }

        $this.DefaultSettings()
        $this.AdminState()
        $this.ADmodul()

        if(Test-Path ".\config.ini")
        {
            $this.FromFile()
        }
        else
        {
            Write-Host "A CONFIG.INI FÁJL HIÁNYZIK, VAGY SÉRÜLT!" -ForegroundColor Red
            $this.hiba = 1
        }

        if ($this.hiba)
        {
            switch ($this.maxhiba)
            {
                1 { Add-Log "[KONFIGURÁCIÓS HIBA] A konfigurációs fájl hiányzik, vagy sérült" }
                2 { Add-Log "[KONFIGURÁCIÓS HIBA] A konfigurációs fájlban hibás érték(ek) szerepel(nek)" }
                3 { Add-Log "[KONFIGURÁCIÓS HIBA] Ismeretlen hiba a konfigurációs fájllal" }
                Default {}
            }
            Write-Host "A program az alapértelmezett beállításokkal fog futni. A folytatáshoz üss le egy billentyűt!"
            Read-Host
        }
    }

    FromFile()
    {
        $config = @{}
        try
        {
            $ErrorActionPreference = "Stop"
            $config = Get-Content ".\config.ini" | Out-String | ConvertFrom-StringData
        }
        catch [System.ArgumentException]
        {
            Write-Host "HIBA A KONFIGURÁCIÓS FÁJLBAN!" -ForegroundColor Red
            Write-Host "Valószínűleg hiányzik egy \ jel valahonnan, ahol kettőnek kellene lennie egymás mellett" -ForegroundColor Yellow
            $this.hiba = 2
        }
        catch
        {
            Write-Host "ISMERETLEN HIBA!" -ForegroundColor Red
            $this.hiba = 3
        }

        if($this.hiba)
        {
            $this.DefaultSettings()
        }
        else
        {
            foreach ($key in @($config.keys))
            {
                if ($config[$key] -eq "True")
                {
                    $config[$key] = $true
                }
                elseif ($config[$key] -eq "False")
                {
                    $config[$key] = $false
                }
            }
            $this.log = $config.log
            $this.logtime = $config.logtime
            $this.debug = $config.debug
            $this.logonline = $config.logonline
            $this.logoffline = $config.logoffline
            $this.nevgyujtes = $config.nevgyujtes
            $this.Switch = $config.switch
            $this.port = $config.port
            [int32]$this.waittime = $config.waittime
            [int32]$this.maxhiba = $config.maxhiba
            [int32]$this.retrytime = $config.retrytime
            $this.csvnevelotag = $config.csvnevelotag
            $this.csvkonyvtar = $config.csvkonyvtar
            $this.aktivnapok = $config.aktivnapok
        }
    }

    DefaultSettings()
    {
        $this.log = $true
        $this.logtime = $true
        $this.debug = $false
        $this.nevgyujtes = $true
        $this.logonline = $true
        $this.logoffline = $true
        $this.Switch = "10.59.1.252"
        $this.port = 23
        [int32]$this.waittime = 500
        [int32]$this.maxhiba = 4
        [int32]$this.retrytime = 600
        $this.aktivnapok = 180
        $this.csvnevelotag = "Geplista"
        $this.csvkonyvtar = ".\Logfiles"
        $this.logfile = ".\Logfiles\NetworkToolbox.log"
    }

    AdminState()
    {
        $adminobj = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
        $this.admin = $adminobj.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    }

    ADmodul()
    {
        $this.AD = $true
        if (!(Get-Module -ListAvailable -Name ActiveDirectory)) 
        {
            try
            {
                $ErrorActionPreference = "Stop"
                Import-Module .\Microsoft.ActiveDirectory.Management.dll
                Import-Module .\Microsoft.ActiveDirectory.Management.resources.dll
            }
            catch
            {
                Add-Log "[HIÁNYZÓ MODUL] Az AD modul nincs telepítve, és a kapcsolódó DLL-ek sem találhatóak"
                $this.AD = $false
            }
        }
        if($this.AD)
        {
            try
            {
                Get-ADUser teszt
            }
            catch #[Microsoft.ActiveDirectory.Management.ADServerDownException]
            {
                Add-Log "[ELÉRHETETLEN ACTIVE DIRECTORY] A hálózaton nincs elérhető Active Directory kiszolgáló"
                $this.AD = $false
            }
        }
    }

    ModifyConfig()
    {
        $valasztas = $false
        do
        {
            Show-Cimsor "BEÁLLÍTÁSOK"

            $csvsavemode = 0
            if ($this.logonline -and $this.logoffline)
            {
                $optlogonline = "Az Online és Offline gépek is mentésre kerülnek"
                $csvsavemode = 1
            }
            elseif ($this.logonline -and !$this.logoffline)
            {
                $optlogonline = "Csak az Online gépek kerülnek mentésre"
                $csvsavemode = 2
            }
            elseif (!$this.logonline -and $this.logoffline)
            {
                $optlogonline = "Csak az Offline gépek kerülnek mentésre"
                $csvsavemode = 3
            }
            else
            {
                $optlogonline = "Az eredmények nem kerülnek mentésre"
                $csvsavemode = 0
            }

            if ($this.method -eq 2)
            {
                $optmethod = "Sokkal lassabb, de valamivel megbízhatóbb"
            }
            else
            {
                $optmethod = "Gyors, de néha ad fals negatív eredményt"
            }
            Write-Host "(1) Logolás: " -NoNewline
            Get-TrueFalse $this.log
            Write-Host "(2) Időbélyegző a logokhoz: " -NoNewline
            Get-TrueFalse $this.logtime
            Write-Host "(3) Debug mód: " -NoNewline
            Get-TrueFalse $this.debug
            Write-Host "(4) Pingelés során az online eszközök nevének gyűjtése (bizonyos esetekben jelentősen lassíthatja a folyamatot): " -NoNewline
            Get-TrueFalse $this.nevgyujtes
            Write-Host "(5) A pingelési folyamat során készülő CSV fájlba: $optlogonline"
            Write-Host "(6) A lekérdezés módja: $optmethod"
            Write-Host "(7) Az eszközök kereséséhez használt switch IP címe: $($this.Switch)"
            Write-Host "(8) Alapértelmezett várakozási idő két switch parancs között miliszekundumban: $($this.waittime)"
            Write-Host "(9) Maximális újrapróbálkozások száma sikertelen eredmény esetén: $($this.maxhiba)"
            Write-Host "(10) AD lekérdezés esetén ennyi napon belül belépett gépek használata: $($this.aktivnapok)"
            Write-Host "(11) A logok mentésének jelenlegi fájlja: $($this.logfile)"
            Write-Host "(K) Beállítások véglegesítése"
            Write-Host "A beállítások megváltoztatásához használd a mellettük látható számbillentyűket!"
            $valasztas = Get-Valasztas ("1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "K")

            switch ($valasztas)
            {
                1 { if ($this.log) { $this.log = $false} else { $this.log = $true} }
                2 { if ($this.logtime) { $this.logtime = $false} else { $this.logtime = $true} }
                3 { if ($this.debug) { $this.debug = $false} else { $this.debug = $true} }
                4 { if ($this.nevgyujtes) { $this.nevgyujtes = $false} else { $this.nevgyujtes = $true} }
                5 { if ($csvsavemode -lt 3) { $csvsavemode++ } else { $csvsavemode = 0 } }
                6 { if ($this.method -eq 1) { $this.method = 2} else { $this.method = 1} }
                7 { [Telnet]::SetSwitch() }
                8 { try { [int32]$this.waittime = Read-Host -Prompt "Várakozási idő" } catch { Write-Host "HIBÁS ÉRTÉK" -ForegroundColor Red; Read-Host } }
                9 { try { [int32]$this.maxhiba = Read-Host -Prompt "Megengedett hibaszám" } catch { Write-Host "HIBÁS ÉRTÉK" -ForegroundColor Red; Read-Host } }
                10 { try { [int32]$this.aktivnapok = Read-Host -Prompt "Ennyi napon belül aktív gépek" } catch { Write-Host "HIBÁS ÉRTÉK" -ForegroundColor Red; Read-Host } }
                11 { Write-Host "A program gyökérkönyvtárára a '.\' kezdéssel lehet hivatkozni."; $templog = Read-Host -Prompt "Log mentési hely"; if(!$templog) { Write-Host "HIBÁS ÉRTÉK" -ForegroundColor Red; Read-Host } else { $this.logfile = $templog } }
                default {}
            }

            switch ($csvsavemode)
            {
                1 { $this.logonline = $true; $this.logoffline = $true }
                2 { $this.logonline = $true; $this.logoffline = $false }
                3 { $this.logonline = $false; $this.logoffline = $true }
                0 { $this.logonline = $false; $this.logoffline = $false }
            }
        } while ($valasztas -ne "K")

        Write-Host "Szeretnéd menteni a beállításokat, hogy legközelebb is ezeket használja a program?"
        Write-Host "Üss I-t, ha igen, N-t, ha nem."
        $valasztas = Get-YesNo

        if($valasztas -eq "I")
        {
            $this.SaveConfig()
        }
    }

    SaveConfig()
    {
        $path = $this.logfile -Replace "\\", "\\"
        "log = $($this.log)" | Out-File .\config.ini
        "logtime = $($this.logtime)" | Out-File .\config.ini -Append
        "debug = $($this.debug)" | Out-File .\config.ini -Append
        "nevgyujtes = $($this.nevgyujtes)" | Out-File .\config.ini -Append
        "logonline = $($this.logonline)" | Out-File .\config.ini -Append
        "logoffline = $($this.logoffline)" | Out-File .\config.ini -Append
        "switch = $($this.Switch)" | Out-File .\config.ini -Append
        "port = $($this.port)" | Out-File .\config.ini -Append
        "waittime = $($this.waittime)" | Out-File .\config.ini -Append
        "maxhiba = $($this.maxhiba)" | Out-File .\config.ini -Append
        "retrytime = $($this.retrytime)" | Out-File .\config.ini -Append
        "aktivnapok = $($this.aktivnapok)" | Out-File .\config.ini -Append
        "csvnevelotag = $($this.csvnevelotag)" | Out-File .\config.ini -Append
        "csvkonyvtar = $($this.csvkonyvtar)" | Out-File .\config.ini -Append
        "logfile = $($path)" | Out-File .\config.ini -Append
    }
}

Class Time
{
    $filetime

    Time()
    {
        [string]$this.filetime = Get-Date -Format "yyyyMMdd_HHmm"
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

#####
##
##  Objektumok. Ebben a részben találhatóak a kezelendő objektumokhoz készített osztályok
##
#####

Class Eszkoz
{
    $Eszkoznev
    $IPaddress
    $MACaddress
    $SwitchNev
    $SwitchIP
    $Port
    $Felhasznalo

    Eszkoz($IP, $eszkoznev)
    {
        $this.IPaddress = $IP
        $this.Eszkoznev = $eszkoznev
    }

    Eszkoz($bemenet)
    {
        if($bemenet -match $global:config.IPpattern)
        {
            $this.IPaddress = $bemenet
        }
        else
        {
            $this.Eszkoznev = $bemenet
        }
    }

    SetNev()
    {
        try
        {
            $namesplit = ([System.Net.DNS]::GetHostEntry($this.IPaddress).HostName)
            $kimenet = $namesplit.Split(".")
            $this.Eszkoznev = $kimenet[0]
        }
        catch [System.Net.Sockets.SocketException]
        {
            $this.Eszkoznev = "Nem elérhető"
        }
    }

    SetIP($IP)
    {
        $this.IPaddress = $IP
    }

    SetMAC($MAC)
    {
        $this.MACaddress = $MAC
    }

    SetSwitchnev($switchnev)
    {
        $this.SwitchNev = $switchnev
    }

    SetSwitchIP($switchIP)
    {
        try
        {
            $this.SwitchIP = $switchIP.Trim("(", ")")
        }
        catch
        {
            $this.SwitchIP = "IP cím nem elérhető"
        }
    }

    SetPort($port)
    {
        $this.Port = $port
    }

    SetFelhasznalo()
    {
        if($script:config.admin)
        {
            $this.Felhasznalo = Get-UtolsoUser $this.Eszkoznev
        }
    }
}

Class Local
{
    $Gepnev
    $IPaddress
    $MACaddress
    $Mask
    $SwitchNev
    $SwitchIP
    $Port

    Local()
    {
        $this.Gepnev = HOSTNAME.EXE
        $gateway = (Get-NetRoute -DestinationPrefix "0.0.0.0/0").NextHop
        $getMAC = get-wmiobject -class "win32_networkadapterconfiguration" | Where-Object {$_.DefaultIPGateway -Match $gateway}
        $kimenet = ($getMAC.MACAddress).Split(":")
        $this.MACaddress = "$($kimenet[0])$($kimenet[1]).$($kimenet[2])$($kimenet[3]).$($kimenet[4])$($kimenet[5])"
        $this.IPaddress = (($getMAC.IPAddress).Split(","))[0]
        $This.Mask = (Get-NetIPAddress | Where-Object {$_.IPAddress -match $getMAC.IPAddress[0] -and $_.AddressFamily -match "IPv4"} ).PrefixLength
    }

    [bool]Kesze()
    {
        if(!$this.SwitchNev)
        {
            return $false
        }
        else
        {
            return $true
        }
    }
}

Class Remote
{
    [string]$Eszkoznev
    [string]$IPaddress
    [string]$MACaddress
    $Online

    Remote()
    {
        $this.AdatBeker()
    }

    Remote($keresetteszkoz)
    {
        if($this.Allapot($keresetteszkoz))
        {
            $this.GetEszkoz($keresetteszkoz)
            $this.GetIP($keresetteszkoz)
        }
    }

    Remote($keresetteszkoz, [bool]$dontcheck)
    {
        $this.GetEszkoz($keresetteszkoz)
    }

    AdatBeker()
    {
        $keresetteszkoz = Read-Host -Prompt "Keresett eszköz IP címe, vagy neve"
        if($this.Allapot($keresetteszkoz))
        {
            $this.GetEszkoz($keresetteszkoz)
            $this.GetIP($keresetteszkoz)
        }
    }

    GetEszkoz($keresetteszkoz)
    {
        if($this.IfIP($keresetteszkoz))
        {
            $this.IPaddress = $keresetteszkoz
        }
        else
        {
            $this.Eszkoznev = $keresetteszkoz
        }
    }

    [bool]Allapot($keresetteszkoz)
    {
        $this.Online = Test-Ping $keresetteszkoz
        if(!$this.Online)
        {
            $message = "A(z) $keresetteszkoz eszköz jelenleg nem elérhető"
            Add-Log "[ESZKOZ OFFLINE] $message"
            Write-Host "$message!" -ForegroundColor Red
        }
        return $this.Online
    }

    [Bool]IfIP($keresetteszkoz)
    {
        if($keresetteszkoz -match $global:config.IPpattern)
        {
            return $true
        }
        else
        {
            return $false
        }
    }

    GetIP($hostname)
    {
        $addresses = [System.Net.Dns]::GetHostAddresses($hostname)
        foreach ($address in $addresses)
        {
            if ($address -match $global:config.IPpattern)
            {
                $this.IPaddress = $address
                Break
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

Class IPcim
{
    $tag1
    $tag2
    $tag3
    $tag4

    IPcim($bemenet)
    {
        $kimenet = $false
        do
        {
            if($bemenet -match $global:config.IPpattern)
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

#####
##
##  Végrehajtó osztályok. Ebben a részben találhatóak az olyan osztályok,
##  amik valamilyen feladat elvégzésére lettek létrehozva
##
#####

Class Telnet
{
    Static $felhasznalonev = $false
    Static $jelszo = $false
    Static Login()
    {
        if (![Telnet]::felhasznalonev -or ![Telnet]::jelszo)
            {
            $login = $false
            do
            {
                #[Telnet]::SetSwitch()
                Show-Cimsor "Bejelentkezés a $($global:config.switch) switchre"
                [Telnet]::LoginCreds()
                $login = [Telnet]::TestConnection()

                if (!$login)
                {
                    Write-Host "Újrapróbálkozol a switch bejelentkezési adatainak megadásával? Üss I-t, ha igen, és N-t, ha inkább kilépnél a programból" -ForegroundColor Red
                    $valassz = Get-YesNo
                    if($valassz -ne "I")
                    {
                        Exit
                    }
                }
            }while(!$login)
        }
    }

    Static SetConnection($switch, $felhasznalonev, $jelszo)
    {
        $global:config.switch = $switch
        [Telnet]::felhasznalonev = $felhasznalonev
        [Telnet]::jelszo = $jelszo
    }

    Static LoginCreds()
    {
        [Telnet]::felhasznalonev = Read-Host -Prompt "Felhasználónév"
        $pass = Read-Host -AsSecureString -Prompt "Jelszó"
        [Telnet]::jelszo = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($pass))
    }

    Static SetSwitch()
    {
        Show-Cimsor "SWITCH BEJELENTKEZÉS"
        Write-Host "Az alapértelmezett switchet használod ($($global:config.switch)), vagy megadod kézzel a címet?`nAdd meg a switch IP címét, ha választani szeretnél, vagy üss Entert, ha az alapértelmezettet használnád!"
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
                    $global:config.switch = $valassz
                }
            }
        }while(!$kilep)
    }

    Static [bool]TestConnection()
    {
        $login = $false
        Write-Host "`nKísérlet csatlakozásra..."
        $logintest = [Telnet]::InvokeCommands("")
        $login = $logintest | Select-String -Pattern "#", ">"
        if (!$login -or !$logintest)
        {
            $message = "A megadott felhasználónév: $([Telnet]::felhasznalonev), vagy a hozzá tartozó jelszó nem megfelelő, esetleg a(z) $($global:config.switch) címen nincs elérhető switch"
            Add-Log "[SWITCH KAPCSOLÓDÁSI HIBA] $message"
            Write-Host "$message!" -ForegroundColor Red
            $login = $false
        }
        else
        {
            Add-Log "[SWITCH SIKERES KAPCSOLÓDÁS] A(z) $([Telnet]::felhasznalonev) sikeresen kapcsolódott a(z) $($global:config.switch) switchez"
            $login = $true
        }
        return $login
    }

    Static [Object]InvokeCommands($parancsok)
    {
        $socket = $false
        $result = ""
        [String[]]$commands = @([Telnet]::felhasznalonev, [Telnet]::jelszo)
    
        foreach ($parancs in $parancsok)
        {
            $commands += $parancs
        }
    
        try
        {
            $socket = New-Object System.Net.Sockets.TcpClient($global:config.switch, $global:config.port)
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

            foreach ($command in $commands)
            {
                $writer.WriteLine($command)
                $writer.Flush()
                Start-Sleep -Milliseconds $global:config.waittime
            }
    
            Start-Sleep -Milliseconds $global:config.waittime
    
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
                $remote.AdatBeker()
            }
        }while(!$result)
        return $result
    }
    
    Static [Object]Elkeszit($remote)
    {
        if(!(Test-IfSameSubnet $script:local.IPaddress $remote.IPaddress $script:local.Mask))
        {
            $result = $false
            $message = "A(z) $($remote.IPaddress) IP című eszköz a jelenlegitől eltérő VLAN-ban található"
            Add-Log "[VLAN ÁTJÁRÁS HIBA] $message"
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
        $waittimeorig = $global:config.waittime
        do
        {
            Write-Host "A(z) $($script:remote.IPaddress) IP című eszköz helyének lekérdezése folyamatban..."
            $this.result = [Telnet]::InvokeCommands($parancs)
            if(!$this.result)
            {
                $message = "A(z) $($script:remote.IPaddress) című eszköz lekérdezése során a programnak nem sikerült csatlakozni a(z) $($global:config.switch) IP című switchhez!"
                Add-Log "[KAPCSOLÓDÁSI HIBA] $message"
                Write-Host $message -ForegroundColor Red
            }
            elseif ($this.result | Select-String -Pattern "found on")
            {
                $this.sikeres = $true
            }
            if (!$this.Siker() -and $failcount -lt $global:config.maxhiba)
            {
                $failcount++
                $visszamaradt = $global:config.maxhiba - $failcount
                Write-Host "A(z) $($script:remote.IPaddress) eszköz helyének lekérdezése most nem járt sikerrel. Még $visszamaradt alkalommal újrapróbálkozom!" -ForegroundColor Yellow
                if ($failcount -eq $global:config.maxhiba)
                {
                    $message = "A(z) $($script:remote.IPaddress) eszköz helyének lekérdezése a(z) $($global:config.switch) IP című switchről időtúllépés miatt nem sikerült"
                    Write-Host $message -ForegroundColor Red
                    Add-Log "[IDŐTÚLLÉPÉS] $message"
                    #Write-Host $this.result
                }
                $global:config.waittime = $global:config.waittime + 1000
            }
        }while (!$this.Siker() -and $failcount -lt $global:config.maxhiba)
        $global:config.waittime = $waittimeorig
    }

    Feldolgoz()
    {
        $eszkozhely = 0
        $sajateszkoz = 0
        $this.sorok = $this.result.Split("`r`n")
        for ($i = 0; $i -lt $this.sorok.Length; $i++)
        {
            if ($this.sorok[$i] | Select-String -pattern "=>")
            {
                if ($sajateszkoz -eq 0)
                {
                    $sajateszkoz = $i
                }
                $eszkozhely = $i
            }
        }
        $utolsosor = $this.sorok[$eszkozhely].Split(" ")
        $this.switchnev = $utolsosor[1]
        $this.switchip = $utolsosor[2]
        $this.eszkozport = $utolsosor[6]
        if(!$script:local.Kesze())
        {
            $elsosor = $this.sorok[$sajateszkoz].Split(" ")
            $script:local.switchnev = $elsosor[1]
            $script:local.switchip = $elsosor[2]
            $script:local.port = $elsosor[4]
        }
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
        Show-Cimsor "ESZKÖZ FIZIKAI HELYÉNEK MEGKERESÉSE"
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
            if ($csvdata[$i].IPaddress)
            {
                $script:eszkoz[$i] = [Eszkoz]::New($csvdata[$i].IPaddress)
            }
            else
            {
                $script:eszkoz[$i] = [Eszkoz]::New($csvdata[$i].Eszkoznev)
            }
        }
    }
}

#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#
#-#-#                                    FÜGGVÉNYEK                                           #-#-#
#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#

#####
##
##  Menü kezelést könnyítő függvények
##
#####
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
            Write-Host "Kérlek csak a megadott lehetőségek közül válassz!" -ForegroundColor Yellow # This is the error message, the user gets here after every single bad entry
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
    $confirm = Get-Valasztas ("I", "N")
    return $confirm    
}

function Get-TrueFalse
{
    param($ertek)

    if ($ertek)
    {
        Write-Host "Bekapcsolva" -ForegroundColor Green
    }
    else
    {
        Write-Host "Kikapcsolva" -ForegroundColor Red
    }
}

function Show-Cimsor
{
    param($almenu)
    Clear-Host
    Write-Host "HÁLÓZATKEZELÉSI SVÁJCIBICSKA`n`n$almenu`n`n"
}

#####
##
##  Egyszerűbb függvények egyetlen egyszerűbb feladat ellátására
##
#####

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

    catch [System.UnauthorizedAccessException]
    {
        return "Nincs jogosultságod a felhasználó lekérésére!"
    }

    catch
    {
        return "Nincs bejelentkezett felhasználó"
    }
}

function Get-NameByIP
{
    param ($IPaddress)
    try
    {
        $namesplit = ([System.Net.DNS]::GetHostEntry($IPaddress)).HostName
        $kimenet = $namesplit.Split(".")
        $name = $kimenet[0]
    }
    catch [System.Net.Sockets.SocketException]
    {
        $name = "Nem elérhető"
    }

    return $name
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

function Test-Ping
{
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
Function Test-CSV
{
    Param($kozeptag)
    $script:csvnev = "$($config.csvnevelotag)-$kozeptag.csv"
    $script:oldcsvnev = "$($config.csvnevelotag)-$kozeptag-OLD.csv"
    $script:csv = ".\Logfiles\$script:csvnev"
    $script:oldcsv = ".\Logfiles\$script:oldcsvnev"
    $script:csvsave = $script:csv
    $script:csvkimenet = "$($config.csvkonyvtar)\VÉGEREDMÉNY_$($config.csvnevelotag)_$kozeptag.csv"

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

function Test-IfSameSubnet
{
    param($local, $remote, $subnet)

    $masktag = [Math]::truncate(($subnet - 1) / 8)
    $samesubnet = $true

    for ($i = $masktag - 1; $i -ge 0; $i--)
    {
        if ((($local).Split("."))[$i] -ne ((($remote).Split("."))[$i]))
        {
            $samesubnet = $false
            Break
        }
    }
    if($samesubnet)
    {
        $local = (($local).Split("."))[$masktag]
        $remote = (($remote).Split("."))[$masktag]
        $subnetsize = (($masktag + 1) * 8) - $subnet
        $samesubnet = $false
        if ($subnetsize -eq 0)
        {
            if ($local -eq $remote)
            {
                $samesubnet = $true
            }
        }
        else
        {
            if ($subnetsize -eq 1)
            {
                $subnetsize = 2
            }
            else
            {
                $subnetsize = [Math]::Pow(2, $subnetsize)
            }
            $subnetstart = $local - ($local % $subnetsize)
            $subnetend = $subnetstart + $subnetsize
            if($remote -ge $subnetstart -and $remote -lt $subnetend)
            {
                $samesubnet = $true
            }
        }
    }
    return $samesubnet
}

function Add-Log
{
    param ($logtext)

    if($config.log) # A config.ini log bejegyzését false-ra állítva a logolás kikapcsolható
    {
        if($config.logtime)
        {
            $logtext = "$logtext $([Time]::Stamp())"
        }
        $logtext | Out-File $config.logfile -Append -Force -Encoding unicode
    }
}

function Set-Logname
{
    param($logname)

    $script:config.logfile = ".\Logfiles\$logname.log"
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

function Get-EgyszeriLekerdezes
{
    $script:local = [Local]::New()
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

#####
##
##  Összetett kisegítőfüggvények. Ezek a függvényeket összetettebb,
##  vagy akár egyszerr több feladatokat látnak el
##
#####

# Hasonlóan az Get-DistinguishedName függvényhez, ez is egy másik programból származik
# Ennek a függvénynek az a feladata, hogy ellenőrzötten bekérje a lekérdezni kívánt OU elérési útját
function Get-OU
{
    param($bemenet)
    $eredetiou = $bemenet
    $time = (Get-Date).Adddays(-($config.aktivnapok)) # Csak azokkal foglalkozunk, amik a megadott időn belül voltak bekapcsolva
    do 
    {
        if(!($bemenet)) # Ez az elágazás csak az első (sikertelen) futást követően lép életbe
        {
            Write-Host "FIGYELMEZTETÉS! A megadott OU nem létezik, vagy nem tartalmaz a kritériumnak megfelelő számítógépeket!" -ForegroundColor Red
            Write-Host "Adj meg egy helyes elérési utat."
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
                    Write-Host "A lekérdezett OU méretétől függően ez akár 30-40 másodpercet is igénybe vehet"
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

function Get-IPRange
{
    param ($elsoIP, $utolsoIP, $elsokihagyott, $utolsokihagyott)

    $eszkoz = New-Object System.Collections.ArrayList($null)
    $keszip = New-Object IPcim("1.1.1.1")

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
                    if($elsokihagyott)
                    {
                        $keszip.NoCheck($ipstring)
                        if((Compare-IPs $elsokihagyott $keszip) -or (Compare-IPs $keszip $utolsokihagyott))
                        {
                            $eszkoz.Add([Remote]::New($ipstring, $false)) > $null
                        }
                    }
                    else
                    {
                        $eszkoz.Add([Remote]::New($ipstring, $false)) > $null
                    }
                }
            }
        }
    }

    return $eszkoz
}

function Compare-IPs
{
    param ($IP1, $IP2)
    
    $elsonagyobb = $false
    if ($IP1.Tag1 -gt $IP2.Tag1)
    {
        $elsonagyobb = $true
    }
    elseif($IP1.Tag1 -eq $IP2.Tag1)
    {
        if($IP1.Tag2 -gt $IP2.Tag2)
        {
            $elsonagyobb = $true
        }
        elseif($IP1.Tag2 -eq $IP2.Tag2)
        {
            if($IP1.Tag3 -gt $IP2.Tag3)
            {
                $elsonagyobb = $true
            }
            elseif($IP1.Tag3 -eq $IP2.Tag3)
            {
                if($IP1.Tag4 -gt $IP2.Tag4)
                {
                    $elsonagyobb = $true
                }
            }
        }
    }

    return $elsonagyobb 
}

function Import-IPaddresses
{
    do
    {
        $endloop = $true
        Show-Cimsor "IP TARTOMÁNY ELLENŐRZŐ"
        if ($debug -ne 1)
        {
            Write-Host "Kérlek add meg a lekérdezni kívánt IP tartomány első IP címét!"
            $script:elsoIP = New-Object IPcim(Read-Host -Prompt "Első IP cím")
            Write-Host "Kérlek add meg a lekérdezni kívánt IP tartomány utolsó IP címét!"
            $script:utolsoIP = New-Object IPcim(Read-Host -Prompt "Utolsó IP cím")
            Write-Host "Szeretnél kihagyni egy megadott tartományt a két IP cím között?`nAdd meg a kihagyni kívánt tartomány also IP címét, ha igen, üss Entert, ha nem!"
            $valassz = Read-Host -Prompt "Válassz"
            if($valassz)
            {
                $script:elsokihagyott = New-Object IPcim($valassz)
                Write-Host "Kérlek add meg az utolsó kihagyni kívánt IP címet!"
                $script:utolsokihagyott = New-Object IPcim(Read-Host -Prompt "Utolsó kihagyott IP cím")
            }
            else
            {
                $script:elsokihagyott = $false
            }
        }
        else
        {
            $elsoIP = New-Object IPcim $debugip1
            $utolsoIP = New-Object IPcim $debugip2
        }

        $script:ipdarab = Get-IPcount $elsoIP $utolsoIP
        if($script:elsokihagyott)
        {
            $kihagy = Get-IPcount $script:elsokihagyott $script:utolsokihagyott
            $script:ipdarab = $script:ipdarab - $kihagy
        }

        if ($elsoIP.ToString() -eq $utolsoIP.ToString())
        {
            Write-Host "A megadott IP címek megegyeznek! Egy billentyű leütését követően add meg újra lekérdezni kívánt tartományt!" -ForegroundColor Red
            Read-Host
            $endloop = $false
        }
        elseif($ipdarab -lt 1)
        {
            Write-Host "A megadott tartományban nincs egyetlen IP cím sem! Így a lekérdezés nem folytatható le!`nEgy billentyű leütését követően kérlek add meg újra a lekérdezni kívánt tartományt!" -ForegroundColor Red
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
        elseif($elsokihagyott)
        {
            if ((Compare-IPs $elsoIP $elsokihagyott) -or (Compare-IPs $utolsokihagyott $utolsoIP))
            {
                Write-Host "A megadott tartományban nincs egyetlen IP cím sem! Így a lekérdezés nem folytatható le!`nEgy billentyű leütését követően kérlek add meg újra a lekérdezni kívánt tartományt!" -ForegroundColor Red
                Read-Host
                $endloop = $false
            }
        }
    }while(!$endloop)
    if($script:elsokihagyott)
    {
        $eszkozok = Get-IPRange $elsoIP $utolsoIP $script:elsokihagyott $script:utolsokihagyott
    }
    else
    {
        $eszkozok = Get-IPRange $elsoIP $utolsoIP
    }

    return $eszkozok
}

#####
##
##  Menüpontok. Ezeket a függvényeket hívják meg közvetlenül a főmenü menüpontjai
##
#####

function Set-Kiiratas
{
    Show-Cimsor "EGYETLEN ESZKÖZ MEGKERESÉSE"
    Set-Logname "EszkozHely"
    Get-EgyszeriLekerdezes
    [Telnet]::Login()
    $lekerdezes = [Lekerdezes]::New($global:keresesiparancs)
    if($lekerdezes.Siker())
    {
        $lekerdezes.Feldolgoz()
        $lekerdezes.Kiirat()
    }
    Write-Host "`nA továbblépéshez üss Entert!"
    Read-Host
}
function Set-ParancsKiiratas
{
    Show-Cimsor "EGYETLEN ESZKÖZ MEGKERESÉSE"
    Set-Logname "EszkozHely"
    Get-EgyszeriLekerdezes
    Write-Host "Helyi IP cím:           $($script:local.IPaddress) (ezt kell pingelni a switchről, ha a TraceRoute parancs 'Error: Source Mac address not found.' hibát ad."
    Write-Host "Keresett eszköz IP-je:  $($script:remote.IPaddress) (ezt kell pingelni a switchről, ha a TraceRoute parancs 'Error: Destination Mac address not found.' hibát ad."
    Write-Host "Keresési parancs:       $global:keresesiparancs (automatikusan a vágólapra másolva)`n"
    Set-Clipboard $global:keresesiparancs
    Write-Host "A továbblépéshez üss Entert!"
    Read-Host
}
function Import-ADList
{
    Show-Cimsor "AD-BÓL VETT GÉPEK LISTÁJÁNAK LEKÉRDEZÉSE"
    Set-Logname "EszkozHely"
    $config.csvnevelotag = "EszközHely"
    $script:local = [Local]::New()
    $sajateszkoz = $false
    $ADgeplista = $false

    Write-Host "Kérlek szúrd be a lekérdezni kívánt OU elérési útját!"
    $valaszt = Read-Host -Prompt "Válassz"
    $ADgeplista = Get-OU $valaszt
    if($ADgeplista)
    {
        [Import]::AD($ADgeplista) # Meghívjuk az importáló osztály ADból imortálást végző statikus metódusát
        Add-Log "[LEKÉRDEZÉS MEGKEZDVE] A(z) $($script:ounev) OU gépeinek helyének lekérdezése megkezdődött:"
    }
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
            if ($eszkoz[$i].Eszkoznev -eq $script:local.Gepnev)
            {
                $sajateszkoz = $i
            }

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
                        $eszkoz[$i].SetFelhasznalo()
                        if(!(Test-Path $script:csvkimenet) -or !(Select-String -Path $script:csvkimenet -Pattern $eszkoz[$i].Eszkoznev))
                        {
                            $eszkoz[$i] | export-csv -encoding UTF8 -path $script:csvkimenet -NoTypeInformation -Append -Force -Delimiter ";"
                        }
                        $keszdb++
                        $fail = $false
                    }
                    if ($sajateszkoz -and !$eszkoz[$sajateszkoz].SwitchIP)
                    {
                        $eszkoz[$sajateszkoz].SetSwitchNev($script:local.SwitchNev)
                        $eszkoz[$sajateszkoz].SetSwitchIP($script:local.SwitchIP)
                        $eszkoz[$sajateszkoz].SetPort($script:local.Port)
                        $eszkoz[$sajateszkoz].SetIP($script:local.IPaddress)
                        $eszkoz[$sajateszkoz].SetMAC($script:local.MACaddress)
                        $eszkoz[$sajateszkoz].SetFelhasznalo()
                        if(!(Test-Path $script:csvkimenet) -or !(Select-String -Path $script:csvkimenet -Pattern $eszkoz[$sajateszkoz].Eszkoznev))
                        {
                            $eszkoz[$sajateszkoz] | export-csv -encoding UTF8 -path $script:csvkimenet -NoTypeInformation -Append -Force -Delimiter ";"
                        }
                        $keszdb++
                    }
                }
            }

            if($fail -and !($remote.Elerheto()))
            {
                $eszkoz[$i] | export-csv -encoding UTF8 -path $script:csvsave -NoTypeInformation -Append -Force -Delimiter ";"
            }
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
            for ($i = 0; $i -lt $config.retrytime; $i++)
            {
                $remaining = $config.retrytime - $i
                Write-Host "`r                                                        " -NoNewline
                Write-Host "`rA folyamat folytatódik $remaining másodperc múlva." -NoNewline
                Start-Sleep -s 1
            }
            Write-Host "`r                                                                  "
            Write-Host "A FOLYAMAT FOLYTATÓDIK"
        }
    }while ($script:elemszam -ne $keszdb) # Ha a lista és kész gépek elemszáma megegyezik, a futás végetért
    $message = "A(z) $($script.OUnev) OU számítógépeinek helyének lekérdezése sikeresen befejeződött:"
    Add-Log "[FOLYAMAT VÉGE] $message"
    Write-Host "$message`nA program egy billetnyű leütését követően visszatér a főmenübe."
    Read-Host
}

function Import-IPRange
{
    Show-Cimsor "MEGADOTT IP TARTOMÁNY ESZKÖZEI HELYÉNEK LEKÉRDEZÉSE"
    Set-Logname "EszkozHely"
    $config.csvnevelotag = "EszközHely"
    $script:local = [Local]::New()
    $ipcim = Import-IPaddresses
    $config.csvnevelotag = "IP_TartományEszközei"
    Test-CSV "$($elsoIP.ToString())-$($utolsoIP.ToString())"

    Show-Cimsor "A(Z) $($elsoIP.ToString()) - $($utolsoIP.ToString()) IP TARTOMÁNY ESZKÖZEI HELYÉNEK LEKÉRDEZÉSE"

    Add-Log "[LEKÉRDEZÉS MEGKEZDVE] A(z) $($elsoIP.ToString())-$($utolsoIP.ToString())) IP tartomány eszközei helyének lekérdezése megkezdődött:"
    [Telnet]::Login()

    # Itt kezdődik a függvény munkaciklusa. Ezen belül történik a lekérdezést végző függvény meghívása
    # és az adatok CSV fájlból való beolvasása (utóbbi akkor is, ha eleve CSV-ből vesszük az adatokat,
    # és akkor is, ha a program a saját maga által, egy korábbi ciklusban készített fájlokat használja)

    $eszkoz = New-Object 'object[]' $script:ipdarab
    for ($i = 0; $i -lt $script:ipdarab; $i++)
    {
        $sorszam = $i + 1
        $eszkoz[$i] = [Eszkoz]::New($ipcim[$i].IPaddress)
        Write-Host "A FOLYAMAT ÁLLAPOTA: $sorszam/$script:ipdarab`nA(z) $($eszkoz[$i].IPaddress) eszköz lekérdezése folyamatban."

        if ($eszkoz[$i].IPaddress -eq $script:local.IPaddress)
        {
            $sajateszkoz = $i
        }

        $script:remote = $ipcim[$i]
        if(Test-Connection $eszkoz[$i].IPaddress -Quiet -Count 1)
        {
            $keresesiparancs = [Parancs]::Elkeszit($ipcim[$i])
            if($keresesiparancs)
            {
                $lekerdezes = [Lekerdezes]::New($keresesiparancs)
                if($lekerdezes.Siker())
                {
                    $lekerdezes.Feldolgoz()
                    $lekerdezes.ObjektumKitolto($eszkoz[$i])
                    $eszkoz[$i].SetNev()
                    if(!(Test-Path $script:csvkimenet) -or !(Select-String -Path $script:csvkimenet -Pattern $eszkoz[$i].IPAddress))
                    {
                        $eszkoz[$i] | export-csv -encoding UTF8 -path $script:csvkimenet -NoTypeInformation -Append -Force -Delimiter ";"
                    }
                    $keszdb++
                }
                if ($sajateszkoz -and !$eszkoz[$sajateszkoz].SwitchIP)
                {
                    $eszkoz[$sajateszkoz].SetSwitchNev($script:local.SwitchNev)
                    $eszkoz[$sajateszkoz].SetSwitchIP($script:local.SwitchIP)
                    $eszkoz[$sajateszkoz].SetPort($script:local.Port)
                    $eszkoz[$sajateszkoz].SetIP($script:local.IPaddress)
                    $eszkoz[$sajateszkoz].SetMAC($script:local.MACaddress)
                    $eszkoz[$sajateszkoz].SetNev()
                    if(!(Test-Path $script:csvkimenet) -or !(Select-String -Path $script:csvkimenet -Pattern $eszkoz[$sajateszkoz].IPAddress))
                    {
                        $eszkoz[$sajateszkoz] | export-csv -encoding UTF8 -path $script:csvkimenet -NoTypeInformation -Append -Force -Delimiter ";"
                    }
                    $keszdb++
                }
            }
        }
        else
        {
            $message = "$($eszkoz[$i].IPaddress) Eszköz nem érhető el"
            Add-Log "[ESZKÖZ OFFLINE] $message"
            Write-Host $message! -ForegroundColor Red
        }
    }

    $message = "A(z) $($elsoIP.ToString()) - $($utolsoIP.ToString()) IP tartomány eszközei helyének lekérdezése sikeresen befejeződött:"
    Add-Log "[FOLYAMAT VÉGE] $message"
    Write-Host "$message`nA program egy billetnyű leütését követően visszatér a főmenübe."
    Read-Host
}

function Get-IPaddressesState
{
    Show-Cimsor "IP TARTOMÁNY LEKÉRDEZÉSE"
    Set-Logname "EszkozAllapot"
    $eszkozok = Import-IPaddresses
    $time = [Time]::New()
    $config.csvnevelotag = "IP_Címlista"
    $jelenelem = 1
    Test-CSV "$($elsoIP.ToString())-$($utolsoIP.ToString())_$($time.FileName())"

    Show-Cimsor "A(Z) $($elsoIP.ToString()) - $($utolsoIP.ToString()) IP TARTOMÁNY LEKÉRDEZÉSE"

    foreach ($eszkoz in $eszkozok)
    {
        Write-Host "$($eszkoz.IPaddress) kapcsolatának ellenőrzése ($jelenelem/$($eszkozok.Length))" -NoNewline
        switch ($method)
        {
            1 { $online = Test-Ping $eszkoz.IPaddress }
            2 { $online = (Test-Connection $eszkoz.IPaddress -Quiet -Count 1) }
            Default{ $online = Test-Ping $eszkoz.IPaddress }
        }

        $eszkoz.Online = $online
        $name = ""
        $neve = ""
        if($online -and $config.nevgyujtes)
        {
            $name = Get-NameByIP $eszkoz.IPaddress
            $neve = "; Neve: $name"
            $eszkoz.Eszkoznev = $name
        }

        $eszkoz.Online = $eszkoz.EszkozAllapot()
        $jelenelem++
        Write-Host "`r$($eszkoz.IPaddress): Állapota: $($eszkoz.Online)$neve                  "
        Add-Log "[ESZKÖZ ÁLLAPOT] $($eszkoz.IPaddress): Állapota: $($eszkoz.Online)$neve Idő:"
        if(($config.logonline) -and ($config.logoffline))
        {
            $eszkoz | export-csv -encoding UTF8 -path $script:csvkimenet -NoTypeInformation -Append -Force -Delimiter ";"
        }
        elseif(($config.logonline) -and $online)
        {
            $eszkoz | export-csv -encoding UTF8 -path $script:csvkimenet -NoTypeInformation -Append -Force -Delimiter ";"
        }
        elseif(($config.logoffline) -and !$online)
        {
            $eszkoz | export-csv -encoding UTF8 -path $script:csvkimenet -NoTypeInformation -Append -Force -Delimiter ";"
        }
    }
    Write-Host "A(z) $($elsoIP.ToString()) - $($utolsoIP.ToString()) IP tartomány lekérdezése befejeződött. Egy billentyű leütésével visszatérhetsz a főmenübe"
    Read-Host
}

function Get-ADcomputersState
{
    Show-Cimsor "AD OU PILLANATYNI ÁLLAPOTÁNAK LEKÉRDEZÉSE"
    Set-Logname "EszkozAllapot"
    $config.csvnevelotag = "AD_GépÁllapot"

    Write-Host "Kérlek szúrd be a lekérdezni kívánt OU elérési útját!"
    $valaszt = Read-Host -Prompt "Válassz"
    $ADgeplista = Get-OU $valaszt
    Show-Cimsor "A(Z) $($script:ounev) OU GÉPEINEK LEKÉRDEZÉSE"
    $jelenelem = 1

    foreach ($gep in $ADgeplista)
    {
        $eszkoz = [Remote]::New($gep.Name, $false)
        Write-Host "$($eszkoz.Eszkoznev) kapcsolatának ellenőrzése ($jelenelem/$($ADgeplista.Length))" -NoNewline
        switch ($method)
        {
            1 { $online = Test-Ping $eszkoz.Eszkoznev }
            2 { $online = (Test-Connection $eszkoz.Eszkoznev -Quiet -Count 1) }
            Default{ $online = Test-Ping $eszkoz.Eszkoznev }
        }

        $eszkoz.Online = $online
        $eszkoz.Online = $eszkoz.EszkozAllapot()
        $jelenelem++
        Write-Host "`r$($eszkoz.Eszkoznev): Állapota: $($eszkoz.Online)                  "
        Add-Log "[ESZKÖZ ÁLLAPOT] $($eszkoz.Eszkoznev): Állapota: $($eszkoz.Online) Idő:"
        if(($config.logonline) -and ($config.logoffline))
        {
            $eszkoz | export-csv -encoding UTF8 -path $script:csvkimenet -NoTypeInformation -Append -Force -Delimiter ";"
        }
        elseif(($config.logonline) -and $online)
        {
            $eszkoz | export-csv -encoding UTF8 -path $script:csvkimenet -NoTypeInformation -Append -Force -Delimiter ";"
        }
        elseif(($config.logoffline) -and !$online)
        {
            $eszkoz | export-csv -encoding UTF8 -path $script:csvkimenet -NoTypeInformation -Append -Force -Delimiter ";"
        }
    }
    Write-Host "A(z) $($script:ounev) OU gépeinek lekérdezése befejeződött. Egy billentyű leütésével visszatérhetsz a főmenübe"
    Read-Host
}

#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#
#-#-#                                   BELÉPÉSI PONT                                         #-#-#
#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#

$global:config = [Setting]::New()

for(;;)
{
    Write-Host "HÁLÓZATKEZELÉSI SVÁJCIBICSKA`n"
    Write-Host "Válassz az alábbi menüpontok közül:"
    Write-Host "(1) Egy eszköz helyének megkeresése a hálózaton"
    Write-Host "(2) Egy eszköz helyének megkereséséhez szükséges parancs vágólapra másolása"
    Write-Host "(3) Egy OU minden számítógépe helyének lekérdezése, és fájlba mentése"
    Write-Host "(4) Egy IP cím tartomány minden eszköze helyének lekérdezése, és fájlba mentése"
    Write-Host "(5) Egy OU gépeinek végigpingelése, és az eredmény fájlba mentése"
    Write-Host "(6) Egy IP cím tartomány végigpingelése, és az eredmény fájlba mentése"
    Write-Host "(S) Beállítások"
    Write-Host "(K) Kilépés"
    $valassz = Get-Valasztas ("1", "2", "3", "4", "5", "6", "S", "K")

    switch ($valassz) {
        1 { Set-Kiiratas }
        2 { Set-ParancsKiiratas }
        3 { Import-ADList }
        4 { Import-IPRange }
        5 { Get-ADcomputersState }
        6 { Get-IPaddressesState }
        S { $config.ModifyConfig() }
        K { Exit }
        Default {}
    }
}