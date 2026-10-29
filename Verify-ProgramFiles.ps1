<#
.SYNOPSIS
    Inwentaryzacja i weryfikacja plików programu: podpisy cyfrowe, wydawca, wersje, daty, hashe.
    Działa w pełni offline. Opcjonalnie wykorzystuje Sysinternals Sigcheck.

.DESCRIPTION
    Skrypt rekurencyjnie listuje WSZYSTKIE pliki we wskazanym katalogu i dla każdego zbiera:
      - ścieżkę, rozmiar, atrybuty, daty utworzenia / modyfikacji / ostatniego dostępu,
      - właściciela pliku w NTFS (konto, które utworzyło / przejęło plik),
      - informacje o wersji (FileVersion, ProductVersion, CompanyName, ProductName, opis,
        OriginalFilename, InternalName, Copyright),
      - typ binarki (PE: x86/x64/ARM64, .NET),
      - podpis Authenticode (status, podpisujący, wystawca, numer seryjny, odcisk certyfikatu,
        ważność certyfikatu, znacznik czasu, typ podpisu: osadzony / katalogowy),
      - hashe (domyślnie SHA256, opcjonalnie SHA1/MD5/SHA384/SHA512),
      - znacznik "Mark of the Web" (strumień Zone.Identifier – skąd plik pobrano),
      - dane z Sysinternals Sigcheck (jeżeli dostępny): data podpisu, wydawca, entropia,
        PESHA256, IMPHASH, typ maszyny.
    Na koniec wystawia werdykt dla każdego pliku i zapisuje raporty: CSV, HTML, JSON oraz SHA256SUMS.

    Tryb offline:
      - nie jest używana opcja VirusTotal Sigcheck (-v / -vt),
      - weryfikacja podpisu korzysta z lokalnego magazynu certyfikatów Windows; przy braku sieci
        sprawdzenie listy CRL może jedynie wydłużyć działanie, nie zmienia wyniku „Valid”.

.PARAMETER Path
    Katalog do weryfikacji (np. katalog instalacyjny programu).

.PARAMETER OutputDir
    Katalog na raporty. Domyślnie: .\Raport_<nazwa_katalogu>_<data>.

.PARAMETER NoRecurse
    Nie wchodź do podkatalogów.

.PARAMETER HashAlgorithm
    Lista algorytmów hash. Domyślnie SHA256. Np. -HashAlgorithm SHA256,SHA1,MD5

.PARAMETER SigcheckPath
    Ścieżka do sigcheck64.exe / sigcheck.exe. Jeśli nie podano, skrypt szuka w katalogu skryptu,
    w podkatalogu .\Sysinternals oraz w PATH.

.PARAMETER NoSigcheck
    Nie używaj Sigcheck (tylko natywne mechanizmy PowerShell).

.PARAMETER ExpectedPublisher
    Lista dozwolonych wydawców (wzorce -like dopasowywane do Subject certyfikatu), np.
    -ExpectedPublisher '*O=Microsoft Corporation*','*CN=Moja Firma Sp. z o.o.*'
    Pliki podpisane przez innego wydawcę dostaną werdykt UWAGA.

.PARAMETER Baseline
    Poprzedni raport (Report.json lub Report.csv) traktowany jako wzorzec. Skrypt porówna hashe
    i wykaże pliki zmienione, nowe oraz brakujące.

.PARAMETER Delimiter
    Separator w pliku CSV. Domyślnie ';' (polski Excel).

.EXAMPLE
    .\Verify-ProgramFiles.ps1 -Path 'C:\Program Files\MojProgram'

.EXAMPLE
    .\Verify-ProgramFiles.ps1 -Path D:\Release\App -SigcheckPath C:\Tools\Sysinternals\sigcheck64.exe `
        -ExpectedPublisher '*CN=Moja Firma*' -HashAlgorithm SHA256,SHA1

.EXAMPLE
    # Porównanie z wcześniej zatwierdzonym wzorcem
    .\Verify-ProgramFiles.ps1 -Path D:\Release\App -Baseline .\Wzorzec\Report.json

.NOTES
    Wymagania: Windows PowerShell 5.1 lub PowerShell 7+ na Windows.
    Kody wyjścia: 0 = wszystko OK, 1 = są ostrzeżenia (UWAGA), 2 = są błędy (BŁĄD).
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Container })]
    [string]$Path,

    [string]$OutputDir,

    [switch]$NoRecurse,

    [ValidateSet('SHA1', 'SHA256', 'SHA384', 'SHA512', 'MD5')]
    [string[]]$HashAlgorithm = @('SHA256'),

    [string]$SigcheckPath,

    [switch]$NoSigcheck,

    [string[]]$ExpectedPublisher,

    [string]$Baseline,

    [string]$Delimiter = ';'
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

# Rozszerzenia, które mogą nieść podpis Authenticode (oprócz plików z nagłówkiem MZ wykrywanych po zawartości)
$SignableExtensions = @(
    '.exe', '.dll', '.sys', '.ocx', '.cpl', '.scr', '.drv', '.efi', '.mui', '.winmd', '.ax', '.com',
    '.msi', '.msp', '.msm', '.mst', '.cab', '.cat', '.appx', '.msix', '.appxbundle', '.msixbundle',
    '.ps1', '.psm1', '.psd1', '.ps1xml', '.psc1', '.cdxml', '.vbs', '.js', '.wsf', '.jse', '.vbe'
)

$Root = (Resolve-Path -LiteralPath $Path).ProviderPath.TrimEnd('\')
if ($Root -match '^[A-Za-z]:$') { $Root += '\' }

if (-not $OutputDir) {
    $leaf = Split-Path -Path $Root -Leaf
    if (-not $leaf) { $leaf = 'root' }
    $leaf = $leaf -replace '[\\/:*?"<>|]', '_'
    $OutputDir = Join-Path -Path (Get-Location).ProviderPath -ChildPath ("Raport_{0}_{1}" -f $leaf, (Get-Date -Format 'yyyyMMdd_HHmmss'))
}
New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
$OutputDir = (Resolve-Path -LiteralPath $OutputDir).ProviderPath

$Errors = New-Object System.Collections.Generic.List[string]

# ---------------------------------------------------------------- funkcje pomocnicze

function Get-RelativePath {
    param([string]$Base, [string]$Full)
    $b = $Base.TrimEnd('\') + '\'
    if ($Full.StartsWith($b, [StringComparison]::OrdinalIgnoreCase)) { return $Full.Substring($b.Length) }
    return $Full
}

function Format-Date {
    param($Value)
    if ($null -eq $Value) { return '' }
    try { return ([datetime]$Value).ToString('yyyy-MM-dd HH:mm:ss') } catch { return [string]$Value }
}

function Get-PeInfo {
    # Odczyt nagłówka PE bez zewnętrznych narzędzi: czy to binarka, architektura, czy .NET
    param([string]$FilePath)
    $result = [ordered]@{ IsPE = $false; Machine = ''; IsDotNet = $false; Subsystem = '' }
    $fs = $null
    try {
        $fs = [System.IO.File]::Open($FilePath, 'Open', 'Read', 'ReadWrite, Delete')
        $br = New-Object System.IO.BinaryReader($fs)
        if ($fs.Length -lt 64) { return $result }
        if ($br.ReadUInt16() -ne 0x5A4D) { return $result }          # 'MZ'
        $fs.Position = 0x3C
        $peOffset = $br.ReadInt32()
        if ($peOffset -le 0 -or ($peOffset + 24) -gt $fs.Length) { return $result }
        $fs.Position = $peOffset
        if ($br.ReadUInt32() -ne 0x00004550) { return $result }      # 'PE\0\0'
        $result.IsPE = $true
        $machine = $br.ReadUInt16()
        switch ($machine) {
            0x014c { $result.Machine = 'x86' }
            0x8664 { $result.Machine = 'x64' }
            0xAA64 { $result.Machine = 'ARM64' }
            0x01c4 { $result.Machine = 'ARM' }
            0x0200 { $result.Machine = 'IA64' }
            default { $result.Machine = ('0x{0:X4}' -f $machine) }
        }
        $fs.Position = $peOffset + 20
        $optSize = $br.ReadUInt16()
        $characteristics = $br.ReadUInt16()
        if ($optSize -gt 0) {
            $optStart = $peOffset + 24
            $fs.Position = $optStart
            $magic = $br.ReadUInt16()
            $fs.Position = $optStart + 68
            $sub = $br.ReadUInt16()
            switch ($sub) {
                1 { $result.Subsystem = 'Native/Driver' }
                2 { $result.Subsystem = 'GUI' }
                3 { $result.Subsystem = 'Console' }
                10 { $result.Subsystem = 'EFI' }
                default { $result.Subsystem = [string]$sub }
            }
            if ($characteristics -band 0x2000) { $result.Subsystem += ' (DLL)' }
            # Katalog danych nr 14 = CLR Runtime Header (.NET)
            $dataDirStart = if ($magic -eq 0x20B) { $optStart + 112 } else { $optStart + 96 }
            $clrEntry = $dataDirStart + 14 * 8
            if (($clrEntry + 8) -le ($optStart + $optSize) -and ($clrEntry + 8) -le $fs.Length) {
                $fs.Position = $clrEntry
                $rva = $br.ReadUInt32(); $size = $br.ReadUInt32()
                $result.IsDotNet = ($rva -ne 0 -and $size -ne 0)
            }
        }
    }
    catch { }
    finally { if ($fs) { $fs.Dispose() } }
    return $result
}

function Get-ZoneIdentifier {
    # Mark of the Web – informacja, że plik pochodzi z Internetu i skąd
    param([string]$FilePath)
    try {
        $content = Get-Content -LiteralPath $FilePath -Stream 'Zone.Identifier' -ErrorAction Stop
        $zone = ($content | Where-Object { $_ -like 'ZoneId=*' }) -replace 'ZoneId=', ''
        $url = ($content | Where-Object { $_ -like 'HostUrl=*' }) -replace 'HostUrl=', ''
        $zoneName = switch ([string]$zone) { '0' { 'Local' } '1' { 'Intranet' } '2' { 'Trusted' } '3' { 'Internet' } '4' { 'Restricted' } default { [string]$zone } }
        return ("{0} {1}" -f $zoneName, $url).Trim()
    }
    catch { return '' }
}

function Get-CertName {
    param([string]$Subject, [string]$Part = 'CN')
    if (-not $Subject) { return '' }
    $m = [regex]::Match($Subject, "(?:^|,\s*)$Part=(""[^""]*""|[^,]*)")
    if ($m.Success) { return $m.Groups[1].Value.Trim('"').Trim() }
    return ''
}

function Get-Field {
    # Zwraca pierwszą niepustą wartość spośród podanych nazw kolumn (różne wersje Sigcheck)
    param($Row, [string[]]$Names)
    if ($null -eq $Row) { return '' }
    foreach ($n in $Names) {
        $p = $Row.PSObject.Properties[$n]
        if ($p -and $p.Value -and $p.Value -ne 'n/a') { return [string]$p.Value }
    }
    return ''
}

function Find-Sigcheck {
    param([string]$Explicit)
    if ($Explicit) {
        if (Test-Path -LiteralPath $Explicit -PathType Leaf) { return (Resolve-Path -LiteralPath $Explicit).ProviderPath }
        throw "Nie znaleziono Sigcheck: $Explicit"
    }
    $names = if ([Environment]::Is64BitOperatingSystem) { @('sigcheck64.exe', 'sigcheck.exe') } else { @('sigcheck.exe') }
    $dirs = @($PSScriptRoot, (Join-Path $PSScriptRoot 'Sysinternals'), (Join-Path $PSScriptRoot 'SysinternalsSuite'), (Get-Location).ProviderPath)
    foreach ($d in $dirs) {
        if (-not $d) { continue }
        foreach ($n in $names) {
            $c = Join-Path $d $n
            if (Test-Path -LiteralPath $c -PathType Leaf) { return $c }
        }
    }
    foreach ($n in $names) {
        $cmd = Get-Command $n -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($cmd) { return $cmd.Source }
    }
    return $null
}

function Read-ProcessOutputFile {
    # Sigcheck w zależności od wersji zapisuje wynik jako UTF-16 lub ANSI/OEM – wykrywamy kodowanie
    param([string]$File)
    $bytes = [System.IO.File]::ReadAllBytes($File)
    if ($bytes.Length -eq 0) { return '' }
    if ($bytes.Length -ge 2 -and $bytes[0] -eq 0xFF -and $bytes[1] -eq 0xFE) { return [System.Text.Encoding]::Unicode.GetString($bytes, 2, $bytes.Length - 2) }
    if ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) { return [System.Text.Encoding]::UTF8.GetString($bytes, 3, $bytes.Length - 3) }
    if ($bytes.Length -ge 2 -and $bytes[1] -eq 0) { return [System.Text.Encoding]::Unicode.GetString($bytes) }
    try {
        $utf8 = New-Object System.Text.UTF8Encoding($false, $true)
        return $utf8.GetString($bytes)
    }
    catch {
        return [System.Text.Encoding]::GetEncoding([System.Globalization.CultureInfo]::CurrentCulture.TextInfo.OEMCodePage).GetString($bytes)
    }
}

function Invoke-Sigcheck {
    param([string]$Exe, [string]$Target, [bool]$Recurse)
    $map = @{}
    # Unikamy problemu z cudzysłowem po końcowym '\' w argumencie
    $t = $Target.TrimEnd('\')
    if ($t -match '^[A-Za-z]:$') { $t += '\.' }
    # -a: rozszerzone info, -h: hashe, -e: tylko pliki wykonywalne (po nagłówku), -c: CSV
    # Brak -v/-vt => brak zapytań do VirusTotal (praca offline)
    $sigArgs = @('-accepteula', '-nobanner', '-c', '-a', '-h', '-e')
    if ($Recurse) { $sigArgs += '-s' }
    $sigArgs += ('"{0}"' -f $t)

    $outFile = [System.IO.Path]::GetTempFileName()
    $errFile = [System.IO.Path]::GetTempFileName()
    try {
        $p = Start-Process -FilePath $Exe -ArgumentList $sigArgs -NoNewWindow -Wait -PassThru `
            -RedirectStandardOutput $outFile -RedirectStandardError $errFile
        $text = Read-ProcessOutputFile -File $outFile
        $lines = $text -split "`r?`n" | Where-Object { $_.Trim() -ne '' }
        $start = 0
        for ($i = 0; $i -lt $lines.Count; $i++) { if ($lines[$i] -match '^"?Path"?[,\t]') { $start = $i; break } }
        if ($lines.Count -gt $start) {
            $rows = $lines[$start..($lines.Count - 1)] | ConvertFrom-Csv
            foreach ($r in $rows) {
                $pathVal = Get-Field $r @('Path')
                if ($pathVal) { $map[$pathVal.ToLowerInvariant()] = $r }
            }
        }
        if ($p.ExitCode -ne 0 -and $map.Count -eq 0) {
            $errText = Read-ProcessOutputFile -File $errFile
            $script:Errors.Add("Sigcheck zakończył się kodem $($p.ExitCode): $errText")
        }
    }
    catch {
        $script:Errors.Add("Błąd uruchomienia Sigcheck: $($_.Exception.Message)")
    }
    finally {
        Remove-Item -LiteralPath $outFile, $errFile -Force -ErrorAction SilentlyContinue
    }
    return $map
}

function ConvertTo-HtmlSafe { param($s) [System.Net.WebUtility]::HtmlEncode([string]$s) }

# ---------------------------------------------------------------- Sigcheck

$SigcheckExe = $null
$SigcheckMap = @{}
$SigcheckInfo = 'nie użyto'
if (-not $NoSigcheck) {
    $SigcheckExe = Find-Sigcheck -Explicit $SigcheckPath
    if ($SigcheckExe) {
        # Samo narzędzie też weryfikujemy – musi być podpisane przez Microsoft
        $sigOfTool = Get-AuthenticodeSignature -LiteralPath $SigcheckExe
        $toolSigner = if ($sigOfTool.SignerCertificate) { $sigOfTool.SignerCertificate.Subject } else { '' }
        if ($sigOfTool.Status -ne 'Valid' -or $toolSigner -notmatch 'O=Microsoft Corporation') {
            Write-Warning "Sigcheck ($SigcheckExe) nie ma ważnego podpisu Microsoft ($($sigOfTool.Status)). Pomijam."
            $Errors.Add("Sigcheck odrzucony – podpis: $($sigOfTool.Status), $toolSigner")
            $SigcheckExe = $null
        }
        else {
            $SigcheckInfo = "{0} (wersja {1})" -f $SigcheckExe, (Get-Item -LiteralPath $SigcheckExe).VersionInfo.FileVersion
            Write-Host "Sigcheck: $SigcheckInfo" -ForegroundColor Cyan
            Write-Host 'Uruchamiam Sigcheck (offline, bez VirusTotal)...' -ForegroundColor Cyan
            $SigcheckMap = Invoke-Sigcheck -Exe $SigcheckExe -Target $Root -Recurse (-not $NoRecurse)
            Write-Host ("Sigcheck zwrócił dane dla {0} plików wykonywalnych." -f $SigcheckMap.Count) -ForegroundColor Cyan
        }
    }
    else {
        Write-Warning 'Nie znaleziono Sigcheck (sigcheck64.exe/sigcheck.exe). Kontynuuję tylko z mechanizmami natywnymi. Użyj -SigcheckPath.'
    }
}

# ---------------------------------------------------------------- Wzorzec (baseline)

$BaselineMap = $null
if ($Baseline) {
    if (-not (Test-Path -LiteralPath $Baseline -PathType Leaf)) { throw "Nie znaleziono pliku wzorca: $Baseline" }
    $bRows = if ($Baseline -like '*.json') {
        Get-Content -LiteralPath $Baseline -Raw -Encoding UTF8 | ConvertFrom-Json
    }
    else {
        Import-Csv -LiteralPath $Baseline -Delimiter $Delimiter -Encoding UTF8
    }
    $BaselineMap = @{}
    foreach ($b in @($bRows)) {
        if ($b.RelativePath) { $BaselineMap[([string]$b.RelativePath).ToLowerInvariant()] = $b }
    }
    Write-Host ("Wczytano wzorzec: {0} pozycji." -f $BaselineMap.Count) -ForegroundColor Cyan
}

# ---------------------------------------------------------------- Lista plików

Write-Host "Skanuję: $Root" -ForegroundColor Cyan
$gciParams = @{ LiteralPath = $Root; File = $true; Force = $true; ErrorAction = 'SilentlyContinue'; ErrorVariable = '+gciErrors' }
if (-not $NoRecurse) { $gciParams.Recurse = $true }
$gciErrors = @()
$files = @(Get-ChildItem @gciParams)
foreach ($e in $gciErrors) { $Errors.Add("Brak dostępu: $($e.TargetObject) – $($e.Exception.Message)") }
Write-Host ("Znaleziono plików: {0}" -f $files.Count) -ForegroundColor Cyan

# ---------------------------------------------------------------- Analiza

$results = New-Object System.Collections.Generic.List[object]
$i = 0
foreach ($f in $files) {
    $i++
    if ($files.Count -gt 0) {
        Write-Progress -Activity 'Weryfikacja plików' -Status $f.FullName -PercentComplete ([int](100 * $i / $files.Count))
    }

    $rel = Get-RelativePath -Base $Root -Full $f.FullName
    $row = [ordered]@{
        RelativePath       = $rel
        FileName           = $f.Name
        Extension          = $f.Extension.ToLowerInvariant()
        SizeBytes          = $f.Length
        Created            = Format-Date $f.CreationTime
        Modified           = Format-Date $f.LastWriteTime
        LastAccess         = Format-Date $f.LastAccessTime
        Attributes         = [string]$f.Attributes
        Owner              = ''
        IsPE               = $false
        Machine            = ''
        Subsystem          = ''
        IsDotNet           = $false
        CompanyName        = ''
        ProductName        = ''
        FileDescription    = ''
        FileVersion        = ''
        ProductVersion     = ''
        OriginalFilename   = ''
        InternalName       = ''
        Copyright          = ''
        SignatureStatus    = ''
        SignatureMessage   = ''
        SignatureType      = ''
        IsOSBinary         = ''
        SignerName         = ''
        SignerOrganization = ''
        SignerSubject      = ''
        SignerIssuer       = ''
        SignerSerial       = ''
        SignerThumbprint   = ''
        CertValidFrom      = ''
        CertValidTo        = ''
        TimestampSigner    = ''
        SigningDate        = ''
        Sigcheck_Verified  = ''
        Sigcheck_Publisher = ''
        Sigcheck_Entropy   = ''
        PESHA256           = ''
        IMPHASH            = ''
        ZoneIdentifier     = ''
        BaselineStatus     = ''
        Verdict            = ''
        Notes              = ''
        FullPath           = $f.FullName
    }
    foreach ($alg in $HashAlgorithm) { $row[$alg] = '' }
    $notes = New-Object System.Collections.Generic.List[string]

    # Właściciel NTFS
    try { $row.Owner = (Get-Acl -LiteralPath $f.FullName).Owner } catch { $notes.Add('brak odczytu ACL') }

    # Hashe
    foreach ($alg in $HashAlgorithm) {
        try { $row[$alg] = (Get-FileHash -LiteralPath $f.FullName -Algorithm $alg).Hash }
        catch { $row[$alg] = 'BŁĄD'; $notes.Add("hash $alg`: $($_.Exception.Message)") }
    }

    # Nagłówek PE
    $pe = Get-PeInfo -FilePath $f.FullName
    $row.IsPE = $pe.IsPE; $row.Machine = $pe.Machine; $row.Subsystem = $pe.Subsystem; $row.IsDotNet = $pe.IsDotNet

    # Informacje o wersji
    try {
        $vi = $f.VersionInfo
        if ($vi) {
            $row.CompanyName = [string]$vi.CompanyName
            $row.ProductName = [string]$vi.ProductName
            $row.FileDescription = [string]$vi.FileDescription
            $row.FileVersion = [string]$vi.FileVersion
            $row.ProductVersion = [string]$vi.ProductVersion
            $row.OriginalFilename = [string]$vi.OriginalFilename
            $row.InternalName = [string]$vi.InternalName
            $row.Copyright = [string]$vi.LegalCopyright
        }
    }
    catch { }

    # Podpis Authenticode (osadzony lub katalogowy)
    $isSignable = $pe.IsPE -or ($SignableExtensions -contains $row.Extension)
    if ($isSignable) {
        try {
            $sig = Get-AuthenticodeSignature -LiteralPath $f.FullName
            $row.SignatureStatus = [string]$sig.Status
            $row.SignatureMessage = [string]$sig.StatusMessage
            if ($sig.PSObject.Properties['SignatureType']) { $row.SignatureType = [string]$sig.SignatureType }
            if ($sig.PSObject.Properties['IsOSBinary']) { $row.IsOSBinary = [string]$sig.IsOSBinary }
            if ($sig.SignerCertificate) {
                $c = $sig.SignerCertificate
                $row.SignerSubject = $c.Subject
                $row.SignerName = Get-CertName $c.Subject 'CN'
                $row.SignerOrganization = Get-CertName $c.Subject 'O'
                $row.SignerIssuer = $c.Issuer
                $row.SignerSerial = $c.SerialNumber
                $row.SignerThumbprint = $c.Thumbprint
                $row.CertValidFrom = Format-Date $c.NotBefore
                $row.CertValidTo = Format-Date $c.NotAfter
            }
            if ($sig.TimeStamperCertificate) { $row.TimestampSigner = Get-CertName $sig.TimeStamperCertificate.Subject 'CN' }
        }
        catch {
            $row.SignatureStatus = 'Error'
            $row.SignatureMessage = $_.Exception.Message
        }
    }
    else {
        $row.SignatureStatus = 'N/A'
    }

    # Dane z Sigcheck
    $sc = $null
    if ($SigcheckMap.Count -gt 0) { $sc = $SigcheckMap[$f.FullName.ToLowerInvariant()] }
    if ($sc) {
        $row.Sigcheck_Verified = Get-Field $sc @('Verified')
        $row.Sigcheck_Publisher = Get-Field $sc @('Publisher')
        $row.SigningDate = Get-Field $sc @('Date', 'Signing date')
        $row.Sigcheck_Entropy = Get-Field $sc @('Entropy')
        $row.PESHA256 = Get-Field $sc @('PESHA256')
        $row.IMPHASH = Get-Field $sc @('IMP', 'IMPHASH')
        if (-not $row.CompanyName) { $row.CompanyName = Get-Field $sc @('Company') }
        if (-not $row.FileVersion) { $row.FileVersion = Get-Field $sc @('File version', 'File Version') }
        if (-not $row.ProductVersion) { $row.ProductVersion = Get-Field $sc @('Product version', 'Product Version') }
        if (-not $row.Machine) { $row.Machine = Get-Field $sc @('Machine Type', 'MachineType') }
    }

    # Mark of the Web
    $row.ZoneIdentifier = Get-ZoneIdentifier -FilePath $f.FullName

    # ------------------------------------------------ Werdykt
    $level = 0   # 0 = OK/INFO, 1 = UWAGA, 2 = BŁĄD
    $verdictText = 'OK'
    switch ($row.SignatureStatus) {
        'Valid' {
            $verdictText = 'OK – podpis ważny'
            if ($ExpectedPublisher) {
                $match = $false
                foreach ($pat in $ExpectedPublisher) { if ($row.SignerSubject -like $pat) { $match = $true; break } }
                if (-not $match) { $level = [Math]::Max($level, 1); $notes.Add("nieoczekiwany wydawca: $($row.SignerName)") }
            }
        }
        'NotSigned' {
            $level = [Math]::Max($level, 1); $verdictText = 'brak podpisu'
        }
        'HashMismatch' {
            $level = 2; $verdictText = 'plik zmodyfikowany po podpisaniu (HashMismatch)'
        }
        'NotTrusted' {
            $level = 2; $verdictText = 'podpis niezaufany (certyfikat spoza zaufanych głównych urzędów)'
        }
        'NotSupportedFileFormat' {
            $verdictText = 'format nie obsługuje podpisu'
        }
        'N/A' {
            $verdictText = 'INFO – plik niewykonywalny (dane/zasoby)'
        }
        default {
            $level = 2; $verdictText = "problem z podpisem: $($row.SignatureStatus)"
        }
    }
    if ($row.SignatureStatus -eq 'Valid' -and $row.CertValidTo) {
        try {
            if ([datetime]$row.CertValidTo -lt (Get-Date) -and -not $row.TimestampSigner) {
                $level = [Math]::Max($level, 1); $notes.Add('certyfikat wygasł, a podpis nie ma znacznika czasu')
            }
        }
        catch { }
    }
    if ($sc -and $row.SignatureStatus -eq 'Valid' -and $row.Sigcheck_Verified -and $row.Sigcheck_Verified -ne 'Signed') {
        $level = [Math]::Max($level, 1); $notes.Add("Sigcheck: $($row.Sigcheck_Verified)")
    }
    if ($pe.IsPE -and $SignableExtensions -notcontains $row.Extension) {
        $level = [Math]::Max($level, 1); $notes.Add('plik wykonywalny PE z nietypowym rozszerzeniem')
    }
    if ($row.ZoneIdentifier) { $notes.Add("pobrany z: $($row.ZoneIdentifier)") }

    # Porównanie ze wzorcem
    if ($BaselineMap) {
        $key = $rel.ToLowerInvariant()
        if ($BaselineMap.ContainsKey($key)) {
            $b = $BaselineMap[$key]
            $cmpAlg = $null
            foreach ($alg in $HashAlgorithm) { if ($b.PSObject.Properties[$alg] -and $b.$alg) { $cmpAlg = $alg; break } }
            if ($cmpAlg) {
                if ($b.$cmpAlg -eq $row[$cmpAlg]) { $row.BaselineStatus = 'zgodny' }
                else { $row.BaselineStatus = 'ZMIENIONY'; $level = 2; $notes.Add("hash $cmpAlg inny niż we wzorcu") }
            }
            else { $row.BaselineStatus = 'brak wspólnego hasha' }
        }
        else {
            $row.BaselineStatus = 'NOWY'; $level = [Math]::Max($level, 1); $notes.Add('plik nie występuje we wzorcu')
        }
    }

    $prefix = switch ($level) { 0 { '' } 1 { 'UWAGA – ' } 2 { 'BŁĄD – ' } }
    if ($level -gt 0 -and $verdictText -like 'OK*') { $verdictText = $verdictText -replace '^OK – ', '' }
    $row.Verdict = $prefix + $verdictText
    $row.Notes = ($notes -join '; ')
    $row['_Level'] = $level
    $results.Add([pscustomobject]$row)
}
Write-Progress -Activity 'Weryfikacja plików' -Completed

# Pliki ze wzorca, których brakuje
$missing = @()
if ($BaselineMap) {
    $present = @{}
    foreach ($r in $results) { $present[$r.RelativePath.ToLowerInvariant()] = $true }
    $missing = @($BaselineMap.Keys | Where-Object { -not $present.ContainsKey($_) } | ForEach-Object { $BaselineMap[$_].RelativePath })
}

# ---------------------------------------------------------------- Raporty

$exportRows = $results | Select-Object -Property * -ExcludeProperty '_Level'
$csvPath = Join-Path $OutputDir 'Report.csv'
$jsonPath = Join-Path $OutputDir 'Report.json'
$htmlPath = Join-Path $OutputDir 'Report.html'
$sumPath = Join-Path $OutputDir 'SHA256SUMS.txt'
$errPath = Join-Path $OutputDir 'Errors.txt'

$exportRows | Export-Csv -LiteralPath $csvPath -NoTypeInformation -Delimiter $Delimiter -Encoding UTF8
$exportRows | ConvertTo-Json -Depth 3 | Set-Content -LiteralPath $jsonPath -Encoding UTF8

if ($HashAlgorithm -contains 'SHA256') {
    $results | ForEach-Object { '{0} *{1}' -f $_.SHA256.ToLowerInvariant(), $_.RelativePath } |
        Set-Content -LiteralPath $sumPath -Encoding UTF8
}

$cntOk = @($results | Where-Object { $_._Level -eq 0 }).Count
$cntWarn = @($results | Where-Object { $_._Level -eq 1 }).Count
$cntErr = @($results | Where-Object { $_._Level -eq 2 }).Count
$cntPE = @($results | Where-Object { $_.IsPE }).Count
$cntSigned = @($results | Where-Object { $_.SignatureStatus -eq 'Valid' }).Count
$cntUnsigned = @($results | Where-Object { $_.SignatureStatus -eq 'NotSigned' }).Count

$publishers = $results | Where-Object { $_.SignerName } | Group-Object SignerName | Sort-Object Count -Descending

# HTML
$sb = New-Object System.Text.StringBuilder
[void]$sb.AppendLine('<!DOCTYPE html><html lang="pl"><head><meta charset="utf-8"><title>Raport weryfikacji plików</title><style>')
[void]$sb.AppendLine('body{font-family:Segoe UI,Arial,sans-serif;font-size:12px;margin:16px;background:#fff;color:#222}')
[void]$sb.AppendLine('table{border-collapse:collapse;width:100%}th,td{border:1px solid #ccc;padding:3px 5px;vertical-align:top}')
[void]$sb.AppendLine('th{background:#2b4a6f;color:#fff;position:sticky;top:0}tr.l1{background:#fff4cc}tr.l2{background:#ffd6d6}')
[void]$sb.AppendLine('td.h{font-family:Consolas,monospace;font-size:11px;word-break:break-all}.sum td{border:none;padding:2px 12px 2px 0}')
[void]$sb.AppendLine('</style></head><body>')
[void]$sb.AppendLine('<h1>Raport weryfikacji plików</h1><table class="sum">')
$summary = [ordered]@{
    'Katalog'                  = $Root
    'Data raportu'             = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
    'Komputer / użytkownik'    = "$env:COMPUTERNAME / $env:USERDOMAIN\$env:USERNAME"
    'Sigcheck'                 = $SigcheckInfo
    'Liczba plików'            = $results.Count
    'Pliki wykonywalne (PE)'   = $cntPE
    'Podpis ważny'             = $cntSigned
    'Bez podpisu'              = $cntUnsigned
    'OK / UWAGA / BŁĄD'        = "$cntOk / $cntWarn / $cntErr"
}
if ($BaselineMap) { $summary['Brakujące względem wzorca'] = $missing.Count }
foreach ($k in $summary.Keys) { [void]$sb.AppendLine("<tr><td><b>$(ConvertTo-HtmlSafe $k)</b></td><td>$(ConvertTo-HtmlSafe $summary[$k])</td></tr>") }
[void]$sb.AppendLine('</table>')

if ($publishers) {
    [void]$sb.AppendLine('<h2>Podpisujący</h2><table style="width:auto"><tr><th>Podpisujący (CN)</th><th>Liczba plików</th></tr>')
    foreach ($p in $publishers) { [void]$sb.AppendLine("<tr><td>$(ConvertTo-HtmlSafe $p.Name)</td><td>$($p.Count)</td></tr>") }
    [void]$sb.AppendLine('</table>')
}
if ($missing.Count -gt 0) {
    [void]$sb.AppendLine('<h2>Pliki brakujące względem wzorca</h2><ul>')
    foreach ($m in $missing) { [void]$sb.AppendLine("<li>$(ConvertTo-HtmlSafe $m)</li>") }
    [void]$sb.AppendLine('</ul>')
}

$cols = @('RelativePath', 'Verdict', 'Notes', 'SizeBytes', 'Created', 'Modified', 'Owner', 'Machine', 'CompanyName', 'ProductName',
    'FileDescription', 'FileVersion', 'ProductVersion', 'OriginalFilename', 'SignatureStatus', 'SignatureType', 'SignerName',
    'SignerOrganization', 'SignerIssuer', 'CertValidFrom', 'CertValidTo', 'SigningDate', 'TimestampSigner', 'BaselineStatus') + $HashAlgorithm
[void]$sb.AppendLine('<h2>Pliki</h2><table><tr>')
foreach ($c in $cols) { [void]$sb.Append("<th>$c</th>") }
[void]$sb.AppendLine('</tr>')
foreach ($r in ($results | Sort-Object @{ Expression = '_Level'; Descending = $true }, RelativePath)) {
    [void]$sb.Append("<tr class=""l$($r._Level)"">")
    foreach ($c in $cols) {
        $cls = if ($HashAlgorithm -contains $c) { ' class="h"' } else { '' }
        [void]$sb.Append("<td$cls>$(ConvertTo-HtmlSafe $r.$c)</td>")
    }
    [void]$sb.AppendLine('</tr>')
}
[void]$sb.AppendLine('</table></body></html>')
[System.IO.File]::WriteAllText($htmlPath, $sb.ToString(), (New-Object System.Text.UTF8Encoding($true)))

if ($Errors.Count -gt 0) { $Errors | Set-Content -LiteralPath $errPath -Encoding UTF8 }

# ---------------------------------------------------------------- Podsumowanie w konsoli

Write-Host ''
Write-Host '================ PODSUMOWANIE ================' -ForegroundColor White
Write-Host ("Pliki:          {0}" -f $results.Count)
Write-Host ("Wykonywalne PE: {0}" -f $cntPE)
Write-Host ("Podpis ważny:   {0}" -f $cntSigned)
Write-Host ("Bez podpisu:    {0}" -f $cntUnsigned)
Write-Host ("OK:             {0}" -f $cntOk) -ForegroundColor Green
Write-Host ("UWAGA:          {0}" -f $cntWarn) -ForegroundColor Yellow
Write-Host ("BŁĄD:           {0}" -f $cntErr) -ForegroundColor Red
if ($BaselineMap) { Write-Host ("Brakujące wzgl. wzorca: {0}" -f $missing.Count) -ForegroundColor $(if ($missing.Count) { 'Red' } else { 'Green' }) }

$problems = $results | Where-Object { $_._Level -gt 0 } | Sort-Object _Level -Descending
if ($problems) {
    Write-Host ''
    Write-Host 'Pliki wymagające uwagi:' -ForegroundColor Yellow
    $problems | Select-Object -First 50 RelativePath, Verdict, SignerName, FileVersion, Notes | Format-Table -AutoSize -Wrap | Out-String -Width 220 | Write-Host
    if (@($problems).Count -gt 50) { Write-Host ("... oraz {0} kolejnych (zob. raport)" -f (@($problems).Count - 50)) }
}

Write-Host ''
Write-Host "Raporty zapisano w: $OutputDir" -ForegroundColor Cyan
Write-Host "  $csvPath"
Write-Host "  $htmlPath"
Write-Host "  $jsonPath"
if (Test-Path -LiteralPath $sumPath) { Write-Host "  $sumPath" }
if ($Errors.Count -gt 0) { Write-Host "  $errPath  ($($Errors.Count) błędów odczytu)" -ForegroundColor Yellow }

if ($cntErr -gt 0 -or $missing.Count -gt 0) { exit 2 }
elseif ($cntWarn -gt 0) { exit 1 }
else { exit 0 }
