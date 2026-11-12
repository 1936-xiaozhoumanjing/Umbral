# SK Manager APK 构建脚本（不依赖 Gradle）
# 用法: powershell -ExecutionPolicy Bypass -File build.ps1

param(
    [switch]$Clean
)

$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot

# ---------- 工具路径 ----------
$JDK   = "D:\tools\jdk25\jdk-25.0.5+8"
$SDK   = "F:\android-sdk"
$BT    = "$SDK\build-tools\34.0.0"
$AJAR  = "$SDK\platforms\android-34\android.jar"

$JAVAC     = "$JDK\bin\javac.exe"
$KEYTOOL   = "$JDK\bin\keytool.exe"
$AAPT2     = "$BT\aapt2.exe"
$D8        = "$SDK\cmdline-tools\latest\bin\d8.bat"   # 9.4.14（build-tools 34 自带的 8.2.2 处理不了 JDK25 字节码）
$ZIPALIGN  = "$BT\zipalign.exe"
$APKSIGNER = "$BT\apksigner.bat"

# d8 / apksigner 是 .bat，靠 JAVA_HOME 找 java
$env:JAVA_HOME = $JDK
$env:PATH = "$JDK\bin;$env:PATH"

$OUT  = "$PSScriptRoot\build"
$RES  = "$PSScriptRoot\res"
$SRC  = "$PSScriptRoot\java"
$GEN  = "$OUT\gen"
$CLS  = "$OUT\classes"
$DEX  = "$OUT\dex"

# ---------- 前置检查 ----------
foreach ($t in @($JAVAC, $AAPT2, $D8, $ZIPALIGN, $APKSIGNER, $AJAR)) {
    if (-not (Test-Path $t)) { throw "missing tool: $t" }
}

if ($Clean -and (Test-Path $OUT)) {
    Remove-Item $OUT -Recurse -Force
}

New-Item -ItemType Directory -Force -Path $OUT, $GEN, $CLS, $DEX | Out-Null

$resZip   = "$OUT\resources.zip"
$baseApk  = "$OUT\base.apk"
$dexedApk = "$OUT\dexed.apk"
$aligned  = "$OUT\aligned.apk"
$final    = "$PSScriptRoot\umbral-0.90.apk"
$sk       = "$PSScriptRoot\umbral-release.jks"

Write-Host "=== 1. aapt2 compile ===" -ForegroundColor Cyan
& $AAPT2 compile --dir $RES -o $resZip
if ($LASTEXITCODE -ne 0) { throw "aapt2 compile failed" }

Write-Host "=== 2. aapt2 link ===" -ForegroundColor Cyan
$assetsDir = "$PSScriptRoot\assets"
if (Test-Path $assetsDir) {
    & $AAPT2 link -o $baseApk `
        -I $AJAR `
        --manifest "$PSScriptRoot\AndroidManifest.xml" `
        --java $GEN `
        -R $resZip `
        -A $assetsDir `
        --auto-add-overlay
} else {
    & $AAPT2 link -o $baseApk `
        -I $AJAR `
        --manifest "$PSScriptRoot\AndroidManifest.xml" `
        --java $GEN `
        -R $resZip `
        --auto-add-overlay
}
if ($LASTEXITCODE -ne 0) { throw "aapt2 link failed" }

Write-Host "=== 2.5 strip BOM from java sources ===" -ForegroundColor Cyan
$bomFixed = 0
Get-ChildItem -Path $SRC -Filter *.java -Recurse | ForEach-Object {
    $bb = [System.IO.File]::ReadAllBytes($_.FullName)
    if ($bb.Length -ge 3 -and $bb[0] -eq 0xEF -and $bb[1] -eq 0xBB -and $bb[2] -eq 0xBF) {
        $nb = New-Object byte[] ($bb.Length - 3)
        [Array]::Copy($bb, 3, $nb, 0, $bb.Length - 3)
        [System.IO.File]::WriteAllBytes($_.FullName, $nb)
        $bomFixed++
    }
}
Write-Host "  stripped BOM from $bomFixed file(s)"

Write-Host "=== 3. javac ===" -ForegroundColor Cyan
$javaFiles = Get-ChildItem -Path $SRC -Filter *.java -Recurse | Select-Object -ExpandProperty FullName
$rJava = Get-ChildItem -Path $GEN -Filter R.java -Recurse | Select-Object -First 1 -ExpandProperty FullName
if (-not $rJava) { throw "R.java not generated" }
$allJava = @($rJava) + $javaFiles
$argFile = "$OUT\javac.args"
$allJava | ForEach-Object { '"' + ($_ -replace '\\','\\') + '"' } | Set-Content $argFile -Encoding ASCII

# javac 需要能看到 XZ 库（纯 Java 解码器）—— 用参数数组，避免引号被吞
$javacArgs = @('-source', '8', '-target', '8', '-g:none', '-nowarn',
               '-bootclasspath', $AJAR,
               '-d', $CLS, '-encoding', 'UTF-8')
$xzJarForJavac = "$PSScriptRoot\libs\xz.jar"
if (Test-Path $xzJarForJavac) {
    $javacArgs += @('-classpath', $xzJarForJavac)
}
$javacArgs += "@$argFile"
& $JAVAC @javacArgs
if ($LASTEXITCODE -ne 0) { throw "javac failed" }

Write-Host "=== 4. d8 ===" -ForegroundColor Cyan
# 把纯 Java XZ 库的 class 解到 $CLS，d8 会自动一起 dex
$xzp = [System.IO.Path]::Combine($PSScriptRoot, "libs", "xz.jar")
if ([System.IO.File]::Exists($xzp)) {
    try {
        [System.IO.Compression.ZipFile]::ExtractToDirectory($xzp, $CLS)
        Write-Host "  extracted xz.jar classes into $CLS" -ForegroundColor Green
    } catch {
        Write-Host "  warn: xz.jar extract failed: $_" -ForegroundColor Yellow
    }
}

$classFiles = Get-ChildItem -Path $CLS -Filter *.class -Recurse | Select-Object -ExpandProperty FullName
if (-not $classFiles) { throw "no class files produced" }
# jar 打包后交给 d8，避免命令行超长
$jarFile = "$OUT\classes.jar"
if (Test-Path $jarFile) { Remove-Item $jarFile -Force }
& "$JDK\bin\jar.exe" cf $jarFile -C $CLS .
if ($LASTEXITCODE -ne 0) { throw "jar failed" }
& $D8 --lib $AJAR --min-api 29 --output $DEX $jarFile "E:\sk-root\manager\libs\xz.jar"
if ($LASTEXITCODE -ne 0) { throw "d8 failed" }

Write-Host "=== 5. inject classes.dex ===" -ForegroundColor Cyan
Copy-Item $baseApk $dexedApk -Force
Add-Type -AssemblyName System.IO.Compression.FileSystem
Add-Type -AssemblyName System.IO.Compression
$zip = [System.IO.Compression.ZipFile]::Open($dexedApk, [System.IO.Compression.ZipArchiveMode]::Update)
$dexPath = "$DEX\classes.dex"
if (-not (Test-Path $dexPath)) { throw "classes.dex not produced" }
$existing = $zip.GetEntry("classes.dex")
if ($existing) { $existing.Delete() }
[System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile($zip, $dexPath, "classes.dex", [System.IO.Compression.CompressionLevel]::Optimal) | Out-Null
# ── 打进本地 .so（XZ 解码器）──
$soSrc = "$PSScriptRoot\assets\lib\arm64-v8a\libumbral_xz.so"
if (Test-Path $soSrc) {
    $e = $zip.CreateEntry("lib/arm64-v8a/libumbral_xz.so", [System.IO.Compression.CompressionLevel]::NoCompression)
    $es = $e.Open()
    $bytes = [System.IO.File]::ReadAllBytes($soSrc)
    $es.Write($bytes, 0, $bytes.Length)
    $es.Close()
    Write-Host ("  packed libumbral_xz.so " + $bytes.Length + " bytes") -ForegroundColor Green
}
$zip.Dispose()

Write-Host "=== 6. zipalign ===" -ForegroundColor Cyan
& $ZIPALIGN -f 4 $dexedApk $aligned
if ($LASTEXITCODE -ne 0) { throw "zipalign failed" }


Write-Host "=== 7. keystore ===" -ForegroundColor Cyan
if (-not (Test-Path $sk)) {
    $oldEAP = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    & $KEYTOOL -genkeypair -v -keystore $sk -storepass Umbral2026! -alias umbral `
        -keypass android -keyalg RSA -keysize 2048 -validity 10000 `
        -dname "CN=Umbral,O=Umbral,C=CN" 2>&1 | Out-Null
    $ErrorActionPreference = $oldEAP
}
if (-not (Test-Path $sk)) { throw "keystore creation failed" }

Write-Host "=== 8. apksigner ===" -ForegroundColor Cyan
$oldEAP2 = $ErrorActionPreference
$ErrorActionPreference = 'Continue'
Copy-Item $aligned $final -Force
& $APKSIGNER sign --ks $sk --ks-pass pass:Umbral2026! --key-pass pass:Umbral2026! --out $final $aligned 2>&1 | Out-Null
$signExit = $LASTEXITCODE
$ErrorActionPreference = $oldEAP2
if ($signExit -ne 0) { throw "apksigner failed (exit $signExit)" }

Write-Host "=== 9. verify ===" -ForegroundColor Cyan
$oldEAP3 = $ErrorActionPreference
$ErrorActionPreference = 'Continue'
& $APKSIGNER verify --print-certs $final 2>&1 | Select-Object -First 4
$ErrorActionPreference = $oldEAP3

$fi = Get-Item $final
Write-Host ""
Write-Host "==========================================" -ForegroundColor Green
Write-Host (" APK : {0}" -f $fi.FullName) -ForegroundColor Green
Write-Host (" size: {0:N0} bytes ({1:N1} KB)" -f $fi.Length, ($fi.Length/1KB)) -ForegroundColor Green
Write-Host "==========================================" -ForegroundColor Green
