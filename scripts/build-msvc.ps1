$ErrorActionPreference = "Stop"

$vsDevCmd = "C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\Common7\Tools\VsDevCmd.bat"
$cmake = "C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe"
$ninja = "C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\Common7\IDE\CommonExtensions\Microsoft\CMake\Ninja\ninja.exe"
$buildDir = "build-msvc"
$repo = (Resolve-Path ".").Path
$buildPath = Join-Path $repo $buildDir

if (-not (Test-Path $vsDevCmd)) {
    throw "VsDevCmd.bat not found: $vsDevCmd"
}

if (-not (Test-Path $cmake)) {
    throw "cmake.exe not found: $cmake"
}

if (-not (Test-Path $ninja)) {
    throw "ninja.exe not found: $ninja"
}

$command = "call `"$vsDevCmd`" -arch=x64 -host_arch=x64 && `"$cmake`" -S `"$repo`" -B `"$buildPath`" -G Ninja -DCMAKE_MAKE_PROGRAM=`"$ninja`" && `"$cmake`" --build `"$buildPath`""

cmd.exe /d /s /c $command
if ($LASTEXITCODE -ne 0) {
    throw "MSVC build failed with exit code $LASTEXITCODE"
}

Write-Host "WhiteDNS built successfully: $buildPath\whitedns.exe"
