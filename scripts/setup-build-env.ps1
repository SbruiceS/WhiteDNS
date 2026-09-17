$ErrorActionPreference = "Stop"

$cmakeCandidates = @(
    "C:\Program Files\Microsoft Visual Studio\18\Enterprise\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin",
    "C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin",
    "C:\Program Files\CMake\bin"
)

$ninjaCandidates = @(
    "C:\Program Files\Microsoft Visual Studio\18\Enterprise\Common7\IDE\CommonExtensions\Microsoft\CMake\Ninja",
    "C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\Common7\IDE\CommonExtensions\Microsoft\CMake\Ninja"
)

$msvcCandidates = @(
    "C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\VC\Tools\MSVC\14.51.36231\bin\Hostx64\x64",
    "C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC\14.51.36231\bin\Hostx64\x64"
)

$gppCandidates = @(
    "C:\msys64\ucrt64\bin",
    "C:\msys64\mingw64\bin",
    "C:\mingw64\bin",
    "C:\MinGW\bin"
)

$existing = @()
foreach ($path in $cmakeCandidates + $ninjaCandidates + $msvcCandidates + $gppCandidates) {
    if (Test-Path $path) {
        $existing += $path
    }
}

$env:PATH = ($existing + ($env:PATH -split ';' | Where-Object { $_ })) -join ';'

Write-Host "WhiteDNS build PATH updated for this PowerShell session."
Write-Host "cmake: $((Get-Command cmake -ErrorAction SilentlyContinue).Source)"
Write-Host "ninja: $((Get-Command ninja -ErrorAction SilentlyContinue).Source)"
Write-Host "cl:    $((Get-Command cl -ErrorAction SilentlyContinue).Source)"
Write-Host "g++:   $((Get-Command g++ -ErrorAction SilentlyContinue).Source)"
