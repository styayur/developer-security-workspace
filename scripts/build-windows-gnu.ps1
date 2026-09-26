$ErrorActionPreference = "Stop"

$workspace = Split-Path -Parent $PSScriptRoot
Set-Location $workspace

$toolchain = "stable-x86_64-pc-windows-gnu"
$toolchains = rustup toolchain list
if (-not ($toolchains -match [regex]::Escape($toolchain))) {
    throw "Rust GNU toolchain is missing. Run: rustup toolchain install $toolchain --profile minimal"
}

if (-not (Get-Command x86_64-w64-mingw32-gcc -ErrorAction SilentlyContinue)) {
    throw "MinGW-w64 GCC is missing from PATH. Install WinLibs or another MinGW-w64 x64 toolchain."
}

$gnuRustc = rustup which --toolchain $toolchain rustc
$gnuRustdoc = rustup which --toolchain $toolchain rustdoc
$gnuBin = Split-Path -Parent $gnuRustc

$env:RUSTC = $gnuRustc
$env:RUSTDOC = $gnuRustdoc
$env:PATH = $gnuBin + ";" + $env:PATH
$env:CARGO_TARGET_DIR = Join-Path $workspace "src-tauri\target-gnu-release"

pnpm tauri build
