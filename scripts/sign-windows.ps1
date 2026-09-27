param([Parameter(Mandatory)][string]$Path)
$ErrorActionPreference = 'Stop'
if (-not $env:DSW_SIGNING_THUMBPRINT) { throw 'DSW_SIGNING_THUMBPRINT is required' }
$certificate = Get-Item -LiteralPath "Cert:\CurrentUser\My\$env:DSW_SIGNING_THUMBPRINT"
if (-not $certificate.HasPrivateKey) { throw 'Code-signing private key is unavailable' }
$signature = Set-AuthenticodeSignature -LiteralPath $Path -Certificate $certificate -HashAlgorithm SHA256
if ($signature.SignerCertificate.Thumbprint -ne $certificate.Thumbprint) { throw 'Signer mismatch' }
& "$PSScriptRoot/verify-windows-signature.ps1" -Path $Path -CertificatePath "$PSScriptRoot/../docs/release/DSW-self-signed.cer"
if (-not $?) { throw 'Signature verification failed' }
