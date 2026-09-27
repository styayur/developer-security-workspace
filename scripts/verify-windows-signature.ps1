param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$CertificatePath)
$ErrorActionPreference = 'Stop'
$expected = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new((Resolve-Path -LiteralPath $CertificatePath).Path)
$signature = Get-AuthenticodeSignature -LiteralPath $Path
if ($signature.SignerCertificate.Thumbprint -ne $expected.Thumbprint) { throw "Unexpected signer: $Path" }
# WinVerifyTrust checks the PE digest as well as the embedded signature. The only
# tolerated trust error is the known self-signed root; never ignore HashMismatch.
if (-not ('DswSignatureTrust' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class DswSignatureTrust {
    [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
    struct FileInfo { public uint size; [MarshalAs(UnmanagedType.LPWStr)] public string path; public IntPtr file; public IntPtr subject; }
    [StructLayout(LayoutKind.Sequential)]
    struct TrustData {
        public uint size; public IntPtr policy, sip; public uint ui, revocation, choice;
        public IntPtr file; public uint state; public IntPtr stateData, url; public uint flags, context; public IntPtr settings;
    }
    [DllImport("wintrust.dll", ExactSpelling=true)]
    static extern int WinVerifyTrust(IntPtr window, ref Guid action, ref TrustData data);
    public static uint Verify(string path) {
        var file = new FileInfo {size=(uint)Marshal.SizeOf<FileInfo>(), path=path};
        var pointer=Marshal.AllocHGlobal(Marshal.SizeOf<FileInfo>());
        Marshal.StructureToPtr(file,pointer,false);
        var data=new TrustData {size=(uint)Marshal.SizeOf<TrustData>(),ui=2,choice=1,file=pointer,flags=0x1000};
        var action=new Guid("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");
        try { return unchecked((uint)WinVerifyTrust(new IntPtr(-1),ref action,ref data)); }
        finally { Marshal.DestroyStructure<FileInfo>(pointer); Marshal.FreeHGlobal(pointer); }
    }
}
'@
}
$status = [DswSignatureTrust]::Verify((Resolve-Path -LiteralPath $Path).Path)
if ($status -notin @(0, [uint32]2148204809)) { throw ('Invalid Authenticode signature: 0x{0:X8}' -f $status) }
# Establish the exact public certificate as an isolated verification root,
# without modifying any Windows certificate trust store.
$chain = [System.Security.Cryptography.X509Certificates.X509Chain]::new()
try {
    $chain.ChainPolicy.TrustMode = 'CustomRootTrust'
    $null = $chain.ChainPolicy.CustomTrustStore.Add($expected)
    $chain.ChainPolicy.RevocationMode = 'NoCheck'
    $null = $chain.ChainPolicy.ApplicationPolicy.Add([System.Security.Cryptography.Oid]::new('1.3.6.1.5.5.7.3.3'))
    if (-not $chain.Build($signature.SignerCertificate)) { throw 'Code-signing certificate is invalid or expired' }
} finally { $chain.Dispose() }
Write-Output "Verified file integrity and expected self-signed publisher: $([IO.Path]::GetFileName($Path))"
