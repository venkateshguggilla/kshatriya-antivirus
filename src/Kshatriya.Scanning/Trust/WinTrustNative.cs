using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace Kshatriya.Scanning.Trust;

/// <summary>WinTrust / catalog interop. Structure layouts follow wintrust.h and mscat.h.</summary>
internal static unsafe partial class WinTrustNative
{
    internal static readonly Guid GenericVerifyV2 = new("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");
    internal static readonly Guid DriverActionVerify = new("F750E6C3-38EE-11d1-85E5-00C04FC295EE");

    internal const uint WtdUiNone = 2;
    internal const uint WtdRevokeNone = 0;
    internal const uint WtdChoiceFile = 1;
    internal const uint WtdChoiceCatalog = 2;
    internal const uint WtdStateActionVerify = 1;
    internal const uint WtdStateActionClose = 2;

    // No revocation checks and no network retrieval: offline-first, and no data leaves the machine.
    internal const uint WtdRevocationCheckNone = 0x00000010;
    internal const uint WtdCacheOnlyUrlRetrieval = 0x00001000;

    internal const int TrustENoSignature = unchecked((int)0x800B0100);
    internal const int TrustESubjectFormUnknown = unchecked((int)0x800B0003);
    internal const int TrustEProviderUnknown = unchecked((int)0x800B0001);

    internal const uint CertNameSimpleDisplayType = 4;

    [StructLayout(LayoutKind.Sequential)]
    internal struct WinTrustFileInfo
    {
        public uint CbStruct;
        public char* FilePath;
        public IntPtr File;
        public Guid* KnownSubject;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct WinTrustCatalogInfo
    {
        public uint CbStruct;
        public uint CatalogVersion;
        public char* CatalogFilePath;
        public char* MemberTag;
        public char* MemberFilePath;
        public IntPtr MemberFile;
        public byte* CalculatedFileHash;
        public uint CalculatedFileHashLength;
        public IntPtr CatalogContext;
        public IntPtr CatAdmin;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct WinTrustData
    {
        public uint CbStruct;
        public IntPtr PolicyCallbackData;
        public IntPtr SipClientData;
        public uint UiChoice;
        public uint RevocationChecks;
        public uint UnionChoice;
        public void* Info;
        public uint StateAction;
        public IntPtr StateData;
        public char* UrlReference;
        public uint ProvFlags;
        public uint UiContext;
        public IntPtr SignatureSettings;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct CatalogInfo
    {
        public uint CbStruct;
        public fixed char CatalogFile[260];
    }

    /// <summary>Leading fields of CRYPT_PROVIDER_SIGNER.</summary>
    [StructLayout(LayoutKind.Sequential)]
    internal struct CryptProviderSignerHead
    {
        public uint CbStruct;
        public uint VerifyAsOfLow;   // FILETIME is two DWORDs (4-byte aligned), not a 64-bit integer
        public uint VerifyAsOfHigh;
        public uint CertChainCount;
        public IntPtr CertChain;
    }

    /// <summary>Leading fields of CRYPT_PROVIDER_CERT.</summary>
    [StructLayout(LayoutKind.Sequential)]
    internal struct CryptProviderCertHead
    {
        public uint CbStruct;
        public IntPtr Cert;
    }

    [LibraryImport("wintrust.dll")]
    internal static partial int WinVerifyTrust(IntPtr hwnd, Guid* actionId, WinTrustData* data);

    [LibraryImport("wintrust.dll")]
    internal static partial IntPtr WTHelperProvDataFromStateData(IntPtr stateData);

    [LibraryImport("wintrust.dll")]
    internal static partial IntPtr WTHelperGetProvSignerFromChain(
        IntPtr provData,
        uint signerIndex,
        [MarshalAs(UnmanagedType.Bool)] bool counterSigner,
        uint counterSignerIndex);

    [LibraryImport("wintrust.dll", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool CryptCATAdminAcquireContext2(
        out IntPtr catAdmin,
        Guid* subsystem,
        string hashAlgorithm,
        IntPtr strongHashPolicy,
        uint flags);

    [LibraryImport("wintrust.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool CryptCATAdminReleaseContext(IntPtr catAdmin, uint flags);

    [LibraryImport("wintrust.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool CryptCATAdminCalcHashFromFileHandle2(
        IntPtr catAdmin,
        SafeFileHandle file,
        ref uint hashLength,
        byte* hash,
        uint flags);

    [LibraryImport("wintrust.dll", SetLastError = true)]
    internal static partial IntPtr CryptCATAdminEnumCatalogFromHash(
        IntPtr catAdmin,
        byte* hash,
        uint hashLength,
        uint flags,
        IntPtr previousCatInfo);

    [LibraryImport("wintrust.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool CryptCATCatalogInfoFromContext(IntPtr catInfo, CatalogInfo* info, uint flags);

    [LibraryImport("wintrust.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool CryptCATAdminReleaseCatalogContext(IntPtr catAdmin, IntPtr catInfo, uint flags);

    [LibraryImport("crypt32.dll", EntryPoint = "CertGetNameStringW")]
    internal static partial uint CertGetNameString(IntPtr certContext, uint type, uint flags, IntPtr typePara, char* name, uint nameLength);
}
