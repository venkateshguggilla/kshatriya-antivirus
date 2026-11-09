using Microsoft.Win32.SafeHandles;
using Kshatriya.Core;
using static Kshatriya.Scanning.Trust.WinTrustNative;

namespace Kshatriya.Scanning.Trust;

/// <summary>Determines whether file content is validly code-signed.</summary>
public interface ITrustProvider
{
    /// <summary>Checks the file behind <paramref name="handle"/>. Must not follow links or modify the file.</summary>
    FileTrust Evaluate(SafeFileHandle handle, string displayPath);
}

/// <summary>
/// Authenticode verification through WinVerifyTrust: first the embedded signature, then the system
/// catalogs (most Windows system files are catalog-signed). Revocation checks and network retrieval
/// are disabled, so verification is offline and sends nothing anywhere. Verification reads through the
/// already-open handle, so it checks exactly the content that was scanned.
/// </summary>
public sealed unsafe class AuthenticodeTrustProvider : ITrustProvider
{
    private static readonly string[] s_catalogHashAlgorithms = ["SHA256", "SHA1"];

    public FileTrust Evaluate(SafeFileHandle handle, string displayPath)
    {
        ArgumentNullException.ThrowIfNull(handle);
        ArgumentException.ThrowIfNullOrEmpty(displayPath);

        (int result, string? signer) = VerifyEmbedded(handle, displayPath);
        if (result == 0)
        {
            return new FileTrust(TrustStatus.Valid, TrustSource.Embedded, signer);
        }

        if (result is not (TrustENoSignature or TrustESubjectFormUnknown or TrustEProviderUnknown))
        {
            return new FileTrust(TrustStatus.Invalid, TrustSource.Embedded, signer);
        }

        foreach (string algorithm in s_catalogHashAlgorithms)
        {
            FileTrust? catalog = VerifyCatalog(handle, displayPath, algorithm);
            if (catalog is not null)
            {
                return catalog;
            }
        }

        return FileTrust.NotSigned;
    }

    private static (int Result, string? Signer) VerifyEmbedded(SafeFileHandle handle, string displayPath)
    {
        bool addedRef = false;
        handle.DangerousAddRef(ref addedRef);
        try
        {
            fixed (char* path = displayPath)
            {
                var file = new WinTrustFileInfo
                {
                    CbStruct = (uint)sizeof(WinTrustFileInfo),
                    FilePath = path,
                    File = handle.DangerousGetHandle(),
                };
                var data = NewData(WtdChoiceFile, &file);
                return VerifyAndClose(&data);
            }
        }
        finally
        {
            if (addedRef)
            {
                handle.DangerousRelease();
            }
        }
    }

    private static FileTrust? VerifyCatalog(SafeFileHandle handle, string displayPath, string algorithm)
    {
        Guid subsystem = DriverActionVerify;
        if (!CryptCATAdminAcquireContext2(out IntPtr catAdmin, &subsystem, algorithm, IntPtr.Zero, 0))
        {
            return null;
        }

        IntPtr catInfo = IntPtr.Zero;
        try
        {
            byte* hash = stackalloc byte[64];
            uint hashLength = 64;
            if (!CryptCATAdminCalcHashFromFileHandle2(catAdmin, handle, ref hashLength, hash, 0))
            {
                return null;
            }

            catInfo = CryptCATAdminEnumCatalogFromHash(catAdmin, hash, hashLength, 0, IntPtr.Zero);
            if (catInfo == IntPtr.Zero)
            {
                return null;
            }

            var info = new CatalogInfo { CbStruct = (uint)sizeof(CatalogInfo) };
            if (!CryptCATCatalogInfoFromContext(catInfo, &info, 0))
            {
                return null;
            }

            string memberTag = Convert.ToHexString(new ReadOnlySpan<byte>(hash, (int)hashLength));
            bool addedRef = false;
            handle.DangerousAddRef(ref addedRef);
            try
            {
                fixed (char* tag = memberTag)
                fixed (char* member = displayPath)
                {
                    var catalog = new WinTrustCatalogInfo
                    {
                        CbStruct = (uint)sizeof(WinTrustCatalogInfo),
                        CatalogFilePath = info.CatalogFile,
                        MemberTag = tag,
                        MemberFilePath = member,
                        MemberFile = handle.DangerousGetHandle(),
                        CalculatedFileHash = hash,
                        CalculatedFileHashLength = hashLength,
                        CatAdmin = catAdmin,
                    };
                    var data = NewData(WtdChoiceCatalog, &catalog);
                    (int result, string? signer) = VerifyAndClose(&data);
                    return result == 0
                        ? new FileTrust(TrustStatus.Valid, TrustSource.Catalog, signer)
                        : new FileTrust(TrustStatus.Invalid, TrustSource.Catalog, signer);
                }
            }
            finally
            {
                if (addedRef)
                {
                    handle.DangerousRelease();
                }
            }
        }
        finally
        {
            if (catInfo != IntPtr.Zero)
            {
                CryptCATAdminReleaseCatalogContext(catAdmin, catInfo, 0);
            }

            CryptCATAdminReleaseContext(catAdmin, 0);
        }
    }

    private static WinTrustData NewData(uint unionChoice, void* info) => new()
    {
        CbStruct = (uint)sizeof(WinTrustData),
        UiChoice = WtdUiNone,
        RevocationChecks = WtdRevokeNone,
        UnionChoice = unionChoice,
        Info = info,
        StateAction = WtdStateActionVerify,
        ProvFlags = WtdRevocationCheckNone | WtdCacheOnlyUrlRetrieval,
    };

    private static (int Result, string? Signer) VerifyAndClose(WinTrustData* data)
    {
        Guid action = GenericVerifyV2;
        int result = WinVerifyTrust(new IntPtr(-1), &action, data);
        string? signer = null;
        try
        {
            if (data->StateData != IntPtr.Zero)
            {
                signer = ReadSigner(data->StateData);
            }
        }
        finally
        {
            data->StateAction = WtdStateActionClose;
            _ = WinVerifyTrust(new IntPtr(-1), &action, data); // closing the state cannot meaningfully fail
        }

        return (result, signer);
    }

    private static string? ReadSigner(IntPtr stateData)
    {
        IntPtr provData = WTHelperProvDataFromStateData(stateData);
        if (provData == IntPtr.Zero)
        {
            return null;
        }

        IntPtr signerPtr = WTHelperGetProvSignerFromChain(provData, 0, false, 0);
        if (signerPtr == IntPtr.Zero)
        {
            return null;
        }

        var signer = (CryptProviderSignerHead*)signerPtr;
        if (signer->CertChainCount == 0 || signer->CertChain == IntPtr.Zero)
        {
            return null;
        }

        IntPtr cert = ((CryptProviderCertHead*)signer->CertChain)->Cert;
        if (cert == IntPtr.Zero)
        {
            return null;
        }

        char* buffer = stackalloc char[256];
        uint length = CertGetNameString(cert, CertNameSimpleDisplayType, 0, IntPtr.Zero, buffer, 256);
        return length > 1 ? new string(buffer, 0, (int)length - 1) : null;
    }
}
