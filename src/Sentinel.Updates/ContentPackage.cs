using System.Buffers.Binary;
using System.Globalization;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Sentinel.Updates;

/// <summary>One content file listed in a manifest.</summary>
/// <param name="Name">Simple file name (letters, digits, '.', '-', '_'), ending in .hashdb or .yar.</param>
/// <param name="Kind">"hashdb" or "yara".</param>
/// <param name="Sha256">Lower-case hex SHA-256 of the file.</param>
/// <param name="Size">Size in bytes.</param>
public sealed record ContentFile(string Name, string Kind, string Sha256, long Size);

/// <summary>The signed description of a content release.</summary>
public sealed record ContentManifest(string Channel, long Sequence, DateTimeOffset CreatedUtc, DateTimeOffset ExpiresUtc, IReadOnlyList<ContentFile> Files);

/// <summary>A verified package: the manifest, its exact signed bytes, and the file contents by name.</summary>
public sealed record VerifiedContent(ContentManifest Manifest, string KeyId, IReadOnlyDictionary<string, byte[]> Files, bool Expired);

/// <summary>Stable reasons a package is refused.</summary>
public static class ContentErrors
{
    public const string Malformed = "malformed";
    public const string TooLarge = "tooLarge";
    public const string UntrustedKey = "untrustedKey";
    public const string BadSignature = "badSignature";
    public const string HashMismatch = "hashMismatch";
    public const string Expired = "expired";
    public const string Rollback = "rollback";
    public const string NoTrustedKeys = "noTrustedKeys";
    public const string ContentInvalid = "contentInvalid";
}

/// <summary>A package failed verification; <see cref="Code"/> is one of <see cref="ContentErrors"/>.</summary>
public sealed class ContentVerificationException : Exception
{
    public ContentVerificationException()
    {
        Code = ContentErrors.Malformed;
    }

    public ContentVerificationException(string message)
        : base(message)
    {
        Code = ContentErrors.Malformed;
    }

    public ContentVerificationException(string message, Exception innerException)
        : base(message, innerException)
    {
        Code = ContentErrors.Malformed;
    }

    public ContentVerificationException(string code, string message)
        : base(message)
    {
        Code = code;
    }

    public string Code { get; }
}

/// <summary>A public key allowed to sign content. The id is the first 16 hex digits of SHA-256(SubjectPublicKeyInfo).</summary>
public sealed record ContentKey(string KeyId, byte[] SubjectPublicKeyInfo)
{
    public static ContentKey FromSpki(byte[] spki)
    {
        ArgumentNullException.ThrowIfNull(spki);
        using ECDsa probe = ECDsa.Create();
        probe.ImportSubjectPublicKeyInfo(spki, out _);
        if (probe.KeySize != 256)
        {
            throw new CryptographicException("Content keys must be ECDSA P-256.");
        }

        return new ContentKey(IdOf(spki), spki);
    }

    /// <summary>Parses a base64 SubjectPublicKeyInfo (as written by the content tool).</summary>
    public static ContentKey Parse(string base64) => FromSpki(Convert.FromBase64String(base64));

    public static string IdOf(byte[] spki) => Convert.ToHexStringLower(SHA256.HashData(spki))[..16];
}

/// <summary>
/// Signed content packages (<c>.sntu</c>). Layout, little-endian:
/// <c>"SNTU" | u8 version=1 | u8[3] 0 | u32 manifestLength | manifest (UTF-8 JSON) | u32 signatureLength |
/// signature (UTF-8 JSON) | file bytes in manifest order</c>.
/// The signature (ECDSA P-256, SHA-256, IEEE P1363) covers the exact manifest bytes and is checked
/// <em>before</em> the manifest is parsed; every file is then checked against its manifest hash and size.
/// Every length is bounded before anything is allocated.
/// </summary>
public static class ContentPackage
{
    public const int MaxManifestBytes = 64 * 1024;
    public const int MaxSignatureBytes = 4 * 1024;
    public const int MaxFiles = 64;
    public const long MaxFileBytes = 128L * 1024 * 1024;
    public const long MaxPackageBytes = 256L * 1024 * 1024;
    public const string Algorithm = "ecdsa-p256-sha256";
    private const int HeaderSize = 8;
    private static readonly byte[] s_magic = "SNTU"u8.ToArray();
    private static readonly TimeSpan s_clockSkew = TimeSpan.FromDays(1);

    /// <summary>
    /// Verifies a package. When <paramref name="allowExpired"/> is false an expired manifest is refused
    /// (used for imports); installed content is re-verified with it true and flagged instead.
    /// </summary>
    public static VerifiedContent Verify(ReadOnlySpan<byte> package, IReadOnlyCollection<ContentKey> trustedKeys, DateTimeOffset now, bool allowExpired = false)
    {
        ArgumentNullException.ThrowIfNull(trustedKeys);
        if (trustedKeys.Count == 0)
        {
            throw new ContentVerificationException(ContentErrors.NoTrustedKeys, "No content signing keys are trusted on this device, so no content package can be accepted.");
        }

        if (package.Length > MaxPackageBytes)
        {
            throw new ContentVerificationException(ContentErrors.TooLarge, $"The package is larger than {MaxPackageBytes} bytes.");
        }

        if (package.Length < HeaderSize + 8 || !package[..4].SequenceEqual(s_magic) || package[4] != 1 || package[5] != 0 || package[6] != 0 || package[7] != 0)
        {
            throw Malformed("Not a Sentinel content package (bad header).");
        }

        int offset = HeaderSize;
        ReadOnlySpan<byte> manifestBytes = Section(package, ref offset, MaxManifestBytes, "manifest");
        ReadOnlySpan<byte> signatureBytes = Section(package, ref offset, MaxSignatureBytes, "signature");

        SignatureDto signature = Parse(signatureBytes, PackageJsonContext.Default.SignatureDto, "signature");
        if (signature.Algorithm != Algorithm)
        {
            throw Malformed($"Unsupported signature algorithm '{signature.Algorithm}'.");
        }

        ContentKey key = trustedKeys.FirstOrDefault(k => k.KeyId == signature.KeyId)
            ?? throw new ContentVerificationException(ContentErrors.UntrustedKey, $"The package is signed with key '{signature.KeyId}', which this device does not trust.");

        byte[] sig;
        try
        {
            sig = Convert.FromBase64String(signature.Signature);
        }
        catch (FormatException ex)
        {
            throw new ContentVerificationException("Signature is not base64.", ex);
        }

        using (ECDsa ecdsa = ECDsa.Create())
        {
            ecdsa.ImportSubjectPublicKeyInfo(key.SubjectPublicKeyInfo, out _);
            if (!ecdsa.VerifyData(manifestBytes, sig, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation))
            {
                throw new ContentVerificationException(ContentErrors.BadSignature, "The manifest signature is not valid.");
            }
        }

        // Only signed bytes are parsed from here on.
        ContentManifest manifest = ParseManifest(manifestBytes);
        if (manifest.CreatedUtc > now + s_clockSkew)
        {
            throw Malformed("The manifest was created in the future.");
        }

        bool expired = manifest.ExpiresUtc <= now;
        if (expired && !allowExpired)
        {
            throw new ContentVerificationException(ContentErrors.Expired, $"The package expired on {manifest.ExpiresUtc:u}. Stale content is refused.");
        }

        long remaining = package.Length - offset;
        if (manifest.Files.Sum(f => f.Size) != remaining)
        {
            throw Malformed("The file data does not match the sizes in the manifest.");
        }

        var files = new Dictionary<string, byte[]>(StringComparer.OrdinalIgnoreCase);
        foreach (ContentFile file in manifest.Files)
        {
            ReadOnlySpan<byte> data = package.Slice(offset, (int)file.Size);
            offset += (int)file.Size;
            if (Convert.ToHexStringLower(SHA256.HashData(data)) != file.Sha256)
            {
                throw new ContentVerificationException(ContentErrors.HashMismatch, $"'{file.Name}' does not match its manifest hash.");
            }

            files[file.Name] = data.ToArray();
        }

        return new VerifiedContent(manifest, key.KeyId, files, expired);
    }

    /// <summary>Builds and signs a package (content tool and tests). The private key never leaves the caller.</summary>
    public static byte[] Create(string channel, long sequence, DateTimeOffset createdUtc, DateTimeOffset expiresUtc, IReadOnlyList<(string Name, byte[] Data)> files, ECDsa signingKey)
    {
        ArgumentNullException.ThrowIfNull(files);
        ArgumentNullException.ThrowIfNull(signingKey);
        var dto = new ManifestDto
        {
            SchemaVersion = 1,
            Channel = channel,
            Sequence = sequence,
            CreatedUtc = createdUtc.UtcDateTime.ToString("O", CultureInfo.InvariantCulture),
            ExpiresUtc = expiresUtc.UtcDateTime.ToString("O", CultureInfo.InvariantCulture),
            Files = [.. files.Select(f => new ManifestFileDto
            {
                Name = f.Name,
                Kind = KindOf(f.Name) ?? throw new ArgumentException($"'{f.Name}' must end in .hashdb or .yar."),
                Sha256 = Convert.ToHexStringLower(SHA256.HashData(f.Data)),
                Size = f.Data.Length,
            })],
        };
        byte[] manifest = JsonSerializer.SerializeToUtf8Bytes(dto, PackageJsonContext.Default.ManifestDto);
        ParseManifest(manifest); // the same validation the verifier applies

        byte[] spki = signingKey.ExportSubjectPublicKeyInfo();
        byte[] signature = JsonSerializer.SerializeToUtf8Bytes(
            new SignatureDto
            {
                KeyId = ContentKey.IdOf(spki),
                Algorithm = Algorithm,
                Signature = Convert.ToBase64String(signingKey.SignData(manifest, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation)),
            },
            PackageJsonContext.Default.SignatureDto);

        using var output = new MemoryStream();
        output.Write(s_magic);
        output.Write([1, 0, 0, 0]);
        WriteSection(output, manifest);
        WriteSection(output, signature);
        foreach ((_, byte[] data) in files)
        {
            output.Write(data);
        }

        return output.ToArray();
    }

    public static string? KindOf(string name) =>
        name.EndsWith(".hashdb", StringComparison.OrdinalIgnoreCase) ? "hashdb"
        : name.EndsWith(".yar", StringComparison.OrdinalIgnoreCase) ? "yara"
        : null;

    private static ContentManifest ParseManifest(ReadOnlySpan<byte> bytes)
    {
        ManifestDto dto = Parse(bytes, PackageJsonContext.Default.ManifestDto, "manifest");
        if (dto.SchemaVersion != 1)
        {
            throw Malformed($"Unsupported manifest schemaVersion {dto.SchemaVersion}.");
        }

        if (string.IsNullOrWhiteSpace(dto.Channel) || dto.Channel.Length > 32 || !dto.Channel.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_'))
        {
            throw Malformed("Invalid channel name.");
        }

        if (dto.Sequence < 1)
        {
            throw Malformed("Sequence must be at least 1.");
        }

        if (!TryTime(dto.CreatedUtc, out DateTimeOffset created) || !TryTime(dto.ExpiresUtc, out DateTimeOffset expires) || expires <= created)
        {
            throw Malformed("Invalid createdUtc/expiresUtc.");
        }

        if (dto.Files.Count is 0 or > MaxFiles)
        {
            throw Malformed($"A package must list 1 to {MaxFiles} files.");
        }

        var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var files = new List<ContentFile>();
        foreach (ManifestFileDto f in dto.Files)
        {
            bool validName = f.Name.Length is > 0 and <= 64 && f.Name.All(c => char.IsAsciiLetterOrDigit(c) || c is '.' or '-' or '_') && !f.Name.StartsWith('.');
            if (!validName || KindOf(f.Name) != f.Kind || !names.Add(f.Name))
            {
                throw Malformed($"Invalid or duplicate file entry '{f.Name}'.");
            }

            if (f.Size < 0 || f.Size > MaxFileBytes || f.Sha256.Length != 64 || !f.Sha256.All(c => char.IsAsciiDigit(c) || c is >= 'a' and <= 'f'))
            {
                throw Malformed($"Invalid size or hash for '{f.Name}'.");
            }

            files.Add(new ContentFile(f.Name, f.Kind, f.Sha256, f.Size));
        }

        return new ContentManifest(dto.Channel, dto.Sequence, created, expires, files);
    }

    private static bool TryTime(string value, out DateTimeOffset time) =>
        DateTimeOffset.TryParseExact(value, "O", CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out time);

    private static ReadOnlySpan<byte> Section(ReadOnlySpan<byte> package, ref int offset, int max, string what)
    {
        if (package.Length - offset < 4)
        {
            throw Malformed($"Truncated {what} length.");
        }

        uint length = BinaryPrimitives.ReadUInt32LittleEndian(package.Slice(offset, 4));
        offset += 4;
        if (length == 0 || length > max || length > package.Length - offset)
        {
            throw Malformed($"Invalid {what} length.");
        }

        ReadOnlySpan<byte> section = package.Slice(offset, (int)length);
        offset += (int)length;
        return section;
    }

    private static void WriteSection(Stream output, byte[] data)
    {
        Span<byte> length = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32LittleEndian(length, (uint)data.Length);
        output.Write(length);
        output.Write(data);
    }

    private static T Parse<T>(ReadOnlySpan<byte> json, System.Text.Json.Serialization.Metadata.JsonTypeInfo<T> type, string what)
        where T : class
    {
        try
        {
            return JsonSerializer.Deserialize(json, type) ?? throw Malformed($"Empty {what}.");
        }
        catch (JsonException ex)
        {
            throw new ContentVerificationException($"The {what} is not valid: {ex.Message}", ex);
        }
    }

    private static ContentVerificationException Malformed(string message) => new(ContentErrors.Malformed, message);
}

internal sealed class ManifestDto
{
    public required int SchemaVersion { get; init; }

    public required string Channel { get; init; }

    public required long Sequence { get; init; }

    public required string CreatedUtc { get; init; }

    public required string ExpiresUtc { get; init; }

    public required List<ManifestFileDto> Files { get; init; }
}

internal sealed class ManifestFileDto
{
    public required string Name { get; init; }

    public required string Kind { get; init; }

    public required string Sha256 { get; init; }

    public required long Size { get; init; }
}

internal sealed class SignatureDto
{
    public required string KeyId { get; init; }

    public required string Algorithm { get; init; }

    public required string Signature { get; init; }
}

[JsonSourceGenerationOptions(
    PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase,
    UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
    RespectNullableAnnotations = true,
    MaxDepth = 8)]
[JsonSerializable(typeof(ManifestDto))]
[JsonSerializable(typeof(SignatureDto))]
internal sealed partial class PackageJsonContext : JsonSerializerContext
{
}

/// <summary>Content signing keys compiled into the product.</summary>
public static class ContentTrust
{
    /// <summary>
    /// Production signing keys. Empty: no production signing key has been provisioned yet, so the
    /// installed service accepts content only from keys an administrator adds to its protected settings.
    /// </summary>
    public static IReadOnlyList<ContentKey> ProductionKeys { get; } = [];
}
