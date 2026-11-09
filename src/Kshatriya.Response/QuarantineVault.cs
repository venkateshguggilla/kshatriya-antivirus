using System.Buffers.Binary;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using Kshatriya.Response.Native;

namespace Kshatriya.Response;

/// <summary>Metadata of one quarantined file.</summary>
public sealed record QuarantineEntry
{
    public required string Id { get; init; }

    public required string OriginalPath { get; init; }

    public required string Sha256 { get; init; }

    public required long SizeBytes { get; init; }

    public required DateTimeOffset QuarantinedUtc { get; init; }

    /// <summary>SID of the user on whose behalf the file was quarantined.</summary>
    public required string ActorSid { get; init; }

    public required string ActorName { get; init; }

    /// <summary>Detection names that led to the quarantine (empty for a manual quarantine).</summary>
    public required IReadOnlyList<string> Detections { get; init; }

    /// <summary>"scan" (automatic, from a detection) or "manual".</summary>
    public required string Origin { get; init; }
}

/// <summary>What the caller knows about the file being stored.</summary>
public sealed record QuarantineDraft(string OriginalPath, Actor Actor, IReadOnlyList<string> Detections, string Origin);

/// <summary>The content read while storing did not match the expected SHA-256; nothing was kept.</summary>
public sealed class VaultContentMismatchException : Exception
{
    public VaultContentMismatchException()
    {
    }

    public VaultContentMismatchException(string message)
        : base(message)
    {
    }

    public VaultContentMismatchException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}

/// <summary>A vault item failed authentication or its content hash check (corruption or tampering).</summary>
public sealed class VaultIntegrityException : Exception
{
    public VaultIntegrityException()
    {
    }

    public VaultIntegrityException(string message)
        : base(message)
    {
    }

    public VaultIntegrityException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}

/// <summary>
/// Encrypted store for quarantined files. Each item is encrypted with AES-256-GCM in authenticated 1 MiB
/// chunks under a per-item key derived (HKDF-SHA256) from a random vault key, which is itself protected
/// with DPAPI for the account that owns the vault. The directory has an explicit ACL (SYSTEM and
/// Administrators, or the owning user). Encryption keeps quarantined content inert: it cannot be run,
/// opened by accident or re-detected while in the vault.
/// </summary>
public sealed class QuarantineVault
{
    public const int ChunkSize = 1 << 20;
    private const int TagSize = 16;
    private const int HeaderSize = 28;
    private const byte FormatVersion = 1;
    private static readonly byte[] s_magic = "KSTQ"u8.ToArray();
    private static readonly byte[] s_keyEntropy = "Kshatriya.Quarantine.VaultKey.v1"u8.ToArray();
    private static readonly byte[] s_hkdfInfo = "kshatriya-quarantine-v1"u8.ToArray();

    private readonly byte[] _vaultKey;

    private QuarantineVault(string directory, byte[] vaultKey)
    {
        Directory = directory;
        _vaultKey = vaultKey;
    }

    public string Directory { get; }

    /// <summary>Opens (creating if needed) the vault in <paramref name="directory"/> and applies its ACL.</summary>
    public static QuarantineVault Open(string directory, StorageAccess access)
    {
        ArgumentException.ThrowIfNullOrEmpty(directory);
        string full = Path.GetFullPath(directory);
        ProtectedDirectory.Ensure(full, access);
        return new QuarantineVault(full, LoadOrCreateKey(Path.Combine(full, "vault.key")));
    }

    public static bool IsValidId(string? id) =>
        id is { Length: 32 } && id.All(c => c is (>= '0' and <= '9') or (>= 'a' and <= 'f'));

    /// <summary>
    /// Encrypts <paramref name="content"/> (read from its current position to the end) into a new item.
    /// If <paramref name="expectedSha256"/> is given and the content read does not match it, nothing is
    /// kept and <see cref="VaultContentMismatchException"/> is thrown.
    /// </summary>
    public QuarantineEntry Store(Stream content, QuarantineDraft draft, string? expectedSha256, TimeProvider? time = null)
    {
        ArgumentNullException.ThrowIfNull(content);
        ArgumentNullException.ThrowIfNull(draft);
        byte[] idBytes = RandomNumberGenerator.GetBytes(16);
        string id = Convert.ToHexStringLower(idBytes);
        string blob = BlobPath(id);
        string temp = blob + ".tmp";
        string sha256;
        long size;
        try
        {
            using (var output = new FileStream(temp, FileMode.CreateNew, FileAccess.Write, FileShare.None, 4096, FileOptions.None))
            {
                (sha256, size) = Encrypt(content, output, idBytes);
                output.Flush(flushToDisk: true);
            }

            if (expectedSha256 is not null && !string.Equals(sha256, expectedSha256, StringComparison.OrdinalIgnoreCase))
            {
                throw new VaultContentMismatchException("The file changed after it was scanned; it was not quarantined.");
            }

            File.Move(temp, blob);
            var entry = new QuarantineEntry
            {
                Id = id,
                OriginalPath = draft.OriginalPath,
                Sha256 = sha256,
                SizeBytes = size,
                QuarantinedUtc = (time ?? TimeProvider.System).GetUtcNow(),
                ActorSid = draft.Actor.Sid,
                ActorName = draft.Actor.Name,
                Detections = draft.Detections,
                Origin = draft.Origin,
            };
            WriteMetadata(entry);
            return entry;
        }
        catch
        {
            TryDelete(temp);
            TryDelete(blob);
            TryDelete(MetadataPath(id));
            throw;
        }
    }

    public IReadOnlyList<QuarantineEntry> List()
    {
        var entries = new List<QuarantineEntry>();
        foreach (string file in System.IO.Directory.EnumerateFiles(Directory, "*.json"))
        {
            string id = Path.GetFileNameWithoutExtension(file);
            if (IsValidId(id) && File.Exists(BlobPath(id)) && TryReadMetadata(file) is { } entry && entry.Id == id)
            {
                entries.Add(entry);
            }
        }

        entries.Sort(static (a, b) => b.QuarantinedUtc.CompareTo(a.QuarantinedUtc));
        return entries;
    }

    public QuarantineEntry? Get(string id)
    {
        if (!IsValidId(id) || !File.Exists(BlobPath(id)))
        {
            return null;
        }

        return TryReadMetadata(MetadataPath(id)) is { } entry && entry.Id == id ? entry : null;
    }

    /// <summary>Decrypts an item into <paramref name="destination"/>, verifying every chunk and the final SHA-256.</summary>
    public void ExtractTo(QuarantineEntry entry, Stream destination)
    {
        ArgumentNullException.ThrowIfNull(entry);
        ArgumentNullException.ThrowIfNull(destination);
        using var input = new FileStream(BlobPath(entry.Id), FileMode.Open, FileAccess.Read, FileShare.Read);
        string sha256 = Decrypt(input, destination, Convert.FromHexString(entry.Id));
        if (!string.Equals(sha256, entry.Sha256, StringComparison.Ordinal))
        {
            throw new VaultIntegrityException("The decrypted content does not match the recorded SHA-256.");
        }
    }

    /// <summary>Permanently removes an item. Returns false if it did not exist.</summary>
    public bool Delete(string id)
    {
        if (!IsValidId(id))
        {
            return false;
        }

        bool existed = File.Exists(BlobPath(id)) || File.Exists(MetadataPath(id));
        File.Delete(MetadataPath(id));
        File.Delete(BlobPath(id));
        return existed;
    }

    private string BlobPath(string id) => Path.Combine(Directory, id + ".bin");

    private string MetadataPath(string id) => Path.Combine(Directory, id + ".json");

    private (string Sha256, long Size) Encrypt(Stream content, Stream output, byte[] idBytes)
    {
        byte[] header = new byte[HeaderSize];
        s_magic.CopyTo(header, 0);
        header[4] = FormatVersion;
        idBytes.CopyTo(header, 8);
        RandomNumberGenerator.Fill(header.AsSpan(24, 4));
        output.Write(header);

        byte[] key = HKDF.DeriveKey(HashAlgorithmName.SHA256, _vaultKey, 32, idBytes, s_hkdfInfo);
        using var gcm = new AesGcm(key, TagSize);
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        byte[] plain = new byte[ChunkSize];
        byte[] cipher = new byte[ChunkSize];
        byte[] tag = new byte[TagSize];
        byte[] chunkHeader = new byte[5];
        long index = 0, total = 0;
        while (true)
        {
            int read = content.ReadAtLeast(plain, ChunkSize, throwOnEndOfStream: false);
            bool final = read < ChunkSize;
            hash.AppendData(plain, 0, read);
            total += read;

            gcm.Encrypt(Nonce(header, index), plain.AsSpan(0, read), cipher.AsSpan(0, read), tag, Aad(header, index, final));
            BinaryPrimitives.WriteUInt32LittleEndian(chunkHeader, (uint)read);
            chunkHeader[4] = final ? (byte)1 : (byte)0;
            output.Write(chunkHeader);
            output.Write(cipher, 0, read);
            output.Write(tag);
            index++;
            if (final)
            {
                break;
            }
        }

        CryptographicOperations.ZeroMemory(key);
        CryptographicOperations.ZeroMemory(plain);
        return (Convert.ToHexStringLower(hash.GetHashAndReset()), total);
    }

    private string Decrypt(Stream input, Stream destination, byte[] idBytes)
    {
        byte[] header = new byte[HeaderSize];
        if (input.ReadAtLeast(header, HeaderSize, throwOnEndOfStream: false) != HeaderSize
            || !header.AsSpan(0, 4).SequenceEqual(s_magic)
            || header[4] != FormatVersion
            || !header.AsSpan(8, 16).SequenceEqual(idBytes))
        {
            throw new VaultIntegrityException("The vault item header is invalid.");
        }

        byte[] key = HKDF.DeriveKey(HashAlgorithmName.SHA256, _vaultKey, 32, idBytes, s_hkdfInfo);
        using var gcm = new AesGcm(key, TagSize);
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        byte[] plain = new byte[ChunkSize];
        byte[] cipher = new byte[ChunkSize];
        byte[] tag = new byte[TagSize];
        byte[] chunkHeader = new byte[5];
        long index = 0;
        try
        {
            while (true)
            {
                if (input.ReadAtLeast(chunkHeader, 5, throwOnEndOfStream: false) != 5)
                {
                    throw new VaultIntegrityException("The vault item is truncated.");
                }

                uint length = BinaryPrimitives.ReadUInt32LittleEndian(chunkHeader);
                bool final = chunkHeader[4] == 1;
                if (length > ChunkSize || chunkHeader[4] > 1 || (!final && length != ChunkSize))
                {
                    throw new VaultIntegrityException("The vault item has an invalid chunk.");
                }

                if (input.ReadAtLeast(cipher.AsSpan(0, (int)length), (int)length, throwOnEndOfStream: false) != length
                    || input.ReadAtLeast(tag, TagSize, throwOnEndOfStream: false) != TagSize)
                {
                    throw new VaultIntegrityException("The vault item is truncated.");
                }

                gcm.Decrypt(Nonce(header, index), cipher.AsSpan(0, (int)length), tag, plain.AsSpan(0, (int)length), Aad(header, index, final));
                hash.AppendData(plain, 0, (int)length);
                destination.Write(plain, 0, (int)length);
                index++;
                if (final)
                {
                    break;
                }
            }

            if (input.ReadByte() != -1)
            {
                throw new VaultIntegrityException("The vault item has trailing data.");
            }
        }
        catch (AuthenticationTagMismatchException ex)
        {
            throw new VaultIntegrityException("The vault item failed authentication (corrupt or modified).", ex);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
            CryptographicOperations.ZeroMemory(plain);
        }

        return Convert.ToHexStringLower(hash.GetHashAndReset());
    }

    private static byte[] Nonce(byte[] header, long index)
    {
        byte[] nonce = new byte[12];
        header.AsSpan(24, 4).CopyTo(nonce);
        BinaryPrimitives.WriteInt64LittleEndian(nonce.AsSpan(4), index);
        return nonce;
    }

    private static byte[] Aad(byte[] header, long index, bool final)
    {
        byte[] aad = new byte[HeaderSize + 9];
        header.CopyTo(aad, 0);
        BinaryPrimitives.WriteInt64LittleEndian(aad.AsSpan(HeaderSize), index);
        aad[HeaderSize + 8] = final ? (byte)1 : (byte)0;
        return aad;
    }

    private void WriteMetadata(QuarantineEntry entry)
    {
        var dto = new VaultEntryDto
        {
            SchemaVersion = 1,
            Id = entry.Id,
            OriginalPath = entry.OriginalPath,
            Sha256 = entry.Sha256,
            SizeBytes = entry.SizeBytes,
            QuarantinedUtc = entry.QuarantinedUtc.UtcDateTime.ToString("O", CultureInfo.InvariantCulture),
            ActorSid = entry.ActorSid,
            ActorName = entry.ActorName,
            Detections = [.. entry.Detections],
            Origin = entry.Origin,
        };
        string path = MetadataPath(entry.Id);
        string temp = path + ".tmp";
        using (var stream = new FileStream(temp, FileMode.CreateNew, FileAccess.Write, FileShare.None))
        {
            JsonSerializer.Serialize(stream, dto, VaultJsonContext.Default.VaultEntryDto);
            stream.Flush(flushToDisk: true);
        }

        File.Move(temp, path);
    }

    private static QuarantineEntry? TryReadMetadata(string path)
    {
        try
        {
            VaultEntryDto? dto = JsonSerializer.Deserialize(File.ReadAllBytes(path), VaultJsonContext.Default.VaultEntryDto);
            if (dto is null || dto.SchemaVersion != 1 || !IsValidId(dto.Id)
                || !DateTimeOffset.TryParse(dto.QuarantinedUtc, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out DateTimeOffset when))
            {
                return null;
            }

            return new QuarantineEntry
            {
                Id = dto.Id,
                OriginalPath = dto.OriginalPath,
                Sha256 = dto.Sha256,
                SizeBytes = dto.SizeBytes,
                QuarantinedUtc = when,
                ActorSid = dto.ActorSid,
                ActorName = dto.ActorName,
                Detections = dto.Detections,
                Origin = dto.Origin,
            };
        }
        catch (Exception ex) when (ex is JsonException or IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }

    private static byte[] LoadOrCreateKey(string path)
    {
        for (int attempt = 0; attempt < 2; attempt++)
        {
            if (File.Exists(path))
            {
                return Unprotect(File.ReadAllBytes(path));
            }

            byte[] key = RandomNumberGenerator.GetBytes(32);
            try
            {
                using var stream = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None);
                stream.Write(Protect(key));
                stream.Flush(flushToDisk: true);
                return key;
            }
            catch (IOException) when (File.Exists(path))
            {
                // Another process created the key first; use theirs.
            }
        }

        throw new IOException($"Could not create or read the vault key '{path}'.");
    }

    private static byte[] Protect(byte[] data) => Dpapi(data, protect: true);

    private static byte[] Unprotect(byte[] data)
    {
        try
        {
            return Dpapi(data, protect: false);
        }
        catch (CryptographicException ex)
        {
            throw new VaultIntegrityException("The vault key cannot be unprotected by this account (wrong account or corrupt key).", ex);
        }
    }

    private static unsafe byte[] Dpapi(byte[] data, bool protect)
    {
        fixed (byte* pData = data)
        fixed (byte* pEntropy = s_keyEntropy)
        {
            var input = new ResponseNative.DataBlob { Size = (uint)data.Length, Data = (IntPtr)pData };
            var entropy = new ResponseNative.DataBlob { Size = (uint)s_keyEntropy.Length, Data = (IntPtr)pEntropy };
            bool ok = protect
                ? ResponseNative.CryptProtectData(in input, "Kshatriya quarantine vault key", in entropy, IntPtr.Zero, IntPtr.Zero, ResponseNative.CryptProtectUiForbidden, out ResponseNative.DataBlob output)
                : ResponseNative.CryptUnprotectData(in input, IntPtr.Zero, in entropy, IntPtr.Zero, IntPtr.Zero, ResponseNative.CryptProtectUiForbidden, out output);
            if (!ok)
            {
                throw new CryptographicException(Marshal.GetLastPInvokeError());
            }

            try
            {
                byte[] result = new byte[output.Size];
                Marshal.Copy(output.Data, result, 0, (int)output.Size);
                return result;
            }
            finally
            {
                ResponseNative.LocalFree(output.Data);
            }
        }
    }

    private static void TryDelete(string path)
    {
        try
        {
            File.Delete(path);
        }
        catch (IOException)
        {
        }
        catch (UnauthorizedAccessException)
        {
        }
    }
}

internal sealed class VaultEntryDto
{
    public required int SchemaVersion { get; init; }

    public required string Id { get; init; }

    public required string OriginalPath { get; init; }

    public required string Sha256 { get; init; }

    public required long SizeBytes { get; init; }

    public required string QuarantinedUtc { get; init; }

    public required string ActorSid { get; init; }

    public required string ActorName { get; init; }

    public required List<string> Detections { get; init; }

    public required string Origin { get; init; }
}

[JsonSourceGenerationOptions(
    PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase,
    UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
    RespectNullableAnnotations = true,
    MaxDepth = 8)]
[JsonSerializable(typeof(VaultEntryDto))]
internal sealed partial class VaultJsonContext : JsonSerializerContext
{
}
