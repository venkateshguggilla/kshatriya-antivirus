using System.Text;
using System.Text.Json;
using Kshatriya.Engines.Hash;
using Kshatriya.Updates;

namespace Kshatriya.Mobile;

/// <summary>Outcome of importing a signed content package on the device.</summary>
public sealed record ContentImportResult(bool Succeeded, string? Code, string Message, long Sequence = 0);

/// <summary>
/// Signed content (ADR 0008) on the device (ADR 0020): packages are verified exactly as on Windows (signature
/// before parsing, hashes, expiry) and must have a higher sequence than any installed before (anti-rollback).
/// Everything lives in an app-private folder that only this app can write.
/// </summary>
public sealed class MobileContentStore
{
    private const string ActiveFile = "active.kstu";
    private const string StateFile = "state.json";
    private const string KeysFile = "trusted-keys.txt";
    private readonly string _folder;
    private readonly IReadOnlyList<ContentKey> _builtInKeys;
    private readonly object _gate = new();

    public MobileContentStore(string folder, IReadOnlyList<ContentKey>? builtInKeys = null)
    {
        ArgumentException.ThrowIfNullOrEmpty(folder);
        _folder = folder;
        _builtInKeys = builtInKeys ?? ContentTrust.ProductionKeys;
        Directory.CreateDirectory(folder);
    }

    /// <summary>Built-in keys plus keys the user added.</summary>
    public IReadOnlyList<ContentKey> TrustedKeys
    {
        get
        {
            lock (_gate)
            {
                return [.. _builtInKeys, .. UserKeys()];
            }
        }
    }

    /// <summary>
    /// Parses a public key file as written by <c>kshatriya-content keygen</c> (base64 SubjectPublicKeyInfo)
    /// without trusting it, so the app can show its id and ask the user first.
    /// </summary>
    public static ContentKey ReadKey(string text) => ContentKey.Parse(text.Trim());

    /// <summary>Trusts a key the user confirmed. Returns false if it was already trusted.</summary>
    public bool AddTrustedKey(ContentKey key)
    {
        ArgumentNullException.ThrowIfNull(key);
        lock (_gate)
        {
            if (TrustedKeysUnlocked().Any(k => k.KeyId == key.KeyId))
            {
                return false;
            }

            File.AppendAllText(Path.Combine(_folder, KeysFile), Convert.ToBase64String(key.SubjectPublicKeyInfo) + "\n");
            return true;
        }
    }

    /// <summary>Verifies and installs a package. Any failure leaves the current content in place.</summary>
    public ContentImportResult Import(byte[] package, DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(package);
        lock (_gate)
        {
            VerifiedContent content;
            try
            {
                content = ContentPackage.Verify(package, TrustedKeysUnlocked(), now);
                // The lists must parse before anything is replaced.
                _ = SignaturesOf(content);
                _ = AppIndicatorsOf(content);
            }
            catch (ContentVerificationException ex)
            {
                return new ContentImportResult(false, ex.Code, ex.Message);
            }
            catch (FormatException ex)
            {
                return new ContentImportResult(false, ContentErrors.ContentInvalid, $"A list in the package is invalid: {ex.Message}");
            }

            long highest = ReadState().HighestSequence;
            if (content.Manifest.Sequence <= highest)
            {
                return new ContentImportResult(false, ContentErrors.Rollback, $"Update {content.Manifest.Sequence} is not newer than update {highest}, which was already installed.");
            }

            string temporary = Path.Combine(_folder, ActiveFile + ".new");
            File.WriteAllBytes(temporary, package);
            File.Move(temporary, Path.Combine(_folder, ActiveFile), overwrite: true);
            WriteState(new StoreState { HighestSequence = content.Manifest.Sequence });
            return new ContentImportResult(true, null, $"Update {content.Manifest.Sequence} is installed, valid until {content.Manifest.ExpiresUtc:yyyy-MM-dd}.", content.Manifest.Sequence);
        }
    }

    /// <summary>
    /// The installed package, re-verified (an expired package is still used, and flagged), or null when none
    /// is installed. Throws <see cref="ContentVerificationException"/> if it no longer verifies.
    /// </summary>
    public VerifiedContent? LoadActive(DateTimeOffset now)
    {
        lock (_gate)
        {
            string path = Path.Combine(_folder, ActiveFile);
            return File.Exists(path) ? ContentPackage.Verify(File.ReadAllBytes(path), TrustedKeysUnlocked(), now, allowExpired: true) : null;
        }
    }

    /// <summary>The signature lists (<c>*.hashdb</c>) of a package, merged.</summary>
    public static HashSignatureDatabase SignaturesOf(VerifiedContent content)
    {
        ArgumentNullException.ThrowIfNull(content);
        return HashSignatureDatabase.Merge(content.Manifest.Files.Where(f => f.Kind == "hashdb")
            .Select(f => HashSignatureDatabase.Parse(Encoding.UTF8.GetString(content.Files[f.Name]), f.Name)));
    }

    /// <summary>The app indicator lists (<c>*.appblock</c>) of a package, merged.</summary>
    public static AppIndicatorSet AppIndicatorsOf(VerifiedContent content)
    {
        ArgumentNullException.ThrowIfNull(content);
        return new AppIndicatorSet(content.Manifest.Files.Where(f => f.Kind == "appblock")
            .SelectMany(f => AppBlockList.Parse(Encoding.UTF8.GetString(content.Files[f.Name]), f.Name)));
    }

    private IReadOnlyList<ContentKey> TrustedKeysUnlocked() => [.. _builtInKeys, .. UserKeys()];

    private IEnumerable<ContentKey> UserKeys()
    {
        string path = Path.Combine(_folder, KeysFile);
        if (!File.Exists(path))
        {
            yield break;
        }

        foreach (string line in File.ReadAllLines(path).Select(l => l.Trim()).Where(l => l.Length > 0))
        {
            yield return ContentKey.Parse(line);
        }
    }

    private StoreState ReadState()
    {
        string path = Path.Combine(_folder, StateFile);
        return File.Exists(path) ? JsonSerializer.Deserialize(File.ReadAllText(path), StoreJsonContext.Default.StoreState) ?? new StoreState() : new StoreState();
    }

    private void WriteState(StoreState state) =>
        File.WriteAllText(Path.Combine(_folder, StateFile), JsonSerializer.Serialize(state, StoreJsonContext.Default.StoreState));

}

internal sealed class StoreState
{
    public long HighestSequence { get; set; }
}

[System.Text.Json.Serialization.JsonSerializable(typeof(StoreState))]
internal sealed partial class StoreJsonContext : System.Text.Json.Serialization.JsonSerializerContext
{
}
