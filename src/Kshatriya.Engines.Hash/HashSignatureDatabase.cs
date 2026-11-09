using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using Kshatriya.Core;

namespace Kshatriya.Engines.Hash;

/// <summary>One SHA-256 signature.</summary>
public sealed record HashSignature(string Sha256, string Name, DetectionCategory Category);

/// <summary>
/// An immutable set of SHA-256 signatures loaded from the Kshatriya hash database text format (v1):
/// <code>
/// # kshatriya-hashdb v1
/// # comment lines start with '#'
/// sha256:&lt;64 hex chars&gt; &lt;Name&gt; [malware|pua|suspicious|test]
/// </code>
/// Loading fails closed: any malformed line rejects the whole file, so a corrupted or tampered
/// database can never be half-loaded. (Cryptographic signing of databases arrives with signed updates.)
/// </summary>
public sealed class HashSignatureDatabase
{
    public const string Header = "# kshatriya-hashdb v1";
    private const int MaxNameLength = 128;

    private readonly Dictionary<string, HashSignature> _bySha256;

    private HashSignatureDatabase(Dictionary<string, HashSignature> bySha256, string contentVersion)
    {
        _bySha256 = bySha256;
        ContentVersion = contentVersion;
    }

    public static HashSignatureDatabase Empty { get; } = new(new Dictionary<string, HashSignature>(StringComparer.Ordinal), "empty");

    public int Count => _bySha256.Count;

    /// <summary>A short, stable identifier of the loaded content (count + digest prefix).</summary>
    public string ContentVersion { get; }

    public IEnumerable<HashSignature> Signatures => _bySha256.Values;

    public HashSignature? Find(string sha256) =>
        _bySha256.TryGetValue(sha256.ToLowerInvariant(), out HashSignature? sig) ? sig : null;

    public static HashSignatureDatabase LoadFile(string path)
    {
        ArgumentException.ThrowIfNullOrEmpty(path);
        string text = File.ReadAllText(path, Encoding.UTF8);
        return Parse(text, Path.GetFileName(path));
    }

    public static HashSignatureDatabase Parse(string text, string sourceName = "<inline>")
    {
        ArgumentNullException.ThrowIfNull(text);
        var map = new Dictionary<string, HashSignature>(StringComparer.Ordinal);
        using var reader = new StringReader(text);
        string? line;
        int lineNumber = 0;
        bool headerSeen = false;

        while ((line = reader.ReadLine()) is not null)
        {
            lineNumber++;
            string trimmed = line.Trim();
            if (lineNumber == 1)
            {
                trimmed = trimmed.TrimStart('﻿');
            }

            if (!headerSeen)
            {
                if (trimmed.Length == 0)
                {
                    continue;
                }

                if (!string.Equals(trimmed, Header, StringComparison.Ordinal))
                {
                    throw Error(sourceName, lineNumber, $"expected header '{Header}'");
                }

                headerSeen = true;
                continue;
            }

            if (trimmed.Length == 0 || trimmed[0] == '#')
            {
                continue;
            }

            HashSignature signature = ParseLine(trimmed, sourceName, lineNumber);
            if (map.TryGetValue(signature.Sha256, out HashSignature? existing))
            {
                if (!string.Equals(existing.Name, signature.Name, StringComparison.Ordinal) || existing.Category != signature.Category)
                {
                    throw Error(sourceName, lineNumber, $"conflicting duplicate for {signature.Sha256}");
                }

                continue;
            }

            map.Add(signature.Sha256, signature);
        }

        if (!headerSeen)
        {
            throw Error(sourceName, Math.Max(lineNumber, 1), $"missing header '{Header}'");
        }

        return new HashSignatureDatabase(map, ComputeContentVersion(map));
    }

    /// <summary>Combines databases; conflicting entries for the same hash are rejected.</summary>
    public static HashSignatureDatabase Merge(params IEnumerable<HashSignatureDatabase> databases)
    {
        var map = new Dictionary<string, HashSignature>(StringComparer.Ordinal);
        foreach (HashSignatureDatabase db in databases)
        {
            foreach (HashSignature sig in db.Signatures)
            {
                if (map.TryGetValue(sig.Sha256, out HashSignature? existing) && existing != sig)
                {
                    throw new FormatException($"Conflicting signatures for {sig.Sha256}: '{existing.Name}' and '{sig.Name}'.");
                }

                map[sig.Sha256] = sig;
            }
        }

        return new HashSignatureDatabase(map, ComputeContentVersion(map));
    }

    internal static HashSignatureDatabase FromSignatures(IEnumerable<HashSignature> signatures)
    {
        var map = signatures.ToDictionary(s => s.Sha256, StringComparer.Ordinal);
        return new HashSignatureDatabase(map, ComputeContentVersion(map));
    }

    private static HashSignature ParseLine(string line, string source, int lineNumber)
    {
        string[] parts = line.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length is < 2 or > 3)
        {
            throw Error(source, lineNumber, "expected 'sha256:<hex> <name> [category]'");
        }

        const string prefix = "sha256:";
        if (!parts[0].StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
        {
            throw Error(source, lineNumber, "only 'sha256:' digests are supported");
        }

        string hex = parts[0][prefix.Length..].ToLowerInvariant();
        if (hex.Length != 64 || !hex.All(char.IsAsciiHexDigitLower))
        {
            throw Error(source, lineNumber, "SHA-256 digest must be 64 hexadecimal characters");
        }

        string name = parts[1];
        if (name.Length > MaxNameLength || !name.All(IsNameChar))
        {
            throw Error(source, lineNumber, $"name must be 1-{MaxNameLength} characters of [A-Za-z0-9._-/:]");
        }

        DetectionCategory category = parts.Length == 3 ? ParseCategory(parts[2], source, lineNumber) : DetectionCategory.Malware;
        return new HashSignature(hex, name, category);
    }

    private static DetectionCategory ParseCategory(string value, string source, int lineNumber) => value.ToLowerInvariant() switch
    {
        "malware" => DetectionCategory.Malware,
        "pua" => DetectionCategory.PotentiallyUnwanted,
        "suspicious" => DetectionCategory.Suspicious,
        "test" => DetectionCategory.TestFile,
        _ => throw Error(source, lineNumber, $"unknown category '{value}'"),
    };

    private static bool IsNameChar(char c) => char.IsAsciiLetterOrDigit(c) || c is '.' or '_' or '-' or '/' or ':';

    private static string ComputeContentVersion(Dictionary<string, HashSignature> map)
    {
        if (map.Count == 0)
        {
            return "empty";
        }

        var builder = new StringBuilder();
        foreach (HashSignature sig in map.Values.OrderBy(s => s.Sha256, StringComparer.Ordinal))
        {
            builder.Append(sig.Sha256).Append(' ').Append(sig.Name).Append(' ').Append((int)sig.Category).Append('\n');
        }

        string digest = Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(builder.ToString())));
        return string.Create(CultureInfo.InvariantCulture, $"{map.Count}-{digest[..12]}");
    }

    private static FormatException Error(string source, int line, string message) =>
        new(string.Create(CultureInfo.InvariantCulture, $"{source}({line}): invalid hash database: {message}."));
}
