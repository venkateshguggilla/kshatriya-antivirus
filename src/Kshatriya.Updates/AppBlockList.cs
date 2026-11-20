namespace Kshatriya.Updates;

/// <summary>What an app indicator compares.</summary>
public enum AppIndicatorKind
{
    /// <summary>The app's package name (application id).</summary>
    Package,

    /// <summary>SHA-1 of a signing certificate (DER), lower-case hex.</summary>
    CertificateSha1,

    /// <summary>SHA-256 of a signing certificate (DER), lower-case hex.</summary>
    CertificateSha256,
}

/// <summary>One listed app identity.</summary>
/// <param name="Kind">What <paramref name="Value"/> is compared with.</param>
/// <param name="Value">A package name, or a lower-case hex certificate digest.</param>
/// <param name="Name">The detection name to report, for example "Android.Stalkerware.TheTruthSpy".</param>
/// <param name="Category">"malware", "pua" or "suspicious" as listed (package matches are reported as suspicious).</param>
public sealed record AppIndicator(AppIndicatorKind Kind, string Value, string Name, string Category);

/// <summary>
/// Lists of Android apps by identity (ADR 0020), delivered as signed content (<c>*.appblock</c>, header
/// <c># kshatriya-appblock v1</c>), one indicator per line: <c>package &lt;name&gt; &lt;detection name&gt; &lt;category&gt;</c>,
/// <c>cert-sha1 &lt;hex&gt; ...</c> or <c>cert-sha256 &lt;hex&gt; ...</c>. Lines starting with <c>#</c> are comments.
/// Any invalid line rejects the whole list.
/// </summary>
public static class AppBlockList
{
    public const string Header = "# kshatriya-appblock v1";
    public const int MaxEntries = 100_000;
    private const int MaxNameLength = 128;
    private const int MaxPackageLength = 255;

    /// <summary>
    /// SHA-1 digests of the public AOSP signing keys (testkey, platform, shared, media). Builds signed with
    /// them are common, so a list naming one would flag unrelated apps.
    /// </summary>
    private static readonly HashSet<string> s_publicKeys = new(StringComparer.Ordinal)
    {
        "61ed377e85d386a8dfee6b864bd85b0bfaa5af81",
        "27196e386b875e76adf700e7ea84e4c6eee33dfa",
        "5b368cff2da2686996bc95eac190eaa4f5630fe5",
        "b79df4a82e90b57ea76525ab7037ab238a42f5d3",
    };

    public static IReadOnlyList<AppIndicator> Parse(string text, string origin)
    {
        ArgumentNullException.ThrowIfNull(text);
        string[] lines = text.Replace("\r\n", "\n", StringComparison.Ordinal).Split('\n');
        if (lines[0].Trim().TrimStart('﻿') != Header)
        {
            throw new FormatException($"{origin}: the first line must be '{Header}'.");
        }

        var entries = new List<AppIndicator>();
        var seen = new Dictionary<(AppIndicatorKind, string), AppIndicator>();
        for (int i = 1; i < lines.Length; i++)
        {
            string line = lines[i].Trim();
            if (line.Length == 0 || line.StartsWith('#'))
            {
                continue;
            }

            string where = $"{origin} line {i + 1}";
            string[] parts = line.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length != 4)
            {
                throw new FormatException($"{where}: expected '<package|cert-sha1|cert-sha256> <value> <detection name> <category>'.");
            }

            AppIndicatorKind kind = parts[0] switch
            {
                "package" => AppIndicatorKind.Package,
                "cert-sha1" => AppIndicatorKind.CertificateSha1,
                "cert-sha256" => AppIndicatorKind.CertificateSha256,
                _ => throw new FormatException($"{where}: unknown indicator kind '{Clip(parts[0])}'."),
            };
            string value = kind == AppIndicatorKind.Package ? parts[1] : parts[1].ToLowerInvariant();
            bool validValue = kind switch
            {
                AppIndicatorKind.Package => IsPackageName(value),
                AppIndicatorKind.CertificateSha1 => IsHex(value, 40),
                _ => IsHex(value, 64),
            };
            if (!validValue)
            {
                throw new FormatException($"{where}: '{Clip(parts[1])}' is not a valid {parts[0]} value.");
            }

            if (kind == AppIndicatorKind.CertificateSha1 && s_publicKeys.Contains(value))
            {
                throw new FormatException($"{where}: {value} is a public AOSP signing key; listing it would flag unrelated apps.");
            }

            string name = parts[2];
            if (name.Length > MaxNameLength || !name.All(c => char.IsAsciiLetterOrDigit(c) || c is '.' or '_' or '-' or '/' or ':'))
            {
                throw new FormatException($"{where}: the detection name must be 1-{MaxNameLength} characters of [A-Za-z0-9._-/:].");
            }

            string category = parts[3].ToLowerInvariant();
            if (category is not ("malware" or "pua" or "suspicious"))
            {
                throw new FormatException($"{where}: the category must be malware, pua or suspicious.");
            }

            var indicator = new AppIndicator(kind, value, name, category);
            if (seen.TryGetValue((kind, value), out AppIndicator? existing))
            {
                if (existing != indicator)
                {
                    throw new FormatException($"{where}: conflicting duplicate for {parts[0]} {value}.");
                }

                continue;
            }

            seen.Add((kind, value), indicator);
            entries.Add(indicator);
            if (entries.Count > MaxEntries)
            {
                throw new FormatException($"{origin}: more than {MaxEntries} indicators.");
            }
        }

        return entries;
    }

    /// <summary>An Android package name: two or more dot-separated identifiers, each starting with a letter.</summary>
    public static bool IsPackageName(string value)
    {
        if (string.IsNullOrEmpty(value) || value.Length > MaxPackageLength)
        {
            return false;
        }

        string[] segments = value.Split('.');
        return segments.Length >= 2 && segments.All(s => s.Length > 0 && char.IsAsciiLetter(s[0]) && s.All(c => char.IsAsciiLetterOrDigit(c) || c == '_'));
    }

    private static bool IsHex(string value, int length) =>
        value.Length == length && value.All(char.IsAsciiHexDigitLower);

    private static string Clip(string text) => text.Length <= 80 ? text : text[..80] + "…";
}
