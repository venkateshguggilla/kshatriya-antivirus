namespace Kshatriya.Updates;

/// <summary>
/// Lists of dangerous web sites for the browser extension (ADR 0019), delivered as signed content
/// (<c>*.webblock</c>, header <c># kshatriya-webblock v1</c>, then one domain per line; <c>#</c> starts a
/// comment line). A listed domain also covers its subdomains. Domains are ASCII (internationalised names in
/// their <c>xn--</c> form), with at least two labels and a non-numeric last label, so IP addresses, single
/// labels and wildcards are refused. Any invalid line rejects the whole list.
/// </summary>
public static class WebBlockList
{
    public const string Header = "# kshatriya-webblock v1";

    /// <summary>
    /// Most domains across all lists. The extension puts 1,000 domains in each browser rule, so this is
    /// 500 rules, far below the 30,000 dynamic rules a browser guarantees (ADR 0019).
    /// </summary>
    public const int MaxDomains = 500_000;

    /// <summary>Most characters across all domains.</summary>
    public const int MaxTotalChars = 16 * 1024 * 1024;

    /// <summary>Smallest page budget a client may ask for (fits the longest domain).</summary>
    public const int MinPageBytes = 1024;

    /// <summary>
    /// Largest page budget. Pages travel to the browser in one native message, which browsers limit to 1 MB.
    /// </summary>
    public const int MaxPageBytes = 900_000;

    private const int MaxDomainChars = 253;
    private const int MaxLabelChars = 63;

    /// <summary>Parses one list. Throws <see cref="FormatException"/> naming the first invalid line.</summary>
    public static IReadOnlyList<string> Parse(string text, string origin)
    {
        ArgumentNullException.ThrowIfNull(text);
        string[] lines = text.Replace("\r\n", "\n", StringComparison.Ordinal).Split('\n');
        if (lines[0].Trim() != Header)
        {
            throw new FormatException($"{origin}: the first line must be '{Header}'.");
        }

        var domains = new List<string>();
        var seen = new HashSet<string>(StringComparer.Ordinal);
        for (int i = 1; i < lines.Length; i++)
        {
            string line = lines[i].Trim();
            if (line.Length == 0 || line.StartsWith('#'))
            {
                continue;
            }

            string domain = line.ToLowerInvariant();
            if (!IsValidDomain(domain))
            {
                throw new FormatException($"{origin} line {i + 1}: '{Clip(line)}' is not a domain name.");
            }

            if (IsProtected(domain))
            {
                throw new FormatException($"{origin} line {i + 1}: '{domain}' is a shared platform or public suffix (or a parent of one); listing it would block many legitimate sites.");
            }

            if (seen.Add(domain))
            {
                domains.Add(domain);
                if (domains.Count > MaxDomains)
                {
                    throw new FormatException($"{origin}: more than {MaxDomains} domains.");
                }
            }
        }

        return domains;
    }

    /// <summary>Merges lists (duplicates removed, first occurrence kept) and enforces the overall limits.</summary>
    public static IReadOnlyList<string> Combine(IEnumerable<IReadOnlyList<string>> lists)
    {
        ArgumentNullException.ThrowIfNull(lists);
        var all = new List<string>();
        var seen = new HashSet<string>(StringComparer.Ordinal);
        long chars = 0;
        foreach (string domain in lists.SelectMany(l => l))
        {
            if (!seen.Add(domain))
            {
                continue;
            }

            all.Add(domain);
            chars += domain.Length;
            if (all.Count > MaxDomains)
            {
                throw new FormatException($"The web blocklists hold more than {MaxDomains} domains.");
            }

            if (chars > MaxTotalChars)
            {
                throw new FormatException($"The web blocklists hold more than {MaxTotalChars} characters of domains.");
            }
        }

        return all;
    }

    /// <summary>
    /// The domains from <paramref name="offset"/> that fit in <paramref name="maxBytes"/>, counting each as its
    /// length plus 3 (JSON quotes and comma), and the offset of the next page (the count when done). A page
    /// always holds at least one domain while any remain.
    /// </summary>
    public static (IReadOnlyList<string> Page, int Next) Page(IReadOnlyList<string> domains, int offset, int maxBytes)
    {
        ArgumentNullException.ThrowIfNull(domains);
        ArgumentOutOfRangeException.ThrowIfNegative(offset);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(offset, domains.Count);
        var page = new List<string>();
        long used = 0;
        int next = offset;
        while (next < domains.Count)
        {
            int cost = domains[next].Length + 3;
            if (page.Count > 0 && used + cost > maxBytes)
            {
                break;
            }

            page.Add(domains[next]);
            used += cost;
            next++;
        }

        return (page, next);
    }

    /// <summary>A lower-case ASCII host name with at least two labels whose last label is not numeric.</summary>
    public static bool IsValidDomain(string domain)
    {
        if (string.IsNullOrEmpty(domain) || domain.Length > MaxDomainChars)
        {
            return false;
        }

        string[] labels = domain.Split('.');
        if (labels.Length < 2 || labels[^1].All(char.IsAsciiDigit))
        {
            return false;
        }

        foreach (string label in labels)
        {
            if (label.Length is 0 or > MaxLabelChars || label[0] == '-' || label[^1] == '-'
                || !label.All(c => c is (>= 'a' and <= 'z') or (>= '0' and <= '9') or '-'))
            {
                return false;
            }
        }

        return true;
    }

    /// <summary>A valid domain that may be listed: not protected (see <see cref="IsProtected"/>).</summary>
    public static bool IsBlockable(string domain) => IsValidDomain(domain) && !IsProtected(domain);

    /// <summary>
    /// True when blocking <paramref name="domain"/> would block a shared platform or public suffix from
    /// <c>protected-domains.txt</c>: the domain is one of them, or a parent of one.
    /// </summary>
    public static bool IsProtected(string domain)
    {
        ArgumentNullException.ThrowIfNull(domain);
        return s_protected.Value.Any(p => p == domain || p.EndsWith("." + domain, StringComparison.Ordinal));
    }

    private static readonly Lazy<string[]> s_protected = new(() =>
    {
        using Stream stream = typeof(WebBlockList).Assembly.GetManifestResourceStream("Kshatriya.Updates.protected-domains.txt")
            ?? throw new InvalidOperationException("The protected-domains list is missing from the assembly.");
        using var reader = new StreamReader(stream);
        return [.. reader.ReadToEnd().Split('\n').Select(l => l.Trim()).Where(l => l.Length > 0 && !l.StartsWith('#'))];
    });

    private static string Clip(string text) => text.Length <= 80 ? text : text[..80] + "…";
}
