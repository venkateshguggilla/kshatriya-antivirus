using Kshatriya.Core;
using Kshatriya.Updates;

namespace Kshatriya.Mobile;

/// <summary>An installed app's identity as Android reports it: package name and signing certificate digests.</summary>
/// <param name="PackageName">The app's package name (application id).</param>
/// <param name="CertificateSha1">Lower-case hex SHA-1 of each signing certificate (DER).</param>
/// <param name="CertificateSha256">Lower-case hex SHA-256 of each signing certificate (DER).</param>
public sealed record AppIdentity(string PackageName, IReadOnlyList<string> CertificateSha1, IReadOnlyList<string> CertificateSha256);

/// <summary>
/// Matches app identities against app indicator lists (ADR 0020). Certificate matches keep the list's
/// category at high confidence; package-name matches alone are reported as suspicious.
/// </summary>
public sealed class AppIndicatorSet
{
    public const string EngineId = "app-indicators";

    private readonly Dictionary<string, AppIndicator> _packages = new(StringComparer.Ordinal);
    private readonly Dictionary<string, AppIndicator> _certificates = new(StringComparer.Ordinal);

    public AppIndicatorSet(IEnumerable<AppIndicator> indicators)
    {
        ArgumentNullException.ThrowIfNull(indicators);
        foreach (AppIndicator indicator in indicators)
        {
            Dictionary<string, AppIndicator> map = indicator.Kind == AppIndicatorKind.Package ? _packages : _certificates;
            map.TryAdd(indicator.Value, indicator);
        }
    }

    public static AppIndicatorSet Empty { get; } = new([]);

    public int Count => _packages.Count + _certificates.Count;

    public IReadOnlyList<Detection> Match(AppIdentity app)
    {
        ArgumentNullException.ThrowIfNull(app);
        foreach (string digest in app.CertificateSha256.Concat(app.CertificateSha1))
        {
            if (_certificates.TryGetValue(digest.ToLowerInvariant(), out AppIndicator? byCertificate))
            {
                return [new Detection(EngineId, byCertificate.Name, Category(byCertificate.Category), DetectionConfidence.High,
                    "The app is signed with a certificate listed for this app.")];
            }
        }

        return _packages.TryGetValue(app.PackageName, out AppIndicator? byPackage)
            ? [new Detection(EngineId, byPackage.Name, DetectionCategory.Suspicious, DetectionConfidence.Medium,
                "The app's package name is listed for this app, but its signing certificate is not; it may be a copy or an unrelated app with the same name.")]
            : [];
    }

    private static DetectionCategory Category(string value) => value switch
    {
        "malware" => DetectionCategory.Malware,
        "pua" => DetectionCategory.PotentiallyUnwanted,
        _ => DetectionCategory.Suspicious,
    };
}
