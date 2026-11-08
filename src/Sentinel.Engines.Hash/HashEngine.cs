using Sentinel.Core;

namespace Sentinel.Engines.Hash;

/// <summary>Exact-match SHA-256 signature engine.</summary>
public sealed class HashEngine : IDetectionEngine
{
    public const string EngineId = "hash";
    public const string EngineVersion = "1.0.0";

    private readonly HashSignatureDatabase _database;

    public HashEngine(HashSignatureDatabase database)
    {
        ArgumentNullException.ThrowIfNull(database);
        _database = database;
        Descriptor = new EngineDescriptor(EngineId, EngineVersion, database.ContentVersion);
    }

    /// <summary>Creates an engine with the built-in test signatures plus any additional databases.</summary>
    public static HashEngine CreateDefault(params IEnumerable<HashSignatureDatabase> additional) =>
        new(HashSignatureDatabase.Merge([BuiltInSignatures.Database, .. additional]));

    public EngineDescriptor Descriptor { get; }

    public int SignatureCount => _database.Count;

    public ValueTask<IReadOnlyList<Detection>> ScanAsync(ScanSubject subject, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(subject);
        cancellationToken.ThrowIfCancellationRequested();

        HashSignature? match = _database.Find(subject.Sha256);
        IReadOnlyList<Detection> result = match is null
            ? []
            : [new Detection(EngineId, match.Name, match.Category, DetectionConfidence.High, "Exact SHA-256 match against a known signature.")];
        return ValueTask.FromResult(result);
    }
}
