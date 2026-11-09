using Kshatriya.Core;

namespace Kshatriya.Engines.Hash;

/// <summary>
/// Signatures compiled into the product. Only harmless industry test files belong here;
/// real threat content is delivered as (later: signed) database files.
/// </summary>
public static class BuiltInSignatures
{
    /// <summary>SHA-256 of the standard 68-byte EICAR anti-malware test file.</summary>
    public const string EicarSha256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";

    public const string EicarName = "Kshatriya.Test.EICAR";

    public static HashSignatureDatabase Database { get; } = HashSignatureDatabase.FromSignatures(
    [
        new HashSignature(EicarSha256, EicarName, DetectionCategory.TestFile),
    ]);
}
