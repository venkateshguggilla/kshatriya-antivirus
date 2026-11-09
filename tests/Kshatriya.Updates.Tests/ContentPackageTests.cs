using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Kshatriya.Updates;

namespace Kshatriya.Updates.Tests;

public sealed class ContentPackageTests : IDisposable
{
    private static readonly DateTimeOffset s_now = new(2026, 11, 8, 12, 0, 0, TimeSpan.Zero);
    private readonly ECDsa _key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    private readonly ContentKey _trusted;

    public ContentPackageTests() => _trusted = ContentKey.FromSpki(_key.ExportSubjectPublicKeyInfo());

    public void Dispose() => _key.Dispose();

    private byte[] Package(long sequence = 5, DateTimeOffset? expires = null, ECDsa? signer = null) => ContentPackage.Create(
        "stable",
        sequence,
        s_now.AddHours(-1),
        expires ?? s_now.AddDays(30),
        [("extra.hashdb", Encoding.UTF8.GetBytes("# kshatriya-hashdb v1\n")), ("rules.yar", Encoding.UTF8.GetBytes("rule x { condition: false }"))],
        signer ?? _key);

    [Fact]
    public void A_valid_package_verifies_and_exposes_its_files()
    {
        VerifiedContent content = ContentPackage.Verify(Package(), [_trusted], s_now);

        Assert.Equal(5, content.Manifest.Sequence);
        Assert.Equal(_trusted.KeyId, content.KeyId);
        Assert.False(content.Expired);
        Assert.Equal(["extra.hashdb", "rules.yar"], content.Manifest.Files.Select(f => f.Name));
        Assert.Equal("rule x { condition: false }", Encoding.UTF8.GetString(content.Files["rules.yar"]));
    }

    [Fact]
    public void Another_key_is_not_trusted()
    {
        using ECDsa other = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var ex = Assert.Throws<ContentVerificationException>(() => ContentPackage.Verify(Package(signer: other), [_trusted], s_now));
        Assert.Equal(ContentErrors.UntrustedKey, ex.Code);
    }

    [Fact]
    public void Without_trusted_keys_nothing_is_accepted()
    {
        var ex = Assert.Throws<ContentVerificationException>(() => ContentPackage.Verify(Package(), [], s_now));
        Assert.Equal(ContentErrors.NoTrustedKeys, ex.Code);
    }

    [Fact]
    public void A_modified_manifest_fails_the_signature()
    {
        byte[] package = Package();
        int manifestLength = (int)BinaryPrimitives.ReadUInt32LittleEndian(package.AsSpan(8));
        string manifest = Encoding.UTF8.GetString(package, 12, manifestLength);
        byte[] forged = Encoding.UTF8.GetBytes(manifest.Replace("\"sequence\":5", "\"sequence\":9", StringComparison.Ordinal));
        Assert.Equal(manifestLength, forged.Length);
        forged.CopyTo(package, 12);

        var ex = Assert.Throws<ContentVerificationException>(() => ContentPackage.Verify(package, [_trusted], s_now));
        Assert.Equal(ContentErrors.BadSignature, ex.Code);
    }

    [Fact]
    public void Modified_file_bytes_fail_the_hash_check()
    {
        byte[] package = Package();
        package[^3] ^= 0x20;

        var ex = Assert.Throws<ContentVerificationException>(() => ContentPackage.Verify(package, [_trusted], s_now));
        Assert.Equal(ContentErrors.HashMismatch, ex.Code);
    }

    [Theory]
    [InlineData(-1)]
    [InlineData(1)]
    public void Truncated_or_padded_packages_are_malformed(int delta)
    {
        byte[] package = Package();
        byte[] changed = delta < 0 ? package[..^1] : [.. package, 0];

        var ex = Assert.Throws<ContentVerificationException>(() => ContentPackage.Verify(changed, [_trusted], s_now));
        Assert.Equal(ContentErrors.Malformed, ex.Code);
    }

    [Fact]
    public void Expired_packages_are_refused_for_import_but_flagged_when_already_installed()
    {
        byte[] package = Package(expires: s_now.AddMinutes(-1));

        var ex = Assert.Throws<ContentVerificationException>(() => ContentPackage.Verify(package, [_trusted], s_now));
        Assert.Equal(ContentErrors.Expired, ex.Code);
        Assert.True(ContentPackage.Verify(package, [_trusted], s_now, allowExpired: true).Expired);
    }

    [Theory]
    [InlineData("../evil.hashdb")]
    [InlineData("notes.txt")]
    [InlineData(".hidden.yar")]
    public void Unsafe_file_names_cannot_be_packaged(string name)
    {
        Assert.ThrowsAny<Exception>(() => ContentPackage.Create("stable", 1, s_now, s_now.AddDays(1), [(name, [1])], _key));
    }

    [Fact]
    public void Garbage_is_rejected_cleanly()
    {
        var random = new Random(3);
        for (int i = 0; i < 2000; i++)
        {
            byte[] data = new byte[random.Next(0, 200)];
            random.NextBytes(data);
            if (data.Length > 8 && i % 2 == 0)
            {
                "KSTU\u0001\0\0\0"u8.CopyTo(data);
            }

            Assert.Throws<ContentVerificationException>(() => ContentPackage.Verify(data, [_trusted], s_now));
        }
    }

    [Fact]
    public void Key_ids_are_stable_and_short()
    {
        Assert.Equal(16, _trusted.KeyId.Length);
        Assert.Equal(_trusted.KeyId, ContentKey.Parse(Convert.ToBase64String(_key.ExportSubjectPublicKeyInfo())).KeyId);
        using var rsa = RSA.Create(2048);
        Assert.ThrowsAny<CryptographicException>(() => ContentKey.FromSpki(rsa.ExportSubjectPublicKeyInfo()));
    }
}
