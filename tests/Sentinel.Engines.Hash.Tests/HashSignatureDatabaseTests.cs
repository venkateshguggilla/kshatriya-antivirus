using Sentinel.Core;
using Sentinel.Engines.Hash;
using Sentinel.Tests.Shared;

namespace Sentinel.Engines.Hash.Tests;

public class HashSignatureDatabaseTests
{
    private static readonly string s_hashA = new('a', 64);
    private static readonly string s_hashB = new('b', 64);

    [Fact]
    public void Builtin_eicar_hash_matches_the_standard_test_string()
    {
        byte[] eicar = TestData.EicarBytes();
        Assert.Equal(68, eicar.Length);
        Assert.Equal(BuiltInSignatures.EicarSha256, TestData.Sha256Hex(eicar));
    }

    [Fact]
    public void Parse_reads_entries_comments_and_categories()
    {
        string text = $"""
            # sentinel-hashdb v1
            # a comment

            sha256:{s_hashA} Family.One malware
            SHA256:{s_hashB.ToUpperInvariant()} Test.Two test
            """;

        HashSignatureDatabase db = HashSignatureDatabase.Parse(text);

        Assert.Equal(2, db.Count);
        Assert.Equal(new HashSignature(s_hashA, "Family.One", DetectionCategory.Malware), db.Find(s_hashA));
        Assert.Equal(DetectionCategory.TestFile, db.Find(s_hashB)!.Category);
        Assert.NotNull(db.Find(s_hashB.ToUpperInvariant()));
    }

    [Fact]
    public void Category_defaults_to_malware()
    {
        HashSignatureDatabase db = HashSignatureDatabase.Parse($"# sentinel-hashdb v1\nsha256:{s_hashA} X\n");
        Assert.Equal(DetectionCategory.Malware, db.Find(s_hashA)!.Category);
    }

    [Theory]
    [InlineData("sha256:aaaa X")]                                  // short digest
    [InlineData("md5:00000000000000000000000000000000 X")]          // unsupported algorithm
    [InlineData("sha256:gggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg X")] // not hex
    [InlineData("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")]   // no name
    [InlineData("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa Bad|Name")]
    [InlineData("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa X nope")]
    [InlineData("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa X malware extra")]
    public void Malformed_lines_reject_the_whole_database(string line)
    {
        string text = $"# sentinel-hashdb v1\nsha256:{s_hashB} Good\n{line}\n";
        FormatException ex = Assert.Throws<FormatException>(() => HashSignatureDatabase.Parse(text, "db.txt"));
        Assert.Contains("db.txt(3)", ex.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("")]
    [InlineData("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa X\n")]
    [InlineData("# sentinel-hashdb v2\n")]
    public void Missing_or_wrong_header_is_rejected(string text)
    {
        Assert.Throws<FormatException>(() => HashSignatureDatabase.Parse(text));
    }

    [Fact]
    public void Identical_duplicates_are_allowed_but_conflicts_are_rejected()
    {
        HashSignatureDatabase ok = HashSignatureDatabase.Parse($"# sentinel-hashdb v1\nsha256:{s_hashA} X\nsha256:{s_hashA} X\n");
        Assert.Equal(1, ok.Count);

        Assert.Throws<FormatException>(() =>
            HashSignatureDatabase.Parse($"# sentinel-hashdb v1\nsha256:{s_hashA} X\nsha256:{s_hashA} Y\n"));
    }

    [Fact]
    public void Content_version_is_independent_of_line_order()
    {
        var one = HashSignatureDatabase.Parse($"# sentinel-hashdb v1\nsha256:{s_hashA} X\nsha256:{s_hashB} Y\n");
        var two = HashSignatureDatabase.Parse($"# sentinel-hashdb v1\nsha256:{s_hashB} Y\nsha256:{s_hashA} X\n");
        var three = HashSignatureDatabase.Parse($"# sentinel-hashdb v1\nsha256:{s_hashB} Z\nsha256:{s_hashA} X\n");

        Assert.Equal(one.ContentVersion, two.ContentVersion);
        Assert.NotEqual(one.ContentVersion, three.ContentVersion);
        Assert.StartsWith("2-", one.ContentVersion, StringComparison.Ordinal);
    }

    [Fact]
    public void Merge_rejects_conflicting_names_for_the_same_hash()
    {
        var a = HashSignatureDatabase.Parse($"# sentinel-hashdb v1\nsha256:{s_hashA} X\n");
        var b = HashSignatureDatabase.Parse($"# sentinel-hashdb v1\nsha256:{s_hashA} Y\n");
        Assert.Throws<FormatException>(() => HashSignatureDatabase.Merge(a, b));
        Assert.Equal(1, HashSignatureDatabase.Merge(a, a).Count);
    }
}
