using Kshatriya.Updates;

namespace Kshatriya.Updates.Tests;

public class AppBlockListTests
{
    private const string Cert = "31a6ececd97cf39bc4126b8745cd94a7c30bf81c";

    [Fact]
    public void Lists_parse_packages_and_certificates_ignoring_comments_and_case_of_digests()
    {
        IReadOnlyList<AppIndicator> list = AppBlockList.Parse(
            "# kshatriya-appblock v1\r\n# source: test\npackage com.thetruth Android.Stalkerware.TheTruthSpy pua\n"
            + "cert-sha1 31A6ECECD97CF39BC4126B8745CD94A7C30BF81C Android.Stalkerware.TheTruthSpy PUA\n"
            + "cert-sha256 " + new string('a', 64) + " Android.Test.X malware\n"
            + "package com.thetruth Android.Stalkerware.TheTruthSpy pua\n",
            "test");

        Assert.Equal(
            [
                new AppIndicator(AppIndicatorKind.Package, "com.thetruth", "Android.Stalkerware.TheTruthSpy", "pua"),
                new AppIndicator(AppIndicatorKind.CertificateSha1, Cert, "Android.Stalkerware.TheTruthSpy", "pua"),
                new AppIndicator(AppIndicatorKind.CertificateSha256, new string('a', 64), "Android.Test.X", "malware"),
            ],
            list);
    }

    [Theory]
    [InlineData("package com Android.X pua")]                       // single segment
    [InlineData("package com.1bad Android.X pua")]                  // segment starting with a digit
    [InlineData("package com..x Android.X pua")]
    [InlineData("package com.x-y Android.X pua")]
    [InlineData("cert-sha1 31a6 Android.X pua")]                      // too short
    [InlineData("cert-sha256 31a6ececd97cf39bc4126b8745cd94a7c30bf81c Android.X pua")] // SHA-1 length
    [InlineData("cert-md5 00 Android.X pua")]
    [InlineData("package com.x Android.X")]                          // missing category
    [InlineData("package com.x Android.X test")]                     // test is not an app category
    [InlineData("package com.x Android X pua")]                      // name with a space
    [InlineData("cert-sha1 61ed377e85d386a8dfee6b864bd85b0bfaa5af81 Android.X pua")] // AOSP testkey
    public void Anything_invalid_rejects_the_whole_list(string line)
    {
        var error = Assert.Throws<FormatException>(() => AppBlockList.Parse($"# kshatriya-appblock v1\npackage com.ok Android.Ok pua\n{line}\n", "test"));
        Assert.Contains("line 3", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Conflicting_duplicates_and_a_missing_header_are_refused()
    {
        Assert.Throws<FormatException>(() => AppBlockList.Parse("# kshatriya-appblock v1\npackage com.x A pua\npackage com.x B pua\n", "test"));
        Assert.Throws<FormatException>(() => AppBlockList.Parse("package com.x A pua\n", "test"));
    }

    [Fact]
    public void App_lists_travel_in_signed_packages()
    {
        Assert.Equal("appblock", ContentPackage.KindOf("stalkerware.appblock"));
    }
}
