using Kshatriya.Updates;

namespace Kshatriya.Updates.Tests;

public class WebBlockListTests
{
    [Fact]
    public void Lists_parse_domains_ignoring_comments_case_and_duplicates()
    {
        IReadOnlyList<string> domains = WebBlockList.Parse("# kshatriya-webblock v1\r\n# phishing\nBad.Example\n\n  phish.test  \nbad.example\nxn--pypal-4ve.com\n", "test");

        Assert.Equal(["bad.example", "phish.test", "xn--pypal-4ve.com"], domains);
    }

    [Theory]
    [InlineData("*.bad.example")]
    [InlineData("localhost")]
    [InlineData("203.0.113.7")]
    [InlineData("[2001:db8::1]")]
    [InlineData("http://bad.example/")]
    [InlineData("bad.example/path")]
    [InlineData("-bad.example")]
    [InlineData("bad-.example")]
    [InlineData("bad..example")]
    [InlineData("bad.example.")]
    [InlineData("bad example.com")]
    [InlineData("bаd.example")] // Cyrillic 'а': must be listed in its xn-- form
    public void Anything_but_a_domain_rejects_the_whole_list(string entry)
    {
        var error = Assert.Throws<FormatException>(() => WebBlockList.Parse($"# kshatriya-webblock v1\nok.example\n{entry}\n", "test"));
        Assert.Contains("line 3", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void The_header_is_required()
    {
        Assert.Throws<FormatException>(() => WebBlockList.Parse("bad.example\n", "test"));
        Assert.Throws<FormatException>(() => WebBlockList.Parse("", "test"));
    }

    [Fact]
    public void Overlong_labels_and_names_are_refused()
    {
        Assert.True(WebBlockList.IsValidDomain(new string('a', 63) + ".com"));
        Assert.False(WebBlockList.IsValidDomain(new string('a', 64) + ".com"));
        string longest = string.Join('.', Enumerable.Repeat(new string('a', 49), 5)) + ".com"; // 253 characters
        Assert.Equal(253, longest.Length);
        Assert.True(WebBlockList.IsValidDomain(longest));
        Assert.False(WebBlockList.IsValidDomain("a" + longest));
    }

    [Fact]
    public void Combined_lists_are_deduplicated_and_limited()
    {
        Assert.Equal(["a.example", "b.example", "c.example"], WebBlockList.Combine([["a.example", "b.example"], ["b.example", "c.example"]]));

        List<string> many = [.. Enumerable.Range(0, WebBlockList.MaxDomains + 1).Select(i => $"d{i}.example")];
        Assert.Throws<FormatException>(() => WebBlockList.Combine([many]));

        List<string> long_ = [.. Enumerable.Range(0, 4000).Select(i => $"{i:D5}{new string('a', 240)}.com")];
        Assert.Throws<FormatException>(() => WebBlockList.Combine([long_]));
    }

    [Fact]
    public void A_single_list_over_the_domain_limit_is_refused()
    {
        string text = "# kshatriya-webblock v1\n" + string.Join('\n', Enumerable.Range(0, WebBlockList.MaxDomains + 1).Select(i => $"d{i}.example"));
        Assert.Throws<FormatException>(() => WebBlockList.Parse(text, "test"));
    }

    [Fact]
    public void Web_blocklists_travel_in_signed_packages()
    {
        Assert.Equal("webblock", ContentPackage.KindOf("phishing.webblock"));
    }
}
