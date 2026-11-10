using System.Security.Cryptography;
using System.Text;
using Kshatriya.Protocol;
using Kshatriya.Runtime.Ipc;
using Kshatriya.Tests.Shared;
using Kshatriya.Updates;

namespace Kshatriya.Service.Tests;

public class WebBlocklistTests
{
    [Fact]
    public async Task Imported_web_blocklists_are_served_to_any_client_and_bad_ones_are_refused()
    {
        using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var temp = new TempDirectory();
        var settings = new ServiceSettings { ContentKeys = [Convert.ToBase64String(key.ExportSubjectPublicKeyInfo())] };
        await using RunningService service = await RunningService.StartAsync(settings);
        await using ServiceClient client = await service.ConnectAsync();
        DateTimeOffset now = DateTimeOffset.UtcNow;
        string Package(string name, long sequence, params (string Name, string Text)[] files) => temp.File(name, ContentPackage.Create(
            "stable", sequence, now.AddMinutes(-1), now.AddDays(1), [.. files.Select(f => (f.Name, Encoding.UTF8.GetBytes(f.Text)))], key));

        WebBlocklistReplyDto before = await client.GetWebBlocklistAsync();
        ContentImportReplyDto good = await client.ImportContentAsync(Package(
            "a.kstu", 1,
            ("phishing.webblock", "# kshatriya-webblock v1\nphish.test\nbad.example\n"),
            ("malware.webblock", "# kshatriya-webblock v1\nbad.example\nmalware.test\n")));
        ContentImportReplyDto bad = await client.ImportContentAsync(Package("b.kstu", 2, ("x.webblock", "# kshatriya-webblock v1\n*.example\n")));
        WebBlocklistReplyDto after = await client.GetWebBlocklistAsync();

        Assert.Equal(0, before.Sequence);
        Assert.Empty(before.Domains);
        Assert.True(good.Succeeded, good.Message);
        Assert.Equal(ContentErrors.ContentInvalid, bad.Code);
        Assert.Equal(1, after.Sequence);
        Assert.Equal(["phish.test", "bad.example", "malware.test"], after.Domains);
    }
}
