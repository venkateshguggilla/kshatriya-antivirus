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

        WebBlocklistReplyDto before = await client.GetWebBlocklistAsync(0, WebBlockList.MaxPageBytes);
        ContentImportReplyDto good = await client.ImportContentAsync(Package(
            "a.kstu", 1,
            ("phishing.webblock", "# kshatriya-webblock v1\nphish.test\nbad.example\n"),
            ("malware.webblock", "# kshatriya-webblock v1\nbad.example\nmalware.test\n")));
        ContentImportReplyDto bad = await client.ImportContentAsync(Package("b.kstu", 2, ("x.webblock", "# kshatriya-webblock v1\n*.example\n")));
        WebBlocklistReplyDto after = await client.GetWebBlocklistAsync(0, WebBlockList.MaxPageBytes);

        Assert.Equal(0, before.Sequence);
        Assert.Equal(0, before.Total);
        Assert.Empty(before.Domains);
        Assert.True(good.Succeeded, good.Message);
        Assert.Equal(ContentErrors.ContentInvalid, bad.Code);
        Assert.Equal(1, after.Sequence);
        Assert.Equal(3, after.Next);
        Assert.Equal(["phish.test", "bad.example", "malware.test"], after.Domains);
    }

    [Fact]
    public async Task Large_lists_are_served_in_pages_that_fit_a_native_message()
    {
        using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var temp = new TempDirectory();
        var settings = new ServiceSettings { ContentKeys = [Convert.ToBase64String(key.ExportSubjectPublicKeyInfo())] };
        await using RunningService service = await RunningService.StartAsync(settings);
        await using ServiceClient client = await service.ConnectAsync();
        DateTimeOffset now = DateTimeOffset.UtcNow;
        List<string> domains = [.. Enumerable.Range(0, 100_000).Select(i => $"phishing-site-number-{i}.example")];
        string list = "# kshatriya-webblock v1\n" + string.Join('\n', domains) + "\n";
        ContentImportReplyDto imported = await client.ImportContentAsync(temp.File("big.kstu", ContentPackage.Create(
            "stable", 1, now.AddMinutes(-1), now.AddDays(1), [("big.webblock", Encoding.UTF8.GetBytes(list))], key)));
        Assert.True(imported.Succeeded, imported.Message);

        var received = new List<string>();
        int offset = 0, pages = 0;
        while (true)
        {
            WebBlocklistReplyDto page = await client.GetWebBlocklistAsync(offset, WebBlockList.MaxPageBytes);
            Assert.Equal(domains.Count, page.Total);
            Assert.Equal(offset, page.Offset);
            Assert.True(page.Domains.Sum(d => d.Length + 3) <= WebBlockList.MaxPageBytes);
            received.AddRange(page.Domains);
            pages++;
            if (page.Next == page.Total)
            {
                break;
            }

            offset = page.Next;
        }

        Assert.Equal(domains, received);
        Assert.InRange(pages, 4, 5); // about 3.6 MB of domains in pages of at most 0.9 MB

        var error = await Assert.ThrowsAsync<ServiceException>(() => client.GetWebBlocklistAsync(domains.Count + 1, WebBlockList.MaxPageBytes));
        Assert.Equal(ErrorCodes.BadRequest, error.Code);
    }
}
