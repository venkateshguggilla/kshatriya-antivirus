using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using Sentinel.Core;
using Sentinel.Protocol;
using Sentinel.Runtime.Ipc;
using Sentinel.Tests.Shared;
using Sentinel.Updates;

namespace Sentinel.Service.Tests;

public sealed class ContentUpdateTests : IDisposable
{
    private readonly ECDsa _key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    private readonly TempDirectory _files = new();

    public void Dispose()
    {
        _key.Dispose();
        _files.Dispose();
    }

    private ServiceSettings Settings => new() { ContentKeys = [Convert.ToBase64String(_key.ExportSubjectPublicKeyInfo())] };

    private string WritePackage(string name, long sequence, string hashdb, DateTimeOffset? expires = null, ECDsa? signer = null, string? yara = null)
    {
        var files = new List<(string, byte[])> { ("update.hashdb", Encoding.UTF8.GetBytes(hashdb)) };
        if (yara is not null)
        {
            files.Add(("update.yar", Encoding.UTF8.GetBytes(yara)));
        }

        DateTimeOffset now = DateTimeOffset.UtcNow;
        return _files.File(name, ContentPackage.Create("stable", sequence, now.AddMinutes(-5), expires ?? now.AddDays(30), files, signer ?? _key));
    }

    [Fact]
    public async Task An_imported_package_adds_detections_and_shows_in_status()
    {
        await using RunningService service = await RunningService.StartAsync(Settings);
        byte[] sample = TestData.BenignBytes(901, 2048);
        string target = _files.File(@"scan\sample.bin", sample);
        string package = WritePackage("u1.sntu", 1, TestData.HashDb((TestData.Sha256Hex(sample), "Update.Test.Sample", "test")));
        await using ServiceClient client = await service.ConnectAsync();

        Assert.Empty((await client.ScanAsync([target], includeClean: false)).Items);
        ContentImportReplyDto reply = await client.ImportContentAsync(package);
        ScanReport after = await client.ScanAsync([target], includeClean: false);
        StatusReplyDto status = await client.GetStatusAsync();

        Assert.True(reply.Succeeded, reply.Message);
        Assert.Equal(1, reply.Sequence);
        Assert.Equal("Update.Test.Sample", Assert.Single(Assert.Single(after.Items).Detections).Name);
        Assert.Equal(1, status.Content.Sequence);
        Assert.False(status.Content.Expired);
        Assert.Contains(service.Core.Quarantine.Audit.ReadRecent(5), r => r.Action == "contentUpdate" && r.Outcome == "succeeded");
    }

    [Fact]
    public async Task Rollback_untrusted_expired_and_broken_packages_are_refused_and_the_current_content_stays()
    {
        await using RunningService service = await RunningService.StartAsync(Settings);
        await using ServiceClient client = await service.ConnectAsync();
        Assert.True((await client.ImportContentAsync(WritePackage("v2.sntu", 2, "# sentinel-hashdb v1\n"))).Succeeded);

        using ECDsa stranger = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        ContentImportReplyDto older = await client.ImportContentAsync(WritePackage("v1.sntu", 1, "# sentinel-hashdb v1\n"));
        ContentImportReplyDto same = await client.ImportContentAsync(WritePackage("v2b.sntu", 2, "# sentinel-hashdb v1\n"));
        ContentImportReplyDto untrusted = await client.ImportContentAsync(WritePackage("x.sntu", 3, "# sentinel-hashdb v1\n", signer: stranger));
        ContentImportReplyDto expired = await client.ImportContentAsync(WritePackage("e.sntu", 4, "# sentinel-hashdb v1\n", expires: DateTimeOffset.UtcNow.AddMinutes(-1)));
        ContentImportReplyDto broken = await client.ImportContentAsync(WritePackage("b.sntu", 5, "this is not a hash database"));
        ContentImportReplyDto badRule = await client.ImportContentAsync(WritePackage("r.sntu", 6, "# sentinel-hashdb v1\n", yara: "rule broken {"));

        Assert.Equal(ContentErrors.Rollback, older.Code);
        Assert.Equal(ContentErrors.Rollback, same.Code);
        Assert.Equal(ContentErrors.UntrustedKey, untrusted.Code);
        Assert.Equal(ContentErrors.Expired, expired.Code);
        Assert.Equal(ContentErrors.ContentInvalid, broken.Code);
        Assert.Equal(ContentErrors.ContentInvalid, badRule.Code);
        Assert.Equal(2, (await client.GetStatusAsync()).Content.Sequence);

        // The service keeps scanning with the active content.
        Assert.True((await client.ScanAsync([_files.Path], includeClean: false)).IsComplete);
    }

    [Fact]
    public async Task Installed_content_is_reverified_on_start_and_a_tampered_package_is_not_used()
    {
        using var data = new TempDirectory();
        var store = new ContentStore(data.Path, production: false);
        byte[] package = File.ReadAllBytes(WritePackage("s.sntu", 3, "# sentinel-hashdb v1\n"));
        ContentKey key = ContentKey.FromSpki(_key.ExportSubjectPublicKeyInfo());
        store.Stage(3, package);
        store.Activate(3);

        Assert.Equal(3, store.LoadActive([key], DateTimeOffset.UtcNow)!.Manifest.Sequence);
        Assert.True(store.LoadActive([key], DateTimeOffset.UtcNow.AddDays(60))!.Expired);

        package[^2] ^= 1;
        File.WriteAllBytes(Path.Combine(data.Path, "3.sntu"), package);
        var ex = Assert.Throws<ContentVerificationException>(() => store.LoadActive([key], DateTimeOffset.UtcNow));
        Assert.Equal(ContentErrors.HashMismatch, ex.Code);
        Assert.Equal(3, store.HighestSequence);
    }

    [Fact]
    public async Task Content_import_requires_an_administrator_when_enforced()
    {
        await using RunningService service = await RunningService.StartAsync(Settings, requireAdministrator: true);
        await using ServiceClient client = await service.ConnectAsync();
        string package = WritePackage("a.sntu", 1, "# sentinel-hashdb v1\n");

        if (new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator))
        {
            Assert.True((await client.ImportContentAsync(package)).Succeeded);
            return;
        }

        var ex = await Assert.ThrowsAsync<ServiceException>(() => client.ImportContentAsync(package));
        Assert.Equal(ErrorCodes.AccessDenied, ex.Code);
        Assert.Equal(0, (await client.GetStatusAsync()).Content.Sequence);
    }

    [Fact]
    public void Content_keys_in_settings_must_be_p256_public_keys()
    {
        Assert.Throws<FormatException>(() => ServiceSettings.Parse("""{ "schemaVersion": 1, "contentKeys": ["bm90IGEga2V5"] }"""));
        string good = Convert.ToBase64String(_key.ExportSubjectPublicKeyInfo());
        Assert.Single(ServiceSettings.Parse($$"""{ "schemaVersion": 1, "contentKeys": ["{{good}}"] }""").ContentKeys);
    }
}
