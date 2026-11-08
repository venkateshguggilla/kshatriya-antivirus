using System.Security.AccessControl;
using System.Security.Principal;
using Sentinel.Response;
using Sentinel.Tests.Shared;

namespace Sentinel.Response.Tests;

public class VaultTests
{
    private static readonly QuarantineDraft s_draft = new(@"C:\nowhere\sample.bin", new Actor("S-1-5-18", "tests"), ["Test.Sample"], "manual");

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(QuarantineVault.ChunkSize)]
    [InlineData((QuarantineVault.ChunkSize * 2) + 12345)]
    public void Store_and_extract_round_trip(int size)
    {
        using var temp = new TempDirectory();
        QuarantineVault vault = QuarantineVault.Open(temp.Dir("vault"), StorageAccess.CurrentUser);
        byte[] content = TestData.BenignBytes(size, size);

        QuarantineEntry entry = vault.Store(new MemoryStream(content), s_draft, TestData.Sha256Hex(content));
        using var output = new MemoryStream();
        vault.ExtractTo(entry, output);

        Assert.Equal(content, output.ToArray());
        Assert.Equal(size, entry.SizeBytes);
        Assert.Equal(TestData.Sha256Hex(content), entry.Sha256);
        Assert.Equal(entry, Assert.Single(vault.List()) with { Detections = entry.Detections, QuarantinedUtc = entry.QuarantinedUtc });
    }

    [Fact]
    public void Stored_content_is_encrypted_at_rest()
    {
        using var temp = new TempDirectory();
        QuarantineVault vault = QuarantineVault.Open(temp.Dir("vault"), StorageAccess.CurrentUser);
        byte[] content = new byte[4096];
        Array.Fill(content, (byte)'A');

        QuarantineEntry entry = vault.Store(new MemoryStream(content), s_draft, null);
        byte[] blob = File.ReadAllBytes(Path.Combine(vault.Directory, entry.Id + ".bin"));

        Assert.Equal(-1, blob.AsSpan().IndexOf(content.AsSpan(0, 32)));
    }

    [Fact]
    public void A_mismatching_hash_keeps_nothing()
    {
        using var temp = new TempDirectory();
        QuarantineVault vault = QuarantineVault.Open(temp.Dir("vault"), StorageAccess.CurrentUser);

        Assert.Throws<VaultContentMismatchException>(() => vault.Store(new MemoryStream([1, 2, 3]), s_draft, new string('0', 64)));

        Assert.Empty(vault.List());
        Assert.Equal(["vault.key"], Directory.GetFiles(vault.Directory).Select(Path.GetFileName));
    }

    [Theory]
    [InlineData("flip")]
    [InlineData("truncate")]
    [InlineData("append")]
    [InlineData("swap")]
    public void Tampering_is_detected(string kind)
    {
        using var temp = new TempDirectory();
        QuarantineVault vault = QuarantineVault.Open(temp.Dir("vault"), StorageAccess.CurrentUser);
        byte[] content = TestData.BenignBytes(5, QuarantineVault.ChunkSize + 100);
        QuarantineEntry entry = vault.Store(new MemoryStream(content), s_draft, null);
        QuarantineEntry other = vault.Store(new MemoryStream(TestData.BenignBytes(6, 50)), s_draft, null);
        string blob = Path.Combine(vault.Directory, entry.Id + ".bin");
        byte[] bytes = File.ReadAllBytes(blob);
        switch (kind)
        {
            case "flip":
                bytes[bytes.Length / 2] ^= 0x01;
                File.WriteAllBytes(blob, bytes);
                break;
            case "truncate":
                File.WriteAllBytes(blob, bytes[..^20]);
                break;
            case "append":
                File.WriteAllBytes(blob, [.. bytes, 0]);
                break;
            case "swap":
                File.Copy(Path.Combine(vault.Directory, other.Id + ".bin"), blob, overwrite: true);
                break;
        }

        Assert.Throws<VaultIntegrityException>(() => vault.ExtractTo(entry, new MemoryStream()));
    }

    [Theory]
    [InlineData("..\\..\\x")]
    [InlineData("vault")]
    [InlineData("ABCDEF0123456789ABCDEF0123456789")]
    [InlineData("")]
    public void Ids_that_are_not_vault_ids_are_rejected(string id)
    {
        using var temp = new TempDirectory();
        QuarantineVault vault = QuarantineVault.Open(temp.Dir("vault"), StorageAccess.CurrentUser);

        Assert.False(QuarantineVault.IsValidId(id));
        Assert.Null(vault.Get(id));
        Assert.False(vault.Delete(id));
    }

    [Fact]
    public void Vault_key_is_protected_and_reused()
    {
        using var temp = new TempDirectory();
        string dir = temp.Dir("vault");
        QuarantineVault first = QuarantineVault.Open(dir, StorageAccess.CurrentUser);
        QuarantineEntry entry = first.Store(new MemoryStream([9, 8, 7]), s_draft, null);
        byte[] keyFile = File.ReadAllBytes(Path.Combine(dir, "vault.key"));

        QuarantineVault second = QuarantineVault.Open(dir, StorageAccess.CurrentUser);
        using var output = new MemoryStream();
        second.ExtractTo(entry, output);

        Assert.Equal([9, 8, 7], output.ToArray());
        Assert.True(keyFile.Length > 64, "The key file holds a DPAPI blob, not the raw 32-byte key.");
    }

    [Fact]
    public void Vault_directory_is_private_to_its_owner()
    {
        using var temp = new TempDirectory();
        QuarantineVault vault = QuarantineVault.Open(temp.Dir("vault"), StorageAccess.CurrentUser);

        DirectorySecurity security = new DirectoryInfo(vault.Directory).GetAccessControl();
        var me = WindowsIdentity.GetCurrent().User!;
        var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        Assert.True(security.AreAccessRulesProtected);
        var sids = security.GetAccessRules(true, true, typeof(SecurityIdentifier)).Cast<FileSystemAccessRule>().Select(r => (SecurityIdentifier)r.IdentityReference).ToHashSet();
        Assert.Equal(new HashSet<SecurityIdentifier> { me, system }, sids);
    }
}
