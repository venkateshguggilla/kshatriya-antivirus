using Kshatriya.App.Services;

namespace Kshatriya.App.Tests;

public sealed class BrowserExtensionCopyTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "kshatriya-ext-" + Guid.NewGuid().ToString("N"));

    private string Source => Path.Combine(_root, "installed");

    private string Target => Path.Combine(_root, "user");

    public BrowserExtensionCopyTests()
    {
        Directory.CreateDirectory(Path.Combine(Source, "rules"));
        File.WriteAllText(Path.Combine(Source, "manifest.json"), "{\"version\":\"1\"}");
        File.WriteAllText(Path.Combine(Source, "rules", "blocklist.json"), "[]");
    }

    public void Dispose() => Directory.Delete(_root, recursive: true);

    [Fact]
    public void The_first_sync_copies_every_file()
    {
        Assert.True(BrowserExtensionCopy.Sync(Source, Target));

        Assert.Equal("{\"version\":\"1\"}", File.ReadAllText(Path.Combine(Target, "manifest.json")));
        Assert.Equal("[]", File.ReadAllText(Path.Combine(Target, "rules", "blocklist.json")));
    }

    [Fact]
    public void A_newer_install_replaces_changed_and_removed_files_but_keeps_the_browsers_metadata()
    {
        BrowserExtensionCopy.Sync(Source, Target);
        Directory.CreateDirectory(Path.Combine(Target, "_metadata"));
        File.WriteAllText(Path.Combine(Target, "_metadata", "index"), "browser");
        File.WriteAllText(Path.Combine(Target, "old.js"), "stale");

        File.WriteAllText(Path.Combine(Source, "manifest.json"), "{\"version\":\"2\"}");
        BrowserExtensionCopy.Sync(Source, Target);

        Assert.Equal("{\"version\":\"2\"}", File.ReadAllText(Path.Combine(Target, "manifest.json")));
        Assert.False(File.Exists(Path.Combine(Target, "old.js")));
        Assert.Equal("browser", File.ReadAllText(Path.Combine(Target, "_metadata", "index")));
    }

    [Fact]
    public void An_edited_copy_is_restored_from_the_install()
    {
        BrowserExtensionCopy.Sync(Source, Target);
        File.WriteAllText(Path.Combine(Target, "manifest.json"), "{\"tampered\":1}");

        BrowserExtensionCopy.Sync(Source, Target);

        Assert.Equal("{\"version\":\"1\"}", File.ReadAllText(Path.Combine(Target, "manifest.json")));
    }

    [Fact]
    public void Nothing_is_copied_without_an_installed_extension()
    {
        Assert.False(BrowserExtensionCopy.Sync(Path.Combine(_root, "missing"), Target));
        Assert.False(Directory.Exists(Target));
    }
}
