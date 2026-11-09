using Kshatriya.Core;
using Kshatriya.Scanning;
using Kshatriya.Tests.Shared;

namespace Kshatriya.Scanning.Tests;

public class SafeFileEnumeratorTests
{
    [Fact]
    public void Finds_files_in_nested_directories()
    {
        using var temp = new TempDirectory();
        temp.File("a.txt", [1]);
        temp.File(@"x\b.txt", [2]);
        temp.File(@"x\y\z\c.txt", [3]);

        var candidates = SafeFileEnumerator.Walk(temp.Path).Where(e => e.IsCandidate).Select(e => Path.GetFileName(e.Path)).Order().ToArray();

        Assert.Equal(["a.txt", "b.txt", "c.txt"], candidates);
    }

    [Fact]
    public void Junction_inside_tree_is_reported_and_not_followed_even_when_it_points_to_an_ancestor()
    {
        using var temp = new TempDirectory();
        temp.File(@"sub\only-once.txt", [1]);
        string link = Path.Combine(temp.Path, "sub", "loop");
        Assert.True(TempDirectory.TryCreateJunction(link, temp.Path), "Could not create a directory junction.");

        WalkEntry[] entries = SafeFileEnumerator.Walk(temp.Path).ToArray();

        Assert.Single(entries, e => e.IsCandidate && e.Path.EndsWith("only-once.txt", StringComparison.Ordinal));
        WalkEntry skipped = Assert.Single(entries, e => !e.IsCandidate);
        Assert.Equal(link, skipped.Path);
        Assert.Equal(ScanStatus.Skipped, skipped.Result!.Status);
        Assert.Equal(ScanReason.ReparsePoint, skipped.Result.Reason);
        Assert.Equal(ScanItemKind.Directory, skipped.Result.Kind);
    }

    [Fact]
    public void Junction_given_explicitly_as_target_is_resolved_once()
    {
        using var temp = new TempDirectory();
        temp.File(@"real\inside.txt", [1]);
        string link = Path.Combine(temp.Path, "link");
        Assert.True(TempDirectory.TryCreateJunction(link, Path.Combine(temp.Path, "real")));

        WalkEntry entry = Assert.Single(SafeFileEnumerator.Walk(link));

        Assert.True(entry.IsCandidate);
        Assert.Equal(Path.Combine(temp.Path, "real", "inside.txt"), entry.Path);
    }

    [Fact]
    public void File_symbolic_link_is_skipped_when_links_can_be_created()
    {
        using var temp = new TempDirectory();
        string target = temp.File("target.txt", [1, 2, 3]);
        string link = Path.Combine(temp.Path, "link.txt");
        try
        {
            File.CreateSymbolicLink(link, target);
        }
        catch (IOException)
        {
            return; // Creating symlinks needs Developer Mode or admin rights; junction tests cover link handling.
        }
        catch (UnauthorizedAccessException)
        {
            return;
        }

        WalkEntry[] entries = SafeFileEnumerator.Walk(temp.Path).ToArray();

        Assert.Single(entries, e => e.IsCandidate);
        WalkEntry skipped = Assert.Single(entries, e => !e.IsCandidate);
        Assert.Equal(link, skipped.Path);
        Assert.Equal(ScanReason.ReparsePoint, skipped.Result!.Reason);
    }

    [Fact]
    public void Offline_file_is_skipped_as_cloud_placeholder_without_being_opened()
    {
        using var temp = new TempDirectory();
        string offline = temp.File("offline.bin", TestData.BenignBytes(7, 32));
        File.SetAttributes(offline, FileAttributes.Offline);

        WalkEntry entry = Assert.Single(SafeFileEnumerator.Walk(temp.Path));

        Assert.False(entry.IsCandidate);
        Assert.Equal(ScanStatus.Skipped, entry.Result!.Status);
        Assert.Equal(ScanReason.CloudPlaceholder, entry.Result.Reason);
    }

    [Fact]
    public void Paths_longer_than_max_path_are_enumerated()
    {
        using var temp = new TempDirectory();
        string deep = temp.Path;
        while (deep.Length < 400)
        {
            deep = Path.Combine(deep, new string('d', 50));
        }

        Directory.CreateDirectory(deep);
        string file = Path.Combine(deep, "deep-file.txt");
        File.WriteAllBytes(file, [9]);
        Assert.True(file.Length > 260);

        WalkEntry entry = Assert.Single(SafeFileEnumerator.Walk(temp.Path));

        Assert.True(entry.IsCandidate);
        Assert.Equal(file, entry.Path);
    }

    [Fact]
    public void Access_denied_directory_is_reported_and_walk_continues()
    {
        using var temp = new TempDirectory();
        temp.File("visible.txt", [1]);
        string locked = temp.Dir("locked");
        temp.File(@"locked\hidden.txt", [2]);
        temp.File(@"after\later.txt", [3]);

        var dir = new DirectoryInfo(locked);
        var deny = new System.Security.AccessControl.FileSystemAccessRule(
            System.Security.Principal.WindowsIdentity.GetCurrent().User!,
            System.Security.AccessControl.FileSystemRights.ListDirectory | System.Security.AccessControl.FileSystemRights.ReadData,
            System.Security.AccessControl.AccessControlType.Deny);
        var acl = dir.GetAccessControl();
        acl.AddAccessRule(deny);
        dir.SetAccessControl(acl);
        try
        {
            WalkEntry[] entries = SafeFileEnumerator.Walk(temp.Path).ToArray();

            WalkEntry failure = Assert.Single(entries, e => !e.IsCandidate);
            Assert.Equal(locked, failure.Path);
            Assert.Equal(ScanStatus.NotScanned, failure.Result!.Status);
            Assert.Equal(ScanReason.AccessDenied, failure.Result.Reason);
            Assert.Equal(["later.txt", "visible.txt"], entries.Where(e => e.IsCandidate).Select(e => Path.GetFileName(e.Path)).Order());
        }
        finally
        {
            acl.RemoveAccessRule(deny);
            dir.SetAccessControl(acl);
        }
    }

    [Fact]
    public void Missing_target_is_reported_not_found()
    {
        using var temp = new TempDirectory();
        string missing = Path.Combine(temp.Path, "does-not-exist");

        WalkEntry entry = Assert.Single(SafeFileEnumerator.Walk(missing));

        Assert.Equal(ScanStatus.NotScanned, entry.Result!.Status);
        Assert.Equal(ScanReason.NotFound, entry.Result.Reason);
    }

    [Fact]
    public void Single_file_target_is_returned_as_candidate()
    {
        using var temp = new TempDirectory();
        string file = temp.File("one.txt", [1, 2]);

        WalkEntry entry = Assert.Single(SafeFileEnumerator.Walk(file));

        Assert.True(entry.IsCandidate);
        Assert.Equal(2, entry.Length);
    }
}
