using System.Security.AccessControl;
using System.Security.Principal;
using Kshatriya.Service;
using Kshatriya.Tests.Shared;

namespace Kshatriya.Service.Tests;

public class SettingsAndPolicyTests
{
    [Fact]
    public void Full_settings_file_is_parsed()
    {
        ServiceSettings s = ServiceSettings.Parse("""
            {
              // comments are allowed
              "schemaVersion": 1,
              "workers": 3,
              "signatureFiles": ["C:\\Kshatriya\\extra.hashdb"],
              "ruleFiles": [],
              "heuristics": true,
              "heuristicsIncludeSigned": false,
              "maxFileSizeMiB": 128,
              "reportRetention": 10,
              "maxConcurrentScans": 1,
              "scheduledScans": [
                { "name": "weekly-quick", "days": ["sunday", "Wednesday"], "time": "03:30", "paths": ["C:\\Users"] }
              ]
            }
            """);

        Assert.Equal(3, s.Workers);
        Assert.Equal(128L * 1024 * 1024, s.MaxFileSizeBytes);
        Assert.Equal(1, s.MaxConcurrentScans);
        ScheduledScan scan = Assert.Single(s.ScheduledScans);
        Assert.Equal(new TimeOnly(3, 30), scan.Time);
        Assert.Equal(new HashSet<DayOfWeek> { DayOfWeek.Sunday, DayOfWeek.Wednesday }, scan.Days);
    }

    [Fact]
    public void Minimal_settings_use_defaults()
    {
        ServiceSettings s = ServiceSettings.Parse("""{ "schemaVersion": 1 }""");

        Assert.Equal(new ServiceSettings().Workers, s.Workers);
        Assert.Empty(s.ScheduledScans);
    }

    [Theory]
    [InlineData("""{ "schemaVersion": 2 }""", "schemaVersion")]
    [InlineData("""{ "schemaVersion": 1, "unknown": true }""", "not valid")]
    [InlineData("""{ "schemaVersion": 1, "workers": 0 }""", "workers")]
    [InlineData("""{ "schemaVersion": 1, "maxFileSizeMiB": 65537 }""", "maxFileSizeMiB")]
    [InlineData("""{ "schemaVersion": 1, "signatureFiles": ["\\\\server\\share\\x.hashdb"] }""", "local path")]
    [InlineData("""{ "schemaVersion": 1, "scheduledScans": [{ "name": "a", "days": ["funday"], "time": "03:00", "paths": ["C:\\"] }] }""", "unknown day")]
    [InlineData("""{ "schemaVersion": 1, "scheduledScans": [{ "name": "a", "days": ["daily"], "time": "3pm", "paths": ["C:\\"] }] }""", "HH:mm")]
    [InlineData("""{ "schemaVersion": 1, "scheduledScans": [{ "name": "a", "days": ["daily"], "time": "03:00", "paths": ["relative\\dir"] }] }""", "local path")]
    [InlineData("""{ "schemaVersion": 1, "scheduledScans": [{ "name": "a b", "days": ["daily"], "time": "03:00", "paths": ["C:\\"] }] }""", "letters")]
    [InlineData("""{ "schemaVersion": 1, "scheduledScans": [{ "name": "a", "days": ["daily"], "time": "03:00", "paths": ["C:\\"] }, { "name": "A", "days": ["daily"], "time": "04:00", "paths": ["C:\\"] }] }""", "Duplicate")]
    [InlineData("""{ "schemaVersion": 1, "scheduledScans": [{ "name": "a", "days": [], "time": "03:00", "paths": ["C:\\"] }] }""", "at least one day")]
    public void Invalid_settings_are_rejected_entirely(string json, string expected)
    {
        var ex = Assert.Throws<FormatException>(() => ServiceSettings.Parse(json));
        Assert.Contains(expected, ex.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(@"C:\Users\me\Downloads", true)]
    [InlineData(@"D:\", true)]
    [InlineData(@"\\server\share\folder", false)]
    [InlineData(@"\\?\C:\Windows", false)]
    [InlineData(@"\\.\PhysicalDrive0", false)]
    [InlineData(@"relative\path", false)]
    [InlineData(@"C:relative", false)]
    [InlineData(@"C:\Windows\*.exe", false)]
    [InlineData(@"C:\file.txt:stream", false)]
    [InlineData("", false)]
    public void Scan_path_policy_accepts_only_local_absolute_paths(string path, bool accepted)
    {
        Assert.Equal(accepted, ScanPathPolicy.IsLocalAbsolutePath(path));
    }

    [Fact]
    public void Too_many_paths_are_rejected()
    {
        string[] paths = [.. Enumerable.Range(0, ScanPathPolicy.MaxPathsPerRequest + 1).Select(i => $@"C:\dir{i}")];
        Assert.NotNull(ScanPathPolicy.Validate(paths));
        Assert.Null(ScanPathPolicy.Validate(paths[..ScanPathPolicy.MaxPathsPerRequest]));
    }

    [Fact]
    public void Development_mode_trusts_files_owned_by_the_current_user()
    {
        using var temp = new TempDirectory();
        string file = FileLockdown.ToCurrentUser(temp.File("service.json", [(byte)'{', (byte)'}']));

        Assert.Null(SecureStorage.CheckTrustedFile(file, production: false));
    }

    [Fact]
    public void Production_mode_refuses_files_a_standard_user_can_change()
    {
        using var temp = new TempDirectory();
        string file = temp.File("service.json", [(byte)'{', (byte)'}']);

        Assert.NotNull(SecureStorage.CheckTrustedFile(file, production: true));
    }

    [Fact]
    public void Files_writable_by_everyone_are_refused()
    {
        using var temp = new TempDirectory();
        string file = FileLockdown.ToCurrentUser(temp.File("rules.yar", [(byte)'x']));
        var info = new FileInfo(file);
        FileSecurity acl = info.GetAccessControl();
        acl.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.WorldSid, null), FileSystemRights.Modify, AccessControlType.Allow));
        info.SetAccessControl(acl);

        string? problem = SecureStorage.CheckTrustedFile(file, production: false);

        Assert.NotNull(problem);
        Assert.Contains("can be modified", problem, StringComparison.Ordinal);
    }

    [Fact]
    public void Missing_trusted_file_is_reported()
    {
        Assert.Contains("does not exist", SecureStorage.CheckTrustedFile(@"C:\does-not-exist\x.hashdb", production: true), StringComparison.Ordinal);
    }
}
