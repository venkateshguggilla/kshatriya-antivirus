using Kshatriya.Scanning.Targets;

namespace Kshatriya.Scanning.Tests;

public class ScanTargetsTests
{
    private static readonly string s_windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);

    private static Func<string, bool> Exists(params string[] files)
    {
        var set = new HashSet<string>(files, StringComparer.OrdinalIgnoreCase);
        return set.Contains;
    }

    [Theory]
    [InlineData(@"""C:\Program Files\App\app.exe"" --minimized", @"C:\Program Files\App\app.exe")]
    [InlineData(@"C:\Program Files\App\app.exe --minimized", @"C:\Program Files\App\app.exe")] // unquoted, with spaces
    [InlineData(@"C:\Tools\updater", @"C:\Tools\updater.exe")]                                     // missing .exe
    [InlineData(@"\??\C:\Drivers\svc.exe", @"C:\Drivers\svc.exe")]
    public void Startup_commands_resolve_to_the_program_they_run(string commandLine, string expected)
    {
        Assert.Equal([expected], ScanTargets.FilesFromCommandLine(commandLine, Exists(@"C:\Program Files\App\app.exe", @"C:\Tools\updater.exe", @"C:\Drivers\svc.exe")));
    }

    [Fact]
    public void System_relative_names_and_rundll32_dlls_are_resolved()
    {
        string rundll = Path.Combine(s_windows, "System32", "rundll32.exe");
        string svchost = Path.Combine(s_windows, "System32", "svchost.exe");
        Func<string, bool> exists = Exists(rundll, svchost, @"C:\Users\alice\AppData\evil.dll");

        Assert.Equal([rundll, @"C:\Users\alice\AppData\evil.dll"], ScanTargets.FilesFromCommandLine(@"rundll32.exe ""C:\Users\alice\AppData\evil.dll"",Start", exists));
        Assert.Equal([svchost], ScanTargets.FilesFromCommandLine(@"%SystemRoot%\System32\svchost.exe -k netsvcs", exists));
        Assert.Equal([svchost], ScanTargets.FilesFromCommandLine(@"\SystemRoot\System32\svchost.exe -k x", exists));
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData(@"C:\does\not\exist.exe")]
    [InlineData(@"\\server\share\app.exe")]
    [InlineData(@"""C:\x\*.exe""")]
    public void Unresolvable_commands_yield_nothing(string commandLine)
    {
        Assert.Empty(ScanTargets.FilesFromCommandLine(commandLine, _ => false));
    }

    [Fact]
    public void A_quick_scan_for_one_user_never_reaches_into_other_profiles()
    {
        var inputs = new QuickScanInputs(
            Folders: [@"C:\Users\alice\Downloads", @"C:\Users\alice\Downloads\", @"C:\Users\bob\Downloads", @"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp", @"C:\Missing"],
            CommandLines: [@"""C:\Users\bob\AppData\run.exe""", @"""C:\Users\Public\shared.exe""", @"""C:\Program Files\App\app.exe"""],
            ProcessImages: [@"C:\Program Files\App\app.exe", @"C:\Users\alice\tool.exe", @"\\server\share\x.exe"],
            ProfilesRoot: @"C:\Users",
            AllowedProfile: @"C:\Users\alice");
        Func<string, bool> files = Exists(@"C:\Users\bob\AppData\run.exe", @"C:\Users\Public\shared.exe", @"C:\Program Files\App\app.exe", @"C:\Users\alice\tool.exe");
        Func<string, bool> folders = Exists(@"C:\Users\alice\Downloads", @"C:\Users\bob\Downloads", @"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp");

        IReadOnlyList<string> targets = ScanTargets.Quick(inputs, files, folders);

        Assert.Equal(
            [@"C:\Users\alice\Downloads", @"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp", @"C:\Users\Public\shared.exe", @"C:\Program Files\App\app.exe", @"C:\Users\alice\tool.exe"],
            targets);
    }

    [Fact]
    public void A_machine_wide_quick_scan_covers_every_profile()
    {
        var inputs = new QuickScanInputs([@"C:\Users\alice\Downloads", @"C:\Users\bob\Downloads"], [], [], @"C:\Users", AllowedProfile: null);

        Assert.Equal(2, ScanTargets.Quick(inputs, _ => false, _ => true).Count);
    }

    [Fact]
    public void A_full_scan_covers_ready_fixed_drives_only()
    {
        IReadOnlyList<string> roots = ScanTargets.FullSystem(
        [
            (@"D:\", DriveType.Fixed, true),
            (@"C:\", DriveType.Fixed, true),
            (@"E:\", DriveType.Removable, true),
            (@"F:\", DriveType.Fixed, false),
            (@"Z:\", DriveType.Network, true),
            (@"G:\", DriveType.CDRom, true),
        ]);

        Assert.Equal([@"C:\", @"D:\"], roots);
    }

    [Fact]
    public void Scan_kind_names_round_trip_and_unknown_names_are_refused()
    {
        foreach (ScanKind kind in Enum.GetValues<ScanKind>())
        {
            Assert.Equal(kind, ScanKindNames.Parse(ScanKindNames.Of(kind)));
        }

        Assert.Equal(ScanKind.Custom, ScanKindNames.Parse(null));
        Assert.Null(ScanKindNames.Parse("Quick"));
        Assert.Null(ScanKindNames.Parse("deep"));
    }

    [Fact]
    public void This_machine_has_quick_scan_targets()
    {
        string profile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        IReadOnlyList<string> targets = ScanTargets.Quick(new QuickScanScope(System.Security.Principal.WindowsIdentity.GetCurrent().User?.Value, profile, IncludeAdminLocations: false));

        Assert.NotEmpty(targets);
        Assert.All(targets, t => Assert.True(PathPolicy.IsLocalAbsolutePath(t), t));
        Assert.Contains(targets, t => t.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)); // at least this test runner's process
        Assert.Equal(targets.Count, targets.Distinct(StringComparer.OrdinalIgnoreCase).Count());
    }
}
