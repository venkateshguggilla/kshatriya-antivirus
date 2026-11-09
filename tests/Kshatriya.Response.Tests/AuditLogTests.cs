using Kshatriya.Response;
using Kshatriya.Tests.Shared;

namespace Kshatriya.Response.Tests;

public class AuditLogTests
{
    private static readonly Actor s_actor = new("S-1-5-21-1-2-3-1001", @"HOST\alice");

    [Fact]
    public void Records_are_chained_and_read_newest_first()
    {
        using var temp = new TempDirectory();
        AuditLog log = AuditLog.Open(temp.Dir("audit"), StorageAccess.CurrentUser);

        AuditRecord first = log.Append(s_actor, AuditActions.Quarantine, @"C:\a.exe", AuditOutcomes.Succeeded, "scan", new string('1', 32));
        AuditRecord second = log.Append(s_actor, AuditActions.Restore, @"C:\a.exe", AuditOutcomes.Denied, "not an administrator");

        Assert.Equal(AuditLog.Genesis, first.Previous);
        Assert.Equal(first.Hash, second.Previous);
        Assert.Equal(2, second.Sequence);
        Assert.Equal([second, first], log.ReadRecent(10));
        Assert.Equal(new AuditVerification(true, 2, null), log.Verify());
    }

    [Fact]
    public void Edited_records_are_detected()
    {
        using var temp = new TempDirectory();
        AuditLog log = AuditLog.Open(temp.Dir("audit"), StorageAccess.CurrentUser);
        log.Append(s_actor, AuditActions.Quarantine, @"C:\a.exe", AuditOutcomes.Succeeded);
        log.Append(s_actor, AuditActions.Delete, @"C:\a.exe", AuditOutcomes.Succeeded);
        string file = Path.Combine(log.Directory, "audit.jsonl");

        File.WriteAllText(file, File.ReadAllText(file).Replace(@"C:\\a.exe", @"C:\\b.exe", StringComparison.Ordinal));
        AuditVerification result = log.Verify();

        Assert.False(result.Valid);
        Assert.Contains("modified", result.Problem, StringComparison.Ordinal);
    }

    [Fact]
    public void Removed_records_are_detected()
    {
        using var temp = new TempDirectory();
        AuditLog log = AuditLog.Open(temp.Dir("audit"), StorageAccess.CurrentUser);
        for (int i = 0; i < 3; i++)
        {
            log.Append(s_actor, AuditActions.Quarantine, $@"C:\{i}.exe", AuditOutcomes.Succeeded);
        }

        string file = Path.Combine(log.Directory, "audit.jsonl");
        string[] lines = File.ReadAllLines(file);
        File.WriteAllLines(file, [lines[0], lines[2]]);

        AuditVerification result = log.Verify();
        Assert.False(result.Valid);
        Assert.Contains("does not follow", result.Problem, StringComparison.Ordinal);
    }

    [Fact]
    public void Rotation_keeps_the_chain()
    {
        using var temp = new TempDirectory();
        AuditLog log = AuditLog.Open(temp.Dir("audit"), StorageAccess.CurrentUser, rotateBytes: 600);
        for (int i = 0; i < 6; i++)
        {
            log.Append(s_actor, AuditActions.Quarantine, $@"C:\file{i}.exe", AuditOutcomes.Succeeded, new string('x', 100));
        }

        Assert.True(File.Exists(Path.Combine(log.Directory, "audit.1.jsonl")));
        Assert.True(log.Verify().Valid);
        Assert.Equal(6, log.ReadRecent(100).Max(r => r.Sequence));
    }

    [Fact]
    public void Concurrent_appends_from_several_threads_stay_valid()
    {
        using var temp = new TempDirectory();
        string dir = temp.Dir("audit");
        AuditLog a = AuditLog.Open(dir, StorageAccess.CurrentUser);
        AuditLog b = AuditLog.Open(dir, StorageAccess.CurrentUser);

        Parallel.For(0, 40, i => (i % 2 == 0 ? a : b).Append(s_actor, AuditActions.Quarantine, $@"C:\{i}", AuditOutcomes.Succeeded));

        Assert.Equal(new AuditVerification(true, 40, null), a.Verify());
    }
}
