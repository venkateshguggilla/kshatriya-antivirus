using System.Diagnostics;
using System.Security.Principal;
using Kshatriya.Service.RealTime;
using Kshatriya.Tests.Shared;

namespace Kshatriya.Service.Tests;

public sealed class UsnJournalTests
{
    private static bool IsAdministrator => new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator);

    [Fact]
    public void Version_2_records_are_parsed_and_other_versions_skipped()
    {
        byte[] buffer = UsnRecordBuilder.Concat(
            UsnRecordBuilder.Record(10, 5, UsnRecords.ReasonFileCreate, 0x20, "new.bin"),
            UsnRecordBuilder.Record(11, 5, 0, 0, "future", majorVersion: 3),
            UsnRecordBuilder.Record(12, 6, UsnRecords.ReasonRenameNewName, UsnRecords.AttributeDirectory, "moved-in"));

        List<UsnEntry> entries = UsnRecords.Parse(buffer);

        Assert.Equal(2, entries.Count);
        Assert.Equal(new UsnEntry(10, 5, UsnRecords.ReasonFileCreate, 0x20, "new.bin"), entries[0]);
        Assert.Equal("moved-in", entries[1].Name);
        Assert.Equal(6UL, entries[1].ParentReference);
    }

    [Theory]
    [InlineData(0, 59)]        // record shorter than its header
    [InlineData(0, 100_000)]   // record longer than the buffer
    [InlineData(56, 3)]        // odd name length
    [InlineData(58, 40)]       // name inside the header
    [InlineData(58, 200)]      // name past the record
    public void Malformed_records_end_parsing_without_throwing(int field, int value)
    {
        byte[] good = UsnRecordBuilder.Record(1, 5, UsnRecords.ReasonFileCreate, 0x20, "ok.bin");
        byte[] bad = UsnRecordBuilder.Record(2, 5, UsnRecords.ReasonFileCreate, 0x20, "bad.bin");
        if (field == 0)
        {
            System.Buffers.Binary.BinaryPrimitives.WriteUInt32LittleEndian(bad, (uint)value);
        }
        else
        {
            System.Buffers.Binary.BinaryPrimitives.WriteUInt16LittleEndian(bad.AsSpan(field), (ushort)value);
        }

        List<UsnEntry> entries = UsnRecords.Parse(UsnRecordBuilder.Concat(good, bad, good));

        Assert.Equal("ok.bin", Assert.Single(entries).Name);
    }

    [Fact]
    public void Only_existing_files_and_created_or_moved_in_folders_are_scanned()
    {
        Assert.True(UsnRecords.IsScannable(new UsnEntry(1, 5, UsnRecords.ReasonFileCreate, 0x20, "a")));
        Assert.True(UsnRecords.IsScannable(new UsnEntry(1, 5, 0x2 /* data extend */, 0x20, "a")));
        Assert.True(UsnRecords.IsScannable(new UsnEntry(1, 5, UsnRecords.ReasonRenameNewName, UsnRecords.AttributeDirectory, "d")));
        Assert.False(UsnRecords.IsScannable(new UsnEntry(1, 5, UsnRecords.ReasonFileDelete, 0x20, "a")));
        Assert.False(UsnRecords.IsScannable(new UsnEntry(1, 5, UsnRecords.ReasonRenameOldName, 0x20, "a")));
        Assert.False(UsnRecords.IsScannable(new UsnEntry(1, 5, 0x8000 /* basic info */, UsnRecords.AttributeDirectory, "d")));
    }

    [Fact]
    public void The_journal_reports_files_changed_since_a_checkpoint_and_needs_administrator_rights()
    {
        using var temp = new TempDirectory();
        using UsnJournal? journal = UsnJournal.TryOpen(temp.Path, out string reason);
        if (!IsAdministrator)
        {
            Assert.Null(journal);
            Assert.Contains("cannot be opened", reason, StringComparison.Ordinal);
            return;
        }

        Assert.NotNull(journal);
        UsnCheckpoint start = journal.Current(out reason) ?? throw new InvalidOperationException(reason);
        string written = temp.File(@"sub\written.bin", TestData.BenignBytes(1, 100));
        string deleted = temp.File("deleted.bin", TestData.BenignBytes(2, 100));
        File.Delete(deleted);
        string movedIn = Path.Combine(temp.Path, "moved-in");
        using (var outside = new TempDirectory())
        {
            outside.File("inside.bin", TestData.BenignBytes(3, 100));
            Directory.Move(outside.Path, movedIn);
        }

        IReadOnlyCollection<string>? changed = journal.ChangedSince(start, 10_000, out reason);

        Assert.True(changed is not null, reason);
        Assert.Contains(written, changed, StringComparer.OrdinalIgnoreCase);
        Assert.Contains(movedIn, changed, StringComparer.OrdinalIgnoreCase);
        Assert.DoesNotContain(deleted, changed, StringComparer.OrdinalIgnoreCase);
        Assert.Null(journal.ChangedSince(start with { JournalId = start.JournalId + 1 }, 10_000, out reason));
        Assert.Contains("recreated", reason, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Lost_notifications_are_recovered_from_the_journal_or_by_a_full_rescan()
    {
        using var watched = new TempDirectory();
        for (int i = 0; i < 300; i++)
        {
            watched.File($@"old\{i}.bin", TestData.BenignBytes(i, 64));
        }

        var settings = new ServiceSettings
        {
            RealTime = new RealTimeOptions { Enabled = true, Paths = [watched.Path], Debounce = TimeSpan.FromMilliseconds(200) },
        };

        // Without administrator rights there is no journal and the whole root is rescanned, which finds a
        // file the watcher never reported (it existed before monitoring started).
        byte[] knownBad = TestData.BenignBytes(77, 4096); // what RunningService's signature database flags
        string bad = IsAdministrator ? Path.Combine(watched.Path, "after-start.bin") : watched.File("before-start.bin", knownBad);
        await using RunningService service = await RunningService.StartAsync(settings);
        Assert.Equal(knownBad, service.KnownBad);
        string expectedSource = "rescan after lost events";
        if (IsAdministrator)
        {
            // Written after the checkpoint: the journal finds it and the 300 old files are not rescanned.
            await Task.Delay(300);
            File.WriteAllBytes(bad, knownBad);
            await Task.Delay(1000);
            expectedSource = "recovered from change journal";
        }

        long before = service.Core.RealTime!.Stats.Scanned;
        service.Core.RealTime.OnLostEvents(watched.Path, "simulated");

        await WaitForAsync(service, bad, expectedSource);
        if (IsAdministrator)
        {
            Assert.True(service.Core.RealTime.Stats.Scanned - before < 300, "Only changed paths were rescanned.");
        }
    }

    [Fact]
    public async Task Change_notifications_arriving_after_shutdown_are_ignored()
    {
        // A file-system callback already in flight can reach the monitor after it was disposed; it used to
        // throw ObjectDisposedException on a thread-pool thread, which ends the process (seen in CI).
        using var watched = new TempDirectory();
        var settings = new ServiceSettings
        {
            RealTime = new RealTimeOptions { Enabled = true, Paths = [watched.Path], Debounce = TimeSpan.FromMilliseconds(200) },
        };
        RunningService service = await RunningService.StartAsync(settings);
        var monitor = service.Core.RealTime!;

        await service.DisposeAsync(); // stops the service, which disposes the monitor

        monitor.Enqueue(Path.Combine(watched.Path, "late.bin"), "late event");
        monitor.OnLostEvents(watched.Path, "late loss");
    }

    private static async Task WaitForAsync(RunningService service, string path, string source)
    {
        var clock = Stopwatch.StartNew();
        while (clock.Elapsed < TimeSpan.FromSeconds(30))
        {
            if (service.Core.History.Recent(200).Any(r => string.Equals(r.Path, path, StringComparison.OrdinalIgnoreCase) && r.Source.Contains(source, StringComparison.Ordinal)))
            {
                return;
            }

            await Task.Delay(100);
        }

        throw new TimeoutException($"No detection of {path} from '{source}'.");
    }
}
