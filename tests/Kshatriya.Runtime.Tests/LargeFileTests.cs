using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using Kshatriya.Core;
using Kshatriya.Runtime.Workers;
using Kshatriya.Scanning;
using Kshatriya.Tests.Shared;
using Microsoft.Win32.SafeHandles;

namespace Kshatriya.Runtime.Tests;

/// <summary>
/// Files larger than a byte array (2 GiB) are scanned from a read-only mapping, inside the sandbox too. The
/// test file is sparse: 3 GiB long but only a few clusters on disk, with a marker beyond the 2 GiB boundary.
/// </summary>
public sealed partial class LargeFileTests : IDisposable
{
    private const string Marker = "KSHATRIYA-LARGE-FILE-TEST-MARKER-7f3a";
    private const long Size = 3L << 30;
    private const long MarkerOffset = (5L << 30) / 2; // 2.5 GiB
    private readonly TempDirectory _temp = new();

    public void Dispose() => _temp.Dispose();

    private static EngineConfiguration Engines => new()
    {
        YaraRules = [new TextSource("marker.yar", $$"""
            rule LargeFileMarker
            {
                meta:
                    category = "test"
                    confidence = "high"
                strings:
                    $m = "{{Marker}}"
                condition:
                    $m
            }
            """)],
        YaraRequired = true,
    };

    [Fact]
    public async Task A_file_beyond_2_GiB_is_scanned_through_the_sandbox_without_copying_it()
    {
        string path = CreateSparse("big.bin");
        using WorkerPoolAnalyzer pool = await SandboxTests.StartAsync(testHooks: false, engines: Engines, workers: 1);
        var runner = new ScanRunner(pool, new ScanOptions());
        var clock = Stopwatch.StartNew();

        ScanReport report = await runner.ScanPathsAsync([path]);

        ScanItemResult item = Assert.Single(report.Items);
        Assert.Equal(ScanStatus.Detected, item.Status);
        Assert.Equal(ScanReason.None, item.Reason);
        Assert.Equal(Size, item.SizeBytes);
        Assert.Contains(item.Detections, d => d.EngineId == "yara");
        Assert.Equal(0, pool.Stats.Crashed); // the worker stayed within its 1.5 GB private-memory cap
        Assert.True(clock.Elapsed < TimeSpan.FromMinutes(3), $"Took {clock.Elapsed}.");
    }

    [Fact]
    public async Task A_file_beyond_2_GiB_is_scanned_in_process_from_a_mapping()
    {
        string path = CreateSparse("big-local.bin");
        (InProcessAnalyzer local, EngineSet set) = EngineSetup.BuildInProcess(Engines);
        using (set)
        {
            ScanReport report = await new ScanRunner(local, new ScanOptions()).ScanPathsAsync([path]);

            ScanItemResult item = Assert.Single(report.Items);
            Assert.Equal(ScanStatus.Detected, item.Status);
            Assert.Equal(ScanReason.None, item.Reason);
        }
    }

    [Fact]
    public async Task Files_above_the_configured_limit_are_still_reported_not_scanned()
    {
        string path = CreateSparse("over-limit.bin");
        (InProcessAnalyzer local, EngineSet set) = EngineSetup.BuildInProcess(Engines);
        using (set)
        {
            var runner = new ScanRunner(local, new ScanOptions { Limits = new ScanLimits { MaxFileSizeBytes = 1L << 30 } });

            ScanItemResult item = Assert.Single((await runner.ScanPathsAsync([path])).Items);

            Assert.Equal(ScanStatus.NotScanned, item.Status);
            Assert.Equal(ScanReason.TooLarge, item.Reason);
        }
    }

    [Fact]
    public void The_default_limit_is_10_GiB_and_time_limits_grow_with_size()
    {
        var limits = new ScanLimits();

        Assert.Equal(10L << 30, limits.MaxFileSizeBytes);
        Assert.Equal(TimeSpan.FromSeconds(60), limits.TimeoutFor(0));
        Assert.Equal(TimeSpan.FromSeconds(60 + 300), limits.TimeoutFor(10L << 30));
    }

    private string CreateSparse(string name)
    {
        string path = Path.Combine(_temp.Path, name);
        using var stream = new FileStream(path, FileMode.CreateNew, FileAccess.ReadWrite);
        if (!DeviceIoControl(stream.SafeFileHandle, 0x000900C4 /* FSCTL_SET_SPARSE */, IntPtr.Zero, 0, IntPtr.Zero, 0, out _, IntPtr.Zero))
        {
            throw new IOException($"Could not make the test file sparse (error {Marshal.GetLastPInvokeError()}).");
        }

        stream.SetLength(Size);
        stream.Position = MarkerOffset;
        stream.Write(Encoding.ASCII.GetBytes(Marker));
        return path;
    }

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool DeviceIoControl(SafeFileHandle device, uint code, IntPtr input, uint inputSize, IntPtr output, uint outputSize, out uint returned, IntPtr overlapped);
}
