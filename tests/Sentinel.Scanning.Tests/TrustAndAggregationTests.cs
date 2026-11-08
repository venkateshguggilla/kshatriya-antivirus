using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using Sentinel.Core;
using Sentinel.Engines;
using Sentinel.Scanning;
using Sentinel.Scanning.Trust;
using Sentinel.Tests.Shared;

namespace Sentinel.Scanning.Tests;

public class TrustAndAggregationTests
{
    private static FileTrust Evaluate(string path)
    {
        OpenResult open = SafeFileOpener.Open(path);
        Assert.True(open.Success, open.Message);
        using SafeFileHandle handle = open.Handle!;
        return new AuthenticodeTrustProvider().Evaluate(handle, path);
    }

    private static string RuntimeFile(string name) => Path.Combine(RuntimeEnvironment.GetRuntimeDirectory(), name);

    [Fact]
    public void Embedded_signature_on_runtime_binary_is_valid()
    {
        FileTrust trust = Evaluate(RuntimeFile("coreclr.dll"));

        Assert.Equal(TrustStatus.Valid, trust.Status);
        Assert.Equal(TrustSource.Embedded, trust.Source);
        Assert.False(string.IsNullOrEmpty(trust.Signer));
    }

    [Fact]
    public void Catalog_signed_system_binary_is_valid()
    {
        string notepad = Path.Combine(Environment.SystemDirectory, "notepad.exe");
        if (!File.Exists(notepad))
        {
            return;
        }

        FileTrust trust = Evaluate(notepad);

        Assert.Equal(TrustStatus.Valid, trust.Status);
        Assert.NotEqual(TrustSource.None, trust.Source);
    }

    [Fact]
    public void Tampered_copy_of_signed_binary_is_invalid()
    {
        using var temp = new TempDirectory();
        byte[] bytes = File.ReadAllBytes(RuntimeFile("coreclr.dll"));
        bytes[0x1000] ^= 0xFF; // flip a byte inside the signed content
        string copy = temp.File("tampered.dll", bytes);

        FileTrust trust = Evaluate(copy);

        Assert.Equal(TrustStatus.Invalid, trust.Status);
    }

    [Fact]
    public void Synthetic_unsigned_image_is_not_signed()
    {
        using var temp = new TempDirectory();
        string pe = temp.File("plain.exe", PeBuilder.Benign().Build());

        Assert.Equal(TrustStatus.NotSigned, Evaluate(pe).Status);
    }

    [Fact]
    public async Task Pipeline_attaches_trust_only_to_executables()
    {
        using var temp = new TempDirectory();
        temp.File("plain.exe", PeBuilder.Benign().Build());
        temp.File("notes.txt", "hello"u8.ToArray());
        var options = new ScanOptions { IncludeCleanItems = true, TrustProvider = new AuthenticodeTrustProvider() };

        ScanReport report = await new ScanRunner([new FixedEngine()], options).ScanPathsAsync([temp.Path]);

        Assert.Equal(TrustStatus.NotSigned, report.Items.Single(i => i.Path.EndsWith(".exe", StringComparison.Ordinal)).Trust!.Status);
        Assert.Null(report.Items.Single(i => i.Path.EndsWith(".txt", StringComparison.Ordinal)).Trust);
    }

    [Fact]
    public async Task Suspicious_only_findings_produce_suspicious_status()
    {
        using var temp = new TempDirectory();
        temp.File("a.bin", [1, 2, 3]);

        ScanReport report = await new ScanRunner([new FixedEngine(DetectionCategory.Suspicious)]).ScanPathsAsync([temp.Path]);

        Assert.Equal(ScanStatus.Suspicious, Assert.Single(report.Items).Status);
        Assert.Equal(1, report.Summary.Suspicious);
        Assert.Equal(0, report.Summary.Detected);
    }

    [Fact]
    public async Task Confirmed_detection_outranks_suspicious()
    {
        using var temp = new TempDirectory();
        temp.File("a.bin", [1, 2, 3]);

        ScanReport report = await new ScanRunner([new FixedEngine(DetectionCategory.Suspicious), new FixedEngine(DetectionCategory.Malware)])
            .ScanPathsAsync([temp.Path]);

        ScanItemResult item = Assert.Single(report.Items);
        Assert.Equal(ScanStatus.Detected, item.Status);
        Assert.Equal(2, item.Detections.Count);
    }

    [Fact]
    public async Task Findings_before_a_timeout_are_kept_and_item_is_partial()
    {
        using var temp = new TempDirectory();
        temp.File("a.bin", [1, 2, 3]);
        var options = new ScanOptions { Limits = new ScanLimits { PerItemTimeout = TimeSpan.FromMilliseconds(300) } };

        ScanReport report = await new ScanRunner([new FixedEngine(DetectionCategory.Malware), new HangingEngine()], options).ScanPathsAsync([temp.Path]);

        ScanItemResult item = Assert.Single(report.Items);
        Assert.Equal(ScanStatus.Detected, item.Status);
        Assert.Equal(ScanReason.Timeout, item.Reason);
        Assert.True(item.IsIncomplete);
    }

    [Fact]
    public async Task Engine_timeout_exception_maps_to_timeout_reason()
    {
        using var temp = new TempDirectory();
        temp.File("a.bin", [1]);

        ScanReport report = await new ScanRunner([new TimeoutEngine()]).ScanPathsAsync([temp.Path]);

        ScanItemResult item = Assert.Single(report.Items);
        Assert.Equal(ScanStatus.NotScanned, item.Status);
        Assert.Equal(ScanReason.Timeout, item.Reason);
    }

    private sealed class FixedEngine(DetectionCategory? category = null) : IDetectionEngine
    {
        public EngineDescriptor Descriptor { get; } = new($"fixed-{category}", "1", "none");

        public ValueTask<IReadOnlyList<Detection>> ScanAsync(ScanSubject subject, CancellationToken cancellationToken) =>
            ValueTask.FromResult<IReadOnlyList<Detection>>(category is { } c
                ? [new Detection(Descriptor.Id, $"Test.{c}", c, DetectionConfidence.Low)]
                : []);
    }

    private sealed class HangingEngine : IDetectionEngine
    {
        public EngineDescriptor Descriptor { get; } = new("hang", "1", "none");

        public async ValueTask<IReadOnlyList<Detection>> ScanAsync(ScanSubject subject, CancellationToken cancellationToken)
        {
            await Task.Delay(Timeout.Infinite, cancellationToken);
            return [];
        }
    }

    private sealed class TimeoutEngine : IDetectionEngine
    {
        public EngineDescriptor Descriptor { get; } = new("timeout", "1", "none");

        public ValueTask<IReadOnlyList<Detection>> ScanAsync(ScanSubject subject, CancellationToken cancellationToken) =>
            throw new EngineTimeoutException("budget exceeded");
    }
}
