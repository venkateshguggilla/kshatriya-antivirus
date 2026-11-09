using Kshatriya.Core;
using Kshatriya.Engines.Pe;
using Kshatriya.Tests.Shared;

namespace Kshatriya.Engines.Pe.Tests;

public class PeHeuristicsTests
{
    private static IReadOnlyList<PeIndicator> Indicators(PeBuilder builder)
    {
        Assert.True(PeImage.TryParse(builder.Build(), out PeImage? image, out string? error), error);
        return PeHeuristics.Evaluate(image!);
    }

    private static ScanSubject Subject(byte[] data, FileTrust? trust = null) =>
        new("sample.exe", data.Length, TestData.Sha256Hex(data), new MemoryStream(data, writable: false), trust);

    [Fact]
    public void Benign_layout_has_no_indicators()
    {
        Assert.Empty(Indicators(PeBuilder.Benign()));
    }

    [Fact]
    public void Packed_layout_triggers_expected_indicators()
    {
        var ids = Indicators(PeBuilder.PackedLike()).Select(i => i.Id).ToHashSet();

        Assert.Contains("packer-section-name", ids);
        Assert.Contains("high-entropy-code", ids);
        Assert.Contains("writable-executable-section", ids);
        Assert.Contains("dynamic-import-resolution", ids);
    }

    [Fact]
    public void Injection_api_combination_is_flagged()
    {
        var builder = PeBuilder.Benign().Import("KERNEL32.dll", "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread", "OpenProcess");
        Assert.Contains(Indicators(builder), i => i.Id == "process-injection-apis");
    }

    [Fact]
    public void Entry_point_outside_sections_is_flagged()
    {
        var builder = PeBuilder.Benign();
        builder.EntryPointOverride = 0x00F00000;
        Assert.Contains(Indicators(builder), i => i.Id == "entry-point-outside-sections");
    }

    [Fact]
    public void Entry_point_in_data_section_is_flagged()
    {
        var builder = PeBuilder.Benign();
        builder.EntryPointOverride = 0x3000 + 0x10; // inside .data
        Assert.Contains(Indicators(builder), i => i.Id == "entry-point-non-executable");
    }

    [Fact]
    public void Executable_without_imports_is_flagged_but_dll_is_not()
    {
        var exe = new PeBuilder().Section(".text", PeBuilder.Code | PeBuilder.Execute | PeBuilder.Read, PeBuilder.Pattern(4096));
        var dll = new PeBuilder { IsDll = true }.Section(".text", PeBuilder.Code | PeBuilder.Execute | PeBuilder.Read, PeBuilder.Pattern(4096));

        Assert.Contains(Indicators(exe), i => i.Id == "no-imports");
        Assert.DoesNotContain(Indicators(dll), i => i.Id == "no-imports");
    }

    [Fact]
    public async Task Engine_reports_packed_sample_as_suspicious_with_medium_confidence()
    {
        byte[] data = PeBuilder.PackedLike().Build();

        Detection d = Assert.Single(await new PeHeuristicEngine().ScanAsync(Subject(data), CancellationToken.None));

        Assert.Equal(PeHeuristicEngine.DetectionName, d.Name);
        Assert.Equal(DetectionCategory.Suspicious, d.Category);
        Assert.Equal(DetectionConfidence.Medium, d.Confidence);
        Assert.Contains("packer", d.Description, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Engine_is_silent_for_benign_sample_and_non_pe_content()
    {
        var engine = new PeHeuristicEngine();
        Assert.Empty(await engine.ScanAsync(Subject(PeBuilder.Benign().Build()), CancellationToken.None));
        Assert.Empty(await engine.ScanAsync(Subject(TestData.BenignBytes(1, 10_000)), CancellationToken.None));
    }

    [Fact]
    public async Task Engine_skips_validly_signed_files_by_default()
    {
        byte[] data = PeBuilder.PackedLike().Build();
        var signed = new FileTrust(TrustStatus.Valid, TrustSource.Embedded, "Example Publisher");

        Assert.Empty(await new PeHeuristicEngine().ScanAsync(Subject(data, signed), CancellationToken.None));
        Assert.Single(await new PeHeuristicEngine(new PeHeuristicOptions { SkipValidlySigned = false }).ScanAsync(Subject(data, signed), CancellationToken.None));
        Assert.Single(await new PeHeuristicEngine().ScanAsync(Subject(data, new FileTrust(TrustStatus.Invalid)), CancellationToken.None));
    }
}
