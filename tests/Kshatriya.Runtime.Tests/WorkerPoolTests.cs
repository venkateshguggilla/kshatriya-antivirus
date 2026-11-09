using Kshatriya.Core;
using Kshatriya.Runtime.Workers;
using Kshatriya.Scanning;
using Kshatriya.Tests.Shared;

namespace Kshatriya.Runtime.Tests;

/// <summary>Behaviour of the sandboxed worker pool as an <see cref="IContentAnalyzer"/>.</summary>
public class WorkerPoolTests
{
    private static readonly TimeSpan Budget = TimeSpan.FromSeconds(30);

    [Fact]
    public async Task Detects_eicar_inside_the_sandbox()
    {
        using WorkerPoolAnalyzer pool = await SandboxTests.StartAsync(testHooks: false);

        AnalysisResult result = await AnalyzeAsync(pool, "eicar.txt", TestData.EicarBytes());

        Assert.Equal(ScanReason.None, result.Reason);
        Assert.Contains(result.Detections, d => d.Name == "Kshatriya.Test.EICAR" && d.EngineId == "hash");
        Assert.Contains(result.Detections, d => d.EngineId == "yara");
    }

    [Fact]
    public async Task Custom_signatures_are_sent_to_the_worker_as_content()
    {
        byte[] sample = TestData.BenignBytes(42, 4096);
        var engines = new EngineConfiguration
        {
            HashDatabases = [new TextSource("custom.hashdb", TestData.HashDb((TestData.Sha256Hex(sample), "Custom.Test.Sample", "test")))],
        };
        using WorkerPoolAnalyzer pool = await SandboxTests.StartAsync(testHooks: false, engines: engines);

        AnalysisResult result = await AnalyzeAsync(pool, "sample.bin", sample);

        Detection d = Assert.Single(result.Detections);
        Assert.Equal("Custom.Test.Sample", d.Name);
    }

    [Fact]
    public async Task Worker_and_in_process_analysis_agree()
    {
        byte[][] samples =
        [
            TestData.BenignBytes(1, 10_000),
            TestData.EicarBytes(),
            ZipFactory.Create(("docs/readme.txt", TestData.BenignBytes(2, 500)), ("payload/eicar.com", TestData.EicarBytes())),
            PeBuilder.PackedLike().Build(),
            PeBuilder.Benign().Build(),
            ZipFactory.MarkAllEncrypted(ZipFactory.Create(("secret.bin", TestData.BenignBytes(3, 2000)))),
        ];

        var configuration = new EngineConfiguration();
        (InProcessAnalyzer local, EngineSet set) = EngineSetup.BuildInProcess(configuration);
        using (set)
        {
            using WorkerPoolAnalyzer pool = await SandboxTests.StartAsync(testHooks: false, engines: configuration);
            Assert.Equal(local.ConfigurationFingerprint, pool.ConfigurationFingerprint);
            Assert.Equal(local.Engines, pool.Engines);

            for (int i = 0; i < samples.Length; i++)
            {
                AnalysisResult expected = await AnalyzeAsync(local, $"sample-{i}", samples[i]);
                AnalysisResult actual = await AnalyzeAsync(pool, $"sample-{i}", samples[i]);

                Assert.Equal(expected.Reason, actual.Reason);
                Assert.Equal(expected.Message, actual.Message);
                Assert.Equal(expected.Detections, actual.Detections);
            }
        }
    }

    [Fact]
    public async Task Worker_crash_is_reported_and_the_pool_recovers()
    {
        using WorkerPoolAnalyzer pool = await SandboxTests.StartAsync(testHooks: true, workers: 1);

        AnalysisResult crashed = await AnalyzeAsync(pool, "kshatriya-test://crash", [1, 2, 3]);
        AnalysisResult next = await AnalyzeAsync(pool, "eicar.txt", TestData.EicarBytes());

        Assert.Equal(ScanReason.EngineError, crashed.Reason);
        Assert.Contains("stopped unexpectedly", crashed.Message, StringComparison.Ordinal);
        Assert.NotEmpty(next.Detections);
        Assert.Equal(1, pool.Stats.Crashed);
        Assert.Equal(2, pool.Stats.Started);
    }

    [Fact]
    public async Task Hung_worker_is_killed_at_the_deadline_and_the_pool_recovers()
    {
        using WorkerPoolAnalyzer pool = await SandboxTests.StartAsync(testHooks: true, workers: 1);

        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(2));
        AnalysisResult hung = await pool.AnalyzeAsync(Request("kshatriya-test://hang", [1, 2, 3], TimeSpan.FromSeconds(2)), deadline.Token);
        AnalysisResult next = await AnalyzeAsync(pool, "eicar.txt", TestData.EicarBytes());

        Assert.Equal(ScanReason.Timeout, hung.Reason);
        Assert.NotEmpty(next.Detections);
        Assert.Equal(1, pool.Stats.TimedOut);
    }

    [Fact]
    public async Task Parallel_requests_share_a_bounded_number_of_workers()
    {
        using WorkerPoolAnalyzer pool = await SandboxTests.StartAsync(testHooks: false, workers: 3);
        byte[] eicar = TestData.EicarBytes();

        AnalysisResult[] results = await Task.WhenAll(Enumerable.Range(0, 60).Select(i =>
            AnalyzeAsync(pool, $"item-{i}", i % 2 == 0 ? eicar : TestData.BenignBytes(i, 2048))));

        Assert.Equal(30, results.Count(r => r.Detections.Count > 0));
        Assert.All(results, r => Assert.Equal(ScanReason.None, r.Reason));
        Assert.InRange(pool.Stats.Started, 1, 3);
    }

    [Fact]
    public async Task Large_content_round_trips()
    {
        byte[] large = TestData.BenignBytes(9, 24 * 1024 * 1024);
        large[^1] = 7;
        var engines = new EngineConfiguration
        {
            HashDatabases = [new TextSource("large.hashdb", TestData.HashDb((TestData.Sha256Hex(large), "Large.Test.Sample", "test")))],
        };
        using WorkerPoolAnalyzer pool = await SandboxTests.StartAsync(testHooks: false, engines: engines);

        AnalysisResult result = await AnalyzeAsync(pool, "large.bin", large);

        Assert.Equal("Large.Test.Sample", Assert.Single(result.Detections).Name);
    }

    [Fact]
    public async Task Invalid_signature_database_fails_startup_with_its_origin()
    {
        var engines = new EngineConfiguration { HashDatabases = [new TextSource("broken.hashdb", "not a database")] };

        var ex = await Assert.ThrowsAsync<WorkerStartException>(() => SandboxTests.StartAsync(testHooks: false, engines: engines));

        Assert.Contains("broken.hashdb", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Scan_runner_scans_a_folder_through_workers()
    {
        using var temp = new TempDirectory();
        temp.File("clean.bin", TestData.BenignBytes(5, 1000));
        temp.File(@"sub\eicar.zip", ZipFactory.Create(("e.com", TestData.EicarBytes())));
        using WorkerPoolAnalyzer pool = await SandboxTests.StartAsync(testHooks: false);
        var runner = new ScanRunner(pool, new ScanOptions());

        ScanReport report = await runner.ScanPathsAsync([temp.Path]);

        Assert.Equal(2, report.Summary.FilesScanned);
        ScanItemResult hit = Assert.Single(report.Items);
        Assert.Equal(ScanStatus.Detected, hit.Status);
        Assert.Equal("e.com", hit.Detections[0].Location);
        Assert.True(report.IsComplete);
    }

    private static Task<AnalysisResult> AnalyzeAsync(IContentAnalyzer analyzer, string name, byte[] content) =>
        analyzer.AnalyzeAsync(Request(name, content, Budget), CancellationToken.None);

    private static AnalysisRequest Request(string name, byte[] content, TimeSpan budget) =>
        new(name, content.Length, TestData.Sha256Hex(content), new MemoryStream(content, writable: false), Trust: null, budget);
}
