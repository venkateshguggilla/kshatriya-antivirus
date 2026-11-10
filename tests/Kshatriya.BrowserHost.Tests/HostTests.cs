using System.Buffers.Binary;
using System.Text;
using System.Text.Json;
using Kshatriya.BrowserHost;
using Kshatriya.Core;
using Kshatriya.Protocol;
using Kshatriya.Runtime.Ipc;
using NJsonSchema;

namespace Kshatriya.BrowserHost.Tests;

public class FramingTests
{
    private static MemoryStream Frame(uint length, byte[] body)
    {
        var stream = new MemoryStream();
        byte[] header = new byte[4];
        BinaryPrimitives.WriteUInt32LittleEndian(header, length);
        stream.Write(header);
        stream.Write(body);
        stream.Position = 0;
        return stream;
    }

    [Fact]
    public async Task A_frame_round_trips()
    {
        var stream = new MemoryStream();
        await NativeFraming.WriteAsync(stream, "{\"v\":1}"u8.ToArray(), CancellationToken.None);
        stream.Position = 0;

        (byte[]? message, FrameError error) = await NativeFraming.ReadAsync(stream, NativeFraming.MaxRequestBytes, CancellationToken.None);

        Assert.Equal(FrameError.None, error);
        Assert.Equal("{\"v\":1}", Encoding.UTF8.GetString(message!));
    }

    [Theory]
    [InlineData(0u)]
    [InlineData(NativeFraming.MaxRequestBytes + 1u)]
    [InlineData(uint.MaxValue)]
    public async Task Bad_lengths_are_rejected_before_reading_the_body(uint length)
    {
        (byte[]? message, FrameError error) = await NativeFraming.ReadAsync(Frame(length, []), NativeFraming.MaxRequestBytes, CancellationToken.None);

        Assert.Null(message);
        Assert.Equal(FrameError.BadLength, error);
    }

    [Fact]
    public async Task Truncated_frames_and_a_clean_end_of_stream_are_told_apart()
    {
        Assert.Equal(FrameError.Truncated, (await NativeFraming.ReadAsync(Frame(10, [1, 2]), 100, CancellationToken.None)).Error);
        Assert.Equal(FrameError.Truncated, (await NativeFraming.ReadAsync(new MemoryStream([1, 0]), 100, CancellationToken.None)).Error);
        Assert.Equal(FrameError.None, (await NativeFraming.ReadAsync(new MemoryStream(), 100, CancellationToken.None)).Error);
    }
}

public class RequestTests
{
    private static HostRequest? Parse(string json, out string? error) => HostRequest.Parse(Encoding.UTF8.GetBytes(json), out error);

    [Fact]
    public void Valid_requests_parse()
    {
        Assert.Equal(new HostRequest("status", null), Parse("""{"v":1,"type":"status"}""", out _));
        Assert.Equal(new HostRequest("blocklist", null), Parse("""{"v":1,"type":"blocklist"}""", out _));
        Assert.Equal(
            new HostRequest("scan", @"C:\Users\a\Downloads\setup.exe"),
            Parse("""{"v":1,"type":"scan","path":"C:\\Users\\a\\Downloads\\setup.exe"}""", out string? error));
        Assert.Null(error);
    }

    [Theory]
    [InlineData("""[]""")]
    [InlineData("""not json""")]
    [InlineData("""{"v":1,"type":"status","extra":true}""")]
    [InlineData("""{"v":1,"type":"status","path":"C:\\a"}""")]
    [InlineData("""{"v":1,"type":"scan"}""")]
    [InlineData("""{"v":1,"type":"blocklist","path":"C:\a"}""")]
    [InlineData("""{"v":1,"type":"delete","path":"C:\\a.txt"}""")]
    [InlineData("""{"v":1,"type":"status","type":"scan"}""")]
    [InlineData("""{"v":"1","type":"status"}""")]
    [InlineData("""{"v":1,"type":"scan","path":{"a":1}}""")]
    public void Anything_else_is_an_invalid_request(string json)
    {
        Assert.Null(Parse(json, out string? error));
        Assert.Equal(HostErrors.InvalidRequest, error);
    }

    [Fact]
    public void Other_versions_are_refused()
    {
        Assert.Null(Parse("""{"v":2,"type":"status"}""", out string? error));
        Assert.Equal(HostErrors.UnsupportedVersion, error);
    }

    [Theory]
    [InlineData(@"setup.exe")]
    [InlineData(@"C:setup.exe")]
    [InlineData(@"\\server\share\setup.exe")]
    [InlineData(@"\\?\C:\setup.exe")]
    [InlineData(@"\\.\PhysicalDrive0")]
    [InlineData(@"C:\a.txt:hidden")]
    [InlineData(@"C:\*.exe")]
    [InlineData(@"/c/setup.exe")]
    public void Only_local_drive_paths_are_accepted(string path)
    {
        string json = JsonSerializer.Serialize(new Dictionary<string, object> { ["v"] = 1, ["type"] = "scan", ["path"] = path });
        Assert.Null(Parse(json, out string? error));
        Assert.Equal(HostErrors.InvalidPath, error);
    }
}

public class HandlerTests
{
    private const string ScanRequest = """{"v":1,"type":"scan","path":"C:\\d\\f.exe"}""";

    private sealed class FakeService : IHostService
    {
        public Exception? Failure { get; init; }

        public ScanReport? Report { get; init; }

        public List<string> Scanned { get; } = [];

        public WebBlocklistReplyDto Blocklist { get; init; } = new() { Sequence = 3, Domains = ["bad.example", "phish.test"] };

        public Task<string> GetVersionAsync(CancellationToken cancellationToken) =>
            Failure is null ? Task.FromResult("0.12.0") : Task.FromException<string>(Failure);

        public Task<ScanReport> ScanFileAsync(string path, CancellationToken cancellationToken)
        {
            Scanned.Add(path);
            return Failure is null ? Task.FromResult(Report!) : Task.FromException<ScanReport>(Failure);
        }

        public Task<WebBlocklistReplyDto> GetWebBlocklistAsync(CancellationToken cancellationToken) =>
            Failure is null ? Task.FromResult(Blocklist) : Task.FromException<WebBlocklistReplyDto>(Failure);
    }

    private static ScanReport Report(params ScanItemResult[] items) => new()
    {
        Targets = [@"C:\d\f.exe"],
        StartedUtc = DateTimeOffset.UtcNow,
        FinishedUtc = DateTimeOffset.UtcNow,
        Engines = [],
        Summary = new ScanSummary { ItemsSeen = 1, FilesScanned = 1 },
        Items = items,
    };

    private static ScanItemResult Eicar() => new()
    {
        Path = @"C:\d\f.exe",
        Kind = ScanItemKind.File,
        Status = ScanStatus.Detected,
        Detections = [new Detection("hash", "EICAR-Test-File", DetectionCategory.TestFile, DetectionConfidence.High)],
    };

    private static async Task<JsonElement> RunAsync(HostHandler handler, string json)
    {
        byte[] reply = await handler.HandleAsync(Encoding.UTF8.GetBytes(json), CancellationToken.None);
        return JsonDocument.Parse(reply).RootElement;
    }

    [Fact]
    public async Task A_clean_file_is_reported_clean()
    {
        var service = new FakeService { Report = Report() };
        JsonElement reply = await RunAsync(new HostHandler(service, _ => true), ScanRequest);

        Assert.True(reply.GetProperty("ok").GetBoolean());
        Assert.Equal("clean", reply.GetProperty("status").GetString());
        Assert.Equal([@"C:\d\f.exe"], service.Scanned);
    }

    [Fact]
    public async Task Detections_are_reported_with_wire_names()
    {
        JsonElement reply = await RunAsync(new HostHandler(new FakeService { Report = Report(Eicar()) }, _ => true), ScanRequest);

        Assert.Equal("detected", reply.GetProperty("status").GetString());
        JsonElement detection = reply.GetProperty("detections")[0];
        Assert.Equal("EICAR-Test-File", detection.GetProperty("name").GetString());
        Assert.Equal("test", detection.GetProperty("category").GetString());
        Assert.Equal("high", detection.GetProperty("confidence").GetString());
    }

    [Fact]
    public async Task A_file_that_was_not_scanned_says_why()
    {
        var item = new ScanItemResult { Path = @"C:\d\f.exe", Kind = ScanItemKind.File, Status = ScanStatus.NotScanned, Reason = ScanReason.Locked };
        JsonElement reply = await RunAsync(new HostHandler(new FakeService { Report = Report(item) }, _ => true), ScanRequest);

        Assert.Equal("notScanned", reply.GetProperty("status").GetString());
        Assert.Equal("locked", reply.GetProperty("reason").GetString());
    }

    [Fact]
    public async Task Folders_and_missing_files_are_not_sent_to_the_service()
    {
        var service = new FakeService { Report = Report() };
        JsonElement reply = await RunAsync(new HostHandler(service, _ => false), ScanRequest);

        Assert.False(reply.GetProperty("ok").GetBoolean());
        Assert.Equal(HostErrors.NotAFile, reply.GetProperty("error").GetString());
        Assert.Empty(service.Scanned);
    }

    [Fact]
    public async Task A_stopped_service_is_reported_as_unavailable()
    {
        var service = new FakeService { Failure = new ServiceException("The Kshatriya service is not reachable.", new TimeoutException()) };
        JsonElement reply = await RunAsync(new HostHandler(service, _ => true), """{"v":1,"type":"status"}""");

        Assert.False(reply.GetProperty("ok").GetBoolean());
        Assert.Equal(HostErrors.ServiceUnavailable, reply.GetProperty("error").GetString());
    }

    [Fact]
    public async Task The_web_blocklist_is_passed_on_from_the_service()
    {
        JsonElement reply = await RunAsync(new HostHandler(new FakeService(), _ => true), """{"v":1,"type":"blocklist"}""");

        Assert.True(reply.GetProperty("ok").GetBoolean());
        Assert.Equal(3, reply.GetProperty("sequence").GetInt64());
        Assert.Equal(["bad.example", "phish.test"], reply.GetProperty("domains").EnumerateArray().Select(d => d.GetString()!));
    }

    [Theory]
    [InlineData("*.bad.example")]
    [InlineData("203.0.113.7")]
    [InlineData("localhost")]
    [InlineData("Bad.Example")]
    [InlineData("sites.google.com")]
    public async Task A_malformed_web_blocklist_from_the_service_is_not_passed_on(string domain)
    {
        var service = new FakeService { Blocklist = new() { Sequence = 3, Domains = ["ok.example", domain] } };
        JsonElement reply = await RunAsync(new HostHandler(service, _ => true), """{"v":1,"type":"blocklist"}""");

        Assert.False(reply.GetProperty("ok").GetBoolean());
        Assert.Equal(HostErrors.BlocklistFailed, reply.GetProperty("error").GetString());
    }

    [Fact]
    public void The_largest_allowed_web_blocklist_fits_in_one_native_message()
    {
        // 30,000 domains of the average length the character limit allows (26 characters each).
        int perDomain = Kshatriya.Updates.WebBlockList.MaxTotalChars / Kshatriya.Updates.WebBlockList.MaxDomains;
        List<string> domains = [.. Enumerable.Range(0, Kshatriya.Updates.WebBlockList.MaxDomains).Select(i => $"{i:D5}{new string('a', perDomain - 9)}.com")];
        Assert.Equal(perDomain, domains[0].Length);

        byte[] reply = HostHandler.BlocklistReply(new WebBlocklistReplyDto { Sequence = 1, Domains = domains });

        Assert.True(JsonDocument.Parse(reply).RootElement.GetProperty("ok").GetBoolean());
        Assert.True(reply.Length <= NativeFraming.MaxReplyBytes);
    }

    [Fact]
    public async Task Every_reply_matches_the_published_schema()
    {
        JsonSchema schema = await JsonSchema.FromFileAsync(Path.Combine(AppContext.BaseDirectory, "schemas", "browser-host.v1.schema.json"));
        var notScanned = new ScanItemResult { Path = @"C:\d\f.exe", Kind = ScanItemKind.File, Status = ScanStatus.NotScanned, Reason = ScanReason.TooLarge };
        byte[][] replies =
        [
            HostHandler.ScanReply(Report()),
            HostHandler.ScanReply(Report(Eicar())),
            HostHandler.ScanReply(Report(notScanned)),
            HostHandler.Error("error", HostErrors.InvalidRequest, "x"),
            HostHandler.BlocklistReply(new WebBlocklistReplyDto { Sequence = 0, Domains = [] }),
            HostHandler.BlocklistReply(new WebBlocklistReplyDto { Sequence = 7, Domains = ["bad.example"] }),
            HostHandler.BlocklistReply(new WebBlocklistReplyDto { Sequence = 7, Domains = ["*"] }),
            await new HostHandler(new FakeService(), _ => true).HandleAsync("""{"v":1,"type":"status"}"""u8.ToArray(), CancellationToken.None),
        ];

        foreach (byte[] reply in replies)
        {
            Assert.Empty(schema.Validate(Encoding.UTF8.GetString(reply)));
        }
    }
}
