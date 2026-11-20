using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using Kshatriya.Mobile;
using Kshatriya.Tests.Shared;
using Kshatriya.Updates;

namespace Kshatriya.Mobile.Tests;

public sealed class UpdateCheckerTests : IDisposable
{
    private const string Source = "https://updates.example/android-content.kstu";
    private readonly string _folder = Path.Combine(Path.GetTempPath(), "kshatriya-update-" + Guid.NewGuid().ToString("N"));
    private readonly ECDsa _key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    private readonly DateTimeOffset _now = DateTimeOffset.UtcNow;
    private readonly FakeServer _server = new();

    public void Dispose()
    {
        _key.Dispose();
        _server.Dispose();
        if (Directory.Exists(_folder))
        {
            Directory.Delete(_folder, recursive: true);
        }
    }

    private MobileContentStore Store() =>
        new(Path.Combine(_folder, "content"), [ContentKey.FromSpki(_key.ExportSubjectPublicKeyInfo())]);

    private ContentUpdateChecker Checker(MobileContentStore store) => new(store, _server, Path.Combine(_folder, "updates"));

    private byte[] Package(long sequence, ECDsa? signer = null) => ContentPackage.Create(
        "stable", sequence, _now.AddMinutes(-1), _now.AddDays(30),
        [("android.hashdb", Encoding.UTF8.GetBytes(TestData.HashDb((TestData.Sha256Hex([(byte)sequence]), "Android.Test.Known", "malware"))))],
        signer ?? _key);

    [Theory]
    [InlineData("http://updates.example/a.kstu")]
    [InlineData("ftp://updates.example/a.kstu")]
    [InlineData("https://user:pass@updates.example/a.kstu")]
    [InlineData("updates.example/a.kstu")]
    [InlineData("")]
    [InlineData(null)]
    public void Only_plain_https_addresses_are_accepted(string? source)
    {
        Assert.NotNull(ContentUpdateChecker.ValidateSource(source));
    }

    [Fact]
    public void A_https_address_is_accepted()
    {
        Assert.Null(ContentUpdateChecker.ValidateSource(Source));
    }

    [Fact]
    public async Task A_newer_package_is_installed_and_the_same_one_again_is_up_to_date()
    {
        MobileContentStore store = Store();
        ContentUpdateChecker checker = Checker(store);
        _server.Respond(Package(3));

        UpdateCheckResult first = await checker.CheckAsync(Source, _now, CancellationToken.None);
        UpdateCheckResult second = await checker.CheckAsync(Source, _now, CancellationToken.None);

        Assert.Equal(UpdateCheckOutcome.Installed, first.Outcome);
        Assert.Equal(3, first.Sequence);
        Assert.Equal(UpdateCheckOutcome.UpToDate, second.Outcome);
        Assert.Equal(3, store.LoadActive(_now)!.Manifest.Sequence);
        Assert.Equal(_now, checker.Status.LastSuccessUtc);
    }

    [Fact]
    public async Task Requests_carry_only_a_generic_user_agent_and_the_servers_validators()
    {
        ContentUpdateChecker checker = Checker(Store());
        _server.Respond(Package(1), etag: "\"v1\"");
        await checker.CheckAsync(Source, _now, CancellationToken.None);
        _server.RespondNotModified();

        UpdateCheckResult again = await checker.CheckAsync(Source, _now, CancellationToken.None);

        Assert.Equal(UpdateCheckOutcome.UpToDate, again.Outcome);
        HttpRequestMessage request = _server.Requests[^1];
        Assert.Equal(ContentUpdateChecker.UserAgent, request.Headers.UserAgent.ToString());
        Assert.Equal("\"v1\"", Assert.Single(request.Headers.IfNoneMatch).ToString());
        Assert.False(request.Headers.Contains("Cookie"));
        Assert.Null(request.Headers.Authorization);
        Assert.Null(_server.Requests[0].Headers.IfNoneMatch.FirstOrDefault()); // the first request had nothing to send
    }

    [Fact]
    public async Task A_refused_download_is_not_remembered_as_current()
    {
        MobileContentStore store = Store();
        ContentUpdateChecker checker = Checker(store);
        using ECDsa stranger = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        _server.Respond(Package(2, stranger), etag: "\"bad\"");

        UpdateCheckResult refused = await checker.CheckAsync(Source, _now, CancellationToken.None);
        _server.Respond(Package(2), etag: "\"good\"");
        UpdateCheckResult retried = await checker.CheckAsync(Source, _now, CancellationToken.None);

        Assert.Equal(UpdateCheckOutcome.Failed, refused.Outcome);
        Assert.Equal(ContentErrors.UntrustedKey, refused.Code);
        Assert.Empty(_server.Requests[1].Headers.IfNoneMatch); // the refused package's tag was not kept
        Assert.Equal(UpdateCheckOutcome.Installed, retried.Outcome);
    }

    [Fact]
    public async Task An_older_package_from_the_source_is_refused()
    {
        MobileContentStore store = Store();
        Assert.True(store.Import(Package(5), _now).Succeeded);
        _server.Respond(Package(4));

        ContentUpdateChecker checker = Checker(store);
        UpdateCheckResult result = await checker.CheckAsync(Source, _now, CancellationToken.None);

        Assert.Equal(UpdateCheckOutcome.Failed, result.Outcome);
        Assert.Equal(ContentErrors.Rollback, result.Code);
        Assert.Equal(5, store.LoadActive(_now)!.Manifest.Sequence);
    }

    [Fact]
    public async Task Oversized_downloads_are_refused_before_and_while_reading()
    {
        ContentUpdateChecker checker = Checker(Store());
        _server.Respond(new byte[16], declaredLength: ContentUpdateChecker.MaxDownloadBytes + 1L);
        UpdateCheckResult declared = await checker.CheckAsync(Source, _now, CancellationToken.None);

        _server.Respond(new byte[ContentUpdateChecker.MaxDownloadBytes + 1], declaredLength: null);
        UpdateCheckResult streamed = await checker.CheckAsync(Source, _now, CancellationToken.None);

        Assert.Equal("too_large", declared.Code);
        Assert.Equal("too_large", streamed.Code);
    }

    [Fact]
    public async Task Server_and_network_errors_leave_the_content_unchanged()
    {
        MobileContentStore store = Store();
        Assert.True(store.Import(Package(1), _now).Succeeded);
        ContentUpdateChecker checker = Checker(store);

        _server.RespondStatus(HttpStatusCode.NotFound);
        UpdateCheckResult missing = await checker.CheckAsync(Source, _now, CancellationToken.None);
        _server.Fail(new HttpRequestException("no route to host"));
        UpdateCheckResult offline = await checker.CheckAsync(Source, _now.AddDays(1), CancellationToken.None);

        Assert.Equal("http_status", missing.Code);
        Assert.Equal("download_failed", offline.Code);
        Assert.Equal(1, store.LoadActive(_now)!.Manifest.Sequence);
        Assert.Equal(_now.AddDays(1), checker.Status.LastCheckUtc);
        Assert.Null(checker.Status.LastSuccessUtc);
    }

    [Fact]
    public async Task A_redirect_to_http_is_refused()
    {
        ContentUpdateChecker checker = Checker(Store());
        _server.Respond(Package(1), finalUri: new Uri("http://mirror.example/a.kstu"));

        UpdateCheckResult result = await checker.CheckAsync(Source, _now, CancellationToken.None);

        Assert.Equal("insecure_redirect", result.Code);
    }

    [Fact]
    public async Task A_damaged_state_file_costs_only_a_full_download()
    {
        ContentUpdateChecker checker = Checker(Store());
        File.WriteAllText(Path.Combine(_folder, "updates", "update-check.json"), "{ not json");
        _server.Respond(Package(1));

        UpdateCheckResult result = await checker.CheckAsync(Source, _now, CancellationToken.None);

        Assert.Equal(UpdateCheckOutcome.Installed, result.Outcome);
    }

    [Fact]
    public async Task Checks_started_together_run_one_after_the_other()
    {
        MobileContentStore store = Store();
        _server.Respond(Package(1));

        UpdateCheckResult[] results = await Task.WhenAll(
            Enumerable.Range(0, 4).Select(_ => Task.Run(() => Checker(store).CheckAsync(Source, _now, CancellationToken.None))));

        Assert.Single(results, r => r.Outcome == UpdateCheckOutcome.Installed);
        Assert.All(results, r => Assert.NotEqual(UpdateCheckOutcome.Failed, r.Outcome));
    }

    /// <summary>Answers each request with the response set up last, and records the requests.</summary>
    private sealed class FakeServer : HttpMessageHandler
    {
        private Func<HttpRequestMessage, HttpResponseMessage> _next = _ => new HttpResponseMessage(HttpStatusCode.InternalServerError);

        public List<HttpRequestMessage> Requests { get; } = [];

        public void Respond(byte[] body, string? etag = null, long? declaredLength = -1, Uri? finalUri = null) => _next = request =>
        {
            var content = new StreamContent(new MemoryStream(body));
            content.Headers.ContentLength = declaredLength == -1 ? body.Length : declaredLength;
            var response = new HttpResponseMessage(HttpStatusCode.OK) { Content = content };
            if (etag is not null)
            {
                response.Headers.ETag = EntityTagHeaderValue.Parse(etag);
            }

            if (finalUri is not null)
            {
                request.RequestUri = finalUri;
            }

            return response;
        };

        public void RespondNotModified() => _next = _ => new HttpResponseMessage(HttpStatusCode.NotModified);

        public void RespondStatus(HttpStatusCode status) => _next = _ => new HttpResponseMessage(status);

        public void Fail(Exception error) => _next = _ => throw error;

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Requests.Add(request);
            HttpResponseMessage response = _next(request);
            response.RequestMessage = request;
            return Task.FromResult(response);
        }
    }
}
