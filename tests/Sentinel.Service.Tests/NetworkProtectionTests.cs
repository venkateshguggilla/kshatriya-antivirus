using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using Sentinel.Protocol;
using Sentinel.Runtime.Ipc;
using Sentinel.Tests.Shared;
using Sentinel.Updates;
using Sentinel.Service.Net;

namespace Sentinel.Service.Tests;

public class NetworkProtectionTests
{
    private static bool IsElevatedAdmin => new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator);

    [Fact]
    public void Blocklists_parse_addresses_and_ranges()
    {
        var entries = NetBlockList.Parse("# sentinel-netblock v1\n# comment\n203.0.113.7 Example.C2\n198.51.100.0/24 Example.Range\n2001:db8::1 Example.V6\n2001:db8:1::/48\n", "test");

        Assert.Equal(["203.0.113.7/32", "198.51.100.0/24", "2001:db8::1/128", "2001:db8:1::/48"], entries.Select(e => e.ToString()));
        Assert.Equal("Example.C2", entries[0].Name);
        Assert.Equal("unnamed", entries[3].Name);
    }

    [Theory]
    [InlineData("0.0.0.0")]
    [InlineData("127.0.0.1")]
    [InlineData("10.0.0.0/8")]
    [InlineData("169.254.1.1")]
    [InlineData("224.0.0.1")]
    [InlineData("::1")]
    [InlineData("fe80::1")]
    [InlineData("2001:db8::/32")]
    [InlineData("1.2")]
    [InlineData("203.0.113.7/33")]
    [InlineData("example.com")]
    public void Dangerous_or_invalid_entries_reject_the_whole_list(string entry) =>
        Assert.Throws<FormatException>(() => NetBlockList.Parse($"# sentinel-netblock v1\n203.0.113.9 ok\n{entry} bad\n", "test"));

    [Fact]
    public void Random_input_is_rejected_cleanly()
    {
        var random = new Random(10);
        const string alphabet = "0123456789abcdef.:/ \n#xyz-";
        for (int i = 0; i < 20_000; i++)
        {
            var text = new StringBuilder("# sentinel-netblock v1\n");
            for (int j = random.Next(1, 40); j > 0; j--)
            {
                text.Append(alphabet[random.Next(alphabet.Length)]);
            }

            try
            {
                foreach (BlockEntry entry in NetBlockList.Parse(text.ToString(), "fuzz"))
                {
                    Assert.InRange(entry.PrefixLength, entry.IsIPv4 ? 16 : 48, entry.IsIPv4 ? 32 : 128);
                    Assert.False(IPAddress.IsLoopback(entry.Address));
                }
            }
            catch (FormatException)
            {
                // Expected for most inputs.
            }
        }
    }

    [Fact]
    public void Native_structures_match_the_sdk_layouts() =>
        Assert.Equal((72, 200, 40, 17), WfpBlocker.StructSizes);

    [Fact]
    public void A_list_without_the_header_is_rejected() =>
        Assert.Throws<FormatException>(() => NetBlockList.Parse("203.0.113.7\n", "test"));

    [Fact]
    public async Task The_wfp_blocker_blocks_and_unblocks_connections_when_elevated()
    {
        if (!IsElevatedAdmin)
        {
            Assert.Throws<UnauthorizedAccessException>(() =>
            {
                using WfpBlocker blocker = WfpBlocker.Open();
                blocker.Replace([new BlockEntry(IPAddress.Parse("203.0.113.7"), 32, "test")]);
            });
            return;
        }

        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        int port = ((IPEndPoint)listener.LocalEndpoint).Port;
        Task accept = AcceptForeverAsync(listener);

        await ConnectAsync(port); // reachable before

        using (WfpBlocker blocker = WfpBlocker.Open())
        {
            // The test-only port condition keeps the block from affecting anything else on the machine.
            blocker.Replace([new BlockEntry(IPAddress.Loopback, 32, "test")], remotePort: (ushort)port);
            Assert.Equal(1, blocker.FilterCount);
            var refused = await Assert.ThrowsAsync<SocketException>(() => ConnectAsync(port));
            Assert.Equal(SocketError.AccessDenied, refused.SocketErrorCode);

            blocker.Replace([], remotePort: (ushort)port);
            await ConnectAsync(port);

            blocker.Replace([new BlockEntry(IPAddress.Loopback, 32, "test")], remotePort: (ushort)port);
        }

        // Closing the dynamic session removes every filter.
        await ConnectAsync(port);
        listener.Stop();
        await accept.ContinueWith(_ => { }, TaskScheduler.Default);
    }

    [Fact]
    public async Task Imported_blocklists_drive_network_protection_and_bad_ones_are_refused()
    {
        using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var temp = new TempDirectory();
        var settings = new ServiceSettings { NetworkProtection = true, ContentKeys = [Convert.ToBase64String(key.ExportSubjectPublicKeyInfo())] };
        await using RunningService service = await RunningService.StartAsync(settings);
        await using ServiceClient client = await service.ConnectAsync();
        DateTimeOffset now = DateTimeOffset.UtcNow;
        string Package(string name, long sequence, string netblock) => temp.File(name, ContentPackage.Create(
            "stable", sequence, now.AddMinutes(-1), now.AddDays(1), [("block.netblock", Encoding.UTF8.GetBytes(netblock))], key));

        ContentImportReplyDto good = await client.ImportContentAsync(Package("a.sntu", 1, "# sentinel-netblock v1\n203.0.113.7 Test.Blocked\n"));
        ContentImportReplyDto bad = await client.ImportContentAsync(Package("b.sntu", 2, "# sentinel-netblock v1\n127.0.0.1 loopback\n"));
        NetworkStatusDto network = (await client.GetStatusAsync()).Network;

        Assert.True(good.Succeeded, good.Message);
        Assert.Equal(ContentErrors.ContentInvalid, bad.Code);
        Assert.Equal(1, (await client.GetStatusAsync()).Content.Sequence);
        if (IsElevatedAdmin)
        {
            Assert.Equal("blocking 1 address range(s)", network.State);
        }
        else
        {
            Assert.StartsWith("unavailable:", network.State, StringComparison.Ordinal);
        }
    }

    private static async Task ConnectAsync(int port)
    {
        using var client = new TcpClient();
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        await client.ConnectAsync(IPAddress.Loopback, port, timeout.Token);
    }

    private static async Task AcceptForeverAsync(TcpListener listener)
    {
        while (true)
        {
            using TcpClient _ = await listener.AcceptTcpClientAsync();
        }
    }
}
