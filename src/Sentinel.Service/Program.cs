using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Hosting.WindowsServices;
using Microsoft.Extensions.Options;
using Sentinel.Runtime.Ipc;

namespace Sentinel.Service;

/// <summary>
/// Entry point. Without arguments it runs as the Windows service "SentinelService" (installed by
/// scripts/Install-SentinelService.ps1, running as LocalSystem). With <c>--dev</c> it runs in the
/// console as the current user, on a per-user pipe, with data under %LOCALAPPDATA%\Sentinel\dev.
/// </summary>
internal static class Program
{
    public static async Task<int> Main(string[] args)
    {
        bool dev = args.Contains("--dev");
        // Content root = install directory (admin-only), never the current directory, so a stray
        // appsettings.json next to wherever the service is started from is not picked up.
        HostApplicationBuilder builder = Host.CreateApplicationBuilder(new HostApplicationBuilderSettings
        {
            Args = [.. args.Where(a => a != "--dev")],
            ContentRootPath = AppContext.BaseDirectory,
        });
        builder.Services.AddWindowsService(o => o.ServiceName = ServiceEndpoint.DefaultServiceName);
        if (WindowsServiceHelpers.IsWindowsService())
        {
            builder.Services.AddSingleton<IHostLifetime, SentinelServiceLifetime>();
        }

        builder.Services.AddSingleton(new ServiceCoreOptions
        {
            Paths = dev ? ServicePaths.ForDevelopment() : ServicePaths.ForProduction(),
            Pipe = new PipeServerOptions(dev ? ServiceEndpoint.Development().PipeName : ServiceEndpoint.ProductionPipeName, Production: !dev),
        });
        builder.Services.AddHostedService<SentinelHostedService>();

        using IHost host = builder.Build();
        await host.RunAsync();
        return Environment.ExitCode;
    }
}

/// <summary>
/// Reports <see cref="Environment.ExitCode"/> to the Service Control Manager when the service stops, so a
/// failed start is a service failure (and triggers the restart actions set by the install script)
/// rather than a clean stop.
/// </summary>
internal sealed class SentinelServiceLifetime(
    IHostEnvironment environment,
    IHostApplicationLifetime applicationLifetime,
    ILoggerFactory loggerFactory,
    IOptions<HostOptions> hostOptions,
    IOptions<WindowsServiceLifetimeOptions> serviceOptions)
    : WindowsServiceLifetime(environment, applicationLifetime, loggerFactory, hostOptions, serviceOptions)
{
    protected override void OnStop()
    {
        ExitCode = Environment.ExitCode;
        base.OnStop();
    }
}

/// <summary>Runs <see cref="ServiceCore"/> for the lifetime of the host.</summary>
internal sealed class SentinelHostedService(ServiceCoreOptions options, ILogger<SentinelHostedService> logger, IHostApplicationLifetime lifetime) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        try
        {
            using ServiceCore core = await ServiceCore.StartAsync(options, logger, stoppingToken);
            await core.RunAsync(stoppingToken);
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
            // Stopping.
        }
        catch (Exception ex)
        {
            // Fail visibly (event log + non-zero exit) rather than run half-configured.
            Log.StartFailed(logger, ex, ex.Message);
            Environment.ExitCode = 1;
            lifetime.StopApplication();
        }
    }
}
