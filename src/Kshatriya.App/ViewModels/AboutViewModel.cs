using System.Collections.ObjectModel;
using System.Globalization;
using Kshatriya.App.Infrastructure;
using Kshatriya.App.Services;
using Kshatriya.Core;
using Kshatriya.Presentation;
using Kshatriya.Protocol;

namespace Kshatriya.App.ViewModels;
public sealed class AboutViewModel(IServiceGateway gateway) : PageViewModel("Help and about", "Version, status and limitations", Glyphs.Info)
{
    public string Version { get; } = $"Kshatriya Antivirus {AppInfo.Version}";

    public string Endpoint => $"Talking to the {gateway.EndpointDescription}.";

    public string Status { get; } =
        "Prototype. Kshatriya is an early-stage, defensive security project. It is not a replacement for Microsoft Defender or any commercial antivirus and makes no claim of equivalent protection. Keep Microsoft Defender turned on.";

    public string Limitations { get; } =
        "Scans run on demand, on a schedule, and (when enabled) shortly after files are written or programs start. This user-mode monitoring cannot block a file or program before it runs; there is no real-time protection yet in that sense. Quarantine removes only confirmed, high-confidence detections and only when you ask for it. Running programs are not stopped.";

    protected override Task RefreshCoreAsync() => Task.CompletedTask;
}
