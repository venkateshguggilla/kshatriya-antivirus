using System.Collections.ObjectModel;
using System.Globalization;
using Kshatriya.App.Infrastructure;
using Kshatriya.App.Services;
using Kshatriya.Core;
using Kshatriya.Presentation;
using Kshatriya.Protocol;

namespace Kshatriya.App.ViewModels;
/// <summary>One finding in the detections history.</summary>
public sealed record DetectionRow(string TimeLocal, string Status, string Path, string Names, string Source, string Action)
{
    public Tone Tone => Status == "Detected" ? Tone.Critical : Tone.Caution;
}

public sealed class DetectionsViewModel(IServiceGateway gateway) : PageViewModel("Detections", "Recent findings from scans and real-time monitoring", Glyphs.Warning)
{
    public ObservableCollection<DetectionRow> Items { get; } = [];

    protected override async Task RefreshCoreAsync()
    {
        DetectionsReplyDto reply = await gateway.GetDetectionsAsync(200, CancellationToken.None);
        Items.Clear();
        foreach (DetectionRecordDto d in reply.Items)
        {
            Items.Add(new DetectionRow(HomeViewModel.Local(d.TimeUtc), d.Status == "detected" ? "Detected" : "Suspicious", d.Path, string.Join(", ", d.Names), d.Source, d.Action));
        }

        ShowInfo(null); // an empty list shows the page's empty state
    }
}
