using System.Collections.ObjectModel;
using Kshatriya.App.Infrastructure;
using Kshatriya.App.Services;
using Kshatriya.Protocol;

namespace Kshatriya.App.ViewModels;

/// <summary>
/// Signature and rule content (ADR 0008): which signed update is installed, until when, and importing a
/// newer package. The service verifies the signature before reading anything else and refuses older updates.
/// </summary>
public sealed class UpdatesViewModel : PageViewModel
{
    private readonly IServiceGateway _gateway;
    private readonly IDialogs _dialogs;
    private string _installed = "-";
    private string _validity = "-";
    private Tone _tone = Tone.Neutral;

    public UpdatesViewModel(IServiceGateway gateway, IDialogs dialogs)
        : base("Updates", "Signatures and rules, delivered only as signed packages", Glyphs.Download)
    {
        _gateway = gateway;
        _dialogs = dialogs;
        ImportCommand = new AsyncCommand(_ => RunAsync(ImportAsync), onError: ShowError);
    }

    /// <summary>"Update 42 (stable)" or "Built-in signatures only".</summary>
    public string Installed { get => _installed; private set => Set(ref _installed, value); }

    public string Validity { get => _validity; private set => Set(ref _validity, value); }

    public Tone Tone { get => _tone; private set => Set(ref _tone, value); }

    /// <summary>One line per engine with its content version.</summary>
    public ObservableCollection<string> Engines { get; } = [];

    public AsyncCommand ImportCommand { get; }

    public string Explanation { get; } =
        "Kshatriya accepts only signed .kstu packages. Their signature is checked before anything else in them is read, " +
        "an update older than the installed one is refused, and an expired package is not installed. A trusted key can only add signatures and lists; it cannot turn protection off.";

    protected override async Task RefreshCoreAsync()
    {
        var (_, status) = await _gateway.GetStatusAsync(CancellationToken.None);
        Show(status);
    }

    private void Show(StatusReplyDto status)
    {
        ContentStatusDto c = status.Content;
        if (c.Sequence == 0)
        {
            (Installed, Validity, Tone) = ("Built-in signatures only", "No signed update is installed." + (c.Problem is null ? string.Empty : $" {c.Problem}"), Tone.Neutral);
        }
        else
        {
            Installed = $"Update {c.Sequence}" + (c.Channel is null ? string.Empty : $" ({c.Channel})");
            (Validity, Tone) = c.Expired
                ? ($"Expired on {HomeViewModel.Local(c.ExpiresUtc)}. Install a newer update.", Tone.Caution)
                : ($"Valid until {HomeViewModel.Local(c.ExpiresUtc)}." + (c.Problem is null ? string.Empty : $" {c.Problem}"), Tone.Success);
        }

        Engines.Clear();
        foreach (EngineInfoDto e in status.Engines)
        {
            Engines.Add($"{e.Id} {e.Version}  [{e.ContentVersion}]");
        }
    }

    private async Task ImportAsync()
    {
        string? path = _dialogs.PickUpdatePackage();
        if (path is null)
        {
            return;
        }

        ContentImportReplyDto reply = await _gateway.ImportContentAsync(path, CancellationToken.None);
        if (reply.Succeeded)
        {
            ShowInfo($"Update {reply.Sequence} is installed" + (reply.ExpiresUtc is null ? "." : $", valid until {HomeViewModel.Local(reply.ExpiresUtc)}."));
        }
        else
        {
            IsError = true;
            Message = $"The update was not installed ({reply.Code}). {reply.Message}".TrimEnd();
        }

        var (_, status) = await _gateway.GetStatusAsync(CancellationToken.None);
        Show(status);
    }
}
