using System.Collections.ObjectModel;
using System.Globalization;
using Kshatriya.App.Infrastructure;
using Kshatriya.App.Services;
using Kshatriya.Core;
using Kshatriya.Presentation;
using Kshatriya.Protocol;

namespace Kshatriya.App.ViewModels;
/// <summary>One exclusion.</summary>
public sealed record ExclusionRow(string Kind, string Value);

public sealed class ExclusionsViewModel : PageViewModel
{
    private readonly IServiceGateway _gateway;
    private readonly IDialogs _dialogs;
    private ExclusionRow? _selected;
    private string _newValue = string.Empty;

    public ExclusionsViewModel(IServiceGateway gateway, IDialogs dialogs)
        : base("Exclusions", "Folders, files and hashes Kshatriya does not scan", Glyphs.Filter)
    {
        _gateway = gateway;
        _dialogs = dialogs;
        AddFolderCommand = new AsyncCommand(_ => AddFoldersAsync(), onError: ShowError);
        AddValueCommand = new AsyncCommand(_ => ChangeAsync(add: true, NewValue.Trim()), _ => !string.IsNullOrWhiteSpace(NewValue), ShowError);
        RemoveCommand = new AsyncCommand(_ => ChangeAsync(add: false, Selected!.Value), _ => Selected is not null, ShowError);
    }

    public ObservableCollection<ExclusionRow> Items { get; } = [];

    public ExclusionRow? Selected { get => _selected; set => Set(ref _selected, value); }

    public string NewValue { get => _newValue; set => Set(ref _newValue, value); }

    public AsyncCommand AddFolderCommand { get; }

    public AsyncCommand AddValueCommand { get; }

    public AsyncCommand RemoveCommand { get; }

    protected override async Task RefreshCoreAsync() => Show(await _gateway.GetExclusionsAsync(CancellationToken.None));

    private async Task AddFoldersAsync()
    {
        foreach (string folder in _dialogs.PickFolders())
        {
            await ChangeAsync(add: true, folder);
        }
    }

    private async Task ChangeAsync(bool add, string value)
    {
        if (add && !_dialogs.Confirm("Add exclusion?", $"Kshatriya will stop scanning {value}. Excluded items are still listed as skipped in every report. This does not change Microsoft Defender."))
        {
            return;
        }

        Show(await _gateway.ChangeExclusionAsync(add, value, CancellationToken.None));
        NewValue = string.Empty;
        ShowInfo(add ? $"Excluded {value}." : $"Removed the exclusion for {value}.");
    }

    private void Show(ExclusionsReplyDto reply)
    {
        Items.Clear();
        foreach (string p in reply.Paths)
        {
            Items.Add(new ExclusionRow("Path", p));
        }

        foreach (string h in reply.Sha256)
        {
            Items.Add(new ExclusionRow("SHA-256", h));
        }

        ShowInfo(null); // an empty list shows the page's empty state
    }
}
