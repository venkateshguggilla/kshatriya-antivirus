using System.Collections.ObjectModel;
using System.Globalization;
using Kshatriya.App.Infrastructure;
using Kshatriya.App.Services;
using Kshatriya.Core;
using Kshatriya.Presentation;
using Kshatriya.Protocol;

namespace Kshatriya.App.ViewModels;
/// <summary>One quarantined item.</summary>
public sealed record QuarantineRow(string Id, string QuarantinedLocal, string OriginalPath, string Detections, string User, long SizeBytes);

public sealed class QuarantineViewModel : PageViewModel
{
    private readonly IServiceGateway _gateway;
    private readonly IDialogs _dialogs;
    private QuarantineRow? _selected;

    public QuarantineViewModel(IServiceGateway gateway, IDialogs dialogs)
        : base("Quarantine", "Files Kshatriya moved into its encrypted vault", Glyphs.Lock)
    {
        _gateway = gateway;
        _dialogs = dialogs;
        RestoreCommand = new AsyncCommand(_ => RestoreAsync(toOtherLocation: false), _ => Selected is not null, ShowError);
        RestoreToCommand = new AsyncCommand(_ => RestoreAsync(toOtherLocation: true), _ => Selected is not null, ShowError);
        DeleteCommand = new AsyncCommand(_ => DeleteAsync(), _ => Selected is not null, ShowError);
    }

    public ObservableCollection<QuarantineRow> Items { get; } = [];

    public QuarantineRow? Selected { get => _selected; set => Set(ref _selected, value); }

    public AsyncCommand RestoreCommand { get; }

    public AsyncCommand RestoreToCommand { get; }

    public AsyncCommand DeleteCommand { get; }

    protected override async Task RefreshCoreAsync()
    {
        QuarantineListReplyDto list = await _gateway.ListQuarantineAsync(CancellationToken.None);
        Items.Clear();
        foreach (QuarantineItemDto i in list.Items)
        {
            Items.Add(new QuarantineRow(i.Id, HomeViewModel.Local(i.QuarantinedUtc), i.OriginalPath, i.Detections.Count == 0 ? "Added manually" : string.Join(", ", i.Detections), i.User, i.SizeBytes));
        }

        ShowInfo(null); // an empty list shows the page's empty state
    }

    private async Task RestoreAsync(bool toOtherLocation)
    {
        QuarantineRow row = Selected!;
        string? target = null;
        if (toOtherLocation)
        {
            target = _dialogs.PickRestoreLocation(Path.GetFileName(row.OriginalPath));
            if (target is null)
            {
                return;
            }
        }

        if (!_dialogs.Confirm(
                "Restore file?",
                $"Restore {Path.GetFileName(row.OriginalPath)} to {target ?? row.OriginalPath}?\n\nKshatriya quarantined it because of: {row.Detections}. Restore only if you are sure it is safe. It will be marked as downloaded from the internet and will be detected again by the next scan unless you exclude it."))
        {
            return;
        }

        OperationReplyDto reply = await _gateway.RestoreAsync(row.Id, target, CancellationToken.None);
        await RefreshCoreAsync();
        if (reply.Succeeded)
        {
            ShowInfo($"Restored to {reply.Path}.");
        }
        else
        {
            IsError = true;
            Message = $"Not restored ({reply.Code}): {reply.Message}";
        }
    }

    private async Task DeleteAsync()
    {
        QuarantineRow row = Selected!;
        if (!_dialogs.Confirm("Delete permanently?", $"Permanently delete the quarantined copy of {row.OriginalPath}? This cannot be undone."))
        {
            return;
        }

        OperationReplyDto reply = await _gateway.DeleteQuarantinedAsync(row.Id, CancellationToken.None);
        await RefreshCoreAsync();
        if (reply.Succeeded)
        {
            ShowInfo("Deleted permanently.");
        }
        else
        {
            IsError = true;
            Message = reply.Message;
        }
    }
}
