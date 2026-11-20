using System.Collections.ObjectModel;
using System.Globalization;
using Kshatriya.App.Infrastructure;
using Kshatriya.App.Services;
using Kshatriya.Core;
using Kshatriya.Presentation;
using Kshatriya.Protocol;

namespace Kshatriya.App.ViewModels;
/// <summary>One audit record.</summary>
public sealed record AuditRow(long Seq, string TimeLocal, string User, string Action, string Outcome, string Target, string Detail);

public sealed class AuditLogViewModel(IServiceGateway gateway) : PageViewModel("Actions log", "Audit log of quarantine, restore and exclusion changes", Glyphs.History)
{
    private string _chainState = string.Empty;

    public ObservableCollection<AuditRow> Records { get; } = [];

    public string ChainState { get => _chainState; private set => Set(ref _chainState, value); }

    private Tone _chainTone = Tone.Neutral;

    /// <summary>Success when the hash chain verified, critical when it did not.</summary>
    public Tone ChainTone { get => _chainTone; private set => Set(ref _chainTone, value); }

    protected override async Task RefreshCoreAsync()
    {
        AuditReplyDto reply = await gateway.GetAuditAsync(500, CancellationToken.None);
        Records.Clear();
        foreach (AuditRecordDto r in reply.Records)
        {
            Records.Add(new AuditRow(r.Seq, HomeViewModel.Local(r.TimeUtc), r.User, r.Action, r.Outcome, r.Target, r.Detail ?? string.Empty));
        }

        ChainTone = reply.ChainValid ? Tone.Success : Tone.Critical;
        ChainState = reply.ChainValid
            ? $"Integrity check passed: the hash chain of {Records.Count} shown record(s) and the full log is intact."
            : $"Integrity check FAILED: {reply.Problem} The log may have been edited.";
        ShowInfo(null);
    }
}
