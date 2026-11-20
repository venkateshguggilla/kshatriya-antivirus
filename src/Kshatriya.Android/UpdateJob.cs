using Android.App;
using Android.App.Job;
using Android.Content;
using Kshatriya.Core;
using Kshatriya.Mobile;

namespace Kshatriya.AndroidApp;

/// <summary>
/// Automatic signature updates (ADR 0020, point 12): once a day, when the user turned them on, downloads the
/// signed package from the chosen https address and installs it if it verifies and is newer. After a new
/// update every installed app is checked against it (unchanged APKs come from the hash cache).
/// </summary>
[Service(Name = "com.kshatriya.antivirus.UpdateJob", Permission = "android.permission.BIND_JOB_SERVICE", Exported = true)]
public sealed class UpdateJob : JobService
{
    /// <summary>The project's own update address (a GitHub release asset).</summary>
    public const string DefaultSource = "https://github.com/venkateshguggilla/kshatriya-antivirus/releases/download/content-android/android-content.kstu";

    private const int JobId = 2;
    private const string Preferences = "updates";

    public static UpdateSettings ReadSettings(Context context)
    {
        ISharedPreferences prefs = context.GetSharedPreferences(Preferences, FileCreationMode.Private)!;
        return new UpdateSettings(prefs.GetBoolean("enabled", false), prefs.GetString("source", DefaultSource) ?? DefaultSource, prefs.GetBoolean("unmeteredOnly", true));
    }

    /// <summary>Saves the settings and schedules or cancels the daily check to match.</summary>
    public static void Apply(Context context, UpdateSettings settings)
    {
        using (ISharedPreferencesEditor editor = context.GetSharedPreferences(Preferences, FileCreationMode.Private)!.Edit()!)
        {
            editor.PutBoolean("enabled", settings.Enabled);
            editor.PutString("source", settings.Source);
            editor.PutBoolean("unmeteredOnly", settings.UnmeteredOnly);
            editor.Commit();
        }

        var scheduler = (JobScheduler)context.GetSystemService(Context.JobSchedulerService)!;
        scheduler.Cancel(JobId);
        if (!settings.Enabled)
        {
            return;
        }

        var builder = new JobInfo.Builder(JobId, new ComponentName(context, Java.Lang.Class.FromType(typeof(UpdateJob))));
        builder.SetPeriodic((long)TimeSpan.FromDays(1).TotalMilliseconds);
        builder.SetRequiredNetworkType(settings.UnmeteredOnly ? NetworkType.Unmetered : NetworkType.Any);
        builder.SetPersisted(true);
        scheduler.Schedule(builder.Build()!);
    }

    /// <summary>The checker for this app's content store.</summary>
    internal static ContentUpdateChecker Checker(Context context, Protection protection) =>
        new(protection.Store, s_handler, System.IO.Path.Combine(context.FilesDir!.AbsolutePath, "updates"));

    // One handler for the process (the platform's HTTP stack); no cookies are stored or sent.
    private static readonly HttpClientHandler s_handler = new() { UseCookies = false };

    /// <summary>One line about automatic updates, for the screen.</summary>
    internal static string StatusLine(Context context, Protection protection)
    {
        UpdateSettings settings = ReadSettings(context);
        ContentUpdateChecker checker = Checker(context, protection);
        UpdateCheckStatus status = checker.Status;
        string state = settings.Enabled ? "Automatic updates: on, daily" + (settings.UnmeteredOnly ? " on Wi-Fi." : ".") : "Automatic updates: off.";
        return status.LastCheckUtc is { } last
            ? $"{state} Last check {last.ToLocalTime():yyyy-MM-dd HH:mm}: {status.LastMessage}"
            : state;
    }

    public override bool OnStartJob(JobParameters? @params)
    {
        Task.Run(async () =>
        {
            try
            {
                await RunAsync(this, CancellationToken.None);
            }
            catch (Exception ex) when (ex is not OutOfMemoryException)
            {
                Android.Util.Log.Warn("Kshatriya", $"The update check failed: {ex.Message}");
            }
            finally
            {
                JobFinished(@params, wantsReschedule: false);
            }
        });
        return true;
    }

    public override bool OnStopJob(JobParameters? @params) => true;

    /// <summary>Checks for an update; after a new one, checks every installed app against it.</summary>
    internal static async Task<UpdateCheckResult> RunAsync(Context context, CancellationToken cancellationToken)
    {
        UpdateSettings settings = ReadSettings(context);
        Protection protection = Protection.Load(context);
        UpdateCheckResult result;
        result = await Checker(context, protection).CheckAsync(settings.Source, DateTimeOffset.UtcNow, cancellationToken);

        if (result.Outcome == UpdateCheckOutcome.Installed)
        {
            Protection updated = Protection.Load(context);
            var results = new List<MobileScanResult>();
            foreach (MobileScanTarget target in Protection.InstalledAppTargets(context.PackageManager!))
            {
                if (target.PackageName != context.PackageName)
                {
                    results.Add(await updated.Scanner.ScanAsync(target, cancellationToken));
                }
            }

            // Recorded for Home and History; only findings not reported before are notified (ADR 0021).
            IReadOnlyList<MobileFinding> fresh = Protection.Findings(context).Record(results, "update", "update", DateTimeOffset.UtcNow, allApps: true);
            Notifier.ShowFindings(context, fresh, "after a signature update");
            Protection.SaveCache(context);
            Android.Util.Log.Info("Kshatriya", $"Update {result.Sequence} installed; {fresh.Count} new finding(s) in installed apps.");
        }

        return result;
    }
}

/// <summary>The user's choices for automatic updates.</summary>
public sealed record UpdateSettings(bool Enabled, string Source, bool UnmeteredOnly);
