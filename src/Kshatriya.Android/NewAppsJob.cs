using Android.App;
using Android.App.Job;
using Android.Content;
using Android.Content.PM;
using Kshatriya.Core;
using Kshatriya.Mobile;

namespace Kshatriya.AndroidApp;

/// <summary>
/// Checks new and updated apps about every 15 minutes (ADR 0020). Android 8+ does not deliver "app installed"
/// broadcasts to apps in the background, so the job asks which packages changed since the last check.
/// </summary>
[Service(Name = "com.kshatriya.antivirus.NewAppsJob", Permission = "android.permission.BIND_JOB_SERVICE", Exported = true)]
public sealed class NewAppsJob : JobService
{
    private const int JobId = 1;
    private const string Preferences = "new-apps";

    /// <summary>Schedules the periodic check (persisted across restarts). Safe to call repeatedly.</summary>
    public static void Schedule(Context context)
    {
        var scheduler = (JobScheduler)context.GetSystemService(Context.JobSchedulerService)!;
        if (scheduler.GetPendingJob(JobId) is not null)
        {
            return;
        }

        var builder = new JobInfo.Builder(JobId, new ComponentName(context, Java.Lang.Class.FromType(typeof(NewAppsJob))));
        builder.SetPeriodic((long)TimeSpan.FromMinutes(15).TotalMilliseconds);
        builder.SetPersisted(true);
        scheduler.Schedule(builder.Build()!);
    }

    public override bool OnStartJob(JobParameters? @params)
    {
        Task.Run(() =>
        {
            try
            {
                CheckChangedApps(this);
            }
            finally
            {
                JobFinished(@params, wantsReschedule: false);
            }
        });
        return true; // still running on the background task
    }

    public override bool OnStopJob(JobParameters? @params) => true; // run again at the next opportunity

    /// <summary>Scans the apps changed since the last check and notifies about findings.</summary>
    internal static int CheckChangedApps(Context context)
    {
        ISharedPreferences prefs = context.GetSharedPreferences(Preferences, FileCreationMode.Private)!;
        PackageManager packages = context.PackageManager!;
        int boot = Android.Provider.Settings.Global.GetInt(context.ContentResolver, Android.Provider.Settings.Global.BootCount, 0);
        bool firstRun = !prefs.Contains("sequence");

        // The sequence number restarts at 0 on every boot.
        int sequence = prefs.GetInt("boot", -1) == boot ? prefs.GetInt("sequence", 0) : 0;
        ChangedPackages? changes = packages.GetChangedPackages(sequence);
        int next = changes?.SequenceNumber ?? sequence;
        int found = 0;
        if (!firstRun && changes is not null)
        {
            Protection protection = Protection.Load(context);
            foreach (string name in changes.PackageNames.Distinct())
            {
                if (name == context.PackageName || Protection.FindApp(packages, name) is not { } app)
                {
                    continue; // ourselves, or removed
                }

                foreach (MobileScanTarget target in Protection.AppTargets(packages, app))
                {
                    MobileScanResult result = protection.Scanner.ScanAsync(target, CancellationToken.None).GetAwaiter().GetResult();
                    if (result.Item.Status is ScanStatus.Detected or ScanStatus.Suspicious)
                    {
                        found++;
                        (_, string text) = MobileText.Describe(result);
                        Notifier.Show(context, 1000 + Math.Abs(name.GetHashCode(StringComparison.Ordinal) % 100_000), "Threat found in a new app", text + ". Open Kshatriya to review it.");
                    }
                }
            }
        }

        // The first run only records the starting point, so apps installed earlier are not reported here.
        using ISharedPreferencesEditor editor = prefs.Edit()!;
        editor.PutInt("boot", boot);
        editor.PutInt("sequence", next);
        editor.Apply();
        return found;
    }
}
