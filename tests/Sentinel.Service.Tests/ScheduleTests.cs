using Sentinel.Service;

namespace Sentinel.Service.Tests;

public class ScheduleTests
{
    private static readonly TimeZoneInfo Utc = TimeZoneInfo.Utc;

    private static ScheduledScan Weekly(DayOfWeek day, int hour, int minute = 0) =>
        new("weekly", new HashSet<DayOfWeek> { day }, new TimeOnly(hour, minute), [@"C:\Users"]);

    [Fact]
    public void Next_finds_the_following_occurrence()
    {
        ScheduledScan scan = Weekly(DayOfWeek.Sunday, 3);
        var wednesday = new DateTimeOffset(2026, 11, 4, 12, 0, 0, TimeSpan.Zero);

        Assert.Equal(new DateTimeOffset(2026, 11, 8, 3, 0, 0, TimeSpan.Zero), ScheduleCalculator.Next(scan, wednesday, Utc));
    }

    [Fact]
    public void Next_is_strictly_after_the_reference_time()
    {
        ScheduledScan scan = Weekly(DayOfWeek.Sunday, 3);
        var exactly = new DateTimeOffset(2026, 11, 8, 3, 0, 0, TimeSpan.Zero);

        Assert.Equal(exactly.AddDays(7), ScheduleCalculator.Next(scan, exactly, Utc));
    }

    [Fact]
    public void Previous_finds_the_last_occurrence_at_or_before()
    {
        ScheduledScan scan = Weekly(DayOfWeek.Sunday, 3);
        var wednesday = new DateTimeOffset(2026, 11, 4, 12, 0, 0, TimeSpan.Zero);

        Assert.Equal(new DateTimeOffset(2026, 11, 1, 3, 0, 0, TimeSpan.Zero), ScheduleCalculator.Previous(scan, wednesday, Utc));
    }

    [Fact]
    public void A_schedule_that_never_ran_is_not_due_immediately()
    {
        ScheduledScan scan = Weekly(DayOfWeek.Sunday, 3);

        Assert.False(ScheduleCalculator.IsDue(scan, lastRun: null, DateTimeOffset.UtcNow, Utc));
    }

    [Fact]
    public void A_missed_occurrence_is_due_once()
    {
        ScheduledScan scan = Weekly(DayOfWeek.Sunday, 3);
        var lastRun = new DateTimeOffset(2026, 10, 25, 3, 0, 5, TimeSpan.Zero);
        var tuesdayAfterMissedSunday = new DateTimeOffset(2026, 11, 3, 9, 0, 0, TimeSpan.Zero);

        Assert.True(ScheduleCalculator.IsDue(scan, lastRun, tuesdayAfterMissedSunday, Utc));
        Assert.False(ScheduleCalculator.IsDue(scan, tuesdayAfterMissedSunday, tuesdayAfterMissedSunday.AddHours(1), Utc));
    }

    [Fact]
    public void Daily_schedule_runs_every_day()
    {
        var scan = new ScheduledScan("daily", Enum.GetValues<DayOfWeek>().ToHashSet(), new TimeOnly(1, 15), [@"C:\"]);
        var now = new DateTimeOffset(2026, 11, 4, 2, 0, 0, TimeSpan.Zero);

        Assert.Equal(new DateTimeOffset(2026, 11, 5, 1, 15, 0, TimeSpan.Zero), ScheduleCalculator.Next(scan, now, Utc));
    }

    [Fact]
    public void Time_inside_a_daylight_saving_gap_runs_after_the_gap()
    {
        // W. Europe: clocks jump from 02:00 to 03:00 local on 2026-03-29.
        TimeZoneInfo zone = TimeZoneInfo.FindSystemTimeZoneById("W. Europe Standard Time");
        ScheduledScan scan = Weekly(DayOfWeek.Sunday, 2, 30);
        var saturday = new DateTimeOffset(2026, 3, 28, 12, 0, 0, TimeSpan.FromHours(1));

        DateTimeOffset next = ScheduleCalculator.Next(scan, saturday, zone);

        Assert.Equal(new DateTimeOffset(2026, 3, 29, 3, 0, 0, TimeSpan.FromHours(2)), next);
    }
}
