using Kshatriya.Cli;

using var cancellation = new CancellationTokenSource();
Console.CancelKeyPress += (_, e) =>
{
    // First Ctrl+C asks for a graceful stop; the report is marked incomplete.
    e.Cancel = true;
    cancellation.Cancel();
};

await using Stream stdin = Console.OpenStandardInput();
return await CliApp.RunAsync(args, stdin, Console.Out, Console.Error, cancellation.Token);
