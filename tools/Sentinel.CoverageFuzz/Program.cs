// Coverage-guided fuzzing for Sentinel's binary parsers (PE, ZIP, signed content packages).
//   dotnet run -c Release --project tools/Sentinel.CoverageFuzz -- <pe|zip|content|all> [seconds] [seed] [outDir]
//
// The tool copies its own build output to a temporary folder, instruments the parser assemblies there
// with SharpFuzz (AFL-style edge coverage), and re-runs itself from the copy. The instrumented run keeps
// every input that reaches new code (an in-process, AFL-style loop; no native libFuzzer is needed) and
// mutates from that corpus. Unexpected exceptions and hangs are failures; inputs are saved to outDir.
// The corpus is kept in outDir/corpus/<target> and reused by later runs.

using System.Diagnostics;
using System.Globalization;
using Sentinel.CoverageFuzz;

const string InstrumentedVariable = "SENTINEL_COVFUZZ_INSTRUMENTED";
string[] instrumentedAssemblies = ["Sentinel.Engines.Pe.dll", "Sentinel.Scanning.dll", "Sentinel.Updates.dll"];

string target = args.Length > 0 ? args[0] : "all";
int seconds = args.Length > 1 ? int.Parse(args[1], CultureInfo.InvariantCulture) : 60;
int seed = args.Length > 2 ? int.Parse(args[2], CultureInfo.InvariantCulture) : 20261109;
string outDir = Path.GetFullPath(args.Length > 3 ? args[3] : Path.Combine(Path.GetTempPath(), "sentinel-coverage-fuzz"));
string[] targets = target == "all" ? ["pe", "zip", "content"] : [target];
if (targets.Any(t => !Targets.Names.Contains(t)))
{
    Console.Error.WriteLine($"Unknown target '{target}'. Use one of: {string.Join(", ", Targets.Names)}, all.");
    return 3;
}

if (Environment.GetEnvironmentVariable(InstrumentedVariable) != "1")
{
    return Launcher.RunInstrumented(instrumentedAssemblies, InstrumentedVariable, [target, seconds.ToString(CultureInfo.InvariantCulture), seed.ToString(CultureInfo.InvariantCulture), outDir]);
}

int failures = 0;
foreach (string name in targets)
{
    failures += new GuidedFuzzer(name, Targets.Create(name), Targets.Seeds(name), seed, outDir).Run(TimeSpan.FromSeconds(seconds));
}

return failures == 0 ? 0 : 1;

namespace Sentinel.CoverageFuzz
{
    internal static class Launcher
    {
        /// <summary>Copies the build output, instruments the parser assemblies in the copy and runs the copy.</summary>
        public static int RunInstrumented(string[] assemblies, string variable, string[] arguments)
        {
            string source = AppContext.BaseDirectory;
            string work = Path.Combine(Path.GetTempPath(), $"sentinel-covfuzz-{Guid.NewGuid():N}");
            try
            {
                CopyDirectory(source, work);
                foreach (string assembly in assemblies)
                {
                    string path = Path.Combine(work, assembly);
                    // Instrument only Sentinel's own types: the parsers and the code paths they drive.
                    SharpFuzz.Fuzzer.Instrument(path, type => type.StartsWith("Sentinel.", StringComparison.Ordinal), SharpFuzz.Options.Value);
                    Console.WriteLine($"Instrumented {assembly}");
                }

                var start = new ProcessStartInfo(Path.Combine(work, "Sentinel.CoverageFuzz.exe")) { UseShellExecute = false };
                foreach (string argument in arguments)
                {
                    start.ArgumentList.Add(argument);
                }

                start.Environment[variable] = "1";
                using Process child = Process.Start(start) ?? throw new InvalidOperationException("Could not start the instrumented fuzzer.");
                child.WaitForExit();
                return child.ExitCode;
            }
            finally
            {
                try
                {
                    Directory.Delete(work, recursive: true);
                }
                catch (IOException)
                {
                    // Best effort: the temp folder is cleaned up by the system eventually.
                }
            }
        }

        private static void CopyDirectory(string from, string to)
        {
            Directory.CreateDirectory(to);
            foreach (string file in Directory.EnumerateFiles(from, "*", SearchOption.AllDirectories))
            {
                string destination = Path.Combine(to, Path.GetRelativePath(from, file));
                Directory.CreateDirectory(Path.GetDirectoryName(destination)!);
                File.Copy(file, destination);
            }
        }
    }
}
