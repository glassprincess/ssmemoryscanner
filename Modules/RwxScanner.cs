using Jrss.Core;
using Jrss.Ui;

namespace Jrss.Modules;

internal static class RwxScanner
{
    public static void Run()
    {
        if (!OperatingSystem.IsWindows())
        {
            ConsoleUi.Warn("RWX scanner is only available on Windows.");
            return;
        }

        ConsoleUi.Section("RWX Memory Scanner — javaw.exe");
        ConsoleUi.Info("Looking for committed RWX regions in the Java process. RWX is a red flag, possible injection indicator.");
        ConsoleUi.Info("This is not an automatic verdict, but a reason for manual inspection.");

        using var process = JavaProcesses.Pick();
        if (process is null)
        {
            return;
        }

        try
        {
            var report = RwxMemoryScanner.ScanProcess(process);

            Console.WriteLine();
            ConsoleUi.Info($"PID {report.ProcessId} ({report.ProcessName})");
            ConsoleUi.Info($"RWX regions found: {report.RedDetections}");

            Console.WriteLine();
            switch (report.Flag)
            {
                case ScanFlag.Green:
                    ConsoleUi.Success(report.Verdict);
                    break;
                case ScanFlag.Yellow:
                    ConsoleUi.Warn(report.Verdict);
                    break;
                case ScanFlag.Red:
                    ConsoleUi.Error(report.Verdict);
                    break;
            }

            if (report.SuspiciousRegions.Count > 0)
            {
                Console.WriteLine();
                ConsoleUi.Section("Suspicious RWX Regions");
                foreach (var region in report.SuspiciousRegions.OrderByDescending(r => r.RegionSize))
                {
                    Console.WriteLine($"  ▸ 0x{region.BaseAddress.ToInt64():X16} — {region.RegionSize / 1024.0:F1} KB — {region.Analysis}");
                }
            }

            Console.WriteLine();
            ConsoleUi.Dim(report.Notice);
        }
        catch (PlatformNotSupportedException ex)
        {
            ConsoleUi.Warn(ex.Message);
        }
        catch (Exception ex)
        {
            ConsoleUi.Error($"Scan error: {ex.Message}");
        }
    }
}
