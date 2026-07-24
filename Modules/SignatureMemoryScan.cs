using Jrss.Core;
using Jrss.Ui;

namespace Jrss.Modules;

internal static class SignatureMemoryScan
{
    public static void Run(SignatureDatabase database)
    {
        ConsoleUi.Section("Скан памяти javaw.exe");
        ConsoleUi.Info($"База сигнатур: {database.FamilyCount} семейств, {database.PatternCount} сигнатур.");

        using var process = JavaProcesses.Pick();
        if (process is null)
        {
            return;
        }

        var detection = ProcessMemoryScanner.ScanProcess(process, database, progress =>
            ConsoleUi.ProgressBar("Сканирование", progress));
        ConsoleUi.RenderScanResult(detection);
    }
}
