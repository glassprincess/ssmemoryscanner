using System.Diagnostics;
using Jrss.Ui;

namespace Jrss.Modules;

internal static class JavaProcesses
{
    public static Process? Pick()
    {
        var processes = Process.GetProcesses()
            .Where(IsJavaProcess)
            .OrderBy(process => process.Id)
            .ToList();
        if (processes.Count == 0)
        {
            ConsoleUi.Warn("javaw.exe processes not found.");
            return null;
        }

        Console.WriteLine();
        for (int i = 0; i < processes.Count; i++)
        {
            Console.WriteLine($"  {i + 1}  PID {processes[i].Id} — {processes[i].ProcessName}");
        }

        string input = ConsoleUi.Prompt("Select process number (Enter = first):");
        int index = string.IsNullOrEmpty(input) ? 0 : int.TryParse(input, out int selected) ? selected - 1 : -1;
        if (index < 0 || index >= processes.Count)
        {
            ConsoleUi.Error("Invalid number.");
            foreach (var process in processes) process.Dispose();
            return null;
        }

        var chosen = processes[index];
        for (int i = 0; i < processes.Count; i++)
        {
            if (i != index) processes[i].Dispose();
        }
        return chosen;
    }

    private static bool IsJavaProcess(Process process)
    {
        try
        {
            return process.ProcessName.Equals("javaw", StringComparison.OrdinalIgnoreCase);
        }
        catch
        {
            return false;
        }
    }
}
