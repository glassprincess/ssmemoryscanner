using System.Diagnostics;

namespace Jrss.ClassDumper;

public static class ExternalClassDumper
{
    /// <summary>
    /// Запускает java-агент (external-dumper-agent.jar), который через штатный
    /// Java Attach API подключается к уже работающему процессу javaw.exe (pid)
    /// и дампит байткод всех загруженных классов в outputDir. Это тот же
    /// официальный механизм, на котором работают VisualVM/jcmd/профилировщики —
    /// не инжект в привычном смысле, а штатная функция JVM (работает, только
    /// если целевая JVM не запущена с -XX:+DisableAttachMechanism).
    ///
    /// Требует установленный JDK (не просто JRE) на машине ОПЕРАТОРА — именно
    /// оператор подключается к целевому процессу, а не наоборот, так что сама
    /// Minecraft-java не обязана иметь Attach API/tools.
    /// </summary>
    public static (bool ok, string message) Dump(int pid, string outputDir)
    {
        var javaExe = FindJavaExecutable();
        if (javaExe is null)
        {
            return (false, "java.exe not found in PATH/JAVA_HOME. External dumper requires a JDK installed on this machine (not necessarily on the player's machine).");
        }

        var agentJar = Path.Combine(AppContext.BaseDirectory, "ClassDumper", "agent", "external-dumper-agent.jar");
        if (!File.Exists(agentJar))
        {
            return (false, $"Agent not found: {agentJar}.");
        }

        try
        {
            Directory.CreateDirectory(outputDir);

            var psi = new ProcessStartInfo
            {
                FileName = javaExe,
                ArgumentList = { "-jar", agentJar, pid.ToString(), outputDir },
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true,
            };

            using var proc = Process.Start(psi);
            if (proc is null)
            {
                return (false, "failed to start java.exe");
            }

            string stdout = proc.StandardOutput.ReadToEnd();
            string stderr = proc.StandardError.ReadToEnd();
            proc.WaitForExit(30000);

            if (proc.ExitCode != 0)
            {
                return (false, string.IsNullOrWhiteSpace(stderr) ? stdout : stderr);
            }

            var summaryPath = Path.Combine(outputDir, "_dump_summary.txt");
            var summary = File.Exists(summaryPath) ? File.ReadAllText(summaryPath) : stdout;
            return (true, summary);
        }
        catch (Exception ex)
        {
            return (false, ex.Message);
        }
    }

    private static string? FindJavaExecutable()
    {
        var javaHome = Environment.GetEnvironmentVariable("JAVA_HOME");
        if (!string.IsNullOrEmpty(javaHome))
        {
            var candidate = Path.Combine(javaHome, "bin", OperatingSystem.IsWindows() ? "java.exe" : "java");
            if (File.Exists(candidate))
            {
                return candidate;
            }
        }

        var pathVar = Environment.GetEnvironmentVariable("PATH") ?? "";
        var exeName = OperatingSystem.IsWindows() ? "java.exe" : "java";
        foreach (var dir in pathVar.Split(Path.PathSeparator))
        {
            try
            {
                var candidate = Path.Combine(dir, exeName);
                if (File.Exists(candidate))
                {
                    return candidate;
                }
            }
            catch
            {
                // некорректная запись в PATH — пропускаем
            }
        }

        return null;
    }
}
