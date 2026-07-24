using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using Jrss.Ui;

namespace Jrss.Modules;

internal static class ModuleInspector
{
    private const uint ListModules32Bit = 0x01;
    private const uint ListModules64Bit = 0x02;
    private const uint ListModulesAll = ListModules32Bit | ListModules64Bit;

    public static void Run()
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException("Инспектор модулей поддерживается только на Windows.");
        }

        ConsoleUi.Section("JVMTI / инжект-инспектор");
        ConsoleUi.Info("Ищем DLL в java/javaw вне System32, SysWOW64 и каталога Java. Это эвристика, не автоматический вердикт.");
        using var process = JavaProcesses.Pick();
        if (process is null)
        {
            return;
        }

        string? javaDirectory;
        try
        {
            javaDirectory = Path.GetDirectoryName(process.MainModule?.FileName);
        }
        catch
        {
            javaDirectory = null;
        }

        try
        {
            var modules = EnumerateModules(process.Id);
            modules.Sort((a, b) => string.Compare(a.FileName, b.FileName, StringComparison.OrdinalIgnoreCase));

            int flagged = 0;
            foreach (var module in modules)
            {
                if (IsExpectedLocation(module.FileName, javaDirectory))
                {
                    continue;
                }

                flagged++;
                ConsoleUi.Warn($"▸ {module.Name} — {module.FileName}");
            }

            Console.WriteLine();
            if (flagged == 0)
            {
                ConsoleUi.Success("Все загруженные модули лежат в ожидаемых директориях.");
            }
            else
            {
                ConsoleUi.Warn($"Найдено модулей вне ожидаемых директорий: {flagged}. Проверь их подпись, издателя и репутацию вручную.");
            }
        }
        catch (Exception ex) when (ex is InvalidOperationException or Win32Exception or NotSupportedException)
        {
            ConsoleUi.Warn($"Не удалось получить список модулей: {ex.Message}");
        }
    }

    private static List<ModuleInfo> EnumerateModules(int processId)
    {
        IntPtr snapshot = CreateToolhelp32Snapshot(0x00000008, processId);
        if (snapshot == IntPtr.Zero || snapshot == new IntPtr(-1))
        {
            throw new Win32Exception(Marshal.GetLastWin32Error(), "CreateToolhelp32Snapshot не удался.");
        }

        try
        {
            var modules = new List<ModuleInfo>();
            var entry = new ModuleEntry32
            {
                dwSize = (uint)Marshal.SizeOf<ModuleEntry32>()
            };

            if (!Module32FirstW(snapshot, ref entry))
            {
                int error = Marshal.GetLastWin32Error();
                if (error != 0 && error != 0x12)
                {
                    throw new Win32Exception(error, "Module32FirstW не удался.");
                }
                return modules;
            }

            do
            {
                string path = entry.szExePath ?? "";
                string name = string.IsNullOrEmpty(path) ? entry.szModule ?? "" : Path.GetFileName(path);
                if (string.IsNullOrEmpty(path)) continue;
                modules.Add(new ModuleInfo(name, path));
            }
            while (Module32NextW(snapshot, ref entry));

            return modules;
        }
        finally
        {
            CloseHandle(snapshot);
        }
    }

    private static bool IsExpectedLocation(string modulePath, string? javaDirectory)
    {
        string fullPath = Path.GetFullPath(modulePath);
        string systemDirectory = Environment.SystemDirectory;
        string wowDirectory = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "SysWOW64");
        if (IsWithin(fullPath, systemDirectory) || IsWithin(fullPath, wowDirectory))
        {
            return true;
        }

        if (IsWithin(fullPath, Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "WinSxS")))
        {
            return true;
        }

        string tempPath = Path.GetTempPath();
        if (fullPath.StartsWith(tempPath, StringComparison.OrdinalIgnoreCase) &&
            (fullPath.AsSpan(tempPath.Length).StartsWith("lwjgl", StringComparison.OrdinalIgnoreCase) ||
             fullPath.AsSpan(tempPath.Length).StartsWith("jna", StringComparison.OrdinalIgnoreCase)))
        {
            return true;
        }

        string programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        if (IsWithin(fullPath, Path.Combine(programFiles, "Windhawk")))
        {
            return true;
        }

        string programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
        if (IsWithin(fullPath, Path.Combine(programData, "Microsoft", "Windows Defender")))
        {
            return true;
        }

        if (string.IsNullOrWhiteSpace(javaDirectory))
        {
            return false;
        }

        return IsWithin(fullPath, javaDirectory) ||
               (Directory.GetParent(javaDirectory)?.FullName is { } parent && IsWithin(fullPath, parent));
    }

    private static bool IsWithin(string path, string root)
    {
        if (string.IsNullOrWhiteSpace(root)) return false;
        string normalizedRoot = Path.TrimEndingDirectorySeparator(Path.GetFullPath(root)) + Path.DirectorySeparatorChar;
        return path.StartsWith(normalizedRoot, StringComparison.OrdinalIgnoreCase) ||
               path.Equals(Path.TrimEndingDirectorySeparator(normalizedRoot), StringComparison.OrdinalIgnoreCase);
    }

    private readonly record struct ModuleInfo(string Name, string FileName);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr CreateToolhelp32Snapshot(uint dwFlags, int th32ProcessID);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool Module32FirstW(IntPtr hSnapshot, ref ModuleEntry32 lpme);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool Module32NextW(IntPtr hSnapshot, ref ModuleEntry32 lpme);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr hObject);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct ModuleEntry32
    {
        public uint dwSize;
        public uint th32ModuleID;
        public uint th32ProcessID;
        public uint GlblcntUsage;
        public uint ProccntUsage;
        public IntPtr modBaseAddr;
        public uint modBaseSize;
        public IntPtr hModule;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
        public string szModule;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
        public string szExePath;
    }
}
