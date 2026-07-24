using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace Jrss.Core;

public enum ScanFlag
{
    Green,
    Yellow,
    Red
}

public sealed class RwxRegion
{
    public required IntPtr BaseAddress { get; init; }
    public required ulong RegionSize { get; init; }
    public required uint Protect { get; init; }
    public required uint State { get; init; }
    public required uint Type { get; init; }
    public required string Analysis { get; init; }
}

public sealed class RwxScanReport
{
    public DateTime TimestampUtc { get; init; } = DateTime.UtcNow;
    public required int ProcessId { get; init; }
    public required string ProcessName { get; init; }
    public int RedDetections { get; init; }
    public ScanFlag Flag { get; init; }
    public required string Verdict { get; init; }
    public string Notice { get; init; } = "RWX regions are a red flag, but not direct proof of cheats.";
    public IReadOnlyList<RwxRegion> SuspiciousRegions { get; init; } = Array.Empty<RwxRegion>();
}

public static class RwxMemoryScanner
{
    private const uint ProcessQueryInformation = 0x0400;
    private const uint ProcessVmRead = 0x0010;

    private const uint MemCommit = 0x1000;
    private const uint MemPrivate = 0x20000;
    private const uint MemImage = 0x1000000;

    private const uint PageExecuteReadWrite = 0x40;
    private const uint PageGuard = 0x100;

    private const int MaxRwxThresholdGreen = 10;
    private const int MaxRwxThresholdYellow = 30;

    public static RwxScanReport ScanProcess(Process process)
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException("RWX region scanning is only supported on Windows.");
        }

        IntPtr handle = OpenProcess(ProcessQueryInformation | ProcessVmRead, false, process.Id);
        if (handle == IntPtr.Zero)
        {
            throw new Win32Exception(Marshal.GetLastWin32Error(),
                "Could not open process. Run the scanner as administrator.");
        }

        try
        {
            var suspicious = new List<RwxRegion>();
            long address = 0;
            long maxAddress = Environment.Is64BitProcess ? long.MaxValue : uint.MaxValue;
            int mbiSize = Marshal.SizeOf<MemoryBasicInformation>();

            while (address < maxAddress)
            {
                IntPtr current = new IntPtr(address);
                UIntPtr written = VirtualQueryEx(handle, current, out MemoryBasicInformation mbi, (UIntPtr)mbiSize);
                if (written == UIntPtr.Zero)
                {
                    break;
                }

                bool isCommitted = mbi.State == MemCommit;
                bool hasGuard = (mbi.Protect & PageGuard) != 0;
                bool isRwx = (mbi.Protect & PageExecuteReadWrite) == PageExecuteReadWrite;

                if (isCommitted && !hasGuard && isRwx)
                {
                    suspicious.Add(new RwxRegion
                    {
                        BaseAddress = mbi.BaseAddress,
                        RegionSize = (ulong)mbi.RegionSize.ToInt64(),
                        Protect = mbi.Protect,
                        State = mbi.State,
                        Type = mbi.Type,
                        Analysis = AnalyzeRegion(mbi)
                    });
                }

                long next = address + mbi.RegionSize.ToInt64();
                if (next <= address) break;
                address = next;
            }

            int redDetections = suspicious.Count;
            ScanFlag flag = ResolveFlag(redDetections);
            string verdict = ResolveVerdict(redDetections, flag);

            return new RwxScanReport
            {
                ProcessId = process.Id,
                ProcessName = process.ProcessName,
                RedDetections = redDetections,
                Flag = flag,
                Verdict = verdict,
                SuspiciousRegions = suspicious
            };
        }
        finally
        {
            CloseHandle(handle);
        }
    }

    private static ScanFlag ResolveFlag(int redDetections)
    {
        if (redDetections <= MaxRwxThresholdGreen) return ScanFlag.Green;
        if (redDetections <= MaxRwxThresholdYellow) return ScanFlag.Yellow;
        return ScanFlag.Red;
    }

    private static string ResolveVerdict(int redDetections, ScanFlag flag)
    {
        return flag switch
        {
            ScanFlag.Green => $"GREEN: {redDetections} RWX regions (≤ {MaxRwxThresholdGreen}). Low anomaly level.",
            ScanFlag.Yellow => $"YELLOW: {redDetections} RWX regions (≤ {MaxRwxThresholdYellow}). Worth a closer look.",
            _ => $"RED: {redDetections} RWX regions (> {MaxRwxThresholdYellow}). EXTREMELY SUSPICIOUS."
        };
    }

    private static string AnalyzeRegion(MemoryBasicInformation mbi)
    {
        if (mbi.Type == MemPrivate && mbi.RegionSize.ToInt64() >= 0x10000)
        {
            return "Large private committed RWX region — high risk of injection.";
        }

        if (mbi.Type == MemImage)
        {
            return "Image-backed RWX region — verify module legitimacy and load path.";
        }

        return "Committed RWX region — a red flag, but not direct proof.";
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint desiredAccess, [MarshalAs(UnmanagedType.Bool)] bool inheritHandle, int processId);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern UIntPtr VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress, out MemoryBasicInformation lpBuffer, UIntPtr dwLength);

    [StructLayout(LayoutKind.Sequential)]
    private struct MemoryBasicInformation
    {
        public IntPtr BaseAddress;
        public IntPtr AllocationBase;
        public uint AllocationProtect;
        public IntPtr RegionSize;
        public uint State;
        public uint Protect;
        public uint Type;
    }
}
