using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace Jrss.Core;

/// <summary>Read-only scan of committed, readable virtual-memory regions on Windows.</summary>
public static class ProcessMemoryScanner
{
    private const uint ProcessQueryInformation = 0x0400;
    private const uint ProcessVmRead = 0x0010;
    private const uint MemCommit = 0x1000;
    private const uint PageNoAccess = 0x01;
    private const uint PageGuard = 0x100;
    private const uint ReadableProtectionMask = 0x02 | 0x04 | 0x08 | 0x20 | 0x40 | 0x80;
    private const int ChunkSize = 4 * 1024 * 1024;

    public static ProcessDetection ScanProcess(Process process, SignatureDatabase database, Action<ScanProgress>? onProgress = null)
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException("Process memory scanning is only supported on Windows.");
        }

        var stopwatch = Stopwatch.StartNew();
        IntPtr handle = OpenProcess(ProcessQueryInformation | ProcessVmRead, false, process.Id);
        if (handle == IntPtr.Zero)
        {
            throw new Win32Exception(Marshal.GetLastWin32Error(),
                "Could not open process. Run the scanner as administrator.");
        }

        try
        {
            var regions = EnumerateReadableRegions(handle);
            long totalEstimate = regions.Aggregate(0L, (total, region) => SaturatingAdd(total, checked((long)region.Size)));
            var result = new ProcessDetection { ProcessId = process.Id, ProcessName = process.ProcessName };
            var buffer = new byte[ChunkSize];

            for (int index = 0; index < regions.Count; index++)
            {
                var region = regions[index];
                ScanRegion(handle, region, buffer, database, result);
                result.RegionsScanned = index + 1;
                onProgress?.Invoke(new ScanProgress(result.BytesScanned, totalEstimate, result.RegionsScanned, regions.Count));
            }

            result.Elapsed = stopwatch.Elapsed;
            return result;
        }
        finally
        {
            _ = CloseHandle(handle);
        }
    }

    private static void ScanRegion(
        IntPtr handle,
        MemoryRegion region,
        byte[] buffer,
        SignatureDatabase database,
        ProcessDetection result)
    {
        nuint address = region.BaseAddress;
        nuint remaining = region.Size;
        int state = database.Automaton.InitialState;

        while (remaining > 0)
        {
            nuint requested = Math.Min((nuint)buffer.Length, remaining);
            if (!ReadProcessMemory(handle, (IntPtr)(long)address, buffer, requested, out nuint read) || read == 0)
            {
                break;
            }

            int bytesRead = checked((int)read);
            state = database.Automaton.ScanChunk(state, buffer.AsSpan(0, bytesRead), tag => { result.Matches.Add(tag); });
            result.BytesScanned = SaturatingAdd(result.BytesScanned, bytesRead);
            address += read;
            remaining -= read;
        }
    }

    private static List<MemoryRegion> EnumerateReadableRegions(IntPtr handle)
    {
        var regions = new List<MemoryRegion>();
        nuint address = 0;
        nuint structureSize = (nuint)Marshal.SizeOf<MemoryBasicInformation>();

        while (true)
        {
            nuint written = VirtualQueryEx(handle, (IntPtr)(long)address, out var info, structureSize);
            if (written == 0 || info.RegionSize == 0)
            {
                break;
            }

            nuint regionSize = unchecked((nuint)info.RegionSize.ToInt64());
            if (info.State == MemCommit && IsReadable(info.Protect))
            {
                regions.Add(new MemoryRegion(unchecked((nuint)info.BaseAddress.ToInt64()), regionSize));
            }

            nuint next = unchecked((nuint)info.BaseAddress.ToInt64()) + regionSize;
            if (next <= address)
            {
                break;
            }
            address = next;
        }

        return regions;
    }

    private static bool IsReadable(uint protect) =>
        (protect & (PageGuard | PageNoAccess)) == 0 && (protect & ReadableProtectionMask) != 0;

    private static long SaturatingAdd(long left, long right) =>
        right > long.MaxValue - left ? long.MaxValue : left + right;

    private readonly record struct MemoryRegion(nuint BaseAddress, nuint Size);

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

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint desiredAccess, [MarshalAs(UnmanagedType.Bool)] bool inheritHandle, int processId);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr handle);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern nuint VirtualQueryEx(
        IntPtr process,
        IntPtr address,
        out MemoryBasicInformation buffer,
        nuint length);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ReadProcessMemory(
        IntPtr process,
        IntPtr baseAddress,
        [Out] byte[] buffer,
        nuint size,
        out nuint bytesRead);
}
