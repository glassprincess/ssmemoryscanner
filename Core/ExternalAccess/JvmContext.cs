using System.Runtime.InteropServices;

namespace Jrss.ExternalAccess;

internal sealed class JvmContext : IDisposable
{
    private readonly IntPtr _handle;
    private readonly RemoteMemory _mem;
    private IntPtr _jvmBase;

    private ulong _narrowOopBase;
    private int _narrowOopShift;
    private bool _useCompressedOops;

    private const int VMStructCount = 788;

    private readonly List<StructEntry> _structs = new();

    private sealed class StructEntry
    {
        public required string TypeName { get; init; }
        public required string FieldName { get; init; }
        public ulong Offset { get; init; }
        public IntPtr Address { get; init; }
    }

    [StructLayout(LayoutKind.Sequential, Pack = 8)]
    private struct RawStructEntry
    {
        public IntPtr typeName;
        public IntPtr fieldName;
        public IntPtr typeString;
        public int isStatic;
        public ulong offset;
        public IntPtr address;
    }

    public JvmContext(int pid)
    {
        _handle = NativeMethods.OpenProcess(NativeMethods.ProcessVmRead | NativeMethods.ProcessQueryInformation, false, pid);
        if (_handle == IntPtr.Zero)
            throw new InvalidOperationException("Failed to open process. Run as administrator.");
        _mem = new RemoteMemory(_handle);
    }

    public bool Initialize()
    {
        _jvmBase = FindJvmBase();
        if (_jvmBase == IntPtr.Zero) return false;

        if (!ParseVmStructTable()) return false;
        if (!ReadCompressedOopsInfo()) return false;

        return true;
    }

    private IntPtr FindJvmBase()
    {
        var modules = new IntPtr[256];
        if (!NativeMethods.EnumProcessModulesEx(_handle, modules, (uint)(modules.Length * IntPtr.Size), out var needed, NativeMethods.ListModules64Bit))
            return IntPtr.Zero;

        int count = (int)(needed / (uint)IntPtr.Size);
        for (int i = 0; i < count; i++)
        {
            var nameBytes = new byte[260];
            NativeMethods.GetModuleBaseNameA(_handle, modules[i], nameBytes, 260);
            var name = System.Text.Encoding.ASCII.GetString(nameBytes, 0, Array.IndexOf(nameBytes, (byte)0));
            if (name.Equals("jvm.dll", StringComparison.OrdinalIgnoreCase))
                return modules[i];
        }
        return IntPtr.Zero;
    }

    private bool ParseVmStructTable()
    {
        var exports = ParseExportTable();
        if (exports.Count == 0) return false;

        var gHotSpotVMStructs = exports.FirstOrDefault(e => e.Name == "gHotSpotVMStructs");
        if (gHotSpotVMStructs.Address == 0) return false;

        var gHotSpotVMStructsAddr = _jvmBase + (int)gHotSpotVMStructs.Address;
        var tableBase = _mem.ReadPtr(gHotSpotVMStructsAddr);

        var entrySize = Marshal.SizeOf<RawStructEntry>();
        for (int i = 0; i < VMStructCount; i++)
        {
            var entryAddr = tableBase + (i * entrySize);
            var raw = new byte[entrySize];
            if (!_mem.ReadBytes(entryAddr, raw, entrySize)) break;

            var handle = GCHandle.Alloc(raw, GCHandleType.Pinned);
            RawStructEntry entry;
            try { entry = Marshal.PtrToStructure<RawStructEntry>(handle.AddrOfPinnedObject()); }
            finally { handle.Free(); }

            if (entry.typeName == IntPtr.Zero) break;

            var typeName = _mem.ReadString(entry.typeName, 200);
            var fieldName = _mem.ReadString(entry.fieldName, 200);
            if (string.IsNullOrEmpty(typeName) || string.IsNullOrEmpty(fieldName)) break;

            _structs.Add(new StructEntry
            {
                TypeName = typeName,
                FieldName = fieldName,
                Offset = entry.offset,
                Address = entry.address,
            });
        }

        return _structs.Count > 0;
    }

    private List<ExportEntry> ParseExportTable()
    {
        var exports = new List<ExportEntry>();

        var dosRaw = new byte[Marshal.SizeOf<ImageDosHeader>()];
        if (!_mem.ReadBytes(_jvmBase, dosRaw, dosRaw.Length)) return exports;

        var dosHandle = GCHandle.Alloc(dosRaw, GCHandleType.Pinned);
        ImageDosHeader dos;
        try { dos = Marshal.PtrToStructure<ImageDosHeader>(dosHandle.AddrOfPinnedObject()); }
        finally { dosHandle.Free(); }

        if (dos.e_magic != 0x5A4D) return exports;

        var ntRaw = new byte[Marshal.SizeOf<ImageNtHeaders64>()];
        if (!_mem.ReadBytes(_jvmBase + dos.e_lfanew, ntRaw, ntRaw.Length)) return exports;

        var ntHandle = GCHandle.Alloc(ntRaw, GCHandleType.Pinned);
        ImageNtHeaders64 nt;
        try { nt = Marshal.PtrToStructure<ImageNtHeaders64>(ntHandle.AddrOfPinnedObject()); }
        finally { ntHandle.Free(); }

        if (nt.Signature != 0x00004550) return exports;

        var exportDir = nt.OptionalHeader.DataDirectory[0];
        if (exportDir.Size == 0) return exports;

        var exportRaw = new byte[Marshal.SizeOf<ImageExportDirectory>()];
        if (!_mem.ReadBytes(_jvmBase + (int)exportDir.VirtualAddress, exportRaw, exportRaw.Length)) return exports;

        var expHandle = GCHandle.Alloc(exportRaw, GCHandleType.Pinned);
        ImageExportDirectory exp;
        try { exp = Marshal.PtrToStructure<ImageExportDirectory>(expHandle.AddrOfPinnedObject()); }
        finally { expHandle.Free(); }

        var nameOffsets = new byte[exp.NumberOfNames * 4];
        var ordOffsets = new byte[exp.NumberOfNames * 2];
        var funcOffsets = new byte[exp.NumberOfFunctions * 4];

        if (!_mem.ReadBytes(_jvmBase + (int)exp.AddressOfNames, nameOffsets, nameOffsets.Length)) return exports;
        if (!_mem.ReadBytes(_jvmBase + (int)exp.AddressOfNameOrdinals, ordOffsets, ordOffsets.Length)) return exports;
        if (!_mem.ReadBytes(_jvmBase + (int)exp.AddressOfFunctions, funcOffsets, funcOffsets.Length)) return exports;

        for (uint i = 0; i < exp.NumberOfNames; i++)
        {
            var nameOffset = BitConverter.ToUInt32(nameOffsets, (int)(i * 4));
            var ordinal = BitConverter.ToUInt16(ordOffsets, (int)(i * 2));
            var funcOffset = BitConverter.ToUInt32(funcOffsets, ordinal * 4);
            var name = _mem.ReadString(_jvmBase + (int)nameOffset, 200);
            if (!string.IsNullOrEmpty(name))
                exports.Add(new ExportEntry { Name = name, Ordinal = ordinal, Address = funcOffset });
        }

        return exports;
    }

    private bool ReadCompressedOopsInfo()
    {
        var oopBase = FindStruct("CompressedOops", "_narrow_oop._base");
        var oopShift = FindStruct("CompressedOops", "_narrow_oop._shift");
        var oopUse = FindStruct("CompressedOops", "_narrow_oop._use_implicit_null_checks");

        if (oopBase == null || oopShift == null || oopUse == null) return false;

        var baseBuf = new byte[8];
        var shiftBuf = new byte[4];
        var useBuf = new byte[1];

        if (!_mem.ReadBytes(oopBase.Address, baseBuf, 8)) return false;
        if (!_mem.ReadBytes(oopShift.Address, shiftBuf, 4)) return false;
        _mem.ReadBytes(oopUse.Address, useBuf, 1);

        _narrowOopBase = BitConverter.ToUInt64(baseBuf, 0);
        _narrowOopShift = BitConverter.ToInt32(shiftBuf, 0);
        _useCompressedOops = useBuf[0] != 0;
        return true;
    }

    private StructEntry? FindStruct(string typeName, string fieldName)
    {
        foreach (var entry in _structs)
            if (entry.TypeName == typeName && entry.FieldName == fieldName)
                return entry;
        return null;
    }

    public IntPtr ReadPointer(IntPtr address)
    {
        if (_useCompressedOops)
        {
            var val = _mem.ReadU32(address);
            if (val == 0) return IntPtr.Zero;
            return new IntPtr((long)(((ulong)val << _narrowOopShift) + _narrowOopBase));
        }
        return _mem.ReadPtr(address);
    }

    public IntPtr ReadPointerRaw(IntPtr address)
    {
        return _mem.ReadPtr(address);
    }

    public List<string> EnumerateAllClassNames()
    {
        var result = new List<string>();

        var classLoaderDataGraphHead = FindStruct("ClassLoaderDataGraph", "_head");
        if (classLoaderDataGraphHead == null) return result;

        var classLoaderData = ReadPointerRaw(classLoaderDataGraphHead.Address);
        if (classLoaderData == IntPtr.Zero) return result;

        var klassesOffset = (int)GetStructOffset("ClassLoaderData", "_klasses");
        var nextLinkOffset = (int)GetStructOffset("Klass", "_next_link");
        var nextLoaderOffset = (int)GetStructOffset("ClassLoaderData", "_next");

        while (classLoaderData != IntPtr.Zero)
        {
            var klass = ReadPointerRaw(classLoaderData + klassesOffset);

            while (klass != IntPtr.Zero)
            {
                var className = GetClassName(klass);
                if (!string.IsNullOrEmpty(className))
                    result.Add(className);

                klass = ReadPointerRaw(klass + nextLinkOffset);
            }

            classLoaderData = ReadPointerRaw(classLoaderData + nextLoaderOffset);
        }

        return result;
    }

    private ulong GetStructOffset(string typeName, string fieldName)
    {
        var entry = FindStruct(typeName, fieldName);
        return entry?.Offset ?? 0;
    }

    private string GetClassName(IntPtr klass)
    {
        var nameOffset = (int)GetStructOffset("Klass", "_name");
        if (nameOffset == 0) return string.Empty;

        var symbolAddr = ReadPointerRaw(klass + nameOffset);
        if (symbolAddr == IntPtr.Zero) return string.Empty;

        var length = _mem.ReadU16(symbolAddr + 4);
        if (length == 0 || length > 500) return string.Empty;

        var body = new byte[length];
        if (_mem.ReadBytes(symbolAddr + 6, body, length))
            return System.Text.Encoding.UTF8.GetString(body, 0, length);
        return string.Empty;
    }

    public void Dispose()
    {
        if (_handle != IntPtr.Zero)
            NativeMethods.CloseHandle(_handle);
    }

    private struct ExportEntry
    {
        public string Name;
        public ushort Ordinal;
        public uint Address;
    }

    // --- PE structs ---
    [StructLayout(LayoutKind.Sequential, Pack = 8)]
    private struct ImageDosHeader
    {
        public ushort e_magic;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 58)]
        public byte[] e_reserved1;
        public int e_lfanew;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 8)]
    private struct ImageNtHeaders64
    {
        public uint Signature;
        public ImageFileHeader FileHeader;
        public ImageOptionalHeader64 OptionalHeader;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 4)]
    private struct ImageFileHeader
    {
        public ushort Machine;
        public ushort NumberOfSections;
        public uint TimeDateStamp;
        public uint PointerToSymbolTable;
        public uint NumberOfSymbols;
        public ushort SizeOfOptionalHeader;
        public ushort Characteristics;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 8)]
    private struct ImageOptionalHeader64
    {
        public ushort Magic;
        public byte MajorLinkerVersion;
        public byte MinorLinkerVersion;
        public uint SizeOfCode;
        public uint SizeOfInitializedData;
        public uint SizeOfUninitializedData;
        public uint AddressOfEntryPoint;
        public uint BaseOfCode;
        public ulong ImageBase;
        public uint SectionAlignment;
        public uint FileAlignment;
        public ushort MajorOperatingSystemVersion;
        public ushort MinorOperatingSystemVersion;
        public ushort MajorImageVersion;
        public ushort MinorImageVersion;
        public ushort MajorSubsystemVersion;
        public ushort MinorSubsystemVersion;
        public uint Win32VersionValue;
        public uint SizeOfImage;
        public uint SizeOfHeaders;
        public uint CheckSum;
        public ushort Subsystem;
        public ushort DllCharacteristics;
        public ulong SizeOfStackReserve;
        public ulong SizeOfStackCommit;
        public ulong SizeOfHeapReserve;
        public ulong SizeOfHeapCommit;
        public uint LoaderFlags;
        public uint NumberOfRvaAndSizes;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public ImageDataDirectory[] DataDirectory;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 4)]
    private struct ImageDataDirectory
    {
        public uint VirtualAddress;
        public uint Size;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 4)]
    private struct ImageExportDirectory
    {
        public uint Characteristics;
        public uint TimeDateStamp;
        public ushort MajorVersion;
        public ushort MinorVersion;
        public uint Name;
        public uint Base;
        public uint NumberOfFunctions;
        public uint NumberOfNames;
        public uint AddressOfFunctions;
        public uint AddressOfNames;
        public uint AddressOfNameOrdinals;
    }
}
