using System.Runtime.InteropServices;

namespace Jrss.ExternalAccess;

internal class RemoteMemory
{
    private readonly IntPtr _handle;

    public RemoteMemory(IntPtr processHandle)
    {
        _handle = processHandle;
    }

    public bool ReadBytes(IntPtr address, byte[] buffer, int size)
    {
        return NativeMethods.ReadProcessMemory(_handle, address, buffer, (nuint)size, out _);
    }

    public int ReadI32(IntPtr address)
    {
        var buf = new byte[4];
        NativeMethods.ReadProcessMemory(_handle, address, buf, 4, out _);
        return BitConverter.ToInt32(buf, 0);
    }

    public uint ReadU32(IntPtr address)
    {
        var buf = new byte[4];
        NativeMethods.ReadProcessMemory(_handle, address, buf, 4, out _);
        return BitConverter.ToUInt32(buf, 0);
    }

    public ushort ReadU16(IntPtr address)
    {
        var buf = new byte[2];
        NativeMethods.ReadProcessMemory(_handle, address, buf, 2, out _);
        return BitConverter.ToUInt16(buf, 0);
    }

    public long ReadI64(IntPtr address)
    {
        var buf = new byte[8];
        NativeMethods.ReadProcessMemory(_handle, address, buf, 8, out _);
        return BitConverter.ToInt64(buf, 0);
    }

    public ulong ReadU64(IntPtr address)
    {
        var buf = new byte[8];
        NativeMethods.ReadProcessMemory(_handle, address, buf, 8, out _);
        return BitConverter.ToUInt64(buf, 0);
    }

    public IntPtr ReadPtr(IntPtr address)
    {
        if (IntPtr.Size == 8)
            return new IntPtr((long)ReadU64(address));
        return new IntPtr(ReadU32(address));
    }

    public string ReadString(IntPtr address, int maxLength = 256)
    {
        var buf = new byte[maxLength];
        if (!ReadBytes(address, buf, maxLength))
            return string.Empty;
        int len = 0;
        while (len < maxLength && buf[len] != 0) len++;
        return System.Text.Encoding.UTF8.GetString(buf, 0, len);
    }

    public T ReadStruct<T>(IntPtr address) where T : struct
    {
        var buf = new byte[Marshal.SizeOf<T>()];
        ReadBytes(address, buf, buf.Length);
        var handle = GCHandle.Alloc(buf, GCHandleType.Pinned);
        try
        {
            return Marshal.PtrToStructure<T>(handle.AddrOfPinnedObject());
        }
        finally
        {
            handle.Free();
        }
    }

    public int ReadStructRaw(IntPtr address, byte[] buffer, int size)
    {
        NativeMethods.ReadProcessMemory(_handle, address, buffer, (nuint)size, out var read);
        return (int)read;
    }
}
