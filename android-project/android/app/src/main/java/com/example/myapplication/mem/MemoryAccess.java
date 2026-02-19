package com.example.myapplication.mem;

public final class MemoryAccess {
    static {
        System.loadLibrary("memoryaccess");
    }

    private MemoryAccess() {}

    public static native byte[] read(long address, int length);
    public static native void write(long address, byte[] data);

    // Helpers for primitives (optional convenience)
    public static long readLong(long address) {
        byte[] b = read(address, 8);
        if (b == null || b.length != 8) throw new IllegalStateException("read failed");
        return ((long)(b[7] & 0xFF) << 56) |
               ((long)(b[6] & 0xFF) << 48) |
               ((long)(b[5] & 0xFF) << 40) |
               ((long)(b[4] & 0xFF) << 32) |
               ((long)(b[3] & 0xFF) << 24) |
               ((long)(b[2] & 0xFF) << 16) |
               ((long)(b[1] & 0xFF) << 8)  |
               ((long)(b[0] & 0xFF));
    }

    public static void writeLong(long address, long value) {
        byte[] b = new byte[8];
        b[0] = (byte)(value);
        b[1] = (byte)(value >>> 8);
        b[2] = (byte)(value >>> 16);
        b[3] = (byte)(value >>> 24);
        b[4] = (byte)(value >>> 32);
        b[5] = (byte)(value >>> 40);
        b[6] = (byte)(value >>> 48);
        b[7] = (byte)(value >>> 56);
        write(address, b);
    }
}

