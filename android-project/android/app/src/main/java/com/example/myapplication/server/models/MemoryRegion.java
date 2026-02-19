package com.example.myapplication.server.models;

public class MemoryRegion {
    private String start;      // 十六进制字符串
    private String end;        // 十六进制字符串
    private long size;
    private String perms;      // rwxp格式
    private long offset;
    private String device;
    private long inode;
    private String path;
    
    public MemoryRegion() {
    }
    
    public boolean isReadable() {
        return perms != null && perms.length() > 0 && perms.charAt(0) == 'r';
    }
    
    public boolean isWritable() {
        return perms != null && perms.length() > 1 && perms.charAt(1) == 'w';
    }
    
    public boolean isExecutable() {
        return perms != null && perms.length() > 2 && perms.charAt(2) == 'x';
    }
    
    // Getters and setters
    public String getStart() {
        return start;
    }
    
    public void setStart(String start) {
        this.start = start;
    }
    
    public String getEnd() {
        return end;
    }
    
    public void setEnd(String end) {
        this.end = end;
    }
    
    public long getSize() {
        return size;
    }
    
    public void setSize(long size) {
        this.size = size;
    }
    
    public String getPerms() {
        return perms;
    }
    
    public void setPerms(String perms) {
        this.perms = perms;
    }
    
    public long getOffset() {
        return offset;
    }
    
    public void setOffset(long offset) {
        this.offset = offset;
    }
    
    public String getDevice() {
        return device;
    }
    
    public void setDevice(String device) {
        this.device = device;
    }
    
    public long getInode() {
        return inode;
    }
    
    public void setInode(long inode) {
        this.inode = inode;
    }
    
    public String getPath() {
        return path;
    }
    
    public void setPath(String path) {
        this.path = path;
    }
}

