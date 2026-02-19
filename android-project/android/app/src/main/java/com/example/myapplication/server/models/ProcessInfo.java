package com.example.myapplication.server.models;

public class ProcessInfo {
    private int pid;
    private String name;
    private String cmdline;
    private String user;
    private long memoryUsage;
    
    public ProcessInfo() {
    }
    
    public ProcessInfo(int pid, String name) {
        this.pid = pid;
        this.name = name;
    }
    
    public int getPid() {
        return pid;
    }
    
    public void setPid(int pid) {
        this.pid = pid;
    }
    
    public String getName() {
        return name;
    }
    
    public void setName(String name) {
        this.name = name;
    }
    
    public String getCmdline() {
        return cmdline;
    }
    
    public void setCmdline(String cmdline) {
        this.cmdline = cmdline;
    }
    
    public String getUser() {
        return user;
    }
    
    public void setUser(String user) {
        this.user = user;
    }
    
    public long getMemoryUsage() {
        return memoryUsage;
    }
    
    public void setMemoryUsage(long memoryUsage) {
        this.memoryUsage = memoryUsage;
    }
}

