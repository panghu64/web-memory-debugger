package com.example.myapplication.server.models;

public class WatchpointResult {
    private boolean triggered;
    private String pc;              // 程序计数器
    private String[] registers;     // 通用寄存器 X0-X30
    private String sp;              // 栈指针
    private String lr;              // 链接寄存器
    private String instruction;     // 触发的指令
    private int signal;             // 触发的信号
    private String error;           // 错误信息（如果失败）
    
    public WatchpointResult() {
    }
    
    public WatchpointResult(boolean triggered) {
        this.triggered = triggered;
    }
    
    // Getters and setters
    public boolean isTriggered() {
        return triggered;
    }
    
    public void setTriggered(boolean triggered) {
        this.triggered = triggered;
    }
    
    public String getPc() {
        return pc;
    }
    
    public void setPc(String pc) {
        this.pc = pc;
    }
    
    public String[] getRegisters() {
        return registers;
    }
    
    public void setRegisters(String[] registers) {
        this.registers = registers;
    }
    
    public String getSp() {
        return sp;
    }
    
    public void setSp(String sp) {
        this.sp = sp;
    }
    
    public String getLr() {
        return lr;
    }
    
    public void setLr(String lr) {
        this.lr = lr;
    }
    
    public String getInstruction() {
        return instruction;
    }
    
    public void setInstruction(String instruction) {
        this.instruction = instruction;
    }
    
    public int getSignal() {
        return signal;
    }
    
    public void setSignal(int signal) {
        this.signal = signal;
    }
    
    public String getError() {
        return error;
    }
    
    public void setError(String error) {
        this.error = error;
    }
}

