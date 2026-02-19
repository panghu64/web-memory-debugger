package com.example.myapplication.server.models;

public class DisasmLine {
    private String address;     // 十六进制字符串
    private String bytes;       // 十六进制字节串
    private String mnemonic;    // 指令助记符
    private String opStr;       // 操作数字符串
    private boolean isMemAccess; // 是否是内存访问指令
    
    public DisasmLine() {
    }
    
    public DisasmLine(String address, String bytes, String mnemonic, String opStr) {
        this.address = address;
        this.bytes = bytes;
        this.mnemonic = mnemonic;
        this.opStr = opStr;
        this.isMemAccess = detectMemoryAccess(mnemonic);
    }
    
    private boolean detectMemoryAccess(String mnemonic) {
        if (mnemonic == null) return false;
        String mn = mnemonic.toUpperCase();
        // ARM64/ARMv7 内存访问指令
        return mn.startsWith("LDR") || mn.startsWith("STR") || 
               mn.startsWith("LDP") || mn.startsWith("STP") ||
               mn.startsWith("LDRB") || mn.startsWith("STRB") ||
               mn.startsWith("LDRH") || mn.startsWith("STRH") ||
               mn.startsWith("LDRSW") || mn.startsWith("LDUR") || 
               mn.startsWith("STUR");
    }
    
    // Getters and setters
    public String getAddress() {
        return address;
    }
    
    public void setAddress(String address) {
        this.address = address;
    }
    
    public String getBytes() {
        return bytes;
    }
    
    public void setBytes(String bytes) {
        this.bytes = bytes;
    }
    
    public String getMnemonic() {
        return mnemonic;
    }
    
    public void setMnemonic(String mnemonic) {
        this.mnemonic = mnemonic;
        this.isMemAccess = detectMemoryAccess(mnemonic);
    }
    
    public String getOpStr() {
        return opStr;
    }
    
    public void setOpStr(String opStr) {
        this.opStr = opStr;
    }
    
    public boolean isMemAccess() {
        return isMemAccess;
    }
    
    public void setMemAccess(boolean memAccess) {
        isMemAccess = memAccess;
    }
}

