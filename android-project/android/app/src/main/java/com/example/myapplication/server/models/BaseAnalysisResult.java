package com.example.myapplication.server.models;

import java.util.List;

public class BaseAnalysisResult {
    private List<BaseCandidate> candidateBases;
    private List<String> offsetChain;
    private int confidence;  // 0-100
    
    public BaseAnalysisResult() {
    }
    
    public List<BaseCandidate> getCandidateBases() {
        return candidateBases;
    }
    
    public void setCandidateBases(List<BaseCandidate> candidateBases) {
        this.candidateBases = candidateBases;
    }
    
    public List<String> getOffsetChain() {
        return offsetChain;
    }
    
    public void setOffsetChain(List<String> offsetChain) {
        this.offsetChain = offsetChain;
    }
    
    public int getConfidence() {
        return confidence;
    }
    
    public void setConfidence(int confidence) {
        this.confidence = confidence;
    }
    
    public static class BaseCandidate {
        private String register;      // 寄存器名 (e.g. "X19")
        private String value;         // 寄存器值
        private String type;          // 类型 (e.g. "ADRP", "Global Pointer", "Stack")
        private long offset;          // 相对于目标地址的偏移
        private String source;        // 来源地址
        
        public BaseCandidate() {
        }
        
        public BaseCandidate(String register, String value, String type, long offset) {
            this.register = register;
            this.value = value;
            this.type = type;
            this.offset = offset;
        }
        
        // Getters and setters
        public String getRegister() {
            return register;
        }
        
        public void setRegister(String register) {
            this.register = register;
        }
        
        public String getValue() {
            return value;
        }
        
        public void setValue(String value) {
            this.value = value;
        }
        
        public String getType() {
            return type;
        }
        
        public void setType(String type) {
            this.type = type;
        }
        
        public long getOffset() {
            return offset;
        }
        
        public void setOffset(long offset) {
            this.offset = offset;
        }
        
        public String getSource() {
            return source;
        }
        
        public void setSource(String source) {
            this.source = source;
        }
    }
}

