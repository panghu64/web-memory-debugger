package com.example.myapplication.server.services;

import android.content.Context;
import android.util.Log;

import com.example.myapplication.server.models.BaseAnalysisResult;
import com.example.myapplication.server.models.DisasmLine;
import com.example.myapplication.server.models.WatchpointResult;

import java.util.ArrayList;
import java.util.List;

/**
 * 智能分析服务（基址推断、指针链分析等）
 */
public class AnalysisService {
    private static final String TAG = "AnalysisService";
    private DisasmService disasmService;
    
    public AnalysisService(Context context) {
        this.disasmService = new DisasmService(context);
    }
    
    /**
     * 分析断点结果，推断可能的基址
     * @param pid 进程ID
     * @param result 断点结果
     * @param targetAddress 目标地址
     * @return 基址分析结果
     */
    public BaseAnalysisResult analyzeBase(int pid, WatchpointResult result, String targetAddress) {
        BaseAnalysisResult analysis = new BaseAnalysisResult();
        List<BaseAnalysisResult.BaseCandidate> candidates = new ArrayList<>();
        
        try {
            if (result == null || !result.isTriggered()) {
                analysis.setConfidence(0);
                return analysis;
            }
            
            // 解析目标地址
            long targetAddr = Long.parseLong(targetAddress.replaceFirst("^0x", ""), 16);
            
            // 分析寄存器，查找接近目标地址的寄存器（±4KB范围）
            String[] registers = result.getRegisters();
            if (registers != null) {
                for (int i = 0; i < Math.min(registers.length, 31); i++) {
                    try {
                        String regValue = registers[i];
                        if (regValue == null) continue;
                        
                        long regAddr = Long.parseLong(regValue.replaceFirst("^0x", ""), 16);
                        long offset = targetAddr - regAddr;
                        
                        // 如果偏移在合理范围内（±4KB）
                        if (Math.abs(offset) < 4096) {
                            BaseAnalysisResult.BaseCandidate candidate = new BaseAnalysisResult.BaseCandidate();
                            candidate.setRegister("X" + i);
                            candidate.setValue(regValue);
                            candidate.setOffset(offset);
                            candidate.setType("Direct");
                            candidates.add(candidate);
                            
                            Log.d(TAG, "Found candidate register: X" + i + " = " + regValue + 
                                      " (offset: " + offset + ")");
                        }
                    } catch (NumberFormatException e) {
                        // 忽略无效的寄存器值
                    }
                }
            }
            
            // 反汇编触发指令前后的代码
            if (result.getPc() != null) {
                try {
                    String pcStr = result.getPc().replaceFirst("^0x", "");
                    long pc = Long.parseLong(pcStr, 16);
                    
                    // 向前反汇编10条指令
                    long startAddr = pc - 40; // 10 * 4字节
                    List<DisasmLine> lines = disasmService.disassemble(pid, 
                                                Long.toHexString(startAddr), 15);
                    
                    // 分析反汇编结果，查找ADRP、LDR模式
                    for (DisasmLine line : lines) {
                        String mnemonic = line.getMnemonic();
                        if (mnemonic == null) continue;
                        
                        if (mnemonic.equalsIgnoreCase("ADRP")) {
                            // ADRP指令加载页基址
                            BaseAnalysisResult.BaseCandidate candidate = new BaseAnalysisResult.BaseCandidate();
                            candidate.setType("ADRP");
                            candidate.setSource(line.getAddress());
                            candidates.add(candidate);
                            Log.d(TAG, "Found ADRP at " + line.getAddress());
                        } else if (mnemonic.toUpperCase().startsWith("LDR") && 
                                   line.getOpStr() != null && 
                                   line.getOpStr().contains("[")) {
                            // LDR可能从全局指针加载
                            BaseAnalysisResult.BaseCandidate candidate = new BaseAnalysisResult.BaseCandidate();
                            candidate.setType("Global Pointer");
                            candidate.setSource(line.getAddress());
                            candidates.add(candidate);
                            Log.d(TAG, "Found potential global pointer load at " + line.getAddress());
                        }
                    }
                } catch (NumberFormatException e) {
                    Log.e(TAG, "Failed to parse PC address", e);
                }
            }
            
            analysis.setCandidateBases(candidates);
            
            // 计算置信度
            int confidence = 0;
            if (!candidates.isEmpty()) {
                confidence = Math.min(100, 30 + candidates.size() * 10);
            }
            analysis.setConfidence(confidence);
            
        } catch (Exception e) {
            Log.e(TAG, "Failed to analyze base", e);
            analysis.setConfidence(0);
        }
        
        return analysis;
    }
}

