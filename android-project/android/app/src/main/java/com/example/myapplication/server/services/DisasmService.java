package com.example.myapplication.server.services;

import android.content.Context;
import android.util.Log;

import com.example.myapplication.debug.DebugNative;
import com.example.myapplication.server.models.DisasmLine;

import java.util.Arrays;
import java.util.List;

/**
 * 反汇编服务
 */
public class DisasmService {
    private static final String TAG = "DisasmService";
    private DebugNative debugNative;
    
    public DisasmService(Context context) {
        this.debugNative = new DebugNative(context);
    }
    
    /**
     * 反汇编指定地址的代码
     * @param pid 进程ID
     * @param address 地址（十六进制字符串）
     * @param count 指令数量
     * @return 反汇编结果列表
     */
    public List<DisasmLine> disassemble(int pid, String address, int count) {
        try {
            DisasmLine[] lines = debugNative.disassemble(pid, address, count);
            return Arrays.asList(lines);
        } catch (Exception e) {
            Log.e(TAG, "Failed to disassemble", e);
            return Arrays.asList(new DisasmLine[0]);
        }
    }
}

