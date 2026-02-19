package com.example.myapplication.server.services;

import android.content.Context;
import android.util.Log;

import com.example.myapplication.debug.DebugNative;
import com.example.myapplication.server.models.WatchpointResult;

/**
 * 调试服务（硬件断点等）
 */
public class DebugService {
    private static final String TAG = "DebugService";
    private DebugNative debugNative;
    
    public DebugService(Context context) {
        this.debugNative = new DebugNative(context);
    }
    
    /**
     * 设置硬件断点监控内存访问
     * @param pid 进程ID
     * @param address 地址（十六进制字符串）
     * @param timeout 超时时间（秒）
     * @return 断点结果
     */
    public WatchpointResult setWatchpoint(int pid, String address, int timeout) {
        try {
            return debugNative.setWatchpoint(pid, address, timeout);
        } catch (Exception e) {
            Log.e(TAG, "Failed to set watchpoint", e);
            WatchpointResult result = new WatchpointResult(false);
            result.setError(e.getMessage());
            return result;
        }
    }
}

