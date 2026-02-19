package com.example.myapplication.server.services;

import android.content.Context;
import android.os.Build;
import android.util.Log;

import com.example.myapplication.server.models.MemoryRegion;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;

/**
 * 内存读写服务
 */
public class MemoryService {
    private static final String TAG = "MemoryService";
    private Context context;
    
    public MemoryService(Context context) {
        this.context = context;
    }
    
    /**
     * 获取进程内存映射
     */
    public List<MemoryRegion> getMemoryMaps(int pid) {
        List<MemoryRegion> regions = new ArrayList<>();
        
        try {
            Process p = Runtime.getRuntime().exec(new String[]{"su", "-c", "cat /proc/" + pid + "/maps"});
            BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
            String line;
            
            while ((line = br.readLine()) != null) {
                // 格式: 12c00000-12c21000 rw-p 00000000 00:00 0  [heap]
                String[] parts = line.split("\\s+");
                if (parts.length >= 5) {
                    MemoryRegion region = new MemoryRegion();
                    
                    // 解析地址范围
                    String[] range = parts[0].split("-");
                    if (range.length == 2) {
                        region.setStart(range[0]);
                        region.setEnd(range[1]);
                        
                        try {
                            long start = Long.parseLong(range[0], 16);
                            long end = Long.parseLong(range[1], 16);
                            region.setSize(end - start);
                        } catch (NumberFormatException e) {
                            region.setSize(0);
                        }
                    }
                    
                    // 权限
                    region.setPerms(parts[1]);
                    
                    // 偏移
                    try {
                        region.setOffset(Long.parseLong(parts[2], 16));
                    } catch (NumberFormatException e) {
                        region.setOffset(0);
                    }
                    
                    // 设备
                    region.setDevice(parts[3]);
                    
                    // inode
                    try {
                        region.setInode(Long.parseLong(parts[4]));
                    } catch (NumberFormatException e) {
                        region.setInode(0);
                    }
                    
                    // 路径（可选）
                    if (parts.length > 5) {
                        region.setPath(parts[5]);
                    }
                    
                    regions.add(region);
                }
            }
            br.close();
            p.waitFor();
            
        } catch (Exception e) {
            Log.e(TAG, "Failed to get memory maps for pid " + pid, e);
        }
        
        return regions;
    }
    
    /**
     * 读取内存（使用memtool_procmem，绕过SELinux）
     */
    public String readMemory(int pid, String address, int length) {
        try {
            File bin = ensureMemtoolProcmem();
            // 使用/data/data/包名/lib目录（libcapstone.so所在位置）
            String libDir = "/data/data/com.example.myapplication/lib";
            String cmd = "cd " + libDir + " && LD_LIBRARY_PATH=. " +
                        bin.getAbsolutePath() + " read " + pid + " " + address + " " + length;
            
            Log.d(TAG, "readMemory cmd: " + cmd);
            
            Process p = Runtime.getRuntime().exec(new String[]{"su", "-c", cmd});
            BufferedReader reader = new BufferedReader(new InputStreamReader(p.getInputStream()));
            BufferedReader errReader = new BufferedReader(new InputStreamReader(p.getErrorStream()));
            
            String output = reader.readLine();
            
            // 读取错误输出
            String err;
            while ((err = errReader.readLine()) != null) {
                Log.e(TAG, "memtool stderr: " + err);
            }
            
            reader.close();
            errReader.close();
            
            int rc = p.waitFor();
            Log.d(TAG, "readMemory exit code: " + rc + ", output: " + output);
            
            if (rc == 0 && output != null) {
                return output.trim();
            }
            
        } catch (Exception e) {
            Log.e(TAG, "Failed to read memory", e);
        }
        
        return null;
    }
    
    /**
     * 写入内存（使用memtool_procmem，绕过SELinux）
     */
    public boolean writeMemory(int pid, String address, int value) {
        try {
            File bin = ensureMemtoolProcmem();
            // 使用/data/data/包名/lib目录（libcapstone.so所在位置）
            String libDir = "/data/data/com.example.myapplication/lib";
            
            // memtool期望的是十进制值（它内部会转换为小端序）
            String cmd = "cd " + libDir + " && LD_LIBRARY_PATH=. " +
                        bin.getAbsolutePath() + " write " + pid + " " + address + " " + value;
            
            Log.d(TAG, "writeMemory cmd: " + cmd);
            
            Process p = Runtime.getRuntime().exec(new String[]{"su", "-c", cmd});
            
            BufferedReader errReader = new BufferedReader(new InputStreamReader(p.getErrorStream()));
            String err;
            while ((err = errReader.readLine()) != null) {
                Log.e(TAG, "memtool stderr: " + err);
            }
            errReader.close();
            
            int rc = p.waitFor();
            Log.d(TAG, "writeMemory exit code: " + rc);
            
            return rc == 0;
            
        } catch (Exception e) {
            Log.e(TAG, "Failed to write memory", e);
            return false;
        }
    }
    
    /**
     * 确保memtool_procmem可执行文件存在（CE风格，绕过SELinux）
     */
    private File ensureMemtoolProcmem() throws Exception {
        String abi = Build.SUPPORTED_ABIS != null && Build.SUPPORTED_ABIS.length > 0 
                     ? Build.SUPPORTED_ABIS[0] : "arm64-v8a";
        String assetPath = "memtool/" + abi + "/memtool_procmem";
        File out = new File(context.getFilesDir(), "memtool_procmem");
        
        if (!out.exists() || out.length() == 0) {
            try (java.io.InputStream in = context.getAssets().open(assetPath);
                 java.io.FileOutputStream fos = new java.io.FileOutputStream(out)) {
                byte[] buf = new byte[8192];
                int n;
                while ((n = in.read(buf)) > 0) {
                    fos.write(buf, 0, n);
                }
            }
            Runtime.getRuntime().exec(new String[]{"su", "-c", "chmod 700 " + out.getAbsolutePath()}).waitFor();
            Log.d(TAG, "memtool_procmem extracted to: " + out.getAbsolutePath());
        }
        return out;
    }
}

