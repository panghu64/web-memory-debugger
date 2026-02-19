package com.example.myapplication.debug;

import android.content.Context;
import android.os.Build;
import android.util.Log;

import com.example.myapplication.server.models.DisasmLine;
import com.example.myapplication.server.models.WatchpointResult;
import com.google.gson.Gson;
import com.google.gson.JsonSyntaxException;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;

/**
 * JNI 包装类，用于调用 memtool 可执行文件
 */
public class DebugNative {
    private static final String TAG = "DebugNative";
    private Context context;
    private Gson gson = new Gson();
    
    public DebugNative(Context context) {
        this.context = context;
    }
    
    /**
     * 确保memtool可执行文件和libcapstone.so存在
     */
    private File ensureMemtool() throws IOException {
        String abi = Build.SUPPORTED_ABIS != null && Build.SUPPORTED_ABIS.length > 0 
                     ? Build.SUPPORTED_ABIS[0] : "arm64-v8a";
        String assetPath = "memtool/" + abi + "/memtool";
        File out = new File(context.getFilesDir(), "memtool-" + abi);
        
        // 解压memtool
        if (!out.exists() || out.length() == 0) {
            try (InputStream in = context.getAssets().open(assetPath);
                 FileOutputStream fos = new FileOutputStream(out)) {
                byte[] buf = new byte[8192];
                int n;
                while ((n = in.read(buf)) > 0) {
                    fos.write(buf, 0, n);
                }
            }
            // 设置执行权限
            try {
                Runtime.getRuntime().exec(new String[]{"su", "-c", "chmod 700 " + out.getAbsolutePath()}).waitFor();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
        
        // 确保libcapstone.so也被解压（用于反汇编）
        File capstoneLib = new File(context.getFilesDir(), "libcapstone.so");
        if (!capstoneLib.exists() || capstoneLib.length() < 1000000) {
            // 从APK的lib目录提取（如果打包进去了）
            File apkLibDir = new File(context.getApplicationInfo().nativeLibraryDir);
            File capstoneInLib = new File(apkLibDir, "libcapstone.so");
            if (capstoneInLib.exists()) {
                try (InputStream in = new FileInputStream(capstoneInLib);
                     FileOutputStream fos = new FileOutputStream(capstoneLib)) {
                    byte[] buf = new byte[8192];
                    int n;
                    while ((n = in.read(buf)) > 0) {
                        fos.write(buf, 0, n);
                    }
                }
                Log.d(TAG, "Capstone library copied from native lib dir");
            }
        }
        
        return out;
    }
    
    /**
     * 设置硬件断点监控内存访问
     * @param pid 进程ID
     * @param address 内存地址（十六进制字符串）
     * @param timeoutSec 超时时间（秒）
     * @return WatchpointResult
     */
    public WatchpointResult setWatchpoint(int pid, String address, int timeoutSec) {
        try {
            File bin = ensureMemtool();
            // 设置LD_LIBRARY_PATH以找到libcapstone.so
            String filesDir = context.getFilesDir().getAbsolutePath();
            String cmd = "cd " + filesDir + " && LD_LIBRARY_PATH=" + filesDir + " " + 
                        bin.getAbsolutePath() + " watchpoint " + pid + " " + address + " " + timeoutSec;
            
            Process p = Runtime.getRuntime().exec(new String[]{"su", "-c", cmd});
            
            // 读取stdout（JSON输出）
            BufferedReader reader = new BufferedReader(new InputStreamReader(p.getInputStream()));
            StringBuilder output = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line);
            }
            reader.close();
            
            // 读取stderr（日志）
            BufferedReader errorReader = new BufferedReader(new InputStreamReader(p.getErrorStream()));
            while ((line = errorReader.readLine()) != null) {
                Log.d(TAG, "[memtool] " + line);
            }
            errorReader.close();
            
            int rc = p.waitFor();
            Log.d(TAG, "watchpoint exit code: " + rc);
            
            // 解析JSON结果
            String jsonResult = output.toString().trim();
            if (!jsonResult.isEmpty()) {
                try {
                    return gson.fromJson(jsonResult, WatchpointResult.class);
                } catch (JsonSyntaxException e) {
                    Log.e(TAG, "Failed to parse watchpoint result: " + jsonResult, e);
                }
            }
            
            // 失败情况
            WatchpointResult result = new WatchpointResult(false);
            result.setError("Failed to set watchpoint, exit code: " + rc);
            return result;
            
        } catch (IOException | InterruptedException e) {
            Log.e(TAG, "setWatchpoint failed", e);
            WatchpointResult result = new WatchpointResult(false);
            result.setError(e.getMessage());
            return result;
        }
    }
    
    /**
     * 反汇编内存中的代码
     * @param pid 进程ID
     * @param address 内存地址（十六进制字符串）
     * @param count 指令数量
     * @return DisasmLine数组
     */
    public DisasmLine[] disassemble(int pid, String address, int count) {
        try {
            // 使用memtool_procmem（CE风格，无需ptrace）
            File filesDir = context.getFilesDir();
            File binProcmem = new File(filesDir, "memtool_procmem");
            
            // 如果memtool_procmem不存在，解压它
            if (!binProcmem.exists()) {
                String abi = Build.SUPPORTED_ABIS != null && Build.SUPPORTED_ABIS.length > 0 
                             ? Build.SUPPORTED_ABIS[0] : "arm64-v8a";
                String assetPath = "memtool/" + abi + "/memtool_procmem";
                try (InputStream in = context.getAssets().open(assetPath);
                     FileOutputStream fos = new FileOutputStream(binProcmem)) {
                    byte[] buf = new byte[8192];
                    int n;
                    while ((n = in.read(buf)) > 0) {
                        fos.write(buf, 0, n);
                    }
                }
                Runtime.getRuntime().exec(new String[]{"su", "-c", "chmod 700 " + binProcmem.getAbsolutePath()}).waitFor();
            }
            
            // 设置LD_LIBRARY_PATH指向lib目录（包含libcapstone.so）
            String libDir = filesDir.getAbsolutePath() + "/../lib";
            String cmd = "cd " + libDir + " && LD_LIBRARY_PATH=. " + 
                        binProcmem.getAbsolutePath() + " disasm " + pid + " " + address + " " + count;
            
            Process p = Runtime.getRuntime().exec(new String[]{"su", "-c", cmd});
            
            // 读取stdout（JSON输出）
            BufferedReader reader = new BufferedReader(new InputStreamReader(p.getInputStream()));
            StringBuilder output = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line);
            }
            reader.close();
            
            // 读取stderr（日志）
            BufferedReader errorReader = new BufferedReader(new InputStreamReader(p.getErrorStream()));
            while ((line = errorReader.readLine()) != null) {
                Log.d(TAG, "[memtool] " + line);
            }
            errorReader.close();
            
            int rc = p.waitFor();
            Log.d(TAG, "disasm exit code: " + rc);
            
            // 解析JSON结果
            String jsonResult = output.toString().trim();
            if (!jsonResult.isEmpty() && rc == 0) {
                try {
                    return gson.fromJson(jsonResult, DisasmLine[].class);
                } catch (JsonSyntaxException e) {
                    Log.e(TAG, "Failed to parse disasm result: " + jsonResult, e);
                }
            }
            
            return new DisasmLine[0];
            
        } catch (IOException | InterruptedException e) {
            Log.e(TAG, "disassemble failed", e);
            return new DisasmLine[0];
        }
    }
}

