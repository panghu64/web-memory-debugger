package com.example.myapplication.util;

import android.util.Log;

import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;

public class RootUtils {
    private static final String TAG = "RootUtils";

    /**
     * 尝试请求 root 权限并校验是否为 uid=0。
     * 返回 true 表示已获取 root；否则返回 false。
     */
    public static boolean tryObtainRoot() {
        Process process = null;
        DataOutputStream os = null;
        BufferedReader reader = null;
        try {
            process = Runtime.getRuntime().exec("su");
            os = new DataOutputStream(process.getOutputStream());
            // 通过执行 id 命令判断是否为 root
            os.writeBytes("id\n");
            os.flush();
            os.writeBytes("exit\n");
            os.flush();

            int exitCode = process.waitFor();
            reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            StringBuilder out = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                out.append(line).append('\n');
            }
            String output = out.toString();
            Log.d(TAG, "su exit=" + exitCode + ", output=" + output);
            // 常见返回如：uid=0(root) gid=0(root) groups=0(root) ...
            return exitCode == 0 && output.contains("uid=0");
        } catch (Exception e) {
            Log.w(TAG, "tryObtainRoot failed", e);
            return false;
        } finally {
            if (reader != null) {
                try { reader.close(); } catch (IOException ignored) {}
            }
            if (os != null) {
                try { os.close(); } catch (IOException ignored) {}
            }
            if (process != null) {
                process.destroy();
            }
        }
    }
}

