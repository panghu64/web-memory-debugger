package com.example.myapplication;

import android.content.Intent;
import android.os.Handler;
import android.os.Looper;
import android.util.Log;
import android.os.Build;
import android.view.Gravity;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;
import android.widget.CheckBox;
import androidx.appcompat.app.AlertDialog;
import androidx.appcompat.app.AppCompatActivity;
import android.os.Bundle;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.Scanner;
import com.example.myapplication.util.Utils;
import com.example.myapplication.server.MemoryDebugService;

public class MainActivity extends AppCompatActivity {

    // Web调试服务器
    private boolean serverRunning = false;
    private Button btnStartServer;
    private TextView tvServerStatus;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        // 1. 首先初始化Activity
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        
        // 2. 然后再使用Toast
        // 在子线程中执行Root权限检查
        new Thread(new Runnable() {
            @Override
            public void run() {
                try {
                    Process process = Runtime.getRuntime().exec(new String[]{"su", "-c", "id"});
                    int result = process.waitFor();
                    System.out.println(result+"666666666666666666666666666");
                    final boolean isRootSuccess = (result == 0);
                    
                    // 确保在主线程上显示Toast和提示框
                    runOnUiThread(new Runnable() {
                        @Override
                        public void run() {
                            if (isRootSuccess) {
                                showRootSuccessMessage();
                            } else {
                                showRootFailureMessage();
                            }
                        }
                    });
                } catch (Exception e) {
                    // 捕获异常后在主线程显示失败消息
                    runOnUiThread(new Runnable() {
                        @Override
                        public void run() {
                            showRootFailureMessage();
                        }
                    });
                }
            }
        }).start();
        TextView tv = findViewById(R.id.tv);
        tv.setText("你好，世界");
        System.out.println(tv.getText());
        Button but = findViewById(R.id.but);
        but.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                // 显示Toast提示
                Toast.makeText(MainActivity.this, "按钮被点击了！", Toast.LENGTH_SHORT).show();
                
                // 获取进程ID并打开进程
                new Thread(new Runnable() {
                    @Override
                    public void run() {
                        try {
                            // 这里假设我们要操作的是当前应用的进程，也可以修改为其他进程名
                            String targetProcessName = "com.tencent.tmgp.codev";
                            int pid = getPidByProcessName(targetProcessName);
                            
                            if (pid > 0) {
                                // 使用Root权限打开进程
                                boolean isProcessOpened = openProcessWithRoot(pid);
                                
                                final String message;
                                if (isProcessOpened) {
                                    message = "成功打开进程: " + targetProcessName + " (PID: " + pid + ")，可以开始内存读写操作";
                                } else {
                                    message = "无法打开进程，请检查Root权限";
                                }
                                
                                // 保存pid值用于Toast显示
                                final int finalPid = pid;
                                
                                // 在主线程显示结果和Toast
                                runOnUiThread(new Runnable() {
                                    @Override
                                    public void run() {
                                        // 显示Toast提示获取到的pid
                                        Toast.makeText(MainActivity.this, "获取到的进程PID: " + finalPid, Toast.LENGTH_SHORT).show();
                                        showCustomAlertDialog("进程操作结果", message);
                                    }
                                });
                            } else {
                                runOnUiThread(new Runnable() {
                                    @Override
                                    public void run() {
                                        showCustomAlertDialog("错误", "未找到目标进程: " + targetProcessName);
                                    }
                                });
                            }
                        } catch (Exception e) {
                            final String errorMessage = "操作进程时出错: " + e.getMessage();
                            runOnUiThread(new Runnable() {
                                @Override
                                public void run() {
                                    showCustomAlertDialog("错误", errorMessage);
                                }
                            });
                        }
                    }
                }).start();
                
                // 原有功能：启动MainActivity2
                // 已注释掉跳转页面功能
                /*
                Intent intent = new Intent();
                intent.setClass(MainActivity.this,MainActivity2.class);
                startActivity(intent);
                */
            }
        });
        TextView tv_code = findViewById(R.id.tv_code);
        ViewGroup.LayoutParams params = tv_code.getLayoutParams();
        params.width = Utils.dip2px(this,200);
        tv_code.setLayoutParams(params);
        
        // 初始化Web服务器控件
        btnStartServer = findViewById(R.id.btn_start_server);
        tvServerStatus = findViewById(R.id.tv_server_status);
        
        btnStartServer.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                if (!serverRunning) {
                    startWebServer();
                } else {
                    stopWebServer();
                }
            }
        });
        
        // 自动启动Web服务器（前台服务）
        new Handler(Looper.getMainLooper()).postDelayed(new Runnable() {
            @Override
            public void run() {
                if (!serverRunning) {
                    startWebServer();
                }
            }
        }, 2000); // 延迟2秒后自动启动
        
        // 添加新按钮but1及其点击事件
        Button but1 = findViewById(R.id.but1);
        but1.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                // 显示Toast提示
                Toast.makeText(MainActivity.this, "开始读取内存地址...", Toast.LENGTH_SHORT).show();
                
                // 在子线程中读取内存地址
                new Thread(new Runnable() {
                    @Override
                    public void run() {
                        try {
                            // 目标进程名
                            String targetProcessName = "com.zwjszz.mi";
                            // 目标内存地址
                            final String targetAddress = "6DB2031D58";
                            
                            // 获取进程ID
                            int pid = getPidByProcessName(targetProcessName);
                            
                            // 调试：显示获取到的PID
                            runOnUiThread(new Runnable() {
                                @Override
                                public void run() {
                                    Toast.makeText(MainActivity.this, "获取到PID: " + pid, Toast.LENGTH_SHORT).show();
                                }
                            });
                            
                            if (pid > 0) {
                                // 调试：即将调用readMemoryValue方法
                                runOnUiThread(new Runnable() {
                                    @Override
                                    public void run() {
                                        Toast.makeText(MainActivity.this, "准备读取内存地址: " + targetAddress, Toast.LENGTH_SHORT).show();
                                    }
                                });
                                
                                // 读取内存地址值（4字节）
                                final int memoryValue = readMemoryValue(pid, targetAddress);
                                
                                // 调试：readMemoryValue返回值
                                runOnUiThread(new Runnable() {
                                    @Override
                                    public void run() {
                                        Toast.makeText(MainActivity.this, "readMemoryValue返回: " + memoryValue + " (Integer.MIN_VALUE=" + Integer.MIN_VALUE + ")", Toast.LENGTH_SHORT).show();
                                        // 根据返回值决定日志级别
                                        if (memoryValue == Integer.MIN_VALUE) {
                                            Log.e("MainActivity", "readMemoryValue返回: " + memoryValue + " (读取失败)");
                                        } else {
                                            Log.d("MainActivity", "readMemoryValue返回: " + memoryValue + " (读取成功)");
                                        }
                                    }
                                });
                                
                                // 写入4字节的新值 10000 (0x00002710, 小端 10 27 00 00)，并验证
                                if (memoryValue != Integer.MIN_VALUE) {
                                    final int newValue = 10000;
                                    boolean writable = isAddressWritable(pid, targetAddress);
                                    Log.d("MainActivity", "地址可写检查: " + writable);
                                    boolean writeOk = writeMemoryValue4(pid, targetAddress, newValue);
                                    Log.d("MainActivity", "写入新值结果: " + writeOk);
                                    // 再次读取验证
                                    int verify = readMemoryValue(pid, targetAddress);
                                    Log.d("MainActivity", "写入后读取值: " + verify);
                                }

                                // 在主线程显示结果
                                runOnUiThread(new Runnable() {
                                    @Override
                                    public void run() {
                                        if (memoryValue != Integer.MIN_VALUE) {
                                            Toast.makeText(MainActivity.this, "内存地址 " + targetAddress + " 的值: " + memoryValue, Toast.LENGTH_SHORT).show();
                                        } else {
                                            Toast.makeText(MainActivity.this, "读取内存地址失败", Toast.LENGTH_SHORT).show();
                                        }
                                    }
                                });
                            } else {
                                runOnUiThread(new Runnable() {
                                    @Override
                                    public void run() {
                                        Toast.makeText(MainActivity.this, "未找到目标进程: " + targetProcessName, Toast.LENGTH_SHORT).show();
                                    }
                                });
                            }
                        } catch (Exception e) {
                            final String errorMessage = "读取内存地址时出错: " + e.getMessage();
                            runOnUiThread(new Runnable() {
                                @Override
                                public void run() {
                                    Toast.makeText(MainActivity.this, errorMessage, Toast.LENGTH_SHORT).show();
                                }
                            });
                        }
                    }
                }).start();
            }
        });

        // 写入并校验按钮：读取用户输入的地址与整数值，执行写入并再读回
        Button btnWrite = findViewById(R.id.btn_write);
        EditText etAddress = findViewById(R.id.et_address);
        EditText etValue = findViewById(R.id.et_value);
        btnWrite.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                final String addressHex = etAddress.getText() != null ? etAddress.getText().toString().trim() : "";
                final String valueStr = etValue.getText() != null ? etValue.getText().toString().trim() : "";
                if (addressHex.isEmpty()) {
                    Toast.makeText(MainActivity.this, "请输入64位地址", Toast.LENGTH_SHORT).show();
                    return;
                }
                int val;
                try {
                    val = Integer.parseInt(valueStr);
                } catch (Exception ex) {
                    Toast.makeText(MainActivity.this, "请输入有效的整数值", Toast.LENGTH_SHORT).show();
                    return;
                }

                Toast.makeText(MainActivity.this, "开始写入并校验...", Toast.LENGTH_SHORT).show();

                new Thread(new Runnable() {
                    @Override
                    public void run() {
                        String targetProcessName = "com.tencent.tmgp.codev";
                        int pid = getPidByProcessName(targetProcessName);
                        if (pid <= 0) {
                            runOnUiThread(() -> Toast.makeText(MainActivity.this, "未找到目标进程", Toast.LENGTH_SHORT).show());
                            return;
                        }

                        boolean writable = isAddressWritable(pid, addressHex);
                        Log.d("MainActivity", "地址可写检查(用户输入): " + writable);
                        boolean writeOk = writeMemoryValue4(pid, addressHex, val);
                        String backHex = memtoolReadHex(pid, addressHex, 4);
                        int verify = (backHex != null && backHex.length() >= 8)
                                ? parseLittleEndianInt(backHex.substring(0, 8))
                                : readMemoryValue(pid, addressHex);
                        Log.d("MainActivity", "readback via memtool: hex=" + (backHex == null ? "-" : backHex) + ", val=" + verify);

                        runOnUiThread(() -> {
                            Toast.makeText(MainActivity.this,
                                    "写入" + (writeOk ? "成功" : "失败") + ", 读回=" + verify,
                                    Toast.LENGTH_LONG).show();
                        });
                    }
                }).start();
            }
        });
    }
    
    /**
     * 显示Root权限获取成功的消息
     */
    private void showRootSuccessMessage() {
        // 显示Toast提示
        Toast.makeText(this, "获取Root成功!", Toast.LENGTH_SHORT).show();
        
        // 在Toast下方显示额外的提示框
        showCustomAlertDialog("提示", "Root权限已成功获取，您可以使用需要Root权限的功能了。");
    }
    
    /**
     * 显示Root权限获取失败的消息
     */
    private void showRootFailureMessage() {
        // 显示Toast提示
        Toast.makeText(this, "获取Root失败", Toast.LENGTH_SHORT).show();
        
        // 在Toast下方显示额外的提示框
        showCustomAlertDialog("提示", "无法获取Root权限，请确保您的设备已Root。");
    }
    
    /**
     * 显示自定义提示框
     * @param title 标题
     * @param message 消息内容
     */
    private void showCustomAlertDialog(String title, String message) {
        // 使用AlertDialog.Builder创建提示框
        AlertDialog.Builder builder = new AlertDialog.Builder(this);
        builder.setTitle(title)
               .setMessage(message)
               .setPositiveButton("确定", null) // 只添加一个确定按钮，点击后关闭对话框
               .show();
    }
    
    /**
     * 根据进程名获取进程ID
     * @param processName 进程名
     * @return 进程ID，如果未找到返回-1
     */
    private int getPidByProcessName(String processName) {
        try {
            // 方法1: 尝试通过/proc目录读取
            File procDir = new File("/proc");
            File[] files = procDir.listFiles();
            if (files != null) {
                for (File file : files) {
                    if (file.isDirectory()) {
                        try {
                            int pid = Integer.parseInt(file.getName());
                            File cmdlineFile = new File(file, "cmdline");
                            if (cmdlineFile.exists()) {
                                // 使用更可靠的方式读取cmdline文件
                                StringBuilder cmdlineBuilder = new StringBuilder();
                                FileInputStream fis = new FileInputStream(cmdlineFile);
                                byte[] buffer = new byte[1024];
                                int bytesRead = fis.read(buffer);
                                fis.close();
                                
                                if (bytesRead > 0) {
                                    // cmdline文件中的进程名以null字符分隔，需要处理
                                    for (int i = 0; i < bytesRead; i++) {
                                        if (buffer[i] == 0) break;
                                        cmdlineBuilder.append((char) buffer[i]);
                                    }
                                    String cmdline = cmdlineBuilder.toString().trim();
                                    
                                    Log.d("MainActivity", "检查进程: PID=" + pid + ", CMDLINE=" + cmdline);
                                    
                                    if (cmdline.contains(processName)) {
                                        Log.d("MainActivity", "找到匹配进程: " + processName + " PID=" + pid);
                                        return pid;
                                    }
                                }
                            }
                        } catch (NumberFormatException e) {
                            // 忽略非数字文件夹
                        }
                    }
                }
            }
            
            // 方法2: 如果方法1失败，尝试使用ps命令（需要Root权限）
            Log.d("MainActivity", "尝试使用ps命令获取进程PID");
            Process process = Runtime.getRuntime().exec(new String[]{"su", "-c", "ps | grep " + processName});
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.contains(processName)) {
                    String[] parts = line.trim().split("\\s+");
                    if (parts.length >= 2) {
                        try {
                            int pid = Integer.parseInt(parts[1]);
                            Log.d("MainActivity", "通过ps命令找到进程: " + processName + " PID=" + pid);
                            return pid;
                        } catch (NumberFormatException e) {
                            // 忽略格式错误
                        }
                    }
                }
            }
            reader.close();
            
        } catch (Exception e) {
            Log.e("MainActivity", "获取进程ID失败: " + e.getMessage(), e);
        }
        
        Log.d("MainActivity", "未找到进程: " + processName);
        return -1;
    }
    
    /**
     * 使用Root权限打开进程
     * @param pid 进程ID
     * @return 是否成功打开
     */
    private boolean openProcessWithRoot(int pid) {
        try {
            // 使用Root权限检查是否可以访问进程内存
            Process process = Runtime.getRuntime().exec(new String[]{"su", "-c", "ls -la /proc/" + pid + "/mem"});
            int result = process.waitFor();
            return result == 0;
        } catch (Exception e) {
            Log.e("MainActivity", "打开进程失败", e);
            return false;
        }
    }
    
    /**
     * 读取指定进程的内存地址值
     * @param pid 进程ID
     * @param address 十六进制内存地址字符串
     * @return 读取到的整数值，如果失败返回Integer.MIN_VALUE
     */
    private int readMemoryValue(int pid, String address) {
        try {
            // 先检查进程是否存在
            if (!checkProcessExists(pid)) {
                Log.e("MainActivity", "进程 " + pid + " 不存在");
                final String processNotFound = "进程 " + pid + " 不存在或已终止";
                new Handler(Looper.getMainLooper()).post(new Runnable() {
                    @Override
                    public void run() {
                        Toast.makeText(MainActivity.this, processNotFound, Toast.LENGTH_SHORT).show();
                    }
                });
                return Integer.MIN_VALUE;
            }
            
            // 检查/proc/pid/mem文件权限
            if (!checkMemoryFileAccess(pid)) {
                Log.e("MainActivity", "没有足够权限访问进程 " + pid + " 的内存");
                final String permissionDenied = "没有足够权限访问进程内存，请确保已获取Root权限";
                new Handler(Looper.getMainLooper()).post(new Runnable() {
                    @Override
                    public void run() {
                        Toast.makeText(MainActivity.this, permissionDenied, Toast.LENGTH_SHORT).show();
                    }
                });
                return Integer.MIN_VALUE;
            }
            
            // 方法1: 使用dd+xxd命令读取内存
            int value = readMemoryWithDD2(pid, address);
            if (value != Integer.MIN_VALUE) {
                return value;
            }
            
            // 方法2: 如果方法1失败，尝试使用hexdump命令（备选方案）
            Log.d("MainActivity", "dd命令读取失败，尝试使用hexdump命令");
            value = readMemoryWithHexdump2(pid, address);
            if (value != Integer.MIN_VALUE) {
                return value;
            }
            
            // 方法3: 尝试读取更大范围的内存（可能地址对齐有问题）
            Log.d("MainActivity", "hexdump命令读取失败，尝试读取更大范围的内存");
            value = readMemoryWithLargerBlock2(pid, address);
            if (value != Integer.MIN_VALUE) {
                return value;
            }
            
            // 所有方法都失败，显示详细的错误分析
            Log.e("MainActivity", "所有内存读取方法都失败，地址: " + address + ", PID: " + pid);
            final String allMethodsFailed = "无法读取内存地址 " + address + ". 可能原因: 1)地址不存在 2)地址受保护 3)进程内存结构特殊 4)Root权限不足";
            new Handler(Looper.getMainLooper()).post(new Runnable() {
                @Override
                public void run() {
                    Toast.makeText(MainActivity.this, allMethodsFailed, Toast.LENGTH_LONG).show();
                }
            });
        } catch (Exception e) {
            Log.e("MainActivity", "读取内存值失败: " + e.getMessage(), e);
            final String exceptionError = "读取内存时出现异常: " + e.getMessage();
            new Handler(Looper.getMainLooper()).post(new Runnable() {
                @Override
                public void run() {
                    Toast.makeText(MainActivity.this, exceptionError, Toast.LENGTH_SHORT).show();
                }
            });
        }
        return Integer.MIN_VALUE; // 表示读取失败
    }
    
    /**
     * 检查进程是否存在（使用root权限）
     */
    private boolean checkProcessExists(int pid) {
        try {
            // 尝试使用文件检查方法
            File procDir = new File("/proc/" + pid);
            if (procDir.exists() && procDir.isDirectory()) {
                return true;
            }
            
            // 如果文件检查失败，尝试使用root权限检查
            Log.d("MainActivity", "文件检查失败，尝试使用root权限检查进程是否存在: " + pid);
            Process process = Runtime.getRuntime().exec(new String[]{"su", "-c", "ls -d /proc/" + pid});
            int result = process.waitFor();
            boolean exists = (result == 0);
            Log.d("MainActivity", "root权限检查进程结果: " + exists);
            return exists;
        } catch (Exception e) {
            Log.e("MainActivity", "检查进程是否存在时出错: " + e.getMessage());
            return false;
        }
    }
    
    /**
     * 检查是否有访问内存文件的权限（使用root权限）
     */
    private boolean checkMemoryFileAccess(int pid) {
        try {
            // 使用root权限检查内存文件是否可访问
            Log.d("MainActivity", "使用root权限检查内存文件访问权限: /proc/" + pid + "/mem");
            Process process = Runtime.getRuntime().exec(new String[]{"su", "-c", "test -r /proc/" + pid + "/mem && echo accessible || echo not_accessible"});
            
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            String output = reader.readLine();
            reader.close();
            
            int result = process.waitFor();
            boolean hasAccess = (result == 0 && output != null && output.contains("accessible"));
            
            Log.d("MainActivity", "内存文件访问权限检查结果: " + hasAccess + ", 命令输出: " + output);
            return hasAccess;
        } catch (Exception e) {
            Log.e("MainActivity", "检查内存文件权限时出错: " + e.getMessage());
            return false;
        }
    }
    
    /**
     * 将8位十六进制（按内存字节顺序）解析为小端32位整数
     */
    private int parseLittleEndianInt(String hex8) {
        if (hex8 == null || hex8.length() < 8) {
            throw new IllegalArgumentException("hex8 must be 8 chars");
        }
        String b0 = hex8.substring(0, 2);
        String b1 = hex8.substring(2, 4);
        String b2 = hex8.substring(4, 6);
        String b3 = hex8.substring(6, 8);
        String leHex = b3 + b2 + b1 + b0;
        long unsigned = Long.parseLong(leHex, 16);
        return (int) unsigned;
    }

    /**
     * 使用dd+xxd读取4字节（优先iflag字节跳过，失败回退bs=1）
     */
    private int readMemoryWithDD2(int pid, String address) {
        try {
            long addr = Long.parseLong(address, 16);

            // A: iflag=skip_bytes,count_bytes（字节级skip）
            String innerA = "dd if=/proc/" + pid + "/mem iflag=skip_bytes,count_bytes skip=" + addr + " count=4 status=none 2>/dev/null | xxd -p -c 4 -l 4";
            Log.d("MainActivity", "执行dd按字节跳过命令: " + innerA);
            Process processA = Runtime.getRuntime().exec(new String[]{"su", "-c", innerA});
            BufferedReader readerA = new BufferedReader(new InputStreamReader(processA.getInputStream()));
            String outputA = readerA.readLine();
            readerA.close();
            int resultA = processA.waitFor();
            if (resultA == 0 && outputA != null && !outputA.isEmpty() && outputA.length() >= 8) {
                String hex8 = outputA.trim().substring(0, 8);
                int value = parseLittleEndianInt(hex8);
                Log.d("MainActivity", "dd(字节跳过)读取内存成功: hex=" + hex8 + ", 值=" + value);
                return value;
            }

            // B: 回退 bs=1（通用但稍慢）
            String innerB = "dd if=/proc/" + pid + "/mem bs=1 count=4 skip=" + addr + " status=none 2>/dev/null | xxd -p";
            Log.d("MainActivity", "执行dd(bs=1)回退命令: " + innerB);
            Process processB = Runtime.getRuntime().exec(new String[]{"su", "-c", innerB});
            BufferedReader readerB = new BufferedReader(new InputStreamReader(processB.getInputStream()));
            String outputB = readerB.readLine();
            readerB.close();
            int resultB = processB.waitFor();
            if (resultB == 0 && outputB != null && !outputB.isEmpty() && outputB.length() >= 8) {
                String hex8 = outputB.trim().substring(0, 8);
                int value = parseLittleEndianInt(hex8);
                Log.d("MainActivity", "dd(bs=1)读取内存成功: hex=" + hex8 + ", 值=" + value);
                return value;
            }

            Log.d("MainActivity", "dd读取失败，A: result=" + resultA + "; B: result=" + resultB);
        } catch (Exception e) {
            Log.e("MainActivity", "dd命令执行失败: " + e.getMessage());
        }
        return Integer.MIN_VALUE;
    }

    /**
     * 使用hexdump读取4字节（字节序解析为int小端）
     */
    private int readMemoryWithHexdump2(int pid, String address) {
        try {
            long addr = Long.parseLong(address, 16);
            String inner = "dd if=/proc/" + pid + "/mem iflag=skip_bytes,count_bytes skip=" + addr + " count=4 status=none 2>/dev/null | hexdump -v -e '1/1 \"%02x\"'";
            Log.d("MainActivity", "执行hexdump命令: " + inner);
            Process process = Runtime.getRuntime().exec(new String[]{"su", "-c", inner});
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            String output = reader.readLine();
            reader.close();
            int result = process.waitFor();
            if (result == 0 && output != null && !output.isEmpty() && output.length() >= 8) {
                String hex8 = output.trim().substring(0, 8);
                int value = parseLittleEndianInt(hex8);
                Log.d("MainActivity", "hexdump读取内存成功: hex=" + hex8 + ", 值=" + value);
                return value;
            }
        } catch (Exception e) {
            Log.e("MainActivity", "hexdump命令执行失败: " + e.getMessage());
        }
        return Integer.MIN_VALUE;
    }

    /**
     * 读取更大范围的内存块（小端解析目标偏移4字节）
     */
    private int readMemoryWithLargerBlock2(int pid, String address) {
        try {
            long baseAddress = Long.parseLong(address, 16) - 16; // 向前偏移16字节
            String inner = "dd if=/proc/" + pid + "/mem bs=1 count=32 skip=" + baseAddress + " status=none 2>/dev/null | xxd -p";
            Log.d("MainActivity", "执行大区块读取命令: " + inner);
            Process process = Runtime.getRuntime().exec(new String[]{"su", "-c", inner});
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            StringBuilder fullOutput = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                fullOutput.append(line);
            }
            reader.close();
            int result = process.waitFor();
            String output = fullOutput.toString().trim();
            if (result == 0 && output != null && !output.isEmpty() && output.length() >= 32) {
                int targetOffset = 16 * 2; // 跳过前16字节
                if (targetOffset + 8 <= output.length()) {
                    String targetBytes = output.substring(targetOffset, targetOffset + 8);
                    return parseLittleEndianInt(targetBytes);
                }
            }
        } catch (Exception e) {
            Log.e("MainActivity", "大区块读取失败: " + e.getMessage());
        }
        return Integer.MIN_VALUE;
    }

    /** 判断地址所在映射是否具备写权限（解析 /proc/<pid>/maps） */
    private boolean isAddressWritable(int pid, String address) {
        try {
            long addr = Long.parseLong(address, 16);
            Process p = Runtime.getRuntime().exec(new String[]{"su","-c","cat /proc/"+pid+"/maps"});
            BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
            String line;
            while ((line = br.readLine()) != null) {
                // 形如: 12c00000-12c21000 rw-p 00000000 00:00 0                                  [heap]
                String[] parts = line.split("\\s+");
                if (parts.length >= 2) {
                    String[] range = parts[0].split("-");
                    String perms = parts[1];
                    if (range.length == 2) {
                        long start = Long.parseLong(range[0], 16);
                        long end = Long.parseLong(range[1], 16);
                        if (addr >= start && addr < end) {
                            boolean writable = perms.contains("w");
                            Log.d("MainActivity", String.format("映射命中: %s perms=%s writable=%s", parts[0], perms, String.valueOf(writable)));
                            return writable;
                        }
                    }
                }
            }
            br.close();
        } catch (Exception e) {
            Log.e("MainActivity", "检查可写映射失败: "+e.getMessage());
        }
        return false;
    }
    
    /**
     * 使用dd+xxd命令读取内存
     */
    private int readMemoryWithDD(int pid, String address) {
        try {
            // 优化dd命令，正确计算内存地址（除以块大小bs=4）
            // 使用skip参数时，实际是跳过的块数，不是字节数
            // 需要先将十六进制地址转换为十进制，再除以块大小4
            String command = "su -c \"dd if=/proc/" + pid + "/mem bs=4 count=1 skip=$((0x" + address + ">>2)) 2>/dev/null | xxd -p | head -n 1\"";
            
            Log.d("MainActivity", "执行优化后的dd命令: " + command);
            
            Process process = Runtime.getRuntime().exec(new String[]{"su", "-c", command});
            
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            BufferedReader errorReader = new BufferedReader(new InputStreamReader(process.getErrorStream()));
            
            String output = reader.readLine();
            String errorOutput = errorReader.readLine();
            
            reader.close();
            errorReader.close();
            
            int result = process.waitFor();
            
            final String debugOutput = "dd命令结果: " + result + ", 输出: " + (output != null ? output : "null");
            new Handler(Looper.getMainLooper()).post(new Runnable() {
                @Override
                public void run() {
                    Toast.makeText(MainActivity.this, debugOutput, Toast.LENGTH_LONG).show();
                }
            });
            
            if (result == 0 && output != null && !output.isEmpty()) {
                try {
                    if (output.length() == 8) {
                        // 反转字节顺序
                        String reversed = new StringBuilder(output).reverse().toString();
                        // 重新分组为每两个字符
                        StringBuilder fixed = new StringBuilder();
                        for (int i = 0; i < reversed.length(); i += 2) {
                            if (i + 1 < reversed.length()) {
                                fixed.append(reversed.charAt(i + 1)).append(reversed.charAt(i));
                            }
                        }
                        // 使用Long.parseLong处理可能超过int范围的无符号整数
                        long longValue = Long.parseLong(fixed.toString(), 16);
                        // 如果值在int范围内，返回int；否则返回long的低32位
                        int value = (int) longValue;
                        Log.d("MainActivity", "dd命令成功读取内存值: " + value + " (原始值: " + longValue + ")");
                        return value;
                    } else {
                        // 使用Long.parseLong处理可能超过int范围的无符号整数
                        long longValue = Long.parseLong(output, 16);
                        // 如果值在int范围内，返回int；否则返回long的低32位
                        int value = (int) longValue;
                        Log.d("MainActivity", "dd命令成功读取内存值: " + value + " (原始值: " + longValue + ")");
                        return value;
                    }
                } catch (NumberFormatException e) {
                    Log.e("MainActivity", "dd命令输出转换失败: " + e.getMessage());
                }
            }
        } catch (Exception e) {
            Log.e("MainActivity", "dd命令执行失败: " + e.getMessage());
        }
        return Integer.MIN_VALUE;
    }
    
    /**
     * 使用hexdump命令读取内存（备选方案）
     */
    private int readMemoryWithHexdump(int pid, String address) {
        try {
            // 修复地址计算，与dd方法保持一致
            String command = "su -c \"dd if=/proc/" + pid + "/mem bs=4 count=1 skip=$((0x" + address + ">>2)) 2>/dev/null | hexdump -e '4/1 \"%02x\"'\"";
            
            Log.d("MainActivity", "执行优化后的hexdump命令: " + command);
            
            Process process = Runtime.getRuntime().exec(new String[]{"su", "-c", command});
            
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            String output = reader.readLine();
            reader.close();
            
            int result = process.waitFor();
            
            if (result == 0 && output != null && !output.isEmpty() && output.length() >= 8) {
                String trimmedOutput = output.trim();
                if (trimmedOutput.length() >= 8) {
                        // 使用Long.parseLong处理可能超过int范围的无符号整数
                        long longValue = Long.parseLong(trimmedOutput.substring(0, 8), 16);
                        // 如果值在int范围内，返回int；否则返回long的低32位
                        int value = (int) longValue;
                        Log.d("MainActivity", "hexdump命令成功读取内存值: " + value + " (原始值: " + longValue + ")");
                    final String successMsg = "hexdump命令成功读取内存值: " + value;
                    new Handler(Looper.getMainLooper()).post(new Runnable() {
                        @Override
                        public void run() {
                            Toast.makeText(MainActivity.this, successMsg, Toast.LENGTH_SHORT).show();
                        }
                    });
                    return value;
                }
            }
        } catch (Exception e) {
            Log.e("MainActivity", "hexdump命令执行失败: " + e.getMessage());
        }
        return Integer.MIN_VALUE;
    }
    
    /**
     * 读取更大范围的内存块（可能地址对齐有问题）
     */
    private int readMemoryWithLargerBlock(int pid, String address) {
        try {
            // 计算对齐的基地址（减去一些偏移量）
            long baseAddress = Long.parseLong(address, 16) - 16; // 向前偏移16字节
            String command = "su -c \"dd if=/proc/" + pid + "/mem bs=1 count=32 skip=" + baseAddress + " 2>/dev/null | xxd -p\"";
            
            Log.d("MainActivity", "执行优化后的大区块读取命令: " + command);
            
            Process process = Runtime.getRuntime().exec(new String[]{"su", "-c", command});
            
            // 同时读取标准输出和错误输出
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            BufferedReader errorReader = new BufferedReader(new InputStreamReader(process.getErrorStream()));
            
            StringBuilder fullOutput = new StringBuilder();
            StringBuilder errorOutput = new StringBuilder();
            
            String line;
            while ((line = reader.readLine()) != null) {
                fullOutput.append(line);
            }
            while ((line = errorReader.readLine()) != null) {
                errorOutput.append(line);
            }
            
            reader.close();
            errorReader.close();
            
            int result = process.waitFor();
            
            String output = fullOutput.toString().trim();
            String errOutput = errorOutput.toString().trim();
            
            // 添加详细的调试信息
            Log.d("MainActivity", "大区块命令结果: " + result + ", 输出: " + (output.isEmpty() ? "空" : output) + ", 错误输出: " + (errOutput.isEmpty() ? "空" : errOutput));
            
            // 在主线程显示调试信息
            final String debugOutput = "大区块结果: " + result + ", 输出长度: " + output.length() + "字节";
            new Handler(Looper.getMainLooper()).post(new Runnable() {
                @Override
                public void run() {
                    Toast.makeText(MainActivity.this, debugOutput, Toast.LENGTH_LONG).show();
                }
            });
            
            if (result == 0 && output != null && !output.isEmpty() && output.length() >= 32) {
                // 从完整输出中提取目标地址附近的数据（跳过前面16字节，取8个字符即4字节）
                int targetOffset = 16 * 2; // 16字节 = 32个十六进制字符
                if (targetOffset + 8 <= output.length()) {
                    String targetBytes = output.substring(targetOffset, targetOffset + 8);
                    try {
                            // 使用Long.parseLong处理可能超过int范围的无符号整数
                            long longValue = Long.parseLong(targetBytes, 16);
                            // 如果值在int范围内，返回int；否则返回long的低32位
                            int value = (int) longValue;
                            Log.d("MainActivity", "大区块读取成功获取内存值: " + value + " (原始值: " + longValue + ")");
                            final String successMsg = "大区块读取成功获取内存值: " + value;
                            new Handler(Looper.getMainLooper()).post(new Runnable() {
                                @Override
                                public void run() {
                                    Toast.makeText(MainActivity.this, successMsg, Toast.LENGTH_SHORT).show();
                                }
                            });
                            return value;
                    } catch (NumberFormatException e) {
                        Log.e("MainActivity", "大区块输出转换失败: " + e.getMessage());
                    }
                }
                
                // 调试：显示完整的内存块数据
                Log.d("MainActivity", "大区块读取到的数据: " + output);
                final String largeBlockData = "大区块读取数据: " + output.substring(0, Math.min(32, output.length())) + "...";
                new Handler(Looper.getMainLooper()).post(new Runnable() {
                    @Override
                    public void run() {
                        Toast.makeText(MainActivity.this, largeBlockData, Toast.LENGTH_LONG).show();
                    }
                });
            }
        } catch (Exception e) {
            Log.e("MainActivity", "大区块读取失败: " + e.getMessage());
        }
        return Integer.MIN_VALUE;
    }

    /**
     * 将int以小端方式写入到给定的64位地址（只写4字节）
     */
    private boolean writeMemoryValue4(int pid, String address, int value) {
        try {
            long addr = Long.parseLong(address, 16);

            int b0 = value & 0xFF;
            int b1 = (value >>> 8) & 0xFF;
            int b2 = (value >>> 16) & 0xFF;
            int b3 = (value >>> 24) & 0xFF;
            String bytesEscaped = String.format("\\x%02x\\x%02x\\x%02x\\x%02x", b0, b1, b2, b3);

            // A: 使用 oflag=seek_bytes（优先），移除不被toybox支持的 iflag=fullblock
            String innerA = "printf \"" + bytesEscaped + "\" | dd of=/proc/" + pid + "/mem oflag=seek_bytes conv=notrunc seek=" + addr + " bs=1 count=4 status=none";
            Log.d("MainActivity", "执行写内存命令A: " + innerA);
            Process pa = Runtime.getRuntime().exec(new String[]{"su", "-c", innerA});
            BufferedReader ea = new BufferedReader(new InputStreamReader(pa.getErrorStream()));
            StringBuilder eab = new StringBuilder();
            String el;
            while ((el = ea.readLine()) != null) { eab.append(el); }
            ea.close();
            int ra = pa.waitFor();
            if (ra == 0) {
                Log.d("MainActivity", "写入成功(A) at 0x" + address + ": " + value);
                return true;
            }
            Log.e("MainActivity", "A失败, stderr: "+eab.toString());

            // B: 回退到 bs=1 + seek（按字节寻址），同样不使用 iflag=fullblock
            String innerB = "printf \"" + bytesEscaped + "\" | dd of=/proc/" + pid + "/mem bs=1 seek=" + addr + " conv=notrunc count=4 status=none";
            Log.d("MainActivity", "执行写内存命令B: " + innerB);
            Process pb = Runtime.getRuntime().exec(new String[]{"su", "-c", innerB});
            BufferedReader eb = new BufferedReader(new InputStreamReader(pb.getErrorStream()));
            StringBuilder ebb = new StringBuilder();
            while ((el = eb.readLine()) != null) { ebb.append(el); }
            eb.close();
            int rb = pb.waitFor();
            if (rb == 0) {
                Log.d("MainActivity", "写入成功(B) at 0x" + address + ": " + value);
                return true;
            }

            Log.e("MainActivity", "写入失败: A=" + ra + " ("+eab+") , B=" + rb + " ("+ebb+")");
        } catch (Exception e) {
            Log.e("MainActivity", "写入内存时出错: " + e.getMessage(), e);
        }
        return false;
    }

    // 通过 root 暂停/继续目标进程，减少写入与游戏刷新竞争
    private void pauseProcess(int pid) {
        try {
            Runtime.getRuntime().exec(new String[]{"su","-c","kill -STOP " + pid}).waitFor();
            Log.d("MainActivity","已发送 SIGSTOP 至进程: "+pid);
        } catch (Exception e) {
            Log.e("MainActivity","暂停进程失败: "+e.getMessage());
        }
    }
    private void resumeProcess(int pid) {
        try {
            Runtime.getRuntime().exec(new String[]{"su","-c","kill -CONT " + pid}).waitFor();
            Log.d("MainActivity","已发送 SIGCONT 至进程: "+pid);
        } catch (Exception e) {
            Log.e("MainActivity","继续进程失败: "+e.getMessage());
        }
    }

    private volatile boolean freezeRunning = false;

    // 选择当前 ABI 对应的 memtool，解压到 filesDir 并 chmod +x
    private File ensureMemtool() throws IOException {
        String abi = Build.SUPPORTED_ABIS != null && Build.SUPPORTED_ABIS.length > 0 ? Build.SUPPORTED_ABIS[0] : "arm64-v8a";
        String assetPath = "memtool/" + abi + "/memtool";
        File out = new File(getFilesDir(), "memtool-" + abi);
        if (!out.exists() || out.length() == 0) {
            try (java.io.InputStream in = getAssets().open(assetPath);
                 java.io.FileOutputStream fos = new java.io.FileOutputStream(out)) {
                byte[] buf = new byte[8192];
                int n;
                while ((n = in.read(buf)) > 0) fos.write(buf, 0, n);
            }
            try {
                Runtime.getRuntime().exec(new String[]{"su","-c","chmod 700 " + out.getAbsolutePath()}).waitFor();
            } catch (InterruptedException ignored) { }
        }
        return out;
    }

    // 使用 memtool 以 ptrace + process_vm_writev 写入 4 字节小端整数
    private boolean memtoolWrite4(int pid, String addressHex, int value) {
        try {
            File bin = ensureMemtool();
            String cmd = bin.getAbsolutePath() + " write " + pid + " " + addressHex + " " + value;
            Process p = Runtime.getRuntime().exec(new String[]{"su","-c", cmd});
            int rc = p.waitFor();
            Log.d("MainActivity","memtool write rc="+rc);
            return rc == 0;
        } catch (Exception e) {
            Log.e("MainActivity","memtool write failed: "+e.getMessage());
            return false;
        }
    }

    // 使用 memtool 读取原始字节为十六进制字符串（小端顺序的内存字节流）
    private String memtoolReadHex(int pid, String addressHex, int length) {
        try {
            File bin = ensureMemtool();
            String cmd = bin.getAbsolutePath() + " read " + pid + " " + addressHex + " " + length;
            Process p = Runtime.getRuntime().exec(new String[]{"su","-c", cmd});
            BufferedReader r = new BufferedReader(new InputStreamReader(p.getInputStream()));
            String line = r.readLine();
            r.close();
            int rc = p.waitFor();
            if (rc == 0 && line != null) {
                String out = line.trim();
                // 仅保留 length*2 个十六进制字符
                int max = Math.min(out.length(), length * 2);
                if (max > 0) return out.substring(0, max);
            } else {
                Log.e("MainActivity","memtool read failed rc="+rc);
            }
        } catch (Exception e) {
            Log.e("MainActivity","memtool read failed: "+e.getMessage());
        }
        return null;
    }
    
    /**
     * 启动Web调试服务器（前台服务）
     */
    private void startWebServer() {
        Intent serviceIntent = new Intent(this, MemoryDebugService.class);
        
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            startForegroundService(serviceIntent);
        } else {
            startService(serviceIntent);
        }
        
        serverRunning = true;
        tvServerStatus.setText("服务器运行中:\nhttp://localhost:8080\n(可在后台运行)");
        tvServerStatus.setTextColor(0xFF27AE60);
        btnStartServer.setText("停止Web服务器");
        
        Toast.makeText(this, "Web服务器已启动（前台服务），可切换到后台", Toast.LENGTH_LONG).show();
    }
    
    /**
     * 停止Web调试服务器
     */
    private void stopWebServer() {
        Intent serviceIntent = new Intent(this, MemoryDebugService.class);
        stopService(serviceIntent);
        
        serverRunning = false;
        tvServerStatus.setText("服务器未启动");
        tvServerStatus.setTextColor(0xFF666666);
        btnStartServer.setText("启动Web服务器");
        
        Toast.makeText(this, "Web服务器已停止", Toast.LENGTH_SHORT).show();
    }
    
    @Override
    protected void onDestroy() {
        super.onDestroy();
        // Activity销毁时不停止服务器，让它在后台继续运行
        // 用户可以通过按钮手动停止
    }
}
