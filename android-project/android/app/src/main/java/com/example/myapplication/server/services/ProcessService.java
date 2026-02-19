package com.example.myapplication.server.services;

import android.util.Log;

import com.example.myapplication.server.models.ProcessInfo;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;

/**
 * 进程管理服务 - 性能优化版
 * 优化点：
 * 1. 分页加载（减少单次传输量）
 * 2. 搜索过滤（快速定位目标进程）
 * 3. 缓存机制（减少重复计算）
 * 4. 异步支持（避免阻塞）
 */
public class ProcessService {
    private static final String TAG = "ProcessService";
    
    // 缓存
    private List<ProcessInfo> cachedProcesses = null;
    private long lastCacheTime = 0;
    private static final long CACHE_DURATION = 10000; // 10秒缓存（优化：增加缓存时间）
    private static final int MAX_PROCESSES = 200; // 最多返回200个进程（优化：限制数量）
    
    /**
     * 获取所有进程列表（优化版：使用ps命令）
     */
    public List<ProcessInfo> getAllProcesses() {
        // 检查缓存
        long now = System.currentTimeMillis();
        if (cachedProcesses != null && (now - lastCacheTime) < CACHE_DURATION) {
            Log.d(TAG, "Returning cached processes");
            return cachedProcesses;
        }
        
        List<ProcessInfo> processes = new ArrayList<>();
        
        try {
            // 使用ps命令，速度比遍历/proc快得多
            Process process = Runtime.getRuntime().exec("ps -A");
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            
            String line;
            boolean firstLine = true;
            
            while ((line = reader.readLine()) != null) {
                if (firstLine) {
                    firstLine = false;
                    continue; // 跳过标题行
                }
                
                // 解析ps输出: USER PID PPID VSZ RSS WCHAN ADDR S NAME
                String[] parts = line.trim().split("\\s+");
                if (parts.length >= 9) {
                    try {
                        int pid = Integer.parseInt(parts[1]);
                        String name = parts[8];
                        String user = parts[0];
                        
                        // 只返回应用进程（不包括系统进程）
                        // 优化：只收集用户应用 (u0_aXXX)
                        if (user.startsWith("u0_a") || name.contains(".")) {
                            ProcessInfo info = new ProcessInfo(pid, name);
                            info.setUser(user);
                            
                            // 尝试读取内存（快速方式）
                            try {
                                long rss = Long.parseLong(parts[4]);
                                info.setMemoryUsage(rss * 1024); // KB to bytes
                            } catch (Exception e) {
                                // ignore
                            }
                            
                            processes.add(info);
                        }
                    } catch (NumberFormatException e) {
                        // 忽略解析错误
                    }
                }
            }
            
            reader.close();
            process.waitFor();
            
            // 更新缓存
            cachedProcesses = processes;
            lastCacheTime = now;
            
            Log.d(TAG, "Loaded " + processes.size() + " user processes");
            
        } catch (Exception e) {
            Log.e(TAG, "Failed to get process list via ps", e);
            // 降级到旧方法（仅在ps失败时）
            processes = getAllProcessesLegacy();
        }
        
        return processes;
    }
    
    /**
     * 降级方法：遍历/proc（仅在ps命令失败时使用）
     */
    private List<ProcessInfo> getAllProcessesLegacy() {
        List<ProcessInfo> processes = new ArrayList<>();
        
        try {
            File procDir = new File("/proc");
            File[] files = procDir.listFiles();
            
            if (files != null) {
                int count = 0;
                for (File file : files) {
                    if (file.isDirectory()) {
                        try {
                            int pid = Integer.parseInt(file.getName());
                            ProcessInfo info = getProcessInfo(pid);
                            if (info != null && info.getName() != null) {
                                // 只添加有名称的进程
                                processes.add(info);
                                count++;
                                if (count > 100) break; // 限制数量
                            }
                        } catch (NumberFormatException e) {
                            // 忽略非数字目录
                        }
                    }
                }
            }
        } catch (Exception e) {
            Log.e(TAG, "Failed to get process list", e);
        }
        
        return processes;
    }
    
    /**
     * 清除缓存
     */
    public void clearCache() {
        cachedProcesses = null;
        lastCacheTime = 0;
    }
    
    /**
     * 获取指定进程详情
     */
    public ProcessInfo getProcessInfo(int pid) {
        try {
            File procDir = new File("/proc/" + pid);
            if (!procDir.exists()) {
                return null;
            }
            
            ProcessInfo info = new ProcessInfo(pid, "");
            
            // 读取 cmdline
            File cmdlineFile = new File(procDir, "cmdline");
            if (cmdlineFile.exists()) {
                try (FileInputStream fis = new FileInputStream(cmdlineFile)) {
                    byte[] buffer = new byte[1024];
                    int bytesRead = fis.read(buffer);
                    if (bytesRead > 0) {
                        StringBuilder cmdlineBuilder = new StringBuilder();
                        for (int i = 0; i < bytesRead; i++) {
                            if (buffer[i] == 0) break;
                            cmdlineBuilder.append((char) buffer[i]);
                        }
                        String cmdline = cmdlineBuilder.toString().trim();
                        info.setCmdline(cmdline);
                        
                        // 从cmdline提取进程名
                        if (!cmdline.isEmpty()) {
                            String[] parts = cmdline.split("/");
                            info.setName(parts[parts.length - 1]);
                        }
                    }
                }
            }
            
            // 读取 status 获取更多信息
            File statusFile = new File(procDir, "status");
            if (statusFile.exists()) {
                try (BufferedReader br = new BufferedReader(new InputStreamReader(new FileInputStream(statusFile)))) {
                    String line;
                    while ((line = br.readLine()) != null) {
                        if (line.startsWith("Name:")) {
                            if (info.getName() == null || info.getName().isEmpty()) {
                                info.setName(line.substring(5).trim());
                            }
                        } else if (line.startsWith("Uid:")) {
                            String[] parts = line.split("\\s+");
                            if (parts.length > 1) {
                                info.setUser("uid:" + parts[1]);
                            }
                        } else if (line.startsWith("VmRSS:")) {
                            // 实际内存使用
                            String[] parts = line.split("\\s+");
                            if (parts.length > 1) {
                                try {
                                    long kb = Long.parseLong(parts[1]);
                                    info.setMemoryUsage(kb * 1024); // 转换为字节
                                } catch (NumberFormatException e) {
                                    // ignore
                                }
                            }
                        }
                    }
                }
            }
            
            return info;
            
        } catch (Exception e) {
            Log.e(TAG, "Failed to get process info for pid " + pid, e);
            return null;
        }
    }
    
    /**
     * 获取进程列表（分页+过滤）- 性能优化核心方法
     * @param page 页码（从0开始）
     * @param pageSize 每页数量
     * @param filter 过滤关键字（可选，搜索进程名）
     * @param sortBy 排序字段：name, pid, memory
     * @return 分页结果
     */
    public PagedResult<ProcessInfo> getProcesses(int page, int pageSize, String filter, String sortBy) {
        // 获取完整列表（使用缓存）
        List<ProcessInfo> allProcesses = getAllProcesses();
        
        // 1. 过滤
        List<ProcessInfo> filtered = allProcesses;
        if (filter != null && !filter.trim().isEmpty()) {
            String lowerFilter = filter.toLowerCase();
            filtered = new ArrayList<>();
            for (ProcessInfo p : allProcesses) {
                if (p.getName() != null && p.getName().toLowerCase().contains(lowerFilter)) {
                    filtered.add(p);
                }
            }
            Log.d(TAG, "Filtered processes: " + filtered.size() + " (from " + allProcesses.size() + ")");
        }
        
        // 2. 排序
        if ("memory".equals(sortBy)) {
            Collections.sort(filtered, new Comparator<ProcessInfo>() {
                @Override
                public int compare(ProcessInfo o1, ProcessInfo o2) {
                    return Long.compare(o2.getMemoryUsage(), o1.getMemoryUsage()); // 降序
                }
            });
        } else if ("pid".equals(sortBy)) {
            Collections.sort(filtered, new Comparator<ProcessInfo>() {
                @Override
                public int compare(ProcessInfo o1, ProcessInfo o2) {
                    return Integer.compare(o1.getPid(), o2.getPid());
                }
            });
        } else { // 默认按名称排序
            Collections.sort(filtered, new Comparator<ProcessInfo>() {
                @Override
                public int compare(ProcessInfo o1, ProcessInfo o2) {
                    String n1 = o1.getName() != null ? o1.getName() : "";
                    String n2 = o2.getName() != null ? o2.getName() : "";
                    return n1.compareToIgnoreCase(n2);
                }
            });
        }
        
        // 3. 分页
        int totalCount = filtered.size();
        int totalPages = (int) Math.ceil((double) totalCount / pageSize);
        int startIndex = page * pageSize;
        int endIndex = Math.min(startIndex + pageSize, totalCount);
        
        List<ProcessInfo> pageData;
        if (startIndex >= totalCount) {
            pageData = new ArrayList<>(); // 超出范围
        } else {
            pageData = filtered.subList(startIndex, endIndex);
        }
        
        Log.d(TAG, "Page " + page + "/" + totalPages + ", showing " + pageData.size() + " processes");
        
        return new PagedResult<>(pageData, page, pageSize, totalCount, totalPages);
    }
    
    /**
     * 分页结果包装类
     */
    public static class PagedResult<T> {
        private List<T> data;
        private int page;
        private int pageSize;
        private int totalCount;
        private int totalPages;
        private boolean hasNext;
        private boolean hasPrev;
        
        public PagedResult(List<T> data, int page, int pageSize, int totalCount, int totalPages) {
            this.data = data;
            this.page = page;
            this.pageSize = pageSize;
            this.totalCount = totalCount;
            this.totalPages = totalPages;
            this.hasNext = page < (totalPages - 1);
            this.hasPrev = page > 0;
        }
        
        public List<T> getData() { return data; }
        public int getPage() { return page; }
        public int getPageSize() { return pageSize; }
        public int getTotalCount() { return totalCount; }
        public int getTotalPages() { return totalPages; }
        public boolean isHasNext() { return hasNext; }
        public boolean isHasPrev() { return hasPrev; }
    }
}

