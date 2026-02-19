package com.example.myapplication.server;

import android.content.Context;
import android.util.Log;

import com.example.myapplication.server.models.ApiResponse;
import com.example.myapplication.server.models.BaseAnalysisResult;
import com.example.myapplication.server.models.DisasmLine;
import com.example.myapplication.server.models.MemoryRegion;
import com.example.myapplication.server.models.ProcessInfo;
import com.example.myapplication.server.models.WatchpointResult;
import com.example.myapplication.server.services.AnalysisService;
import com.example.myapplication.server.services.DebugService;
import com.example.myapplication.server.services.DisasmService;
import com.example.myapplication.server.services.MemoryService;
import com.example.myapplication.server.services.ProcessService;
import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import fi.iki.elonen.NanoHTTPD;

/**
 * Web内存调试服务器
 */
public class MemoryDebugServer extends NanoHTTPD {
    private static final String TAG = "MemoryDebugServer";
    
    private Context context;
    private Gson gson;
    private ProcessService processService;
    private MemoryService memoryService;
    private DisasmService disasmService;
    private DebugService debugService;
    private AnalysisService analysisService;
    
    public MemoryDebugServer(int port, Context context) throws IOException {
        super(port);
        this.context = context;
        this.gson = new Gson();
        
        // 初始化服务
        this.processService = new ProcessService();
        this.memoryService = new MemoryService(context);
        this.disasmService = new DisasmService(context);
        this.debugService = new DebugService(context);
        this.analysisService = new AnalysisService(context);
        
        Log.i(TAG, "Memory Debug Server initialized on port " + port);
    }
    
    @Override
    public Response serve(IHTTPSession session) {
        String uri = session.getUri();
        Method method = session.getMethod();
        
        Log.d(TAG, method + " " + uri);
        
        // CORS headers
        Response response;
        
        try {
            // API路由
            if (uri.startsWith("/api/")) {
                response = handleApiRequest(session);
            } else {
                // 静态文件服务
                response = serveStaticFile(uri);
            }
            
            // 添加CORS headers
            response.addHeader("Access-Control-Allow-Origin", "*");
            response.addHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
            response.addHeader("Access-Control-Allow-Headers", "Content-Type");
            
            return response;
            
        } catch (Exception e) {
            Log.e(TAG, "Error handling request", e);
            return newFixedLengthResponse(Response.Status.INTERNAL_ERROR, 
                                         MIME_PLAINTEXT, 
                                         "Internal Server Error: " + e.getMessage());
        }
    }
    
    private Response handleApiRequest(IHTTPSession session) {
        String uri = session.getUri();
        Method method = session.getMethod();
        
        try {
            // GET /api/processes?page=0&pageSize=20&filter=xxx&sortBy=name
            // 新的分页API（推荐使用）
            if (uri.equals("/api/processes") && method == Method.GET) {
                Map<String, String> params = session.getParms();
                
                // 分页参数
                int page = 0;
                int pageSize = 20;
                String filter = null;
                String sortBy = "name";
                
                try {
                    if (params.get("page") != null) {
                        page = Integer.parseInt(params.get("page"));
                    }
                    if (params.get("pageSize") != null) {
                        pageSize = Integer.parseInt(params.get("pageSize"));
                        if (pageSize > 100) pageSize = 100; // 限制最大值
                    }
                    filter = params.get("filter");
                    if (params.get("sortBy") != null) {
                        sortBy = params.get("sortBy");
                    }
                } catch (NumberFormatException e) {
                    return newJsonResponse(ApiResponse.error("Invalid page or pageSize parameter"));
                }
                
                ProcessService.PagedResult<ProcessInfo> result = 
                    processService.getProcesses(page, pageSize, filter, sortBy);
                return newJsonResponse(ApiResponse.success(result));
            }
            
            // GET /api/process/list（旧API，保留兼容性）
            else if (uri.equals("/api/process/list") && method == Method.GET) {
                List<ProcessInfo> processes = processService.getAllProcesses();
                return newJsonResponse(ApiResponse.success(processes));
            }
            
            // GET /api/process/info?pid=X
            else if (uri.startsWith("/api/process/info") && method == Method.GET) {
                Map<String, String> params = session.getParms();
                String pidStr = params.get("pid");
                if (pidStr != null) {
                    int pid = Integer.parseInt(pidStr);
                    ProcessInfo info = processService.getProcessInfo(pid);
                    if (info != null) {
                        return newJsonResponse(ApiResponse.success(info));
                    } else {
                        return newJsonResponse(ApiResponse.error("Process not found"));
                    }
                }
                return newJsonResponse(ApiResponse.error("Missing pid parameter"));
            }
            
            // GET /api/memory/maps?pid=X
            else if (uri.startsWith("/api/memory/maps") && method == Method.GET) {
                Map<String, String> params = session.getParms();
                String pidStr = params.get("pid");
                if (pidStr != null) {
                    int pid = Integer.parseInt(pidStr);
                    List<MemoryRegion> regions = memoryService.getMemoryMaps(pid);
                    
                    // 可选筛选
                    String type = params.get("type");
                    if (type != null) {
                        regions.removeIf(r -> {
                            if (type.equals("executable")) return !r.isExecutable();
                            if (type.equals("writable")) return !r.isWritable();
                            return false;
                        });
                    }
                    
                    return newJsonResponse(ApiResponse.success(regions));
                }
                return newJsonResponse(ApiResponse.error("Missing pid parameter"));
            }
            
            // POST /api/memory/read
            else if (uri.equals("/api/memory/read") && method == Method.POST) {
                Map<String, String> files = new HashMap<>();
                session.parseBody(files);
                String body = files.get("postData");
                
                JsonObject json = JsonParser.parseString(body).getAsJsonObject();
                int pid = json.get("pid").getAsInt();
                String address = json.get("address").getAsString();
                int length = json.get("length").getAsInt();
                
                String hexData = memoryService.readMemory(pid, address, length);
                if (hexData != null) {
                    Map<String, String> result = new HashMap<>();
                    result.put("hex", hexData);
                    return newJsonResponse(ApiResponse.success(result));
                } else {
                    return newJsonResponse(ApiResponse.error("Failed to read memory"));
                }
            }
            
            // POST /api/memory/write
            else if (uri.equals("/api/memory/write") && method == Method.POST) {
                Map<String, String> files = new HashMap<>();
                session.parseBody(files);
                String body = files.get("postData");
                
                JsonObject json = JsonParser.parseString(body).getAsJsonObject();
                int pid = json.get("pid").getAsInt();
                String address = json.get("address").getAsString();
                int value = json.get("value").getAsInt();
                
                boolean success = memoryService.writeMemory(pid, address, value);
                if (success) {
                    return newJsonResponse(ApiResponse.success("Memory written successfully"));
                } else {
                    return newJsonResponse(ApiResponse.error("Failed to write memory"));
                }
            }
            
            // POST /api/disasm
            else if (uri.equals("/api/disasm") && method == Method.POST) {
                Map<String, String> files = new HashMap<>();
                session.parseBody(files);
                String body = files.get("postData");
                
                JsonObject json = JsonParser.parseString(body).getAsJsonObject();
                int pid = json.get("pid").getAsInt();
                String address = json.get("address").getAsString();
                int count = json.get("count").getAsInt();
                
                List<DisasmLine> lines = disasmService.disassemble(pid, address, count);
                return newJsonResponse(ApiResponse.success(lines));
            }
            
            // POST /api/debug/watchpoint
            else if (uri.equals("/api/debug/watchpoint") && method == Method.POST) {
                Map<String, String> files = new HashMap<>();
                session.parseBody(files);
                String body = files.get("postData");
                
                JsonObject json = JsonParser.parseString(body).getAsJsonObject();
                int pid = json.get("pid").getAsInt();
                String address = json.get("address").getAsString();
                int timeout = json.has("timeout") ? json.get("timeout").getAsInt() : 30;
                
                // 异步执行（避免阻塞HTTP请求）
                WatchpointResult result = debugService.setWatchpoint(pid, address, timeout);
                return newJsonResponse(ApiResponse.success(result));
            }
            
            // POST /api/analysis/base
            else if (uri.equals("/api/analysis/base") && method == Method.POST) {
                Map<String, String> files = new HashMap<>();
                session.parseBody(files);
                String body = files.get("postData");
                
                JsonObject json = JsonParser.parseString(body).getAsJsonObject();
                int pid = json.get("pid").getAsInt();
                String targetAddress = json.get("targetAddress").getAsString();
                WatchpointResult wpResult = gson.fromJson(json.get("watchpointResult"), WatchpointResult.class);
                
                BaseAnalysisResult analysis = analysisService.analyzeBase(pid, wpResult, targetAddress);
                return newJsonResponse(ApiResponse.success(analysis));
            }
            
            else {
                return newJsonResponse(ApiResponse.error("API endpoint not found"));
            }
            
        } catch (Exception e) {
            Log.e(TAG, "API error", e);
            return newJsonResponse(ApiResponse.error("API error: " + e.getMessage()));
        }
    }
    
    private Response serveStaticFile(String uri) {
        try {
            // 默认首页
            if (uri.equals("/")) {
                uri = "/index.html";
            }
            
            // 从assets/web/读取文件
            String assetPath = "web" + uri;
            InputStream is = context.getAssets().open(assetPath);
            
            // 确定MIME类型
            String mimeType = getMimeType(uri);
            
            return newChunkedResponse(Response.Status.OK, mimeType, is);
            
        } catch (IOException e) {
            Log.w(TAG, "Static file not found: " + uri);
            return newFixedLengthResponse(Response.Status.NOT_FOUND, 
                                         MIME_PLAINTEXT, 
                                         "File not found");
        }
    }
    
    private String getMimeType(String uri) {
        if (uri.endsWith(".html")) return "text/html";
        if (uri.endsWith(".css")) return "text/css";
        if (uri.endsWith(".js")) return "application/javascript";
        if (uri.endsWith(".json")) return "application/json";
        if (uri.endsWith(".png")) return "image/png";
        if (uri.endsWith(".jpg") || uri.endsWith(".jpeg")) return "image/jpeg";
        return "text/plain";
    }
    
    private Response newJsonResponse(Object obj) {
        String json = gson.toJson(obj);
        return newFixedLengthResponse(Response.Status.OK, "application/json", json);
    }
}

