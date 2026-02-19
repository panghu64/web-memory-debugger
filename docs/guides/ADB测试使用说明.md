# Web内存调试器 - ADB测试使用说明

## ? 快速开始

### 方法1: 使用测试菜单（推荐）?

```powershell
powershell -ExecutionPolicy Bypass -File test_menu.ps1
```

提供交互式菜单，包含所有测试功能：
1. 检查ADB连接
2. 启动应用
3. 快速API测试
4. 启动游戏并测试内存
5. 打开Web界面
6. 查看应用日志
7. 重启应用
8. 查看测试报告

---

## ? 测试脚本说明

### 1. test_menu.ps1 - 测试菜单 ?
**用途**: 交互式测试菜单  
**适用**: 所有测试场景  
**使用**: 
```powershell
powershell -ExecutionPolicy Bypass -File test_menu.ps1
```

### 2. quick_api_test.ps1 - 快速API测试
**用途**: 快速验证API功能  
**适用**: 应用已运行  
**测试内容**:
- HTTP服务器状态
- API端点响应
- 进程列表
- 内存映射
- API性能

**使用**:
```powershell
powershell -ExecutionPolicy Bypass -File quick_api_test.ps1
```

### 3. test_game_memory.ps1 - 游戏内存测试
**用途**: 详细测试游戏内存功能  
**适用**: 游戏已运行  
**测试内容**:
- 游戏PID获取
- 内存映射（4895个区域）
- libpvz.so识别
- 内存读取
- 内存写入
- 反汇编
- 基址分析

**使用**:
```powershell
powershell -ExecutionPolicy Bypass -File test_game_memory.ps1
```

### 4. test_full_functionality.ps1 - 完整功能测试
**用途**: 从零开始的完整测试  
**适用**: 完整部署测试  
**测试内容**:
- 环境检查
- APK安装
- 端口转发
- 应用启动
- 所有API测试
- 性能测试

**使用**:
```powershell
powershell -ExecutionPolicy Bypass -File test_full_functionality.ps1
```

---

## ? 完整测试流程

### 步骤1: 准备环境
```powershell
# 连接设备
adb connect 10.99.99.3:5555

# 检查连接
adb devices
```

### 步骤2: 启动应用
```powershell
# 启动应用
adb shell am start -n com.example.myapplication/.MainActivity

# 等待20秒
Start-Sleep -Seconds 20
```

### 步骤3: 配置端口转发
```powershell
adb forward tcp:8080 tcp:8080
```

### 步骤4: 测试API
```powershell
powershell -ExecutionPolicy Bypass -File quick_api_test.ps1
```

### 步骤5: 启动游戏
```powershell
adb shell am start -n com.ea.game.pvzfree_cn/com.ea.game.pvzfree_row.PvZActivity

# 等待5秒
Start-Sleep -Seconds 5
```

### 步骤6: 测试游戏内存
```powershell
powershell -ExecutionPolicy Bypass -File test_game_memory.ps1
```

### 步骤7: 访问Web界面
```
浏览器打开: http://localhost:8080
```

---

## ? 测试结果

### 已验证功能 ?

| 功能 | 状态 | 数据 |
|------|------|------|
| HTTP服务器 | ? | 200 OK |
| API响应 | ? | ~100ms |
| 进程管理 | ? | 完整功能 |
| 内存映射 | ? | 4895个区域 |
| libpvz.so识别 | ? | 3个段 |
| 基址分析方法 | ? | 可行 |

### 测试数据

#### 游戏信息
```
游戏PID: 6913
内存区域: 4895个
├─ 可读: 3671个
├─ 可写: 1901个
└─ 可执行: 412个
```

#### libpvz.so段
```
1. r-xp (代码段)
   0x6db5c52000-0x6db7720000 | 26.8MB

2. r--p (只读数据)
   0x6db7721000-0x6db77c8000 | 0.65MB

3. rw-p (可写数据)
   0x6db77c8000-0x6db77fa000 | 0.2MB
```

---

## ? 常用命令

### ADB基础命令
```bash
# 连接设备
adb connect <IP>:5555

# 断开设备
adb disconnect

# 查看设备
adb devices

# 端口转发
adb forward tcp:8080 tcp:8080

# 查看端口转发
adb forward --list

# 移除端口转发
adb forward --remove-all
```

### 应用管理命令
```bash
# 启动应用
adb shell am start -n com.example.myapplication/.MainActivity

# 停止应用
adb shell am force-stop com.example.myapplication

# 查看应用进程
adb shell "ps -A | grep myapplication"

# 查看日志
adb logcat | Select-String "MemoryDebug"
```

### 游戏管理命令
```bash
# 启动游戏
adb shell am start -n com.ea.game.pvzfree_cn/com.ea.game.pvzfree_row.PvZActivity

# 查看游戏进程
adb shell "ps -A | grep pvz"

# 停止游戏
adb shell am force-stop com.ea.game.pvzfree_cn
```

### API测试命令
```powershell
# 获取进程列表
Invoke-RestMethod "http://localhost:8080/api/process/list"

# 获取内存映射
Invoke-RestMethod "http://localhost:8080/api/memory/maps?pid=6913"

# 读取内存
$body = @{pid=6913;address="6db77c8000";length=64} | ConvertTo-Json
Invoke-RestMethod "http://localhost:8080/api/memory/read" -Method Post -Body $body -ContentType "application/json"

# 写入内存
$body = @{pid=6913;address="6db77c8000";value=999999} | ConvertTo-Json
Invoke-RestMethod "http://localhost:8080/api/memory/write" -Method Post -Body $body -ContentType "application/json"

# 反汇编
$body = @{pid=6913;address="6db5c52000";count=20} | ConvertTo-Json
Invoke-RestMethod "http://localhost:8080/api/disasm" -Method Post -Body $body -ContentType "application/json"
```

---

## ? 故障排除

### 问题1: 设备离线
```bash
# 重新连接
adb disconnect
adb connect <IP>:5555
```

### 问题2: 应用无响应
```bash
# 重启应用
adb shell am force-stop com.example.myapplication
adb shell am start -n com.example.myapplication/.MainActivity
```

### 问题3: 端口转发失败
```bash
# 重新配置
adb forward --remove-all
adb forward tcp:8080 tcp:8080
```

### 问题4: API无响应
```bash
# 查看日志
adb logcat | Select-String "MemoryDebug"

# 检查应用是否运行
adb shell "ps -A | grep myapplication"
```

---

## ? 参考文档

### 项目文档
- `【项目完成】一页纸总结.md` - 项目总览
- `完整构建指南.md` - 从源码构建
- `QUICK_START.md` - 快速开始
- `FINAL_SUCCESS_REPORT.md` - 成功报告
- `测试报告_20251023.md` - 本次测试报告

### API文档
- `WEB_DEBUGGER_README.md` - API使用说明
- `TESTING_GUIDE.md` - 测试指南

### 技术文档
- `SELINUX_SOLUTION.md` - SELinux解决方案
- `BACKGROUND_SERVICE_SUCCESS.md` - 后台服务
- `CAPSTONE_配置完成.md` - Capstone配置

---

## ? 使用建议

### 日常使用
1. 使用 `test_menu.ps1` 进行快速操作
2. 需要详细测试时使用专项脚本
3. 通过Web界面进行可视化操作

### 开发调试
1. 实时查看日志: `adb logcat | Select-String "MemoryDebug"`
2. 使用API直接测试功能
3. 参考测试脚本编写自动化脚本

### 游戏修改
1. 启动游戏
2. 使用Web界面查看内存映射
3. 通过API读写内存
4. 使用基址分析方法构建稳定指针

---

## ? 下一步

### 立即可用
- ? Web界面查看内存
- ? API编程操作
- ? 基址分析

### 需要验证
- ? 内存读写功能（/proc/mem）
- ? 反汇编功能（Capstone）
- ? 后台运行稳定性

---

**文档版本**: 1.0  
**创建日期**: 2025-10-23  
**适用版本**: Web内存调试器 v1.0

