# Web内存调试器 - 测试工具集

## ? 快速开始

### 最简单的方式（推荐）?

```powershell
powershell -ExecutionPolicy Bypass -File test_menu.ps1
```

**交互式菜单包含所有功能！**

---

## ? 工具清单

### 1. 测试脚本（4个）

| 脚本 | 用途 | 使用场景 |
|------|------|----------|
| **test_menu.ps1** ? | 交互式测试菜单 | 日常使用、快速测试 |
| quick_api_test.ps1 | 快速API验证 | 应用已运行时 |
| test_game_memory.ps1 | 游戏内存专项测试 | 游戏运行时 |
| test_full_functionality.ps1 | 完整部署测试 | 首次部署、全面测试 |

### 2. 文档（2个）

| 文档 | 说明 |
|------|------|
| **测试报告_20251023.md** | 详细测试报告 |
| **ADB测试使用说明.md** | 完整使用指南 |

---

## ? 使用指南

### 场景1: 第一次使用

```powershell
# 1. 运行交互式菜单
powershell -ExecutionPolicy Bypass -File test_menu.ps1

# 2. 选择: 1 - 检查ADB连接
# 3. 选择: 2 - 启动应用
# 4. 选择: 3 - 快速API测试
# 5. 选择: 5 - 打开Web界面
```

### 场景2: 测试游戏内存

```powershell
# 1. 运行菜单
powershell -ExecutionPolicy Bypass -File test_menu.ps1

# 2. 选择: 4 - 启动游戏并测试内存
```

### 场景3: 单独测试

```powershell
# 快速测试API
powershell -ExecutionPolicy Bypass -File quick_api_test.ps1

# 或者测试游戏内存
powershell -ExecutionPolicy Bypass -File test_game_memory.ps1
```

---

## ? 已验证功能

### 测试结果（2025-10-23）

```
? HTTP服务器: 200 OK
? API响应时间: ~100ms
? 内存映射: 4895个区域
? libpvz.so: 3个段（26.8MB代码+0.65MB只读+0.2MB可写）
? 基址分析: 方法可行
? 性能: 优秀
```

### 详细数据

#### 游戏内存
- **PID**: 6913
- **内存区域**: 4895个
  - 可读: 3671个
  - 可写: 1901个
  - 可执行: 412个

#### libpvz.so段
1. **r-xp** (代码段): 0x6db5c52000 | 26.8MB
2. **r--p** (只读数据): 0x6db7721000 | 0.65MB
3. **rw-p** (可写数据): 0x6db77c8000 | 0.2MB

---

## ? 测试脚本详解

### test_menu.ps1 - 交互式菜单 ?

**功能**:
```
1. 检查ADB连接 - 验证设备连接和端口转发
2. 启动应用 - 启动Web内存调试器
3. 快速API测试 - 验证所有API端点
4. 启动游戏并测试内存 - 完整游戏测试
5. 打开Web界面 - 在浏览器中打开
6. 查看应用日志 - 实时日志监控
7. 重启应用 - 重新启动调试器
8. 查看测试报告 - 打开测试报告
```

### quick_api_test.ps1 - 快速测试

**测试项**:
- ? ADB连接检查
- ? 端口转发验证
- ? HTTP服务器状态
- ? API进程列表
- ? system_server查找
- ? 游戏进程检测
- ? API性能测试（5次平均）

**输出**: 彩色格式化报告

### test_game_memory.ps1 - 游戏内存测试

**测试项**:
- ? 自动获取游戏PID
- ? 获取内存映射（4895个区域）
- ? 识别libpvz.so（3个段）
- ? 读取ELF头验证
- ? 读取数据段
- ? 写入测试值
- ? 反汇编测试
- ? 基址分析示例

**输出**: 详细的内存信息和分析结果

### test_full_functionality.ps1 - 完整测试

**测试阶段**:
1. 环境检查（3项）
2. 应用安装（3项）
3. 端口转发（2项）
4. 应用启动（4项）
5. HTTP服务器（2项）
6. 进程管理（2项）
7. 游戏启动（2项）
8. 内存映射（4项）
9. 内存读写（2项）
10. 反汇编（1项）
11. 后台运行（2项）
12. 性能测试（1项）

**总计**: 28个测试项

---

## ? 常用命令速查

### ADB基础
```bash
adb connect <IP>:5555          # 连接设备
adb devices                    # 查看设备
adb forward tcp:8080 tcp:8080  # 端口转发
```

### 应用操作
```bash
# 启动
adb shell am start -n com.example.myapplication/.MainActivity

# 停止
adb shell am force-stop com.example.myapplication

# 查看日志
adb logcat | Select-String "MemoryDebug"
```

### API测试
```powershell
# 进程列表
Invoke-RestMethod "http://localhost:8080/api/process/list"

# 内存映射
Invoke-RestMethod "http://localhost:8080/api/memory/maps?pid=6913"
```

---

## ? 相关文档

### 本次测试
- ? `测试报告_20251023.md` - 详细测试报告
- ? `ADB测试使用说明.md` - 使用指南
- ? `测试工具README.md` - 本文档

### 项目文档
- `【项目完成】一页纸总结.md` - 项目总览
- `完整构建指南.md` - 构建指南
- `QUICK_START.md` - 快速开始
- `FINAL_SUCCESS_REPORT.md` - 成功报告

---

## ? 使用建议

### 日常使用
? 使用 **test_menu.ps1** 即可满足所有需求

### 自动化测试
? 使用 **test_full_functionality.ps1** 进行完整验证

### 快速验证
? 使用 **quick_api_test.ps1** 快速检查

### 游戏分析
? 使用 **test_game_memory.ps1** 详细分析

---

## ? 总结

### ? 核心成果

1. **4个测试脚本** - 覆盖所有测试场景
2. **2个详细文档** - 完整使用指南
3. **100%验证** - 核心功能全部通过
4. **真机测试** - 实际游戏验证成功

### ? 项目状态

- **HTTP服务器**: ? 正常
- **API接口**: ? 完整
- **内存映射**: ? 4895个区域
- **模块识别**: ? libpvz.so完美识别
- **基址分析**: ? 方法可行
- **性能**: ? 响应<100ms

**结论**: ? **项目核心功能全部正常，可立即投入使用！**

---

## ? 立即开始

```powershell
powershell -ExecutionPolicy Bypass -File test_menu.ps1
```

**祝使用愉快！** ?

---

*测试工具集 v1.0 | 创建日期: 2025-10-23*

