# Web内存调试器测试指南

## 测试目标
测试游戏：植物大战僵尸 (com.ea.game.pvzfree_cn)
目标：通过Web界面读取和修改游戏内存

## 前置条件检查

### 1. Capstone库准备（重要！）
反汇编功能需要 libcapstone.so，请完成以下步骤：

```bash
# 下载 Capstone Android 预编译库
# https://github.com/capstone-engine/capstone/releases

# 或使用以下命令下载（示例）
cd app/src/main/jniLibs/arm64-v8a
# 放置 libcapstone.so

cd ../armeabi-v7a  
# 放置 libcapstone.so
```

**注意**：如果没有 libcapstone.so，反汇编功能将不可用，但其他功能正常。

### 2. 编译项目
```bash
# 在项目根目录执行
gradlew.bat assembleDebug

# 或在 Android Studio 中
# Build -> Build Bundle(s)/APK(s) -> Build APK(s)
```

### 3. 安装APK
```bash
# 查找生成的APK
# app/build/outputs/apk/debug/app-debug.apk

# 安装到模拟器或设备
adb install -r app/build/outputs/apk/debug/app-debug.apk
```

## 测试步骤

### 步骤1：启动应用和Web服务器

1. 在Android设备上启动应用
2. 确保设备已Root（必需）
3. 点击"启动Web服务器"按钮
4. 看到提示："服务器运行中: http://localhost:8080"

### 步骤2：配置端口转发（如果使用远程设备）

```bash
# 建立端口转发
adb forward tcp:8080 tcp:8080

# 验证转发
adb forward --list
```

### 步骤3：访问Web界面

在电脑浏览器中打开：`http://localhost:8080`

应该看到左侧导航栏和主界面。

### 步骤4：启动目标游戏

```bash
# 启动植物大战僵尸
adb shell am start -n com.ea.game.pvzfree_cn/.MainActivity

# 或手动在设备上启动游戏
```

### 步骤5：选择游戏进程

1. 在Web界面点击"进程管理"
2. 在搜索框输入：`pvz` 或 `com.ea.game`
3. 找到游戏进程（PID可能类似：12345）
4. 点击"选择"按钮
5. 左侧应显示：当前进程: PID XXXX

### 步骤6：查看内存映射

1. 点击"内存浏览器"
2. 点击"刷新"按钮
3. 勾选"只显示可写"（金币数据通常在可写区域）
4. 查看内存区域列表，找到：
   - [heap] - 堆内存（游戏数据常在此）
   - [anon] - 匿名内存
   - libil2cpp.so - 游戏引擎库

### 步骤7：读取内存（查找金币地址）

**方法A：已知地址**
如果已知金币地址（如：`0x12C0AB48`）：
1. 点击"Hex编辑器"
2. 输入地址（不带0x）：`12C0AB48`
3. 点击"读取"
4. 查看十六进制数据

**方法B：搜索金币值**
在游戏中记下当前金币数（如：1000）：
1. 使用现有的内存搜索功能
2. 或在内存映射中逐个区域搜索

### 步骤8：反汇编代码

找到可执行内存区域后：
1. 点击"反汇编视图"
2. 输入代码地址（如游戏主模块地址）
3. 指令数量：20
4. 点击"反汇编"
5. 查看ARM64汇编指令
6. 内存访问指令（LDR/STR）会高亮显示

### 步骤9：设置硬件断点（高级功能）

**目标**：捕获访问金币地址时的寄存器状态

1. 点击"硬件断点"
2. 输入金币地址（如：`12C0AB48`）
3. 超时设置：30秒
4. 点击"设置断点"
5. **立即**在游戏中触发金币变化（购买植物）
6. 等待断点触发

**断点触发后会显示**：
- 触发指令地址（PC）
- 所有寄存器值（X0-X30）
- 可疑寄存器标记（值接近目标地址）

### 步骤10：分析基址

在断点触发后：
1. 点击"分析基址"按钮
2. 自动切换到"基址分析"视图
3. 查看候选基址列表：
   - 寄存器（如 X19）
   - 寄存器值
   - 偏移量
   - 类型（Direct/ADRP/Global Pointer）

**分析结果示例**：
```
候选基址：
X19 = 0x12C0AB30, 偏移: +0x18, 类型: Direct
→ 金币地址 = [X19 + 0x18]

如果 X19 来自：
ADRP X19, #0x12000000
LDR  X19, [X19, #0x3450]

→ 完整指针链：
基址 = [模块基址 + 0x3450] + 0x18
```

## 常见测试场景

### 场景1：修改金币数量
```javascript
// 使用API直接修改（浏览器控制台）
await api.writeMemory(selectedPid, "12C0AB48", 9999);

// 或在应用内使用现有的写入功能
```

### 场景2：查找代码访问点
1. 设置硬件断点在金币地址
2. 触发游戏操作
3. 查看触发的PC地址
4. 反汇编该地址周围代码
5. 分析游戏逻辑

### 场景3：动态调试
1. 查看内存映射找到libil2cpp.so
2. 反汇编引擎代码
3. 查找特定函数模式
4. 设置断点跟踪执行

## API测试（高级）

可以在浏览器控制台直接调用API：

```javascript
// 获取进程列表
const processes = await api.getProcessList();
console.log(processes);

// 获取内存映射
const maps = await api.getMemoryMaps(12345);
console.log(maps);

// 读取内存
const data = await api.readMemory(12345, "12C0AB48", 64);
console.log(data);

// 反汇编
const disasm = await api.disassemble(12345, "7123456780", 10);
console.log(disasm);
```

## 故障排除

### 问题1：无法连接Web界面
**检查**：
- 服务器是否启动成功？
- 端口转发是否配置？
- 防火墙是否阻止？

**解决**：
```bash
# 检查端口转发
adb forward --list

# 重新配置
adb forward --remove-all
adb forward tcp:8080 tcp:8080

# 检查应用日志
adb logcat | grep MemoryDebugServer
```

### 问题2：找不到进程
**检查**：
- 游戏是否正在运行？
- Root权限是否已授予？

**解决**：
```bash
# 验证Root权限
adb shell su -c id

# 查看运行的进程
adb shell su -c "ps | grep pvz"
```

### 问题3：无法读取内存
**可能原因**：
- 地址无效
- 权限不足
- SELinux限制

**解决**：
```bash
# 检查SELinux状态
adb shell getenforce

# 临时禁用（测试用）
adb shell su -c setenforce 0
```

### 问题4：反汇编失败
**原因**：缺少 libcapstone.so

**解决**：
- 下载 Capstone 库
- 放置到 jniLibs 目录
- 重新编译项目

### 问题5：硬件断点不触发
**原因**：
- 内核不支持硬件断点
- 地址未被访问
- 超时时间太短

**建议**：
- 增加超时时间（60秒）
- 确保在设置断点后立即触发操作
- 使用反汇编定位代码访问点

## 性能建议

1. **内存映射**：数据量大，仅在需要时刷新
2. **反汇编**：一次不要超过50条指令
3. **硬件断点**：每次只设置一个
4. **浏览器**：推荐使用Chrome/Edge（开发者工具好用）

## 测试完成标准

✅ 成功启动Web服务器
✅ 能够在浏览器访问界面
✅ 成功列出所有进程
✅ 选择游戏进程
✅ 查看内存映射
✅ 读取内存数据（Hex显示）
✅ 反汇编代码（如果有Capstone）
✅ 设置硬件断点（可选）
✅ 分析基址（可选）

## 下一步

完成基础测试后，可以：
1. 实现自动化金币修改脚本
2. 创建指针链扫描工具
3. 导出反汇编结果到IDA
4. 实现内存快照和对比
5. 添加Lua脚本支持

## 参考资料

- NanoHTTPD文档：https://github.com/NanoHttpd/nanohttpd
- Capstone文档：https://www.capstone-engine.org/
- ARM64指令集：https://developer.arm.com/documentation/
- Vue 3文档：https://vuejs.org/

---

**祝测试顺利！遇到问题请查看 logcat 日志。**

