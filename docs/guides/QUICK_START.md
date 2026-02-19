# Web内存调试器 - 快速开始

## 🚀 5分钟上手指南

### 第1步：安装应用（1分钟）
```bash
# 确保设备已连接
adb devices

# 安装APK
adb install -r app\build\outputs\apk\debug\app-debug.apk

# 配置端口转发
adb forward tcp:8080 tcp:8080
```

### 第2步：启动（30秒）
```bash
# 启动应用
adb shell am start -n com.example.myapplication/.MainActivity

# Web服务器会在2秒后自动启动
# 提示: "服务器运行中: http://localhost:8080"
```

### 第3步：访问Web界面（30秒）
```
打开浏览器访问: http://localhost:8080

看到界面: 左侧导航栏 + 主内容区
```

### 第4步：选择目标进程（1分钟）
```
1. 点击"进程管理"
2. 启动目标游戏（如植物大战僵尸）
3. 搜索框输入: pvz
4. 点击"选择"按钮
```

### 第5步：操作内存（2分钟）

#### 查看内存映射
```
1. 点击"内存浏览器"
2. 点击"刷新"
3. 勾选"只显示可写"
4. 查看数据段、堆等区域
```

#### 读取内存
```
1. 点击"Hex编辑器"
2. 输入地址（如：04c72100）
3. 点击"读取"
4. 查看十六进制数据
```

#### 修改内存
```
使用API（浏览器控制台F12）:
await api.writeMemory(14993, "04c72100", 999999);
```

---

## 🎯 实战：修改游戏金币

### 准备工作
```bash
# 1. 启动游戏
adb shell am start -n com.ea.game.pvzfree_cn/com.ea.game.pvzfree_row.PvZActivity

# 2. 获取游戏PID
adb shell "ps | grep pvz"
# 输出: u0_a42  14993  ...
```

### 使用PowerShell操作
```powershell
$gamePid = 14993

# 获取libpvz.so数据段基址
$maps = Invoke-RestMethod "http://localhost:8080/api/memory/maps?pid=$gamePid"
$pvzData = $maps.data | Where-Object { $_.path -like "*libpvz.so" -and $_.perms -eq "rw-p" }
Write-Host "基址: 0x$($pvzData[0].start)"

# 假设金币在 基址+0x100
$coinAddr = $pvzData[0].start
# 实际使用时需要通过内存搜索找到真实的金币地址

# 读取金币
$read = Invoke-RestMethod "http://localhost:8080/api/memory/read" -Method Post `
  -Body (@{pid=$gamePid;address=$coinAddr;length=4}|ConvertTo-Json) `
  -ContentType "application/json"

# 修改金币为999999
$write = Invoke-RestMethod "http://localhost:8080/api/memory/write" -Method Post `
  -Body (@{pid=$gamePid;address=$coinAddr;value=999999}|ConvertTo-Json) `
  -ContentType "application/json"

Write-Host "修改结果: $($write.success)"
```

### 使用浏览器操作
```javascript
// 打开 http://localhost:8080
// 按F12打开控制台

// 读取内存
const data = await api.readMemory(14993, "04c72100", 64);
console.log(data.data.hex);

// 写入内存
const result = await api.writeMemory(14993, "04c72100", 999999);
console.log(result.success);
```

---

## 🔍 基址查找技巧

### 方法1：模块偏移法（最简单）✅

**适用**: 全局变量、静态数据

**步骤**:
1. 通过内存搜索找到动态地址（如金币地址）
2. 查看内存映射，找到地址所在模块
3. 计算偏移 = 动态地址 - 模块基址
4. 公式：`[模块基址 + 偏移]`

**示例**:
```
动态地址: 0x04C72100
所属模块: libpvz.so (0x04C72000)
偏移: 0x100
公式: [libpvz.so + 0x100]
```

### 方法2：指针扫描法（需实现）

**适用**: 堆对象、动态分配

**步骤**:
1. 搜索指向目标地址的指针
2. 重复搜索构建指针链
3. 找到静态指针作为基址
4. 公式：`[[[[基址 + A] + B] + C] + D]`

### 方法3：反汇编法（需Capstone）

**适用**: 复杂计算、加密数据

**步骤**:
1. 使用硬件断点捕获访问代码
2. 反汇编访问指令
3. 分析ADRP/LDR指令
4. 逆推基址计算逻辑

---

## 📚 常用API

### 获取进程列表
```javascript
GET /api/process/list
```

### 获取内存映射
```javascript
GET /api/memory/maps?pid=14993&type=writable
```

### 读取内存
```javascript
POST /api/memory/read
Body: {"pid":14993, "address":"04c72100", "length":64}
```

### 写入内存
```javascript
POST /api/memory/write  
Body: {"pid":14993, "address":"04c72100", "value":999999}
```

---

## ⚠️ 重要提示

1. **需要Root权限** - 所有内存操作必需
2. **自动启动** - Web服务器会自动启动（延迟2秒）
3. **端口8080** - 确保端口未被占用
4. **稳定连接** - 网络ADB需要稳定网络

---

## 🎓 进阶使用

### 批量操作（PowerShell脚本）
```powershell
# 批量修改多个地址
$addresses = @("04c72100", "04c72200", "04c72300")
foreach ($addr in $addresses) {
    Invoke-RestMethod "http://localhost:8080/api/memory/write" `
      -Method Post `
      -Body (@{pid=14993;address=$addr;value=999999}|ConvertTo-Json) `
      -ContentType "application/json"
}
```

### 自动化脚本
创建`.ps1`脚本实现自动化金币修改、血量锁定等功能。

### 插件开发
基于API开发自定义插件，实现更复杂的功能。

---

## 📖 文档索引

- **WEB_DEBUGGER_README.md** - 完整使用说明
- **TESTING_GUIDE.md** - 详细测试指南
- **TEST_SUCCESS_REPORT.md** - 测试成功报告
- **IMPLEMENTATION_SUMMARY.md** - 技术实现总结
- **PROJECT_CHECKLIST.md** - 项目检查清单

---

## 🎉 开始使用

1. 按照上述步骤启动服务器
2. 打开浏览器访问 http://localhost:8080
3. 开始调试你的游戏！

**祝调试愉快！** 🚀

---

*快速开始指南 v1.0*  
*最后更新: 2025-10-20*

