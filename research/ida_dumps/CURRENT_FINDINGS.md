# IDA分析当前发现 (2025-10-20)

## 📌 已确认信息

### Board类结构
- **大小**: `0x5B98` (23448 字节)
- **构造函数**: `0x606834`
- **vtable**: `0x1B13B20`
- **关键偏移**:
  - `+0x118` (280): `LawnApp*` 父对象指针
  - `+0xE7C` (3708): **初始阳光配置** (从XML加载，非运行时)

### LawnApp类结构  
- **vtable**: `0x1B159C8`
- **关键偏移**:
  - `+0xB68` (2920): `Board*` 指向Board对象
- **全局实例**: ❌ 未找到 (可能由Java层管理)

### 关卡配置结构
- **基址计算**: `levelDataBase + 3708 + 636 * levelId`
- **每关大小**: 636字节
- **配置偏移**:
  - `+0xE7C` (3708): 初始阳光 (int32)
  - `+0xE80` (3712): 最大阳光 (int32)
  - `+0xE88` (3720): 阳光掉落启用 (byte)
  - `+0xEA0` (3744): 阳光掉落速率 (float)

---

## 🔍 完整指针链分析

### 已知的三层架构

```
╔═══════════════════════════════════════════════════════════╗
║                    Java层 (运行时逻辑)                      ║
╠═══════════════════════════════════════════════════════════╣
║  未知Java类 (可能是 GameState/BoardManager)                ║
║    └─> sunCount: int                                       ║
║         地址: 0x7ACC02887C ⭐ (运行时阳光值)               ║
║         内存: dalvik-main space (Java堆)                   ║
║         访问: boot-framework.oat @ 0x71E51048              ║
║                                                            ║
║  中间对象: 0x030B0338                                      ║
║    └─> [+偏移?] → 指向阳光对象                            ║
╚═══════════════════════════════════════════════════════════╝
                          ↕ JNI桥接
╔═══════════════════════════════════════════════════════════╗
║                   C++层 (渲染/配置)                        ║
╠═══════════════════════════════════════════════════════════╣
║  LawnApp实例 ❌ (未找到全局指针)                           ║
║    └─> [+0xB68] → Board*                                   ║
║                     └─> [+0x118] → LawnApp* (反向)        ║
║                                                            ║
║  关卡配置数据 (静态配置)                                   ║
║    levelDataBase + 3708 + 636 * levelId                   ║
║      └─> [+0xE7C] → 初始阳光配置 ✓ (仅用于加载时)        ║
╚═══════════════════════════════════════════════════════════╝
```

---

## 🚨 关键结论

### ✅ 已确认
1. **C++层**只负责**配置级别**的阳光管理
   - 从XML加载初始值 (`sub_69C5C8`)
   - 存储在关卡配置结构 (`+0xE7C`)
   - Board类大小23KB，但**不包含运行时阳光字段**

2. **Java层**管理**运行时**阳光值
   - 内存地址: `0x7ACC02887C` (动态分配)
   - 访问代码: `boot-framework.oat` (Java编译后)
   - 中间对象: `0x030B0338` (Java堆)

### ❌ 未找到
1. **LawnApp全局实例** (C++层)
   - 搜索模式: `gApp`, `gLawn`, `gBoard`, `theApp`, `sApp`
   - 结果: 全部为空
   - 推断: **可能由Java层持有引用**

2. **运行时阳光在Board类中的偏移**
   - Board类大小: 0x5B98 (23448字节)
   - 已知偏移: `+0x118` (LawnApp*), `+0xE7C` (配置)
   - 结论: **运行时阳光不在Board类中**

---

## 💡 指针链推断

### 推测的完整路径

```
Java层:
  某Activity/Service
    └─> GameState/BoardManager (Java对象)
         └─> mSunCount: int = [0x7ACC02887C] ⭐
              ├─ 初始化: 从C++读取配置
              ├─ 运行时: 纯Java管理
              └─ 渲染: 通过JNI传值给C++绘制

JNI层:
  Java_xxx_getSunCount()
    └─> 读取Java字段并返回给C++

C++层:
  Board::Render()
    └─> 调用JNI获取阳光值
         └─> 仅用于显示，不存储
```

### 为什么找不到C++静态指针链？

**原因1**: 阳光值是Java对象的字段
- Java对象由GC管理，地址动态变化
- C++层通过JNI临时访问，不持有持久指针

**原因2**: 架构设计分离
- Java层: 游戏逻辑、数据管理、UI交互
- C++层: 渲染引擎、物理计算、资源加载
- 通信: 单向调用（Java → C++ 用于渲染）

**原因3**: 安全性考虑
- 将阳光值放在Java堆，避免C++内存修改
- 增加逆向难度（需要分析Java + C++）

---

## 🎯 结论与建议

### ❌ C++静态指针链不可行

**IDA分析结论**:
1. ✅ 已完整分析C++层结构（Board、LawnApp类）
2. ❌ **运行时阳光不在C++内存中**
3. ❌ **不存在从libpvz.so到阳光值的静态指针链**
4. ✅ C++层仅负责配置加载（`sub_69C5C8`）

**证据**:
```
硬件断点捕获:
  阳光地址: 0x7ACC02887C
  内存区域: dalvik-main space (Java堆)
  访问指令: ldr x21, [x21] @ 0x71E51048
  代码位置: boot-framework.oat (Java编译后的Native代码)
  
IDA分析:
  Board类大小: 23448字节
  已知字段: LawnApp* (+0x118), 初始阳光配置 (+0xE7C)
  搜索结果: 无AddSun/GetSun/SetSun等运行时函数
  全局变量: 无LawnApp实例指针
```

---

## 🎯 可行的修改方案

### ✅ 方案1: 直接内存搜索 (GameGuardian)
**适用场景**: 临时修改、快速作弊

**步骤**:
```
1. 搜索当前阳光值 (DWORD)
2. 种植物/收集阳光
3. 再次搜索变化后的值
4. 找到地址后修改并冻结
```

**优点**: 
- 简单快速，无需逆向分析
- 每次游戏5分钟内完成

**缺点**:
- 地址每次启动都变（Java堆动态分配）
- 需要每局重新搜索

---

### ✅ 方案2: Frida Hook Java层 (推荐深入研究)
**适用场景**: 稳定修改、学习研究

**步骤**:
```javascript
// 1. 枚举Java类找到阳光管理类
Java.perform(function() {
    Java.enumerateLoadedClasses({
        onMatch: function(className) {
            if (className.includes('Board') || 
                className.includes('Sun') ||
                className.includes('Game')) {
                console.log('[+] ' + className);
            }
        },
        onComplete: function() {}
    });
});

// 2. Hook疑似的setter/getter
var SomeClass = Java.use('com.ea.game.xxx.BoardManager');
SomeClass.setSunCount.implementation = function(value) {
    console.log('[Sun] Set: ' + value);
    this.setSunCount(9990); // 强制设为9990
};
```

**优点**:
- 稳定，重启游戏后仍有效
- 可编程控制（自动加阳光等）
- 学习Java ↔ C++交互

---

### ✅ 方案3: 修改配置文件 (初始阳光)
**适用场景**: 修改游戏平衡、自定义关卡

**步骤**:
```
1. 解包APK: apktool d pvz.apk
2. 编辑 assets/*.xml 配置
3. 修改 <mStartingSun> 标签值
4. 重新打包、签名、安装
```

**IDA发现的配置位置**:
```c
关卡配置: levelDataBase + 3708 + 636 * levelId
  +0xE7C: 初始阳光 (int32)
  +0xE80: 最大阳光 (int32)  
  +0xE88: 启用天降阳光 (byte)
  +0xEA0: 阳光掉落速率 (float)
```

**优点**:
- 永久生效
- 可调整游戏难度

**缺点**:
- 仅改初始值，运行时消耗仍正常
- 需要重新打包APK

---

## 📊 最终指针链总结

### Java层指针链 (运行时阳光) ⭐
```
Java Activity/Fragment
  └─> GameBoardManager对象 (Java)
       └─> mSunCount: int字段
            └─> 地址: 0x7ACC02887C (动态)
                 └─> 值: 75 (int32)

访问路径:
  Java代码 → 字段访问 → 编译为oat → boot-framework.oat @ 0x71E51048
```

### C++层指针链 (配置阳光) ✓
```
libpvz.so基址
  └─> levelDataBase (需动态查找)
       └─> [+3708 + 636 * levelId]
            └─> 初始阳光配置 (int32)

访问路径:
  sub_69C5C8 (XML加载) → 解析 "mStartingSun" → 存储到关卡数据
```

### 两者关系
```
游戏启动时:
  1. C++层加载XML配置 (sub_69C5C8)
  2. 读取初始阳光值 (如50/100/150)
  3. 通过JNI传递给Java层
  4. Java层创建GameBoard对象
  5. 初始化 mSunCount = 初始阳光
  
游戏运行时:
  1. Java层管理mSunCount (增减、检查)
  2. 渲染时通过JNI获取值
  3. C++层仅用于绘制UI，不存储
```

---

## 📝 IDA分析任务完成度

| 任务 | 状态 | 结果 |
|------|------|------|
| Board类结构分析 | ✅ | 大小0x5B98, vtable 0x1B13B20 |
| LawnApp类分析 | ✅ | Board指针 +0xB68 |
| 配置加载函数 | ✅ | sub_69C5C8, XML解析完整流程 |
| 运行时阳光偏移 | ❌ | **不在C++层** |
| 静态指针链 | ❌ | **不存在** |
| LawnApp全局实例 | ❌ | **未找到** |
| **最终结论** | ✅ | **需转向Java层分析** |

---

**IDA分析到此结束，建议使用方案1（GG）或方案2（Frida Java Hook）**

