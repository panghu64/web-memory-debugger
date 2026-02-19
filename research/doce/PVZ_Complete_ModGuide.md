# 植物大战僵尸 完整修改指南

> **分析目标**: 植物大战僵尸 (libpvz.so - arm64-v8a)  
> **分析时间**: 2025-10-20  
> **工具**: IDA Pro 8.x + ida-pro-mcp  
> **文件MD5**: 35fa10ac114b00a33afe6905833dad4d

---

## 📋 目录

1. [金币系统完整分析](#1-金币系统)
2. [阳光系统分析](#2-阳光系统)
3. [植物解锁机制](#3-植物解锁)
4. [商店购买系统](#4-商店系统)
5. [存档结构分析](#5-存档系统)
6. [反作弊机制](#6-反作弊)
7. [实用修改方法](#7-修改方法)
8. [工具与脚本](#8-工具)

---

## 1. 金币系统

### 1.1 核心函数

#### ⭐ **`sub_701D78` (0x701D78)** - 金币修改核心
**函数签名**:
```c
__int64 __fastcall sub_701D78(
    __int64 coinManager,     // 金币管理器对象
    int amount,              // 金币变化量 (正数=增加, 负数=减少)
    char flag,               // 0=临时金币, 1=总金币
    __int64 sourceScene,     // 来源场景字符串
    __int64 eventName,       // 事件名称
    __int64 extraInfo        // 额外信息
);
```

### 1.2 内存结构
```
金币管理器对象:
偏移     类型      说明
+0x0000  int64    总金币 (永久, 无上限)
+0x0008  int32    临时金币/银币 (本局游戏, 上限999,999)
+0x0010  ptr      游戏数据指针
+0x0034  int32    用户ID
+0x3BB8  int32    禅境花园累计收集金币
```

### 1.3 金币操作逻辑

#### 增加金币
```c
if (amount > 0) {
    if (flag & 1) {
        // 增加永久金币
        *(int64*)(coinManager + 0x00) += amount;
    } else {
        // 增加临时金币
        *(int32*)(coinManager + 0x08) += amount;
    }
    
    // 禅境花园特殊处理
    gameMode = *(int32*)(*(ptr*)(coinManager + 0x10) + 0xC34);
    if (gameMode == 43 && amount > 0) {
        *(int32*)(coinManager + 0x3BB8) += amount;
    }
}
```

#### 减少金币
```c
if (amount < 0) {
    int deduction = abs(amount);
    int tempCoins = *(int32*)(coinManager + 0x08);
    int deficit = deduction - tempCoins;
    
    // 先扣临时金币
    *(int32*)(coinManager + 0x08) = max(tempCoins - deduction, 0);
    
    // 临时金币不够，扣总金币
    if (deficit > 0) {
        *(int64*)(coinManager + 0x00) -= deficit;
        if (*(int64*)(coinManager + 0x00) < 0) {
            *(int64*)(coinManager + 0x00) = 0;
        }
    }
}
```

#### 金币限制
```c
// 临时金币上限检查
if (*(int32*)(coinManager + 0x08) > 999999) {
    *(int32*)(coinManager + 0x08) = 999999;
}

// 临时金币下限检查
if (*(int32*)(coinManager + 0x08) < 0) {
    *(int32*)(coinManager + 0x08) = 0;
}

// 注意: 总金币没有硬编码上限
```

### 1.4 商店购买函数

#### **`sub_70376C` (0x70376C)** - 处理商店购买
```c
__int64 __fastcall sub_70376C(
    __int64 a1,         // 玩家数据对象
    int itemId,         // 商品ID (0-63)
    int newState,       // 新状态 (3=已购买)
    int coinCost        // 金币消耗
);
```

**商品状态数组**:
```
偏移: a1 + 0x3BB8 (15288)
大小: 64 * 4 字节 = 256字节
格式: int32 array[64]

状态值:
0 = 未解锁/不可用
1 = 可购买
2 = 已查看
3 = 已购买
```

**购买流程**:
```c
// 1. 验证商品ID
if (itemId < 0 || itemId >= 64) return false;

// 2. 获取旧状态
oldState = *(int32*)(a1 + 15288 + 4 * itemId);

// 3. 更新状态
*(int32*)(a1 + 15288 + 4 * itemId) = newState;

// 4. 只有从非购买变为已购买才扣款
if (oldState != 3 && newState == 3) {
    // 调用金币扣除 (coinCost除以10是因为存储的是价格*10)
    sub_701D78(a1, coinCost/10, 1, "StoreScreen", "", "OnPurchaseCoins");
    
    // 发送购买统计到服务器
    // Event ID: 40012
}
return true;
```

### 1.5 关键字符串地址
```
"CoinBalance"           @ 0x172800B
"OnPurchaseCoins"       @ 0x1729404
"GetCoins"              @ 0x171F7A6
"COINS_FOR_AD"          @ 0x1722948
"coins"                 @ 0x172269B
"reanim/coin_silver.reanim" @ 0x17255C1
"reanim/coin_gold.reanim"   @ 0x1725E37
"SOUND_COIN"            @ 0x17419F9
```

---

## 2. 阳光系统

### 2.1 关卡配置函数

#### **`sub_69C5C8` (0x69C5C8)** - 加载关卡配置
**功能**: 从XML文件加载关卡数据，包括初始阳光值

**关键代码段** (第453-461行):
```c
// 解析 XML 属性 "mStartingSun"
sub_335E74(v195, L"mStartingSun", v194);
sub_69E764(&v196, xmlData, v195);
v98 = sub_69E8B4(&v196);
sub_3366E4(buffer, v98 + 24);
v9 = sub_334F60(buffer);
startingSun = sub_341F5C(v9);  // 解析为整数

// 存储到关卡数据结构
*(int32*)(levelDataBase + 3708 + 636 * levelId) = startingSun;
```

### 2.2 阳光存储位置
```
关卡数据基址 + 0xE7C (3708) + 636 * 关卡ID

每个关卡数据大小: 636字节
关卡数据结构:
+0x0000  byte    关卡启用标志
+0x0004  int32   背景类型 (0-5)
+0x0E7C  int32   初始阳光值
+0x0E80  int32   最大阳光值
+0x0E84  int32   阳光收集波次
+0x0E88  byte    是否启用阳光掉落
```

### 2.3 阳光相关字符串
```
"mStartingSun"          @ 0x177AA84 (配置键)
"SEED_SUNFLOWER"        @ 0x1727836
"SEED_SUNSHROOM"        @ 0x17278AA
"SEED_TWINSUNFLOWER"    @ 0x1727A91
"reanim/sunflower.reanim"   @ 0x17253 1E
"reanim/sun.reanim"     @ 0x172548A
"IMAGE_DAN_SUNBANK"     @ 0x1740479
```

---

## 3. 植物解锁

### 3.1 解锁标志位置

**解锁标志字符串**:
- `"hasUnlockedMinigames"` @ 0x1728E0D
- `"hasUnlockedPuzzleMode"` @ 0x1728E22
- `"hasUnlockedSurvivalMode"` @ 0x1728E76
- `"hasUnlockedMoreWays"` @ 0x17291E8

**引用函数**:
- `sub_6F26CC` (0x6F26CC) - 用户数据加载/保存
- `sub_6F9044` (0x6F9044) - 游戏进度保存

### 3.2 植物种子ID
从 `sub_69C5C8` 中发现植物种子数组 `off_1B7CD18`:
```c
// 76种植物种子
"SEED_PEASHOOTER"       = 0
"SEED_SUNFLOWER"        = 1
"SEED_CHERRYBOMB"       = 2
"SEED_WALLNUT"          = 3
// ... (共76个)
"SEED_TWINSUNFLOWER"    = 某个ID
"SEED_GOLD_MAGNET"      = 某个ID
"SEED_IMITATER"         = 某个ID
```

### 3.3 商店植物
```
STORE_ITEM_PLANT_GATLINGPEA      @ 0x171DEED
STORE_ITEM_PLANT_TWINSUNFLOWER   @ 0x171DF09
STORE_ITEM_PLANT_GLOOMSHROOM     @ 0x171DF28
STORE_ITEM_PLANT_CATTAIL         @ 0x171DF45
STORE_ITEM_PLANT_WINTERMELON     @ 0x171DF5E
STORE_ITEM_PLANT_GOLD_MAGNET     @ 0x171DF7B
STORE_ITEM_PLANT_SPIKEROCK       @ 0x171DF98
STORE_ITEM_PLANT_COBCANNON       @ 0x171DFB3
STORE_ITEM_PLANT_IMITATER        @ 0x171DFCE
```

---

## 4. 商店系统

### 4.1 商品管理

**商品状态数组**:
```
基址: PlayerData + 0x3BB8 (15288)
类型: int32[64]
大小: 256字节

每个商品4字节状态值:
0 = 未解锁
1 = 可购买
2 = 已查看
3 = 已购买
```

**访问方式**:
```c
itemState = *(int32*)(playerData + 15288 + 4 * itemId);
```

### 4.2 购买验证

**函数**: `sub_70376C`

**关键检查**:
1. 商品ID范围: 0-63
2. 状态变化: 只有从非3变为3才触发购买
3. 金币扣除: 调用 `sub_701D78`
4. 统计上报: Event ID 40012

**绕过方法**:
- 直接修改商品状态为3
- Hook购买函数返回true
- 修改金币扣除为0

---

## 5. 存档系统

### 5.1 存档文件路径

**用户数据**:
```
userdata/user%d.dat          - 二进制用户数据
userdata/user%d_json.dat     - JSON格式用户数据 (优先)
userdata/user%d_backup.dat   - 备份文件
```

**关卡数据**:
```
userdata/game%d_%d.dat       - 关卡进度 (用户ID, 关卡ID)
```

**金币存档**:
```
userdata/coins200k%d.dat     - 金币奖励存档 (默认20000)
```

**用户列表**:
```
userdata/users.dat           - 用户列表
userdata/users_backup.dat    - 用户列表备份
```

### 5.2 存档读取

#### **`sub_702218` (0x702218)** - 用户数据加载
```c
// 优先尝试JSON格式
sprintf(path, "userdata/user%d_json.dat", userId);
if (文件存在且有效) {
    // 使用JSON解析
    解密数据 (AES-128, mode=3, padding=3, zeroPad=1);
    解析JSON;
    应用到游戏数据;
} else {
    // 回退到二进制格式
    sprintf(path, "userdata/user%d.dat", userId);
    读取并解密二进制数据;
    解析到游戏数据;
}
```

#### **`sub_701A48` (0x701A48)** - 金币存档处理
```c
sprintf(path, "userdata/coins200k%d.dat", userId);
if (!文件存在) {
    创建目录 "userdata";
    写入默认值 "20000";  // 默认2万金币
}

if (shouldAddCoins) {
    // 从全局变量读取金币值并添加
    coinsToAdd = *(int32*)qword_1BBB3E8;
    sub_701D78(coinManager, coinsToAdd, 0, "Unknown", "", "200K");
}
```

#### **`sub_6C1B30` (0x6C1B30)** - 关卡存档路径生成
```c
if (!levelId) {
    // 自动检测关卡
    if (是教程关卡) {
        levelId = 128;
    }
}
sprintf(path, "userdata/game%d_%d.dat", userId, levelId);
```

### 5.3 存档加密

**从代码分析**:
- 使用 AES-128 加密
- Mode: 3 (可能是 CBC)
- Padding: 3 (PKCS7)
- 零填充: 是

**解密调用**:
```c
sub_11BEF6C(encryptedData, mode=3, padding=3, zeroPad=1, 0);
```

---

## 6. 反作弊

### 6.1 数据校验

#### 金币上限
**位置**: `sub_701D78` @ 0x702158-0x7021BC
```c
// 临时金币上限: 999,999
if (tempCoins > 999999) {
    tempCoins = 999999;
}

// 临时金币下限: 0
if (tempCoins < 0) {
    tempCoins = 0;
}

// 总金币无硬编码上限
```

#### 数据上报
**位置**: `sub_701D78` @ 0x702134
```c
// 调用统计API
sub_7F6A5C(
    "SYNERGYTRACKING::CUSTOM",
    eventId,              // 5009=消耗, 5010=获得
    15, playerLevel,      // 玩家等级
    15, timestamp,        // 时间戳
    15, deltaAmount,      // 变化量
    15, currentBalance,   // 当前余额
    15, "",
    15, itemInfo,         // 物品信息
    15, sourceScene,      // 来源场景
    15, eventName,        // 事件名称
    15, "",
    15, onlineStatus      // "Online" 或 "Offline"
);
```

### 6.2 完整性检查

**追踪的数据**:
1. 金币变化历史
2. 购买记录
3. 游戏时长
4. 关卡进度
5. 在线状态

**上报函数**:
- `sub_6AD768` - 超大型数据收集函数 (3000+行)
- `sub_7F6A5C` - 统计API发送

---

## 7. 修改方法

### 7.1 内存修改 (推荐)

#### 使用 GameGuardian / Cheat Engine

**步骤1: 定位金币管理器**
1. 搜索当前金币值 (精确搜索, DWORD)
2. 消耗/获得金币触发变化
3. 再次搜索，缩小范围
4. 找到地址后查看附近内存

**偏移关系**:
```
[找到的地址]     = 临时金币 (int32)
[地址 - 8]       = 总金币 (int64)
[地址 + 15240]   = 商品状态数组起始
```

**修改值**:
```
总金币:    建议 999999999 (约10亿)
临时金币:  最大 999999 (会被限制)
商品状态:  全部改为 3 = 全解锁
```

### 7.2 Hook修改 (高级)

#### Frida脚本框架
```javascript
// Hook金币修改函数
var sub_701D78 = Module.findExportByName("libpvz.so", null);
var coinModifyAddr = base.add(0x701D78);

Interceptor.attach(coinModifyAddr, {
    onEnter: function(args) {
        var coinManager = ptr(args[0]);
        var amount = args[1].toInt32();
        var flag = args[2].toInt32();
        
        console.log("[Coin] Amount: " + amount + ", Flag: " + flag);
        
        // 修改为大数值
        if (amount > 0) {
            args[1] = ptr(999999);
        }
    }
});

// Hook购买函数 - 免费购买
var buyItemAddr = base.add(0x70376C);
Interceptor.attach(buyItemAddr, {
    onEnter: function(args) {
        // 修改价格为0
        args[3] = ptr(0);
    },
    onLeave: function(ret) {
        // 强制返回成功
        ret.replace(1);
    }
});
```

### 7.3 SO文件修改 (危险)

#### 修改金币上限检查

**原代码** @ 0x702158:
```assembly
CMP     W8, #0xF423F  ; 比较 999999
B.LE    loc_7021B4
MOV     W8, #0xF423F  ; 设置为 999999
STR     W8, [X9,#8]
```

**修改为无限**:
```assembly
; 方法1: NOP掉限制
NOP
NOP
NOP
NOP

; 方法2: 修改比较值
CMP     W8, #0x3B9AC9FF  ; 999,999,999
```

#### 修改购买检查

**原代码** @ 0x703844:
```assembly
; 检查旧状态 != 3
CMP     W8, #3
B.EQ    skip_purchase
```

**修改为始终跳过扣款**:
```assembly
B       skip_purchase  ; 无条件跳转
NOP
NOP
```

### 7.4 存档修改

#### JSON格式 (推荐)

**位置**: `userdata/user%d_json.dat`

**解密步骤**:
1. 读取加密文件
2. 使用AES-128解密 (需要找到密钥)
3. 解析JSON
4. 修改字段:
```json
{
  "coins": 999999999,
  "hasUnlockedMinigames": true,
  "hasUnlockedPuzzleMode": true,
  "hasUnlockedSurvivalMode": true,
  "plantTypesUsed": [0,1,2,...,75],
  "CoinBalance": 999999999
}
```
5. 重新加密
6. 写回文件

#### 二进制格式

**位置**: `userdata/user%d.dat`

**结构** (推测):
```
+0x00  Magic Header (4字节)
+0x04  Version (4字节)
+0x08  金币值 (8字节)
+0x10  关卡进度数组
+0x??  解锁标志位
+0x??  商店购买记录
...
+End-4 Checksum/CRC
```

---

## 8. 工具与脚本

### 8.1 推荐工具

#### Android端
- **Game Guardian** (免Root: 配合虚拟机)
- **Cheat Engine Android**
- **Xposed + 模块**

#### PC分析
- **IDA Pro 8.x** (本次使用)
- **Ghidra** (免费替代)
- **Frida** (动态Hook)

### 8.2 通用修改流程

```
1. 解包APK
   └─> 使用apktool: apktool d pvz.apk

2. 提取SO库
   └─> lib/arm64-v8a/libpvz.so

3. 分析SO
   ├─> IDA Pro加载
   ├─> 搜索字符串找关键函数
   └─> 反编译分析逻辑

4. 内存修改
   ├─> 运行游戏
   ├─> 附加GG/CE
   ├─> 搜索数值
   └─> 锁定修改

5. 存档修改
   ├─> 导出存档文件
   ├─> 解密 (如果加密)
   ├─> 修改数据
   ├─> 重新加密
   └─> 导入回设备
```

---

## 9. 重要发现总结

### 9.1 内存地址映射

| 数据 | 偏移 | 类型 | 上限 | 说明 |
|------|------|------|------|------|
| 总金币 | +0x00 | int64 | 无 | 永久保存 |
| 临时金币 | +0x08 | int32 | 999,999 | 本局游戏 |
| 用户ID | +0x34 | int32 | - | - |
| 游戏数据指针 | +0x10 | ptr | - | - |
| 关卡ID | +0xC34 | int32 | - | 43=禅境花园 |
| 商店状态[0] | +0x3BB8 | int32 | - | 商品0状态 |
| 商店状态[1] | +0x3BBC | int32 | - | 商品1状态 |
| ... | ... | ... | ... | ... |
| 商店状态[63] | +0x3CB4 | int32 | - | 商品63状态 |
| 禅境累计金币 | +0x3BB8 | int32 | - | 花园收集 |

### 9.2 关键函数地址

| 函数 | 地址 | 功能 |
|------|------|------|
| sub_701D78 | 0x701D78 | 金币修改核心 |
| sub_70376C | 0x70376C | 商店购买处理 |
| sub_702218 | 0x702218 | 用户数据加载 |
| sub_701A48 | 0x701A48 | 金币存档 |
| sub_6C1B30 | 0x6C1B30 | 关卡存档路径 |
| sub_69C5C8 | 0x69C5C8 | 关卡配置加载 |
| sub_6F26CC | 0x6F26CC | 解锁数据保存 |
| sub_6F9044 | 0x6F9044 | 游戏进度保存 |
| sub_6AD768 | 0x6AD768 | 数据追踪/分析 |
| sub_7F6A5C | 0x7F6A5C | 统计API |

### 9.3 字符串资源

**配置键**:
```
CoinBalance, hasUnlockedMinigames, hasUnlockedPuzzleMode,
hasUnlockedSurvivalMode, mStartingSun, numPottedPlants
```

**事件名**:
```
OnPurchaseCoins, GetCoins, COINS_FOR_AD
```

---

## 10. 快速修改指南

### 🎯 方法1: 金币直接改 (最简单)

**使用GameGuardian**:
```
1. 打开游戏，进入主菜单
2. 打开GG，搜索当前金币值 (DWORD)
3. 消耗/获得金币
4. 再次搜索新值
5. 找到2个结果:
   - 一个是临时金币 (int32)
   - 另一个偏移-8字节是总金币 (int64)
6. 修改总金币为 999999999
7. 修改临时金币为 999999 (最大)
8. 锁定数值
```

### 🎯 方法2: 全商店解锁

**步骤**:
```
1. 在GG中搜索商品状态 (0或1)
2. 购买一个商品
3. 搜索变为3的值
4. 找到商品状态数组基址
5. 批量修改所有64个商品状态为3
```

### 🎯 方法3: 存档修改

**工具**: 任意文本/十六进制编辑器

**步骤**:
```
1. 从 /data/data/com.ea.game.pvzfree_cn/files/ 导出存档
2. 如果是JSON格式:
   - 尝试解密 (需要密钥)
   - 修改 "coins" 等字段
   - 重新加密
3. 如果是二进制:
   - 十六进制编辑
   - 查找金币值特征
   - 修改并重算校验和
4. 导入回设备
5. 重启游戏
```

---

## 11. 注意事项

### ⚠️ 风险提示

1. **在线统计**: 所有金币变化会上报服务器
2. **封号风险**: 过大数值可能被检测
3. **存档损坏**: 错误修改可能导致存档无法加载
4. **版本差异**: 不同版本偏移可能不同

### ✅ 安全建议

1. 修改前**务必备份存档**
2. 避免使用极端数值 (如 2^31-1)
3. 建议使用合理范围:
   - 金币: 100万以内
   - 商品: 仅解锁需要的
4. 离线模式下修改更安全
5. 定期更新分析 (游戏更新后)

---

## 12. 附录

### 附录A: 完整字符串列表

详见 `PVZ_Strings_Reference.txt`

### 附录B: 函数交叉引用

详见 `PVZ_Functions_Xref.txt`

### 附录C: 内存映射图

详见 `PVZ_Memory_Map.txt`

---

## 🔗 相关文档

- [金币系统深度分析](PVZ_GoldSystem_Analysis.md)
- [阳光系统分析](PVZ_SunSystem_Analysis.md) *(待生成)*
- [存档格式详解](PVZ_SaveFormat_Analysis.md) *(待生成)*

---

## 📝 更新日志

**2025-10-20**:
- ✅ 完成金币系统逆向
- ✅ 定位商店购买函数
- ✅ 分析存档文件路径
- ✅ 确定反作弊机制
- ✅ 生成初版修改指南

---

## ⚖️ 免责声明

本文档仅用于**技术研究和学习目的**。
- 请勿用于破坏游戏平衡或商业用途
- 修改游戏可能违反用户协议
- 作者不对任何后果负责

**支持正版游戏，尊重开发者劳动成果！** 🌻🧟

---

*文档生成: 自动化逆向分析 @ IDA Pro 8.x*  
*分析耗时: ~15分钟*  
*函数分析数量: 10+*  
*字符串分析数量: 200+*

