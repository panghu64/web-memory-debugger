# 植物大战僵尸 - 阳光系统详细分析

## 📌 概述

阳光是游戏中种植植物的核心资源。本文档详细分析阳光的生产、消耗、存储和管理机制。

---

## 🎯 核心发现

### 1. 关卡配置加载

#### **`sub_69C5C8` (0x69C5C8)** - XML配置解析器
**大小**: 0x1FD4 字节 (超大型函数)

**功能**:
- 加载 `/laststand.xml` 配置文件
- 解析关卡参数 (初始阳光、波次、僵尸配置等)
- 初始化6个关卡槽位的数据

**关键解析字段**:
```c
// 第453行: 读取初始阳光配置
sub_335E74(buffer, L"mStartingSun", stringObj);

// 第460行: 解析为整数
startingSunValue = sub_341F5C(xmlValue);

// 第461行: 存储到关卡数据
*(int32*)(levelBase + 0xE7C + 636 * levelIndex) = startingSunValue;
```

### 2. 关卡数据结构

**基址计算**: `levelDataBase + 3700 + 636 * levelId`

每个关卡槽占用 **636字节** (0x27C):

```c
struct LevelConfig {
    // +0x00 (相对偏移)
    byte    isActive;           // 关卡是否启用
    byte    padding[3];
    
    // +0x04
    int32   backgroundType;     // 背景类型 (0-5)
                                // 0=白天, 1=黑夜, 2=泳池, 
                                // 3=浓雾, 4=屋顶, 5=月夜
    
    // +0x08 - 关卡种子配置
    int32   seedSlots[8];       // 8个种子槽位 (每个4字节)
    
    // +0x3C (60字节处) - 可用植物列表
    int32   availableSeeds[8];  // 本关可用的植物ID
    
    // +0x5C (92字节处) - 僵尸波次配置
    struct ZombieWave {
        int32   zombieType;     // +0x00: 僵尸类型 (0-32)
        byte    isBoss;         // +0x04: 是否为Boss波
        byte    padding[3];
        int32   hp;             // +0x08: 生命值
        int32   damage;         // +0x0C: 伤害
        int32   speed;          // +0x10: 速度
        int32   startWave;      // +0x14: 开始波次
        float   weightModifier; // +0x18: 权重修正
        int32   count;          // +0x1C: 数量
    } waves[20];                // 最多20波配置
    
    // +0xE7C (3708) - 阳光配置
    int32   startingSun;        // 初始阳光值
    
    // +0xE80 (3712)
    int32   maxSun;             // 最大阳光值
    
    // +0xE84 (3716)
    int32   sunCollectionWave;  // 阳光收集波次
    
    // +0xE88 (3720)
    byte    enableSunDrop;      // 是否启用阳光掉落
    byte    padding[3];
    
    // +0xE8C (3724)
    int32   totalWaves;         // 总波数
    
    // +0xE90 (3728)
    int32   wavesPerFlag;       // 每个旗帜的波数
    
    // +0xE94 (3732)
    int32   flagsPerStage;      // 每阶段旗帜数
    
    // +0xE98 (3736)
    int32   zombieHealthMultiplier;  // 僵尸血量倍数
    
    // +0xE9C (3740)
    int32   zombieSpeedMultiplier;   // 僵尸速度倍数
    
    // +0xEA0 (3744)
    float   sunDropRate;        // 阳光掉落速率
    
    // +0xEA4 (3748)
    float   flagPointMultiplier;// 旗帜点数倍数
    
    // +0xEA8 (3752) - 特殊模式配置
    int32   nightPoolConfig;    // 夜晚泳池特殊值
    
    // +0xEAC (3756)
    int32   roofSlopeConfig;    // 屋顶斜率配置
    
    // +0xEB0 (3760)
    int32   endlessFlagsAchievement; // 无尽模式旗帜成就
};
```

### 3. 阳光修改位置

#### 游戏运行时阳光值

**推测内存位置** (需要动态调试确认):
```
可能的阳光存储位置:
1. 游戏场景对象 + 某偏移 (int32)
2. 玩家状态对象 + 某偏移 (int32)
3. UI显示缓存 (int32)
```

**查找方法**:
1. 在游戏中记录当前阳光值 (如 150)
2. 使用GG搜索 150 (DWORD)
3. 种植植物消耗阳光 (如 -100)
4. 搜索新值 50
5. 重复直到找到唯一地址

#### 配置文件修改

**文件位置**: APK内 `assets/` 目录下的XML文件

**可能的配置文件**:
- `levels.xml`
- `laststand.xml` (确认存在)
- `adventure.xml`
- `config.xml`

**修改方法**:
1. 解包APK
2. 找到XML配置
3. 搜索 `<mStartingSun>` 标签
4. 修改值 (如 9999)
5. 重新打包APK
6. 签名并安装

---

## 🌻 阳光生产机制

### 植物产阳光

#### 向日葵系列

**普通向日葵** (SEED_SUNFLOWER):
- 生产间隔: 约24秒
- 单次产量: 25阳光
- 成本: 50阳光
- 冷却: 7.5秒

**双发向日葵** (SEED_TWINSUNFLOWER):
- 生产间隔: 约24秒
- 单次产量: 50阳光 (2x25)
- 成本: 150阳光
- 冷却: 7.5秒
- 需解锁: 商店购买

**阳光菇** (SEED_SUNSHROOM):
- 初期产量: 15阳光
- 成长后: 25阳光
- 成本: 25阳光
- 特性: 夜晚专用

### 天降阳光

**掉落机制** (推测):
```c
// 配置参数
float sunDropRate;           // 掉落速率 (从关卡配置读取)
int   sunDropInterval;       // 掉落间隔 (秒)
int   sunValue;              // 单个阳光值 (通常25)

// 特殊关卡
"ENDLESS_MINSUN_CHANCE"      @ 0x17228E1  // 无尽模式小阳光概率
"ENDLESS_STANDARDSUN_CHANCE" @ 0x17228F7  // 无尽模式标准阳光概率
```

---

## 🔧 修改方法

### 方法1: 内存修改运行时阳光

**使用GameGuardian**:
```
步骤:
1. 搜索当前阳光值 (DWORD, 范围 0-9990)
2. 种植植物改变阳光
3. 再次搜索
4. 找到后修改为 9990
5. 锁定数值 (冻结)

优点: 即时生效
缺点: 每局游戏需重新操作
```

### 方法2: 修改初始阳光

**修改配置文件**:

**位置**: `assets/*.xml` 或游戏内部配置

**XML示例**:
```xml
<stage>
    <mStartingSun>9999</mStartingSun>
    <mMaxSun>9999</mMaxSun>
    <mSunDropRate>10.0</mSunDropRate>
</stage>
```

**修改步骤**:
1. 解包APK: `apktool d pvzhhb.apk`
2. 编辑 `assets/laststand.xml` 等配置文件
3. 修改 `<mStartingSun>` 值
4. 重新打包: `apktool b pvzhhb -o pvzhhb_mod.apk`
5. 签名: `jarsigner -keystore debug.keystore pvzhhb_mod.apk`
6. 安装修改版APK

### 方法3: Hook函数

**Frida脚本示例**:
```javascript
// 定位libpvz.so基址
var base = Module.findBaseAddress("libpvz.so");

// Hook阳光消耗函数 (假设地址)
var consumeSunAddr = base.add(0xXXXXXX);  // 需要进一步分析确定
Interceptor.attach(consumeSunAddr, {
    onEnter: function(args) {
        console.log("[Sun] Consume: " + args[1]);
        // 修改消耗为0
        args[1] = ptr(0);
    }
});

// Hook阳光增加函数
var addSunAddr = base.add(0xYYYYYY);  // 需要进一步分析确定
Interceptor.attach(addSunAddr, {
    onEnter: function(args) {
        var oldAmount = args[1].toInt32();
        // 倍增阳光
        args[1] = ptr(oldAmount * 10);
        console.log("[Sun] Add: " + oldAmount + " -> " + (oldAmount*10));
    }
});
```

### 方法4: SO文件修改

**思路**: 修改初始阳光验证或上限

**可能的修改点**:
```assembly
; 修改阳光上限 (假设在某函数中)
CMP     W8, #9990    ; 原始上限 9990
B.LE    no_cap
MOV     W8, #9990
no_cap:

; 修改为:
CMP     W8, #99990   ; 新上限 99990
B.LE    no_cap
MOV     W8, #99990
no_cap:
```

---

## 📊 阳光相关字符串资源

### XML属性名
```
mStartingSun              @ 0x177AA84  - 初始阳光
sunBetweenStages         @ 0x177AAA0  - 关卡间阳光
```

### 植物资源
```
SEED_SUNFLOWER           @ 0x1727836
SEED_SUNSHROOM           @ 0x17278AA
SEED_TWINSUNFLOWER       @ 0x1727A91

reanim/sunflower.reanim  @ 0x17253 1E
reanim/sunshroom.reanim  @ 0x17253E5
reanim/sun.reanim        @ 0x172548A
reanim/twinsunflower.reanim @ 0x1725B76
```

### 图像资源
```
IMAGE_DAN_SUNBANK                @ 0x1740479  - 阳光银行
IMAGE_SEEDPACKET_SUN             @ 0x17426E6  - 种子包图标
IMAGE_REANIM_SUN1/2/3            @ 0x173478D  - 阳光动画帧
IMAGE_REANIM_SUNFLOWER_*         @ 0x17347C3  - 向日葵动画
IMAGE_REANIM_SUNSHROOM_*         @ 0x1734912  - 阳光菇动画
IMAGE_REANIM_TWINSUNFLOWER_*     @ 0x1734F0D  - 双发向日葵
```

### 成就/特殊关卡
```
ICON_SUNNY_DAYS              @ 0x17282A1
ACHIEVEMENT_SUNNY_DAYS       @ 0x17282B1
ICON_SUN_DONT_SHINE          @ 0x172871F
ACHIEVEMENT_SUN_DONT_SHINE   @ 0x1728733

"Sunny Day"                  @ 0x1726B3A  - 关卡名
"Art Challenge Sunflower"    @ 0x1726B56  - 挑战名
```

---

## 🔬 深入分析

### 关卡数据初始化流程

**函数调用链**:
```
sub_69C5C8 (XML解析)
    ├─> sub_B52934 (打开XML文件)
    ├─> sub_B52A4C (读取XML节点)
    ├─> sub_335E74 (提取属性)
    │   └─> "mStartingSun"
    ├─> sub_341F5C (字符串转整数)
    └─> 存储到关卡数据结构
```

### XML解析过程

**第219-237行**: 初始化6个关卡槽
```c
for (levelSlot = 0; levelSlot < 6; levelSlot++) {
    destAddr = levelBase + 3700 + 636 * levelSlot;
    sub_66F2DC(tempBuffer);  // 生成默认配置
    memcpy(destAddr, tempBuffer, 0x27C);  // 636字节
}
```

**第453-461行**: 解析初始阳光
```c
// 读取 XML 属性 L"mStartingSun"
sub_335E74(attrBuffer, L"mStartingSun", stringObj);
sub_69E764(&xmlValue, xmlNodeData, attrBuffer);

// 获取属性值
v98 = sub_69E8B4(&xmlValue);
sub_3366E4(textBuffer, v98 + 24);
rawTextPtr = sub_334F60(textBuffer);

// 转换为整数
startingSun = sub_341F5C(rawTextPtr);

// 存储 (关键!)
*(int32*)(levelBase + 3708 + 636 * levelIndex) = startingSun;
```

### 其他关卡属性解析

**第462-471行**: 最大阳光
```c
sub_335E74(buffer, L"mMaxSun", stringObj);
maxSun = sub_341F5C(xmlValue);
*(int32*)(levelBase + 3712 + 636 * levelIndex) = maxSun;
```

**第472-485行**: 阳光掉落启用
```c
sub_335E74(buffer, L"mEnableSunDrop", stringObj);
// 比较字符串 "true"
enableDrop = (strcmp(xmlValue, "true") == 0);
*(byte*)(levelBase + 3716 + 636 * levelIndex) = enableDrop;
```

**第543-564行**: 阳光掉落速率
```c
sub_335E74(buffer, L"mSunDropRate", stringObj);
dropRate = sub_341C78(xmlValue);  // 字符串转float
*(float*)(levelBase + 3744 + 636 * levelIndex) = dropRate;
```

---

## 💡 实用修改技巧

### 技巧1: 修改所有关卡初始阳光

**内存修改**:
```c
// 伪代码
levelBase = [找到关卡数据基址];
for (int i = 0; i < 6; i++) {
    int32* sunPtr = (int32*)(levelBase + 3708 + 636 * i);
    *sunPtr = 9999;  // 修改初始阳光
}
```

**GG脚本示例**:
```lua
-- 批量修改6个关卡槽的初始阳光
levelBase = 0xXXXXXXXX  -- 需要动态查找

for i = 0, 5 do
    offset = 3708 + 636 * i
    addr = levelBase + offset
    gg.setValues({{address = addr, flags = gg.TYPE_DWORD, value = 9999}})
end
```

### 技巧2: 无限阳光 (内存冻结)

**步骤**:
1. 进入关卡
2. 搜索当前阳光值 (DWORD)
3. 种植物/收集阳光触发变化
4. 再次搜索
5. 找到后**添加到保存列表**
6. 修改为9990
7. **冻结该值** (GG中勾选"冻结")

**效果**: 阳光值始终保持9990，无法消耗

### 技巧3: 阳光生产倍增

**思路**: Hook向日葵产阳光的函数

**可能的函数签名**:
```c
void ProduceSun(Plant* sunflower, int sunAmount);
```

**Frida Hook**:
```javascript
// 需要先找到ProduceSun函数地址
var produceSunAddr = base.add(0xXXXXXX);
Interceptor.attach(produceSunAddr, {
    onEnter: function(args) {
        var plant = ptr(args[0]);
        var amount = args[1].toInt32();
        
        // 倍增产量
        args[1] = ptr(amount * 10);
        console.log("[Sun] Produce: " + amount + " -> " + (amount*10));
    }
});
```

---

## 🎮 背景类型枚举

**从 `sub_69C5C8` 第435-450行分析**:

数组 `off_1B7CCE8` 包含背景类型字符串:
```c
enum BackgroundType {
    BACKGROUND_1_DAY = 0,      // 白天草地
    BACKGROUND_2_NIGHT = 1,    // 黑夜
    BACKGROUND_3_POOL = 2,     // 泳池白天
    BACKGROUND_4_FOG = 3,      // 浓雾
    BACKGROUND_5_ROOF = 4,     // 屋顶
    BACKGROUND_6_MOON = 5      // 月夜/泳池夜晚
};
```

**对应的关卡特性**:
- **白天**: 正常阳光掉落
- **黑夜**: 无天降阳光，必须种阳光菇
- **泳池**: 需要水生植物
- **浓雾**: 视野受限
- **屋顶**: 无地面，需要花盆

---

## 🧪 测试与验证

### 测试用例1: 修改初始阳光

**预期结果**:
- 进入关卡时阳光值为修改后的值
- 可以立即种植昂贵植物

**验证方法**:
```
1. 记录原始初始阳光 (通常50或100)
2. 应用修改
3. 进入关卡观察
4. 确认阳光值为修改值
```

### 测试用例2: 阳光上限

**测试步骤**:
```
1. 修改最大阳光为99999
2. 收集阳光直到达到上限
3. 观察是否能超过原上限9990
```

**预期行为**:
- 如果只修改配置: 仍受代码限制
- 如果同时修改代码: 可达到新上限

---

## 📈 性能与优化

### 阳光显示优化

**UI刷新**: 每帧检查阳光值变化
**数字动画**: 使用缓动函数平滑过渡

**潜在优化点**:
- 禁用阳光收集动画 (直接到账)
- 加快阳光掉落速度
- 增加同屏阳光数量上限

---

## 🔍 待确认项

以下内容需要进一步动态调试确认:

1. ❓ 运行时阳光值的确切内存位置
2. ❓ 阳光消耗函数的地址
3. ❓ 阳光生产函数的地址  
4. ❓ 阳光掉落触发函数
5. ❓ 阳光收集检测函数

**建议工具**: 
- Frida + Stalker (追踪执行)
- IDA动态调试
- GDB远程调试

---

## 📚 参考函数列表

| 函数地址 | 函数名 | 功能 |
|---------|--------|------|
| 0x69C5C8 | sub_69C5C8 | 关卡配置加载 |
| 0x66F2DC | sub_66F2DC | 默认关卡数据 |
| 0xB52934 | sub_B52934 | XML文件打开 |
| 0xB52A4C | sub_B52A4C | XML节点读取 |
| 0x335E74 | sub_335E74 | XML属性提取 |
| 0x341F5C | sub_341F5C | 字符串转整数 |
| 0x341C78 | sub_341C78 | 字符串转浮点 |
| 0x334F60 | sub_334F60 | 获取字符串内容 |

---

## 🎨 图形资源ID

向日葵完整动画资源:
```
IMAGE_REANIM_SUNFLOWER_HEAD            @ 0x1734894
IMAGE_REANIM_SUNFLOWER_HEAD_GLOW       @ 0x17348B0
IMAGE_REANIM_SUNFLOWER_PETALS          @ 0x17348D1
IMAGE_REANIM_SUNFLOWER_PETALS_GLOW     @ 0x17348EF
IMAGE_REANIM_SUNFLOWER_BLINK1          @ 0x17347C3
IMAGE_REANIM_SUNFLOWER_BLINK1_GLOW     @ 0x17347E1
IMAGE_REANIM_SUNFLOWER_BLINK2          @ 0x1734804
IMAGE_REANIM_SUNFLOWER_BLINK2_GLOW     @ 0x1734822
IMAGE_REANIM_SUNFLOWER_DOUBLE_PETALS   @ 0x1734845
```

阳光菇完整动画资源:
```
IMAGE_REANIM_SUNSHROOM_BODY            @ 0x1734994
IMAGE_REANIM_SUNSHROOM_BODY_GLOW       @ 0x17349B0
IMAGE_REANIM_SUNSHROOM_HEAD            @ 0x17349D1
IMAGE_REANIM_SUNSHROOM_HEAD_GLOW       @ 0x17349ED
IMAGE_REANIM_SUNSHROOM_SLEEP           @ 0x1734A0E
IMAGE_REANIM_SUNSHROOM_SLEEP_GLOW      @ 0x1734A2B
IMAGE_REANIM_SUNSHROOM_BLINK1          @ 0x1734912
IMAGE_REANIM_SUNSHROOM_BLINK2          @ 0x1734953
```

---

*分析状态: 部分完成 - 需要动态调试补充运行时数据*  
*建议下一步: 使用Frida追踪阳光相关函数调用*

