# IDA分析指南 - PVZ阳光基址查找

## 📦 数据包内容

### 已导出文件
1. **libpvz.so** (28.9MB) - PVZ主库文件
2. **x1_object_region.bin** (64KB) - X1中间对象区域
3. **sun_object_region.bin** (4KB) - 阳光对象区域
4. **memory_maps.txt** - 完整内存映射表

---

## 🎯 关键地址信息

### 当前运行时地址（会变化）
- **libpvz.so基址**: `0x7B67825000`
- **libpvz.so数据段**: `0x7B6939B000 - 0x7B693CD000` (204KB)
- **阳光对象地址**: `0x7ACC028870`
- **阳光值地址**: `0x7ACC02887C` (+0x0C偏移)
- **当前阳光值**: `75`
- **X1中间对象**: `0x030B0338` (dalvik-main space)

### 访问代码位置
- **PC**: `0x71E51048`
- **库**: `/system/framework/arm64/boot-framework.oat`
- **关键指令**: `ldr x21, [x21]`

---

## 🔍 IDA分析步骤

### 第一步：加载libpvz.so
```
1. 打开IDA Pro
2. 加载 libpvz.so
3. 选择处理器: ARM64 (AArch64)
4. 基址设置为: 0x7B67825000 (当前运行时基址)
```

### 第二步：定位数据段
```
数据段范围：
  起始: 0x7B6939B000
  结束: 0x7B693CD000
  大小: 204KB
  
相对于库基址的偏移：
  计算: 0x7B6939B000 - 0x7B67825000 = 0x1B76000
```

### 第三步：搜索阳光对象引用
在数据段中搜索以下特征：

#### 方法1：搜索指向阳光区域的指针
```
目标地址: 0x7ACC028870
搜索范围: 数据段 0x7B6939B000-0x7B693CD000
搜索类型: QWORD (8字节指针)
```

#### 方法2：搜索X1对象引用
```
X1地址: 0x030B0338
注意: X1在dalvik-main space，可能没有静态引用
```

#### 方法3：交叉引用分析
```
1. 在IDA中搜索字符串: "sun", "sunshine", "money"
2. 查找相关函数
3. 分析函数中的全局变量访问
4. 定位GameState或类似的单例对象
```

### 第四步：反汇编关键函数
```
关注以下模式：
1. LDR指令从数据段加载指针
2. 间接访问（[ptr] + offset）
3. 单例模式的getInstance()函数
```

---

## 📊 内存布局分析

### libpvz.so内存映射
从`memory_maps.txt`提取：
```
7b67825000-7b693fa000  r-xp  代码段（可执行）
7b693fa000-7b6939b000  r--p  只读数据
7b6939b000-7b693cd000  rw-p  数据段（全局变量）⭐关键
7b693cd000-7b693d0000  rw-p  BSS段
```

### Java Heap布局
```
00e00000-40e00000      dalvik-main space (1GB)
├─ X1对象: 0x030B0338
└─ 其他Java对象
```

### 阳光对象区域
```
7acbda7000-7acc5a7000  匿名rw区域 (8MB)
└─ 阳光对象: 0x7ACC028870
   └─ +0x0C → 阳光值 (int32)
```

---

## 💡 查找静态基址的策略

### 策略1：查找GameState单例
```cpp
// 典型模式
class GameState {
    static GameState* instance;  // ← 在数据段中
    int sunPoints;               // +0x0C偏移
};

// 查找
1. 在数据段搜索指针
2. 验证指针指向的对象结构
3. 检查+0x0C偏移处是否为阳光值
```

### 策略2：分析初始化代码
```
1. 查找 _init, _init_array 函数
2. 查找构造函数调用
3. 定位全局对象初始化
4. 找到GameState创建位置
```

### 策略3：字符串交叉引用
```
1. 搜索调试字符串（如果有）
2. 查找UI相关字符串
3. 追踪到对应的数据结构
```

---

## 🔧 IDA脚本辅助

### 扫描数据段中的有效指针
```python
# IDA Python脚本
data_start = 0x7B6939B000
data_end = 0x7B693CD000

for addr in range(data_start, data_end, 8):
    ptr_value = get_qword(addr)
    # 检查是否指向heap区域
    if 0x7ACC000000 <= ptr_value <= 0x7ACC100000:
        print(f"Found pointer at {hex(addr)}: {hex(ptr_value)}")
        # 进一步检查+0x0C偏移
        sun_value = get_dword(ptr_value + 0x0C)
        print(f"  Value at +0x0C: {sun_value}")
```

---

## 📋 验证基址的步骤

找到可疑的静态指针后，验证方法：

### 1. 计算偏移
```
假设在数据段 0x7B693C5678 找到指针
相对于libpvz.so基址的偏移：
  0x7B693C5678 - 0x7B67825000 = 0x11A0678
```

### 2. 构建指针链
```
libpvz.so基址 (动态)
  + 0x11A0678 (固定偏移)
  = 静态指针地址
  → [指针值]
  + 0x0C
  = 阳光值地址
```

### 3. 实时验证
```bash
# 读取指针
adb shell "su -c 'dd if=/proc/PID/mem bs=8 skip=$((BASE+OFFSET/8)) count=1 | od -A n -t x8'"

# 读取阳光值
adb shell "su -c 'dd if=/proc/PID/mem bs=4 skip=$(([指针值]+0x0C/4)) count=1 | od -A n -t d4'"
```

### 4. 游戏重启后验证
```
1. 重启游戏（基址会变化）
2. 获取新的libpvz.so基址
3. 使用相同的固定偏移
4. 验证是否仍能读取到阳光值
```

---

## ⚠️ 注意事项

### 可能的障碍
1. **Java管理**：阳光可能完全在Java层管理，libpvz.so中没有引用
2. **JNI间接访问**：通过JNI调用，没有C++全局变量
3. **动态分配**：每次都new创建，没有静态实例
4. **优化代码**：编译优化可能让引用不明显

### 如果找不到静态基址
考虑以下可能性：
- 阳光值确实是Java堆对象，无C++静态引用
- 使用方案A（内存特征搜索）或方案C（Frida Hook）
- 尝试AOB特征码扫描（搜索阳光值周围的固定字节模式）

---

## 📌 下一步行动

1. ✅ 在IDA中加载libpvz.so
2. ✅ 导航到数据段 (相对偏移 0x1B76000)
3. ✅ 执行指针扫描脚本
4. ✅ 分析可疑指针
5. ✅ 验证指针链
6. ✅ 测试跨重启稳定性

---

## 📞 数据采集时间
- **PID**: 32288
- **采集时间**: 2025-10-20
- **阳光值**: 75
- **游戏版本**: com.ea.game.pvzfree_cn

祝分析顺利！🎯

