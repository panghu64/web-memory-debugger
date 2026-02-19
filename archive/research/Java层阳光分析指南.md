# Java层阳光分析指南

## ? 重要发现

**阳光地址**: `0x6D4662B22C`  
**位置**: Java堆内存（不是Native C++对象）

这意味着：
- ? 阳光值存储在Java对象中
- ? 需要通过Java类和字段访问
- ? 不能通过libpvz.so的C++指针访问

---

## ? Java层 vs Native层

### Java层特征
```
- 内存在Dalvik/ART虚拟机堆中
- 通过类名.字段名访问
- 使用Frida hook Java方法
- 地址每次GC后可能变化
```

### Native层特征
```
- 内存在so库的数据段
- 通过C++指针访问
- 使用IDA分析汇编
- 地址相对固定（ASLR后）
```

---

## ? Java层分析方法

### 方法1: 使用Frida Hook ???

#### 步骤1: 查找阳光相关的Java类

可能的类名：
- `com.popcap.game.Sun`
- `com.popcap.game.SunManager`
- `com.popcap.game.GameWorld`
- `com.ea.game.pvz.Sun`

#### 步骤2: Frida脚本示例

```javascript
// 搜索包含阳光值的类
Java.perform(function() {
    // 枚举所有类
    Java.enumerateLoadedClasses({
        onMatch: function(className) {
            if (className.toLowerCase().indexOf('sun') !== -1 ||
                className.toLowerCase().indexOf('game') !== -1) {
                console.log('可能的类: ' + className);
            }
        },
        onComplete: function() {
            console.log('搜索完成');
        }
    });
});
```

#### 步骤3: Hook阳光修改方法

```javascript
Java.perform(function() {
    // 假设找到了Sun类
    var SunClass = Java.use('com.popcap.game.Sun');
    
    // Hook阳光设置方法
    SunClass.setSunAmount.implementation = function(amount) {
        console.log('设置阳光: ' + amount);
        console.log('调用栈: ' + Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()));
        return this.setSunAmount(amount);
    };
    
    // Hook阳光增加方法
    SunClass.addSun.implementation = function(amount) {
        console.log('增加阳光: ' + amount);
        return this.addSun(amount);
    };
});
```

---

### 方法2: 使用GameGuardian搜索 ??

```
1. 打开GameGuardian
2. 选择游戏进程
3. 搜索类型: Dword (4字节)
4. 搜索当前阳光值（如：50）
5. 收集阳光后再次搜索新值
6. 重复直到找到唯一地址
7. 查看地址所在内存区域
```

---

### 方法3: 反编译APK查找类 ?

#### 步骤1: 反编译APK

```bash
# 使用jadx反编译
jadx -d output_dir game.apk

# 或使用apktool
apktool d game.apk
```

#### 步骤2: 搜索关键字

在反编译的Java代码中搜索：
- `sun`
- `阳光`
- `sunflower`
- `solar`

---

## ? 实战：使用我们的项目

### 已有的工具

查看项目中的Frida脚本：
```
doce/PVZ_Frida_Scripts.md
```

这个文件可能已经包含了阳光相关的hook！

---

## ? Java层指针链概念

在Java中，"指针链"实际上是**对象引用链**：

```java
// 示例
class GameWorld {
    SunManager sunManager;  // 引用1
}

class SunManager {
    int currentSun;  // 这是我们要找的值
}

// 访问路径：
GameWorld实例 -> sunManager字段 -> currentSun字段
```

---

## ? 使用Frida查找对象引用

### 脚本1: 查找阳光值在哪个对象中

```javascript
Java.perform(function() {
    // 搜索所有实例
    Java.choose('com.popcap.game.GameWorld', {
        onMatch: function(instance) {
            console.log('找到GameWorld实例: ' + instance);
            
            // 尝试读取可能的字段
            var fields = instance.class.getDeclaredFields();
            fields.forEach(function(field) {
                field.setAccessible(true);
                try {
                    var value = field.get(instance);
                    console.log('字段: ' + field.getName() + ' = ' + value);
                } catch(e) {}
            });
        },
        onComplete: function() {}
    });
});
```

### 脚本2: 监控阳光变化

```javascript
Java.perform(function() {
    var targetValue = 50; // 当前阳光值
    
    setInterval(function() {
        Java.choose('com.popcap.game.SunManager', {
            onMatch: function(instance) {
                var currentSun = instance.currentSun.value;
                if (currentSun !== targetValue) {
                    console.log('阳光变化: ' + targetValue + ' -> ' + currentSun);
                    targetValue = currentSun;
                }
            },
            onComplete: function() {}
        });
    }, 1000);
});
```

---

## ? 从Java找到Native

如果阳光值需要同步到Native层：

```java
// Java层
public class SunManager {
    private int currentSun;
    
    public void setSun(int value) {
        this.currentSun = value;
        nativeSetSun(value);  // 调用JNI
    }
    
    private native void nativeSetSun(int value);
}
```

在这种情况下：
1. Java对象持有阳光值（主要）
2. Native代码可能有副本（同步）
3. 修改Java值最可靠

---

## ? 立即开始

### 快速测试：使用我们的Web调试器

```powershell
# 1. 查看现有的Frida脚本
cat doce/PVZ_Frida_Scripts.md

# 2. 如果有Frida服务器，连接
frida -U -n com.ea.game.pvzfree_cn

# 3. 加载脚本
%load script.js
```

### 或者查看项目文档

```powershell
# 查看已有的分析结果
cat ida_dumps/CURRENT_FINDINGS.md
cat doce/PVZ_SunSystem_Analysis.md
```

---

## ? 建议的分析流程

### 第1步：确认Java类

```bash
# 反编译APK
jadx -d pvz_decompiled game.apk

# 搜索阳光相关类
grep -r "sun" pvz_decompiled/sources/
grep -r "阳光" pvz_decompiled/sources/
```

### 第2步：编写Frida Hook

```javascript
// 基于找到的类编写hook
Java.perform(function() {
    var SunClass = Java.use('实际的类名');
    
    // Hook所有方法
    var methods = SunClass.class.getDeclaredMethods();
    methods.forEach(function(method) {
        console.log('方法: ' + method.getName());
    });
});
```

### 第3步：找到静态引用

```javascript
// 查找GameWorld单例
Java.perform(function() {
    var GameWorld = Java.use('com.popcap.game.GameWorld');
    
    // 尝试获取单例
    var instance = GameWorld.getInstance();
    console.log('GameWorld实例: ' + instance);
    
    // 获取sunManager
    var sunManager = instance.getSunManager();
    console.log('当前阳光: ' + sunManager.getCurrentSun());
});
```

---

## ? 预期结果

找到类似这样的访问路径：

```
GameWorld.getInstance()
  -> getSunManager()
    -> getCurrentSun()
```

然后可以通过Frida直接修改：

```javascript
Java.perform(function() {
    var GameWorld = Java.use('com.popcap.game.GameWorld');
    var instance = GameWorld.getInstance();
    var sunManager = instance.getSunManager();
    
    // 修改阳光
    sunManager.setCurrentSun(9999);
    console.log('阳光已修改为: 9999');
});
```

---

## ? 相关资源

### 项目文档
- `doce/PVZ_Frida_Scripts.md` - Frida脚本
- `doce/PVZ_SunSystem_Analysis.md` - 阳光系统分析
- `ida_dumps/CURRENT_FINDINGS.md` - 当前发现

### 工具
- Frida: 动态hook框架
- jadx: APK反编译
- GameGuardian: 内存修改器

---

## ?? 注意事项

### Java对象的特点
1. **地址不固定**: GC后对象会移动
2. **需要对象引用**: 不能用固定地址
3. **通过字段访问**: 使用类名.字段名
4. **权限控制**: 可能需要反射访问私有字段

### 解决方案
- ? 使用Frida hook方法
- ? 查找静态单例引用
- ? 通过类名而非地址访问
- ? 在Java层直接修改

---

## ? 下一步

1. **查看现有文档**: 检查项目中是否已有阳光相关分析
2. **反编译APK**: 找到实际的类名和方法
3. **编写Frida脚本**: Hook关键方法
4. **测试修改**: 验证可以直接修改阳光值

---

**关键点**: 如果是Java对象，就不需要找C++指针链，直接通过Java反射或Frida访问即可！

这比找指针链简单得多！?

