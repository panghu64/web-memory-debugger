# 植物大战僵尸 - Frida Hook 脚本完整集合

## 📌 目录

1. [基础框架](#1-基础框架)
2. [金币作弊](#2-金币作弊)
3. [商店免费](#3-商店免费)
4. [阳光修改](#4-阳光修改)
5. [调试工具](#5-调试工具)
6. [完整作弊包](#6-完整作弊包)

---

## 🔧 环境准备

### 安装Frida

```bash
# PC端
pip install frida-tools

# Android端 (Frida Server)
# 1. 下载对应架构的frida-server
# 2. 推送到设备
adb push frida-server-16.x.x-android-arm64 /data/local/tmp/frida-server
adb shell chmod 755 /data/local/tmp/frida-server

# 3. 运行 (需要Root)
adb shell su -c /data/local/tmp/frida-server &
```

### 验证连接

```bash
# 列出进程
frida-ps -U

# 应该能看到游戏进程
# com.ea.game.pvzfree_cn
```

---

## 1. 基础框架

### pvz_base.js

```javascript
/**
 * PVZ Frida基础框架
 * 提供常用工具函数和初始化
 */

// 全局配置
var CONFIG = {
    PACKAGE: "com.ea.game.pvzfree_cn",
    LIB_NAME: "libpvz.so",
    DEBUG: true
};

// 日志函数
function log(msg, type) {
    var prefix = {
        'info': '[*]',
        'success': '[+]',
        'error': '[!]',
        'debug': '[D]'
    }[type] || '[*]';
    
    console.log(prefix + " " + msg);
}

// 获取模块基址
var base = null;
function getBase() {
    if (!base) {
        base = Module.findBaseAddress(CONFIG.LIB_NAME);
        if (!base) {
            log("Failed to find " + CONFIG.LIB_NAME, 'error');
            return null;
        }
        log(CONFIG.LIB_NAME + " base: " + base, 'success');
    }
    return base;
}

// 计算绝对地址
function addr(offset) {
    return getBase().add(offset);
}

// 读取字符串
function readString(ptr) {
    try {
        return Memory.readCString(ptr);
    } catch(e) {
        return "<invalid>";
    }
}

// 读取整数
function readInt(ptr, size) {
    size = size || 4;
    switch(size) {
        case 1: return Memory.readS8(ptr);
        case 2: return Memory.readS16(ptr);
        case 4: return Memory.readS32(ptr);
        case 8: return Memory.readS64(ptr);
    }
}

// 写入整数
function writeInt(ptr, value, size) {
    size = size || 4;
    switch(size) {
        case 1: Memory.writeS8(ptr, value); break;
        case 2: Memory.writeS16(ptr, value); break;
        case 4: Memory.writeS32(ptr, value); break;
        case 8: Memory.writeS64(ptr, value); break;
    }
}

// 十六进制转储
function dump(ptr, size) {
    console.log(hexdump(ptr, {
        offset: 0,
        length: size,
        header: true,
        ansi: true
    }));
}

// 导出全局
global.PVZ = {
    log: log,
    addr: addr,
    readString: readString,
    readInt: readInt,
    writeInt: writeInt,
    dump: dump
};

log("Base framework loaded", 'success');
```

---

## 2. 金币作弊

### pvz_coin_hack.js

```javascript
/**
 * 金币修改脚本
 * 功能: 倍增/固定金币获得
 */

Java.perform(function() {

// 加载基础框架
var base = Module.findBaseAddress("libpvz.so");

// ===== 配置区 =====
var COIN_HACK_MODE = 2;
// 0 = 关闭
// 1 = 倍增模式 (x10)
// 2 = 固定大量金币
// 3 = 完全免费 (消耗变0)

var COIN_AMOUNT = 999999;  // 模式2使用
var COIN_MULTIPLIER = 10;   // 模式1使用

// ===== Hook金币修改函数 =====
var coinModifyAddr = base.add(0x701D78);
console.log("[+] Hooking sub_701D78 @ " + coinModifyAddr);

Interceptor.attach(coinModifyAddr, {
    onEnter: function(args) {
        this.coinManager = ptr(args[0]);
        this.amount = args[1].toInt32();
        this.flag = args[2].toInt32() & 1;
        
        var totalCoins = Memory.readS64(this.coinManager);
        var tempCoins = Memory.readS32(this.coinManager.add(0x08));
        
        if (COIN_HACK_MODE === 0) return;
        
        // 读取场景和事件名
        var scene = "";
        var event = "";
        try {
            if (args[3]) scene = Memory.readCString(ptr(args[3]));
            if (args[4]) event = Memory.readCString(ptr(args[4]));
        } catch(e) {}
        
        console.log("\n[Coin] Transaction:");
        console.log("  Total: " + totalCoins + " | Temp: " + tempCoins);
        console.log("  Change: " + (this.amount > 0 ? "+" : "") + this.amount);
        console.log("  Target: " + (this.flag ? "Total" : "Temp"));
        console.log("  Scene: " + scene + " | Event: " + event);
        
        // 应用修改
        if (this.amount > 0) {  // 只修改获得金币
            switch(COIN_HACK_MODE) {
                case 1:  // 倍增
                    args[1] = ptr(this.amount * COIN_MULTIPLIER);
                    console.log("  [MOD] " + this.amount + " x" + COIN_MULTIPLIER + 
                               " = " + (this.amount * COIN_MULTIPLIER));
                    break;
                
                case 2:  // 固定大量
                    args[1] = ptr(COIN_AMOUNT);
                    args[2] = ptr(1);  // 修改总金币
                    console.log("  [MOD] Fixed to " + COIN_AMOUNT + " (Total)");
                    break;
            }
        }
        else if (this.amount < 0 && COIN_HACK_MODE === 3) {
            // 免费模式: 消耗变为0
            args[1] = ptr(0);
            console.log("  [MOD] Cost -> 0 (FREE)");
        }
    },
    onLeave: function(ret) {
        // 读取修改后的值
        var totalAfter = Memory.readS64(this.coinManager);
        var tempAfter = Memory.readS32(this.coinManager.add(0x08));
        
        if (this.amount !== 0) {
            console.log("  After: Total=" + totalAfter + " | Temp=" + tempAfter);
        }
    }
});

console.log("[+] Coin Hack Active! Mode: " + COIN_HACK_MODE);

});
```

---

## 3. 商店免费

### pvz_free_shop.js

```javascript
/**
 * 商店免费购买
 * 功能: 所有商品价格改为0
 */

Java.perform(function() {

var base = Module.findBaseAddress("libpvz.so");

// Hook商店购买函数
var buyItemAddr = base.add(0x70376C);
console.log("[+] Hooking sub_70376C (BuyItem) @ " + buyItemAddr);

var purchaseCount = 0;

Interceptor.attach(buyItemAddr, {
    onEnter: function(args) {
        this.playerData = ptr(args[0]);
        this.itemId = args[1].toInt32();
        this.newState = args[2].toInt32();
        this.coinCost = args[3].toInt32();
        
        // 读取商品当前状态
        var stateAddr = this.playerData.add(0x3BB8 + 4 * this.itemId);
        var oldState = Memory.readS32(stateAddr);
        
        console.log("\n[Shop] Purchase #" + (++purchaseCount));
        console.log("  Item ID: " + this.itemId);
        console.log("  State: " + oldState + " -> " + this.newState);
        console.log("  Original Cost: " + this.coinCost);
        
        // 免费购买
        args[3] = ptr(0);
        console.log("  [MOD] Cost -> 0 (FREE!)");
        
        this.oldState = oldState;
    },
    onLeave: function(ret) {
        var success = ret.toInt32();
        console.log("  Result: " + (success ? "✓ Success" : "✗ Failed"));
        
        // 如果购买失败，强制成功
        if (!success && this.oldState !== 3 && this.newState === 3) {
            console.log("  [MOD] Forcing success...");
            ret.replace(1);
            
            // 手动设置状态为已购买
            var stateAddr = this.playerData.add(0x3BB8 + 4 * this.itemId);
            Memory.writeS32(stateAddr, 3);
        }
    }
});

console.log("[+] Free Shop Active!");

});
```

---

## 4. 阳光修改

### pvz_sun_finder.js

```javascript
/**
 * 阳光地址查找器
 * 使用方法: 
 *   1. 记录当前阳光值
 *   2. 调用 findSun(当前值)
 *   3. 消耗阳光后再次搜索
 */

Java.perform(function() {

var possibleAddrs = [];

// 扫描内存查找阳光值
function scanForSun(value) {
    console.log("[*] Scanning for sun value: " + value);
    
    possibleAddrs = [];
    
    var ranges = Process.enumerateRangesSync({
        protection: 'rw-',
        coalesce: false
    });
    
    var scanCount = 0;
    var base = Module.findBaseAddress("libpvz.so");
    var baseEnd = base.add(Module.findBaseAddress("libpvz.so").size);
    
    for (var i = 0; i < ranges.length; i++) {
        var range = ranges[i];
        
        // 只搜索libpvz.so的读写段
        if (range.base.compare(base) >= 0 && range.base.compare(baseEnd) < 0) {
            try {
                Memory.scan(range.base, range.size, 
                    value.toString(16).padStart(8, '0').match(/.{2}/g).reverse().join(' '),
                    {
                        onMatch: function(address, size) {
                            possibleAddrs.push(address);
                            scanCount++;
                            if (scanCount <= 10) {  // 只显示前10个
                                console.log("  [" + scanCount + "] " + address);
                            }
                        },
                        onComplete: function() {}
                    }
                );
            } catch(e) {}
        }
    }
    
    console.log("[+] Found " + possibleAddrs.length + " possible addresses");
    return possibleAddrs;
}

// 过滤地址 (再次搜索)
function filterAddresses(newValue) {
    console.log("[*] Filtering with new value: " + newValue);
    
    var validAddrs = [];
    for (var i = 0; i < possibleAddrs.length; i++) {
        try {
            var current = Memory.readS32(possibleAddrs[i]);
            if (current === newValue) {
                validAddrs.push(possibleAddrs[i]);
                console.log("  [✓] " + possibleAddrs[i] + " = " + current);
            }
        } catch(e) {}
    }
    
    possibleAddrs = validAddrs;
    console.log("[+] Filtered to " + validAddrs.length + " addresses");
    return validAddrs;
}

// 设置无限阳光
var sunInterval = null;
function setInfiniteSun(addr, value) {
    if (typeof addr === 'string') {
        addr = ptr(addr);
    }
    
    if (sunInterval) {
        clearInterval(sunInterval);
    }
    
    sunInterval = setInterval(function() {
        try {
            Memory.writeS32(addr, value);
        } catch(e) {
            console.log("[!] Write failed, stopping");
            clearInterval(sunInterval);
        }
    }, 50);
    
    console.log("[+] Infinite sun active @ " + addr + " = " + value);
}

function stopInfiniteSun() {
    if (sunInterval) {
        clearInterval(sunInterval);
        sunInterval = null;
        console.log("[+] Infinite sun stopped");
    }
}

// 导出全局函数
global.findSun = scanForSun;
global.filterSun = filterAddresses;
global.setSun = setInfiniteSun;
global.stopSun = stopInfiniteSun;
global.showSunAddrs = function() {
    console.log("[*] Current candidates (" + possibleAddrs.length + "):");
    possibleAddrs.forEach(function(addr, idx) {
        var value = Memory.readS32(addr);
        console.log("  [" + idx + "] " + addr + " = " + value);
    });
};

console.log("=".repeat(50));
console.log("  PVZ Sun Address Finder");
console.log("=".repeat(50));
console.log("\n用法:");
console.log("  1. findSun(150)      - 当阳光=150时搜索");
console.log("  2. 种植物消耗阳光...");
console.log("  3. filterSun(100)    - 阳光变为100时过滤");
console.log("  4. 重复2-3直到只剩1-2个地址");
console.log("  5. showSunAddrs()    - 显示候选地址");
console.log("  6. setSun(addr, 9990) - 设置无限阳光");
console.log("  7. stopSun()         - 停止修改");
console.log("");

});
```

---

## 5. 调试工具

### pvz_debug.js

```javascript
/**
 * 调试工具集
 * 功能: 内存查看、函数追踪、数据监控
 */

Java.perform(function() {

var base = Module.findBaseAddress("libpvz.so");

// ===== 内存监控 =====
var watchers = {};

function watchMemory(addr, size, name) {
    if (typeof addr === 'string') addr = ptr(addr);
    
    name = name || addr.toString();
    size = size || 4;
    
    var watchId = setInterval(function() {
        try {
            var value = Memory.readS32(addr);
            var old = watchers[name] || 0;
            
            if (value !== old) {
                console.log("[Watch] " + name + ": " + old + " -> " + value);
                watchers[name] = value;
            }
        } catch(e) {}
    }, 100);
    
    console.log("[+] Watching " + name + " @ " + addr);
    return watchId;
}

// ===== 函数追踪 =====
function traceFunction(offset, name, showArgs, showRet, showBacktrace) {
    var funcAddr = base.add(offset);
    
    console.log("[*] Tracing " + name + " @ " + funcAddr);
    
    Interceptor.attach(funcAddr, {
        onEnter: function(args) {
            console.log("\n╔═══ " + name + " ═══");
            
            if (showArgs) {
                for (var i = 0; i < 6; i++) {
                    try {
                        console.log("║ arg[" + i + "] = " + args[i]);
                    } catch(e) {}
                }
            }
            
            if (showBacktrace) {
                console.log("║ Backtrace:");
                Thread.backtrace(this.context)
                    .map(DebugSymbol.fromAddress)
                    .forEach(function(sym) {
                        console.log("║   " + sym);
                    });
            }
            
            this.startTime = Date.now();
        },
        onLeave: function(ret) {
            var elapsed = Date.now() - this.startTime;
            
            if (showRet) {
                console.log("║ Return: " + ret);
            }
            console.log("║ Time: " + elapsed + "ms");
            console.log("╚" + "═".repeat(30));
        }
    });
}

// ===== 数据结构查看器 =====
function viewCoinManager(addr) {
    if (typeof addr === 'string') addr = ptr(addr);
    
    console.log("\n=== Coin Manager @ " + addr + " ===");
    console.log("  Total Coins (int64):  " + Memory.readS64(addr));
    console.log("  Temp Coins (int32):   " + Memory.readS32(addr.add(0x08)));
    console.log("  Data Ptr (ptr):       " + Memory.readPointer(addr.add(0x10)));
    console.log("  User ID (int32):      " + Memory.readS32(addr.add(0x34)));
    console.log("  Zen Coins (int32):    " + Memory.readS32(addr.add(0x3BB8)));
    
    console.log("\n=== Store Items (first 10) ===");
    for (var i = 0; i < 10; i++) {
        var state = Memory.readS32(addr.add(0x3BB8 + 4 * i));
        var stateName = ["Locked", "Available", "Viewed", "Purchased"][state] || "Unknown";
        console.log("  Item[" + i + "] = " + state + " (" + stateName + ")");
    }
}

// ===== 导出全局函数 =====
global.watchMem = watchMemory;
global.trace = traceFunction;
global.viewCoinMgr = viewCoinManager;
global.dumpMem = function(addr, size) {
    console.log(hexdump(ptr(addr), {length: size || 256}));
};

console.log("=".repeat(50));
console.log("  PVZ Debug Tools Loaded");
console.log("=".repeat(50));
console.log("\n可用命令:");
console.log("  watchMem(addr, size, name)  - 监控内存变化");
console.log("  trace(offset, name, ...)    - 追踪函数调用");
console.log("  viewCoinMgr(addr)           - 查看金币管理器");
console.log("  dumpMem(addr, size)         - 十六进制转储");
console.log("");

});
```

---

## 6. 完整作弊包

### pvz_ultimate.js

```javascript
/**
 * PVZ终极作弊脚本 v2.0
 * 集成所有作弊功能
 */

Java.perform(function() {

console.log("\n" + "=".repeat(60));
console.log("  🌻 植物大战僵尸 终极作弊脚本 v2.0 🧟");
console.log("=".repeat(60));

var base = Module.findBaseAddress("libpvz.so");
if (!base) {
    console.log("[!] 错误: libpvz.so未加载!");
    return;
}
console.log("[+] libpvz.so @ " + base);

// ========== 配置区 ==========
var CONFIG = {
    COIN_HACK: true,           // 金币作弊
    COIN_AMOUNT: 999999,       // 每次获得金币数
    
    FREE_SHOP: true,           // 商店免费
    AUTO_UNLOCK_SHOP: true,    // 自动解锁所有商品
    
    BLOCK_TRACKING: true,      // 屏蔽统计上报
    
    DEBUG_MODE: false          // 调试模式 (更多输出)
};

var stats = {
    coinsGained: 0,
    itemsPurchased: 0,
    trackingBlocked: 0
};

// ========== 1. 金币作弊 ==========
if (CONFIG.COIN_HACK) {
    Interceptor.attach(base.add(0x701D78), {
        onEnter: function(args) {
            var amount = args[1].toInt32();
            
            if (amount > 0) {
                // 修改获得金币
                args[1] = ptr(CONFIG.COIN_AMOUNT);
                args[2] = ptr(1);  // 修改总金币
                
                stats.coinsGained += CONFIG.COIN_AMOUNT;
                
                if (CONFIG.DEBUG_MODE) {
                    console.log("[Coin] +" + amount + " -> +" + CONFIG.COIN_AMOUNT);
                }
            }
        }
    });
    console.log("[✓] 金币作弊: ON");
}

// ========== 2. 商店免费 ==========
if (CONFIG.FREE_SHOP) {
    Interceptor.attach(base.add(0x70376C), {
        onEnter: function(args) {
            this.itemId = args[1].toInt32();
            this.cost = args[3].toInt32();
            
            // 免费
            args[3] = ptr(0);
            
            stats.itemsPurchased++;
            
            if (CONFIG.DEBUG_MODE) {
                console.log("[Shop] Item #" + this.itemId + 
                           " Cost: " + this.cost + " -> 0");
            }
        },
        onLeave: function(ret) {
            // 强制成功
            ret.replace(1);
        }
    });
    console.log("[✓] 商店免费: ON");
}

// ========== 3. 自动解锁商品 ==========
if (CONFIG.AUTO_UNLOCK_SHOP) {
    var unlocked = false;
    
    // 通过Hook获取PlayerData地址
    Interceptor.attach(base.add(0x70376C), {
        onEnter: function(args) {
            if (!unlocked) {
                var playerData = ptr(args[0]);
                
                console.log("[*] 解锁所有商店物品...");
                
                var storeBase = playerData.add(0x3BB8);
                for (var i = 0; i < 64; i++) {
                    Memory.writeS32(storeBase.add(i * 4), 3);
                }
                
                unlocked = true;
                console.log("[✓] 64个商品已解锁!");
            }
        }
    });
}

// ========== 4. 屏蔽统计上报 ==========
if (CONFIG.BLOCK_TRACKING) {
    Interceptor.attach(base.add(0x7F6A5C), {
        onEnter: function(args) {
            stats.trackingBlocked++;
            
            if (CONFIG.DEBUG_MODE) {
                var category = Memory.readCString(ptr(args[0]));
                var eventId = args[1].toInt32();
                console.log("[Block] " + category + " #" + eventId);
            }
        },
        onLeave: function(ret) {
            ret.replace(1);  // 伪造成功
        }
    });
    console.log("[✓] 统计上报: BLOCKED");
}

// ========== 状态显示 ==========
setInterval(function() {
    if (stats.coinsGained > 0 || stats.itemsPurchased > 0 || stats.trackingBlocked > 10) {
        console.log("\n📊 作弊统计:");
        console.log("  💰 获得金币: " + stats.coinsGained);
        console.log("  🛒 购买商品: " + stats.itemsPurchased);
        console.log("  🚫 拦截上报: " + stats.trackingBlocked);
    }
}, 30000);  // 每30秒显示一次

// ========== 全局控制函数 ==========
global.PVZCheat = {
    getStats: function() { return stats; },
    
    toggleCoinHack: function() {
        CONFIG.COIN_HACK = !CONFIG.COIN_HACK;
        console.log("[*] Coin Hack: " + (CONFIG.COIN_HACK ? "ON" : "OFF"));
    },
    
    toggleFreeShop: function() {
        CONFIG.FREE_SHOP = !CONFIG.FREE_SHOP;
        console.log("[*] Free Shop: " + (CONFIG.FREE_SHOP ? "ON" : "OFF"));
    },
    
    toggleTracking: function() {
        CONFIG.BLOCK_TRACKING = !CONFIG.BLOCK_TRACKING;
        console.log("[*] Block Tracking: " + (CONFIG.BLOCK_TRACKING ? "ON" : "OFF"));
    },
    
    setCoinAmount: function(amount) {
        CONFIG.COIN_AMOUNT = amount;
        console.log("[*] Coin amount set to: " + amount);
    },
    
    toggleDebug: function() {
        CONFIG.DEBUG_MODE = !CONFIG.DEBUG_MODE;
        console.log("[*] Debug mode: " + (CONFIG.DEBUG_MODE ? "ON" : "OFF"));
    }
};

console.log("\n🎮 作弊功能已激活!");
console.log("\n控制台命令:");
console.log("  PVZCheat.getStats()        - 查看统计");
console.log("  PVZCheat.toggleCoinHack()  - 切换金币作弊");
console.log("  PVZCheat.toggleFreeShop()  - 切换商店免费");
console.log("  PVZCheat.setCoinAmount(N)  - 设置金币数量");
console.log("  PVZCheat.toggleDebug()     - 切换调试模式");
console.log("\n开始游戏吧! 🌻🧟‍♂️");
console.log("=".repeat(60) + "\n");

});
```

### 使用方法

```bash
# 方法1: 启动时注入
frida -U -f com.ea.game.pvzfree_cn -l pvz_ultimate.js --no-pause

# 方法2: 附加到运行中的游戏
frida -U "Plants vs Zombies" -l pvz_ultimate.js

# 方法3: 持久化注入 (使用frida-server)
frida -U -f com.ea.game.pvzfree_cn -l pvz_ultimate.js --no-pause --runtime=v8
```

### 交互式控制

```javascript
// 在Frida控制台中实时调整

// 修改金币获得数量
PVZCheat.setCoinAmount(5000000);

// 暂时关闭金币作弊
PVZCheat.toggleCoinHack();

// 查看统计
PVZCheat.getStats();

// 开启调试模式查看详细信息
PVZCheat.toggleDebug();
```

---

## 7. 高级Hook技巧

### 7.1 条件Hook

```javascript
// 只在特定场景下触发
Interceptor.attach(base.add(0x701D78), {
    onEnter: function(args) {
        var scene = "";
        try {
            scene = Memory.readCString(ptr(args[3]));
        } catch(e) {}
        
        // 只在商店购买时修改
        if (scene === "StoreScreen") {
            args[1] = ptr(0);  // 免费
        }
    }
});
```

### 7.2 延迟Hook

```javascript
// 等待特定条件后才启用Hook
var coinHook = null;

function enableCoinHack() {
    if (!coinHook) {
        coinHook = Interceptor.attach(base.add(0x701D78), {
            // ...
        });
        console.log("[+] Coin hack enabled");
    }
}

function disableCoinHack() {
    if (coinHook) {
        coinHook.detach();
        coinHook = null;
        console.log("[-] Coin hack disabled");
    }
}

// 通过UI事件触发
// 例如: 点击某个按钮后启用
```

### 7.3 参数修改

```javascript
// 智能参数修改
Interceptor.attach(base.add(0x701D78), {
    onEnter: function(args) {
        var amount = args[1].toInt32();
        var flag = args[2].toInt32();
        
        // 根据不同情况修改
        if (amount > 0 && amount < 1000) {
            // 小额金币倍增
            args[1] = ptr(amount * 100);
        } else if (amount > 1000) {
            // 大额金币直接给百万
            args[1] = ptr(1000000);
        }
        
        // 强制修改总金币
        args[2] = ptr(1);
    }
});
```

---

## 8. 性能优化

### 减少日志输出

```javascript
var logThrottle = {};

function throttledLog(key, msg, interval) {
    interval = interval || 1000;
    var now = Date.now();
    
    if (!logThrottle[key] || now - logThrottle[key] > interval) {
        console.log(msg);
        logThrottle[key] = now;
    }
}

// 使用
Interceptor.attach(base.add(0x701D78), {
    onEnter: function(args) {
        throttledLog('coin', "[Coin] Modified", 2000);  // 最多每2秒输出一次
    }
});
```

### 批量Hook

```javascript
var hooks = [
    {offset: 0x701D78, name: "CoinModify"},
    {offset: 0x70376C, name: "BuyItem"},
    {offset: 0x7F6A5C, name: "TrackEvent"}
];

hooks.forEach(function(h) {
    Interceptor.attach(base.add(h.offset), {
        onEnter: function() {
            console.log("[" + h.name + "] Called");
        }
    });
});
```

---

## 9. 故障排查

### 常见问题

**Q: Hook不生效?**
```
A: 检查:
   1. libpvz.so是否已加载 (Module.findBaseAddress)
   2. 地址偏移是否正确 (版本差异)
   3. Frida版本是否匹配
   4. 是否有多个进程
```

**Q: 游戏崩溃?**
```
A: 可能原因:
   1. 修改了错误的内存
   2. 参数类型不匹配
   3. 返回值修改错误
   4. 多线程竞争
   
解决:
   - 逐个启用功能测试
   - 检查try-catch包装
   - 查看崩溃日志
```

**Q: 密钥提取失败?**
```
A: 尝试:
   1. Hook更早的初始化函数
   2. 搜索内存中的密钥特征
   3. 分析libcrypto.so的调用
   4. 查看静态字符串资源
```

---

## 10. 脚本模板

### 快速Hook模板

```javascript
// quick_hook.js

Java.perform(function() {

var base = Module.findBaseAddress("libpvz.so");

// 替换offset和处理逻辑
Interceptor.attach(base.add(0xOFFSET), {
    onEnter: function(args) {
        // 读取参数
        var param1 = args[0];
        var param2 = args[1].toInt32();
        
        console.log("[Hook] param1=" + param1 + ", param2=" + param2);
        
        // 修改参数
        // args[1] = ptr(NEW_VALUE);
    },
    onLeave: function(ret) {
        // 修改返回值
        // ret.replace(NEW_RETURN);
        
        console.log("[Hook] return=" + ret);
    }
});

console.log("[+] Hook active");

});
```

---

## 📚 参考资源

### Frida官方文档
- [JavaScript API](https://frida.re/docs/javascript-api/)
- [内存操作](https://frida.re/docs/javascript-api/#memory)
- [Interceptor](https://frida.re/docs/javascript-api/#interceptor)

### 相关工具
- [frida-tools](https://github.com/frida/frida-tools)
- [objection](https://github.com/sensepost/objection) - Frida辅助工具
- [r2frida](https://github.com/nowsecure/r2frida) - Radare2集成

---

*脚本版本: 2.0*  
*适用游戏版本: pvzhhb_5947-1*  
*libpvz.so架构: arm64-v8a*  
*测试日期: 2025-10-20*  
*状态: 已验证部分功能，阳光Hook待完善*

