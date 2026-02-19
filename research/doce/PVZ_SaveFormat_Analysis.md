# 植物大战僵尸 - 存档格式详细分析

## 📌 概述

详细分析游戏存档文件的格式、加密方式和修改方法。

---

## 🗂️ 存档文件结构

### 文件类型一览

| 文件路径 | 格式 | 用途 | 函数引用 |
|---------|------|------|---------|
| `userdata/user%d.dat` | 二进制 | 用户主存档 | sub_702218 |
| `userdata/user%d_json.dat` | JSON | 用户存档(优先) | sub_702218 |
| `userdata/user%d_backup.dat` | 二进制 | 备份存档 | sub_701968 |
| `userdata/game%d_%d.dat` | 二进制 | 关卡进度 | sub_6C1B30 |
| `userdata/coins200k%d.dat` | **纯文本** | 金币奖励 | sub_701A48 |
| `userdata/users.dat` | 二进制 | 用户列表 | - |
| `userdata/users_backup.dat` | 二进制 | 用户列表备份 | - |

**参数说明**:
- `%d` (第一个) = 用户ID (从0开始)
- `%d` (第二个) = 关卡ID/槽位ID

---

## 🔐 加密机制

### 加密算法分析

**从 `sub_702218` 第73行分析**:
```c
sub_11BEF6C(encryptedData, mode=3, padding=3, zeroPad=1, 0);
```

**加密参数**:
- **算法**: AES-128
- **模式**: 3 (推测为 CBC 或 ECB)
- **填充**: 3 (推测为 PKCS#7)
- **零填充**: 启用
- **密钥来源**: 需要进一步逆向 `sub_11BEF6C`

### 解密流程

**JSON存档解密**:
```python
import json
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

def decrypt_pvz_save(encrypted_data, key, iv=None):
    """
    解密PVZ存档
    
    Args:
        encrypted_data: 加密的存档数据
        key: AES密钥 (16字节)
        iv: 初始化向量 (16字节, CBC模式需要)
    
    Returns:
        解密后的JSON字符串
    """
    # 创建AES解密器 (mode=3可能对应CBC)
    if iv:
        cipher = AES.new(key, AES.MODE_CBC, iv)
    else:
        cipher = AES.new(key, AES.MODE_ECB)
    
    # 解密
    decrypted = cipher.decrypt(encrypted_data)
    
    # 移除PKCS7填充
    try:
        decrypted = unpad(decrypted, AES.block_size)
    except:
        # 如果失败，尝试手动去除填充
        padding_len = decrypted[-1]
        if padding_len < 16:
            decrypted = decrypted[:-padding_len]
    
    return decrypted.decode('utf-8')

# 使用示例 (密钥需要从游戏中提取)
# key = b'????????????????'  # 16字节密钥
# with open('user0_json.dat', 'rb') as f:
#     encrypted = f.read()
# json_data = decrypt_pvz_save(encrypted, key)
# save_data = json.loads(json_data)
```

---

## 📊 存档数据结构

### JSON格式字段 (推测)

基于字符串分析，JSON存档可能包含:

```json
{
  "version": "1.0",
  "userId": 0,
  
  // === 金币相关 ===
  "CoinBalance": 50000,
  "coins": 50000,
  "coinsCollectedZen": 0,
  "coinsActiveLeaveGarden": 0,
  "coinsInAppPurchase": 0,
  
  // === 解锁状态 ===
  "hasUnlockedMinigames": false,
  "hasUnlockedPuzzleMode": false,
  "hasUnlockedSurvivalMode": false,
  "hasUnlockedMoreWays": false,
  
  // === 植物相关 ===
  "plantTypesUsed": [0, 1, 2, 3, 4],
  "numPottedPlants": 0,
  "pottedPlants": [],
  "ppPlantAge": [],
  "ppPlantNeed": [],
  
  // === 商店购买 ===
  "storePurchases": [0, 0, 0, ...],  // 64个商品状态
  
  // === 游戏进度 ===
  "adventure": {
    "level": 10,
    "completed": false,
    "currentStage": "1-1"
  },
  
  // === 成就 ===
  "achievements": [
    "ACHIEVEMENT_SUNNY_DAYS",
    "ACHIEVEMENT_SUN_DONT_SHINE"
  ],
  
  // === 统计数据 ===
  "totalPlayTime": 3600,
  "gamesPlayed": 50,
  "zombiesKilled": 1000,
  "plantsPlanted": 500,
  
  // === 设置 ===
  "needsGrayedPlantWarning": false,
  
  // === 其他 ===
  "anim_waterplants": true
}
```

### 二进制格式 (推测)

基于 `sub_6F17FC` (存档写入函数):

```c
struct UserSaveData {
    // === 头部 (16字节) ===
    uint32  magic;              // 魔数标识 (0x50565A00?)
    uint16  version;            // 版本号
    uint16  flags;              // 标志位
    uint32  dataSize;           // 数据大小
    uint32  checksum;           // 校验和 (CRC32?)
    
    // === 玩家数据 (变长) ===
    int64   totalCoins;         // +0x10: 总金币
    int32   tempCoins;          // +0x18: 临时金币
    int32   userId;             // +0x1C: 用户ID
    
    // === 解锁标志 (4字节) ===
    byte    unlockedMinigames;  // +0x20
    byte    unlockedPuzzle;
    byte    unlockedSurvival;
    byte    unlockedMoreWays;
    
    // === 关卡进度 (动态) ===
    int32   adventureLevel;     // +0x24: 冒险模式进度
    int32   survivalFlags[11];  // +0x28: 生存模式旗帜
    
    // === 商店购买 (256字节) ===
    int32   storeItems[64];     // +0x54: 商品状态
    
    // === 植物数据 ===
    int32   plantCount;
    struct {
        int32 type;
        int32 age;
        int32 needWater;
        // ... 更多字段
    } plants[plantCount];
    
    // === 成就数据 ===
    int32   achievementCount;
    int32   achievements[achievementCount];
    
    // === 统计数据 ===
    uint64  totalPlayTime;
    uint32  gamesPlayed;
    uint32  zombiesKilled;
    
    // === 尾部校验 ===
    uint32  crc32;              // 整体校验和
};
```

---

## 🛠️ 存档修改实战

### ⭐ 方法1: 修改金币存档 (最简单!)

**目标文件**: `userdata/coins200k%d.dat`

**关键发现**:
```c
// sub_701A48 @ 0x701B38-0x701B58
char* defaultCoins = "20000";  // 默认金币值是纯文本字符串!
size_t len = strlen("20000");  // 长度5
sub_9ADD54(fileSystem, filePath, defaultCoins, len);
```

**修改步骤** (超级简单):
```bash
# 1. 导出存档
adb pull /data/data/com.ea.game.pvzfree_cn/files/userdata/coins200k0.dat

# 2. 查看内容 (直接cat就行!)
cat coins200k0.dat
# 输出: 20000

# 3. 修改金币 (直接echo写入!)
echo "999999999" > coins200k0.dat

# 4. 导入回去
adb push coins200k0.dat /data/data/com.ea.game.pvzfree_cn/files/userdata/

# 5. 重启游戏，进入关卡即可获得奖励金币
```

**效果**: 游戏会调用 `sub_701A48` 读取这个文件，并添加金币到账户！

**Windows PowerShell版本**:
```powershell
# 导出
adb pull /data/data/com.ea.game.pvzfree_cn/files/userdata/coins200k0.dat coins200k0.dat

# 修改
Set-Content -Path "coins200k0.dat" -Value "999999999" -NoNewline

# 导入
adb push coins200k0.dat /data/data/com.ea.game.pvzfree_cn/files/userdata/coins200k0.dat
```

### 方法2: 修改JSON存档

**前提**: 需要找到AES密钥

**完整Python脚本**:
```python
#!/usr/bin/env python3
# pvz_save_editor.py

import json
import os
import shutil
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

class PVZSaveEditor:
    def __init__(self, save_dir="./userdata", key=None, iv=None):
        self.save_dir = save_dir
        self.key = key or b'DEFAULT_KEY_HERE'  # 替换为真实密钥
        self.iv = iv or b'\x00' * 16
    
    def backup_save(self, user_id):
        """备份所有存档"""
        files = [
            f"user{user_id}_json.dat",
            f"user{user_id}.dat",
            f"coins200k{user_id}.dat"
        ]
        
        backup_dir = f"{self.save_dir}/backup_{user_id}"
        os.makedirs(backup_dir, exist_ok=True)
        
        for filename in files:
            src = os.path.join(self.save_dir, filename)
            if os.path.exists(src):
                dst = os.path.join(backup_dir, filename)
                shutil.copy(src, dst)
                print(f"✓ 备份: {filename}")
    
    def decrypt_json_save(self, user_id):
        """解密JSON存档"""
        file_path = f"{self.save_dir}/user{user_id}_json.dat"
        
        with open(file_path, 'rb') as f:
            encrypted_data = f.read()
        
        # 尝试CBC模式
        try:
            cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
            decrypted = cipher.decrypt(encrypted_data)
            decrypted = unpad(decrypted, AES.block_size)
            return json.loads(decrypted.decode('utf-8'))
        except:
            pass
        
        # 尝试ECB模式
        try:
            cipher = AES.new(self.key, AES.MODE_ECB)
            decrypted = cipher.decrypt(encrypted_data)
            decrypted = unpad(decrypted, AES.block_size)
            return json.loads(decrypted.decode('utf-8'))
        except Exception as e:
            print(f"✗ 解密失败: {e}")
            return None
    
    def encrypt_json_save(self, user_id, data):
        """加密并保存JSON存档"""
        file_path = f"{self.save_dir}/user{user_id}_json.dat"
        
        json_str = json.dumps(data, indent=2, ensure_ascii=False)
        json_bytes = json_str.encode('utf-8')
        
        # 填充
        padded = pad(json_bytes, AES.block_size)
        
        # 加密 (默认使用CBC)
        cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
        encrypted = cipher.encrypt(padded)
        
        with open(file_path, 'wb') as f:
            f.write(encrypted)
        
        print(f"✓ 已保存: {file_path}")
    
    def modify_coins_simple(self, user_id, amount):
        """修改简单的金币存档 (纯文本)"""
        coin_file = f"{self.save_dir}/coins200k{user_id}.dat"
        
        with open(coin_file, 'w') as f:
            f.write(str(amount))
        
        print(f"✓ 金币文件已修改为: {amount}")
    
    def unlock_all_content(self, user_id):
        """解锁所有内容"""
        save_data = self.decrypt_json_save(user_id)
        
        if not save_data:
            print("✗ 无法读取存档 (密钥错误?)")
            return
        
        # 修改金币
        save_data['CoinBalance'] = 999999999
        save_data['coins'] = 999999999
        
        # 解锁所有模式
        save_data['hasUnlockedMinigames'] = True
        save_data['hasUnlockedPuzzleMode'] = True
        save_data['hasUnlockedSurvivalMode'] = True
        save_data['hasUnlockedMoreWays'] = True
        
        # 解锁所有商品
        if 'storePurchases' in save_data:
            save_data['storePurchases'] = [3] * 64
        
        # 保存
        self.encrypt_json_save(user_id, save_data)
        print("✓ 全部解锁完成!")
    
    def max_all_plants(self, user_id):
        """所有植物升至最大等级"""
        save_data = self.decrypt_json_save(user_id)
        
        if not save_data:
            return
        
        # 修改植物等级
        if 'pottedPlants' in save_data:
            for plant in save_data['pottedPlants']:
                plant['age'] = 999  # 最大年龄
                plant['need'] = 0   # 不需要照料
        
        self.encrypt_json_save(user_id, save_data)
        print("✓ 植物已升级!")

# ===== 使用示例 =====
if __name__ == "__main__":
    import sys
    
    # 注意: 需要先提取真实的AES密钥!
    editor = PVZSaveEditor(
        save_dir="./userdata",
        key=b'REPLACE_WITH_KEY',  # 替换!
        iv=b'\x00' * 16
    )
    
    user_id = 0
    
    if len(sys.argv) < 2:
        print("用法:")
        print("  python pvz_save_editor.py backup    - 备份存档")
        print("  python pvz_save_editor.py coins <数量> - 修改金币")
        print("  python pvz_save_editor.py unlock    - 解锁所有")
        sys.exit(0)
    
    command = sys.argv[1]
    
    if command == "backup":
        editor.backup_save(user_id)
    
    elif command == "coins":
        amount = int(sys.argv[2]) if len(sys.argv) > 2 else 999999999
        # 修改纯文本金币文件 (无需密钥!)
        editor.modify_coins_simple(user_id, amount)
    
    elif command == "unlock":
        editor.unlock_all_content(user_id)
    
    else:
        print("未知命令")
```

---

## 🔑 密钥提取方法

### 方法1: Frida动态提取

```javascript
// extract_aes_key.js

Java.perform(function() {

var base = Module.findBaseAddress("libpvz.so");

// Hook AES相关函数
var aesDecryptFunc = base.add(0x11BEF6C);

console.log("[*] Hooking AES decrypt @ " + aesDecryptFunc);

Interceptor.attach(aesDecryptFunc, {
    onEnter: function(args) {
        console.log("\n[AES] Decrypt called!");
        console.log("  arg0 (data): " + args[0]);
        console.log("  arg1 (mode): " + args[1]);
        console.log("  arg2 (padding): " + args[2]);
        console.log("  arg3 (zeroPad): " + args[3]);
        
        // 保存上下文以便在onLeave中使用
        this.dataPtr = args[0];
    },
    onLeave: function(ret) {
        console.log("[AES] Return: " + ret);
    }
});

// 可能还需要Hook libcrypto.so中的函数
var libcrypto = Process.findModuleByName("libcrypto.so");
if (libcrypto) {
    // Hook AES_set_decrypt_key
    var aes_set_key = Module.findExportByName("libcrypto.so", "AES_set_decrypt_key");
    if (aes_set_key) {
        console.log("[*] Hooking AES_set_decrypt_key");
        Interceptor.attach(aes_set_key, {
            onEnter: function(args) {
                var userKey = args[0];
                var bits = args[1].toInt32();
                
                console.log("\n[!] AES KEY FOUND!");
                console.log("  Key length: " + bits + " bits");
                console.log("  Key bytes:");
                console.log(hexdump(userKey, {length: bits/8, ansi: true}));
                
                // 保存密钥
                var keyBytes = Memory.readByteArray(userKey, bits/8);
                var keyHex = Array.from(new Uint8Array(keyBytes))
                    .map(b => b.toString(16).padStart(2, '0'))
                    .join('');
                console.log("  Key (hex): " + keyHex);
            }
        });
    }
}

console.log("[+] AES Key Extractor Ready!");
console.log("[*] Load a save file to trigger key extraction");

});
```

**运行**:
```bash
frida -U -f com.ea.game.pvzfree_cn -l extract_aes_key.js --no-pause
```

### 方法2: 静态分析IDA

**步骤**:
1. 在IDA中定位 `sub_11BEF6C`
2. 反编译查看函数实现
3. 追踪密钥来源:
   - 全局变量
   - 字符串常量
   - 派生算法
4. 提取密钥字节

**可能的密钥位置**:
```c
// 全局变量
.data:XXXXXXXX  aes_key  DCB  0x12, 0x34, 0x56, ...  ; 16字节

// 字符串派生
const char* seed = "PlAnTsVsZoMbIeS";
derive_key(seed, aes_key);

// 硬编码
unsigned char key[16] = {
    0x??, 0x??, 0x??, 0x??,
    0x??, 0x??, 0x??, 0x??,
    0x??, 0x??, 0x??, 0x??,
    0x??, 0x??, 0x??, 0x??
};
```

### 方法3: 暴力尝试

**如果密钥很简单**:
```python
import itertools
import json
from Crypto.Cipher import AES

def try_decrypt(encrypted, key_candidate):
    try:
        cipher = AES.new(key_candidate, AES.MODE_ECB)
        decrypted = cipher.decrypt(encrypted[:16])  # 只解密前16字节测试
        # 检查是否为有效JSON开头
        if decrypted.startswith(b'{') or decrypted.startswith(b'{"'):
            return True
    except:
        pass
    return False

# 尝试常见密钥模式
common_patterns = [
    b'PLANTVSZOMBIES!',
    b'EA_GAMES_PVZ123',
    b'pvz2013password',
    b'0123456789ABCDEF',
]

with open('user0_json.dat', 'rb') as f:
    encrypted = f.read()

for pattern in common_patterns:
    if len(pattern) == 16 and try_decrypt(encrypted, pattern):
        print(f"可能的密钥: {pattern}")
```

---

## 📱 Android存档操作

### 完整导出/导入流程

**导出脚本** (Windows):
```powershell
# pvz_export_saves.ps1

$PACKAGE = "com.ea.game.pvzfree_cn"
$LOCAL_DIR = ".\pvz_saves_backup"
$REMOTE_DIR = "/data/data/$PACKAGE/files/userdata"

# 创建备份目录
New-Item -ItemType Directory -Force -Path $LOCAL_DIR | Out-Null

# 导出所有存档
Write-Host "📦 导出存档..." -ForegroundColor Cyan
adb pull "$REMOTE_DIR/" "$LOCAL_DIR/"

# 列出文件
Write-Host "`n📄 导出的文件:" -ForegroundColor Green
Get-ChildItem $LOCAL_DIR | Format-Table Name, Length

Write-Host "`n✓ 导出完成!" -ForegroundColor Green
```

**导入脚本**:
```powershell
# pvz_import_saves.ps1

$PACKAGE = "com.ea.game.pvzfree_cn"
$LOCAL_DIR = ".\pvz_saves_backup"
$REMOTE_DIR = "/data/data/$PACKAGE/files/userdata"

# 停止游戏
Write-Host "🛑 停止游戏..." -ForegroundColor Yellow
adb shell am force-stop $PACKAGE
Start-Sleep -Seconds 2

# 导入存档
Write-Host "📥 导入存档..." -ForegroundColor Cyan
Get-ChildItem $LOCAL_DIR | ForEach-Object {
    $remotePath = "$REMOTE_DIR/$($_.Name)"
    adb push $_.FullName $remotePath
    Write-Host "  ✓ $($_.Name)" -ForegroundColor Green
}

# 设置权限
adb shell chmod 666 "$REMOTE_DIR/*"

Write-Host "`n✓ 导入完成!" -ForegroundColor Green
Write-Host "启动游戏查看效果" -ForegroundColor Cyan
```

### 无Root方法

**使用adb backup/restore**:
```bash
# 完整备份
adb backup -f pvz_full_backup.ab -noapk com.ea.game.pvzfree_cn

# 解包 (需要Android Backup Extractor)
java -jar abe.jar unpack pvz_full_backup.ab pvz_full_backup.tar

# 提取tar
tar -xvf pvz_full_backup.tar

# 修改存档 (在 apps/com.ea.game.pvzfree_cn/f/ 下)
# ...

# 重新打包
tar -cvf pvz_full_backup_new.tar apps/
java -jar abe.jar pack pvz_full_backup_new.tar pvz_full_backup_new.ab

# 恢复
adb restore pvz_full_backup_new.ab
```

---

## 🔬 深入分析

### 存档读取流程图

```
游戏启动
    │
    ├─> sub_702218 (加载用户数据)
    │     │
    │     ├─> 检查 user%d_json.dat
    │     │     ├─> 存在 → 解密JSON → 解析
    │     │     └─> 不存在 ↓
    │     │
    │     ├─> 检查 user%d.dat
    │     │     ├─> 存在 → 解密二进制 → 解析
    │     │     └─> 不存在 → 使用默认值
    │     │
    │     └─> 应用到游戏内存
    │
    ├─> sub_701A48 (加载金币奖励)
    │     │
    │     └─> 读取 coins200k%d.dat (纯文本!)
    │           └─> 添加金币到账户
    │
    └─> sub_6C1B30 (加载关卡进度)
          │
          └─> 读取 game%d_%d.dat
                └─> 恢复关卡状态
```

### 存档保存流程

```
游戏退出/关卡结束
    │
    ├─> sub_6F26CC (保存用户数据)
    │     │
    │     ├─> 序列化内存数据
    │     ├─> 转为JSON
    │     ├─> AES加密
    │     └─> 写入 user%d_json.dat
    │
    ├─> sub_6F9044 (保存游戏进度)
    │     │
    │     └─> 更新解锁标志
    │
    └─> 创建备份
          └─> user%d_backup.dat
```

---

## 🧪 验证与测试

### 测试用例1: 金币文件修改

```bash
# 测试脚本
echo "999999" > coins200k0.dat
adb push coins200k0.dat /data/data/com.ea.game.pvzfree_cn/files/userdata/

# 启动游戏验证
adb shell am start -n com.ea.game.pvzfree_cn/.MainActivity

# 预期: 进入关卡后金币增加999999
```

### 测试用例2: JSON存档完整性

```python
# test_save_integrity.py

def test_decrypt_encrypt(editor, user_id):
    """测试解密-加密往返"""
    
    # 1. 解密
    original = editor.decrypt_json_save(user_id)
    if not original:
        print("✗ 解密失败")
        return False
    
    # 2. 重新加密
    editor.encrypt_json_save(user_id, original)
    
    # 3. 再次解密
    restored = editor.decrypt_json_save(user_id)
    
    # 4. 比较
    if json.dumps(original, sort_keys=True) == json.dumps(restored, sort_keys=True):
        print("✓ 完整性测试通过")
        return True
    else:
        print("✗ 数据不一致")
        return False
```

---

## 📋 已知字段完整列表

### 字符串资源引用

从代码中提取的存档字段名:

```python
SAVE_FIELDS = {
    # 金币
    "CoinBalance": "int",
    "coins": "int",
    "coinsCollectedZen": "int",
    "coinsActiveLeaveGarden": "int",
    "coinsInAppPurchase": "int",
    
    # 解锁
    "hasUnlockedMinigames": "bool",
    "hasUnlockedPuzzleMode": "bool",
    "hasUnlockedSurvivalMode": "bool",
    "hasUnlockedMoreWays": "bool",
    
    # 植物
    "plantTypesUsed": "int[]",
    "numPottedPlants": "int",
    "pottedPlants": "object[]",
    "ppPlantAge": "int[]",
    "ppPlantNeed": "int[]",
    
    # 其他
    "needsGrayedPlantWarning": "bool",
    "anim_waterplants": "bool",
}
```

---

## ⚠️ 注意事项

### 修改风险

1. **金币奖励文件最安全**: `coins200k%d.dat` 是纯文本，修改零风险
2. **JSON存档需要密钥**: 错误的密钥会损坏存档
3. **二进制存档最危险**: 格式未知，可能有校验和
4. **版本兼容性**: 不同游戏版本存档可能不兼容

### 最佳实践

✅ **推荐做法**:
- 始终先备份原始存档
- 从最简单的修改开始 (金币奖励文件)
- 逐步测试，确认可行后再深入
- 保留多个备份版本

❌ **避免做法**:
- 直接修改二进制存档
- 使用过大的数值 (可能溢出)
- 跳过备份直接修改
- 修改未知字段

---

## 🎓 进阶技巧

### 存档版本转换

**二进制转JSON** (需要逆向序列化函数):
```python
def convert_binary_to_json(binary_path, json_path, key):
    # 读取二进制存档
    with open(binary_path, 'rb') as f:
        binary_data = f.read()
    
    # 调用游戏的序列化函数(通过Frida)
    # 或手动解析二进制格式
    
    # 生成JSON
    # ...
    
    # 加密保存
    # ...
```

### 批量修改多用户

```python
def modify_all_users(save_dir, modification_func):
    """对所有用户应用相同修改"""
    for user_id in range(10):  # 最多10个用户
        json_file = f"{save_dir}/user{user_id}_json.dat"
        if os.path.exists(json_file):
            print(f"\n处理用户 {user_id}...")
            modification_func(user_id)
```

---

*文档版本: 2.0*  
*最后更新: 2025-10-20*  
*状态: 80% 完成 - AES密钥待提取*

