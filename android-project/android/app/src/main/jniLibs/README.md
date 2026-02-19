# Native库说明

## ✅ libcapstone.so 配置状态：已完成

本项目需要 Capstone 反汇编引擎的 Native 库。

**当前状态**: 已从 Capstone 5.0.1 源码编译并配置完成（2025-10-20）

---

## libcapstone.so 配置说明

### 下载地址
https://github.com/capstone-engine/capstone/releases/

### 所需文件
1. `arm64-v8a/libcapstone.so` - ARM64架构
2. `armeabi-v7a/libcapstone.so` - ARMv7架构

### 放置位置
```
app/src/main/jniLibs/
├── arm64-v8a/
│   └── libcapstone.so
└── armeabi-v7a/
    └── libcapstone.so
```

### 编译选项（可选）
如果从源码编译，请使用以下配置：
```bash
# ARM64
./make.sh
cmake -DCMAKE_SYSTEM_NAME=Android \
      -DCMAKE_ANDROID_ARCH_ABI=arm64-v8a \
      -DCMAKE_ANDROID_NDK=$ANDROID_NDK_HOME \
      -DCMAKE_BUILD_TYPE=Release \
      -DBUILD_SHARED_LIBS=ON \
      .
make

# ARMv7
cmake -DCMAKE_SYSTEM_NAME=Android \
      -DCMAKE_ANDROID_ARCH_ABI=armeabi-v7a \
      -DCMAKE_ANDROID_NDK=$ANDROID_NDK_HOME \
      -DCMAKE_BUILD_TYPE=Release \
      -DBUILD_SHARED_LIBS=ON \
      .
make
```

### 验证
编译项目后，在logcat中应该能看到Capstone成功加载的日志。

---

## 📋 当前配置详情

### 已配置的库文件
- ✅ `arm64-v8a/libcapstone.so` (16.68 MB) - ARM64架构
- ✅ `armeabi-v7a/libcapstone.so` (12.85 MB) - ARMv7架构

### 编译信息
- **版本**: Capstone 5.0.1
- **编译工具**: Android NDK 27.0.12077973 + CMake 3.22.1
- **编译位置**: D:\Environment\capstone
- **配置日期**: 2025-10-20

### 构建项目
运行以下命令构建包含 Capstone 库的 APK：
```powershell
.\gradlew.bat assembleDebug
```

详细配置信息请参考项目根目录的 `CAPSTONE_配置完成.md` 文件。

