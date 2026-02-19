# Capstone 库配置指南

## 方案一：自动配置（推荐）

运行提供的 PowerShell 脚本：

```powershell
.\setup-capstone.ps1
```

## 方案二：手动下载配置

由于 Capstone 官方不直接提供预编译的 Android native 库，您有以下几种选择：

### 选项 1：从可信的第三方项目获取

一些使用 Capstone 的开源 Android 项目会包含预编译的库：

1. **Frida 项目**
   - 访问: https://github.com/frida/frida
   - Frida 内部使用了 Capstone，可能包含预编译库

2. **Cutter/Rizin 项目**
   - 访问: https://github.com/rizinorg/cutter
   - 这些逆向工程工具使用 Capstone

### 选项 2：使用预编译的库文件（推荐）

您可以从以下链接下载预编译的 Capstone 5.0 Android 库：

1. 访问 https://github.com/capstone-engine/capstone
2. 查找 releases 或 prebuilt 分支
3. 或者使用以下直接链接：

**临时解决方案：使用 Capstone 4.0.2**

```powershell
# 下载 Capstone 4.0.2 源码
Invoke-WebRequest -Uri "https://github.com/capstone-engine/capstone/archive/refs/tags/4.0.2.tar.gz" -OutFile "capstone.tar.gz"
```

### 选项 3：从源码编译（适合开发者）

如果您配置了 Android NDK，可以从源码编译：

```bash
# 克隆 Capstone 仓库
git clone https://github.com/capstone-engine/capstone.git
cd capstone

# 编译 ARM64
mkdir build-arm64 && cd build-arm64
cmake -DCMAKE_SYSTEM_NAME=Android \
      -DCMAKE_ANDROID_ARCH_ABI=arm64-v8a \
      -DCMAKE_ANDROID_NDK=$ANDROID_NDK_HOME \
      -DCMAKE_BUILD_TYPE=Release \
      -DBUILD_SHARED_LIBS=ON \
      ..
make

# 编译 ARMv7
cd ..
mkdir build-armv7 && cd build-armv7
cmake -DCMAKE_SYSTEM_NAME=Android \
      -DCMAKE_ANDROID_ARCH_ABI=armeabi-v7a \
      -DCMAKE_ANDROID_NDK=$ANDROID_NDK_HOME \
      -DCMAKE_BUILD_TYPE=Release \
      -DBUILD_SHARED_LIBS=ON \
      ..
make
```

### 选项 4：使用 Docker 编译

```dockerfile
FROM ubuntu:20.04
RUN apt-get update && apt-get install -y cmake git build-essential wget unzip
RUN wget https://dl.google.com/android/repository/android-ndk-r25c-linux.zip
RUN unzip android-ndk-r25c-linux.zip
ENV ANDROID_NDK_HOME=/android-ndk-r25c
# ... (编译步骤)
```

## 目标文件位置

确保将编译或下载的库文件放置到以下位置：

```
app/src/main/jniLibs/
├── arm64-v8a/
│   └── libcapstone.so
└── armeabi-v7a/
    └── libcapstone.so
```

## 验证配置

1. 清理并重新构建项目：
```powershell
.\gradlew.bat clean
.\gradlew.bat assembleDebug
```

2. 检查 APK 中是否包含库：
```powershell
# 解压 APK 并查看
Expand-Archive app\build\outputs\apk\debug\app-debug.apk -DestinationPath temp_apk
Get-ChildItem temp_apk\lib -Recurse -Filter "libcapstone.so"
```

3. 运行应用，在 logcat 中查看库加载日志

## 当前项目依赖问题

注意：`build.gradle.kts` 中的以下依赖可能不可用：
```kotlin
implementation("io.github.kaeptmblaubaer1000:capstone:5.0.1-android")
```

如果您找不到可用的预编译库，建议：
1. 移除上述依赖
2. 仅使用手动放置的 native 库
3. 或者考虑使用 Capstone 的 Java 绑定（如果有其他可用的版本）

## 需要帮助？

如果您在配置过程中遇到问题，请：
1. 检查 Android NDK 是否正确安装
2. 确认 CMake 版本兼容性
3. 查看 Capstone 官方文档: https://www.capstone-engine.org/


