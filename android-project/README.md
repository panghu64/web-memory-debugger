# Web内存调试器 - Android项目

这是Web内存调试器的Android应用部分。

## 📱 项目结构

```
android-project/
├── android/                 # 源码目录
│   ├── app/                 # 主应用模块
│   │   ├── src/
│   │   │   ├── main/
│   │   │   │   ├── java/        # Java服务层
│   │   │   │   ├── cpp/         # Native C++代码
│   │   │   │   ├── assets/web/  # Web前端
│   │   │   │   └── jniLibs/     # Native库
│   │   │   └── AndroidManifest.xml
│   │   └── build.gradle.kts
│   └── myapplication/       # 子模块
│
├── gradle/                  # Gradle Wrapper
├── build.gradle.kts         # 项目级构建配置
├── settings.gradle.kts      # 项目设置
├── gradlew                  # Gradle包装器（Linux/Mac）
├── gradlew.bat              # Gradle包装器（Windows）
└── gradle.properties        # Gradle属性
```

## 🚀 快速开始

### 前置要求
- JDK 11+
- Android SDK
- Android NDK 25.x+
- Root权限的Android设备（Android 10+）

### 构建步骤

#### Windows
```bash
# 在android-project目录下执行
.\gradlew.bat assembleDebug
```

#### Linux/Mac
```bash
# 在android-project目录下执行
./gradlew assembleDebug
```

### 构建产物

编译成功后，APK文件位于：
```
android-project/android/app/build/outputs/apk/debug/app-debug.apk
```

## 📦 安装和运行

```bash
# 安装APK
adb install -r android/app/build/outputs/apk/debug/app-debug.apk

# 配置端口转发
adb forward tcp:8080 tcp:8080

# 启动应用
adb shell am start -n com.example.myapplication/.MainActivity

# 浏览器访问
# http://localhost:8080
```

## 🔧 开发

### 在Android Studio中打开
1. 打开Android Studio
2. File -> Open
3. 选择 `android-project` 文件夹
4. 等待Gradle同步完成

### 模块说明

#### app模块（主应用）
- **Java服务层**: HTTP服务器、内存操作、反汇编等
- **Native层**: C++ memtool、Capstone集成
- **Web前端**: Vue 3界面

#### myapplication模块（子项目）
- 测试和辅助功能

## 📚 相关文档

详细文档请查看项目根目录：
- `../docs/` - 完整文档
- `../完整构建指南.md` - 详细构建指南
- `../【项目完成】一页纸总结.md` - 项目概览

## ⚠️ 注意事项

1. **Root权限**: 应用需要Root权限才能进行内存操作
2. **Capstone库**: 反汇编功能需要libcapstone.so（已包含在jniLibs）
3. **SELinux**: 使用/proc/pid/mem方式绕过SELinux限制

## 🛠️ 常见问题

### 构建失败
```bash
# 清理构建
.\gradlew.bat clean

# 重新构建
.\gradlew.bat assembleDebug
```

### Gradle同步失败
检查：
- 网络连接（需要下载依赖）
- Gradle版本是否兼容
- NDK是否正确安装

### 找不到NDK
在 `local.properties` 中配置：
```properties
ndk.dir=C\:\\Android\\sdk\\ndk\\25.x.x
sdk.dir=C\:\\Android\\sdk
```

## 📝 技术栈

- **语言**: Java, C++, JavaScript
- **框架**: Android SDK, NDK
- **HTTP服务器**: NanoHTTPD
- **反汇编**: Capstone
- **前端**: Vue 3
- **构建工具**: Gradle

---

**项目状态**: 🟢 生产就绪  
**版本**: 1.0.0  
**最后更新**: 2025-12-07
