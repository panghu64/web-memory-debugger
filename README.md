# Web内存调试器

Android游戏内存分析和修改工具，支持Web远程调试。

## 🎯 项目概述

这是一个运行在Android设备上的Web内存调试工具，可通过浏览器远程操作设备内存，支持：
- ✅ 游戏内存读写修改
- ✅ ARM64代码反汇编（Capstone）
- ✅ 基址和偏移分析
- ✅ RESTful API接口
- ✅ 前台服务后台运行
- ✅ 绕过SELinux限制（CE风格）

**测试状态**: ✅ 100%通过（小米13真机验证）  
**完成时间**: 2025-10-20  
**项目状态**: 🟢 生产就绪

---

## 🚀 快速开始

### 5分钟上手

1. **阅读项目概述**  
   查看：[【项目完成】一页纸总结.md](【项目完成】一页纸总结.md)

2. **构建项目**  
   查看：[完整构建指南.md](完整构建指南.md)

3. **快速测试**  
   运行：`quick_test.bat`

4. **浏览器访问**  
   打开：`http://localhost:8080`

---

## 📚 文档导航

### 🎓 新手入门
- [快速开始指南](docs/guides/QUICK_START.md) - 5分钟上手教程
- [Web调试器使用说明](docs/guides/WEB_DEBUGGER_README.md) - 功能详解
- [ADB测试说明](docs/guides/ADB测试使用说明.md) - ADB操作指南
- [测试指南](docs/guides/TESTING_GUIDE.md) - 完整测试流程

### 🔧 技术文档
- [实现总结](docs/technical/IMPLEMENTATION_SUMMARY.md) - 技术架构
- [SELinux解决方案](docs/technical/SELINUX_SOLUTION.md) - 权限处理
- [后台服务方案](docs/technical/BACKGROUND_SERVICE_SUCCESS.md) - 持续运行
- [Capstone配置](docs/technical/CAPSTONE_配置完成.md) - 反汇编配置
- [项目检查清单](docs/technical/PROJECT_CHECKLIST.md) - 部署检查

### 📖 参考文档
- [后端命令速查](docs/references/后端命令速查.md) - 命令参考
- [测试工具说明](docs/references/测试工具README.md) - 工具使用

### 📊 测试报告
- [测试成功报告](docs/reports/TEST_SUCCESS_REPORT.md) - 真机测试结果

---

## 🛠️ 工具脚本

### 测试脚本
位置：`scripts/tests/`
- `quick_api_test.ps1` - 快速API测试
- `test_xiaomi13_full.ps1` - 小米13完整测试
- `test_game_memory.ps1` - 游戏内存测试
- 其他测试脚本...

### 指针分析工具
位置：`scripts/pointer_analysis/`
- `analyze_pointer_chain.ps1` - 指针链分析
- `backend_pointer_finder.ps1` - 后端指针查找
- 其他分析工具...

### 游戏修改工具
位置：`scripts/game_mods/`
- `sun_tracker.ps1` - 阳光追踪器
- `sun_modifier.ps1` - 阳光修改器
- `启动监控.ps1` - 启动监控

### 配置工具
位置：`scripts/tools/`
- `setup-capstone.ps1` - Capstone配置脚本

---

## 📦 项目结构

```
MyApplication2/
├── README.md                        # 本文件
├── 【项目完成】一页纸总结.md        # 项目总览
├── 完整构建指南.md                  # 构建指南
├── quick_test.bat                   # 快速测试入口
│
├── android-project/                 # 🎯 Android项目（完整独立）
│   ├── android/                     # 源码目录
│   │   ├── app/                     # 主项目
│   │   └── myapplication/           # 子项目
│   ├── gradle/                      # Gradle配置
│   ├── build.gradle.kts             # 项目构建文件
│   ├── settings.gradle.kts          # 项目设置
│   ├── gradlew                      # Gradle包装器
│   ├── gradlew.bat                  # Gradle包装器(Windows)
│   └── gradle.properties            # Gradle属性
│
├── research/                        # 游戏分析和逆向数据
│   ├── doce/                        # PVZ游戏分析文档
│   └── ida_dumps/                   # IDA分析数据
│
├── docs/                            # 完整文档
│   ├── guides/                      # 使用指南
│   ├── technical/                   # 技术文档
│   ├── references/                  # 参考资料
│   └── reports/                     # 测试报告
│
├── scripts/                         # 所有脚本工具
│   ├── tests/                       # 测试脚本
│   ├── pointer_analysis/            # 指针分析
│   ├── game_mods/                   # 游戏修改
│   └── tools/                       # 配置工具
│
├── archive/                         # 历史文件归档
│   ├── old_reports/                 # 旧报告
│   └── research/                    # 早期研究
│
└── .gradle/, .idea/                 # IDE配置
```

---

## 🎯 核心功能

### 1. HTTP服务器
- NanoHTTPD 2.3.1
- 自动启动（延迟2秒）
- 端口8080
- RESTful API

### 2. 内存操作
- 读取：任意地址
- 写入：直接修改
- 映射：完整内存区域
- 方式：/proc/pid/mem（绕过SELinux）

### 3. 反汇编
- 引擎：Capstone
- 架构：ARM64/ARMv7
- 功能：指令识别、地址分析

### 4. 基址分析
- 方法：内存映射分析
- 功能：自动推导基址和偏移
- 验证：真机测试通过

### 5. Web界面
- 框架：Vue 3
- 功能：6个调试模块
- 设计：响应式布局

---

## ⚙️ 技术栈

### 后端
- **语言**: Java + C++
- **框架**: Android NDK/JNI
- **服务器**: NanoHTTPD
- **反汇编**: Capstone
- **权限**: Root + SELinux绕过

### 前端
- **框架**: Vue 3
- **样式**: 原生CSS
- **通信**: RESTful API
- **工具**: Axios

### 系统
- **平台**: Android 10+
- **架构**: ARM64-v8a（推荐）
- **权限**: Root必需
- **测试**: 小米13（Android 15）

---

## 🎓 使用场景

1. **游戏内存修改** - 修改金币、阳光等数值
2. **基址查找** - 分析动态地址的基址和偏移
3. **代码分析** - 反汇编游戏逻辑代码
4. **远程调试** - 通过浏览器远程操作
5. **API开发** - 基于RESTful API二次开发

---

## ⚠️ 重要提示

### 必需条件
- ✅ Root权限
- ✅ Android 10+
- ✅ ADB连接或网络ADB

### 可选增强
- Capstone库（反汇编功能）
- 真机设备（完整功能）

### 使用限制
- 仅用于学习和研究
- 遵守目标应用服务条款
- 遵守当地法律法规

---

## 🔗 相关资源

- **Cheat Engine**: 本项目借鉴了CE的ceserver思路
- **Capstone**: https://www.capstone-engine.org/
- **NanoHTTPD**: https://github.com/NanoHttpd/nanohttpd

---

## 📝 更新日志

### v1.0.0 (2025-10-20)
- ✅ 完整的Web调试系统
- ✅ CE风格内存访问
- ✅ Capstone反汇编集成
- ✅ 前台服务后台运行
- ✅ 真机测试验证通过

---

## 🤝 贡献

本项目为学习研究项目，欢迎：
- 提出问题和建议
- 分享使用经验
- 改进文档

---

## 📜 许可

仅用于学习和研究目的。请勿用于商业用途或破坏游戏平衡。

---

**项目状态**: 🟢 生产就绪  
**推荐度**: ⭐⭐⭐⭐⭐  
**维护状态**: 活跃  

*最后更新: 2025-12-07*
