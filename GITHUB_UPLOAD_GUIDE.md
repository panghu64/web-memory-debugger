# GitHub 上传指南

## 📋 应该上传的文件

### ✅ 核心源代码
```
android-project/
├── android/
│   ├── app/
│   │   ├── src/
│   │   │   ├── main/
│   │   │   │   ├── java/          ✅ Java源代码
│   │   │   │   ├── cpp/           ✅ C++源代码
│   │   │   │   ├── assets/web/    ✅ Web前端代码
│   │   │   │   ├── res/           ✅ Android资源
│   │   │   │   └── AndroidManifest.xml  ✅
│   │   │   ├── androidTest/       ✅ 测试代码
│   │   │   └── test/              ✅ 单元测试
│   │   ├── build.gradle.kts       ✅ 构建配置
│   │   ├── proguard-rules.pro     ✅ 混淆规则
│   │   └── CMakeLists.txt         ✅ CMake配置
│   └── myapplication/             ✅ 子模块（同上）
├── gradle/                        ✅ Gradle Wrapper
├── build.gradle.kts               ✅ 项目构建配置
├── settings.gradle.kts            ✅ 项目设置
├── gradle.properties              ✅ Gradle属性
├── gradlew                        ✅ Gradle包装器
└── gradlew.bat                    ✅ Gradle包装器(Windows)
```

### ✅ 文档
```
docs/                              ✅ 所有文档
├── guides/                        ✅ 使用指南
├── technical/                     ✅ 技术文档
├── references/                    ✅ 参考资料
└── reports/                       ✅ 测试报告

README.md                          ✅ 项目说明
【项目完成】一页纸总结.md          ✅ 项目总结
完整构建指南.md                    ✅ 构建指南
```

### ✅ 脚本工具
```
scripts/                           ✅ 所有脚本
├── tests/                         ✅ 测试脚本
├── pointer_analysis/              ✅ 指针分析工具
├── game_mods/                     ✅ 游戏修改工具
└── tools/                         ✅ 配置工具
```

### ⚠️ 可选上传（根据需要）
```
research/                          ⚠️ 研究数据（可能包含游戏数据）
├── doce/                          ✅ 分析文档（建议上传）
├── ida_dumps/                     ⚠️ IDA分析数据（可能敏感）
└── tools/                         ⚠️ 二进制工具（可能很大）

archive/                           ⚠️ 历史文件（可选）
├── old_reports/                   ❌ 旧报告（不建议）
└── research/                      ❌ 早期研究（不建议）
```

### ⚠️ 大文件处理（需要Git LFS或单独托管）
```
android-project/android/app/src/main/jniLibs/
├── arm64-v8a/libcapstone.so       ⚠️ 16.68MB（考虑Git LFS）
├── armeabi-v7a/libcapstone.so     ⚠️ 大文件（考虑Git LFS）
└── README.md                      ✅ 说明文档

android-project/android/app/src/main/assets/memtool/
├── arm64-v8a/memtool              ⚠️ 二进制文件
├── armeabi-v7a/memtool            ⚠️ 二进制文件
└── ...                            ⚠️ 其他架构
```

---

## ❌ 不应该上传的文件

### ❌ 构建产物
```
build/                             ❌ 所有构建输出
android-project/android/app/build/ ❌ APK和中间文件
*.apk                              ❌ 编译后的APK
*.aab                              ❌ Android App Bundle
*.dex                              ❌ Dalvik字节码
*.class                            ❌ Java字节码
*.o                                ❌ 目标文件
*.a                                ❌ 静态库
```

### ❌ IDE配置
```
.idea/                             ❌ Android Studio配置
.vscode/                           ❌ VS Code配置
.cursor/                           ❌ Cursor配置
.kiro/                             ❌ Kiro配置
*.iml                              ❌ IntelliJ模块文件
```

### ❌ Gradle缓存
```
.gradle/                           ❌ Gradle缓存
android-project/.gradle/           ❌ 项目Gradle缓存
```

### ❌ 本地配置
```
local.properties                   ❌ 本地SDK路径
android-project/local.properties   ❌ 包含个人路径
```

### ❌ NDK构建缓存
```
.cxx/                              ❌ CMake构建缓存
.externalNativeBuild/              ❌ NDK构建输出
android-project/android/app/.cxx/  ❌ 大量临时文件
```

### ❌ 系统文件
```
.DS_Store                          ❌ macOS
Thumbs.db                          ❌ Windows
desktop.ini                        ❌ Windows
```

### ❌ 敏感文件
```
*.keystore                         ❌ 签名密钥
*.jks                              ❌ Java密钥库
key.properties                     ❌ 密钥配置
```

---

## 📊 文件大小统计

### 应该上传的文件（估算）
- 源代码: ~2MB
- 文档: ~1MB
- 脚本: ~500KB
- Gradle配置: ~100KB
- **总计**: ~3.6MB

### 可选/需要特殊处理的文件
- libcapstone.so (ARM64): 16.68MB ⚠️
- libcapstone.so (ARMv7): ~15MB ⚠️
- memtool二进制: ~5MB ⚠️
- research数据: ~10MB ⚠️
- **总计**: ~46MB

---

## 🚀 上传步骤

### 方法1：标准上传（不含大文件）

```bash
# 1. 初始化Git仓库
cd /path/to/project
git init

# 2. 添加远程仓库
git remote add origin https://github.com/yourusername/web-memory-debugger.git

# 3. 添加文件（.gitignore会自动过滤）
git add .

# 4. 提交
git commit -m "Initial commit: Web Memory Debugger v1.0.0"

# 5. 推送
git branch -M main
git push -u origin main
```

### 方法2：使用Git LFS（包含大文件）

```bash
# 1. 安装Git LFS
git lfs install

# 2. 跟踪大文件
git lfs track "*.so"
git lfs track "android-project/android/app/src/main/assets/memtool/**"

# 3. 添加.gitattributes
git add .gitattributes

# 4. 正常添加和提交
git add .
git commit -m "Initial commit with LFS support"
git push -u origin main
```

### 方法3：分离大文件（推荐）

```bash
# 1. 创建releases目录（不上传到Git）
mkdir releases

# 2. 复制大文件到releases
cp android-project/android/app/src/main/jniLibs/arm64-v8a/libcapstone.so releases/
cp android-project/android/app/src/main/jniLibs/armeabi-v7a/libcapstone.so releases/

# 3. 在README中说明下载方式
# "大文件请从Releases页面下载"

# 4. 正常上传代码
git add .
git commit -m "Initial commit (without large binaries)"
git push -u origin main

# 5. 创建Release并上传大文件
# 在GitHub网页上创建Release，手动上传releases/目录的文件
```

---

## 📝 建议的README补充

在README.md中添加：

```markdown
## 📦 大文件下载

由于GitHub文件大小限制，以下文件需要单独下载：

### Capstone库文件
- [libcapstone.so (ARM64-v8a)](https://github.com/yourusername/repo/releases/download/v1.0.0/libcapstone-arm64.so) - 16.68MB
- [libcapstone.so (ARMv7)](https://github.com/yourusername/repo/releases/download/v1.0.0/libcapstone-armv7.so) - 15MB

### 下载后放置位置
```
android-project/android/app/src/main/jniLibs/
├── arm64-v8a/libcapstone.so
└── armeabi-v7a/libcapstone.so
```

### 或者使用自动下载脚本
```bash
.\scripts\tools\download-libs.ps1
```
```

---

## ⚠️ 注意事项

### 1. 敏感信息检查
上传前检查：
- ❌ 不要包含个人SDK路径
- ❌ 不要包含签名密钥
- ❌ 不要包含API密钥
- ❌ 不要包含游戏破解数据

### 2. 许可证
添加LICENSE文件：
```bash
# 建议使用MIT或Apache 2.0
# 在项目根目录创建LICENSE文件
```

### 3. 游戏数据
```
research/data/game_data/           ❌ 不要上传游戏数据
research/ida_dumps/*.bin           ❌ 不要上传内存转储
```

### 4. 法律合规
- ⚠️ 确保不违反游戏服务条款
- ⚠️ 仅用于教育和研究目的
- ⚠️ 在README中添加免责声明

---

## 📋 上传前检查清单

- [ ] 已创建.gitignore文件
- [ ] 已删除所有build/目录
- [ ] 已删除local.properties
- [ ] 已删除.idea/配置
- [ ] 已删除.gradle/缓存
- [ ] 已删除.cxx/构建缓存
- [ ] 已检查敏感信息
- [ ] 已添加LICENSE文件
- [ ] 已更新README（大文件说明）
- [ ] 已测试克隆后能否构建

---

## 🎯 推荐的仓库结构

```
web-memory-debugger/
├── .gitignore                     ✅ 已创建
├── .gitattributes                 ✅ Git LFS配置（可选）
├── LICENSE                        ⚠️ 需要添加
├── README.md                      ✅ 已有
├── GITHUB_UPLOAD_GUIDE.md         ✅ 本文件
├── android-project/               ✅ Android项目
├── docs/                          ✅ 文档
├── scripts/                       ✅ 脚本
├── research/doce/                 ✅ 分析文档
└── releases/                      ❌ 不上传（本地存放大文件）
```

---

## 🔗 相关资源

- [Git LFS文档](https://git-lfs.github.com/)
- [GitHub文件大小限制](https://docs.github.com/en/repositories/working-with-files/managing-large-files)
- [.gitignore模板](https://github.com/github/gitignore)

---

**创建日期**: 2025-12-07  
**版本**: 1.0  
**状态**: ✅ 可用
