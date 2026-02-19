# Capstone Android 库下载和配置脚本
# 此脚本将下载预编译的 Capstone 库并放置到正确的位置

$ErrorActionPreference = "Stop"

Write-Host "=== Capstone Android 库配置脚本 ===" -ForegroundColor Green

# 创建临时目录
$tempDir = "temp_capstone"
New-Item -ItemType Directory -Force -Path $tempDir | Out-Null

try {
    Write-Host "`n1. 正在下载 Capstone 预编译库..." -ForegroundColor Yellow
    
    # 从可靠的开源项目下载预编译的 Capstone 库
    # 这里使用 Frida 项目提供的 Capstone 库作为示例
    $arm64Url = "https://github.com/frida/capstone/releases/download/5.0-android/libcapstone-arm64.so"
    $armv7Url = "https://github.com/frida/capstone/releases/download/5.0-android/libcapstone-armv7.so"
    
    Write-Host "   下载 ARM64 版本..." -ForegroundColor Cyan
    try {
        Invoke-WebRequest -Uri $arm64Url -OutFile "$tempDir\libcapstone-arm64.so" -UseBasicParsing
    } catch {
        Write-Host "   注意: 自动下载失败。请手动下载 Capstone 库。" -ForegroundColor Yellow
        Write-Host "   错误信息: $_" -ForegroundColor Red
    }
    
    Write-Host "   下载 ARMv7 版本..." -ForegroundColor Cyan
    try {
        Invoke-WebRequest -Uri $armv7Url -OutFile "$tempDir\libcapstone-armv7.so" -UseBasicParsing
    } catch {
        Write-Host "   注意: 自动下载失败。" -ForegroundColor Yellow
    }
    
    Write-Host "`n2. 配置库文件..." -ForegroundColor Yellow
    
    # 创建目标目录
    $arm64Dir = "app\src\main\jniLibs\arm64-v8a"
    $armv7Dir = "app\src\main\jniLibs\armeabi-v7a"
    
    New-Item -ItemType Directory -Force -Path $arm64Dir | Out-Null
    New-Item -ItemType Directory -Force -Path $armv7Dir | Out-Null
    
    # 复制文件
    if (Test-Path "$tempDir\libcapstone-arm64.so") {
        Copy-Item "$tempDir\libcapstone-arm64.so" "$arm64Dir\libcapstone.so" -Force
        Write-Host "   ✓ ARM64 库已配置" -ForegroundColor Green
    }
    
    if (Test-Path "$tempDir\libcapstone-armv7.so") {
        Copy-Item "$tempDir\libcapstone-armv7.so" "$armv7Dir\libcapstone.so" -Force
        Write-Host "   ✓ ARMv7 库已配置" -ForegroundColor Green
    }
    
    Write-Host "`n3. 清理临时文件..." -ForegroundColor Yellow
    Remove-Item -Path $tempDir -Recurse -Force
    
    Write-Host "`n=== 配置完成 ===" -ForegroundColor Green
    Write-Host "`n请注意:" -ForegroundColor Yellow
    Write-Host "  - 如果自动下载失败，您需要手动下载 Capstone 库"
    Write-Host "  - 下载地址: https://github.com/capstone-engine/capstone/releases"
    Write-Host "  - 将 libcapstone.so 放置到:"
    Write-Host "    * app/src/main/jniLibs/arm64-v8a/libcapstone.so"
    Write-Host "    * app/src/main/jniLibs/armeabi-v7a/libcapstone.so"
    
} catch {
    Write-Host "`n错误: $_" -ForegroundColor Red
    if (Test-Path $tempDir) {
        Remove-Item -Path $tempDir -Recurse -Force
    }
    exit 1
}


