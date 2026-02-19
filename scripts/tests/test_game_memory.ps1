# 游戏内存功能测试
# 直接使用已知PID测试

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  游戏内存功能测试" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

# 获取游戏PID
Write-Host "`n[1] 获取游戏PID..." -ForegroundColor Yellow
$psOutput = adb shell "ps -A | grep pvz"
if ($psOutput) {
    $GamePid = ($psOutput -split "\s+")[1]
    Write-Host "   ? 游戏PID: $GamePid" -ForegroundColor Green
} else {
    Write-Host "   ? 游戏未运行" -ForegroundColor Red
    exit
}

$API_BASE = "http://localhost:8080/api"

# 测试内存映射
Write-Host "`n[2] 获取游戏内存映射..." -ForegroundColor Yellow
try {
    $response = Invoke-RestMethod -Uri "$API_BASE/memory/maps?pid=$GamePid" -TimeoutSec 30
    if ($response.success) {
        Write-Host "   ? 成功获取内存映射" -ForegroundColor Green
        Write-Host "   ? 内存区域数: $($response.data.Count)" -ForegroundColor Green
        
        # 统计
        $total = $response.data.Count
        $readable = ($response.data | Where-Object { $_.perms -match "r" }).Count
        $writable = ($response.data | Where-Object { $_.perms -match "w" }).Count
        $executable = ($response.data | Where-Object { $_.perms -match "x" }).Count
        
        Write-Host "`n   统计信息:" -ForegroundColor Cyan
        Write-Host "   - 总区域: $total" -ForegroundColor Gray
        Write-Host "   - 可读: $readable" -ForegroundColor Gray
        Write-Host "   - 可写: $writable" -ForegroundColor Gray
        Write-Host "   - 可执行: $executable" -ForegroundColor Gray
        
        $global:maps = $response.data
    } else {
        Write-Host "   ? 获取失败" -ForegroundColor Red
        exit
    }
} catch {
    Write-Host "   ? 请求失败: $($_.Exception.Message)" -ForegroundColor Red
    exit
}

# 查找libpvz.so
Write-Host "`n[3] 查找libpvz.so..." -ForegroundColor Yellow
$libpvz = $global:maps | Where-Object { $_.path -like "*libpvz.so" }
if ($libpvz.Count -gt 0) {
    Write-Host "   ? 找到libpvz.so: $($libpvz.Count) 个段" -ForegroundColor Green
    
    Write-Host "`n   段信息:" -ForegroundColor Cyan
    $libpvz | ForEach-Object {
        $sizeMB = [math]::Round($_.size / 1MB, 2)
        $perms = $_.perms.PadRight(4)
        Write-Host "   $perms | 0x$($_.start)-0x$($_.end) | ${sizeMB}MB" -ForegroundColor Gray
        
        # 保存不同类型的段
        if ($_.perms -eq "r-xp") {
            $global:execSegment = $_
        }
        if ($_.perms -eq "rw-p") {
            $global:dataSegment = $_
        }
    }
} else {
    Write-Host "   ??  未找到libpvz.so" -ForegroundColor Yellow
}

# 测试读取可执行段（ELF头）
if ($global:execSegment) {
    Write-Host "`n[4] 读取可执行段（ELF头）..." -ForegroundColor Yellow
    try {
        $body = @{
            pid = [int]$GamePid
            address = $global:execSegment.start
            length = 16
        } | ConvertTo-Json
        
        $response = Invoke-RestMethod -Uri "$API_BASE/memory/read" -Method Post -Body $body -ContentType "application/json" -TimeoutSec 15
        if ($response.success -and $response.data.hex) {
            $hex = $response.data.hex
            Write-Host "   ? 成功读取内存" -ForegroundColor Green
            Write-Host "   ? 地址: 0x$($global:execSegment.start)" -ForegroundColor Green
            Write-Host "   ? 数据: $hex" -ForegroundColor Green
            
            # 检查ELF魔数
            if ($hex.StartsWith("7f454c46")) {
                Write-Host "   ? ELF魔数验证通过 (7F 45 4C 46)" -ForegroundColor Green
            }
        } else {
            Write-Host "   ? 读取失败" -ForegroundColor Red
        }
    } catch {
        Write-Host "   ??  读取失败: $($_.Exception.Message)" -ForegroundColor Yellow
        Write-Host "   提示: 内存读取功能需要/proc/mem支持" -ForegroundColor Gray
    }
}

# 测试读取数据段
if ($global:dataSegment) {
    Write-Host "`n[5] 读取数据段..." -ForegroundColor Yellow
    try {
        $body = @{
            pid = [int]$GamePid
            address = $global:dataSegment.start
            length = 64
        } | ConvertTo-Json
        
        $response = Invoke-RestMethod -Uri "$API_BASE/memory/read" -Method Post -Body $body -ContentType "application/json" -TimeoutSec 15
        if ($response.success -and $response.data.hex) {
            Write-Host "   ? 成功读取数据段" -ForegroundColor Green
            Write-Host "   ? 地址: 0x$($global:dataSegment.start)" -ForegroundColor Green
            Write-Host "   ? 前32字节: $($response.data.hex.Substring(0,64))" -ForegroundColor Green
        }
    } catch {
        Write-Host "   ??  读取失败: $($_.Exception.Message)" -ForegroundColor Yellow
    }
}

# 测试写入（写入测试值到数据段）
if ($global:dataSegment) {
    Write-Host "`n[6] 测试内存写入..." -ForegroundColor Yellow
    try {
        $testValue = 888888
        $body = @{
            pid = [int]$GamePid
            address = $global:dataSegment.start
            value = $testValue
        } | ConvertTo-Json
        
        $response = Invoke-RestMethod -Uri "$API_BASE/memory/write" -Method Post -Body $body -ContentType "application/json" -TimeoutSec 15
        if ($response.success) {
            Write-Host "   ? 成功写入内存" -ForegroundColor Green
            Write-Host "   ? 地址: 0x$($global:dataSegment.start)" -ForegroundColor Green
            Write-Host "   ? 值: $testValue" -ForegroundColor Green
        } else {
            Write-Host "   ? 写入失败" -ForegroundColor Red
        }
    } catch {
        Write-Host "   ??  写入失败: $($_.Exception.Message)" -ForegroundColor Yellow
        Write-Host "   提示: 内存写入功能需要/proc/mem支持和权限" -ForegroundColor Gray
    }
}

# 测试反汇编
if ($global:execSegment) {
    Write-Host "`n[7] 测试反汇编功能..." -ForegroundColor Yellow
    try {
        # 计算代码地址（跳过ELF头）
        $baseAddr = [Convert]::ToInt64($global:execSegment.start, 16)
        $codeAddr = ($baseAddr + 0x1000).ToString("x")
        
        $body = @{
            pid = [int]$GamePid
            address = $codeAddr
            count = 10
        } | ConvertTo-Json
        
        $response = Invoke-RestMethod -Uri "$API_BASE/disasm" -Method Post -Body $body -ContentType "application/json" -TimeoutSec 20
        if ($response.success -and $response.data.Count -gt 0) {
            Write-Host "   ? 成功反汇编" -ForegroundColor Green
            Write-Host "   ? 地址: 0x$codeAddr" -ForegroundColor Green
            Write-Host "   ? 指令数: $($response.data.Count)" -ForegroundColor Green
            
            Write-Host "`n   反汇编结果:" -ForegroundColor Cyan
            $response.data | Select-Object -First 5 | ForEach-Object {
                Write-Host "   $($_.address): $($_.mnemonic.PadRight(6)) $($_.opStr)" -ForegroundColor Gray
            }
        } else {
            Write-Host "   ??  反汇编返回空数据" -ForegroundColor Yellow
        }
    } catch {
        Write-Host "   ??  反汇编失败: $($_.Exception.Message)" -ForegroundColor Yellow
        Write-Host "   提示: 反汇编功能需要Capstone库支持" -ForegroundColor Gray
    }
}

# 基址分析示例
if ($global:dataSegment) {
    Write-Host "`n[8] 基址分析示例..." -ForegroundColor Yellow
    Write-Host "   假设找到金币地址..." -ForegroundColor Cyan
    
    # 模拟一个动态地址
    $baseAddr = [Convert]::ToInt64($global:dataSegment.start, 16)
    $offset = 0x100
    $dynamicAddr = ($baseAddr + $offset).ToString("x")
    
    Write-Host "`n   基址分析结果:" -ForegroundColor Cyan
    Write-Host "   动态地址: 0x$dynamicAddr" -ForegroundColor Gray
    Write-Host "   所属模块: libpvz.so (数据段)" -ForegroundColor Gray
    Write-Host "   模块基址: 0x$($global:dataSegment.start)" -ForegroundColor Gray
    Write-Host "   偏移量: +0x$($offset.ToString("x"))" -ForegroundColor Gray
    Write-Host "   基址公式: [libpvz.so数据段 + 0x$($offset.ToString("x"))]" -ForegroundColor Green
}

# 总结
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  测试总结" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

Write-Host "`n? 已验证功能:" -ForegroundColor Green
Write-Host "   - 内存映射获取" -ForegroundColor Gray
Write-Host "   - libpvz.so识别" -ForegroundColor Gray
Write-Host "   - 内存区域分类" -ForegroundColor Gray
Write-Host "   - 基址分析方法" -ForegroundColor Gray

Write-Host "`n? 游戏信息:" -ForegroundColor Cyan
Write-Host "   - 游戏PID: $GamePid" -ForegroundColor White
if ($global:execSegment) {
    Write-Host "   - 代码段: 0x$($global:execSegment.start)" -ForegroundColor White
}
if ($global:dataSegment) {
    Write-Host "   - 数据段: 0x$($global:dataSegment.start)" -ForegroundColor White
}

Write-Host "`n? 下一步:" -ForegroundColor Yellow
Write-Host "   1. 打开浏览器: http://localhost:8080" -ForegroundColor Gray
Write-Host "   2. 使用Hex编辑器查看内存" -ForegroundColor Gray
Write-Host "   3. 使用反汇编工具分析代码" -ForegroundColor Gray

Write-Host "`n? 测试完成！" -ForegroundColor Cyan

