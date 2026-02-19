# 测试内存读取功能
# 先确保基础功能正常

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  内存读取功能诊断" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

$API_BASE = "http://localhost:8080/api"
$TARGET_ADDRESS = "6D4662B22C"

# 1. 获取游戏PID
Write-Host "`n[1] 获取游戏PID..." -ForegroundColor Yellow
$psOutput = adb shell "ps -A | grep pvz"
if (-not $psOutput) {
    Write-Host "   ? 游戏未运行" -ForegroundColor Red
    exit
}

$GamePid = ($psOutput -split "\s+")[1]
Write-Host "   ? 游戏PID: $GamePid" -ForegroundColor Green

# 2. 获取内存映射
Write-Host "`n[2] 获取内存映射..." -ForegroundColor Yellow
try {
    $response = Invoke-RestMethod -Uri "$API_BASE/memory/maps?pid=$GamePid" -TimeoutSec 30
    if ($response.success) {
        Write-Host "   ? 成功，区域数: $($response.data.Count)" -ForegroundColor Green
        $maps = $response.data
        
        # 检查目标地址是否在某个区域
        $targetAddrInt = [Convert]::ToInt64($TARGET_ADDRESS, 16)
        $targetRegion = $maps | Where-Object {
            $start = [Convert]::ToInt64($_.start, 16)
            $end = [Convert]::ToInt64($_.end, 16)
            $targetAddrInt -ge $start -and $targetAddrInt -lt $end
        }
        
        if ($targetRegion) {
            Write-Host "`n   ? 找到目标地址所在区域:" -ForegroundColor Green
            Write-Host "   权限: $($targetRegion.perms)" -ForegroundColor Cyan
            Write-Host "   范围: 0x$($targetRegion.start)-0x$($targetRegion.end)" -ForegroundColor Cyan
            Write-Host "   路径: $($targetRegion.path)" -ForegroundColor Cyan
        } else {
            Write-Host "`n   ? 目标地址不在任何内存区域中！" -ForegroundColor Red
            Write-Host "   地址: 0x$TARGET_ADDRESS" -ForegroundColor Yellow
            Write-Host "   提示: 地址可能无效或游戏状态已改变" -ForegroundColor Gray
            
            # 显示最接近的区域
            Write-Host "`n   最接近的内存区域:" -ForegroundColor Yellow
            $maps | ForEach-Object {
                $start = [Convert]::ToInt64($_.start, 16)
                $end = [Convert]::ToInt64($_.end, 16)
                $distance = [Math]::Min([Math]::Abs($targetAddrInt - $start), [Math]::Abs($targetAddrInt - $end))
                
                if ($distance -lt 0x10000000) {  # 256MB范围内
                    [PSCustomObject]@{
                        Start = "0x$($_.start)"
                        End = "0x$($_.end)"
                        Perms = $_.perms
                        Path = $_.path
                        Distance = "0x$($distance.ToString('X'))"
                    }
                }
            } | Sort-Object { [Convert]::ToInt64($_.Distance, 16) } | Select-Object -First 5 | Format-Table -AutoSize
        }
        
        # 显示libpvz.so的段
        Write-Host "`n   libpvz.so段信息:" -ForegroundColor Cyan
        $libpvz = $maps | Where-Object { $_.path -like "*libpvz.so" }
        $libpvz | ForEach-Object {
            $sizeMB = [math]::Round($_.size / 1MB, 2)
            Write-Host "   $($_.perms) | 0x$($_.start)-0x$($_.end) | ${sizeMB}MB" -ForegroundColor Gray
        }
    }
} catch {
    Write-Host "   ? 失败: $($_.Exception.Message)" -ForegroundColor Red
    exit
}

# 3. 测试读取libpvz.so数据段（应该能成功）
Write-Host "`n[3] 测试读取libpvz.so数据段..." -ForegroundColor Yellow
$dataSegment = $libpvz | Where-Object { $_.perms -eq "rw-p" } | Select-Object -First 1

if ($dataSegment) {
    Write-Host "   测试地址: 0x$($dataSegment.start)" -ForegroundColor Cyan
    
    try {
        $body = @{
            pid = [int]$GamePid
            address = $dataSegment.start
            length = 16
        } | ConvertTo-Json
        
        Write-Host "   发送请求..." -ForegroundColor Gray
        $response = Invoke-RestMethod -Uri "$API_BASE/memory/read" -Method Post -Body $body -ContentType "application/json" -TimeoutSec 15
        
        if ($response.success -and $response.data.hex) {
            Write-Host "   ? 读取成功！" -ForegroundColor Green
            Write-Host "   数据: $($response.data.hex)" -ForegroundColor Cyan
        } else {
            Write-Host "   ? API返回失败" -ForegroundColor Red
            Write-Host "   响应: $($response | ConvertTo-Json)" -ForegroundColor Gray
        }
    } catch {
        Write-Host "   ? 读取失败: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "`n   可能的原因:" -ForegroundColor Yellow
        Write-Host "   1. memtool_procmem未正确配置" -ForegroundColor Gray
        Write-Host "   2. SELinux限制（需要临时禁用）" -ForegroundColor Gray
        Write-Host "   3. Root权限问题" -ForegroundColor Gray
        
        Write-Host "`n   解决方法:" -ForegroundColor Yellow
        Write-Host "   adb shell su -c setenforce 0" -ForegroundColor Cyan
    }
}

# 4. 如果目标地址有效，尝试读取
if ($targetRegion) {
    Write-Host "`n[4] 尝试读取目标地址..." -ForegroundColor Yellow
    Write-Host "   地址: 0x$TARGET_ADDRESS" -ForegroundColor Cyan
    
    try {
        $body = @{
            pid = [int]$GamePid
            address = $TARGET_ADDRESS
            length = 4
        } | ConvertTo-Json
        
        $response = Invoke-RestMethod -Uri "$API_BASE/memory/read" -Method Post -Body $body -ContentType "application/json" -TimeoutSec 15
        
        if ($response.success -and $response.data.hex) {
            Write-Host "   ? 读取成功！" -ForegroundColor Green
            
            $hexValue = $response.data.hex
            Write-Host "   Hex: $hexValue" -ForegroundColor Cyan
            
            # 转换为整数（小端序）
            $bytes = $hexValue -split '(..)' | Where-Object { $_ }
            if ($bytes.Count -ge 4) {
                $sunValue = [Convert]::ToInt32($bytes[3] + $bytes[2] + $bytes[1] + $bytes[0], 16)
                Write-Host "   阳光值: $sunValue" -ForegroundColor Green
            }
        } else {
            Write-Host "   ? 读取失败" -ForegroundColor Red
            Write-Host "   响应: $($response | ConvertTo-Json)" -ForegroundColor Gray
        }
    } catch {
        Write-Host "   ? 读取失败: $($_.Exception.Message)" -ForegroundColor Red
    }
} else {
    Write-Host "`n[4] 跳过目标地址读取（地址无效）" -ForegroundColor Yellow
    
    Write-Host "`n   建议操作:" -ForegroundColor Cyan
    Write-Host "   1. 重新在Cheat Engine中搜索阳光地址" -ForegroundColor Gray
    Write-Host "   2. 确保游戏状态正确（在关卡中）" -ForegroundColor Gray
    Write-Host "   3. 地址可能每次游戏启动都不同" -ForegroundColor Gray
}

# 5. 生成诊断报告
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  诊断总结" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

Write-Host "`n游戏信息:" -ForegroundColor Yellow
Write-Host "   PID: $GamePid" -ForegroundColor White
Write-Host "   内存区域数: $($maps.Count)" -ForegroundColor White

Write-Host "`n目标地址状态:" -ForegroundColor Yellow
if ($targetRegion) {
    Write-Host "   ? 地址有效" -ForegroundColor Green
    Write-Host "   所在: $($targetRegion.path)" -ForegroundColor White
} else {
    Write-Host "   ? 地址无效或已改变" -ForegroundColor Red
}

Write-Host "`n下一步建议:" -ForegroundColor Yellow
if (-not $targetRegion) {
    Write-Host "   1. 使用Cheat Engine重新搜索阳光值" -ForegroundColor Gray
    Write-Host "   2. 确保在游戏关卡中（不是主菜单）" -ForegroundColor Gray
    Write-Host "   3. 收集/使用阳光，观察值变化" -ForegroundColor Gray
    Write-Host "   4. 锁定地址后再次运行此脚本" -ForegroundColor Gray
} else {
    Write-Host "   1. 临时禁用SELinux:" -ForegroundColor Gray
    Write-Host "      adb shell su -c setenforce 0" -ForegroundColor Cyan
    Write-Host "   2. 重新运行: analyze_pointer_chain.ps1" -ForegroundColor Gray
    Write-Host "   3. 启用实时监控" -ForegroundColor Gray
}

Write-Host "`n诊断完成！" -ForegroundColor Cyan

