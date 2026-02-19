# 阳光值实时监控和修改工具
param(
    [string]$Address = "703BB3550C",
    [int]$TargetValue = 9999,
    [switch]$Monitor,
    [switch]$Set,
    [switch]$Lock
)

$API_BASE = "http://localhost:8080"

# 获取游戏PID
function Get-GamePID {
    try {
        $output = adb shell "ps | grep pvz"
        if ($output -match '\s+(\d+)\s+') {
            $pid = [int]($Matches[1])
            return $pid
        }
    } catch {
        Write-Host "? 无法获取游戏PID" -ForegroundColor Red
    }
    return $null
}

# 读取阳光值
function Read-SunValue {
    param([int]$ProcessID, [string]$Addr)
    
    try {
        $body = @{
            pid = $ProcessID
            address = $Addr
            length = 4
        } | ConvertTo-Json
        
        $response = Invoke-RestMethod "$API_BASE/api/memory/read" -Method Post -Body $body -ContentType "application/json" -TimeoutSec 2
        
        if ($response.success) {
            $hex = $response.data.hex
            # 小端序转换
            $value = [Convert]::ToInt32($hex.Substring(0,2), 16)
            return $value
        }
    } catch {
        return $null
    }
    return $null
}

# 设置阳光值
function Set-SunValue {
    param([int]$ProcessID, [string]$Addr, [int]$Value)
    
    try {
        $body = @{
            pid = $ProcessID
            address = $Addr
            value = $Value
        } | ConvertTo-Json
        
        $response = Invoke-RestMethod "$API_BASE/api/memory/write" -Method Post -Body $body -ContentType "application/json" -TimeoutSec 2
        
        return $response.success
    } catch {
        return $false
    }
}

# 主函数
$GamePID = Get-GamePID
if (-not $GamePID) {
    Write-Host "? 游戏未运行" -ForegroundColor Red
    exit 1
}

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  ? 阳光值控制工具" -ForegroundColor Yellow
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  游戏PID: $GamePID" -ForegroundColor White
Write-Host "  地址: 0x$Address" -ForegroundColor White
Write-Host "========================================`n" -ForegroundColor Cyan

if ($Set) {
    # 设置模式
    Write-Host "? 设置阳光值为: $TargetValue" -ForegroundColor Cyan
    $success = Set-SunValue -ProcessID $GamePID -Addr $Address -Value $TargetValue
    
    if ($success) {
        Start-Sleep -Milliseconds 500
        $current = Read-SunValue -ProcessID $GamePID -Addr $Address
        Write-Host "? 设置成功！当前值: $current" -ForegroundColor Green
    } else {
        Write-Host "? 设置失败" -ForegroundColor Red
    }
}
elseif ($Lock) {
    # 锁定模式
    Write-Host "? 锁定阳光值为: $TargetValue (按 Ctrl+C 停止)" -ForegroundColor Yellow
    Write-Host ""
    
    $count = 0
    while ($true) {
        $current = Read-SunValue -ProcessID $GamePID -Addr $Address
        
        if ($current -ne $null) {
            if ($current -ne $TargetValue) {
                $success = Set-SunValue -ProcessID $GamePID -Addr $Address -Value $TargetValue
                if ($success) {
                    Write-Host "[$(Get-Date -Format 'HH:mm:ss')] ? 修正: $current -> $TargetValue" -ForegroundColor Yellow
                    $count++
                }
            } else {
                Write-Host "[$(Get-Date -Format 'HH:mm:ss')] ? 锁定中: $TargetValue (修正次数: $count)" -ForegroundColor Green
            }
        }
        
        Start-Sleep -Milliseconds 100
    }
}
else {
    # 监控模式（默认）
    Write-Host "??  实时监控模式 (按 Ctrl+C 停止)" -ForegroundColor Cyan
    Write-Host ""
    
    $lastValue = $null
    $changeCount = 0
    
    while ($true) {
        $current = Read-SunValue -ProcessID $GamePID -Addr $Address
        
        if ($current -ne $null) {
            if ($lastValue -eq $null) {
                Write-Host "[$(Get-Date -Format 'HH:mm:ss')] 初始值: $current" -ForegroundColor White
            }
            elseif ($current -ne $lastValue) {
                $diff = $current - $lastValue
                $color = if ($diff -gt 0) { "Green" } else { "Red" }
                $symbol = if ($diff -gt 0) { "↑" } else { "↓" }
                
                Write-Host "[$(Get-Date -Format 'HH:mm:ss')] $symbol $lastValue -> $current (${diff})" -ForegroundColor $color
                $changeCount++
            }
            
            $lastValue = $current
        }
        
        Start-Sleep -Milliseconds 200
    }
}

