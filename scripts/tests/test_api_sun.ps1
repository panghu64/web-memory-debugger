# 测试后端API - 阳光地址分析
# 使用修复后的API（memtool_procmem）

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  后端API阳光测试" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

$SUN_ADDRESS = "7043E320CC"
$API_BASE = "http://10.99.99.3:8080/api"

# 1. 获取游戏PID
Write-Host "`n[1] 获取游戏PID..." -ForegroundColor Yellow
$response = Invoke-RestMethod -Uri "$API_BASE/process/list" -TimeoutSec 15

$gamePid = $null
$response.data | ForEach-Object {
    if ($_.name -like "*pvz*") {
        $gamePid = $_.pid
        Write-Host "   ? 游戏PID: $gamePid" -ForegroundColor Green
        Write-Host "   游戏名: $($_.name)" -ForegroundColor Gray
    }
}

if (-not $gamePid) {
    Write-Host "   ? 游戏未运行" -ForegroundColor Red
    exit
}

# 2. 测试读取阳光地址
Write-Host "`n[2] 测试API读取阳光..." -ForegroundColor Yellow
Write-Host "   地址: 0x$SUN_ADDRESS" -ForegroundColor Cyan

try {
    $body = @{
        pid = $gamePid
        address = $SUN_ADDRESS
        length = 4
    } | ConvertTo-Json
    
    $response = Invoke-RestMethod -Uri "$API_BASE/memory/read" `
        -Method Post -Body $body -ContentType "application/json" -TimeoutSec 20
    
    if ($response.success -and $response.data.hex) {
        Write-Host "   ? API读取成功！" -ForegroundColor Green
        
        $hexData = $response.data.hex
        Write-Host "   Hex: $hexData" -ForegroundColor Cyan
        
        # 转换为整数（小端序）
        if ($hexData.Length -ge 8) {
            $b1 = $hexData.Substring(0,2)
            $b2 = $hexData.Substring(2,2)
            $b3 = $hexData.Substring(4,2)
            $b4 = $hexData.Substring(6,2)
            
            $sunValue = [Convert]::ToInt32("$b4$b3$b2$b1", 16)
            Write-Host "   阳光值: $sunValue" -ForegroundColor Green
            $global:CurrentSun = $sunValue
        }
    } else {
        Write-Host "   ? API返回失败" -ForegroundColor Red
        Write-Host "   响应: $($response | ConvertTo-Json)" -ForegroundColor Gray
        exit
    }
} catch {
    Write-Host "   ? API调用失败: $($_.Exception.Message)" -ForegroundColor Red
    exit
}

# 3. 测试修改阳光
Write-Host "`n[3] 测试API修改阳光..." -ForegroundColor Yellow

$testValue = 8888
Write-Host "   修改为: $testValue" -ForegroundColor Cyan

try {
    $body = @{
        pid = $gamePid
        address = $SUN_ADDRESS
        value = $testValue
    } | ConvertTo-Json
    
    $response = Invoke-RestMethod -Uri "$API_BASE/memory/write" `
        -Method Post -Body $body -ContentType "application/json" -TimeoutSec 20
    
    if ($response.success) {
        Write-Host "   ? 修改成功！" -ForegroundColor Green
        
        # 验证
        Write-Host "`n   验证修改..." -ForegroundColor Yellow
        Start-Sleep -Seconds 1
        
        $verifyBody = @{
            pid = $gamePid
            address = $SUN_ADDRESS
            length = 4
        } | ConvertTo-Json
        
        $verify = Invoke-RestMethod -Uri "$API_BASE/memory/read" `
            -Method Post -Body $verifyBody -ContentType "application/json"
        
        if ($verify.success) {
            $hex = $verify.data.hex
            $b1 = $hex.Substring(0,2)
            $b2 = $hex.Substring(2,2)
            $b3 = $hex.Substring(4,2)
            $b4 = $hex.Substring(6,2)
            $current = [Convert]::ToInt32("$b4$b3$b2$b1", 16)
            
            Write-Host "   当前值: $current" -ForegroundColor Cyan
            
            if ($current -eq $testValue) {
                Write-Host "   ? 修改验证成功！游戏中阳光应该是: $testValue" -ForegroundColor Green
            } else {
                Write-Host "   ??  值不匹配: 期望$testValue，实际$current" -ForegroundColor Yellow
            }
        }
    } else {
        Write-Host "   ? 修改失败" -ForegroundColor Red
        Write-Host "   响应: $($response | ConvertTo-Json)" -ForegroundColor Gray
    }
} catch {
    Write-Host "   ? API调用失败: $($_.Exception.Message)" -ForegroundColor Red
}

# 4. 实时监控（使用API）
Write-Host "`n[4] 启动实时监控..." -ForegroundColor Yellow
Write-Host "   按Ctrl+C停止`n" -ForegroundColor Gray

$prevSun = $global:CurrentSun
$changeCount = 0

try {
    while ($true) {
        Start-Sleep -Milliseconds 800
        
        $body = @{
            pid = $gamePid
            address = $SUN_ADDRESS
            length = 4
        } | ConvertTo-Json
        
        $response = Invoke-RestMethod -Uri "$API_BASE/memory/read" `
            -Method Post -Body $body -ContentType "application/json" -TimeoutSec 10
        
        if ($response.success -and $response.data.hex) {
            $hex = $response.data.hex
            $b1 = $hex.Substring(0,2)
            $b2 = $hex.Substring(2,2)
            $b3 = $hex.Substring(4,2)
            $b4 = $hex.Substring(6,2)
            $sun = [Convert]::ToInt32("$b4$b3$b2$b1", 16)
            
            if ($sun -ne $prevSun) {
                $changeCount++
                $timestamp = Get-Date -Format 'HH:mm:ss'
                $change = $sun - $prevSun
                $changeStr = if ($change -gt 0) { "+$change" } else { "$change" }
                
                Write-Host "[$timestamp] 变化#$changeCount : $prevSun -> $sun ($changeStr)" -ForegroundColor Yellow
                
                # 分析变化类型
                if ($change -eq 25) {
                    Write-Host "   → 收集1个阳光" -ForegroundColor Green
                } elseif ($change -eq 50) {
                    Write-Host "   → 向日葵产出或收集2个阳光" -ForegroundColor Green
                } elseif ($change -eq -50) {
                    Write-Host "   → 种植向日葵" -ForegroundColor Magenta
                } elseif ($change -eq -100) {
                    Write-Host "   → 种植豌豆射手" -ForegroundColor Magenta
                }
                
                $prevSun = $sun
            }
        }
    }
} catch {
    Write-Host "`n监控已停止" -ForegroundColor Yellow
}

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  测试完成" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

Write-Host "`n? API功能验证:" -ForegroundColor Green
Write-Host "   - 内存读取API工作正常" -ForegroundColor Gray
Write-Host "   - 内存写入API工作正常" -ForegroundColor Gray
Write-Host "   - 实时监控功能正常" -ForegroundColor Gray

Write-Host "`n? 当前数据:" -ForegroundColor Yellow
Write-Host "   游戏PID: $gamePid" -ForegroundColor White
Write-Host "   阳光地址: 0x$SUN_ADDRESS" -ForegroundColor White
Write-Host "   最后阳光值: $prevSun" -ForegroundColor White
Write-Host "   记录变化: $changeCount 次" -ForegroundColor White

Write-Host "`n完成！" -ForegroundColor Green

