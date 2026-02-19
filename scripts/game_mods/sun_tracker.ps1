# 阳光追踪器 - 实时监控和分析

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  阳光追踪器 v1.0" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

$SUN_ADDRESS = "7043E320CC"  # 当前阳光地址
$GAME_PID = 6729
$APP_PATH = "/data/data/com.example.myapplication"
$MEMTOOL = "$APP_PATH/files/memtool_procmem"

# 读取阳光值
function Get-SunValue {
    $cmd = "su -c 'cd $APP_PATH/lib && LD_LIBRARY_PATH=. $MEMTOOL read $GAME_PID $SUN_ADDRESS 4'"
    $output = adb shell $cmd 2>&1 | Out-String
    
    if ($output -match "([0-9a-fA-F]{8})") {
        $hex = $matches[1]
        # 小端序转换
        $b1 = $hex.Substring(0,2)
        $b2 = $hex.Substring(2,2)
        $b3 = $hex.Substring(4,2)
        $b4 = $hex.Substring(6,2)
        
        $value = [Convert]::ToInt32("$b4$b3$b2$b1", 16)
        return $value
    }
    return $null
}

# 修改阳光值
function Set-SunValue {
    param([int]$Value)
    
    # 转换为小端序hex
    $hex = $Value.ToString("X8")
    $b1 = $hex.Substring(6,2)
    $b2 = $hex.Substring(4,2)
    $b3 = $hex.Substring(2,2)
    $b4 = $hex.Substring(0,2)
    $hexLE = "$b1$b2$b3$b4"
    
    $cmd = "su -c 'cd $APP_PATH/lib && LD_LIBRARY_PATH=. $MEMTOOL write $GAME_PID $SUN_ADDRESS $hexLE 4'"
    $output = adb shell $cmd 2>&1 | Out-String
    
    return $output
}

# 测试读取
Write-Host "`n[1] 测试读取..." -ForegroundColor Yellow
$currentSun = Get-SunValue
if ($currentSun -ne $null) {
    Write-Host "   ? 当前阳光: $currentSun" -ForegroundColor Green
} else {
    Write-Host "   ? 读取失败" -ForegroundColor Red
    exit
}

# 菜单
function Show-Menu {
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "当前阳光: $global:LastSunValue" -ForegroundColor White
    Write-Host "地址: 0x$SUN_ADDRESS" -ForegroundColor Gray
    Write-Host "PID: $GAME_PID" -ForegroundColor Gray
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "1. 读取当前阳光值" -ForegroundColor Yellow
    Write-Host "2. 修改阳光值" -ForegroundColor Yellow
    Write-Host "3. 实时监控（捕捉变化）" -ForegroundColor Yellow
    Write-Host "4. 查看地址所在内存区域" -ForegroundColor Yellow
    Write-Host "5. 搜索libpvz.so中的指针" -ForegroundColor Yellow
    Write-Host "0. 退出" -ForegroundColor Red
    Write-Host ""
}

$global:LastSunValue = $currentSun

do {
    Show-Menu
    $choice = Read-Host "请选择"
    
    switch ($choice) {
        "1" {
            Write-Host "`n读取阳光值..." -ForegroundColor Cyan
            $sun = Get-SunValue
            if ($sun -ne $null) {
                Write-Host "   当前阳光: $sun" -ForegroundColor Green
                $global:LastSunValue = $sun
            } else {
                Write-Host "   读取失败" -ForegroundColor Red
            }
            Read-Host "`n按Enter继续"
        }
        
        "2" {
            $newValue = Read-Host "`n请输入新的阳光值"
            Write-Host "修改阳光为: $newValue" -ForegroundColor Yellow
            
            $result = Set-SunValue -Value ([int]$newValue)
            Write-Host "   结果: $result" -ForegroundColor Gray
            
            Write-Host "`n验证修改..." -ForegroundColor Yellow
            Start-Sleep -Seconds 1
            $verify = Get-SunValue
            if ($verify -eq [int]$newValue) {
                Write-Host "   ? 修改成功！游戏中阳光应该显示: $newValue" -ForegroundColor Green
                $global:LastSunValue = $verify
            } else {
                Write-Host "   ??  验证值: $verify (可能未生效)" -ForegroundColor Yellow
            }
            
            Read-Host "`n按Enter继续"
        }
        
        "3" {
            Write-Host "`n========================================" -ForegroundColor Cyan
            Write-Host "  实时监控模式" -ForegroundColor Cyan
            Write-Host "========================================" -ForegroundColor Cyan
            Write-Host "`n提示: 在游戏中执行以下操作观察变化" -ForegroundColor Yellow
            Write-Host "   - 收集掉落的阳光（+25）" -ForegroundColor Gray
            Write-Host "   - 种植豌豆射手（-100）" -ForegroundColor Gray
            Write-Host "   - 种植向日葵（-50）" -ForegroundColor Gray
            Write-Host "`n开始监控... (Ctrl+C停止)`n" -ForegroundColor Cyan
            
            $prevSun = Get-SunValue
            $changeLog = @()
            
            try {
                while ($true) {
                    Start-Sleep -Milliseconds 500
                    
                    $currentSun = Get-SunValue
                    if ($currentSun -ne $null -and $currentSun -ne $prevSun) {
                        $timestamp = Get-Date -Format 'HH:mm:ss.fff'
                        $change = $currentSun - $prevSun
                        $changeStr = if ($change -gt 0) { "+$change" } else { "$change" }
                        
                        Write-Host "[$timestamp] $prevSun -> $currentSun ($changeStr)" -ForegroundColor Yellow
                        
                        $changeLog += @{
                            Time = $timestamp
                            From = $prevSun
                            To = $currentSun
                            Change = $change
                        }
                        
                        # 分析变化模式
                        if ($change -eq 25) {
                            Write-Host "   → 收集了1个阳光" -ForegroundColor Green
                        } elseif ($change -eq 50) {
                            Write-Host "   → 收集了2个阳光或向日葵产出" -ForegroundColor Green
                        } elseif ($change -eq -50) {
                            Write-Host "   → 种植了向日葵" -ForegroundColor Magenta
                        } elseif ($change -eq -100) {
                            Write-Host "   → 种植了豌豆射手" -ForegroundColor Magenta
                        } elseif ($change -eq -150) {
                            Write-Host "   → 种植了双发向日葵" -ForegroundColor Magenta
                        }
                        
                        $prevSun = $currentSun
                    }
                }
            } catch {
                Write-Host "`n监控已停止" -ForegroundColor Yellow
            }
            
            # 显示变化日志
            if ($changeLog.Count -gt 0) {
                Write-Host "`n--- 变化记录 ---" -ForegroundColor Cyan
                $changeLog | ForEach-Object {
                    Write-Host "$($_.Time) | $($_.From) -> $($_.To) ($(if($_.Change -gt 0){"+"})$($_.Change))" -ForegroundColor Gray
                }
            }
            
            Read-Host "`n按Enter继续"
        }
        
        "4" {
            Write-Host "`n查看地址所在内存区域..." -ForegroundColor Yellow
            
            # 获取内存映射
            $maps = adb shell "su -c 'cat /proc/$GAME_PID/maps'" | Out-String
            
            # 查找包含目标地址的区域
            $targetAddr = [Convert]::ToInt64($SUN_ADDRESS, 16)
            $found = $false
            
            $maps -split "`n" | ForEach-Object {
                if ($_ -match "([0-9a-f]+)-([0-9a-f]+)\s+([rwxp-]+)\s+[0-9a-f]+\s+[0-9a-f]+:[0-9a-f]+\s+\d+\s*(.*)") {
                    $start = [Convert]::ToInt64($matches[1], 16)
                    $end = [Convert]::ToInt64($matches[2], 16)
                    $perms = $matches[3]
                    $path = $matches[4].Trim()
                    
                    if ($targetAddr -ge $start -and $targetAddr -lt $end) {
                        $offset = $targetAddr - $start
                        $sizeMB = [math]::Round(($end - $start)/1MB, 2)
                        
                        Write-Host "`n   ? 找到目标区域!" -ForegroundColor Green
                        Write-Host "   权限: $perms" -ForegroundColor Cyan
                        Write-Host "   范围: 0x$($matches[1])-0x$($matches[2])" -ForegroundColor Cyan
                        Write-Host "   大小: ${sizeMB}MB" -ForegroundColor Cyan
                        Write-Host "   路径: $path" -ForegroundColor Cyan
                        Write-Host "   偏移: +0x$($offset.ToString('X'))" -ForegroundColor Yellow
                        
                        if ($path -like "*libpvz.so*") {
                            Write-Host "`n   ? 在libpvz.so中！可以找静态指针！" -ForegroundColor Green
                        } else {
                            Write-Host "`n   ??  在堆内存中（Java对象）" -ForegroundColor Yellow
                            Write-Host "   说明: 地址每次启动都变，需要找指针链" -ForegroundColor Gray
                        }
                        
                        $found = $true
                    }
                }
            }
            
            if (-not $found) {
                Write-Host "   ? 未找到该地址所在区域（地址可能无效）" -ForegroundColor Red
            }
            
            Read-Host "`n按Enter继续"
        }
        
        "5" {
            Write-Host "`n在libpvz.so数据段搜索指针..." -ForegroundColor Yellow
            
            # 获取数据段
            $dataSegLine = adb shell "su -c 'cat /proc/$GAME_PID/maps | grep libpvz.so | grep rw-p'" | Out-String
            
            if ($dataSegLine -match "([0-9a-f]+)-([0-9a-f]+)") {
                $dataStart = $matches[1]
                $dataEnd = $matches[2]
                
                Write-Host "   数据段: 0x$dataStart-0x$dataEnd" -ForegroundColor Cyan
                
                # 生成搜索字节（目标地址的小端序表示）
                $targetAddr = [Convert]::ToInt64($SUN_ADDRESS, 16)
                $searchBytes = @()
                for ($i = 0; $i -lt 8; $i++) {
                    $byte = ($targetAddr -shr ($i * 8)) -band 0xFF
                    $searchBytes += $byte.ToString("X2").ToLower()
                }
                
                Write-Host "   搜索字节序列: $($searchBytes -join ' ')" -ForegroundColor Cyan
                Write-Host "   前4字节: $($searchBytes[0..3] -join ' ')" -ForegroundColor Yellow
                
                Write-Host "`n   提示: 在Cheat Engine或IDA中手动搜索这些字节" -ForegroundColor Gray
                Write-Host "   范围: libpvz.so数据段 (0x$dataStart)" -ForegroundColor Gray
                
                # 尝试读取数据段前1KB
                Write-Host "`n   读取数据段前1KB进行演示..." -ForegroundColor Yellow
                $cmd = "su -c 'cd $APP_PATH/lib && LD_LIBRARY_PATH=. $MEMTOOL read $GAME_PID $dataStart 1024'"
                $output = adb shell $cmd 2>&1 | Out-String
                
                Write-Host "   前64字节:" -ForegroundColor Cyan
                $hexData = ($output -replace '\s+', '') -replace '[^0-9a-fA-F]', ''
                if ($hexData.Length -ge 128) {
                    $preview = $hexData.Substring(0,128)
                    for ($i = 0; $i -lt 128; $i += 32) {
                        Write-Host "   $($preview.Substring($i,32))" -ForegroundColor Gray
                    }
                }
                
                # 检查是否包含目标字节
                $pattern = $searchBytes[0..3] -join ''
                if ($hexData -match $pattern) {
                    Write-Host "`n   ? 在数据段中找到了目标字节序列！" -ForegroundColor Green
                } else {
                    Write-Host "`n   未在前1KB中找到，需要扫描整个数据段" -ForegroundColor Yellow
                }
            }
            
            Read-Host "`n按Enter继续"
        }
        
        "0" {
            Write-Host "`n退出监控..." -ForegroundColor Cyan
        }
        
        default {
            Write-Host "`n无效选择" -ForegroundColor Red
            Start-Sleep -Seconds 1
        }
    }
    
} while ($choice -ne "0")

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  分析完成" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

Write-Host "`n? 快速命令参考:" -ForegroundColor Yellow
Write-Host @"

# 读取阳光
adb shell "su -c 'cd $APP_PATH/lib && LD_LIBRARY_PATH=. $MEMTOOL read $GAME_PID $SUN_ADDRESS 4'"

# 修改阳光为9999 (0x270F → 0F 27 00 00)
adb shell "su -c 'cd $APP_PATH/lib && LD_LIBRARY_PATH=. $MEMTOOL write $GAME_PID $SUN_ADDRESS 0F270000 4'"

# 查看内存映射
adb shell "su -c 'cat /proc/$GAME_PID/maps | grep libpvz.so'"

"@ -ForegroundColor Gray

Write-Host "再见！" -ForegroundColor Green

