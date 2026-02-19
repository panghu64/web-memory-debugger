# 使用后端断点追踪指针链
# 交互式配合脚本

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  指针链追踪 - 断点配合模式" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

$TARGET_ADDRESS = "6D4662B22C"  # 阳光地址
$API_BASE = "http://localhost:8080/api"

# 获取游戏PID
Write-Host "`n[1] 获取游戏进程..." -ForegroundColor Yellow
$psOutput = adb shell "ps -A | grep pvz"
if (-not $psOutput) {
    Write-Host "   ? 游戏未运行" -ForegroundColor Red
    exit
}

$GamePid = ($psOutput -split "\s+")[1]
Write-Host "   ? 游戏PID: $GamePid" -ForegroundColor Green

# 获取libpvz.so信息
Write-Host "`n[2] 获取libpvz.so信息..." -ForegroundColor Yellow
try {
    $response = Invoke-RestMethod -Uri "$API_BASE/memory/maps?pid=$GamePid" -TimeoutSec 30
    if ($response.success) {
        $maps = $response.data
        $libpvz = $maps | Where-Object { $_.path -like "*libpvz.so" }
        
        $dataSegment = $libpvz | Where-Object { $_.perms -eq "rw-p" } | Select-Object -First 1
        $codeSegment = $libpvz | Where-Object { $_.perms -eq "r-xp" } | Select-Object -First 1
        
        Write-Host "   ? libpvz.so数据段: 0x$($dataSegment.start)" -ForegroundColor Green
        Write-Host "   ? libpvz.so代码段: 0x$($codeSegment.start)" -ForegroundColor Green
        
        $global:DataSegment = $dataSegment
        $global:CodeSegment = $codeSegment
    }
} catch {
    Write-Host "   ? 获取失败: $($_.Exception.Message)" -ForegroundColor Red
}

# 设置硬件断点
Write-Host "`n[3] 设置硬件写入断点..." -ForegroundColor Yellow
Write-Host "   目标地址: 0x$TARGET_ADDRESS" -ForegroundColor Cyan
Write-Host "   类型: 写入断点 (write)" -ForegroundColor Cyan
Write-Host "   大小: 4字节 (DWORD)" -ForegroundColor Cyan

try {
    $body = @{
        pid = [int]$GamePid
        address = $TARGET_ADDRESS
        type = "write"
        size = 4
    } | ConvertTo-Json
    
    Write-Host "`n   发送断点设置请求..." -ForegroundColor Gray
    $response = Invoke-RestMethod -Uri "$API_BASE/debug/watchpoint" `
        -Method Post -Body $body -ContentType "application/json" -TimeoutSec 30
    
    if ($response.success) {
        Write-Host "   ? 断点设置成功！" -ForegroundColor Green
        $global:BreakpointSet = $true
    } else {
        Write-Host "   ??  断点设置失败: $($response.message)" -ForegroundColor Yellow
        Write-Host "   提示: 这是实验性功能，可能不支持" -ForegroundColor Gray
        $global:BreakpointSet = $false
    }
} catch {
    Write-Host "   ??  断点功能不可用: $($_.Exception.Message)" -ForegroundColor Yellow
    Write-Host "   将使用替代方案（轮询监控）" -ForegroundColor Gray
    $global:BreakpointSet = $false
}

# 如果断点功能不可用，使用轮询方式
if (-not $global:BreakpointSet) {
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "  替代方案: 实时监控模式" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    
    Write-Host "`n这个方案会持续监控阳光值的变化" -ForegroundColor Yellow
    Write-Host "虽然不能直接定位代码，但可以帮助验证地址" -ForegroundColor Gray
    
    Write-Host "`n? 操作步骤:" -ForegroundColor Cyan
    Write-Host "1. 我会开始监控阳光值" -ForegroundColor White
    Write-Host "2. 您在游戏中收集阳光" -ForegroundColor White
    Write-Host "3. 观察值的变化" -ForegroundColor White
    Write-Host "4. 使用CE或其他工具搜索指针" -ForegroundColor White
    
    Write-Host "`n准备开始监控... (Ctrl+C停止)" -ForegroundColor Yellow
    Write-Host ""
    
    $APP_PATH = "/data/data/com.example.myapplication"
    $memtoolPath = "$APP_PATH/files/memtool_procmem"
    
    $prevValue = -1
    $changeCount = 0
    $iteration = 0
    
    while ($true) {
        $iteration++
        Start-Sleep -Seconds 1
        
        try {
            # 使用后端命令读取
            $cmd = "su -c 'cd $APP_PATH/lib && LD_LIBRARY_PATH=. $memtoolPath read $GamePid $TARGET_ADDRESS 4'"
            $output = adb shell $cmd 2>&1 | Out-String
            
            # 尝试解析输出
            if ($output -match "([0-9a-fA-F\s]{8,})") {
                $hexData = $matches[1].Trim() -replace '\s+', ''
                
                if ($hexData.Length -ge 8) {
                    $byte1 = $hexData.Substring(0,2)
                    $byte2 = $hexData.Substring(2,2)
                    $byte3 = $hexData.Substring(4,2)
                    $byte4 = $hexData.Substring(6,2)
                    
                    # 小端序转换
                    $sunValue = [Convert]::ToInt32("$byte4$byte3$byte2$byte1", 16)
                    
                    $timestamp = Get-Date -Format 'HH:mm:ss'
                    
                    if ($sunValue -ne $prevValue -and $prevValue -ne -1) {
                        $change = $sunValue - $prevValue
                        $changeStr = if ($change -gt 0) { "+$change" } else { "$change" }
                        $changeCount++
                        
                        Write-Host "[$timestamp] ? 阳光变化 #$changeCount : $prevValue -> $sunValue ($changeStr)" -ForegroundColor Yellow
                        Write-Host "   地址: 0x$TARGET_ADDRESS" -ForegroundColor Cyan
                        
                        # 建议下一步
                        if ($changeCount -eq 1) {
                            Write-Host "`n   ? 提示: 现在可以在CE中搜索这个值: $sunValue" -ForegroundColor Green
                            Write-Host "   然后添加地址到列表，右键 > Find what writes to this address" -ForegroundColor Gray
                        }
                        
                    } else {
                        if ($iteration % 5 -eq 0) {
                            Write-Host "[$timestamp] #$iteration - 阳光: $sunValue (监控中...)" -ForegroundColor DarkGray
                        }
                    }
                    
                    $prevValue = $sunValue
                }
            } else {
                if ($iteration -eq 1) {
                    Write-Host "   ??  无法读取内存，请确保:" -ForegroundColor Yellow
                    Write-Host "   1. SELinux已禁用: adb shell 'su -c getenforce'" -ForegroundColor Gray
                    Write-Host "   2. memtool_procmem存在且可执行" -ForegroundColor Gray
                    Write-Host "`n   将继续尝试..." -ForegroundColor Gray
                }
            }
        } catch {
            if ($iteration -eq 1) {
                Write-Host "   ? 读取失败: $($_.Exception.Message)" -ForegroundColor Red
            }
        }
    }
} else {
    # 断点设置成功，等待触发
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "  等待断点触发" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    
    Write-Host "`n? 下一步操作:" -ForegroundColor Yellow
    Write-Host "1. 在游戏中收集阳光" -ForegroundColor White
    Write-Host "2. 断点触发时会记录信息" -ForegroundColor White
    Write-Host "3. 分析寄存器找基址" -ForegroundColor White
    
    Write-Host "`n监控断点状态中..." -ForegroundColor Cyan
    Write-Host "准备在游戏中收集阳光..." -ForegroundColor Yellow
    
    # 轮询检查断点是否触发
    $checkCount = 0
    while ($true) {
        $checkCount++
        Start-Sleep -Seconds 2
        
        try {
            # 查询断点状态（如果API支持）
            $status = Invoke-RestMethod -Uri "$API_BASE/debug/watchpoint?pid=$GamePid" -TimeoutSec 10
            
            if ($status.triggered) {
                Write-Host "`n? 断点触发！" -ForegroundColor Green
                Write-Host "`n断点信息:" -ForegroundColor Cyan
                Write-Host $($status.data | ConvertTo-Json -Depth 5) -ForegroundColor White
                
                # 分析寄存器
                if ($status.data.registers) {
                    Write-Host "`n? 寄存器分析:" -ForegroundColor Yellow
                    $status.data.registers | ForEach-Object {
                        Write-Host "   $($_.name) = 0x$($_.value)" -ForegroundColor Gray
                    }
                }
                
                # 分析指令
                if ($status.data.instruction) {
                    Write-Host "`n? 触发指令:" -ForegroundColor Yellow
                    Write-Host "   $($status.data.instruction)" -ForegroundColor Cyan
                }
                
                break
            } else {
                if ($checkCount % 5 -eq 0) {
                    Write-Host "   [检查 #$checkCount] 等待断点触发..." -ForegroundColor DarkGray
                    Write-Host "   请在游戏中收集阳光" -ForegroundColor Gray
                }
            }
        } catch {
            if ($checkCount -eq 1) {
                Write-Host "`n   ??  无法查询断点状态" -ForegroundColor Yellow
                Write-Host "   将切换到监控模式..." -ForegroundColor Gray
            }
            
            # 如果无法查询状态，回退到监控模式
            if ($checkCount -gt 10) {
                Write-Host "`n   切换到替代方案..." -ForegroundColor Yellow
                $global:BreakpointSet = $false
                break
            }
        }
    }
}

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  分析完成" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

# 保存结果
if ($global:BreakpointSet) {
    Write-Host "`n? 已获取断点信息" -ForegroundColor Green
    Write-Host "请根据寄存器信息分析指针链" -ForegroundColor Yellow
} else {
    Write-Host "`n? 监控完成" -ForegroundColor Green
    Write-Host "请结合CE的'Find what writes'功能追踪指针" -ForegroundColor Yellow
}

Write-Host "`n? 手动方法（如果自动化不工作）:" -ForegroundColor Cyan
Write-Host @"

方法1: 使用Cheat Engine
================================
1. 在CE中附加到游戏进程 (PID: $GamePid)
2. 搜索当前阳光值
3. 添加地址: 0x$TARGET_ADDRESS
4. 右键 > Find out what writes to this address
5. 收集阳光，触发记录
6. 查看写入代码和寄存器

方法2: 使用IDA Pro
================================
1. 附加到进程: Debugger > Attach (PID: $GamePid)
2. 跳转: G > $TARGET_ADDRESS
3. 设置断点: 右键 > Add breakpoint > Hardware, write
4. 继续执行: F9
5. 收集阳光触发断点
6. 查看反汇编和寄存器

方法3: 在libpvz.so数据段搜索
================================
数据段: 0x$($global:DataSegment.start)
搜索字节: 2C B2 66 D4 06 00 00 00
在IDA中: Alt+B搜索
"@ -ForegroundColor Gray

Write-Host "`n? 目标:" -ForegroundColor Yellow
Write-Host "找到从libpvz.so到阳光地址的完整路径" -ForegroundColor White

Write-Host "`n完成！" -ForegroundColor Green

