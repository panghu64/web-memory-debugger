# 后端配合查找指针链
# 使用memtool命令直接操作

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  后端指针链查找工具" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

$TARGET_ADDRESS = "6D4662B22C"  # 阳光地址
$APP_PATH = "/data/data/com.example.myapplication"

# 1. 获取游戏PID
Write-Host "`n[1] 获取游戏进程..." -ForegroundColor Yellow
$psOutput = adb shell "ps -A | grep pvz"
if (-not $psOutput) {
    Write-Host "   ? 游戏未运行" -ForegroundColor Red
    exit
}

$GamePid = ($psOutput -split "\s+")[1]
Write-Host "   ? 游戏PID: $GamePid" -ForegroundColor Green

# 2. 测试后端读取
Write-Host "`n[2] 测试后端读取功能..." -ForegroundColor Yellow

$memtoolPath = "$APP_PATH/files/memtool_procmem"

# 先测试能否读取
$testCmd = "su -c 'cd $APP_PATH/lib && LD_LIBRARY_PATH=. $memtoolPath read $GamePid $TARGET_ADDRESS 4'"
Write-Host "   执行: memtool read..." -ForegroundColor Gray

$output = adb shell $testCmd 2>&1 | Out-String
Write-Host $output

if ($output -match "([0-9a-fA-F]{2}\s){3,}") {
    Write-Host "   ? 读取成功！" -ForegroundColor Green
    
    # 解析阳光值
    $hexData = ($output -replace '\s+', '') -replace '[^0-9a-fA-F]', ''
    if ($hexData.Length -ge 8) {
        $byte1 = $hexData.Substring(0,2)
        $byte2 = $hexData.Substring(2,2)
        $byte3 = $hexData.Substring(4,2)
        $byte4 = $hexData.Substring(6,2)
        
        $sunValue = [Convert]::ToInt32("$byte4$byte3$byte2$byte1", 16)
        Write-Host "   当前阳光值: $sunValue" -ForegroundColor Cyan
        $global:CanRead = $true
        $global:CurrentSun = $sunValue
    }
} else {
    Write-Host "   ? 读取失败" -ForegroundColor Red
    Write-Host "   输出: $output" -ForegroundColor Gray
    $global:CanRead = $false
}

# 3. 获取libpvz.so信息
Write-Host "`n[3] 获取libpvz.so段信息..." -ForegroundColor Yellow
$mapsOutput = adb shell "su -c 'cat /proc/$GamePid/maps | grep libpvz.so'" | Out-String

$libpvzSegments = @()
$mapsOutput -split "`n" | ForEach-Object {
    if ($_ -match "([0-9a-f]+)-([0-9a-f]+)\s+([rwxp-]+)") {
        $segment = @{
            Start = $matches[1]
            End = $matches[2]
            Perms = $matches[3]
        }
        $libpvzSegments += $segment
        
        $sizeMB = [math]::Round(([Convert]::ToInt64($segment.End, 16) - [Convert]::ToInt64($segment.Start, 16))/1MB, 2)
        Write-Host "   $($segment.Perms) | 0x$($segment.Start)-0x$($segment.End) | ${sizeMB}MB" -ForegroundColor Gray
        
        if ($segment.Perms -eq "rw-p") {
            $global:DataSegment = $segment
        }
    }
}

Write-Host "`n   数据段用于搜索: 0x$($global:DataSegment.Start)-0x$($global:DataSegment.End)" -ForegroundColor Cyan

# 4. 交互式配合流程
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  交互式配合流程" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

Write-Host "`n我会通过后端命令配合您操作，请按提示执行：`n" -ForegroundColor Yellow

# 功能菜单
function Show-Menu {
    Write-Host "`n--- 操作菜单 ---" -ForegroundColor Cyan
    Write-Host "1. 读取当前阳光值" -ForegroundColor White
    Write-Host "2. 修改阳光值（测试）" -ForegroundColor White
    Write-Host "3. 实时监控阳光变化" -ForegroundColor White
    Write-Host "4. 在数据段搜索指向阳光的指针" -ForegroundColor White
    Write-Host "5. 读取指定地址（检查指针）" -ForegroundColor White
    Write-Host "6. 反汇编代码段（查找访问代码）" -ForegroundColor White
    Write-Host "0. 退出" -ForegroundColor Red
    Write-Host ""
}

# 读取阳光值
function Read-Sun {
    $cmd = "su -c 'cd $APP_PATH/lib && LD_LIBRARY_PATH=. $memtoolPath read $GamePid $TARGET_ADDRESS 4'"
    $output = adb shell $cmd 2>&1 | Out-String
    
    if ($output -match "([0-9a-fA-F]{2}\s){3,}") {
        $hexData = ($output -replace '\s+', '') -replace '[^0-9a-fA-F]', ''
        if ($hexData.Length -ge 8) {
            $bytes = @($hexData.Substring(0,2), $hexData.Substring(2,2), $hexData.Substring(4,2), $hexData.Substring(6,2))
            $sunValue = [Convert]::ToInt32("$($bytes[3])$($bytes[2])$($bytes[1])$($bytes[0])", 16)
            Write-Host "   当前阳光: $sunValue" -ForegroundColor Green
            return $sunValue
        }
    }
    Write-Host "   读取失败" -ForegroundColor Red
    return $null
}

# 修改阳光值
function Write-Sun {
    param([int]$Value)
    
    # 转换为小端序hex
    $hex = $Value.ToString("X8")
    $byte1 = $hex.Substring(6,2)
    $byte2 = $hex.Substring(4,2)
    $byte3 = $hex.Substring(2,2)
    $byte4 = $hex.Substring(0,2)
    $hexLE = "$byte1$byte2$byte3$byte4"
    
    $cmd = "su -c 'cd $APP_PATH/lib && LD_LIBRARY_PATH=. $memtoolPath write $GamePid $TARGET_ADDRESS $hexLE 4'"
    $output = adb shell $cmd 2>&1 | Out-String
    
    Write-Host "   写入值: $Value (0x$hexLE)" -ForegroundColor Cyan
    Write-Host "   结果: $output" -ForegroundColor Gray
}

# 实时监控
function Monitor-Sun {
    Write-Host "`n开始监控... (Ctrl+C停止)" -ForegroundColor Yellow
    Write-Host "请在游戏中收集阳光，我会记录变化`n" -ForegroundColor Gray
    
    $prevValue = -1
    $changes = @()
    
    while ($true) {
        Start-Sleep -Milliseconds 500
        
        $cmd = "su -c 'cd $APP_PATH/lib && LD_LIBRARY_PATH=. $memtoolPath read $GamePid $TARGET_ADDRESS 4'"
        $output = adb shell $cmd 2>&1 | Out-String
        
        if ($output -match "([0-9a-fA-F]{2}\s){3,}") {
            $hexData = ($output -replace '\s+', '') -replace '[^0-9a-fA-F]', ''
            if ($hexData.Length -ge 8) {
                $bytes = @($hexData.Substring(0,2), $hexData.Substring(2,2), $hexData.Substring(4,2), $hexData.Substring(6,2))
                $sunValue = [Convert]::ToInt32("$($bytes[3])$($bytes[2])$($bytes[1])$($bytes[0])", 16)
                
                if ($sunValue -ne $prevValue -and $prevValue -ne -1) {
                    $timestamp = Get-Date -Format 'HH:mm:ss.fff'
                    $change = $sunValue - $prevValue
                    $changeStr = if ($change -gt 0) { "+$change" } else { "$change" }
                    
                    Write-Host "[$timestamp] 阳光变化: $prevValue -> $sunValue ($changeStr)" -ForegroundColor Yellow
                    
                    $changes += @{
                        Time = $timestamp
                        From = $prevValue
                        To = $sunValue
                        Change = $change
                    }
                    
                    # 建议
                    if ($changes.Count -eq 1) {
                        Write-Host "`n   ? 提示: 记录了第一次变化！" -ForegroundColor Green
                        Write-Host "   现在可以在游戏中多次收集/消耗阳光" -ForegroundColor Gray
                        Write-Host "   以验证地址稳定性`n" -ForegroundColor Gray
                    }
                }
                
                $prevValue = $sunValue
            }
        }
    }
}

# 在数据段搜索指针
function Search-Pointer {
    Write-Host "`n搜索指向阳光地址的指针..." -ForegroundColor Yellow
    Write-Host "   目标地址: 0x$TARGET_ADDRESS" -ForegroundColor Cyan
    Write-Host "   搜索范围: libpvz.so数据段" -ForegroundColor Cyan
    
    # 生成搜索字节（小端序）
    $addr = [Convert]::ToInt64($TARGET_ADDRESS, 16)
    $searchBytes = @()
    for ($i = 0; $i -lt 8; $i++) {
        $byte = ($addr -shr ($i * 8)) -band 0xFF
        $searchBytes += $byte.ToString("X2")
    }
    
    Write-Host "   搜索字节: $($searchBytes -join ' ')" -ForegroundColor Cyan
    
    Write-Host "`n   ??  内存搜索需要读取整个数据段（~200KB）" -ForegroundColor Yellow
    Write-Host "   这需要多次memtool读取调用" -ForegroundColor Gray
    Write-Host "   估计时间: 1-2分钟" -ForegroundColor Gray
    
    $confirm = Read-Host "`n   是否继续? (Y/N)"
    if ($confirm -ne 'Y' -and $confirm -ne 'y') {
        return
    }
    
    # 读取数据段内存
    $segmentStart = [Convert]::ToInt64($global:DataSegment.Start, 16)
    $segmentEnd = [Convert]::ToInt64($global:DataSegment.End, 16)
    $segmentSize = $segmentEnd - $segmentStart
    
    Write-Host "`n   读取数据段 ($(([math]::Round($segmentSize/1KB, 2)))KB)..." -ForegroundColor Yellow
    
    # 分块读取（每次4KB）
    $chunkSize = 4096
    $foundPointers = @()
    
    for ($offset = 0; $offset -lt $segmentSize; $offset += $chunkSize) {
        $currentAddr = ($segmentStart + $offset).ToString("X")
        $readSize = [Math]::Min($chunkSize, $segmentSize - $offset)
        
        $cmd = "su -c 'cd $APP_PATH/lib && LD_LIBRARY_PATH=. $memtoolPath read $GamePid $currentAddr $readSize'"
        $output = adb shell $cmd 2>&1 | Out-String
        
        # 在输出中搜索目标字节序列
        $hexData = ($output -replace '\s+', '') -replace '[^0-9a-fA-F]', ''
        $searchPattern = $searchBytes[0..3] -join ''  # 先搜索前4字节
        
        if ($hexData -match $searchPattern) {
            $foundPointers += "0x$currentAddr"
            Write-Host "   ? 找到可能的指针: 0x$currentAddr" -ForegroundColor Green
        }
        
        # 进度显示
        if (($offset / $chunkSize) % 10 -eq 0) {
            $progress = [math]::Round(($offset / $segmentSize) * 100, 1)
            Write-Host "   进度: $progress%" -ForegroundColor DarkGray
        }
    }
    
    Write-Host "`n   搜索完成！" -ForegroundColor Green
    Write-Host "   找到 $($foundPointers.Count) 个可能的指针" -ForegroundColor Cyan
    
    if ($foundPointers.Count -gt 0) {
        Write-Host "`n   候选指针地址:" -ForegroundColor Yellow
        $foundPointers | ForEach-Object {
            Write-Host "   - $_" -ForegroundColor White
        }
    }
}

# 读取指定地址
function Read-Address {
    param([string]$Address, [int]$Length = 8)
    
    Write-Host "`n读取地址: 0x$Address" -ForegroundColor Yellow
    
    $cmd = "su -c 'cd $APP_PATH/lib && LD_LIBRARY_PATH=. $memtoolPath read $GamePid $Address $Length'"
    $output = adb shell $cmd 2>&1 | Out-String
    
    Write-Host "   输出: $output" -ForegroundColor Gray
    
    # 尝试解析为指针
    if ($output -match "([0-9a-fA-F]{2}\s){7,}") {
        $hexData = ($output -replace '\s+', '') -replace '[^0-9a-fA-F]', ''
        if ($hexData.Length -ge 16) {
            # 解析64位指针（小端序）
            $bytes = @()
            for ($i = 0; $i -lt 16; $i += 2) {
                $bytes += $hexData.Substring($i, 2)
            }
            $ptrValue = ""
            for ($i = 7; $i -ge 0; $i--) {
                $ptrValue += $bytes[$i]
            }
            Write-Host "   指针值: 0x$ptrValue" -ForegroundColor Cyan
            
            # 检查是否指向目标地址
            if ($ptrValue -match $TARGET_ADDRESS.Substring(0,8)) {
                Write-Host "   ? 这个指针指向目标地址！" -ForegroundColor Green
            }
        }
    }
}

# 反汇编代码段
function Disasm-Code {
    Write-Host "`n反汇编libpvz.so代码段..." -ForegroundColor Yellow
    
    # 使用API反汇编
    $API_BASE = "http://localhost:8080/api"
    
    # 找一个可能包含阳光访问代码的地方
    $codeStart = $global:CodeSegment.Start
    $testAddr = ([Convert]::ToInt64($codeStart, 16) + 0x100000).ToString("x")  # 偏移1MB处
    
    Write-Host "   测试地址: 0x$testAddr" -ForegroundColor Cyan
    
    try {
        $body = @{
            pid = [int]$GamePid
            address = $testAddr
            count = 20
        } | ConvertTo-Json
        
        $response = Invoke-RestMethod -Uri "$API_BASE/disasm" -Method Post -Body $body -ContentType "application/json" -TimeoutSec 20
        
        if ($response.success -and $response.data.Count -gt 0) {
            Write-Host "   ? 反汇编成功！" -ForegroundColor Green
            Write-Host "`n   指令:" -ForegroundColor Cyan
            $response.data | Select-Object -First 10 | ForEach-Object {
                Write-Host "   $($_.address): $($_.mnemonic.PadRight(6)) $($_.opStr)" -ForegroundColor Gray
            }
        } else {
            Write-Host "   ??  反汇编返回空" -ForegroundColor Yellow
        }
    } catch {
        Write-Host "   ? 反汇编失败: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# 主循环
if ($global:CanRead) {
    Write-Host "`n? 后端读取功能正常，可以开始分析！" -ForegroundColor Green
    
    do {
        Show-Menu
        $choice = Read-Host "请选择操作"
        
        switch ($choice) {
            "1" {
                Write-Host "`n读取阳光值..." -ForegroundColor Yellow
                $sun = Read-Sun
                if ($sun) {
                    Write-Host "   当前阳光: $sun" -ForegroundColor Green
                }
            }
            
            "2" {
                $newValue = Read-Host "`n请输入新的阳光值"
                Write-Host "修改阳光为: $newValue" -ForegroundColor Yellow
                Write-Sun -Value ([int]$newValue)
                
                Write-Host "`n验证修改..." -ForegroundColor Gray
                Start-Sleep -Seconds 1
                $sun = Read-Sun
            }
            
            "3" {
                Write-Host "`n提示: 监控期间请在游戏中操作" -ForegroundColor Yellow
                Write-Host "   - 收集阳光（观察增加）" -ForegroundColor Gray
                Write-Host "   - 种植植物（观察减少）" -ForegroundColor Gray
                Write-Host "`n按Ctrl+C停止监控" -ForegroundColor Cyan
                Start-Sleep -Seconds 2
                
                Monitor-Sun
            }
            
            "4" {
                Search-Pointer
            }
            
            "5" {
                $addr = Read-Host "`n请输入要读取的地址（16进制，不含0x）"
                $len = Read-Host "读取长度（字节数，默认8）"
                if (-not $len) { $len = 8 }
                
                Read-Address -Address $addr -Length ([int]$len)
            }
            
            "6" {
                Disasm-Code
            }
            
            "0" {
                Write-Host "`n再见！" -ForegroundColor Cyan
                break
            }
            
            default {
                Write-Host "`n无效选择" -ForegroundColor Red
            }
        }
        
        if ($choice -ne "0" -and $choice -ne "3") {
            Read-Host "`n按Enter继续"
        }
        
    } while ($choice -ne "0")
    
} else {
    Write-Host "`n========================================" -ForegroundColor Red
    Write-Host "  后端读取功能不可用" -ForegroundColor Red
    Write-Host "========================================" -ForegroundColor Red
    
    Write-Host "`n可能的原因:" -ForegroundColor Yellow
    Write-Host "1. memtool_procmem未正确配置" -ForegroundColor Gray
    Write-Host "2. libcapstone.so未加载" -ForegroundColor Gray
    Write-Host "3. SELinux限制（虽然已禁用）" -ForegroundColor Gray
    Write-Host "4. 权限问题" -ForegroundColor Gray
    
    Write-Host "`n手动测试命令:" -ForegroundColor Cyan
    Write-Host "adb shell `"su -c 'cd $APP_PATH/lib && LD_LIBRARY_PATH=. $memtoolPath read $GamePid $TARGET_ADDRESS 4'`"" -ForegroundColor White
    
    Write-Host "`n建议:" -ForegroundColor Yellow
    Write-Host "- 使用Cheat Engine的'Find what writes'功能" -ForegroundColor Gray
    Write-Host "- 或使用GameGuardian直接搜索修改" -ForegroundColor Gray
}

Write-Host "`n分析工具退出" -ForegroundColor Cyan

