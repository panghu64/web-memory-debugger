# 指针链分析工具
# 目标: 分析阳光地址的指针链

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  指针链分析工具" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

# 配置
$API_BASE = "http://localhost:8080/api"
$TARGET_ADDRESS = "6D4662B22C"  # 阳光地址

# 获取游戏PID
Write-Host "`n[1] 获取游戏进程..." -ForegroundColor Yellow
$psOutput = adb shell "ps -A | grep pvz"
if (-not $psOutput) {
    Write-Host "   ? 游戏未运行，请先启动游戏" -ForegroundColor Red
    exit
}

$GamePid = ($psOutput -split "\s+")[1]
Write-Host "   ? 游戏PID: $GamePid" -ForegroundColor Green

# 读取目标地址的值
Write-Host "`n[2] 读取阳光地址的值..." -ForegroundColor Yellow
Write-Host "   地址: 0x$TARGET_ADDRESS" -ForegroundColor Cyan

try {
    $body = @{
        pid = [int]$GamePid
        address = $TARGET_ADDRESS
        length = 4
    } | ConvertTo-Json
    
    $response = Invoke-RestMethod -Uri "$API_BASE/memory/read" -Method Post -Body $body -ContentType "application/json" -TimeoutSec 15
    
    if ($response.success -and $response.data.hex) {
        $hexValue = $response.data.hex
        # 转换为整数（小端序）
        $bytes = $hexValue -split '(..)' | Where-Object { $_ }
        $sunValue = [Convert]::ToInt32($bytes[3] + $bytes[2] + $bytes[1] + $bytes[0], 16)
        
        Write-Host "   ? 成功读取" -ForegroundColor Green
        Write-Host "   Hex: $hexValue" -ForegroundColor Gray
        Write-Host "   阳光值: $sunValue" -ForegroundColor Cyan
        
        $global:CurrentSunValue = $sunValue
    } else {
        Write-Host "   ? 读取失败" -ForegroundColor Red
        exit
    }
} catch {
    Write-Host "   ??  读取失败: $($_.Exception.Message)" -ForegroundColor Yellow
    Write-Host "   提示: 确保应用正在运行且支持内存读取" -ForegroundColor Gray
}

# 获取内存映射
Write-Host "`n[3] 获取内存映射..." -ForegroundColor Yellow
try {
    $response = Invoke-RestMethod -Uri "$API_BASE/memory/maps?pid=$GamePid" -TimeoutSec 30
    if ($response.success) {
        $maps = $response.data
        Write-Host "   ? 内存区域数: $($maps.Count)" -ForegroundColor Green
        
        # 找到目标地址所在区域
        $targetAddrInt = [Convert]::ToInt64($TARGET_ADDRESS, 16)
        $targetRegion = $maps | Where-Object {
            $start = [Convert]::ToInt64($_.start, 16)
            $end = [Convert]::ToInt64($_.end, 16)
            $targetAddrInt -ge $start -and $targetAddrInt -lt $end
        }
        
        if ($targetRegion) {
            Write-Host "`n   目标地址所在区域:" -ForegroundColor Cyan
            Write-Host "   权限: $($targetRegion.perms)" -ForegroundColor Gray
            Write-Host "   范围: 0x$($targetRegion.start)-0x$($targetRegion.end)" -ForegroundColor Gray
            Write-Host "   路径: $($targetRegion.path)" -ForegroundColor Gray
            
            # 计算在区域中的偏移
            $offset = $targetAddrInt - [Convert]::ToInt64($targetRegion.start, 16)
            Write-Host "   偏移: +0x$($offset.ToString('X'))" -ForegroundColor Yellow
            
            $global:TargetRegion = $targetRegion
        } else {
            Write-Host "   ??  未找到目标地址所在区域" -ForegroundColor Yellow
        }
        
        # 找到libpvz.so的段
        $libpvz = $maps | Where-Object { $_.path -like "*libpvz.so" }
        Write-Host "`n   libpvz.so段信息:" -ForegroundColor Cyan
        $libpvz | ForEach-Object {
            $sizeMB = [math]::Round($_.size / 1MB, 2)
            Write-Host "   $($_.perms) | 0x$($_.start)-0x$($_.end) | ${sizeMB}MB" -ForegroundColor Gray
            
            # 保存数据段和代码段
            if ($_.perms -eq "rw-p") {
                $global:DataSegment = $_
            }
            if ($_.perms -eq "r-xp") {
                $global:CodeSegment = $_
            }
        }
        
        $global:AllMaps = $maps
    }
} catch {
    Write-Host "   ? 获取失败: $($_.Exception.Message)" -ForegroundColor Red
}

# 指针搜索策略
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  指针链分析策略" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

Write-Host "`n目标地址: 0x$TARGET_ADDRESS" -ForegroundColor Yellow
Write-Host "当前阳光值: $global:CurrentSunValue" -ForegroundColor Yellow

Write-Host "`n方法1: 在libpvz.so数据段搜索指针 ?" -ForegroundColor Cyan
Write-Host "   原理: 全局变量通常在.so的数据段中" -ForegroundColor Gray
Write-Host "   范围: 0x$($global:DataSegment.start)-0x$($global:DataSegment.end)" -ForegroundColor Gray
Write-Host "   大小: $([math]::Round($global:DataSegment.size / 1KB, 2))KB" -ForegroundColor Gray

Write-Host "`n方法2: 使用硬件断点追踪 ??" -ForegroundColor Cyan
Write-Host "   原理: 监控谁在访问这个地址" -ForegroundColor Gray
Write-Host "   需要: 设置硬件写入断点" -ForegroundColor Gray
Write-Host "   效果: 可以找到修改阳光的代码位置" -ForegroundColor Gray

Write-Host "`n方法3: 反汇编代码分析" -ForegroundColor Cyan
Write-Host "   原理: 分析游戏代码，找到阳光相关函数" -ForegroundColor Gray
Write-Host "   需要: Capstone反汇编" -ForegroundColor Gray

# 提供指针搜索命令
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  手动搜索指令（在IDA中）" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

Write-Host "`n在IDA Pro中搜索指向 0x$TARGET_ADDRESS 的指针:" -ForegroundColor Yellow
Write-Host "1. 打开libpvz.so" -ForegroundColor Gray
Write-Host "2. Alt+B (或 Search > Sequence of bytes)" -ForegroundColor Gray

# 生成小端序搜索字节
$addrInt = [Convert]::ToInt64($TARGET_ADDRESS, 16)
$byte1 = ($addrInt -band 0xFF).ToString("X2")
$byte2 = (($addrInt -shr 8) -band 0xFF).ToString("X2")
$byte3 = (($addrInt -shr 16) -band 0xFF).ToString("X2")
$byte4 = (($addrInt -shr 24) -band 0xFF).ToString("X2")
$byte5 = (($addrInt -shr 32) -band 0xFF).ToString("X2")

Write-Host "3. 搜索字节序列（小端序64位）:" -ForegroundColor Gray
Write-Host "   $byte1 $byte2 $byte3 $byte4 $byte5 00 00 00" -ForegroundColor Cyan
Write-Host "   或（如果是32位指针）:" -ForegroundColor Gray
Write-Host "   $byte1 $byte2 $byte3 $byte4" -ForegroundColor Cyan

# 提供ADB命令用于配合断点
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  配合断点的操作步骤" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

Write-Host "`n步骤1: 在游戏中执行操作（种植物、收集阳光）" -ForegroundColor Yellow

Write-Host "`n步骤2: 再次读取阳光值，看是否变化" -ForegroundColor Yellow
Write-Host "   命令: " -ForegroundColor Gray
Write-Host @"
   `$body = @{pid=$GamePid;address="$TARGET_ADDRESS";length=4} | ConvertTo-Json
   `$r = Invoke-RestMethod "http://localhost:8080/api/memory/read" -Method Post -Body `$body -ContentType "application/json"
   `$r.data.hex
"@ -ForegroundColor Cyan

Write-Host "`n步骤3: 使用Cheat Engine或IDA设置硬件断点" -ForegroundColor Yellow
Write-Host "   地址: 0x$TARGET_ADDRESS" -ForegroundColor Cyan
Write-Host "   类型: 写入断点（Write breakpoint）" -ForegroundColor Cyan
Write-Host "   大小: 4字节（DWORD）" -ForegroundColor Cyan

Write-Host "`n步骤4: 触发断点（收集阳光）" -ForegroundColor Yellow
Write-Host "   - 在游戏中收集阳光" -ForegroundColor Gray
Write-Host "   - 断点会停在修改阳光的代码处" -ForegroundColor Gray
Write-Host "   - 查看寄存器，找到基址" -ForegroundColor Gray

# 生成基址分析报告
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  基址分析（初步）" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

if ($global:TargetRegion) {
    $regionStart = [Convert]::ToInt64($global:TargetRegion.start, 16)
    $offset = [Convert]::ToInt64($TARGET_ADDRESS, 16) - $regionStart
    
    Write-Host "`n当前分析:" -ForegroundColor Yellow
    Write-Host "目标地址: 0x$TARGET_ADDRESS" -ForegroundColor White
    Write-Host "所在区域: $($global:TargetRegion.path)" -ForegroundColor White
    Write-Host "区域基址: 0x$($global:TargetRegion.start)" -ForegroundColor White
    Write-Host "偏移量: +0x$($offset.ToString('X'))" -ForegroundColor Cyan
    
    Write-Host "`n可能的指针公式:" -ForegroundColor Yellow
    Write-Host "[$($global:TargetRegion.path) + 0x$($offset.ToString('X'))]" -ForegroundColor Green
    
    if ($global:TargetRegion.path -like "*libpvz.so*") {
        Write-Host "`n? 地址在libpvz.so中，这是静态指针！" -ForegroundColor Green
        Write-Host "重启游戏后，只需要重新获取libpvz.so基址即可定位" -ForegroundColor Gray
    } else {
        Write-Host "`n??  地址在堆中，需要找指针链" -ForegroundColor Yellow
        Write-Host "需要在libpvz.so数据段中搜索指向此地址的指针" -ForegroundColor Gray
    }
}

# 保存分析结果
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  保存分析结果" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

$analysisReport = @"
指针链分析报告
生成时间: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')

目标信息:
- 地址: 0x$TARGET_ADDRESS
- 当前值: $global:CurrentSunValue
- 游戏PID: $GamePid

内存区域:
- 路径: $($global:TargetRegion.path)
- 权限: $($global:TargetRegion.perms)
- 基址: 0x$($global:TargetRegion.start)
- 偏移: +0x$(([Convert]::ToInt64($TARGET_ADDRESS, 16) - [Convert]::ToInt64($global:TargetRegion.start, 16)).ToString('X'))

libpvz.so信息:
- 代码段: 0x$($global:CodeSegment.start)
- 数据段: 0x$($global:DataSegment.start)

下一步行动:
1. 在IDA中搜索指针: $byte1 $byte2 $byte3 $byte4
2. 设置硬件写入断点: 0x$TARGET_ADDRESS
3. 触发断点（收集阳光）
4. 分析寄存器找基址

指针搜索范围:
- libpvz.so数据段: 0x$($global:DataSegment.start)-0x$($global:DataSegment.end)
- 大小: $([math]::Round($global:DataSegment.size / 1KB, 2))KB
"@

$reportFile = "pointer_analysis_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
$analysisReport | Out-File -FilePath $reportFile -Encoding UTF8
Write-Host "分析报告已保存: $reportFile" -ForegroundColor Green

# 交互式监控
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  实时监控" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

Write-Host "`n是否启动实时监控阳光值变化？(Y/N): " -ForegroundColor Yellow -NoNewline
$monitor = Read-Host

if ($monitor -eq 'Y' -or $monitor -eq 'y') {
    Write-Host "`n开始监控... (Ctrl+C停止)" -ForegroundColor Cyan
    Write-Host "请在游戏中收集阳光，观察值的变化`n" -ForegroundColor Gray
    
    $prevValue = $global:CurrentSunValue
    $iteration = 0
    
    while ($true) {
        Start-Sleep -Seconds 2
        $iteration++
        
        try {
            $body = @{
                pid = [int]$GamePid
                address = $TARGET_ADDRESS
                length = 4
            } | ConvertTo-Json
            
            $response = Invoke-RestMethod -Uri "$API_BASE/memory/read" -Method Post -Body $body -ContentType "application/json" -TimeoutSec 10
            
            if ($response.success -and $response.data.hex) {
                $hexValue = $response.data.hex
                $bytes = $hexValue -split '(..)' | Where-Object { $_ }
                $sunValue = [Convert]::ToInt32($bytes[3] + $bytes[2] + $bytes[1] + $bytes[0], 16)
                
                $timestamp = Get-Date -Format 'HH:mm:ss'
                
                if ($sunValue -ne $prevValue) {
                    $change = $sunValue - $prevValue
                    $changeStr = if ($change -gt 0) { "+$change" } else { "$change" }
                    Write-Host "[$timestamp] 阳光值变化: $prevValue -> $sunValue ($changeStr)" -ForegroundColor Yellow
                    $prevValue = $sunValue
                } else {
                    Write-Host "[$timestamp] #$iteration - 阳光值: $sunValue (无变化)" -ForegroundColor Gray
                }
            }
        } catch {
            Write-Host "读取失败，继续..." -ForegroundColor Red
        }
    }
}

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "分析完成！请查看报告文件：$reportFile" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan

