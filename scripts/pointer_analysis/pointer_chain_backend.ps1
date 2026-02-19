# 使用后端命令直接分析指针链
# 绕过API，直接调用memtool

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  指针链分析 - 后端命令模式" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

$TARGET_ADDRESS = "6D4662B22C"  # 阳光地址
$APP_PATH = "/data/data/com.example.myapplication"

# 1. 获取游戏PID
Write-Host "`n[1] 获取游戏PID..." -ForegroundColor Yellow
$psOutput = adb shell "ps -A | grep pvz"
if (-not $psOutput) {
    Write-Host "   ? 游戏未运行" -ForegroundColor Red
    exit
}

$GamePid = ($psOutput -split "\s+")[1]
Write-Host "   ? 游戏PID: $GamePid" -ForegroundColor Green

# 2. 检查memtool工具
Write-Host "`n[2] 检查memtool工具..." -ForegroundColor Yellow
$arch = adb shell "getprop ro.product.cpu.abi" | Out-String
$arch = $arch.Trim()
Write-Host "   CPU架构: $arch" -ForegroundColor Cyan

$memtoolPath = "$APP_PATH/files/memtool_procmem"
$result = adb shell "su -c 'ls -l $memtoolPath'" 2>&1
if ($result -match "memtool_procmem") {
    Write-Host "   ? memtool_procmem 存在" -ForegroundColor Green
    Write-Host "   路径: $memtoolPath" -ForegroundColor Gray
} else {
    Write-Host "   ??  memtool_procmem 未找到" -ForegroundColor Yellow
    $memtoolPath = "$APP_PATH/files/memtool"
    Write-Host "   尝试使用: $memtoolPath" -ForegroundColor Gray
}

# 3. 读取阳光地址
Write-Host "`n[3] 读取阳光地址..." -ForegroundColor Yellow
Write-Host "   地址: 0x$TARGET_ADDRESS" -ForegroundColor Cyan
Write-Host "   PID: $GamePid" -ForegroundColor Cyan

# 构建命令
$cmd = "su -c 'cd $APP_PATH/lib && LD_LIBRARY_PATH=. $memtoolPath read $GamePid $TARGET_ADDRESS 4'"
Write-Host "`n   执行命令:" -ForegroundColor Gray
Write-Host "   $cmd" -ForegroundColor DarkGray

$output = adb shell $cmd 2>&1 | Out-String
Write-Host "`n   输出:" -ForegroundColor Gray
Write-Host $output -ForegroundColor White

# 解析输出
if ($output -match "([0-9a-fA-F\s]{11,})") {
    $hexData = $matches[1].Trim() -replace '\s+', ''
    Write-Host "   ? 读取成功！" -ForegroundColor Green
    Write-Host "   Hex数据: $hexData" -ForegroundColor Cyan
    
    # 转换为整数（小端序）
    if ($hexData.Length -ge 8) {
        $byte1 = $hexData.Substring(0,2)
        $byte2 = $hexData.Substring(2,2)
        $byte3 = $hexData.Substring(4,2)
        $byte4 = $hexData.Substring(6,2)
        
        # 小端序转换
        $intValue = [Convert]::ToInt32("$byte4$byte3$byte2$byte1", 16)
        Write-Host "   阳光值: $intValue" -ForegroundColor Green
        $global:CurrentSunValue = $intValue
    }
} else {
    Write-Host "   ? 读取失败或格式错误" -ForegroundColor Red
    Write-Host "   原始输出: $output" -ForegroundColor Gray
}

# 4. 获取内存映射
Write-Host "`n[4] 获取内存映射..." -ForegroundColor Yellow
$maps = adb shell "su -c 'cat /proc/$GamePid/maps'" | Out-String

Write-Host "   关键内存区域:" -ForegroundColor Cyan
$maps -split "`n" | ForEach-Object {
    if ($_ -match "([0-9a-f]+)-([0-9a-f]+)\s+([rwxp-]+).*?(libpvz\.so|heap)?") {
        $start = $matches[1]
        $end = $matches[2]
        $perms = $matches[3]
        $path = if ($matches[4]) { $matches[4] } else { "[anon]" }
        
        Write-Host "   $perms | 0x$start-0x$end | $path" -ForegroundColor Gray
        
        # 检查目标地址是否在此区域
        $startInt = [Convert]::ToInt64($start, 16)
        $endInt = [Convert]::ToInt64($end, 16)
        $targetInt = [Convert]::ToInt64($TARGET_ADDRESS, 16)
        
        if ($targetInt -ge $startInt -and $targetInt -lt $endInt) {
            Write-Host "   ★ 目标地址在此区域！" -ForegroundColor Yellow
            $global:TargetRegion = @{
                Start = $start
                End = $end
                Perms = $perms
                Path = $path
            }
        }
        
        # 保存libpvz.so数据段
        if ($path -eq "libpvz.so" -and $perms -eq "rw-p") {
            $global:LibpvzDataSegment = @{
                Start = $start
                End = $end
            }
        }
    }
}

# 5. 分析目标地址位置
Write-Host "`n[5] 分析目标地址位置..." -ForegroundColor Yellow

if ($global:TargetRegion) {
    $regionStart = [Convert]::ToInt64($global:TargetRegion.Start, 16)
    $targetAddr = [Convert]::ToInt64($TARGET_ADDRESS, 16)
    $offset = $targetAddr - $regionStart
    
    Write-Host "`n   目标地址: 0x$TARGET_ADDRESS" -ForegroundColor White
    Write-Host "   所在区域: $($global:TargetRegion.Path)" -ForegroundColor White
    Write-Host "   区域基址: 0x$($global:TargetRegion.Start)" -ForegroundColor White
    Write-Host "   偏移量: +0x$($offset.ToString('X'))" -ForegroundColor Cyan
    
    if ($global:TargetRegion.Path -eq "libpvz.so") {
        Write-Host "`n   ? 这是静态指针！在libpvz.so中！" -ForegroundColor Green
        Write-Host "   公式: [libpvz.so + 0x$($offset.ToString('X'))]" -ForegroundColor Green
    } else {
        Write-Host "`n   ??  这是堆地址，需要查找指针链" -ForegroundColor Yellow
    }
}

# 6. 在libpvz.so数据段搜索指向目标地址的指针
Write-Host "`n[6] 搜索指向目标地址的指针..." -ForegroundColor Yellow

if ($global:LibpvzDataSegment) {
    Write-Host "   搜索范围: libpvz.so数据段" -ForegroundColor Cyan
    Write-Host "   基址: 0x$($global:LibpvzDataSegment.Start)" -ForegroundColor Gray
    Write-Host "   结束: 0x$($global:LibpvzDataSegment.End)" -ForegroundColor Gray
    
    $segmentSize = [Convert]::ToInt64($global:LibpvzDataSegment.End, 16) - [Convert]::ToInt64($global:LibpvzDataSegment.Start, 16)
    Write-Host "   大小: $([math]::Round($segmentSize/1KB, 2))KB" -ForegroundColor Gray
    
    # 生成搜索命令
    # 转换目标地址为小端序字节
    $targetBytes = @()
    $addr = [Convert]::ToInt64($TARGET_ADDRESS, 16)
    for ($i = 0; $i -lt 8; $i++) {
        $byte = ($addr -shr ($i * 8)) -band 0xFF
        $targetBytes += $byte.ToString("X2")
    }
    
    $searchBytes = $targetBytes -join ' '
    Write-Host "`n   搜索字节序列（小端序）:" -ForegroundColor Cyan
    Write-Host "   $searchBytes" -ForegroundColor White
    
    Write-Host "`n   提示: 可以使用hexdump或在IDA中搜索这些字节" -ForegroundColor Yellow
    
    # 生成IDA搜索命令
    Write-Host "`n   IDA Pro搜索:" -ForegroundColor Cyan
    Write-Host "   1. Alt+B (Search > Sequence of bytes)" -ForegroundColor Gray
    Write-Host "   2. 输入: $($targetBytes[0..3] -join ' ')" -ForegroundColor White
    Write-Host "   3. 搜索范围: .data 段" -ForegroundColor Gray
}

# 7. 提供手动分析步骤
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  下一步操作指南" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

Write-Host "`n方法1: 使用硬件断点（最有效）???" -ForegroundColor Yellow
Write-Host @"
   1. 在IDA中附加到进程 (PID: $GamePid)
   2. 设置硬件写入断点: 0x$TARGET_ADDRESS
   3. 在游戏中收集阳光
   4. 断点触发时查看:
      - 当前指令（谁在写入？）
      - 寄存器值（基址在哪？）
      - 调用栈（从哪调用的？）
"@ -ForegroundColor Gray

Write-Host "`n方法2: 读取候选指针（需要搜索结果）" -ForegroundColor Yellow
Write-Host @"
   假设在 0x$($global:LibpvzDataSegment.Start) 找到指针:
   
   # 读取指针值
   $cmd = "su -c 'cd $APP_PATH/lib && LD_LIBRARY_PATH=. $memtoolPath read $GamePid POINTER_ADDRESS 8'"
   adb shell $cmd
   
   # 验证指针是否指向目标地址
"@ -ForegroundColor Gray

Write-Host "`n方法3: 实时监控阳光变化" -ForegroundColor Yellow
Write-Host @"
   while (`$true) {
       `$output = adb shell "su -c 'cd $APP_PATH/lib && LD_LIBRARY_PATH=. $memtoolPath read $GamePid $TARGET_ADDRESS 4'"
       # 解析并显示阳光值
       Start-Sleep -Seconds 1
   }
"@ -ForegroundColor Gray

# 8. 生成辅助命令脚本
Write-Host "`n[7] 生成辅助命令..." -ForegroundColor Yellow

$helperScript = @"
# 指针链分析辅助命令
# 游戏PID: $GamePid
# 阳光地址: 0x$TARGET_ADDRESS

# 读取阳光值
function Read-Sun {
    `$output = adb shell "su -c 'cd $APP_PATH/lib && LD_LIBRARY_PATH=. $memtoolPath read $GamePid $TARGET_ADDRESS 4'"
    Write-Host `$output
}

# 读取指定地址（8字节指针）
function Read-Pointer {
    param([string]`$Address)
    `$output = adb shell "su -c 'cd $APP_PATH/lib && LD_LIBRARY_PATH=. $memtoolPath read $GamePid `$Address 8'"
    Write-Host `$output
}

# 写入阳光值（测试用）
function Write-Sun {
    param([int]`$Value)
    `$hexValue = `$Value.ToString("X8")
    `$output = adb shell "su -c 'cd $APP_PATH/lib && LD_LIBRARY_PATH=. $memtoolPath write $GamePid $TARGET_ADDRESS `$hexValue'"
    Write-Host `$output
}

# 使用示例:
# Read-Sun
# Read-Pointer "6DB77C8100"
# Write-Sun 9999
"@

$helperScript | Out-File -FilePath "pointer_helper.ps1" -Encoding UTF8
Write-Host "   ? 已生成: pointer_helper.ps1" -ForegroundColor Green

# 9. 保存分析报告
$reportContent = @"
指针链分析报告（后端命令模式）
生成时间: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')

========================================
基本信息
========================================
游戏PID: $GamePid
阳光地址: 0x$TARGET_ADDRESS
当前阳光值: $global:CurrentSunValue

========================================
内存区域分析
========================================
$(if ($global:TargetRegion) {
@"
目标地址所在区域:
  路径: $($global:TargetRegion.Path)
  权限: $($global:TargetRegion.Perms)
  范围: 0x$($global:TargetRegion.Start)-0x$($global:TargetRegion.End)
  偏移: +0x$(([Convert]::ToInt64($TARGET_ADDRESS, 16) - [Convert]::ToInt64($global:TargetRegion.Start, 16)).ToString('X'))
"@
})

$(if ($global:LibpvzDataSegment) {
@"
libpvz.so数据段:
  基址: 0x$($global:LibpvzDataSegment.Start)
  结束: 0x$($global:LibpvzDataSegment.End)
  大小: $([math]::Round(([Convert]::ToInt64($global:LibpvzDataSegment.End, 16) - [Convert]::ToInt64($global:LibpvzDataSegment.Start, 16))/1KB, 2))KB
"@
})

========================================
搜索字节序列
========================================
目标地址的小端序表示:
$(
$targetBytes = @()
$addr = [Convert]::ToInt64($TARGET_ADDRESS, 16)
for ($i = 0; $i -lt 8; $i++) {
    $byte = ($addr -shr ($i * 8)) -band 0xFF
    $targetBytes += $byte.ToString("X2")
}
"32位: $($targetBytes[0..3] -join ' ')
64位: $($targetBytes -join ' ')"
)

========================================
下一步操作
========================================
1. 在IDA Pro中搜索这些字节
2. 设置硬件断点: 0x$TARGET_ADDRESS
3. 使用 pointer_helper.ps1 中的函数
4. 收集阳光时观察变化

========================================
快速命令
========================================
读取阳光:
adb shell "su -c 'cd $APP_PATH/lib && LD_LIBRARY_PATH=. $memtoolPath read $GamePid $TARGET_ADDRESS 4'"

写入阳光（测试）:
adb shell "su -c 'cd $APP_PATH/lib && LD_LIBRARY_PATH=. $memtoolPath write $GamePid $TARGET_ADDRESS 000027 10'"

查看内存映射:
adb shell "su -c 'cat /proc/$GamePid/maps | grep libpvz.so'"
"@

$reportFile = "pointer_analysis_backend_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
$reportContent | Out-File -FilePath $reportFile -Encoding UTF8
Write-Host "   ? 已生成报告: $reportFile" -ForegroundColor Green

# 10. 总结
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  分析完成！" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

Write-Host "`n? 已完成:" -ForegroundColor Green
Write-Host "   - 确认阳光地址有效" -ForegroundColor Gray
Write-Host "   - 定位内存区域" -ForegroundColor Gray
Write-Host "   - 生成搜索字节序列" -ForegroundColor Gray
Write-Host "   - 创建辅助命令脚本" -ForegroundColor Gray

Write-Host "`n? 生成的文件:" -ForegroundColor Yellow
Write-Host "   - $reportFile" -ForegroundColor White
Write-Host "   - pointer_helper.ps1" -ForegroundColor White

Write-Host "`n? 下一步:" -ForegroundColor Yellow
Write-Host "   1. 使用IDA Pro设置硬件断点" -ForegroundColor Gray
Write-Host "   2. 或者加载 pointer_helper.ps1 使用辅助函数" -ForegroundColor Gray
Write-Host "   3. 在游戏中触发阳光变化" -ForegroundColor Gray
Write-Host "   4. 记录断点信息，构建指针链" -ForegroundColor Gray

Write-Host "`n? 快速测试读取:" -ForegroundColor Cyan
Write-Host "   . .\pointer_helper.ps1" -ForegroundColor White
Write-Host "   Read-Sun" -ForegroundColor White

Write-Host "`n完成！" -ForegroundColor Green

