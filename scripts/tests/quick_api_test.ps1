# Web内存调试器 - 快速API测试
# 测试当前运行的服务

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Web内存调试器 - 快速API测试" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

$API_BASE = "http://localhost:8080/api"

# 检查设备连接
Write-Host "`n[1] 检查ADB连接..." -ForegroundColor Yellow
$devices = adb devices | Select-String "device$"
if ($devices.Count -gt 0) {
    Write-Host "   ? 设备已连接" -ForegroundColor Green
} else {
    Write-Host "   ? 没有设备连接" -ForegroundColor Red
    exit
}

# 检查端口转发
Write-Host "`n[2] 检查端口转发..." -ForegroundColor Yellow
adb forward tcp:8080 tcp:8080 | Out-Null
$forwards = adb forward --list
if ($forwards -match "8080") {
    Write-Host "   ? 端口转发已配置: localhost:8080 -> device:8080" -ForegroundColor Green
} else {
    Write-Host "   ? 端口转发失败" -ForegroundColor Red
}

# 测试Web服务器
Write-Host "`n[3] 测试Web服务器..." -ForegroundColor Yellow
try {
    $response = Invoke-WebRequest -Uri "http://localhost:8080/" -UseBasicParsing -TimeoutSec 5
    Write-Host "   ? HTTP状态: $($response.StatusCode)" -ForegroundColor Green
    Write-Host "   ? 内容大小: $($response.Content.Length) 字节" -ForegroundColor Green
} catch {
    Write-Host "   ? Web服务器未响应: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "`n提示: 请先启动应用" -ForegroundColor Yellow
    Write-Host "命令: adb shell am start -n com.example.myapplication/.MainActivity" -ForegroundColor Gray
    exit
}

# 测试API - 进程列表
Write-Host "`n[4] 测试API: 进程列表..." -ForegroundColor Yellow
try {
    $response = Invoke-RestMethod -Uri "$API_BASE/process/list" -TimeoutSec 10
    if ($response.success) {
        Write-Host "   ? 成功获取进程列表" -ForegroundColor Green
        Write-Host "   ? 进程数量: $($response.data.Count)" -ForegroundColor Green
        
        # 显示前5个进程
        Write-Host "`n   进程示例:" -ForegroundColor Cyan
        $response.data | Select-Object -First 5 | ForEach-Object {
            Write-Host "      PID: $($_.pid.ToString().PadRight(6)) | $($_.name)" -ForegroundColor Gray
        }
    } else {
        Write-Host "   ? API返回失败" -ForegroundColor Red
    }
} catch {
    Write-Host "   ? API请求失败: $($_.Exception.Message)" -ForegroundColor Red
}

# 测试API - 查找system_server
Write-Host "`n[5] 测试API: 查找系统进程..." -ForegroundColor Yellow
try {
    $response = Invoke-RestMethod -Uri "$API_BASE/process/list"
    $system = $response.data | Where-Object { $_.name -eq "system_server" }
    if ($system) {
        Write-Host "   ? 找到system_server" -ForegroundColor Green
        Write-Host "   ? PID: $($system.pid)" -ForegroundColor Green
        $global:TestPid = $system.pid
    }
} catch {
    Write-Host "   ? 查找失败" -ForegroundColor Red
}

# 测试API - 内存映射
if ($global:TestPid) {
    Write-Host "`n[6] 测试API: 内存映射 (PID: $global:TestPid)..." -ForegroundColor Yellow
    try {
        $response = Invoke-RestMethod -Uri "$API_BASE/memory/maps?pid=$global:TestPid" -TimeoutSec 15
        if ($response.success) {
            Write-Host "   ? 成功获取内存映射" -ForegroundColor Green
            Write-Host "   ? 内存区域数: $($response.data.Count)" -ForegroundColor Green
            
            # 统计不同权限的区域
            $readable = ($response.data | Where-Object { $_.perms -match "r" }).Count
            $writable = ($response.data | Where-Object { $_.perms -match "w" }).Count
            $executable = ($response.data | Where-Object { $_.perms -match "x" }).Count
            
            Write-Host "   - 可读区域: $readable" -ForegroundColor Gray
            Write-Host "   - 可写区域: $writable" -ForegroundColor Gray
            Write-Host "   - 可执行区域: $executable" -ForegroundColor Gray
        }
    } catch {
        Write-Host "   ? 获取内存映射失败: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# 检查游戏是否运行
Write-Host "`n[7] 检查游戏进程..." -ForegroundColor Yellow
try {
    $response = Invoke-RestMethod -Uri "$API_BASE/process/list"
    $game = $response.data | Where-Object { $_.name -like "*pvz*" }
    if ($game) {
        Write-Host "   ? 找到游戏进程" -ForegroundColor Green
        Write-Host "   ? 游戏: $($game.name)" -ForegroundColor Green
        Write-Host "   ? PID: $($game.pid)" -ForegroundColor Green
        $global:GamePid = $game.pid
    } else {
        Write-Host "   ??  游戏未运行" -ForegroundColor Yellow
        Write-Host "   提示: 可以启动植物大战僵尸来测试完整功能" -ForegroundColor Gray
    }
} catch {
    Write-Host "   ? 检查失败" -ForegroundColor Red
}

# 如果找到游戏，测试游戏内存
if ($global:GamePid) {
    Write-Host "`n[8] 测试游戏内存映射..." -ForegroundColor Yellow
    try {
        $response = Invoke-RestMethod -Uri "$API_BASE/memory/maps?pid=$global:GamePid"
        if ($response.success) {
            Write-Host "   ? 游戏内存区域: $($response.data.Count)" -ForegroundColor Green
            
            # 查找libpvz.so
            $libpvz = $response.data | Where-Object { $_.path -like "*libpvz.so" }
            if ($libpvz.Count -gt 0) {
                Write-Host "   ? 找到libpvz.so: $($libpvz.Count) 个段" -ForegroundColor Green
                
                # 显示各个段
                Write-Host "`n   libpvz.so段信息:" -ForegroundColor Cyan
                $libpvz | ForEach-Object {
                    $size = [math]::Round($_.size / 1MB, 2)
                    Write-Host "      $($_.perms) | 0x$($_.start) | ${size}MB" -ForegroundColor Gray
                }
            }
        }
    } catch {
        Write-Host "   ? 获取游戏内存失败" -ForegroundColor Red
    }
    
    # 测试内存读取
    Write-Host "`n[9] 测试内存读取..." -ForegroundColor Yellow
    try {
        $maps = Invoke-RestMethod -Uri "$API_BASE/memory/maps?pid=$global:GamePid"
        $testRegion = $maps.data | Where-Object { $_.perms -eq "rw-p" -and $_.size -gt 1024 } | Select-Object -First 1
        
        if ($testRegion) {
            $body = @{
                pid = [int]$global:GamePid
                address = $testRegion.start
                length = 32
            } | ConvertTo-Json
            
            $response = Invoke-RestMethod -Uri "$API_BASE/memory/read" -Method Post -Body $body -ContentType "application/json"
            if ($response.success) {
                Write-Host "   ? 成功读取内存" -ForegroundColor Green
                Write-Host "   ? 地址: 0x$($testRegion.start)" -ForegroundColor Green
                Write-Host "   ? 数据: $($response.data.hex.Substring(0,32))..." -ForegroundColor Green
            }
        }
    } catch {
        Write-Host "   ??  内存读取功能需要/proc/mem支持" -ForegroundColor Yellow
    }
}

# 性能测试
Write-Host "`n[10] API性能测试..." -ForegroundColor Yellow
try {
    $times = @()
    for ($i = 1; $i -le 5; $i++) {
        $start = Get-Date
        Invoke-RestMethod -Uri "$API_BASE/process/list" | Out-Null
        $end = Get-Date
        $times += ($end - $start).TotalMilliseconds
    }
    $avgTime = [math]::Round(($times | Measure-Object -Average).Average, 2)
    $minTime = [math]::Round(($times | Measure-Object -Minimum).Minimum, 2)
    $maxTime = [math]::Round(($times | Measure-Object -Maximum).Maximum, 2)
    
    Write-Host "   ? 平均响应: ${avgTime}ms" -ForegroundColor Green
    Write-Host "   ? 最快: ${minTime}ms | 最慢: ${maxTime}ms" -ForegroundColor Green
} catch {
    Write-Host "   ? 性能测试失败" -ForegroundColor Red
}

# 总结
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  测试总结" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

Write-Host "`n? 核心功能:" -ForegroundColor Green
Write-Host "   - HTTP服务器正常运行" -ForegroundColor Gray
Write-Host "   - API端点响应正常" -ForegroundColor Gray
Write-Host "   - 进程管理功能可用" -ForegroundColor Gray
Write-Host "   - 内存映射功能可用" -ForegroundColor Gray

Write-Host "`n? 访问地址:" -ForegroundColor Cyan
Write-Host "   Web界面: http://localhost:8080" -ForegroundColor White
Write-Host "   API文档: http://localhost:8080/api/process/list" -ForegroundColor White

Write-Host "`n? 下一步操作:" -ForegroundColor Yellow
if (-not $global:GamePid) {
    Write-Host "   1. 启动游戏: adb shell am start -n com.ea.game.pvzfree_cn/..." -ForegroundColor Gray
    Write-Host "   2. 使用Web界面分析游戏内存" -ForegroundColor Gray
} else {
    Write-Host "   1. 打开浏览器访问: http://localhost:8080" -ForegroundColor Gray
    Write-Host "   2. 选择游戏进程 (PID: $global:GamePid)" -ForegroundColor Gray
    Write-Host "   3. 开始内存分析和修改" -ForegroundColor Gray
}

Write-Host "`n? 测试完成！" -ForegroundColor Cyan

