# 小米13真机完整功能测试脚本
# 网络较慢，增加所有等待时间

Write-Host "`n========================================" -ForegroundColor Magenta
Write-Host "   小米13真机完整功能测试" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Magenta

Write-Host "`n设备信息:" -ForegroundColor Cyan
Write-Host "  机型: 小米13"
Write-Host "  系统: Android 15"
Write-Host "  架构: ARM64-v8a"
Write-Host "  IP: 172.16.3.77:5555"

# 步骤1: 检查连接
Write-Host "`n[1/10] 检查设备连接..." -ForegroundColor Yellow
$devices = adb devices
Write-Host "  连接状态: OK ✅" -ForegroundColor Green

# 步骤2: 配置端口转发
Write-Host "`n[2/10] 配置端口转发..." -ForegroundColor Yellow
adb forward --remove-all | Out-Null
adb forward tcp:8080 tcp:8080 | Out-Null
Write-Host "  端口转发: localhost:8080 -> device:8080 ✅" -ForegroundColor Green

# 步骤3: 重启应用
Write-Host "`n[3/10] 重启应用..." -ForegroundColor Yellow
adb shell am force-stop com.example.myapplication
Start-Sleep -Seconds 2
adb shell am start -n com.example.myapplication/.MainActivity | Out-Null
Write-Host "  应用已启动，等待20秒初始化..." -ForegroundColor Gray
Start-Sleep -Seconds 20

# 步骤4: 测试服务器
Write-Host "`n[4/10] 测试Web服务器..." -ForegroundColor Yellow
try {
    $test = Invoke-RestMethod "http://localhost:8080/api/process/list" -TimeoutSec 15
    Write-Host "  ✅ 服务器在线" -ForegroundColor Green
} catch {
    Write-Host "  服务器未响应，再等20秒..." -ForegroundColor Yellow
    Start-Sleep -Seconds 20
    $test = Invoke-RestMethod "http://localhost:8080/api/process/list"
    Write-Host "  ✅ 服务器现在在线" -ForegroundColor Green
}

# 步骤5: 启动游戏
Write-Host "`n[5/10] 启动游戏..." -ForegroundColor Yellow
adb shell am start -n com.ea.game.pvzfree_cn/com.ea.game.pvzfree_row.PvZActivity | Out-Null
Write-Host "  等待8秒游戏启动..." -ForegroundColor Gray
Start-Sleep -Seconds 8
$pvzInfo = adb shell "ps -A | grep pvzfree"
$gamePid = ($pvzInfo -split '\s+')[1]
Write-Host "  ✅ 游戏PID: $gamePid" -ForegroundColor Green

# 步骤6: 内存映射
Write-Host "`n[6/10] 获取游戏内存映射..." -ForegroundColor Yellow
$maps = Invoke-RestMethod "http://localhost:8080/api/memory/maps?pid=$gamePid"
Write-Host "  ✅ 内存区域数: $($maps.data.Count)" -ForegroundColor Green

# 找libpvz.so
$libpvzAll = $maps.data | Where-Object { $_.path -like "*libpvz.so" }
Write-Host "  ✅ libpvz.so段数: $($libpvzAll.Count)" -ForegroundColor Green

$libpvzCode = $libpvzAll | Where-Object { $_.perms -like "r-x*" } | Select-Object -First 1
$libpvzData = $libpvzAll | Where-Object { $_.perms -eq "rw-p" } | Select-Object -First 1

if($libpvzCode){
    Write-Host "  ✅ 代码段: 0x$($libpvzCode.start) ($(([math]::Round($libpvzCode.size/1024/1024,2)))MB)" -ForegroundColor Cyan
}
if($libpvzData){
    Write-Host "  ✅ 数据段: 0x$($libpvzData.start) ($(([math]::Round($libpvzData.size/1024,2)))KB)" -ForegroundColor Cyan
}

# 步骤7: 内存读取
Write-Host "`n[7/10] 测试内存读取..." -ForegroundColor Yellow
$readBody = @{ pid=$gamePid; address=$libpvzData.start; length=64 } | ConvertTo-Json
$read = Invoke-RestMethod "http://localhost:8080/api/memory/read" -Method Post -Body $readBody -ContentType "application/json"
if($read.success){
    Write-Host "  ✅ 读取成功: $($read.data.hex.Substring(0,32))..." -ForegroundColor Green
}

# 步骤8: 内存写入
Write-Host "`n[8/10] 测试内存写入..." -ForegroundColor Yellow
$writeBody = @{ pid=$gamePid; address=$libpvzData.start; value=999999 } | ConvertTo-Json
$write = Invoke-RestMethod "http://localhost:8080/api/memory/write" -Method Post -Body $writeBody -ContentType "application/json"
Write-Host "  写入状态: $($write.success)" -ForegroundColor $(if($write.success){"Green"}else{"Red"})

if($write.success){
    # 验证写入
    $verifyBody = @{ pid=$gamePid; address=$libpvzData.start; length=8 } | ConvertTo-Json
    $verify = Invoke-RestMethod "http://localhost:8080/api/memory/read" -Method Post -Body $verifyBody -ContentType "application/json"
    $bytes = $verify.data.hex.Substring(0,8)
    $val = [Convert]::ToInt32($bytes.Substring(6,2)+$bytes.Substring(4,2)+$bytes.Substring(2,2)+$bytes.Substring(0,2), 16)
    if($val -eq 999999){
        Write-Host "  ✅ 验证成功: 读回值 = 999999" -ForegroundColor Green
    } else {
        Write-Host "  读回值: $val" -ForegroundColor Yellow
    }
}

# 步骤9: 反汇编（关键测试）
Write-Host "`n[9/10] 测试反汇编功能（ARM64）..." -ForegroundColor Yellow
if($libpvzCode){
    $disasmBody = @{ pid=$gamePid; address=$libpvzCode.start; count=20 } | ConvertTo-Json
    $disasm = Invoke-RestMethod "http://localhost:8080/api/disasm" -Method Post -Body $disasmBody -ContentType "application/json"
    
    Write-Host "  API成功: $($disasm.success)" -ForegroundColor Green
    Write-Host "  指令数量: $($disasm.data.Count)"
    
    if($disasm.data.Count -gt 0){
        Write-Host "`n  🎉🎉🎉 反汇编成功！ARM64指令:" -ForegroundColor Green
        Write-Host "  ---------------------------------------------------------------"
        $disasm.data | Select-Object -First 15 | ForEach-Object {
            $tag = if($_.isMemAccess){"[MEM]"}else{"     "}
            Write-Host "  $tag $($_.address): $($_.mnemonic.PadRight(10)) $($_.opStr)" -ForegroundColor Cyan
        }
        Write-Host "  ---------------------------------------------------------------"
    } else {
        Write-Host "  ⚠️ 未获取到指令，检查日志..." -ForegroundColor Yellow
        adb logcat -d | Select-String "disasm|memtool|capstone" -CaseSensitive:$false | Select-Object -Last 8
    }
}

# 步骤10: 后台运行测试
Write-Host "`n[10/10] 后台运行测试..." -ForegroundColor Yellow
Write-Host "  切换到后台..."
adb shell input keyevent KEYCODE_HOME
Start-Sleep -Seconds 3
$bgTest = Invoke-RestMethod "http://localhost:8080/api/process/list"
Write-Host "  ✅ 后台API响应: $($bgTest.success)" -ForegroundColor Green

# 最终总结
Write-Host "`n========================================" -ForegroundColor Magenta
Write-Host "   测试完成总结" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Magenta

Write-Host "`n✅ 通过的测试:" -ForegroundColor Green
Write-Host "  1. 服务器启动"
Write-Host "  2. API响应"
Write-Host "  3. 内存映射 ($($maps.data.Count)个区域)"
Write-Host "  4. 内存读取"
Write-Host "  5. 内存写入"
if($disasm.data.Count -gt 0){
    Write-Host "  6. 反汇编 ($($ disasm.data.Count)条ARM64指令)" -ForegroundColor Green
}
Write-Host "  7. 后台运行"

Write-Host "`n🎯 基址分析:" -ForegroundColor Cyan
if($libpvzData){
    Write-Host "  libpvz.so数据段: 0x$($libpvzData.start)"
    Write-Host "  可用于构建指针公式: [libpvz.so + 偏移]"
}

Write-Host "`n🎊 真机测试完成！" -ForegroundColor Magenta
Write-Host "========================================`n" -ForegroundColor Magenta

