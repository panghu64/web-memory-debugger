# Web内存调试器 - 测试菜单

function Show-Menu {
    Clear-Host
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "  Web内存调试器 - 测试菜单" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "1. 检查ADB连接" -ForegroundColor Yellow
    Write-Host "2. 启动应用" -ForegroundColor Yellow
    Write-Host "3. 快速API测试" -ForegroundColor Yellow
    Write-Host "4. 启动游戏并测试内存" -ForegroundColor Yellow
    Write-Host "5. 打开Web界面" -ForegroundColor Yellow
    Write-Host "6. 查看应用日志" -ForegroundColor Yellow
    Write-Host "7. 重启应用" -ForegroundColor Yellow
    Write-Host "8. 查看测试报告" -ForegroundColor Yellow
    Write-Host "0. 退出" -ForegroundColor Red
    Write-Host ""
}

do {
    Show-Menu
    $choice = Read-Host "请选择"
    
    switch ($choice) {
        "1" {
            Write-Host "`n检查ADB连接..." -ForegroundColor Cyan
            $devices = adb devices
            Write-Host $devices
            
            adb forward tcp:8080 tcp:8080
            Write-Host "端口转发已配置: localhost:8080 -> device:8080" -ForegroundColor Green
            
            Read-Host "`n按Enter继续"
        }
        
        "2" {
            Write-Host "`n启动应用..." -ForegroundColor Cyan
            adb shell am start -n com.example.myapplication/.MainActivity
            Write-Host "应用已启动，等待20秒..." -ForegroundColor Yellow
            Start-Sleep -Seconds 20
            Write-Host "完成！" -ForegroundColor Green
            
            Read-Host "`n按Enter继续"
        }
        
        "3" {
            Write-Host "`n运行快速API测试..." -ForegroundColor Cyan
            powershell -ExecutionPolicy Bypass -File quick_api_test.ps1
            
            Read-Host "`n按Enter继续"
        }
        
        "4" {
            Write-Host "`n启动游戏..." -ForegroundColor Cyan
            adb shell am start -n com.ea.game.pvzfree_cn/com.ea.game.pvzfree_row.PvZActivity
            Write-Host "游戏已启动，等待5秒..." -ForegroundColor Yellow
            Start-Sleep -Seconds 5
            
            Write-Host "`n运行游戏内存测试..." -ForegroundColor Cyan
            powershell -ExecutionPolicy Bypass -File test_game_memory.ps1
            
            Read-Host "`n按Enter继续"
        }
        
        "5" {
            Write-Host "`n打开Web界面..." -ForegroundColor Cyan
            Start-Process "http://localhost:8080"
            Write-Host "已在浏览器中打开 http://localhost:8080" -ForegroundColor Green
            
            Read-Host "`n按Enter继续"
        }
        
        "6" {
            Write-Host "`n查看应用日志（Ctrl+C停止）..." -ForegroundColor Cyan
            Write-Host "过滤关键字: MemoryDebug" -ForegroundColor Gray
            Write-Host ""
            adb logcat | Select-String "MemoryDebug"
        }
        
        "7" {
            Write-Host "`n重启应用..." -ForegroundColor Cyan
            adb shell am force-stop com.example.myapplication
            Write-Host "已停止应用" -ForegroundColor Yellow
            Start-Sleep -Seconds 2
            adb shell am start -n com.example.myapplication/.MainActivity
            Write-Host "应用已启动，等待20秒..." -ForegroundColor Yellow
            Start-Sleep -Seconds 20
            Write-Host "完成！" -ForegroundColor Green
            
            Read-Host "`n按Enter继续"
        }
        
        "8" {
            Write-Host "`n打开测试报告..." -ForegroundColor Cyan
            if (Test-Path "测试报告_20251023.md") {
                notepad "测试报告_20251023.md"
            } else {
                Write-Host "测试报告不存在" -ForegroundColor Red
            }
            
            Read-Host "`n按Enter继续"
        }
        
        "0" {
            Write-Host "`n再见！" -ForegroundColor Cyan
            exit
        }
        
        default {
            Write-Host "`n无效选择！" -ForegroundColor Red
            Start-Sleep -Seconds 1
        }
    }
} while ($choice -ne "0")

