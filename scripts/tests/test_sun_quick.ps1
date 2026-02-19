# 快速测试阳光值读写
$API_BASE = "http://localhost:8080"
$GamePID = 11001
$Address = "703BB3550C"

Write-Host "`n=== 测试阳光值读写 ===" -ForegroundColor Cyan

# 读取当前值
Write-Host "`n1. 读取当前阳光值..." -ForegroundColor Yellow
try {
    $body = @{
        pid = $GamePID
        address = $Address
        length = 4
    } | ConvertTo-Json
    
    $response = Invoke-RestMethod "$API_BASE/api/memory/read" -Method Post -Body $body -ContentType "application/json" -TimeoutSec 3
    
    if ($response.success) {
        $hex = $response.data.hex
        Write-Host "   原始hex: $hex" -ForegroundColor White
        
        # 小端序转换 - 正确的4字节转换
        $bytes = [byte[]]@(
            [Convert]::ToByte($hex.Substring(0,2), 16),
            [Convert]::ToByte($hex.Substring(2,2), 16),
            [Convert]::ToByte($hex.Substring(4,2), 16),
            [Convert]::ToByte($hex.Substring(6,2), 16)
        )
        $value = [BitConverter]::ToInt32($bytes, 0)
        Write-Host "   当前阳光值: $value" -ForegroundColor Green
    } else {
        Write-Host "   读取失败: $($response.error)" -ForegroundColor Red
        exit 1
    }
} catch {
    Write-Host "   读取异常: $_" -ForegroundColor Red
    exit 1
}

# 设置新值
Write-Host "`n2. 设置阳光值为 9999..." -ForegroundColor Yellow
try {
    $body = @{
        pid = $GamePID
        address = $Address
        value = 9999
    } | ConvertTo-Json
    
    $response = Invoke-RestMethod "$API_BASE/api/memory/write" -Method Post -Body $body -ContentType "application/json" -TimeoutSec 3
    
    if ($response.success) {
        Write-Host "   设置成功!" -ForegroundColor Green
    } else {
        Write-Host "   设置失败: $($response.error)" -ForegroundColor Red
        exit 1
    }
} catch {
    Write-Host "   设置异常: $_" -ForegroundColor Red
    exit 1
}

# 验证新值
Write-Host "`n3. 验证新值..." -ForegroundColor Yellow
Start-Sleep -Milliseconds 500
try {
    $body = @{
        pid = $GamePID
        address = $Address
        length = 4
    } | ConvertTo-Json
    
    $response = Invoke-RestMethod "$API_BASE/api/memory/read" -Method Post -Body $body -ContentType "application/json" -TimeoutSec 3
    
    if ($response.success) {
        $hex = $response.data.hex
        $bytes = [byte[]]@(
            [Convert]::ToByte($hex.Substring(0,2), 16),
            [Convert]::ToByte($hex.Substring(2,2), 16),
            [Convert]::ToByte($hex.Substring(4,2), 16),
            [Convert]::ToByte($hex.Substring(6,2), 16)
        )
        $value = [BitConverter]::ToInt32($bytes, 0)
        
        if ($value -eq 9999) {
            Write-Host "   验证成功! 当前值: $value" -ForegroundColor Green
            Write-Host "`n? 所有测试通过!" -ForegroundColor Green
        } else {
            Write-Host "   验证失败! 期望: 9999, 实际: $value" -ForegroundColor Red
        }
    }
} catch {
    Write-Host "   验证异常: $_" -ForegroundColor Red
}

Write-Host ""

