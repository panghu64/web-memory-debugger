# ���ڴ��������ָ��
param(
    [int]$ProcessPID = 11001,
    [string]$StartAddr = "70cf792000",
    [string]$EndAddr = "70cf7c4000",
    [string]$SearchValue = "70a674e0"
)

Write-Host "`n? �ڴ�ָ����������" -ForegroundColor Cyan
Write-Host "================================" -ForegroundColor Cyan
Write-Host "PID: $ProcessPID" -ForegroundColor White
Write-Host "��Χ: 0x$StartAddr - 0x$EndAddr" -ForegroundColor White
Write-Host "����ֵ: 0x$SearchValue" -ForegroundColor White
Write-Host "================================`n" -ForegroundColor Cyan

# ת����ַ
$start = [Convert]::ToInt64($StartAddr, 16)
$end = [Convert]::ToInt64($EndAddr, 16)
$totalSize = $end - $start

# С����ת������ֵ
$searchBytes = $SearchValue -replace '(..)(..)(..)(..)','$4$3$2$1'

Write-Host "�ܴ�С: $([Math]::Round($totalSize/1024/1024, 2)) MB" -ForegroundColor Yellow
Write-Host "����ģʽ(С����): $searchBytes" -ForegroundColor Yellow
Write-Host "��ʼ����...`n" -ForegroundColor Green

# �ֿ�������ÿ��1MB��
$chunkSize = 1024 * 1024
$found = 0

for ($offset = 0; $offset -lt $totalSize; $offset += $chunkSize) {
    $currentAddr = $start + $offset
    $readSize = [Math]::Min($chunkSize, $totalSize - $offset)
    
    # ��ȡ�ڴ��
    $addrHex = "{0:X}" -f $currentAddr
    $result = adb shell "su -c 'cd /data/data/com.example.myapplication/lib && LD_LIBRARY_PATH=. /data/data/com.example.myapplication/files/memtool_procmem read $ProcessPID $addrHex $readSize'" 2>$null
    
    if ($result) {
        # ��ʮ�������ַ���������ģʽ
        $index = $result.IndexOf($searchBytes)
        if ($index -ge 0) {
            # ����ʵ�ʵ�ַ
            $foundOffset = $index / 2
            $foundAddr = $currentAddr + $foundOffset
            $foundAddrHex = "{0:X}" -f $foundAddr
            
            Write-Host "? �ҵ�ƥ�䣡" -ForegroundColor Green
            Write-Host "   ��ַ: 0x$foundAddrHex" -ForegroundColor White
            Write-Host "   ƫ��: +0x$($foundOffset.ToString('X'))" -ForegroundColor Gray
            $found++
        }
    }
    
    # ��ʾ����
    $progress = [Math]::Round(($offset / $totalSize) * 100, 1)
    Write-Host "`r����: $progress% " -NoNewline -ForegroundColor Cyan
}

Write-Host "`n`n������ɣ��ҵ� $found ��ƥ����" -ForegroundColor $(if ($found -gt 0) { "Green" } else { "Yellow" })



