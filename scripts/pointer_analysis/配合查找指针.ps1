# ��ϲ���ָ��������
# API���޸�����������

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  ָ�������� - ��Ϲ���" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

$SUN_ADDR = "7043E320CC"
$GAME_PID = 6729
$API_BASE = "http://10.99.99.3:8080/api"

Write-Host "`n? ���API��������" -ForegroundColor Green
Write-Host "   �����ַ: 0x$SUN_ADDR" -ForegroundColor Cyan
Write-Host "   ��ϷPID: $GAME_PID`n" -ForegroundColor Cyan

# �˵�
function Show-Menu {
    Write-Host "--- �����˵� ---" -ForegroundColor Cyan
    Write-Host "1. ��ȡ��ǰ����ֵ" -ForegroundColor White
    Write-Host "2. �޸�����ֵ����֤" -ForegroundColor White
    Write-Host "3. ʵʱ��أ������������" -ForegroundColor White
    Write-Host "4. ������ַ��������" -ForegroundColor White
    Write-Host "5. ��libpvz.so���ݶ�����ָ��" -ForegroundColor White
    Write-Host "6. �鿴libpvz.so����Ϣ" -ForegroundColor White
    Write-Host "0. �˳�" -ForegroundColor Red
    Write-Host ""
}

do {
    Show-Menu
    $choice = Read-Host "��ѡ��"
    
    switch ($choice) {
        "1" {
            Write-Host "`n[��ȡ����]" -ForegroundColor Yellow
            $body = @{pid=$GAME_PID;address=$SUN_ADDR;length=4} | ConvertTo-Json
            $r = Invoke-RestMethod "$API_BASE/memory/read" -Method Post -Body $body -ContentType "application/json"
            
            if($r.success){
                $h=$r.data.hex
                $sun=[Convert]::ToInt32($h.Substring(6,2)+$h.Substring(4,2)+$h.Substring(2,2)+$h.Substring(0,2),16)
                Write-Host "��ǰ����: $sun" -ForegroundColor Green
                Write-Host "Hex: $h" -ForegroundColor Gray
            } else {
                Write-Host "��ȡʧ��: $($r.message)" -ForegroundColor Red
            }
            Read-Host "`n��Enter����"
        }
        
        "2" {
            $newValue = Read-Host "`n����������ֵ"
            Write-Host "�޸�����Ϊ: $newValue" -ForegroundColor Yellow
            
            $body = @{pid=$GAME_PID;address=$SUN_ADDR;value=[int]$newValue} | ConvertTo-Json
            $r = Invoke-RestMethod "$API_BASE/memory/write" -Method Post -Body $body -ContentType "application/json"
            
            if($r.success){
                Write-Host "? д��ɹ�" -ForegroundColor Green
                Start-Sleep -Seconds 1
                
                # ��֤
                $vbody = @{pid=$GAME_PID;address=$SUN_ADDR;length=4} | ConvertTo-Json
                $vr = Invoke-RestMethod "$API_BASE/memory/read" -Method Post -Body $vbody -ContentType "application/json"
                $h=$vr.data.hex
                $sun=[Convert]::ToInt32($h.Substring(6,2)+$h.Substring(4,2)+$h.Substring(2,2)+$h.Substring(0,2),16)
                Write-Host "��ֵ֤: $sun" -ForegroundColor Cyan
                
                if($sun -eq [int]$newValue){
                    Write-Host "? �޸ĳɹ�����Ϸ��Ӧ��ʾ: $newValue" -ForegroundColor Green
                }
            } else {
                Write-Host "д��ʧ��" -ForegroundColor Red
            }
            Read-Host "`n��Enter����"
        }
        
        "3" {
            Write-Host "`n========================================" -ForegroundColor Cyan
            Write-Host "  ʵʱ���ģʽ" -ForegroundColor Cyan
            Write-Host "========================================" -ForegroundColor Cyan
            Write-Host "`n��ʾ: ������Ϸ��ִ�в���" -ForegroundColor Yellow
            Write-Host "   - �ռ����� (+25)" -ForegroundColor Gray
            Write-Host "   - ��ֲ���տ� (-50)" -ForegroundColor Gray
            Write-Host "   - ��ֲ�㶹���� (-100)" -ForegroundColor Gray
            Write-Host "`n��ʼ���... (Ctrl+Cֹͣ)`n" -ForegroundColor Cyan
            
            $body = @{pid=$GAME_PID;address=$SUN_ADDR;length=4} | ConvertTo-Json
            $r = Invoke-RestMethod "$API_BASE/memory/read" -Method Post -Body $body -ContentType "application/json"
            $h=$r.data.hex
            $prevSun=[Convert]::ToInt32($h.Substring(6,2)+$h.Substring(4,2)+$h.Substring(2,2)+$h.Substring(0,2),16)
            
            $changeLog = @()
            
            while($true){
                Start-Sleep -Milliseconds 500
                
                $r = Invoke-RestMethod "$API_BASE/memory/read" -Method Post -Body $body -ContentType "application/json" -TimeoutSec 5
                if($r.success){
                    $h=$r.data.hex
                    $sun=[Convert]::ToInt32($h.Substring(6,2)+$h.Substring(4,2)+$h.Substring(2,2)+$h.Substring(0,2),16)
                    
                    if($sun -ne $prevSun){
                        $time=Get-Date -Format 'HH:mm:ss.fff'
                        $change=$sun-$prevSun
                        $changeStr=if($change -gt 0){"+$change"}else{"$change"}
                        
                        Write-Host "[$time] $prevSun -> $sun ($changeStr)" -ForegroundColor Yellow
                        
                        # ������������
                        if($change -eq 25){ Write-Host "   �� �ռ�1������" -ForegroundColor Green }
                        elseif($change -eq 50){ Write-Host "   �� ���տ�����" -ForegroundColor Green }
                        elseif($change -eq -50){ Write-Host "   �� ��ֲ���տ�" -ForegroundColor Magenta }
                        elseif($change -eq -100){ Write-Host "   �� ��ֲ�㶹����" -ForegroundColor Magenta }
                        elseif($change -eq -150){ Write-Host "   �� ��ֲ˫�����տ�" -ForegroundColor Magenta }
                        else{ Write-Host "   �� �Զ������" -ForegroundColor Cyan }
                        
                        $changeLog += @{Time=$time;From=$prevSun;To=$sun;Change=$change}
                        $prevSun=$sun
                    }
                }
            }
        }
        
        "4" {
            Write-Host "`n[������ַ��������]" -ForegroundColor Yellow
            
            $maps = Invoke-RestMethod "$API_BASE/memory/maps?pid=$GAME_PID"
            $targetAddr = [Convert]::ToInt64($SUN_ADDR, 16)
            
            $found = $false
            foreach($region in $maps.data){
                $start = [Convert]::ToInt64($region.start, 16)
                $end = [Convert]::ToInt64($region.end, 16)
                
                if($targetAddr -ge $start -and $targetAddr -lt $end){
                    $offset = $targetAddr - $start
                    $sizeMB = [math]::Round($region.size/1MB, 2)
                    
                    Write-Host "`n? �ҵ�Ŀ������" -ForegroundColor Green
                    Write-Host "Ȩ��: $($region.perms)" -ForegroundColor Cyan
                    Write-Host "��Χ: 0x$($region.start)-0x$($region.end)" -ForegroundColor Cyan
                    Write-Host "��С: ${sizeMB}MB" -ForegroundColor Cyan
                    Write-Host "·��: $($region.path)" -ForegroundColor Cyan
                    Write-Host "ƫ��: +0x$($offset.ToString('X'))" -ForegroundColor Yellow
                    
                    if($region.path -like "*libpvz.so*"){
                        Write-Host "`n? ��libpvz.so�У������Ҿ�ָ̬�룡" -ForegroundColor Green
                    } else {
                        Write-Host "`n??  �ڶ��ڴ棨Java���󣩣���ַ��仯" -ForegroundColor Yellow
                    }
                    
                    $found = $true
                    break
                }
            }
            
            if(-not $found){
                Write-Host "δ�ҵ��õ�ַ" -ForegroundColor Red
            }
            
            Read-Host "`n��Enter����"
        }
        
        "5" {
            Write-Host "`n[����libpvz.so�е�ָ��]" -ForegroundColor Yellow
            Write-Host "Ŀ���ַ: 0x$SUN_ADDR" -ForegroundColor Cyan
            
            # ���������ֽ�
            $addr = [Convert]::ToInt64($SUN_ADDR, 16)
            $searchBytes = @()
            for($i=0; $i -lt 8; $i++){
                $byte = ($addr -shr ($i*8)) -band 0xFF
                $searchBytes += $byte.ToString("X2")
            }
            
            Write-Host "�����ֽڣ�С����: $($searchBytes -join ' ')" -ForegroundColor Cyan
            Write-Host "ǰ4�ֽ�: $($searchBytes[0..3] -join ' ')" -ForegroundColor Yellow
            
            Write-Host "`n��IDA/CE��������Щ�ֽڣ���Χ��libpvz.so���ݶ�" -ForegroundColor Gray
            
            Read-Host "`n��Enter����"
        }
        
        "6" {
            Write-Host "`n[libpvz.so����Ϣ]" -ForegroundColor Yellow
            
            $maps = Invoke-RestMethod "$API_BASE/memory/maps?pid=$GAME_PID"
            $libpvz = $maps.data | Where-Object { $_.path -like "*libpvz.so" }
            
            Write-Host "`nlibpvz.so�� $($libpvz.Count) ����:`n" -ForegroundColor Cyan
            
            foreach($seg in $libpvz){
                $sizeMB = [math]::Round($seg.size/1MB, 2)
                Write-Host "$($seg.perms) | 0x$($seg.start)-0x$($seg.end) | ${sizeMB}MB" -ForegroundColor Gray
                
                if($seg.perms -eq "rw-p"){
                    Write-Host "   �� ���ݶΣ�����ָ�뷶Χ��" -ForegroundColor Yellow
                }
                if($seg.perms -eq "r-xp"){
                    Write-Host "   �� �����" -ForegroundColor Green
                }
            }
            
            Read-Host "`n��Enter����"
        }
        
        "0" {
            Write-Host "`n�˳�..." -ForegroundColor Cyan
        }
        
        default {
            Write-Host "��Чѡ��" -ForegroundColor Red
            Start-Sleep -Seconds 1
        }
    }
} while ($choice -ne "0")

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  ��Ϲ������˳�" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "`n? API��������֤������" -ForegroundColor Green
Write-Host "���ڿ���ʹ��Web������������ָ����" -ForegroundColor Gray








