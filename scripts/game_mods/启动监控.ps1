# ��������ֵ��غ��޸Ĺ���
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  ? ����ֵʵʱ���ƹ���" -ForegroundColor Yellow
Write-Host "========================================`n" -ForegroundColor Cyan

Write-Host "ʹ�÷�����" -ForegroundColor White
Write-Host "  1??  ʵʱ��أ��۲�����ֵ�仯��" -ForegroundColor Green
Write-Host "     powershell -ExecutionPolicy Bypass -File sun_modifier.ps1`n" -ForegroundColor Gray

Write-Host "  2??  ��������ֵΪ9999" -ForegroundColor Green
Write-Host "     powershell -ExecutionPolicy Bypass -File sun_modifier.ps1 -Set -TargetValue 9999`n" -ForegroundColor Gray

Write-Host "  3??  ��������ֵ���Զ�ά��9999��" -ForegroundColor Green
Write-Host "     powershell -ExecutionPolicy Bypass -File sun_modifier.ps1 -Lock -TargetValue 9999`n" -ForegroundColor Gray

Write-Host "  4??  ʹ���µ�ַ" -ForegroundColor Green
Write-Host "     powershell -ExecutionPolicy Bypass -File sun_modifier.ps1 -Address �µ�ַ`n" -ForegroundColor Gray

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "�����������ʵʱ���..." -ForegroundColor Yellow
Write-Host "========================================`n" -ForegroundColor Cyan
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")

powershell -ExecutionPolicy Bypass -File sun_modifier.ps1 -Monitor


