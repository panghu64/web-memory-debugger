# API�޸����Բ���

## ? ���޸�������

**����**: APIʹ�ô����libĿ¼·��  
**�޸�**: ��Ϊʹ�� `/data/data/com.example.myapplication/lib`  
**�ļ�**: `app/src/main/java/com/example/myapplication/server/services/MemoryService.java`

---

## ? ���Բ���

### ����1: ��װ���µ�APK���ȴ�1-2���ӣ�
```powershell
adb install -r app\build\outputs\apk\debug\app-debug.apk
```

### ����2: ����Ӧ��
```powershell
adb shell am force-stop com.example.myapplication
adb shell am start -n com.example.myapplication/.MainActivity
```

### ����3: �ȴ�20���÷���������
```powershell
Start-Sleep -Seconds 20
```

### ����4: ����API��ȡ��ʹ��ʵ��PID 6729��
```powershell
$body = @{
    pid = 6729
    address = "7043E320CC"
    length = 4
} | ConvertTo-Json

$response = Invoke-RestMethod "http://10.99.99.3:8080/api/memory/read" `
    -Method Post -Body $body -ContentType "application/json"

# ��ʾ���
$response | ConvertTo-Json
```

**Ԥ�����**:
```json
{
  "success": true,
  "message": "success",
  "data": {
    "hex": "19000000"
  }
}
```

### ����5: ����APIд��
```powershell
$body = @{
    pid = 6729
    address = "7043E320CC"
    value = 9999
} | ConvertTo-Json

$response = Invoke-RestMethod "http://10.99.99.3:8080/api/memory/write" `
    -Method Post -Body $body -ContentType "application/json"

# ��ʾ���
$response | ConvertTo-Json
```

**Ԥ�����**:
```json
{
  "success": true,
  "message": "success"
}
```

### ����6: ��֤�޸�
```powershell
# ��ȡ��֤
$body = @{pid=6729;address="7043E320CC";length=4} | ConvertTo-Json
$r = Invoke-RestMethod "http://10.99.99.3:8080/api/memory/read" -Method Post -Body $body -ContentType "application/json"

# ת��Ϊʮ����
$hex = $r.data.hex
$b1 = $hex.Substring(0,2)
$b2 = $hex.Substring(2,2)
$b3 = $hex.Substring(4,2)
$b4 = $hex.Substring(6,2)
$sunValue = [Convert]::ToInt32("$b4$b3$b2$b1", 16)

Write-Host "��ǰ����ֵ: $sunValue" -ForegroundColor Green
```

**Ԥ��**: Ӧ����ʾ 9999

---

## ? �ɹ���־

������ϲ���ȫ���ɹ���˵����
- ? API�ڴ��ȡ��������
- ? API�ڴ�д�빦������
- ? memtool_procmem��������
- ? ���Կ�ʼָ��������

---

## ? �ɹ������һ��

### ����ʵʱ���
```powershell
powershell -ExecutionPolicy Bypass -File test_api_sun.ps1
```

### ��ʹ�ý���ʽ����
```powershell
powershell -ExecutionPolicy Bypass -File backend_pointer_finder.ps1
```

---

**�밴������Բ������ҽ����**







