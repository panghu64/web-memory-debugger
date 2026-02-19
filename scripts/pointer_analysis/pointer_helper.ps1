# 指针链分析辅助命令
# 游戏PID: 6913
# 阳光地址: 0x6D4662B22C

# 读取阳光值
function Read-Sun {
    $output = adb shell "su -c 'cd /data/data/com.example.myapplication/lib && LD_LIBRARY_PATH=. /data/data/com.example.myapplication/files/memtool_procmem read 6913 6D4662B22C 4'"
    Write-Host $output
}

# 读取指定地址（8字节指针）
function Read-Pointer {
    param([string]$Address)
    $output = adb shell "su -c 'cd /data/data/com.example.myapplication/lib && LD_LIBRARY_PATH=. /data/data/com.example.myapplication/files/memtool_procmem read 6913 $Address 8'"
    Write-Host $output
}

# 写入阳光值（测试用）
function Write-Sun {
    param([int]$Value)
    $hexValue = $Value.ToString("X8")
    $output = adb shell "su -c 'cd /data/data/com.example.myapplication/lib && LD_LIBRARY_PATH=. /data/data/com.example.myapplication/files/memtool_procmem write 6913 6D4662B22C $hexValue'"
    Write-Host $output
}

# 使用示例:
# Read-Sun
# Read-Pointer "6DB77C8100"
# Write-Sun 9999
