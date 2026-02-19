/**
 * 工具函数
 */

// 格式化地址为十六进制
function formatAddress(addr) {
    if (typeof addr === 'number') {
        return '0x' + addr.toString(16).toUpperCase().padStart(8, '0');
    }
    if (typeof addr === 'string') {
        if (addr.startsWith('0x')) return addr.toUpperCase();
        return '0x' + addr.toUpperCase();
    }
    return addr;
}

// 格式化字节大小
function formatBytes(bytes) {
    if (!bytes || bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return (bytes / Math.pow(k, i)).toFixed(2) + ' ' + sizes[i];
}

// 格式化偏移
function formatOffset(offset) {
    if (offset === 0) return '0';
    if (offset > 0) return '+0x' + offset.toString(16).toUpperCase();
    return '-0x' + (-offset).toString(16).toUpperCase();
}

// 解析十六进制字符串为字节数组
function parseHex(hexStr) {
    hexStr = hexStr.replace(/[^0-9a-fA-F]/g, '');
    const bytes = [];
    for (let i = 0; i < hexStr.length; i += 2) {
        bytes.push(parseInt(hexStr.substr(i, 2), 16));
    }
    return bytes;
}

// 字节数组转十六进制字符串
function bytesToHex(bytes) {
    return Array.from(bytes, byte => 
        byte.toString(16).padStart(2, '0')
    ).join('');
}

// 格式化Hex数据为可读格式（每行16字节）
function formatHexData(hexStr) {
    if (!hexStr) return '';
    
    const bytes = parseHex(hexStr);
    let result = '';
    
    for (let i = 0; i < bytes.length; i += 16) {
        // 地址
        const addr = i.toString(16).padStart(8, '0');
        result += addr + '  ';
        
        // 十六进制
        for (let j = 0; j < 16; j++) {
            if (i + j < bytes.length) {
                result += bytes[i + j].toString(16).padStart(2, '0') + ' ';
            } else {
                result += '   ';
            }
            if (j === 7) result += ' ';
        }
        
        result += ' ';
        
        // ASCII
        for (let j = 0; j < 16; j++) {
            if (i + j < bytes.length) {
                const byte = bytes[i + j];
                if (byte >= 32 && byte <= 126) {
                    result += String.fromCharCode(byte);
                } else {
                    result += '.';
                }
            }
        }
        
        result += '\n';
    }
    
    return result;
}

// 判断地址是否接近目标（用于基址分析）
function isAddressNear(addr1, addr2, threshold = 4096) {
    try {
        let a1 = typeof addr1 === 'string' ? 
                parseInt(addr1.replace('0x', ''), 16) : addr1;
        let a2 = typeof addr2 === 'string' ? 
                parseInt(addr2.replace('0x', ''), 16) : addr2;
        return Math.abs(a1 - a2) < threshold;
    } catch (e) {
        return false;
    }
}

