# IDA Python脚本 - 扫描libpvz.so数据段中的指针
# 用途：查找指向阳光对象区域的静态指针

# ======================================
# 配置参数（根据实际情况修改）
# ======================================

# libpvz.so当前运行时基址（会变化）
LIB_BASE = 0x7B67825000

# 数据段地址
DATA_START = 0x7B6939B000
DATA_END = 0x7B693CD000

# 阳光对象区域
SUN_REGION_START = 0x7ACC000000
SUN_REGION_END = 0x7ACC100000

# 当前阳光对象地址
SUN_OBJECT = 0x7ACC028870
SUN_VALUE_OFFSET = 0x0C
CURRENT_SUN_VALUE = 75

# ======================================
# 扫描函数
# ======================================

def scan_data_segment():
    """扫描数据段中所有指向阳光区域的指针"""
    print("[*] 开始扫描数据段...")
    print(f"[*] 数据段范围: {hex(DATA_START)} - {hex(DATA_END)}")
    print(f"[*] 目标区域: {hex(SUN_REGION_START)} - {hex(SUN_REGION_END)}")
    print("-" * 60)
    
    found_count = 0
    matches = []
    
    # 遍历数据段，每8字节对齐
    for addr in range(DATA_START, DATA_END, 8):
        try:
            # 读取8字节指针
            ptr_value = get_qword(addr)
            
            # 检查指针是否指向阳光对象区域
            if SUN_REGION_START <= ptr_value <= SUN_REGION_END:
                found_count += 1
                
                # 计算相对于库基址的偏移
                offset_from_base = addr - LIB_BASE
                
                # 尝试读取+0x0C处的值（可能是阳光值）
                try:
                    potential_sun = get_dword(ptr_value + SUN_VALUE_OFFSET)
                except:
                    potential_sun = -1
                
                match_info = {
                    'addr': addr,
                    'offset': offset_from_base,
                    'ptr_value': ptr_value,
                    'sun_value': potential_sun
                }
                matches.append(match_info)
                
                # 打印发现
                print(f"[+] 找到指针:")
                print(f"    地址: {hex(addr)}")
                print(f"    偏移: {hex(offset_from_base)}")
                print(f"    指向: {hex(ptr_value)}")
                print(f"    [+0x0C]: {potential_sun}")
                
                # 特别标记匹配当前阳光值的
                if potential_sun == CURRENT_SUN_VALUE:
                    print(f"    ⭐⭐⭐ 匹配当前阳光值！⭐⭐⭐")
                print()
                
        except:
            # 忽略读取失败的地址
            pass
    
    print("-" * 60)
    print(f"[*] 扫描完成！共找到 {found_count} 个指向阳光区域的指针")
    
    return matches

def analyze_pointer_chain(ptr_addr):
    """分析单个指针的完整链"""
    print(f"\n[*] 分析指针链: {hex(ptr_addr)}")
    print("-" * 60)
    
    try:
        # 级别1：读取指针值
        level1_ptr = get_qword(ptr_addr)
        print(f"[Level 1] {hex(ptr_addr)} → {hex(level1_ptr)}")
        
        # 级别2：尝试读取对象头部（前64字节）
        print(f"\n[Level 2] 对象结构 @ {hex(level1_ptr)}:")
        for i in range(0, 64, 8):
            try:
                value = get_qword(level1_ptr + i)
                print(f"  +0x{i:02X}: {hex(value)}")
            except:
                print(f"  +0x{i:02X}: <无法读取>")
        
        # 特别检查+0x0C处
        try:
            sun_value = get_dword(level1_ptr + SUN_VALUE_OFFSET)
            print(f"\n[*] 阳光值 @ +0x{SUN_VALUE_OFFSET:02X}: {sun_value}")
            if sun_value == CURRENT_SUN_VALUE:
                print(f"    ✓ 匹配！")
        except:
            print(f"[!] 无法读取+0x{SUN_VALUE_OFFSET:02X}处的值")
        
    except Exception as e:
        print(f"[!] 分析失败: {e}")

def find_xrefs_to_data():
    """查找代码段中对数据段的交叉引用"""
    print("\n[*] 查找对数据段的交叉引用...")
    print("-" * 60)
    
    xref_count = 0
    for addr in range(DATA_START, DATA_END, 8):
        # 获取对当前地址的交叉引用
        for xref in XrefsTo(addr, 0):
            xref_count += 1
            print(f"[XREF] {hex(xref.frm)} → {hex(addr)}")
            print(f"       类型: {xref.type}")
            
            # 尝试反汇编引用处的代码
            try:
                disasm = GetDisasm(xref.frm)
                print(f"       指令: {disasm}")
            except:
                pass
            print()
            
            if xref_count >= 50:  # 限制输出
                print("[*] （输出限制为50条）")
                return
    
    print(f"[*] 共找到 {xref_count} 个交叉引用")

def search_singleton_pattern():
    """搜索单例模式（static instance指针）"""
    print("\n[*] 搜索单例模式...")
    print("-" * 60)
    
    # 搜索常见的单例模式特征
    # 1. 指针非空
    # 2. 指针指向heap区域
    # 3. 该指针被代码引用
    
    singleton_candidates = []
    
    for addr in range(DATA_START, DATA_END, 8):
        try:
            ptr = get_qword(addr)
            
            # 检查是否为有效heap指针
            if 0x00E00000 <= ptr <= 0x40E00000 or \
               0x70000000 <= ptr <= 0x71000000 or \
               0x7ACC000000 <= ptr <= 0x7ACC100000:
                
                # 检查是否有代码引用
                xref_count = len(list(XrefsTo(addr, 0)))
                if xref_count > 0:
                    singleton_candidates.append({
                        'addr': addr,
                        'offset': addr - LIB_BASE,
                        'ptr': ptr,
                        'xrefs': xref_count
                    })
    
    # 按交叉引用数量排序
    singleton_candidates.sort(key=lambda x: x['xrefs'], reverse=True)
    
    print(f"[*] 找到 {len(singleton_candidates)} 个单例候选:")
    for i, candidate in enumerate(singleton_candidates[:20]):  # 只显示前20个
        print(f"\n[{i+1}] 地址: {hex(candidate['addr'])}")
        print(f"    偏移: {hex(candidate['offset'])}")
        print(f"    指向: {hex(candidate['ptr'])}")
        print(f"    引用: {candidate['xrefs']} 次")

# ======================================
# 主执行函数
# ======================================

def main():
    print("=" * 60)
    print("  PVZ阳光基址查找 - IDA Python脚本")
    print("=" * 60)
    print()
    
    # 1. 扫描数据段
    matches = scan_data_segment()
    
    # 2. 如果找到匹配，详细分析第一个
    if matches:
        print("\n[*] 详细分析第一个匹配的指针...")
        analyze_pointer_chain(matches[0]['addr'])
    
    # 3. 查找交叉引用
    # find_xrefs_to_data()  # 可能输出很多，按需启用
    
    # 4. 搜索单例模式
    search_singleton_pattern()
    
    print("\n" + "=" * 60)
    print("  分析完成！")
    print("=" * 60)

# 运行主函数
if __name__ == "__main__":
    # 检查IDA环境
    try:
        get_qword
        print("[*] IDA环境检测成功")
        main()
    except NameError:
        print("[!] 此脚本需要在IDA Pro中运行！")
        print("[*] 使用方法：File → Script file → 选择此脚本")

