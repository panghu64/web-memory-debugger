/*
 * 基于Cheat Engine ceserver的内存访问方法
 * 使用/proc/pid/mem文件方式，避免SELinux ptrace限制
 */

#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <cerrno>
#include <cstring>
#include <ctime>
#include <unistd.h>
#include <fcntl.h>

#ifdef HAVE_CAPSTONE
#include "capstone/capstone/capstone.h"
#endif

/**
 * 通过/proc/pid/mem读取内存（类似CE ceserver）
 * 优点：某些Android版本不需要ptrace权限
 */
static int read_via_procmem(pid_t pid, uint64_t addr, uint8_t* buf, size_t len) {
    char path[256];
    snprintf(path, sizeof(path), "/proc/%d/mem", pid);
    
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "open /proc/%d/mem failed: %s\n", pid, strerror(errno));
        return -1;
    }
    
    // 使用lseek定位到指定地址
    if (lseek64(fd, addr, SEEK_SET) == (off64_t)-1) {
        fprintf(stderr, "lseek failed: %s\n", strerror(errno));
        close(fd);
        return -1;
    }
    
    // 读取数据
    ssize_t n = read(fd, buf, len);
    close(fd);
    
    if (n < 0) {
        fprintf(stderr, "read failed: %s\n", strerror(errno));
        return -1;
    }
    
    return n;
}

/**
 * 通过/proc/pid/mem写入内存
 */
static int write_via_procmem(pid_t pid, uint64_t addr, const uint8_t* buf, size_t len) {
    char path[256];
    snprintf(path, sizeof(path), "/proc/%d/mem", pid);
    
    int fd = open(path, O_WRONLY);
    if (fd < 0) {
        fprintf(stderr, "open /proc/%d/mem for write failed: %s\n", pid, strerror(errno));
        return -1;
    }
    
    if (lseek64(fd, addr, SEEK_SET) == (off64_t)-1) {
        fprintf(stderr, "lseek failed: %s\n", strerror(errno));
        close(fd);
        return -1;
    }
    
    ssize_t n = write(fd, buf, len);
    close(fd);
    
    if (n < 0) {
        fprintf(stderr, "write failed: %s\n", strerror(errno));
        return -1;
    }
    
    return n;
}

/**
 * 反汇编（无需ptrace）
 */
#ifdef HAVE_CAPSTONE
static int do_disasm_procmem(pid_t pid, uint64_t addr, int count) {
    fprintf(stderr, "[disasm] Using /proc/mem method (no ptrace)\n");
    fprintf(stderr, "[disasm] PID=%d, Addr=0x%lx, Count=%d\n", pid, addr, count);
    
    size_t code_len = count * 4;
    uint8_t* code = (uint8_t*)malloc(code_len);
    if (!code) {
        fprintf(stderr, "malloc failed\n");
        return 1;
    }
    
    // 通过/proc/pid/mem读取
    int n = read_via_procmem(pid, addr, code, code_len);
    if (n < 0) {
        fprintf(stderr, "Failed to read memory via /proc/mem\n");
        free(code);
        return 1;
    }
    
    // 初始化Capstone
    csh handle;
    cs_insn* insn;
    
    #if defined(__aarch64__)
    cs_arch arch = CS_ARCH_ARM64;
    cs_mode mode = CS_MODE_ARM;
    #elif defined(__arm__)
    cs_arch arch = CS_ARCH_ARM;
    cs_mode mode = CS_MODE_ARM;
    #else
    fprintf(stderr, "Unsupported architecture\n");
    free(code);
    return 1;
    #endif
    
    cs_err err = cs_open(arch, mode, &handle);
    if (err != CS_ERR_OK) {
        fprintf(stderr, "cs_open failed: %d (%s)\n", err, cs_strerror(err));
        fprintf(stderr, "arch=%d, mode=%d\n", arch, mode);
        free(code);
        return 1;
    }
    fprintf(stderr, "cs_open success!\n");
    
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
    
    fprintf(stderr, "Calling cs_disasm: code_ptr=%p, size=%d, addr=0x%lx\n", code, n, addr);
    fprintf(stderr, "First 16 bytes: ");
    for(int i = 0; i < 16 && i < n; i++) {
        fprintf(stderr, "%02x ", code[i]);
    }
    fprintf(stderr, "\n");
    
    size_t insn_count = cs_disasm(handle, code, n, addr, 0, &insn);
    fprintf(stderr, "cs_disasm returned: %zu instructions\n", insn_count);
    
    if (insn_count > 0) {
        printf("[");
        for (size_t i = 0; i < insn_count && i < (size_t)count; i++) {
            printf("{\"address\":\"0x%llx\",", (unsigned long long)insn[i].address);
            printf("\"bytes\":\"");
            for (size_t j = 0; j < insn[i].size; j++) {
                printf("%02x", insn[i].bytes[j]);
            }
            printf("\",");
            printf("\"mnemonic\":\"%s\",", insn[i].mnemonic);
            printf("\"opStr\":\"%s\"}", insn[i].op_str);
            if (i < insn_count - 1 && i < (size_t)count - 1) printf(",");
        }
        printf("]\n");
        cs_free(insn, insn_count);
    } else {
        fprintf(stderr, "Failed to disassemble (decoded %zu bytes)\n", (size_t)n);
        printf("[]\n");
    }
    
    cs_close(&handle);
    free(code);
    return 0;
}
#endif

/**
 * 读取命令（/proc/mem版本）
 */
static int do_read_procmem(pid_t pid, uint64_t addr, size_t len) {
    uint8_t buf[4096];
    if (len > sizeof(buf)) len = sizeof(buf);
    
    int n = read_via_procmem(pid, addr, buf, len);
    if (n < 0) {
        return 1;
    }
    
    for (int i = 0; i < n; ++i) {
        printf("%02x", buf[i]);
    }
    printf("\n");
    return 0;
}

/**
 * 写入命令（/proc/mem版本）
 */
static int do_write_procmem(pid_t pid, uint64_t addr, const uint8_t* data, size_t len) {
    int n = write_via_procmem(pid, addr, data, len);
    if (n < 0 || (size_t)n != len) {
        return 1;
    }
    return 0;
}

int main(int argc, char** argv) {
    if (argc < 2) {
        fprintf(stderr, "memtool_procmem - Cheat Engine style memory access\n");
        fprintf(stderr, "usage: %s <command> <args...>\n", argv[0]);
        fprintf(stderr, "commands:\n");
        fprintf(stderr, "  read <pid> <addr_hex> <len>\n");
        fprintf(stderr, "  write <pid> <addr_hex> <int_value>\n");
        fprintf(stderr, "  disasm <pid> <addr_hex> <count>\n");
        return 2;
    }
    
    const char* cmd = argv[1];
    
    // read 命令
    if (strcmp(cmd, "read") == 0) {
        if (argc < 5) {
            fprintf(stderr, "usage: %s read <pid> <addr_hex> <len>\n", argv[0]);
            return 2;
        }
        pid_t pid = (pid_t)strtol(argv[2], nullptr, 10);
        uint64_t addr = strtoull(argv[3], nullptr, 16);
        size_t len = (size_t)strtoul(argv[4], nullptr, 10);
        
        return do_read_procmem(pid, addr, len);
    }
    
    // write 命令
    else if (strcmp(cmd, "write") == 0) {
        if (argc < 5) {
            fprintf(stderr, "usage: %s write <pid> <addr_hex> <int_value>\n", argv[0]);
            return 2;
        }
        pid_t pid = (pid_t)strtol(argv[2], nullptr, 10);
        uint64_t addr = strtoull(argv[3], nullptr, 16);
        long value = strtol(argv[4], nullptr, 10);
        
        uint8_t bytes[4];
        bytes[0] = (uint8_t)(value & 0xFF);
        bytes[1] = (uint8_t)((value >> 8) & 0xFF);
        bytes[2] = (uint8_t)((value >> 16) & 0xFF);
        bytes[3] = (uint8_t)((value >> 24) & 0xFF);
        
        return do_write_procmem(pid, addr, bytes, 4);
    }
    
    // disasm 命令（使用/proc/mem，无需ptrace）
    else if (strcmp(cmd, "disasm") == 0) {
        #ifdef HAVE_CAPSTONE
        if (argc < 5) {
            fprintf(stderr, "usage: %s disasm <pid> <addr_hex> <count>\n", argv[0]);
            return 2;
        }
        pid_t pid = (pid_t)strtol(argv[2], nullptr, 10);
        uint64_t addr = strtoull(argv[3], nullptr, 16);
        int count = atoi(argv[4]);
        
        return do_disasm_procmem(pid, addr, count);
        #else
        fprintf(stderr, "disasm requires HAVE_CAPSTONE\n");
        return 1;
        #endif
    }
    
    else {
        fprintf(stderr, "unknown command: %s\n", cmd);
        return 2;
    }
}

