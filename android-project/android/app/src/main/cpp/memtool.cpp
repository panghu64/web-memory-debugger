#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <cerrno>
#include <cstring>
#include <ctime>
#include <sys/ptrace.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>
#include <linux/elf.h>
#include <sys/user.h>
#include <signal.h>

// NT_PRSTATUS定义（用于PTRACE_GETREGSET）
#ifndef NT_PRSTATUS
#define NT_PRSTATUS 1
#endif

// Capstone反汇编引擎
#ifdef HAVE_CAPSTONE
#include "capstone/capstone/capstone.h"
#endif

static int attach_and_wait(pid_t pid) {
    if (ptrace(PTRACE_ATTACH, pid, nullptr, nullptr) == -1) {
        fprintf(stderr, "ptrace attach failed: %s\n", strerror(errno));
        return -1;
    }
    int status = 0;
    if (waitpid(pid, &status, 0) == -1) {
        fprintf(stderr, "waitpid failed: %s\n", strerror(errno));
        return -1;
    }
    if (!WIFSTOPPED(status)) {
        fprintf(stderr, "target not stopped\n");
        return -1;
    }
    return 0;
}

static void detach(pid_t pid) {
    ptrace(PTRACE_DETACH, pid, nullptr, nullptr);
}

static int do_read(pid_t pid, uint64_t addr, size_t len) {
    uint8_t buf[4096];
    if (len > sizeof(buf)) len = sizeof(buf);

    struct iovec local{ buf, len };
    struct iovec remote{ (void*)addr, len };
    ssize_t n = process_vm_readv(pid, &local, 1, &remote, 1, 0);
    if (n < 0) {
        fprintf(stderr, "process_vm_readv failed: %s\n", strerror(errno));
        return 1;
    }
    // Print hex bytes (little-endian order in memory)
    for (ssize_t i = 0; i < n; ++i) {
        printf("%02x", buf[i]);
    }
    printf("\n");
    return 0;
}

static int do_write(pid_t pid, uint64_t addr, const uint8_t* data, size_t len) {
    struct iovec local{ (void*)data, len };
    struct iovec remote{ (void*)addr, len };
    ssize_t n = process_vm_writev(pid, &local, 1, &remote, 1, 0);
    if (n < 0 || (size_t)n != len) {
        fprintf(stderr, "process_vm_writev failed: %s\n", strerror(errno));
        return 1;
    }
    return 0;
}

// ARM64 硬件断点常量
#if defined(__aarch64__)
#ifndef NT_ARM_HW_WATCH
#define NT_ARM_HW_WATCH 0x404  // ARM64 hardware watchpoint regset
#endif
#endif

// 简单的读内存辅助函数（无需attach）
static int read_memory_simple(pid_t pid, uint64_t addr, uint8_t* data, size_t len) {
    struct iovec local = { data, len };
    struct iovec remote = { (void*)addr, len };
    ssize_t n = process_vm_readv(pid, &local, 1, &remote, 1, 0);
    if (n < 0 || (size_t)n != len) {
        return -1;
    }
    return 0;
}

// 硬件断点功能（ARM64真实实现）
static int do_watchpoint(pid_t pid, uint64_t addr, int timeout_sec) {
    fprintf(stderr, "[watchpoint] Setting hardware watchpoint at 0x%lx for pid %d\n", addr, pid);
    
    #if defined(__aarch64__)
    // 尝试使用真正的硬件断点
    {
        struct user_hwdebug_state hwbp_state;
        memset(&hwbp_state, 0, sizeof(hwbp_state));
        
        struct iovec iov;
        iov.iov_base = &hwbp_state;
        iov.iov_len = sizeof(hwbp_state);
        
        if (ptrace(PTRACE_GETREGSET, pid, (void*)NT_ARM_HW_WATCH, &iov) == -1) {
            fprintf(stderr, "[watchpoint] Failed to read hardware watchpoint state: %s\n", strerror(errno));
            fprintf(stderr, "[watchpoint] Falling back to polling mode...\n");
            goto polling_mode;
        }
        
        fprintf(stderr, "[watchpoint] Hardware watchpoint supported, dbg_info=0x%x\n", hwbp_state.dbg_info);
        
        // 设置第一个硬件断点寄存器（对齐到8字节）
        uint64_t aligned_addr = addr & ~7ULL;
        hwbp_state.dbg_regs[0].addr = aligned_addr;
        hwbp_state.dbg_regs[0].ctrl = 0x1 | (0x3 << 3) | (0xff << 5);  // 启用+读写监控+8字节
        
        // 写入硬件断点
        if (ptrace(PTRACE_SETREGSET, pid, (void*)NT_ARM_HW_WATCH, &iov) == -1) {
            fprintf(stderr, "[watchpoint] Failed to set hardware watchpoint: %s\n", strerror(errno));
            fprintf(stderr, "[watchpoint] Falling back to polling mode...\n");
            goto polling_mode;
        }
        
        fprintf(stderr, "[watchpoint] Hardware watchpoint set successfully at 0x%lx\n", aligned_addr);
        
        // 继续执行并等待断点触发
        if (ptrace(PTRACE_CONT, pid, nullptr, nullptr) == -1) {
            fprintf(stderr, "[watchpoint] ptrace cont failed: %s\n", strerror(errno));
            return 1;
        }
        
        fprintf(stderr, "[watchpoint] Waiting for memory access (timeout: %d sec)...\n", timeout_sec);
        
        // 等待断点触发
        time_t hw_start = time(nullptr);
        while ((time(nullptr) - hw_start) < timeout_sec) {
            int status = 0;
            int wait_result = waitpid(pid, &status, WNOHANG);
            
            if (wait_result > 0 && WIFSTOPPED(status)) {
                int sig = WSTOPSIG(status);
                fprintf(stderr, "[watchpoint] Process stopped with signal %d\n", sig);
                
                // 接受 SIGTRAP 或 SIGSEGV（硬件断点可能触发任一信号）
                if (sig == SIGTRAP || sig == SIGSEGV) {
                    struct user_regs_struct {
                        uint64_t regs[31];
                        uint64_t sp;
                        uint64_t pc;
                        uint64_t pstate;
                    };
                    
                    struct iovec reg_iov;
                    struct user_regs_struct regs;
                    reg_iov.iov_base = &regs;
                    reg_iov.iov_len = sizeof(regs);
                    
                    if (ptrace(PTRACE_GETREGSET, pid, (void*)NT_PRSTATUS, &reg_iov) == 0) {
                        fprintf(stderr, "[watchpoint] ✅ Hardware watchpoint triggered!\n");
                        fprintf(stderr, "[watchpoint] PC=0x%lx\n", regs.pc);
                        
                        printf("{\"triggered\":true,");
                        printf("\"pc\":\"0x%lx\",", regs.pc);
                        printf("\"sp\":\"0x%lx\",", regs.sp);
                        printf("\"registers\":[");
                        for (int i = 0; i < 31; i++) {
                            printf("\"0x%lx\"%s", regs.regs[i], i < 30 ? "," : "");
                        }
                        printf("],");
                        printf("\"signal\":%d}\n", sig);
                        
                        // 清除硬件断点
                        memset(&hwbp_state, 0, sizeof(hwbp_state));
                        ptrace(PTRACE_SETREGSET, pid, (void*)NT_ARM_HW_WATCH, &iov);
                        return 0;
                    }
                }
                
                // 恢复执行
                ptrace(PTRACE_CONT, pid, nullptr, nullptr);
            }
            
            usleep(50000); // 50ms
        }
        
        fprintf(stderr, "[watchpoint] Hardware watchpoint timeout\n");
        
        // 清除硬件断点
        memset(&hwbp_state, 0, sizeof(hwbp_state));
        ptrace(PTRACE_SETREGSET, pid, (void*)NT_ARM_HW_WATCH, &iov);
        
        printf("{\"triggered\":false,\"error\":\"hw_timeout\"}\n");
        return 1;
    }
    
polling_mode:
    #endif
    
    // 降级方案：轮询模式（不使用硬件断点）
    fprintf(stderr, "[watchpoint] Using polling mode - checking memory changes\n");
    
    uint8_t initial_data[8];
    if (read_memory_simple(pid, addr, initial_data, 8) != 0) {
        fprintf(stderr, "[watchpoint] Failed to read initial value\n");
        printf("{\"triggered\":false,\"error\":\"read_failed\"}\n");
        return 1;
    }
    
    fprintf(stderr, "[watchpoint] Initial value: ");
    for (int i = 0; i < 8; i++) fprintf(stderr, "%02x ", initial_data[i]);
    fprintf(stderr, "\n");
    
    // 轮询检测变化
    time_t poll_start = time(nullptr);
    uint8_t current_data[8];
    
    while ((time(nullptr) - poll_start) < timeout_sec) {
        if (read_memory_simple(pid, addr, current_data, 8) == 0) {
            if (memcmp(initial_data, current_data, 8) != 0) {
                fprintf(stderr, "[watchpoint] ✅ Value changed (polling)!\n");
                fprintf(stderr, "[watchpoint] New value: ");
                for (int i = 0; i < 8; i++) fprintf(stderr, "%02x ", current_data[i]);
                fprintf(stderr, "\n");
                
                printf("{\"triggered\":true,\"method\":\"polling\",");
                printf("\"old_value\":\"");
                for (int i = 0; i < 8; i++) printf("%02x", initial_data[i]);
                printf("\",\"new_value\":\"");
                for (int i = 0; i < 8; i++) printf("%02x", current_data[i]);
                printf("\"}\n");
                return 0;
            }
        }
        usleep(100000); // 100ms
    }
    
    fprintf(stderr, "[watchpoint] Polling timeout (no change)\n");
    printf("{\"triggered\":false,\"error\":\"polling_timeout\"}\n");
    return 1;
}

// 反汇编功能
#ifdef HAVE_CAPSTONE
static int do_disasm(pid_t pid, uint64_t addr, int count) {
    fprintf(stderr, "[disasm] Disassembling %d instructions at 0x%lx\n", count, addr);
    
    // 读取代码内存
    size_t code_len = count * 4; // ARM指令通常4字节
    uint8_t* code = (uint8_t*)malloc(code_len);
    if (!code) {
        fprintf(stderr, "malloc failed\n");
        return 1;
    }
    
    struct iovec local{ code, code_len };
    struct iovec remote{ (void*)addr, code_len };
    ssize_t n = process_vm_readv(pid, &local, 1, &remote, 1, 0);
    if (n < 0) {
        fprintf(stderr, "process_vm_readv failed: %s\n", strerror(errno));
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
    
    if (cs_open(arch, mode, &handle) != CS_ERR_OK) {
        fprintf(stderr, "cs_open failed\n");
        free(code);
        return 1;
    }
    
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
    
    size_t insn_count = cs_disasm(handle, code, n, addr, 0, &insn);
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
        fprintf(stderr, "Failed to disassemble\n");
        printf("[]\n");
    }
    
    cs_close(&handle);
    free(code);
    return 0;
}
#endif

int main(int argc, char** argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <command> <args...>\n", argv[0]);
        fprintf(stderr, "commands:\n");
        fprintf(stderr, "  read <pid> <addr_hex> <len>\n");
        fprintf(stderr, "  write <pid> <addr_hex> <int_value>\n");
        fprintf(stderr, "  watchpoint <pid> <addr_hex> [timeout_sec]\n");
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
        
        if (attach_and_wait(pid) != 0) return 1;
        int rc = do_read(pid, addr, len);
        detach(pid);
        return rc;
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
        
        if (attach_and_wait(pid) != 0) return 1;
        int rc = do_write(pid, addr, bytes, 4);
        detach(pid);
        return rc;
    }
    
    // watchpoint 命令
    else if (strcmp(cmd, "watchpoint") == 0) {
        if (argc < 4) {
            fprintf(stderr, "usage: %s watchpoint <pid> <addr_hex> [timeout_sec]\n", argv[0]);
            return 2;
        }
        pid_t pid = (pid_t)strtol(argv[2], nullptr, 10);
        uint64_t addr = strtoull(argv[3], nullptr, 16);
        int timeout = argc >= 5 ? atoi(argv[4]) : 30;
        
        if (attach_and_wait(pid) != 0) return 1;
        int rc = do_watchpoint(pid, addr, timeout);
        detach(pid);
        return rc;
    }
    
    // disasm 命令（无需attach，直接使用process_vm_readv）
    else if (strcmp(cmd, "disasm") == 0) {
        #ifdef HAVE_CAPSTONE
        if (argc < 5) {
            fprintf(stderr, "usage: %s disasm <pid> <addr_hex> <count>\n", argv[0]);
            return 2;
        }
        pid_t pid = (pid_t)strtol(argv[2], nullptr, 10);
        uint64_t addr = strtoull(argv[3], nullptr, 16);
        int count = atoi(argv[4]);
        
        // 直接反汇编，不需要attach（避免SELinux限制）
        int rc = do_disasm(pid, addr, count);
        return rc;
        #else
        fprintf(stderr, "disasm command requires HAVE_CAPSTONE to be defined\n");
        return 1;
        #endif
    }
    
    else {
        fprintf(stderr, "unknown command: %s\n", cmd);
        return 2;
    }
}

