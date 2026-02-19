/**
 * Vue应用主逻辑
 */

const { createApp } = Vue;

createApp({
    data() {
        return {
            currentView: 'processes',
            
            // 进程相关
            processes: [],
            processListLoaded: false, // 进程列表是否已加载
            processSearch: '',
            manualPid: null,
            selectedPid: null,
            selectedProcess: null,
            
            // 内存映射
            memoryRegions: [],
            filterExecutable: false,
            filterWritable: false,
            
            // Hex编辑器
            hexAddress: '',
            hexData: '',
            
            // 反汇编
            disasmAddress: '',
            disasmCount: 20,
            disasmLines: [],
            
            // 硬件断点
            watchpointAddress: '',
            watchpointTimeout: 30,
            watchpointRunning: false,
            watchpointResult: null,
            
            // 基址分析
            analysisResult: null
        };
    },
    
    computed: {
        filteredProcesses() {
            if (!this.processSearch) return this.processes;
            const search = this.processSearch.toLowerCase();
            return this.processes.filter(p => 
                p.name.toLowerCase().includes(search) ||
                p.pid.toString().includes(search)
            );
        },
        
        filteredMemoryRegions() {
            let regions = this.memoryRegions;
            if (this.filterExecutable) {
                regions = regions.filter(r => r.perms && r.perms.includes('x'));
            }
            if (this.filterWritable) {
                regions = regions.filter(r => r.perms && r.perms.includes('w'));
            }
            return regions;
        }
    },
    
    methods: {
        // 格式化函数（从utils.js）
        formatBytes,
        formatAddress,
        formatOffset,
        
        // 加载进程列表
        async loadProcesses(forceRefresh = false) {
            try {
                // 强制刷新时清除缓存
                if (forceRefresh) {
                    api.clearProcessCache();
                }
                
                const response = await api.getProcessList();
                if (response.success) {
                    this.processes = response.data;
                    this.processListLoaded = true; // 标记为已加载
                } else {
                    alert('加载进程列表失败: ' + response.message);
                }
            } catch (error) {
                alert('加载进程列表出错: ' + error.message);
            }
        },
        
        // 选择进程
        async selectProcess(proc) {
            this.selectedPid = proc.pid;
            this.selectedProcess = proc;
            // 自动加载内存映射
            if (this.currentView === 'memory') {
                await this.loadMemoryMaps();
            }
        },
        
        // 手动选择PID
        async selectManualPid() {
            if (!this.manualPid || this.manualPid <= 0) {
                alert('请输入有效的PID（大于0的整数）');
                return;
            }
            
            this.selectedPid = this.manualPid;
            this.selectedProcess = {
                pid: this.manualPid,
                name: `手动选择的进程 ${this.manualPid}`,
                user: 'unknown',
                memoryUsage: 0
            };
            
            alert(`✅ 已选择PID: ${this.manualPid}\n\n提示：\n- 确保该进程存在\n- 确保有Root权限\n- 可以切换到"内存浏览器"查看映射`);
            
            // 自动切换到内存浏览器
            this.currentView = 'memory';
            
            // 尝试加载内存映射
            await this.loadMemoryMaps();
        },
        
        // 加载内存映射
        async loadMemoryMaps() {
            if (!this.selectedPid) return;
            try {
                const response = await api.getMemoryMaps(this.selectedPid);
                if (response.success) {
                    this.memoryRegions = response.data;
                } else {
                    alert('加载内存映射失败: ' + response.message);
                }
            } catch (error) {
                alert('加载内存映射出错: ' + error.message);
            }
        },
        
        // 读取Hex数据
        async readHexData() {
            if (!this.selectedPid || !this.hexAddress) return;
            try {
                const response = await api.readMemory(this.selectedPid, this.hexAddress, 256);
                if (response.success && response.data.hex) {
                    this.hexData = formatHexData(response.data.hex);
                } else {
                    alert('读取内存失败: ' + (response.message || '未知错误'));
                }
            } catch (error) {
                alert('读取内存出错: ' + error.message);
            }
        },
        
        // 反汇编
        async disassemble() {
            if (!this.selectedPid || !this.disasmAddress) return;
            try {
                const response = await api.disassemble(
                    this.selectedPid, 
                    this.disasmAddress, 
                    this.disasmCount
                );
                if (response.success) {
                    this.disasmLines = response.data;
                } else {
                    alert('反汇编失败: ' + response.message);
                }
            } catch (error) {
                alert('反汇编出错: ' + error.message);
            }
        },
        
        // 设置硬件断点
        async setWatchpoint() {
            if (!this.selectedPid || !this.watchpointAddress) return;
            
            this.watchpointRunning = true;
            this.watchpointResult = null;
            
            try {
                const response = await api.setWatchpoint(
                    this.selectedPid,
                    this.watchpointAddress,
                    this.watchpointTimeout
                );
                
                if (response.success) {
                    this.watchpointResult = response.data;
                    if (this.watchpointResult.triggered) {
                        alert('断点触发！');
                    } else {
                        alert('断点未触发: ' + (this.watchpointResult.error || '超时'));
                    }
                } else {
                    alert('设置断点失败: ' + response.message);
                }
            } catch (error) {
                alert('设置断点出错: ' + error.message);
            } finally {
                this.watchpointRunning = false;
            }
        },
        
        // 判断寄存器值是否接近目标
        isNearTarget(regValue) {
            if (!this.watchpointAddress || !regValue) return false;
            return isAddressNear(regValue, this.watchpointAddress);
        },
        
        // 分析基址
        async analyzeBase() {
            if (!this.selectedPid || !this.watchpointResult) return;
            
            try {
                const response = await api.analyzeBase(
                    this.selectedPid,
                    this.watchpointAddress,
                    this.watchpointResult
                );
                
                if (response.success) {
                    this.analysisResult = response.data;
                    this.currentView = 'analysis';
                } else {
                    alert('分析基址失败: ' + response.message);
                }
            } catch (error) {
                alert('分析基址出错: ' + error.message);
            }
        }
    },
    
    mounted() {
        // 不再自动加载进程列表，提升页面加载速度
        // 用户可以通过手动输入PID或点击"加载进程列表"按钮来使用
    }
}).mount('#app');

