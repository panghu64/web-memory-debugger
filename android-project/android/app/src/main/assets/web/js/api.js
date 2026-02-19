/**
 * API调用封装
 */

const API_BASE = '';  // 同域，无需前缀

const api = {
    // 缓存
    _processCache: null,
    _processCacheTime: 0,
    
    /**
     * 获取进程列表（分页版本 - 推荐）
     * @param {number} page 页码（从0开始）
     * @param {number} pageSize 每页数量（默认20）
     * @param {string} filter 过滤关键字（可选）
     * @param {string} sortBy 排序字段：name, pid, memory
     * @returns {Promise} 分页结果
     */
    async getProcesses(page = 0, pageSize = 20, filter = null, sortBy = 'name') {
        const params = { page, pageSize, sortBy };
        if (filter) params.filter = filter;
        
        const response = await axios.get(`${API_BASE}/api/processes`, { params });
        return response.data;
    },
    
    // 获取进程列表（旧版本 - 兼容性保留）
    async getProcessList() {
        // 30秒缓存，减少服务器负载
        const now = Date.now();
        if (this._processCache && (now - this._processCacheTime) < 30000) {
            console.log('Using cached process list');
            return this._processCache;
        }
        
        const response = await axios.get(`${API_BASE}/api/process/list`);
        if (response.data.success) {
            this._processCache = response.data;
            this._processCacheTime = now;
        }
        return response.data;
    },
    
    // 清除进程缓存
    clearProcessCache() {
        this._processCache = null;
        this._processCacheTime = 0;
    },
    
    // 获取进程详情
    async getProcessInfo(pid) {
        const response = await axios.get(`${API_BASE}/api/process/info`, {
            params: { pid }
        });
        return response.data;
    },
    
    // 获取内存映射
    async getMemoryMaps(pid, type = null) {
        const params = { pid };
        if (type) params.type = type;
        const response = await axios.get(`${API_BASE}/api/memory/maps`, { params });
        return response.data;
    },
    
    // 读取内存
    async readMemory(pid, address, length) {
        const response = await axios.post(`${API_BASE}/api/memory/read`, {
            pid,
            address,
            length
        });
        return response.data;
    },
    
    // 写入内存
    async writeMemory(pid, address, value) {
        const response = await axios.post(`${API_BASE}/api/memory/write`, {
            pid,
            address,
            value
        });
        return response.data;
    },
    
    // 反汇编
    async disassemble(pid, address, count) {
        const response = await axios.post(`${API_BASE}/api/disasm`, {
            pid,
            address,
            count
        });
        return response.data;
    },
    
    // 设置硬件断点
    async setWatchpoint(pid, address, timeout = 30) {
        const response = await axios.post(`${API_BASE}/api/debug/watchpoint`, {
            pid,
            address,
            timeout
        });
        return response.data;
    },
    
    // 分析基址
    async analyzeBase(pid, targetAddress, watchpointResult) {
        const response = await axios.post(`${API_BASE}/api/analysis/base`, {
            pid,
            targetAddress,
            watchpointResult
        });
        return response.data;
    }
};

