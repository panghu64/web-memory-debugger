cmake_minimum_required(VERSION 3.18.1)

project(memoryaccess)

add_library(memoryaccess SHARED
    memory_access.cpp
)

add_executable(memtool
    memtool.cpp
)

# 添加基于/proc/mem的版本（类似CE ceserver，避免ptrace）
add_executable(memtool_procmem
    memtool_procmem.cpp
)

find_library(log-lib log)

target_link_libraries(memoryaccess
    ${log-lib}
)

# 配置Capstone反汇编引擎
# CMAKE_SOURCE_DIR = .../app/src/main/cpp
# 向上3级到项目根，然后定位jniLibs
set(CAPSTONE_LIB_PATH "${CMAKE_SOURCE_DIR}/../jniLibs/${ANDROID_ABI}/libcapstone.so")
set(CAPSTONE_INCLUDE_DIR "${CMAKE_SOURCE_DIR}/capstone")

message(STATUS "🔍 检查Capstone库")
message(STATUS "  PROJECT_ROOT = ${PROJECT_ROOT}")
message(STATUS "  CAPSTONE_LIB_PATH = ${CAPSTONE_LIB_PATH}")
message(STATUS "  ANDROID_ABI = ${ANDROID_ABI}")
message(STATUS "  EXISTS = ${CAPSTONE_LIB_PATH}")

if(EXISTS ${CAPSTONE_LIB_PATH})
    message(STATUS "✅ Found Capstone library: ${CAPSTONE_LIB_PATH}")
    message(STATUS "✅ Capstone headers: ${CAPSTONE_INCLUDE_DIR}")
    
    # 添加Capstone头文件路径
    target_include_directories(memtool PRIVATE ${CAPSTONE_INCLUDE_DIR})
    
    # 导入Capstone库
    add_library(capstone SHARED IMPORTED)
    set_target_properties(capstone PROPERTIES IMPORTED_LOCATION ${CAPSTONE_LIB_PATH})
    
    # 链接Capstone
    target_link_libraries(memtool capstone)
    
    # 定义HAVE_CAPSTONE宏
    target_compile_definitions(memtool PRIVATE HAVE_CAPSTONE)
    
    message(STATUS "✅ Capstone enabled for memtool with disasm support")
else()
    message(WARNING "❌ Capstone library not found at ${CAPSTONE_LIB_PATH}")
    message(WARNING "   Disasm functionality will be disabled")
endif()

# 为memtool_procmem配置Capstone（强制配置ARM64/ARMv7）
if(ANDROID_ABI STREQUAL "arm64-v8a" OR ANDROID_ABI STREQUAL "armeabi-v7a")
    message(STATUS "🔧 配置memtool_procmem的Capstone（${ANDROID_ABI}）")
    target_include_directories(memtool_procmem PRIVATE ${CAPSTONE_INCLUDE_DIR})
    add_library(capstone_procmem SHARED IMPORTED)
    set_target_properties(capstone_procmem PROPERTIES IMPORTED_LOCATION ${CAPSTONE_LIB_PATH})
    target_link_libraries(memtool_procmem capstone_procmem)
    target_compile_definitions(memtool_procmem PRIVATE HAVE_CAPSTONE)
    message(STATUS "✅ Capstone enabled for memtool_procmem")
endif()

set_target_properties(memtool PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_LIBRARY_OUTPUT_DIRECTORY}"
)

set_target_properties(memtool_procmem PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_LIBRARY_OUTPUT_DIRECTORY}"
)

