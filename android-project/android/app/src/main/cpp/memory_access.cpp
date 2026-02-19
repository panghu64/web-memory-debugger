#include <jni.h>
#include <cstring>
#include <android/log.h>

#define LOG_TAG "MemoryAccess"
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN,  LOG_TAG, __VA_ARGS__)

extern "C" JNIEXPORT jbyteArray JNICALL
Java_com_example_myapplication_mem_MemoryAccess_read(JNIEnv* env, jclass /*clazz*/, jlong address, jint length) {
    if (length <= 0 || length > 16 * 1024 * 1024) { // hard cap 16MB to avoid abuse
        LOGW("Invalid read length: %d", length);
        return nullptr;
    }
    auto* src = reinterpret_cast<const unsigned char*>(static_cast<uintptr_t>(address));
    jbyteArray result = env->NewByteArray(length);
    if (!result) return nullptr;

    // WARNING: invalid address will crash the process (SIGSEGV)
    // This is intended for same-process valid mapped addresses only.
    void* dst_ptr = env->GetPrimitiveArrayCritical(result, nullptr);
    if (!dst_ptr) return nullptr;
    memcpy(dst_ptr, src, static_cast<size_t>(length));
    env->ReleasePrimitiveArrayCritical(result, dst_ptr, 0);
    return result;
}

extern "C" JNIEXPORT void JNICALL
Java_com_example_myapplication_mem_MemoryAccess_write(JNIEnv* env, jclass /*clazz*/, jlong address, jbyteArray data) {
    if (!data) return;
    jsize length = env->GetArrayLength(data);
    if (length <= 0 || length > 16 * 1024 * 1024) {
        LOGW("Invalid write length: %d", length);
        return;
    }
    auto* dst = reinterpret_cast<unsigned char*>(static_cast<uintptr_t>(address));
    void* dst_ptr = static_cast<void*>(dst);

    jboolean isCopy = JNI_FALSE;
    void* src_ptr = env->GetPrimitiveArrayCritical(data, &isCopy);
    if (!src_ptr) return;
    // WARNING: invalid or read-only address will crash or have undefined behavior
    memcpy(dst_ptr, src_ptr, static_cast<size_t>(length));
    env->ReleasePrimitiveArrayCritical(data, src_ptr, JNI_ABORT);
}
