#include <jni.h>
#include <dlfcn.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

typedef int (*decode_fn)(uint64_t *, uint32_t, const void *,
                         const uint8_t *, size_t *, size_t,
                         uint8_t *, size_t *, size_t);

static int last_rc;

JNIEXPORT jint JNICALL
Java_io_umbral_module_XzDecoder_lastRc(JNIEnv *env, jclass cls)
{
    (void)env; (void)cls;
    return (jint)last_rc;
}

JNIEXPORT jbyteArray JNICALL
Java_io_umbral_module_XzDecoder_nativeDecode(JNIEnv *env, jclass cls, jbyteArray in)
{
    (void)cls;
    void *h = dlopen("liblzma.so", RTLD_NOW);
    if (!h) return NULL;
    decode_fn fn = (decode_fn)dlsym(h, "lzma_stream_buffer_decode");
    if (!fn) { dlclose(h); return NULL; }

    jsize inLen = (*env)->GetArrayLength(env, in);
    jbyte *inBuf = (*env)->GetByteArrayElements(env, in, NULL);
    if (!inBuf) { dlclose(h); return NULL; }

    size_t cap = (size_t)inLen * 8 + (1u << 20);
    uint8_t *out = NULL;
    size_t outPos = 0;
    int tries;

    for (tries = 0; tries < 6; tries++) {
        out = (uint8_t *)malloc(cap);
        if (!out) break;
        {
            uint64_t memlimit = UINT64_MAX;
            size_t inPos = 0;
            int rc;
            outPos = 0;
            rc = fn(&memlimit, 0, NULL, (const uint8_t *)inBuf, &inPos,
                    (size_t)inLen, out, &outPos, cap);
            if (rc == 0) break;              /* LZMA_OK */
            free(out); out = NULL;
            /*
             * lzma_ret 取值：0 OK, 1 STREAM_END, 5 MEM_ERROR, 6 MEMLIMIT,
             * 7 FORMAT_ERROR, 8 OPTIONS_ERROR, 9 DATA_ERROR, 10 BUF_ERROR
             * 之前把 9 当成「缓冲区不够」，其实 9 是数据错误、10 才是缓冲区不够。
             */
            if (rc != 10) { last_rc = rc; break; }
            cap *= 2;
        }
    }

    (*env)->ReleaseByteArrayElements(env, in, inBuf, JNI_ABORT);
    dlclose(h);
    if (!out) return NULL;
    {
        jbyteArray ret = (*env)->NewByteArray(env, (jsize)outPos);
        if (ret) (*env)->SetByteArrayRegion(env, ret, 0, (jsize)outPos, (const jbyte *)out);
        free(out);
        return ret;
    }
}