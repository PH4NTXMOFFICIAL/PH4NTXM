#define _GNU_SOURCE

#include <dlfcn.h>
#include <stdlib.h>
#include <string.h>

typedef const unsigned char *(*gl_get_string_fn)(unsigned int);
typedef const char *(*egl_query_string_fn)(void *, int);
typedef const char *(*glx_client_string_fn)(void *, int);
typedef const char *(*glx_server_string_fn)(void *, int, int);

const unsigned char *glGetString(unsigned int name)
{
    const char *value;
    gl_get_string_fn original;
    void *symbol;

    if (name == 0x1f00) {
        value = getenv("PH4NTXM_GL_VENDOR");
        if (value != NULL && value[0] != '\0')
            return (const unsigned char *)value;
    }
    if (name == 0x1f01) {
        value = getenv("PH4NTXM_GL_RENDERER");
        if (value != NULL && value[0] != '\0')
            return (const unsigned char *)value;
    }

    symbol = dlsym(RTLD_NEXT, "glGetString");
    memcpy(&original, &symbol, sizeof(original));
    return original == NULL ? NULL : original(name);
}

const char *eglQueryString(void *display, int name)
{
    const char *value;
    egl_query_string_fn original;
    void *symbol;

    if (name == 0x3053) {
        value = getenv("PH4NTXM_GL_VENDOR");
        if (value != NULL && value[0] != '\0')
            return value;
    }

    symbol = dlsym(RTLD_NEXT, "eglQueryString");
    memcpy(&original, &symbol, sizeof(original));
    return original == NULL ? NULL : original(display, name);
}

const char *glXGetClientString(void *display, int name)
{
    const char *value;
    glx_client_string_fn original;
    void *symbol;

    if (name == 1) {
        value = getenv("PH4NTXM_GL_VENDOR");
        if (value != NULL && value[0] != '\0')
            return value;
    }

    symbol = dlsym(RTLD_NEXT, "glXGetClientString");
    memcpy(&original, &symbol, sizeof(original));
    return original == NULL ? NULL : original(display, name);
}

const char *glXQueryServerString(void *display, int screen, int name)
{
    const char *value;
    glx_server_string_fn original;
    void *symbol;

    if (name == 1) {
        value = getenv("PH4NTXM_GL_VENDOR");
        if (value != NULL && value[0] != '\0')
            return value;
    }

    symbol = dlsym(RTLD_NEXT, "glXQueryServerString");
    memcpy(&original, &symbol, sizeof(original));
    return original == NULL ? NULL : original(display, screen, name);
}
