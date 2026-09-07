#define _GNU_SOURCE
#include <sys/mman.h>
#include <sys/random.h>
#include <sys/sysinfo.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdint.h>
#include <limits.h>

#define MB(x) ((size_t)(x) * 1024 * 1024)

static size_t pagesize;
static size_t f_offset = 0;
static uint64_t noise_state;

static uint64_t next_noise(void) {
    noise_state ^= noise_state << 13;
    noise_state ^= noise_state >> 7;
    noise_state ^= noise_state << 17;
    return noise_state;
}

static void fill_noise(unsigned char *start, size_t n) {
    size_t i = 0;

    while (i < n) {
        uint64_t value = next_noise();
        size_t length = n - i;
        if (length > sizeof(value))
            length = sizeof(value);
        memcpy(start + i, &value, length);
        for (size_t offset = 0; offset < length; ++offset) {
            if (start[i + offset] == 0)
                start[i + offset] = 0xa5;
        }
        i += length;
    }
}

static size_t target_bytes(void)
{
    struct sysinfo i;
    uint64_t total_bytes;
    uint64_t target;

    if (sysinfo(&i) != 0)
        return 0;

    total_bytes = (uint64_t)i.totalram * (uint64_t)i.mem_unit;
    target = total_bytes / 100;
    if (target > SIZE_MAX)
        target = SIZE_MAX;

    return (size_t)target;
}

static void seed(unsigned char *p, size_t len)
{
    const char *f[] = {
        "ELF\x02\x01\x01",
        "\x7f""ELF",
        "MZ",
        "PK\x03\x04",
        "PNG\r\n\x1a\n",
        "SQLite format 3",
        "BZh91AY&SY",
        "7z\xBC\xAF\x27\x1C",

        "ssh-ed25519",
        "ssh-rsa AAAA",
        "ecdsa-sha2-nistp256",
        "-----BEGIN PRIVATE KEY-----",
        "-----BEGIN RSA PRIVATE KEY-----",
        "-----BEGIN OPENSSH PRIVATE KEY-----",

        "TLS_AES_256_GCM_SHA384",
        "TLS_AES_128_GCM_SHA256",
        "TLS_CHACHA20_POLY1305_SHA256",
        "TLS_RSA_WITH_AES_256_CBC_SHA",
        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",

        "Mozilla/5.0",
        "curl/7.88.1",
        "Wget/1.21.3",
        "PostmanRuntime",
        "python-requests/2.31.0",

        "GET / HTTP/1.1",
        "POST /api/login",
        "PUT /api/data",
        "DELETE /api/item",
        "Host: example.com",
        "User-Agent:",
        "Accept: */*",
        "Content-Type: application/json",

        "application/json",
        "application/xml",
        "text/html",
        "text/plain",
        "multipart/form-data",

        "/bin/bash",
        "/usr/bin/python3",
        "/usr/bin/ssh",
        "/usr/bin/sudo",
        "/etc/passwd",
        "/etc/shadow",
        "/proc/self/status",
        "/dev/null",
        "/tmp/.X11-unix",

        "systemd",
        "dbus-daemon",
        "NetworkManager",
        "sshd",
        "cron",
        "udevd",

        "localhost",
        "127.0.0.1",
        "192.168.1.1",
        "8.8.8.8",
        "255.255.255.0",

        "Authorization: Bearer",
        "Cookie: session=",
        "Set-Cookie:",
        "JWT",
        "HS256",
        "RS256",

        "SELECT * FROM users",
        "INSERT INTO logs",
        "DROP TABLE sessions",
        "UPDATE accounts SET",
        "WHERE id=",

        "libc.so.6",
        "ld-linux-x86-64.so.2",
        "libpthread.so.0",
        "libssl.so",
        "libcrypto.so",

        "SIGSEGV",
        "SIGKILL",
        "SIGTERM",
        "core dumped",
        "segmentation fault",

        "uname -a",
        "whoami",
        "id -u",
        "ps aux",
        "netstat -an",

        "docker",
        "containerd",
        "overlayfs",
        "cgroup",
        "namespace",

        "AES256",
        "ChaCha20",
        "SHA256",
        "SHA512",
        "bcrypt",

        "index.html",
        "config.json",
        "settings.yaml",
        "data.db",
        "backup.tar.gz",

        "X11",
        "Wayland",
        "DISPLAY=:0",
        "TERM=xterm",
        "LANG=en_US.UTF-8",

        "DHCPDISCOVER",
        "DHCPREQUEST",
        "HTTP/1.1 200 OK",
        "HTTP/1.1 404 Not Found",
        "SSH-2.0-OpenSSH",
        "OpenSSL",
        "glibc",
        "kernel panic",
        "initrd.img",
        "vmlinuz",
        "bootloader",
        "grub.cfg"
    };

    size_t fn = sizeof(f) / sizeof(f[0]);

    if (len <= 256 || pagesize < 2)
        return;

    for (size_t o = 0; o + 256 < len; ) {
        size_t page_offset = (size_t)rand() % (pagesize / 2);
        size_t q_offset = o + page_offset;

        if (q_offset < len - 64) {
            unsigned char *q = p + q_offset;
            p[o] ^= (unsigned char)(o ^ (getpid() << 3));

            if ((((o / pagesize) + f_offset + rand()) % 23) == 0) {
                const char *s = f[(f_offset + (o / pagesize)) % fn];
                size_t sl = strlen(s);

                if (sl > 8) {
                    size_t start = rand() % (sl - 7);
                    size_t max_l = 8 + (rand() % 16);
                    size_t l = (sl - start < max_l) ? (sl - start) : max_l;

                    size_t max_safe = len - q_offset;
                    if (l > max_safe) l = max_safe;

                    memcpy(q, s + start, l);

                    size_t tail = rand() % 32;
                    size_t space_left = len - (q_offset + l);

                    if (tail > space_left) tail = space_left;

                    if (tail > 0) {
                        fill_noise(q + l, tail);
                    }

                    if ((rand() % 5) == 0 && max_safe >= sizeof(uintptr_t)) {
                        uintptr_t base = (uintptr_t)p;
                        uintptr_t addr = base + (rand() % len);
                        addr &= ~(uintptr_t)0xF;

                        size_t poff = rand() % (l > sizeof(uintptr_t) ? l - sizeof(uintptr_t) : 1);
                        memcpy(q + poff, &addr, sizeof(addr));
                    }
                } else {
                    size_t max_safe = len - q_offset;
                    size_t l = sl < max_safe ? sl : max_safe;
                    memcpy(q, s, l);
                }
            }
        }

        size_t skip = (pagesize / 2) + ((size_t)rand() % pagesize);
        if (skip > len - o)
            break;
        o += skip;
    }
}

int main(void)
{
    if (getrandom(&noise_state, sizeof(noise_state), GRND_NONBLOCK) !=
        (ssize_t)sizeof(noise_state)) {
        noise_state = (uint64_t)time(NULL) ^
                      ((uint64_t)getpid() << 32) ^
                      UINT64_C(0x9e3779b97f4a7c15);
    }
    if (noise_state == 0)
        noise_state = UINT64_C(0x9e3779b97f4a7c15);
    srand((unsigned int)(noise_state ^ (noise_state >> 32)));
    f_offset = rand();

    long system_pagesize = sysconf(_SC_PAGESIZE);
    if (system_pagesize <= 0)
        return 1;
    pagesize = (size_t)system_pagesize;

    size_t len = target_bytes();
    if (len < pagesize)
        return 1;

    unsigned char *p = mmap(
        NULL,
        len,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS,
        -1,
        0
    );

    if (p == MAP_FAILED)
        return 1;

    madvise(p, len, MADV_WILLNEED);
    madvise(p, len, MADV_RANDOM);

    fill_noise(p, len);
    seed(p, len);

    if (mlock(p, len) != 0) {
        for (size_t o = 0; o < len; o += MB(1)) {
            size_t chunk = len - o;
            if (chunk > MB(1))
                chunk = MB(1);
            (void)mlock(p + o, chunk);
        }
    }

    for (;;) {
        for (size_t o = 0; o < len; o += pagesize * 64) {
            p[o] ^= (unsigned char)(getpid() + (o >> 4));
        }

        f_offset ^= rand();

        if ((rand() % 3) == 0) {
            seed(p, len);
        }

        sleep(300 + (rand() % 300));
    }
}
