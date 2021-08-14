#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <error.h>
#include <errno.h>
#include <sys/mman.h>

#define SYS_memfd_secret 447

static int memfd_secret(unsigned int flags)
{
    return syscall(SYS_memfd_secret, flags);
}

static void *secret_alloc(size_t size)
{
    int fd = -1;
    void *m;
    void *result = NULL;

    fd = memfd_secret(0);
    if (fd < 0)
        goto out;

    if (ftruncate(fd, size) < 0)
        goto out;

    m = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (m == MAP_FAILED)
        goto out;

    result = m;

out:
    if (fd >= 0)
        close(fd);
    return result;
}

static void secret_free(void *p, size_t size)
{
    munmap(p, size);
}

int main(void)
{
    static const char data[] = "Secret data!";
    static const size_t size = sizeof(data);
    void *s;

    printf("PID: %d\n", getpid());

    s = secret_alloc(size);
    if (!s)
        error(2, errno, "secret_alloc() failed");

    strncpy(s, data, size);
    printf("Copied %zu bytes to secret area %p\n", size, s);

    printf("Waiting...\n");
    pause();

    secret_free(s, size);
    return 0;
}
