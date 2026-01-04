/*
 * softrx_probe.c - Deterministic syscall generator for SoftRX validation
 * Target: 64-bit Ubuntu 24.04 LTS (AMD64)
 * Compile: gcc -o softrx_probe softrx_probe.c -static -pthread
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/utsname.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>
#include <pthread.h>
#include <poll.h>
#include <time.h>

/* Configuration */
#define WORKSPACE_DIR "./softrx_work"
#define TEST_FILE_A "test_file_a.txt"
#define TEST_FILE_B "test_file_b.txt"
#define TEST_CONTENT "SoftRX_Test_Payload_12345"
#define FORBIDDEN_PATH "/etc/softrx_forbidden_test"
#define REDIRECT_PATH "/tmp/redirect_me"
#define NUM_THREADS 4
#define THREAD_ITERATIONS 10

/* Run modes */
typedef enum {
    MODE_SMOKE,
    MODE_FULL,
    MODE_CHAOS
} run_mode_t;

/* Global state */
static run_mode_t g_mode = MODE_SMOKE;
static char g_workspace[512];
static int g_overall_pass = 1;
static volatile sig_atomic_t g_signal_count = 0;

/* Stage result tracking */
typedef struct {
    int stage_num;
    const char *stage_name;
    int passed;
    const char *expect;
} stage_result_t;

/* Utility macros */
#define STAGE_START(n, name) \
    printf("STAGE %d START: %s\n", n, name); \
    fflush(stdout);

#define STAGE_EXPECT(n, expect_str) \
    printf("STAGE %d EXPECT: %s\n", n, expect_str); \
    fflush(stdout);

#define STAGE_RESULT(n, pass, ...) \
    do { \
        if (pass) { \
            printf("STAGE %d RESULT: PASS\n", n); \
        } else { \
            printf("STAGE %d RESULT: FAIL - ", n); \
            printf(__VA_ARGS__); \
            printf("\n"); \
            g_overall_pass = 0; \
        } \
        fflush(stdout); \
    } while(0)

/* Signal handler for thread stress test */
static void sigusr1_handler(int sig) {
    (void)sig; /* Unused parameter */
    g_signal_count++;
}

/* Stage 0: Banner + environment stamp */
static int stage0_banner(void) {
    pid_t pid, ppid;
    uid_t uid;
    gid_t gid;
    char cwd[512];
    struct utsname uts;
    struct timespec ts;
    int fd;
    
    STAGE_START(0, "Banner + Environment");
    STAGE_EXPECT(0, "Print PID, PPID, UID, GID, CWD and basic /proc info");
    
    pid = getpid();
    ppid = getppid();
    uid = getuid();
    gid = getgid();
    if (getcwd(cwd, sizeof(cwd)) == NULL) {
        strcpy(cwd, "<unknown>");
    }
    
    uname(&uts);
    clock_gettime(CLOCK_MONOTONIC, &ts);
    
    printf("  PID=%d PPID=%d UID=%d GID=%d\n", pid, ppid, uid, gid);
    printf("  CWD=%s\n", cwd);
    printf("  SYSTEM=%s %s %s\n", uts.sysname, uts.release, uts.machine);
    printf("  MONOTONIC=%ld.%09ld\n", ts.tv_sec, ts.tv_nsec);
    
    /* Try reading /proc/self/status */
    fd = open("/proc/self/status", O_RDONLY);
    if (fd >= 0) {
        char buf[256];
        ssize_t n = read(fd, buf, sizeof(buf) - 1);
        if (n > 0) {
            buf[n] = '\0';
            printf("  /proc/self/status: readable (%zd bytes)\n", n);
        }
        close(fd);
    }
    
    STAGE_RESULT(0, 1, "");
    return 1;
}

/* Stage 1: Filesystem operations */
static int stage1_filesystem(void) {
    char path_a[512], path_b[512], path_link[512], path_sym[512];
    int fd;
    ssize_t written, nread;
    char buf[512];
    
    STAGE_START(1, "Filesystem Operations");
    STAGE_EXPECT(1, "Create/write/read/rename/link/unlink files in workspace");
    
    snprintf(path_a, sizeof(path_a), "%s/%s", g_workspace, TEST_FILE_A);
    snprintf(path_b, sizeof(path_b), "%s/%s", g_workspace, TEST_FILE_B);
    snprintf(path_link, sizeof(path_link), "%s/hardlink", g_workspace);
    snprintf(path_sym, sizeof(path_sym), "%s/symlink", g_workspace);
    
    /* Create and write file A */
    fd = open(path_a, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd < 0) {
        STAGE_RESULT(1, 0, "open(%s) failed: %s", path_a, strerror(errno));
        return 0;
    }
    
    written = write(fd, TEST_CONTENT, strlen(TEST_CONTENT));
    if (written != (ssize_t)strlen(TEST_CONTENT)) {
        close(fd);
        STAGE_RESULT(1, 0, "write failed: %zd bytes", written);
        return 0;
    }
    
    fsync(fd);
    close(fd);
    
    /* Read and verify */
    fd = open(path_a, O_RDONLY);
    if (fd < 0) {
        STAGE_RESULT(1, 0, "reopen failed: %s", strerror(errno));
        return 0;
    }
    
    memset(buf, 0, sizeof(buf));
    nread = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    
    if (nread != (ssize_t)strlen(TEST_CONTENT) || strcmp(buf, TEST_CONTENT) != 0) {
        STAGE_RESULT(1, 0, "content mismatch: read '%s'", buf);
        return 0;
    }
    
    /* Rename A to B */
    if (rename(path_a, path_b) != 0) {
        STAGE_RESULT(1, 0, "rename failed: %s", strerror(errno));
        return 0;
    }
    
    /* Create hardlink and symlink */
    if (link(path_b, path_link) != 0) {
        STAGE_RESULT(1, 0, "hardlink failed: %s", strerror(errno));
        return 0;
    }
    
    /* Use symlinkat for proper syscall interception */
    if (symlinkat(TEST_FILE_B, AT_FDCWD, path_sym) != 0) {
        STAGE_RESULT(1, 0, "symlink failed: %s", strerror(errno));
        return 0;
    }
    
    /* Test forbidden path (expected to fail if SoftRX denies) */
    fd = open(FORBIDDEN_PATH, O_WRONLY | O_CREAT, 0644);
    if (fd >= 0) {
        printf("  NOTE: Write to %s succeeded (SoftRX not denying)\n", FORBIDDEN_PATH);
        close(fd);
        unlink(FORBIDDEN_PATH);
    } else {
        printf("  NOTE: Write to %s denied (errno=%d, expected if SoftRX active)\n", 
               FORBIDDEN_PATH, errno);
    }
    
    /* Test path rewrite */
    fd = open(REDIRECT_PATH, O_RDONLY);
    if (fd >= 0) {
        char redir_buf[256];
        memset(redir_buf, 0, sizeof(redir_buf));
        read(fd, redir_buf, sizeof(redir_buf) - 1);
        printf("  NOTE: %s opened, content: '%s'\n", REDIRECT_PATH, redir_buf);
        close(fd);
    }
    
    /* Cleanup */
    unlink(path_b);
    unlink(path_link);
    unlink(path_sym);
    
    STAGE_RESULT(1, 1, "");
    return 1;
}

/* Stage 2: Process + execve */
static int stage2_process(void) {
    pid_t pid;
    int status;
    char *argv_true[] = {"/bin/true", NULL};
    char *argv_fail[] = {"/nonexistent/binary/path", NULL};
    char *envp[] = {NULL};
    
    STAGE_START(2, "Process + Execve");
    STAGE_EXPECT(2, "Fork children, execve /bin/true and test nonexistent path");
    
    /* First child: successful exec */
    pid = fork();
    if (pid < 0) {
        STAGE_RESULT(2, 0, "fork failed: %s", strerror(errno));
        return 0;
    }
    
    if (pid == 0) {
        /* Child */
        execve("/bin/true", argv_true, envp);
        _exit(127); /* Should not reach */
    }
    
    /* Parent waits */
    if (waitpid(pid, &status, 0) < 0) {
        STAGE_RESULT(2, 0, "waitpid failed: %s", strerror(errno));
        return 0;
    }
    
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        STAGE_RESULT(2, 0, "child exit status wrong: %d", WEXITSTATUS(status));
        return 0;
    }
    
    /* Second child: failed exec */
    pid = fork();
    if (pid < 0) {
        STAGE_RESULT(2, 0, "fork2 failed: %s", strerror(errno));
        return 0;
    }
    
    if (pid == 0) {
        execve("/nonexistent/binary/path", argv_fail, envp);
        /* Should fail and reach here */
        if (errno == ENOENT) {
            _exit(42); /* Expected failure marker */
        }
        _exit(1);
    }
    
    waitpid(pid, &status, 0);
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 42) {
        STAGE_RESULT(2, 0, "nonexistent exec didn't fail correctly");
        return 0;
    }
    
    STAGE_RESULT(2, 1, "");
    return 1;
}

/* Stage 3: Memory operations */
static int stage3_memory(void) {
    size_t page_size;
    void *mem;
    int ret;
    
    STAGE_START(3, "Memory: mmap/mprotect");
    STAGE_EXPECT(3, "Allocate page, write pattern, attempt PROT_EXEC");
    
    page_size = sysconf(_SC_PAGESIZE);
    
    /* Allocate RW page */
    mem = mmap(NULL, page_size, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mem == MAP_FAILED) {
        STAGE_RESULT(3, 0, "mmap failed: %s", strerror(errno));
        return 0;
    }
    
    /* Write pattern */
    memset(mem, 0xAA, page_size);
    
    /* Attempt PROT_EXEC (SoftRX may deny this) */
    ret = mprotect(mem, page_size, PROT_READ | PROT_EXEC);
    if (ret == 0) {
        printf("  NOTE: mprotect(PROT_EXEC) succeeded (SoftRX not blocking)\n");
    } else {
        printf("  NOTE: mprotect(PROT_EXEC) denied (errno=%d, expected if SoftRX active)\n", 
               errno);
    }
    
    munmap(mem, page_size);
    
    STAGE_RESULT(3, 1, "");
    return 1;
}

/* Stage 4: Networking */
static int stage4_networking(void) {
    int sock, ret, fd;
    struct sockaddr_in addr;
    const char *msg = "test";
    char buf[256];
    
    STAGE_START(4, "Networking");
    STAGE_EXPECT(4, "Create socket, attempt connect to localhost");
    
    /* TCP socket */
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        STAGE_RESULT(4, 0, "socket failed: %s", strerror(errno));
        return 0;
    }
    
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(9999);
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    
    /* Attempt connect (expected to fail, no listener) */
    ret = connect(sock, (struct sockaddr *)&addr, sizeof(addr));
    printf("  NOTE: connect to 127.0.0.1:9999 returned %d (errno=%d)\n", ret, errno);
    
    close(sock);
    
    /* UDP socket test */
    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock >= 0) {
        addr.sin_port = htons(8888);
        sendto(sock, msg, strlen(msg), 0, (struct sockaddr *)&addr, sizeof(addr));
        close(sock);
    }
    
    /* Read /etc/resolv.conf (simulated DNS behavior) */
    fd = open("/etc/resolv.conf", O_RDONLY);
    if (fd >= 0) {
        read(fd, buf, sizeof(buf) - 1);
        close(fd);
    }
    
    STAGE_RESULT(4, 1, "");
    return 1;
}

/* Stage 5: FD and ioctl operations */
static int stage5_fd_ioctl(void) {
    char path[512];
    int fd, fd2, fd3, flags, bytes_available;
    int pipefd[2];
    struct pollfd pfd;
    
    STAGE_START(5, "FD + ioctl");
    STAGE_EXPECT(5, "dup FDs, fcntl, ioctl, poll on pipe");
    
    snprintf(path, sizeof(path), "%s/ioctl_test", g_workspace);
    
    fd = open(path, O_CREAT | O_RDWR, 0644);
    if (fd < 0) {
        STAGE_RESULT(5, 0, "open failed: %s", strerror(errno));
        return 0;
    }
    
    /* dup operations */
    fd2 = dup(fd);
    fd3 = dup3(fd, 100, O_CLOEXEC);
    if (fd2 < 0 || fd3 < 0) {
        close(fd);
        STAGE_RESULT(5, 0, "dup failed");
        return 0;
    }
    
    /* fcntl - set O_NONBLOCK */
    flags = fcntl(fd, F_GETFL);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    
    /* ioctl - harmless FIONREAD */
    bytes_available = 0;
    ioctl(fd, FIONREAD, &bytes_available);
    
    /* Pipe and poll */
    if (pipe(pipefd) != 0) {
        close(fd);
        close(fd2);
        close(fd3);
        STAGE_RESULT(5, 0, "pipe failed: %s", strerror(errno));
        return 0;
    }
    
    pfd.fd = pipefd[0];
    pfd.events = POLLIN;
    poll(&pfd, 1, 0); /* Non-blocking poll */
    
    close(pipefd[0]);
    close(pipefd[1]);
    close(fd);
    close(fd2);
    close(fd3);
    unlink(path);
    
    STAGE_RESULT(5, 1, "");
    return 1;
}

/* Thread worker for stage 6 */
static void *thread_worker(void *arg) {
    int tid = *(int *)arg;
    char path[512];
    int i, fd;
    struct timespec ts;
    
    for (i = 0; i < THREAD_ITERATIONS; i++) {
        snprintf(path, sizeof(path), "%s/thread_%d_%d", g_workspace, tid, i);
        
        fd = open(path, O_CREAT | O_RDWR, 0644);
        if (fd >= 0) {
            write(fd, "T", 1);
            clock_gettime(CLOCK_MONOTONIC, &ts);
            close(fd);
            unlink(path);
        }
        
        /* Yield to increase concurrency */
        usleep(1);
    }
    
    return NULL;
}

/* Stage 6: Threads + signals */
static int stage6_threads_signals(void) {
    struct sigaction sa;
    pthread_t threads[NUM_THREADS];
    int tids[NUM_THREADS];
    int i;
    
    if (g_mode == MODE_SMOKE) {
        printf("STAGE 6: SKIPPED (smoke mode)\n");
        return 1;
    }
    
    STAGE_START(6, "Threads + Signals");
    STAGE_EXPECT(6, "Spawn threads doing syscalls, send signals concurrently");
    
    /* Install signal handler */
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sigusr1_handler;
    sigaction(SIGUSR1, &sa, NULL);
    
    g_signal_count = 0;
    
    /* Spawn threads */
    for (i = 0; i < NUM_THREADS; i++) {
        tids[i] = i;
        if (pthread_create(&threads[i], NULL, thread_worker, &tids[i]) != 0) {
            STAGE_RESULT(6, 0, "pthread_create failed");
            return 0;
        }
    }
    
    /* Send signals while threads work */
    for (i = 0; i < 5; i++) {
        usleep(1000);
        kill(getpid(), SIGUSR1);
    }
    
    /* Wait for threads */
    for (i = 0; i < NUM_THREADS; i++) {
        pthread_join(threads[i], NULL);
    }
    
    printf("  Signal handler invoked %d times\n", g_signal_count);
    
    if (g_signal_count < 5) {
        STAGE_RESULT(6, 0, "signal count too low: %d", g_signal_count);
        return 0;
    }
    
    STAGE_RESULT(6, 1, "");
    return 1;
}

/* Main execution */
static void print_usage(const char *prog) {
    fprintf(stderr, "Usage: %s [OPTIONS]\n", prog);
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  --mode=smoke        Fast core syscalls (default)\n");
    fprintf(stderr, "  --mode=full         All stages\n");
    fprintf(stderr, "  --mode=chaos        Threads + signals stress test\n");
    fprintf(stderr, "  --policy-hints      Print SoftRX policy recommendations\n");
    fprintf(stderr, "  --help              Show this help\n");
}

static void print_policy_hints(void) {
    printf("\n=== RECOMMENDED SOFTRX DEMO POLICY ===\n");
    printf("DENY: mprotect() with PROT_EXEC\n");
    printf("DENY: openat() writes to /etc/*\n");
    printf("REWRITE: connect() to non-loopback -> 127.0.0.1:9 (discard sink)\n");
    printf("REWRITE: openat(%s) -> workspace file\n", REDIRECT_PATH);
    printf("ALLOW+LOG: everything else\n");
    printf("\nExpected telemetry for each syscall:\n");
    printf("  - timestamp (monotonic), pid/tid\n");
    printf("  - syscall number + name\n");
    printf("  - decoded args (paths, sockaddr, prot flags)\n");
    printf("  - decision (allow/deny/rewrite/emulate)\n");
    printf("  - return value + errno\n");
    printf("  - latency (time in SoftRX)\n");
    printf("  - correlation ID per syscall\n");
    printf("=====================================\n\n");
}

int main(int argc, char **argv) {
    int i;
    
    /* Parse arguments */
    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--mode=smoke") == 0) {
            g_mode = MODE_SMOKE;
        } else if (strcmp(argv[i], "--mode=full") == 0) {
            g_mode = MODE_FULL;
        } else if (strcmp(argv[i], "--mode=chaos") == 0) {
            g_mode = MODE_CHAOS;
        } else if (strcmp(argv[i], "--policy-hints") == 0) {
            print_policy_hints();
            return 0;
        } else if (strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        } else {
            fprintf(stderr, "Unknown option: %s\n", argv[i]);
            print_usage(argv[0]);
            return 1;
        }
    }
    
    /* Setup workspace */
    snprintf(g_workspace, sizeof(g_workspace), "%s", WORKSPACE_DIR);
    mkdir(g_workspace, 0755);
    
    printf("=== SOFTRX_PROBE START ===\n");
    printf("Mode: %s\n", 
           g_mode == MODE_SMOKE ? "smoke" : 
           g_mode == MODE_FULL ? "full" : "chaos");
    printf("Workspace: %s\n\n", g_workspace);
    
    /* Run stages */
    stage0_banner();
    stage1_filesystem();
    stage2_process();
    stage3_memory();
    stage4_networking();
    stage5_fd_ioctl();
    
    if (g_mode >= MODE_FULL) {
        stage6_threads_signals();
    }
    
    /* Final result */
    printf("\n=== OVERALL: %s ===\n", g_overall_pass ? "PASS" : "FAIL");
    
    return g_overall_pass ? 0 : 1;
}