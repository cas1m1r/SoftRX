/*
 * softrx_security_test.c - Security vulnerability validation suite
 * Tests fixes for audit findings in SoftRX sandbox
 * 
 * Compile: gcc -O2 -Wall -Wextra -std=gnu11 -pthread -o softrx_security_test softrx_security_test.c
 * 
 * Usage: ./softrx_security_test [test_name|all]
 * 
 * Tests map to specific audit findings:
 *   1. Symlink escape attacks
 *   2. TOCTOU race conditions
 *   3. Syscall evasion techniques
 *   4. Anti-sandbox detection methods
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
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <time.h>
#include <signal.h>
#include <limits.h>

/* Test configuration */
#define TEST_DIR "./softrx_security_test"
#define JAIL_DIR "./softrx_security_test/jail"
#define SENSITIVE_TARGET "/etc/softrx_canary"
#define TIMING_THRESHOLD_US 1000  /* 1ms - syscalls should be faster */

/* Colors for output */
#define COLOR_RED     "\x1b[31m"
#define COLOR_GREEN   "\x1b[32m"
#define COLOR_YELLOW  "\x1b[33m"
#define COLOR_BLUE    "\x1b[34m"
#define COLOR_RESET   "\x1b[0m"

/* Test result tracking */
typedef struct {
    const char *name;
    int passed;
    int exploited;  /* 1 if vulnerability was successfully exploited */
    const char *details;
} test_result_t;

static int g_tests_run = 0;
static int g_tests_passed = 0;
static int g_exploits_blocked = 0;
static int g_exploits_successful = 0;

/* Utility macros */
#define TEST_START(name) \
    printf("\n" COLOR_BLUE "═══════════════════════════════════════════════════════════════\n" COLOR_RESET); \
    printf(COLOR_BLUE "TEST: %s\n" COLOR_RESET, name); \
    printf(COLOR_BLUE "═══════════════════════════════════════════════════════════════\n" COLOR_RESET); \
    g_tests_run++;

#define TEST_EXPECT(desc) \
    printf(COLOR_YELLOW "EXPECT: %s\n" COLOR_RESET, desc);

#define TEST_RESULT(passed, exploited, msg) \
    do { \
        if (passed) { \
            g_tests_passed++; \
            if (exploited) { \
                g_exploits_successful++; \
                printf(COLOR_RED "RESULT: PASS (EXPLOIT SUCCESSFUL - VULNERABILITY EXISTS)\n" COLOR_RESET); \
                if (msg && strlen(msg) > 0) printf("  Details: %s\n", msg); \
            } else { \
                g_exploits_blocked++; \
                printf(COLOR_GREEN "RESULT: PASS (EXPLOIT BLOCKED - FIX VERIFIED)\n" COLOR_RESET); \
                if (msg && strlen(msg) > 0) printf("  Details: %s\n", msg); \
            } \
        } else { \
            printf(COLOR_RED "RESULT: FAIL - %s\n" COLOR_RESET, msg); \
        } \
        printf(COLOR_BLUE "───────────────────────────────────────────────────────────────\n" COLOR_RESET); \
        fflush(stdout); \
    } while(0)

/* Forward declarations */
void test_symlink_escape_basic(void);
void test_symlink_escape_nested(void);
void test_symlink_escape_relative(void);
void test_hardlink_escape(void);
void test_toctou_path_swap(void);
void test_toctou_fd_confusion(void);
void test_toctou_race_window(void);
void test_mmap_rwx_direct(void);
void test_socket_write_bypass(void);
void test_syscall_aliasing(void);
void test_timing_sidechannel(void);
void test_procfs_detection(void);
void test_getpid_timing(void);
void test_null_byte_injection(void);
void test_dotdot_traversal(void);
void test_path_canonicalization(void);
void test_composite_attack(void);

/* Helper functions */
void setup_test_env(void);
void cleanup_test_env(void);
int create_sensitive_canary(void);
int check_canary_compromised(void);
long long get_time_us(void);

/* ═══════════════════════════════════════════════════════════════
 * CATEGORY 1: SYMLINK ESCAPE ATTACKS
 * Testing Finding #1 from audit
 * ═══════════════════════════════════════════════════════════════ */

void test_symlink_escape_basic(void) {
    char symlink_path[PATH_MAX];
    char target_path[PATH_MAX];
    int fd, canary_before, canary_after;
    
    TEST_START("Symlink Escape - Basic");
    TEST_EXPECT("Create symlink jail/escape -> /etc/softrx_canary, attempt write through it");
    
    snprintf(symlink_path, sizeof(symlink_path), "%s/escape", JAIL_DIR);
    snprintf(target_path, sizeof(target_path), "%s", SENSITIVE_TARGET);
    
    /* Create canary file outside jail */
    canary_before = create_sensitive_canary();
    if (canary_before < 0) {
        TEST_RESULT(0, 0, "Failed to create canary");
        return;
    }
    
    /* Create symlink inside jail pointing outside */
    if (symlink(target_path, symlink_path) != 0) {
        char errmsg[256];
        snprintf(errmsg, sizeof(errmsg), "symlink() failed: %s", strerror(errno));
        TEST_RESULT(0, 0, errmsg);
        return;
    }
    
    printf("Created symlink: %s -> %s\n", symlink_path, target_path);
    
    /* Attempt to write through the symlink */
    printf("Attempting open(%s, O_WRONLY)...\n", symlink_path);
    fd = open(symlink_path, O_WRONLY | O_APPEND);
    
    if (fd >= 0) {
        /* Write succeeded - try to modify canary */
        const char *exploit = "EXPLOITED_VIA_SYMLINK\n";
        ssize_t written = write(fd, exploit, strlen(exploit));
        close(fd);
        
        printf("Write returned: %zd bytes\n", written);
        
        /* Check if canary was actually modified */
        canary_after = check_canary_compromised();
        
        if (canary_after > canary_before) {
            char msg[256];
            snprintf(msg, sizeof(msg), "Canary modified: %d -> %d bytes", 
                    canary_before, canary_after);
            TEST_RESULT(1, 1, msg);
        } else {
            printf("Write succeeded but canary unchanged (possible redirect)\n");
            TEST_RESULT(1, 0, "");
        }
    } else {
        printf("open() denied: %s\n", strerror(errno));
        if (errno == EPERM || errno == EACCES) {
            TEST_RESULT(1, 0, "");
        } else {
            char msg[256];
            snprintf(msg, sizeof(msg), "Unexpected errno: %d", errno);
            TEST_RESULT(0, 0, msg);
        }
    }
    
    unlink(symlink_path);
}

void test_symlink_escape_nested(void) {
    char link1[PATH_MAX], link2[PATH_MAX], link3[PATH_MAX];
    int fd, canary_before, canary_after;
    
    TEST_START("Symlink Escape - Nested Chain");
    TEST_EXPECT("Create chain: jail/a -> jail/b -> jail/c -> /etc/softrx_canary");
    
    snprintf(link1, sizeof(link1), "%s/link_a", JAIL_DIR);
    snprintf(link2, sizeof(link2), "%s/link_b", JAIL_DIR);
    snprintf(link3, sizeof(link3), "%s/link_c", JAIL_DIR);
    
    canary_before = create_sensitive_canary();
    if (canary_before < 0) {
        TEST_RESULT(0, 0, "Failed to create canary");
        return;
    }
    
    /* Create chain: a -> b -> c -> /etc/canary */
    symlink(link2, link1);
    symlink(link3, link2);
    symlink(SENSITIVE_TARGET, link3);
    
    printf("Created chain: %s -> %s -> %s -> %s\n",
           link1, link2, link3, SENSITIVE_TARGET);
    
    fd = open(link1, O_WRONLY | O_APPEND);
    
    if (fd >= 0) {
        const char *exploit = "NESTED_SYMLINK_EXPLOIT\n";
        write(fd, exploit, strlen(exploit));
        close(fd);
        
        canary_after = check_canary_compromised();
        
        if (canary_after > canary_before) {
            TEST_RESULT(1, 1, "Nested symlink chain bypassed jail");
        } else {
            TEST_RESULT(1, 0, "");
        }
    } else {
        if (errno == EPERM || errno == EACCES) {
            TEST_RESULT(1, 0, "");
        } else {
            char msg[256];
            snprintf(msg, sizeof(msg), "Unexpected errno: %d", errno);
            TEST_RESULT(0, 0, msg);
        }
    }
    
    unlink(link1);
    unlink(link2);
    unlink(link3);
}

void test_symlink_escape_relative(void) {
    char symlink_path[PATH_MAX];
    int fd, canary_before, canary_after;
    
    TEST_START("Symlink Escape - Relative Path");
    TEST_EXPECT("Create jail/escape -> ../../etc/softrx_canary (relative traversal)");
    
    snprintf(symlink_path, sizeof(symlink_path), "%s/escape_rel", JAIL_DIR);
    
    canary_before = create_sensitive_canary();
    if (canary_before < 0) {
        TEST_RESULT(0, 0, "Failed to create canary");
        return;
    }
    
    /* Relative path to escape jail */
    if (symlink("../../etc/softrx_canary", symlink_path) != 0) {
        char errmsg[256];
        snprintf(errmsg, sizeof(errmsg), "symlink() failed: %s", strerror(errno));
        TEST_RESULT(0, 0, errmsg);
        return;
    }
    
    printf("Created relative symlink: %s -> ../../etc/softrx_canary\n", symlink_path);
    
    fd = open(symlink_path, O_WRONLY | O_APPEND);
    
    if (fd >= 0) {
        const char *exploit = "RELATIVE_SYMLINK_EXPLOIT\n";
        write(fd, exploit, strlen(exploit));
        close(fd);
        
        canary_after = check_canary_compromised();
        
        if (canary_after > canary_before) {
            TEST_RESULT(1, 1, "Relative symlink bypassed jail");
        } else {
            TEST_RESULT(1, 0, "");
        }
    } else {
        if (errno == EPERM || errno == EACCES) {
            TEST_RESULT(1, 0, "");
        } else {
            char msg[256];
            snprintf(msg, sizeof(msg), "Unexpected errno: %d", errno);
            TEST_RESULT(0, 0, msg);
        }
    }
    
    unlink(symlink_path);
}

void test_hardlink_escape(void) {
    char hardlink_path[PATH_MAX];
    int fd, canary_before, canary_after;
    
    TEST_START("Hardlink Escape Attempt");
    TEST_EXPECT("Try to hardlink jail/escape to /etc/softrx_canary");
    
    snprintf(hardlink_path, sizeof(hardlink_path), "%s/hardlink", JAIL_DIR);
    
    canary_before = create_sensitive_canary();
    if (canary_before < 0) {
        TEST_RESULT(0, 0, "Failed to create canary");
        return;
    }
    
    /* Attempt hardlink (will likely fail due to cross-device or permissions) */
    if (link(SENSITIVE_TARGET, hardlink_path) == 0) {
        printf("Hardlink created (unexpected on modern systems)\n");
        
        fd = open(hardlink_path, O_WRONLY | O_APPEND);
        if (fd >= 0) {
            const char *exploit = "HARDLINK_EXPLOIT\n";
            write(fd, exploit, strlen(exploit));
            close(fd);
            
            canary_after = check_canary_compromised();
            
            if (canary_after > canary_before) {
                TEST_RESULT(1, 1, "Hardlink bypass successful");
            } else {
                TEST_RESULT(1, 0, "");
            }
        } else {
            TEST_RESULT(1, 0, "");
        }
        unlink(hardlink_path);
    } else {
        printf("Hardlink creation failed: %s (expected on most systems)\n", strerror(errno));
        TEST_RESULT(1, 0, "");
    }
}

/* ═══════════════════════════════════════════════════════════════
 * CATEGORY 2: TOCTOU RACE CONDITIONS
 * Testing Finding #2 from audit
 * ═══════════════════════════════════════════════════════════════ */

/* Shared state for TOCTOU tests */
static volatile char g_race_path[PATH_MAX];
static volatile int g_race_trigger = 0;
static pthread_mutex_t g_race_mutex = PTHREAD_MUTEX_INITIALIZER;

void* toctou_path_swapper(void *arg) {
    const char *malicious = (const char *)arg;
    
    /* Wait for main thread to start syscall */
    while (!g_race_trigger) {
        usleep(1);
    }
    
    /* Rapidly swap the path string */
    for (int i = 0; i < 1000; i++) {
        pthread_mutex_lock(&g_race_mutex);
        strcpy((char *)g_race_path, malicious);
        pthread_mutex_unlock(&g_race_mutex);
        usleep(10);
    }
    
    return NULL;
}

void test_toctou_path_swap(void) {
    char safe_path[PATH_MAX], evil_path[PATH_MAX];
    pthread_t swapper;
    int fd, canary_before, canary_after;
    
    TEST_START("TOCTOU - Path Swap Attack");
    TEST_EXPECT("Thread A calls open(safe_path), Thread B swaps string to /etc/canary");
    
    snprintf(safe_path, sizeof(safe_path), "%s/safe_file.txt", JAIL_DIR);
    snprintf(evil_path, sizeof(evil_path), "%s", SENSITIVE_TARGET);
    
    canary_before = create_sensitive_canary();
    if (canary_before < 0) {
        TEST_RESULT(0, 0, "Failed to create canary");
        return;
    }
    
    /* Initialize with safe path */
    pthread_mutex_lock(&g_race_mutex);
    strcpy((char *)g_race_path, safe_path);
    pthread_mutex_unlock(&g_race_mutex);
    
    /* Start swapper thread */
    g_race_trigger = 0;
    if (pthread_create(&swapper, NULL, toctou_path_swapper, evil_path) != 0) {
        TEST_RESULT(0, 0, "pthread_create failed");
        return;
    }
    
    /* Trigger the race */
    g_race_trigger = 1;
    
    /* Attempt open while path is being swapped */
    fd = open((const char *)g_race_path, O_WRONLY | O_CREAT | O_APPEND, 0644);
    
    pthread_join(swapper, NULL);
    
    if (fd >= 0) {
        const char *exploit = "TOCTOU_PATH_SWAP\n";
        write(fd, exploit, strlen(exploit));
        close(fd);
        
        canary_after = check_canary_compromised();
        
        if (canary_after > canary_before) {
            TEST_RESULT(1, 1, "TOCTOU race successful - path was swapped mid-flight");
        } else {
            printf("Write succeeded but to safe location (race lost or mitigated)\n");
            TEST_RESULT(1, 0, "");
        }
    } else {
        printf("open() failed: %s\n", strerror(errno));
        TEST_RESULT(1, 0, "");
    }
}

void test_toctou_fd_confusion(void) {
    int fd1, fd2;
    char safe_file[PATH_MAX], evil_file[PATH_MAX];
    
    TEST_START("TOCTOU - FD Confusion");
    TEST_EXPECT("Open safe FD, close it, reopen with same FD number to evil path");
    
    snprintf(safe_file, sizeof(safe_file), "%s/safe.txt", JAIL_DIR);
    snprintf(evil_file, sizeof(evil_file), "%s", SENSITIVE_TARGET);
    
    if (create_sensitive_canary() < 0) {
        TEST_RESULT(0, 0, "Failed to create canary");
        return;
    }
    
    /* Open safe file */
    fd1 = open(safe_file, O_WRONLY | O_CREAT, 0644);
    if (fd1 < 0) {
        TEST_RESULT(0, 0, "open(safe) failed");
        return;
    }
    
    printf("Opened safe file on FD %d\n", fd1);
    
    /* Close it */
    close(fd1);
    
    /* Immediately reopen - kernel will likely reuse the FD */
    fd2 = open(evil_file, O_WRONLY | O_APPEND);
    
    if (fd2 >= 0) {
        printf("Opened evil file on FD %d\n", fd2);
        
        if (fd2 == fd1) {
            printf("FD reused! This could confuse FD-based tracking.\n");
        }
        
        const char *exploit = "FD_CONFUSION\n";
        write(fd2, exploit, strlen(exploit));
        close(fd2);
        
        int canary_after = check_canary_compromised();
        if (canary_after > 0) {
            TEST_RESULT(1, 1, "FD confusion bypassed tracking");
        } else {
            TEST_RESULT(1, 0, "");
        }
    } else {
        printf("open(evil) denied: %s\n", strerror(errno));
        TEST_RESULT(1, 0, "");
    }
}

void test_toctou_race_window(void) {
    TEST_START("TOCTOU - Race Window Measurement");
    TEST_EXPECT("Measure supervisor decision latency to find race window");
    
    long long times[100];
    int i;
    char test_file[PATH_MAX];
    
    snprintf(test_file, sizeof(test_file), "%s/timing_test.txt", JAIL_DIR);
    
    for (i = 0; i < 100; i++) {
        long long start = get_time_us();
        int fd = open(test_file, O_WRONLY | O_CREAT, 0644);
        long long end = get_time_us();
        
        if (fd >= 0) {
            close(fd);
        }
        
        times[i] = end - start;
    }
    
    /* Calculate statistics */
    long long sum = 0, min = times[0], max = times[0];
    for (i = 0; i < 100; i++) {
        sum += times[i];
        if (times[i] < min) min = times[i];
        if (times[i] > max) max = times[i];
    }
    long long avg = sum / 100;
    
    printf("Race window statistics (100 trials):\n");
    printf("  Min: %lld µs\n", min);
    printf("  Avg: %lld µs\n", avg);
    printf("  Max: %lld µs\n", max);
    
    if (avg > TIMING_THRESHOLD_US) {
        printf("Supervisor adds significant latency (>%d µs)\n", TIMING_THRESHOLD_US);
        printf("TOCTOU race window exists: attacker has ~%lld µs to swap data\n", avg);
        char msg[256];
        snprintf(msg, sizeof(msg), "Race window: %lld µs average", avg);
        TEST_RESULT(1, 1, msg);
    } else {
        printf("Latency within acceptable bounds\n");
        TEST_RESULT(1, 0, "");
    }
}

/* ═══════════════════════════════════════════════════════════════
 * CATEGORY 3: SYSCALL EVASION
 * Testing Finding #3 from audit
 * ═══════════════════════════════════════════════════════════════ */

void test_mmap_rwx_direct(void) {
    void *mem;
    size_t page_size = sysconf(_SC_PAGESIZE);
    
    TEST_START("mmap RWX Direct (Bypass mprotect)");
    TEST_EXPECT("Call mmap() with PROT_WRITE|PROT_EXEC in one shot");
    
    printf("Attempting mmap(PROT_WRITE | PROT_EXEC)...\n");
    
    mem = mmap(NULL, page_size, PROT_WRITE | PROT_EXEC,
               MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    
    if (mem == MAP_FAILED) {
        printf("mmap(RWX) denied: %s\n", strerror(errno));
        TEST_RESULT(1, 0, "");
    } else {
        printf("mmap(RWX) succeeded at %p\n", mem);
        
        /* Write shellcode (harmless RET instruction) */
        unsigned char code[] = {0xc3};  /* x86-64 RET */
        memcpy(mem, code, sizeof(code));
        
        printf("Shellcode written. This bypasses mprotect() monitoring.\n");
        
        munmap(mem, page_size);
        TEST_RESULT(1, 1, "mmap(RWX) allowed - mprotect monitoring insufficient");
    }
}

void test_socket_write_bypass(void) {
    int sock, canary_before, canary_after;
    struct sockaddr_in addr;
    
    TEST_START("Socket write() Bypass");
    TEST_EXPECT("Establish socket via connect(), then use write() instead of sendto()");
    
    canary_before = create_sensitive_canary();
    
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        TEST_RESULT(0, 0, "socket() failed");
        return;
    }
    
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(9999);
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    
    printf("Attempting connect() to 127.0.0.1:9999...\n");
    
    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) == 0) {
        printf("Connected. Now using write() instead of sendto()...\n");
        
        const char *data = "SOCKET_WRITE_BYPASS_DATA";
        ssize_t sent = write(sock, data, strlen(data));
        
        if (sent > 0) {
            printf("write(sock_fd) sent %zd bytes (bypassed sendto tracking?)\n", sent);
            TEST_RESULT(1, 1, "Socket write() bypassed sendto() monitoring");
        } else {
            printf("write(sock_fd) denied: %s\n", strerror(errno));
            TEST_RESULT(1, 0, "");
        }
        
        close(sock);
    } else {
        printf("connect() failed: %s (no listener, but connection attempt logged?)\n", 
               strerror(errno));
        close(sock);
        TEST_RESULT(1, 0, "");
    }
}

void test_syscall_aliasing(void) {
    char test_file[PATH_MAX];
    int fd;
    
    TEST_START("Syscall Aliasing - openat vs open");
    TEST_EXPECT("Use openat(AT_FDCWD, ...) to alias open() call");
    
    snprintf(test_file, sizeof(test_file), "%s/alias_test.txt", JAIL_DIR);
    
    printf("Using openat(AT_FDCWD, ...) instead of open()...\n");
    
    fd = openat(AT_FDCWD, test_file, O_WRONLY | O_CREAT, 0644);
    
    if (fd >= 0) {
        printf("openat() succeeded (FD %d)\n", fd);
        write(fd, "test", 4);
        close(fd);
        unlink(test_file);
        TEST_RESULT(1, 0, "");
    } else {
        printf("openat() failed: %s\n", strerror(errno));
        TEST_RESULT(0, 0, "openat should work for legitimate paths");
    }
}

/* ═══════════════════════════════════════════════════════════════
 * CATEGORY 4: ANTI-SANDBOX DETECTION
 * Testing Finding #4 from audit
 * ═══════════════════════════════════════════════════════════════ */

void test_timing_sidechannel(void) {
    long long times[1000];
    int i;
    
    TEST_START("Timing Side-Channel Detection");
    TEST_EXPECT("Measure getpid() latency to detect supervisor overhead");
    
    for (i = 0; i < 1000; i++) {
        long long start = get_time_us();
        getpid();
        long long end = get_time_us();
        times[i] = end - start;
    }
    
    long long sum = 0;
    for (i = 0; i < 1000; i++) {
        sum += times[i];
    }
    long long avg = sum / 1000;
    
    printf("getpid() average latency: %lld µs (1000 trials)\n", avg);
    
    if (avg > 10) {  /* Normal getpid is ~0.1-1µs */
        printf("ANOMALY: getpid() is %lldx slower than expected\n", avg / 1);
        printf("Malware could detect sandbox via timing analysis\n");
        TEST_RESULT(1, 1, "Timing anomaly detected - sandbox fingerprint visible");
    } else {
        printf("Timing normal - sandbox overhead minimal\n");
        TEST_RESULT(1, 0, "");
    }
}

void test_procfs_detection(void) {
    FILE *fp;
    int open_count = 0, read_count = 0;
    long long start, end;
    
    TEST_START("/proc Introspection Detection");
    TEST_EXPECT("Monitor /proc/self/status access to detect supervisor reads");
    
    /* Supervisor likely reads /proc/<pid>/status for cache_proc_identity */
    start = get_time_us();
    
    for (int i = 0; i < 100; i++) {
        fp = fopen("/proc/self/status", "r");
        if (fp) {
            open_count++;
            char buf[256];
            if (fgets(buf, sizeof(buf), fp)) {
                read_count++;
            }
            fclose(fp);
        }
    }
    
    end = get_time_us();
    long long avg_us = (end - start) / 100;
    
    printf("Opened /proc/self/status %d times (avg %lld µs each)\n", 
           open_count, avg_us);
    
    if (avg_us > 100) {
        printf("ANOMALY: /proc reads are slow (%lld µs)\n", avg_us);
        printf("External process may be competing for same file\n");
        TEST_RESULT(1, 1, "Procfs timing anomaly suggests external monitoring");
    } else {
        TEST_RESULT(1, 0, "");
    }
}

void test_getpid_timing(void) {
    long long native_time, first_time;
    int i;
    
    TEST_START("getpid() Timing Baseline");
    TEST_EXPECT("Compare first call (seccomp trap) vs subsequent (cached)");
    
    /* First call - may trap to seccomp if monitored */
    long long start = get_time_us();
    getpid();
    long long end = get_time_us();
    first_time = end - start;
    
    /* Warm up cache */
    for (i = 0; i < 100; i++) {
        getpid();
    }
    
    /* Measure native performance */
    start = get_time_us();
    for (i = 0; i < 1000; i++) {
        getpid();
    }
    end = get_time_us();
    native_time = (end - start) / 1000;
    
    printf("First call: %lld µs\n", first_time);
    printf("Native avg: %lld µs (1000 calls)\n", native_time);
    printf("Overhead:   %lld µs\n", first_time - native_time);
    
    if (first_time > native_time * 10) {
        printf("First call significantly slower - seccomp trap suspected\n");
        TEST_RESULT(1, 1, "Seccomp overhead detectable via timing");
    } else {
        TEST_RESULT(1, 0, "");
    }
}

/* ═══════════════════════════════════════════════════════════════
 * CATEGORY 5: PATH HANDLING EDGE CASES
 * Additional tests for normalize_inplace vulnerabilities
 * ═══════════════════════════════════════════════════════════════ */

void test_null_byte_injection(void) {
    char path_with_null[PATH_MAX];
    int fd, canary_before, canary_after;
    
    TEST_START("Null Byte Injection");
    TEST_EXPECT("Path: jail/safe.txt\\0../../etc/canary");
    
    canary_before = create_sensitive_canary();
    
    /* Construct path: "jail/safe.txt\0../../etc/canary" */
    snprintf(path_with_null, sizeof(path_with_null), "%s/safe.txt", JAIL_DIR);
    size_t safe_len = strlen(path_with_null);
    snprintf(path_with_null + safe_len + 1, sizeof(path_with_null) - safe_len - 1,
             "../../etc/softrx_canary");
    
    printf("Attempting open with embedded null byte...\n");
    
    /* Most libc functions will stop at first null, but direct syscall wouldn't */
    fd = open(path_with_null, O_WRONLY | O_CREAT, 0644);
    
    if (fd >= 0) {
        write(fd, "NULL_BYTE_TEST\n", 15);
        close(fd);
        
        canary_after = check_canary_compromised();
        
        if (canary_after > canary_before) {
            TEST_RESULT(1, 1, "Null byte allowed path escape");
        } else {
            printf("File created at truncated path (safe behavior)\n");
            TEST_RESULT(1, 0, "");
        }
    } else {
        printf("open() failed: %s\n", strerror(errno));
        TEST_RESULT(1, 0, "");
    }
}

void test_dotdot_traversal(void) {
    char complex_path[PATH_MAX];
    int fd, canary_before, canary_after;
    
    TEST_START("Complex .. Traversal");
    TEST_EXPECT("Path: jail/subdir/../../subdir/../../../etc/canary");
    
    canary_before = create_sensitive_canary();
    
    /* Create confusing path */
    snprintf(complex_path, sizeof(complex_path),
             "%s/subdir/../../subdir/../../../etc/softrx_canary", JAIL_DIR);
    
    printf("Attempting open: %s\n", complex_path);
    
    fd = open(complex_path, O_WRONLY | O_APPEND);
    
    if (fd >= 0) {
        write(fd, "DOTDOT_TRAVERSAL\n", 17);
        close(fd);
        
        canary_after = check_canary_compromised();
        
        if (canary_after > canary_before) {
            TEST_RESULT(1, 1, "Complex .. traversal bypassed jail");
        } else {
            TEST_RESULT(1, 0, "");
        }
    } else {
        printf("open() denied: %s\n", strerror(errno));
        TEST_RESULT(1, 0, "");
    }
}

void test_path_canonicalization(void) {
    char weird_paths[][PATH_MAX] = {
        "jail/./././safe.txt",
        "jail//subdir///file.txt",
        "jail/subdir/..",
        "jail/./subdir/../file.txt"
    };
    int i;
    
    TEST_START("Path Canonicalization Edge Cases");
    TEST_EXPECT("Various malformed but valid paths should be normalized correctly");
    
    int passed = 1;
    for (i = 0; i < 4; i++) {
        printf("Testing path: %s\n", weird_paths[i]);
        
        int fd = open(weird_paths[i], O_WRONLY | O_CREAT, 0644);
        if (fd >= 0) {
            printf("  Opened successfully\n");
            close(fd);
        } else {
            printf("  Failed: %s\n", strerror(errno));
            if (errno != ENOENT) {
                passed = 0;
            }
        }
    }
    
    TEST_RESULT(passed, 0, "");
}

/* ═══════════════════════════════════════════════════════════════
 * CATEGORY 6: COMPOSITE ATTACKS
 * Combine multiple techniques
 * ═══════════════════════════════════════════════════════════════ */

void test_composite_attack(void) {
    char sym_path[PATH_MAX];
    pthread_t racer;
    int fd, canary_before, canary_after;
    
    TEST_START("Composite Attack - Symlink + TOCTOU + FD Confusion");
    TEST_EXPECT("Layer multiple evasion techniques simultaneously");
    
    canary_before = create_sensitive_canary();
    
    snprintf(sym_path, sizeof(sym_path), "%s/composite_sym", JAIL_DIR);
    
    /* Phase 1: Create symlink */
    if (symlink(SENSITIVE_TARGET, sym_path) != 0) {
        TEST_RESULT(0, 0, "symlink creation failed");
        return;
    }
    
    /* Phase 2: Start TOCTOU racer */
    pthread_mutex_lock(&g_race_mutex);
    strcpy((char *)g_race_path, sym_path);
    pthread_mutex_unlock(&g_race_mutex);
    
    g_race_trigger = 0;
    pthread_create(&racer, NULL, toctou_path_swapper, (void *)SENSITIVE_TARGET);
    g_race_trigger = 1;
    
    /* Phase 3: Rapid FD cycling while racing */
    for (int i = 0; i < 10; i++) {
        fd = open((const char *)g_race_path, O_WRONLY | O_APPEND);
        if (fd >= 0) {
            write(fd, "C", 1);
            close(fd);
        }
        usleep(100);
    }
    
    pthread_join(racer, NULL);
    
    canary_after = check_canary_compromised();
    
    if (canary_after > canary_before) {
        TEST_RESULT(1, 1, "Composite attack succeeded");
    } else {
        TEST_RESULT(1, 0, "");
    }
    
    unlink(sym_path);
}

/* ═══════════════════════════════════════════════════════════════
 * HELPER FUNCTIONS
 * ═══════════════════════════════════════════════════════════════ */

void setup_test_env(void) {
    struct stat st;
    
    /* Create test directory */
    if (stat(TEST_DIR, &st) == -1) {
        mkdir(TEST_DIR, 0755);
    }
    
    /* Create jail subdirectory */
    if (stat(JAIL_DIR, &st) == -1) {
        mkdir(JAIL_DIR, 0755);
    }
    
    printf("Test environment ready:\n");
    printf("  TEST_DIR: %s\n", TEST_DIR);
    printf("  JAIL_DIR: %s\n", JAIL_DIR);
    printf("  CANARY:   %s\n\n", SENSITIVE_TARGET);
}

void cleanup_test_env(void) {
    char cmd[512];
    
    /* Remove test files */
    snprintf(cmd, sizeof(cmd), "rm -rf %s", TEST_DIR);
    system(cmd);
    
    /* Remove canary */
    unlink(SENSITIVE_TARGET);
}

int create_sensitive_canary(void) {
    FILE *fp = fopen(SENSITIVE_TARGET, "w");
    if (!fp) {
        /* May fail without root - that's OK */
        return -1;
    }
    
    fprintf(fp, "CANARY_INITIAL_CONTENT\n");
    fclose(fp);
    
    struct stat st;
    if (stat(SENSITIVE_TARGET, &st) == 0) {
        return (int)st.st_size;
    }
    
    return -1;
}

int check_canary_compromised(void) {
    struct stat st;
    if (stat(SENSITIVE_TARGET, &st) != 0) {
        return -1;
    }
    
    FILE *fp = fopen(SENSITIVE_TARGET, "r");
    if (!fp) {
        return -1;
    }
    
    char buf[1024];
    size_t total = 0;
    size_t n;
    
    while ((n = fread(buf, 1, sizeof(buf), fp)) > 0) {
        total += n;
        
        /* Check for exploit markers */
        for (size_t i = 0; i < n; i++) {
            if (strstr(buf + i, "EXPLOIT") ||
                strstr(buf + i, "TOCTOU") ||
                strstr(buf + i, "SYMLINK")) {
                fclose(fp);
                return (int)total;
            }
        }
    }
    
    fclose(fp);
    return (int)total;
}

long long get_time_us(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (long long)tv.tv_sec * 1000000LL + (long long)tv.tv_usec;
}

/* ═══════════════════════════════════════════════════════════════
 * MAIN DRIVER
 * ═══════════════════════════════════════════════════════════════ */

void print_usage(const char *prog) {
    printf("Usage: %s [test_name|all|category]\n\n", prog);
    printf("Categories:\n");
    printf("  symlink    - Symlink escape attacks (Finding #1)\n");
    printf("  toctou     - TOCTOU race conditions (Finding #2)\n");
    printf("  evasion    - Syscall evasion techniques (Finding #3)\n");
    printf("  detection  - Anti-sandbox detection (Finding #4)\n");
    printf("  paths      - Path handling edge cases\n");
    printf("  composite  - Combined attack scenarios\n");
    printf("  all        - Run all tests\n\n");
    printf("Individual tests:\n");
    printf("  symlink_escape_basic\n");
    printf("  symlink_escape_nested\n");
    printf("  symlink_escape_relative\n");
    printf("  hardlink_escape\n");
    printf("  toctou_path_swap\n");
    printf("  toctou_fd_confusion\n");
    printf("  toctou_race_window\n");
    printf("  mmap_rwx_direct\n");
    printf("  socket_write_bypass\n");
    printf("  syscall_aliasing\n");
    printf("  timing_sidechannel\n");
    printf("  procfs_detection\n");
    printf("  getpid_timing\n");
    printf("  null_byte_injection\n");
    printf("  dotdot_traversal\n");
    printf("  path_canonicalization\n");
    printf("  composite_attack\n");
}

void print_summary(void) {
    printf("\n");
    printf(COLOR_BLUE "═══════════════════════════════════════════════════════════════\n" COLOR_RESET);
    printf(COLOR_BLUE "                       TEST SUMMARY\n" COLOR_RESET);
    printf(COLOR_BLUE "═══════════════════════════════════════════════════════════════\n" COLOR_RESET);
    printf("Tests Run:             %d\n", g_tests_run);
    printf("Tests Passed:          %d\n", g_tests_passed);
    printf("Tests Failed:          %d\n", g_tests_run - g_tests_passed);
    printf("\n");
    
    if (g_exploits_successful > 0) {
        printf(COLOR_RED "Exploits Successful:   %d (VULNERABILITIES EXIST)\n" COLOR_RESET, 
               g_exploits_successful);
    } else {
        printf(COLOR_GREEN "Exploits Successful:   0\n" COLOR_RESET);
    }
    
    printf(COLOR_GREEN "Exploits Blocked:      %d (FIXES VERIFIED)\n" COLOR_RESET, 
           g_exploits_blocked);
    printf(COLOR_BLUE "═══════════════════════════════════════════════════════════════\n" COLOR_RESET);
    
    if (g_exploits_successful > 0) {
        printf("\n" COLOR_RED "⚠️  SECURITY ISSUES DETECTED\n" COLOR_RESET);
        printf("Review failed tests above and apply recommended fixes.\n");
    } else {
        printf("\n" COLOR_GREEN "✓ All security fixes verified\n" COLOR_RESET);
        printf("No active vulnerabilities detected.\n");
    }
}

int main(int argc, char **argv) {
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }
    
    setup_test_env();
    
    printf(COLOR_BLUE "═══════════════════════════════════════════════════════════════\n" COLOR_RESET);
    printf(COLOR_BLUE "         SOFTRX SECURITY VULNERABILITY TEST SUITE\n" COLOR_RESET);
    printf(COLOR_BLUE "═══════════════════════════════════════════════════════════════\n" COLOR_RESET);
    printf("Testing sandbox: softrx_launcher.c\n");
    printf("Audit findings: 4 critical vulnerabilities\n\n");
    
    const char *test = argv[1];
    
    if (strcmp(test, "all") == 0) {
        test_symlink_escape_basic();
        test_symlink_escape_nested();
        test_symlink_escape_relative();
        test_hardlink_escape();
        test_toctou_path_swap();
        test_toctou_fd_confusion();
        test_toctou_race_window();
        test_mmap_rwx_direct();
        test_socket_write_bypass();
        test_syscall_aliasing();
        test_timing_sidechannel();
        test_procfs_detection();
        test_getpid_timing();
        test_null_byte_injection();
        test_dotdot_traversal();
        test_path_canonicalization();
        test_composite_attack();
    }
    else if (strcmp(test, "symlink") == 0) {
        test_symlink_escape_basic();
        test_symlink_escape_nested();
        test_symlink_escape_relative();
        test_hardlink_escape();
    }
    else if (strcmp(test, "toctou") == 0) {
        test_toctou_path_swap();
        test_toctou_fd_confusion();
        test_toctou_race_window();
    }
    else if (strcmp(test, "evasion") == 0) {
        test_mmap_rwx_direct();
        test_socket_write_bypass();
        test_syscall_aliasing();
    }
    else if (strcmp(test, "detection") == 0) {
        test_timing_sidechannel();
        test_procfs_detection();
        test_getpid_timing();
    }
    else if (strcmp(test, "paths") == 0) {
        test_null_byte_injection();
        test_dotdot_traversal();
        test_path_canonicalization();
    }
    else if (strcmp(test, "composite") == 0) {
        test_composite_attack();
    }
    else if (strcmp(test, "symlink_escape_basic") == 0) test_symlink_escape_basic();
    else if (strcmp(test, "symlink_escape_nested") == 0) test_symlink_escape_nested();
    else if (strcmp(test, "symlink_escape_relative") == 0) test_symlink_escape_relative();
    else if (strcmp(test, "hardlink_escape") == 0) test_hardlink_escape();
    else if (strcmp(test, "toctou_path_swap") == 0) test_toctou_path_swap();
    else if (strcmp(test, "toctou_fd_confusion") == 0) test_toctou_fd_confusion();
    else if (strcmp(test, "toctou_race_window") == 0) test_toctou_race_window();
    else if (strcmp(test, "mmap_rwx_direct") == 0) test_mmap_rwx_direct();
    else if (strcmp(test, "socket_write_bypass") == 0) test_socket_write_bypass();
    else if (strcmp(test, "syscall_aliasing") == 0) test_syscall_aliasing();
    else if (strcmp(test, "timing_sidechannel") == 0) test_timing_sidechannel();
    else if (strcmp(test, "procfs_detection") == 0) test_procfs_detection();
    else if (strcmp(test, "getpid_timing") == 0) test_getpid_timing();
    else if (strcmp(test, "null_byte_injection") == 0) test_null_byte_injection();
    else if (strcmp(test, "dotdot_traversal") == 0) test_dotdot_traversal();
    else if (strcmp(test, "path_canonicalization") == 0) test_path_canonicalization();
    else if (strcmp(test, "composite_attack") == 0) test_composite_attack();
    else {
        printf("Unknown test: %s\n", test);
        print_usage(argv[0]);
        cleanup_test_env();
        return 1;
    }
    
    print_summary();
    cleanup_test_env();
    
    return (g_exploits_successful > 0) ? 1 : 0;
}