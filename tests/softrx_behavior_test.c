/*
 * SoftRX Behavioral Test Suite
 * C89 compliant - tests dynamic analysis capture capabilities
 * 
 * Compile: gcc -O2 -Wall -Wextra -std=gnu11 -ldl -o softrx_test softrx_behavior_test.c
 * Usage: ./softrx_test <test_name> [args...]
 *        ./softrx_test all  (runs all tests sequentially)
 */

#define _POSIX_C_SOURCE 200809L
#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <signal.h>
#include <errno.h>
#include <time.h>
#include <dirent.h>
#include <dlfcn.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <utime.h>
#include <sys/syscall.h>

/* Test result structure */
typedef struct {
    const char* name;
    int passed;
    const char* message;
} TestResult;

/* Forward declarations */
void test_fork_exec_fanout(void);
void test_exec_weird_locations(void);
void test_interpreter_chain(void);
void test_exit_code_semantics(void);
void test_write_patterns(void);
void test_atomic_swap(void);
void test_symlink_hardlink(void);
void test_permission_metadata(void);
void test_loopback_client(void);
void test_dns_only(void);
void test_blocked_network_fallback(void);
void test_rwx_mprotect(void);
void test_memfd_fexecve(void);
void test_dlopen_dlsym(void);
void test_timing_sleep(void);
void test_environment_probes(void);
void test_self_introspection(void);
void test_signal_crash(void);
void test_dropper_local(void);
void test_fileless_stager(void);
void test_persistence_sim(void);
void test_credential_theft_sim(void);
void test_recon_bundle(void);
void test_noise_generator(void);

/* Helper functions */
void print_banner(const char* test_name);
void create_test_dir(void);
void cleanup_test_dir(void);

/* Global test directory */
static const char* TEST_DIR = "/tmp/softrx_test";
extern char **environ;

/* ============================ MAIN ============================ */

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage: %s <test_name|all>\n\n", argv[0]);
        printf("Available tests:\n");
        printf("  Tier 1A - Process/Execution:\n");
        printf("    fork_exec_fanout\n");
        printf("    exec_weird_locations\n");
        printf("    interpreter_chain\n");
        printf("    exit_code_semantics\n");
        printf("  Tier 1B - Filesystem:\n");
        printf("    write_patterns\n");
        printf("    atomic_swap\n");
        printf("    symlink_hardlink\n");
        printf("    permission_metadata\n");
        printf("  Tier 1C - Network:\n");
        printf("    loopback_client\n");
        printf("    dns_only\n");
        printf("    blocked_network_fallback\n");
        printf("  Tier 1D - Memory:\n");
        printf("    rwx_mprotect\n");
        printf("    memfd_fexecve\n");
        printf("    dlopen_dlsym\n");
        printf("  Tier 1E - Anti-analysis:\n");
        printf("    timing_sleep\n");
        printf("    environment_probes\n");
        printf("    self_introspection\n");
        printf("    signal_crash\n");
        printf("  Tier 2 - Scenarios:\n");
        printf("    dropper_local\n");
        printf("    fileless_stager\n");
        printf("    persistence_sim\n");
        printf("    credential_theft_sim\n");
        printf("    recon_bundle\n");
        printf("    noise_generator\n");
        printf("  Special:\n");
        printf("    all (run all tests)\n");
        return 1;
    }

    create_test_dir();

    if (strcmp(argv[1], "all") == 0) {
        printf("=== Running ALL SoftRX Behavioral Tests ===\n\n");
        test_fork_exec_fanout();
        test_exec_weird_locations();
        test_interpreter_chain();
        test_exit_code_semantics();
        test_write_patterns();
        test_atomic_swap();
        test_symlink_hardlink();
        test_permission_metadata();
        test_loopback_client();
        test_dns_only();
        test_blocked_network_fallback();
        test_rwx_mprotect();
        test_memfd_fexecve();
        test_dlopen_dlsym();
        test_timing_sleep();
        test_environment_probes();
        test_self_introspection();
        test_signal_crash();
        test_dropper_local();
        test_fileless_stager();
        test_persistence_sim();
        test_credential_theft_sim();
        test_recon_bundle();
        test_noise_generator();
    } else if (strcmp(argv[1], "fork_exec_fanout") == 0) {
        test_fork_exec_fanout();
    } else if (strcmp(argv[1], "exec_weird_locations") == 0) {
        test_exec_weird_locations();
    } else if (strcmp(argv[1], "interpreter_chain") == 0) {
        test_interpreter_chain();
    } else if (strcmp(argv[1], "exit_code_semantics") == 0) {
        test_exit_code_semantics();
    } else if (strcmp(argv[1], "write_patterns") == 0) {
        test_write_patterns();
    } else if (strcmp(argv[1], "atomic_swap") == 0) {
        test_atomic_swap();
    } else if (strcmp(argv[1], "symlink_hardlink") == 0) {
        test_symlink_hardlink();
    } else if (strcmp(argv[1], "permission_metadata") == 0) {
        test_permission_metadata();
    } else if (strcmp(argv[1], "loopback_client") == 0) {
        test_loopback_client();
    } else if (strcmp(argv[1], "dns_only") == 0) {
        test_dns_only();
    } else if (strcmp(argv[1], "blocked_network_fallback") == 0) {
        test_blocked_network_fallback();
    } else if (strcmp(argv[1], "rwx_mprotect") == 0) {
        test_rwx_mprotect();
    } else if (strcmp(argv[1], "memfd_fexecve") == 0) {
        test_memfd_fexecve();
    } else if (strcmp(argv[1], "dlopen_dlsym") == 0) {
        test_dlopen_dlsym();
    } else if (strcmp(argv[1], "timing_sleep") == 0) {
        test_timing_sleep();
    } else if (strcmp(argv[1], "environment_probes") == 0) {
        test_environment_probes();
    } else if (strcmp(argv[1], "self_introspection") == 0) {
        test_self_introspection();
    } else if (strcmp(argv[1], "signal_crash") == 0) {
        test_signal_crash();
    } else if (strcmp(argv[1], "dropper_local") == 0) {
        test_dropper_local();
    } else if (strcmp(argv[1], "fileless_stager") == 0) {
        test_fileless_stager();
    } else if (strcmp(argv[1], "persistence_sim") == 0) {
        test_persistence_sim();
    } else if (strcmp(argv[1], "credential_theft_sim") == 0) {
        test_credential_theft_sim();
    } else if (strcmp(argv[1], "recon_bundle") == 0) {
        test_recon_bundle();
    } else if (strcmp(argv[1], "noise_generator") == 0) {
        test_noise_generator();
    } else {
        printf("Unknown test: %s\n", argv[1]);
        return 1;
    }

    cleanup_test_dir();
    return 0;
}

/* ============================ HELPERS ============================ */

void print_banner(const char* test_name) {
    printf("\n");
    printf("========================================\n");
    printf("TEST: %s\n", test_name);
    printf("========================================\n");
}

void create_test_dir(void) {
    struct stat st;
    if (stat(TEST_DIR, &st) == -1) {
        mkdir(TEST_DIR, 0755);
    }
}

void cleanup_test_dir(void) {
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "rm -rf %s", TEST_DIR);
    system(cmd);
}

/* ============================ TIER 1A: PROCESS/EXEC ============================ */

void test_fork_exec_fanout(void) {
    int i, status;
    pid_t pid;
    const char* binaries[] = {"/bin/echo", "/usr/bin/env", "/bin/date", "/bin/pwd"};
    int num_children = 4;
    
    print_banner("Fork/Exec Fan-out");
    printf("Parent PID: %d\n", getpid());
    printf("Spawning %d children with different execs...\n", num_children);
    
    for (i = 0; i < num_children; i++) {
        pid = fork();
        if (pid == 0) {
            /* Child */
            char arg[64];
            snprintf(arg, sizeof(arg), "child_%d", i);
            printf("Child %d (PID %d) exec'ing %s\n", i, getpid(), binaries[i]);
            execl(binaries[i], binaries[i], arg, NULL);
            perror("execl failed");
            exit(1);
        } else if (pid < 0) {
            perror("fork failed");
        }
    }
    
    /* Parent waits for all children */
    for (i = 0; i < num_children; i++) {
        wait(&status);
        printf("Child exited with status: %d\n", WEXITSTATUS(status));
    }
    printf("Test complete: all children exec'd and exited\n");
}

void test_exec_weird_locations(void) {
    pid_t pid;
    char cwd_path[512];
    char tmp_path[512];
    char nested_path[512];
    int status;
    FILE* fp;
    
    print_banner("Exec from Weird Locations");
    
    /* Create test executables in various locations */
    snprintf(cwd_path, sizeof(cwd_path), "%s/test_cwd", TEST_DIR);
    snprintf(tmp_path, sizeof(tmp_path), "/tmp/test_tmp_%d", getpid());
    snprintf(nested_path, sizeof(nested_path), "%s/nested/dir/test_nested", TEST_DIR);
    
    /* Create nested directory */
    {
        char mkcmd[600];
        snprintf(mkcmd, sizeof(mkcmd), "mkdir -p %s/nested/dir", TEST_DIR);
        system(mkcmd);
    }
    
    /* Create simple shell scripts */
    fp = fopen(cwd_path, "w");
    fprintf(fp, "#!/bin/sh\necho 'Exec from cwd'\n");
    fclose(fp);
    chmod(cwd_path, 0755);
    
    fp = fopen(tmp_path, "w");
    fprintf(fp, "#!/bin/sh\necho 'Exec from /tmp'\n");
    fclose(fp);
    chmod(tmp_path, 0755);
    
    fp = fopen(nested_path, "w");
    fprintf(fp, "#!/bin/sh\necho 'Exec from nested'\n");
    fclose(fp);
    chmod(nested_path, 0755);
    
    /* Test 1: Exec from cwd */
    pid = fork();
    if (pid == 0) {
        chdir(TEST_DIR);
        printf("Exec'ing from cwd: %s\n", cwd_path);
        execl(cwd_path, cwd_path, NULL);
        exit(1);
    }
    wait(&status);
    
    /* Test 2: Exec from /tmp */
    pid = fork();
    if (pid == 0) {
        printf("Exec'ing from /tmp: %s\n", tmp_path);
        execl(tmp_path, tmp_path, NULL);
        exit(1);
    }
    wait(&status);
    
    /* Test 3: Exec from nested */
    pid = fork();
    if (pid == 0) {
        printf("Exec'ing from nested: %s\n", nested_path);
        execl(nested_path, nested_path, NULL);
        exit(1);
    }
    wait(&status);
    
    /* Test 4: Exec with relative path */
    pid = fork();
    if (pid == 0) {
        chdir(TEST_DIR);
        printf("Exec'ing with relative path: ./test_cwd\n");
        execl("./test_cwd", "./test_cwd", NULL);
        exit(1);
    }
    wait(&status);
    
    printf("Test complete: exec'd from cwd, /tmp, nested, and relative paths\n");
    
    /* Cleanup */
    unlink(tmp_path);
}

void test_interpreter_chain(void) {
    char script_path[512];
    FILE* fp;
    pid_t pid;
    int status;
    
    print_banner("Interpreter Chain");
    
    snprintf(script_path, sizeof(script_path), "%s/chain.sh", TEST_DIR);
    
    /* Create a script that chains python -> sh -> awk */
    fp = fopen(script_path, "w");
    fprintf(fp, "#!/bin/sh\n");
    fprintf(fp, "echo 'Stage 1: Shell script starting'\n");
fprintf(fp, "PY=python3\n");
fprintf(fp, "command -v $PY >/dev/null 2>&1 || PY=python\n");
fprintf(fp, "command -v $PY >/dev/null 2>&1 || { echo \'No python found; skipping python stage\'; exit 0; }\n");
fprintf(fp, "$PY -c \"import os; os.system(\'echo test | awk \\\'{print \\\\\\\"Stage 3: AWK executed\\\\\\\"}\\\'\')\"\n");


    fprintf(fp, "echo 'Chain complete'\n");
    fclose(fp);
    chmod(script_path, 0755);
    
    printf("Executing interpreter chain: sh -> python -> sh -> awk\n");
    
    pid = fork();
    if (pid == 0) {
        execl(script_path, script_path, NULL);
        exit(1);
    }
    wait(&status);
    
    printf("Test complete: interpreter chain executed\n");
}

void test_exit_code_semantics(void) {
    pid_t pid;
    int status;
    
    print_banner("Exit Code Semantics");
    
    /* Test 1: Exec non-existent */
    printf("Test 1: Exec non-existent binary\n");
    pid = fork();
    if (pid == 0) {
        execl("/nonexistent/binary", "binary", NULL);
        perror("Expected failure");
        exit(127);
    }
    wait(&status);
    printf("Exit code: %d (expected 127 for exec failure)\n", WEXITSTATUS(status));
    
    /* Test 2: Permission denied */
    printf("\nTest 2: Permission denied\n");
    pid = fork();
    if (pid == 0) {
        char no_exec[512];
        FILE* fp;
        snprintf(no_exec, sizeof(no_exec), "%s/no_exec", TEST_DIR);
        fp = fopen(no_exec, "w");
        fprintf(fp, "#!/bin/sh\necho test\n");
        fclose(fp);
        chmod(no_exec, 0644); /* No execute bit */
        execl(no_exec, no_exec, NULL);
        perror("Expected permission denied");
        exit(126);
    }
    wait(&status);
    printf("Exit code: %d (expected 126 for permission denied)\n", WEXITSTATUS(status));
    
    /* Test 3: Intentional crash (SIGSEGV simulation) */
    printf("\nTest 3: Intentional exit with error\n");
    pid = fork();
    if (pid == 0) {
        printf("Child deliberately exiting with code 42\n");
        exit(42);
    }
    wait(&status);
    if (WIFEXITED(status)) {
        printf("Exit code: %d (clean exit)\n", WEXITSTATUS(status));
    } else if (WIFSIGNALED(status)) {
        printf("Killed by signal: %d\n", WTERMSIG(status));
    }
    
    printf("Test complete: various exit scenarios tested\n");
}

/* ============================ TIER 1B: FILESYSTEM ============================ */

void test_write_patterns(void) {
    char path[512];
    char renamed[512];
    FILE* fp;
    
    print_banner("Write Patterns");
    
    snprintf(path, sizeof(path), "%s/test_file.txt", TEST_DIR);
    snprintf(renamed, sizeof(renamed), "%s/test_file_renamed.txt", TEST_DIR);
    
    /* Create */
    printf("1. Creating file: %s\n", path);
    fp = fopen(path, "w");
    fprintf(fp, "Initial content\n");
    fclose(fp);
    
    /* Append */
    printf("2. Appending to file\n");
    fp = fopen(path, "a");
    fprintf(fp, "Appended line 1\n");
    fprintf(fp, "Appended line 2\n");
    fclose(fp);
    
    /* Rename */
    printf("3. Renaming file to: %s\n", renamed);
    if (rename(path, renamed) == 0) {
        printf("   Rename successful\n");
    } else {
        perror("   Rename failed");
    }
    
    /* Delete */
    printf("4. Deleting file: %s\n", renamed);
    if (unlink(renamed) == 0) {
        printf("   Delete successful (file was transient)\n");
    } else {
        perror("   Delete failed");
    }
    
    printf("Test complete: create -> append -> rename -> delete sequence\n");
}

void test_atomic_swap(void) {
    char target[512];
    char temp[512];
    FILE* fp;
    int fd;
    
    print_banner("Atomic Swap");
    
    snprintf(target, sizeof(target), "%s/target.conf", TEST_DIR);
    snprintf(temp, sizeof(temp), "%s/target.conf.tmp", TEST_DIR);
    
    /* Create original target */
    printf("1. Creating original target file\n");
    fp = fopen(target, "w");
    fprintf(fp, "Original configuration\n");
    fclose(fp);
    
    /* Write to temp file */
    printf("2. Writing new content to temp file\n");
    fp = fopen(temp, "w");
    fprintf(fp, "New configuration\n");
    fprintf(fp, "Updated settings\n");
    fclose(fp);
    
    /* fsync */
    printf("3. Calling fsync to ensure data is written\n");
    fd = open(temp, O_RDONLY);
    fsync(fd);
    close(fd);
    
    /* Atomic rename */
    printf("4. Atomically replacing target with rename()\n");
    if (rename(temp, target) == 0) {
        printf("   Atomic swap successful (common in malware & installers)\n");
    } else {
        perror("   Atomic swap failed");
    }
    
    printf("Test complete: atomic file replacement detected\n");
}

void test_symlink_hardlink(void) {
    char real_file[512];
    char symlink_path[512];
    char hardlink[512];
    FILE* fp;
    
    print_banner("Symlink/Hardlink Tricks");
    
    snprintf(real_file, sizeof(real_file), "%s/real.txt", TEST_DIR);
    snprintf(symlink_path, sizeof(symlink_path), "%s/sym.txt", TEST_DIR);
    snprintf(hardlink, sizeof(hardlink), "%s/hard.txt", TEST_DIR);
    
    /* Create real file */
    printf("1. Creating real file: %s\n", real_file);
    fp = fopen(real_file, "w");
    fprintf(fp, "Real content\n");
    fclose(fp);
    
    /* Create symlink */
    printf("2. Creating symlink: %s -> %s\n", symlink_path, real_file);
    if (symlink(real_file, symlink_path) == 0) {
        printf("   Symlink created\n");
    } else {
        perror("   Symlink failed");
    }
    
    /* Write through symlink */
    printf("3. Writing through symlink\n");
    fp = fopen(symlink_path, "a");
    fprintf(fp, "Written via symlink\n");
    fclose(fp);
    
    /* Create hardlink */
    printf("4. Creating hardlink: %s\n", hardlink);
    if (link(real_file, hardlink) == 0) {
        printf("   Hardlink created\n");
    } else {
        perror("   Hardlink failed");
    }
    
    /* Modify through hardlink */
    printf("5. Modifying through hardlink\n");
    fp = fopen(hardlink, "a");
    fprintf(fp, "Written via hardlink\n");
    fclose(fp);
    
    printf("Test complete: resolved targets should be reported, not just link paths\n");
}

void test_permission_metadata(void) {
    char file[512];
    FILE* fp;
    struct stat st;
    
    print_banner("Permission & Metadata Changes");
    
    snprintf(file, sizeof(file), "%s/metadata_test.txt", TEST_DIR);
    
    /* Create file */
    printf("1. Creating file\n");
    fp = fopen(file, "w");
    fprintf(fp, "Test content\n");
    fclose(fp);
    
    /* chmod */
    printf("2. Changing permissions with chmod(0600)\n");
    if (chmod(file, 0600) == 0) {
        printf("   chmod successful\n");
    } else {
        perror("   chmod failed");
    }
    
    /* chown (may require root, will likely fail) */
    printf("3. Attempting chown (may fail without root)\n");
    if (chown(file, getuid(), getgid()) == 0) {
        printf("   chown successful\n");
    } else {
        perror("   chown failed (expected without root)");
    }
    
    /* utime */
    printf("4. Modifying timestamps with utime()\n");
    if (utime(file, NULL) == 0) {
        printf("   utime successful\n");
    } else {
        perror("   utime failed");
    }
    
    /* Verify changes */
    if (stat(file, &st) == 0) {
        printf("5. Current file mode: %o\n", st.st_mode & 0777);
    }
    
    printf("Test complete: metadata changes should appear as first-class events\n");
}

/* ============================ TIER 1C: NETWORK ============================ */

void test_loopback_client(void) {
    int sockfd;
    struct sockaddr_in addr;
    char send_buf[] = "GET / HTTP/1.0\r\n\r\n";
    char recv_buf[1024];
    ssize_t n;
    
    print_banner("Loopback Client");
    
    printf("1. Creating TCP socket\n");
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("socket failed");
        return;
    }
    
    printf("2. Connecting to 127.0.0.1:80\n");
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(80);
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    
    if (connect(sockfd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("connect failed (expected if no local server on :80)");
        close(sockfd);
        printf("Test complete: connection attempt logged (endpoint, protocol hints)\n");
        return;
    }
    
    printf("3. Sending HTTP request (%lu bytes)\n", (unsigned long)strlen(send_buf));
    send(sockfd, send_buf, strlen(send_buf), 0);
    
    printf("4. Reading response\n");
    n = recv(sockfd, recv_buf, sizeof(recv_buf) - 1, 0);
    if (n > 0) {
        recv_buf[n] = '\0';
        printf("   Received %ld bytes\n", (long)n);
    }
    
    close(sockfd);
    printf("Test complete: endpoint, bytes in/out should be visible\n");
}

void test_dns_only(void) {
    struct hostent* he;
    const char* hosts[] = {"example.com", "google.com", "nonexistent.fake.local"};
    int i;
    
    print_banner("DNS-only Behavior");
    
    printf("Performing DNS lookups without connecting:\n");
    for (i = 0; i < 3; i++) {
        printf("%d. Resolving %s... ", i+1, hosts[i]);
        he = gethostbyname(hosts[i]);
        if (he != NULL) {
            printf("resolved to %s\n", inet_ntoa(*(struct in_addr*)he->h_addr));
        } else {
            printf("resolution failed (expected for fake domain)\n");
        }
    }
    
    printf("Test complete: DNS queries should be visible as distinct from socket activity\n");
}

void test_blocked_network_fallback(void) {
    int sockfd;
    struct sockaddr_in addr;
    
    print_banner("Blocked Network with Fallback");
    
    printf("1. Attempting network connection to 192.0.2.1:9999 (TEST-NET, should fail)\n");
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("socket failed");
        printf("2. Network unavailable, entering offline mode\n");
        printf("3. Proceeding with local operations\n");
        printf("Test complete: decision branch should be visible\n");
        return;
    }
    
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(9999);
    addr.sin_addr.s_addr = inet_addr("192.0.2.1");
    
    if (connect(sockfd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("connect failed (expected)");
        printf("2. Network failed, switching to offline mode\n");
        close(sockfd);
    }
    
    printf("3. Continuing in offline mode with local processing\n");
    printf("Test complete: failure -> fallback decision branch visible\n");
}

/* ============================ TIER 1D: MEMORY ============================ */

void test_rwx_mprotect(void) {
    void* mem;
    size_t page_size;
    void (*func)(void);
    /* Simple return instruction for x86-64: 0xc3 */
    unsigned char code[] = {0xc3};
    
    print_banner("RWX / mprotect-to-exec");
    
    page_size = sysconf(_SC_PAGESIZE);
    
    printf("1. Allocating RW memory page\n");
    mem = mmap(NULL, page_size, PROT_READ | PROT_WRITE,
               MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mem == MAP_FAILED) {
        perror("mmap failed");
        return;
    }
    
    printf("2. Writing code bytes to memory\n");
    memcpy(mem, code, sizeof(code));
    
    printf("3. Calling mprotect to make memory executable (RWX -> RX)\n");
    if (mprotect(mem, page_size, PROT_READ | PROT_EXEC) != 0) {
        perror("mprotect failed");
        munmap(mem, page_size);
        return;
    }
    
    printf("4. Executing generated code\n");
    func = (void(*)(void))mem;
    func();
    
    printf("5. Generated code executed successfully\n");
    munmap(mem, page_size);
    
    printf("Test complete: STRONG HIGHLIGHT - generated code executed\n");
}

void test_memfd_fexecve(void) {
#if defined(SYS_memfd_create) || defined(__NR_memfd_create)
    int fd;
    pid_t pid;
    int status;
    char fdpath[64];
    const char* script = "#!/bin/sh\necho 'Fileless execution via memfd'\n";

    print_banner("memfd + fexecve (with robust fallback)");

    printf("1. Creating anonymous memfd\n");
# if defined(SYS_memfd_create)
    fd = (int)syscall(SYS_memfd_create, "anon_exec", 0);
# else
    fd = (int)syscall(__NR_memfd_create, "anon_exec", 0);
# endif
    if (fd < 0) {
        perror("memfd_create failed");
        printf("Test skipped\n");
        return;
    }

    printf("2. Writing script payload to memfd\n");
    if (write(fd, script, (size_t)strlen(script)) < 0) {
        perror("write(memfd) failed");
        close(fd);
        return;
    }
    if (lseek(fd, 0, SEEK_SET) < 0) {
        perror("lseek(memfd) failed");
        close(fd);
        return;
    }
    fchmod(fd, 0755);

    snprintf(fdpath, sizeof(fdpath), "/proc/self/fd/%d", fd);
    printf("   memfd path: %s\n", fdpath);

    printf("3. Forking and attempting fileless exec\n");
    pid = fork();
    if (pid == 0) {
        /* Attempt fexecve first (may fail for scripts on some kernels) */
        char *const argv0[] = { fdpath, NULL };
        fexecve(fd, argv0, environ);

        /* Fallback: run it via /bin/sh reading /proc/self/fd/<fd> */
        if (errno == ENOEXEC || errno == EACCES || errno == EINVAL) {
            char *const sh_argv[] = { "sh", fdpath, NULL };
            execve("/bin/sh", sh_argv, environ);
        }

        perror("fileless exec failed");
        _exit(1);
    }

    waitpid(pid, &status, 0);
    printf("Child exited with status: %d\n", WIFEXITED(status) ? WEXITSTATUS(status) : -1);

    close(fd);
    printf("Test complete: FILELESS EXECUTION attempt should be identified and tracked\n");
#else
    print_banner("memfd + fexecve");
    printf("memfd_create not available on this system; test skipped\n");
#endif
}

void test_dlopen_dlsym(void) {
    void* handle;
    void (*func)(void);
    
    print_banner("dlopen + dlsym");
    
    printf("1. Opening libc with dlopen(RTLD_LAZY)\n");
    handle = dlopen("libc.so.6", RTLD_LAZY);
    if (!handle) {
        printf("   dlopen failed: %s\n", dlerror());
        printf("   Trying alternate name...\n");
        handle = dlopen("libc.so", RTLD_LAZY);
    }
    
    if (!handle) {
        printf("   Could not load libc\n");
        return;
    }
    
    printf("2. Looking up symbol 'printf' with dlsym\n");
    func = (void(*)(void))dlsym(handle, "printf");
    if (!func) {
        printf("   dlsym failed: %s\n", dlerror());
    } else {
        printf("3. Symbol found at %p\n", (void*)func);
        printf("4. Calling dynamically loaded symbol\n");
        ((int(*)(const char*,...))func)("   Dynamic call successful\n");
    }
    
    printf("5. Closing library\n");
    dlclose(handle);
    
    printf("Test complete: dynamic load events + library paths should be visible\n");
}

/* ============================ TIER 1E: ANTI-ANALYSIS ============================ */

void test_timing_sleep(void) {
    struct timespec start, end, delay;
    long long elapsed_ms;
    
    print_banner("Timing / Sleep Jitter");
    
    clock_gettime(CLOCK_MONOTONIC, &start);
    
    printf("1. Sleeping for 100ms\n");
    delay.tv_sec = 0;
    delay.tv_nsec = 100000000;
    nanosleep(&delay, NULL);
    
    clock_gettime(CLOCK_MONOTONIC, &end);
    elapsed_ms = (end.tv_sec - start.tv_sec) * 1000 +
                 (end.tv_nsec - start.tv_nsec) / 1000000;
    printf("   Elapsed: %lld ms\n", elapsed_ms);
    
    printf("2. Variable sleep pattern\n");
    clock_gettime(CLOCK_MONOTONIC, &start);
    delay.tv_nsec = 50000000;
    nanosleep(&delay, NULL);
    delay.tv_nsec = 75000000;
    nanosleep(&delay, NULL);
    delay.tv_nsec = 25000000;
    nanosleep(&delay, NULL);
    
    clock_gettime(CLOCK_MONOTONIC, &end);
    elapsed_ms = (end.tv_sec - start.tv_sec) * 1000 +
                 (end.tv_nsec - start.tv_nsec) / 1000000;
    printf("   Total jittered sleep: %lld ms\n", elapsed_ms);
    
    printf("Test complete: delays and timing patterns should be attributable\n");
}

void test_environment_probes(void) {
    FILE* fp;
    char buf[256];
    char* env;
    
    print_banner("Environment Probes");
    
    printf("1. Reading /proc/self/status\n");
    fp = fopen("/proc/self/status", "r");
    if (fp) {
        while (fgets(buf, sizeof(buf), fp) && strncmp(buf, "Name:", 5) != 0);
        printf("   %s", buf);
        fclose(fp);
    }
    
    printf("2. Reading /proc/cpuinfo\n");
    fp = fopen("/proc/cpuinfo", "r");
    if (fp) {
        while (fgets(buf, sizeof(buf), fp) && strncmp(buf, "model name", 10) != 0);
        printf("   %s", buf);
        fclose(fp);
    }
    
    printf("3. Reading environment variables\n");
    env = getenv("USER");
    printf("   USER=%s\n", env ? env : "(null)");
    env = getenv("HOME");
    printf("   HOME=%s\n", env ? env : "(null)");
    env = getenv("PATH");
    printf("   PATH=%s\n", env ? env : "(null)");
    
    printf("4. Reading hostname\n");
    if (gethostname(buf, sizeof(buf)) == 0) {
        printf("   Hostname: %s\n", buf);
    }
    
    printf("Test complete: system profiling behavior should be flagged\n");
}

void test_self_introspection(void) {
    FILE* fp;
    char buf[256];
    int count = 0;
    DIR* dir;
    struct dirent* entry;
    
    print_banner("Self-introspection");
    
    printf("1. Reading /proc/self/maps (loaded memory regions)\n");
    fp = fopen("/proc/self/maps", "r");
    if (fp) {
        while (fgets(buf, sizeof(buf), fp) && count++ < 5) {
            printf("   %s", buf);
        }
        printf("   ... (truncated)\n");
        fclose(fp);
    }
    
    printf("2. Enumerating loaded libraries from /proc/self/map_files\n");
    dir = opendir("/proc/self/map_files");
    if (dir) {
        count = 0;
        while ((entry = readdir(dir)) && count++ < 5) {
            if (entry->d_name[0] != '.') {
                printf("   %s\n", entry->d_name);
            }
        }
        closedir(dir);
    } else {
        printf("   (requires privileges)\n");
    }
    
    printf("3. Reading /proc/self/cmdline\n");
    fp = fopen("/proc/self/cmdline", "r");
    if (fp) {
        size_t n = fread(buf, 1, sizeof(buf) - 1, fp);
        buf[n] = '\0';
        printf("   %s\n", buf);
        fclose(fp);
    }
    
    printf("Test complete: introspection/discovery behavior should be flagged\n");
}

void signal_handler(int sig) {
    printf("   Signal %d caught and handled\n", sig);
}

void test_signal_crash(void) {
    struct sigaction sa;
    
    print_banner("Signal + Crash Behavior");
    
    printf("1. Installing signal handler for SIGUSR1\n");
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = signal_handler;
    sigaction(SIGUSR1, &sa, NULL);
    
    printf("2. Raising SIGUSR1\n");
    raise(SIGUSR1);
    
    printf("3. Signal handled, continuing execution\n");
    
    printf("4. Installing handler for SIGSEGV\n");
    sigaction(SIGSEGV, &sa, NULL);
    
    printf("5. NOT deliberately crashing (would terminate test suite)\n");
    printf("   In real scenario: crash -> handler -> recovery -> continue\n");
    
    printf("Test complete: crash/catch/continue visibility needed\n");
}

/* ============================ TIER 2: SCENARIOS ============================ */

void test_dropper_local(void) {
    int sockfd, client_fd;
    struct sockaddr_in addr;
    pid_t server_pid, client_pid;
    char payload_path[512];
    FILE* fp;
    char buf[256];
    int status;
    
    print_banner("Dropper (Local Server)");
    
    snprintf(payload_path, sizeof(payload_path), "%s/dropped_payload", TEST_DIR);
    
    /* Fork a simple HTTP server */
    server_pid = fork();
    if (server_pid == 0) {
        /* Simple server child */
        sockfd = socket(AF_INET, SOCK_STREAM, 0);
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(8888);
        addr.sin_addr.s_addr = INADDR_ANY;
        
        if (bind(sockfd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
            exit(1);
        }
        listen(sockfd, 1);
        
        client_fd = accept(sockfd, NULL, NULL);
        if (client_fd >= 0) {
            char response[] = "#!/bin/sh\necho 'Stage 2 payload executed'\n";
            send(client_fd, response, strlen(response), 0);
            close(client_fd);
        }
        close(sockfd);
        exit(0);
    }
    
    sleep(1); /* Let server start */
    
    /* Client: fetch, decode, write, exec, cleanup */
    client_pid = fork();
    if (client_pid == 0) {
        printf("1. Fetching payload from localhost:8888\n");
        sockfd = socket(AF_INET, SOCK_STREAM, 0);
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(8888);
        addr.sin_addr.s_addr = inet_addr("127.0.0.1");
        
        if (connect(sockfd, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
            ssize_t n = recv(sockfd, buf, sizeof(buf) - 1, 0);
            if (n > 0) {
                buf[n] = '\0';
                printf("2. Received %ld bytes\n", (long)n);
                
                printf("3. Writing to disk: %s\n", payload_path);
                fp = fopen(payload_path, "w");
                fwrite(buf, 1, n, fp);
                fclose(fp);
                chmod(payload_path, 0755);
                
                printf("4. Executing payload\n");
                system(payload_path);
                
                printf("5. Cleaning up\n");
                unlink(payload_path);
            }
        }
        close(sockfd);
        exit(0);
    }
    
    wait(&status);
    wait(&status);
    
    printf("Test complete: staged network -> decode -> write -> exec -> delete\n");
}

void test_fileless_stager(void) {
    print_banner("Fileless Stager");

#if defined(SYS_memfd_create) || defined(__NR_memfd_create)
    int fd;
    pid_t pid;
    int status;
    char fdpath[64];
    const char* payload = "#!/bin/sh\necho 'Fileless stage 2 executed'\n";

    printf("1. Creating memfd (fileless storage)\n");
# if defined(SYS_memfd_create)
    fd = (int)syscall(SYS_memfd_create, "stage2", 0);
# else
    fd = (int)syscall(__NR_memfd_create, "stage2", 0);
# endif
    if (fd < 0) {
        perror("memfd_create failed");
        return;
    }

    printf("2. Writing payload to memfd (no disk touch)\n");
    write(fd, payload, (size_t)strlen(payload));
    lseek(fd, 0, SEEK_SET);
    fchmod(fd, 0755);

    snprintf(fdpath, sizeof(fdpath), "/proc/self/fd/%d", fd);
    printf("   memfd path: %s\n", fdpath);

    printf("3. Executing via /bin/sh %s (still fileless)\n", fdpath);
    pid = fork();
    if (pid == 0) {
        char *const sh_argv[] = { "sh", fdpath, NULL };
        execve("/bin/sh", sh_argv, environ);
        perror("execve(/bin/sh) failed");
        _exit(1);
    }

    waitpid(pid, &status, 0);
    close(fd);

    printf("4. No cleanup needed (no disk artifacts)\n");
    printf("Test complete: SoftRX should provide artifact handle despite no disk write\n");
#else
    printf("memfd_create not available, test skipped\n");
#endif
}

void test_persistence_sim(void) {
    char cron_file[512];
    char desktop_file[512];
    FILE* fp;
    
    print_banner("Persistence Simulator");
    
    snprintf(cron_file, sizeof(cron_file), "%s/fake_cron", TEST_DIR);
    snprintf(desktop_file, sizeof(desktop_file), "%s/fake.desktop", TEST_DIR);
    
    printf("1. Writing fake cron entry\n");
    fp = fopen(cron_file, "w");
    fprintf(fp, "*/5 * * * * /tmp/backdoor.sh\n");
    fclose(fp);
    printf("   Wrote: %s\n", cron_file);
    
    printf("2. Writing fake .desktop entry\n");
    fp = fopen(desktop_file, "w");
    fprintf(fp, "[Desktop Entry]\n");
    fprintf(fp, "Type=Application\n");
    fprintf(fp, "Exec=/tmp/malware\n");
    fprintf(fp, "X-GNOME-Autostart-enabled=true\n");
    fclose(fp);
    printf("   Wrote: %s\n", desktop_file);
    
    printf("Test complete: should be flagged as persistence-like intent\n");
}

void test_credential_theft_sim(void) {
    char fixture_dir[512];
    char browser_db[512];
    char ssh_key[512];
    FILE* fp;
    char buf[256];
    
    print_banner("Credential Theft Simulator (Safe)");
    
    snprintf(fixture_dir, sizeof(fixture_dir), "%s/fixtures", TEST_DIR);
    mkdir(fixture_dir, 0755);
    
    snprintf(browser_db, sizeof(browser_db), "%s/fake_browser.sqlite", fixture_dir);
    snprintf(ssh_key, sizeof(ssh_key), "%s/fake_id_rsa", fixture_dir);
    
    /* Create fixtures */
    fp = fopen(browser_db, "w");
    fprintf(fp, "FAKE SQLITE DATABASE WITH PASSWORDS\n");
    fclose(fp);
    
    fp = fopen(ssh_key, "w");
    fprintf(fp, "-----BEGIN FAKE RSA PRIVATE KEY-----\n");
    fclose(fp);
    chmod(ssh_key, 0600);
    
    /* Simulate theft */
    printf("1. Reading fake browser database: %s\n", browser_db);
    fp = fopen(browser_db, "r");
    if (fp) {
        fgets(buf, sizeof(buf), fp);
        printf("   Read: %s", buf);
        fclose(fp);
    }
    
    printf("2. Reading fake SSH key: %s\n", ssh_key);
    fp = fopen(ssh_key, "r");
    if (fp) {
        fgets(buf, sizeof(buf), fp);
        printf("   Read: %s", buf);
        fclose(fp);
    }
    
    printf("Test complete: sensitive-file access patterns detected\n");
}

void test_recon_bundle(void) {
    FILE* fp;
    char buf[256];
    DIR* dir;
    struct dirent* entry;
    
    print_banner("Recon Bundle");
    
    printf("1. Gathering system info (uname)\n");
    system("uname -a > /tmp/softrx_test/recon_uname.txt");
    
    printf("2. Enumerating network interfaces\n");
    fp = fopen("/proc/net/dev", "r");
    if (fp) {
        printf("   Interfaces:\n");
        while (fgets(buf, sizeof(buf), fp)) {
            if (strstr(buf, ":")) {
                printf("   %s", buf);
            }
        }
        fclose(fp);
    }
    
    printf("3. Reading routing table\n");
    fp = fopen("/proc/net/route", "r");
    if (fp) {
        fgets(buf, sizeof(buf), fp); /* header */
        if (fgets(buf, sizeof(buf), fp)) {
            printf("   Route: %s", buf);
        }
        fclose(fp);
    }
    
    printf("4. Enumerating processes\n");
    dir = opendir("/proc");
    if (dir) {
        int count = 0;
        while ((entry = readdir(dir)) && count < 5) {
            if (entry->d_name[0] >= '0' && entry->d_name[0] <= '9') {
                printf("   PID: %s\n", entry->d_name);
                count++;
            }
        }
        printf("   ... (truncated)\n");
        closedir(dir);
    }
    
    printf("Test complete: should summarize as 'host discovery/recon' not 200 tiny reads\n");
}

void test_noise_generator(void) {
    int i;
    char path[512];
    struct stat st;
    DIR* dir;
    struct dirent* entry;
    
    print_banner("Noise Generator");
    
    printf("1. Performing 100 stat() calls\n");
    for (i = 0; i < 100; i++) {
        snprintf(path, sizeof(path), "/tmp/nonexistent_%d", i);
        stat(path, &st);
    }
    printf("   100 stat calls completed\n");
    
    printf("2. Recursive directory walk of /usr/bin\n");
    dir = opendir("/usr/bin");
    if (dir) {
        i = 0;
        while ((entry = readdir(dir)) && i++ < 50) {
            /* Just enumerate, don't process */
        }
        printf("   Walked %d entries\n", i);
        closedir(dir);
    }
    
    printf("3. Repeated file existence checks\n");
    for (i = 0; i < 50; i++) {
        access("/etc/passwd", F_OK);
        access("/etc/shadow", F_OK);
        access("/etc/hosts", F_OK);
    }
    printf("   150 access calls completed\n");
    
    printf("Test complete: UI should compress into 'scan/enumeration' with drill-down\n");
}
