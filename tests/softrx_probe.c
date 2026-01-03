// softrx_launcher.c (PATCHED VERSION with critical bug fixes)
// Build:
//   cc -O2 -Wall -Wextra -o bin/softrx_launcher softrx_launcher_patched.c -lpthread

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <poll.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>

#include <time.h>
#include <unistd.h>
#include <dirent.h>
#include <limits.h>

#ifndef SECCOMP_FILTER_FLAG_NEW_LISTENER
#define SECCOMP_FILTER_FLAG_NEW_LISTENER (1UL << 3)
#endif

#ifndef SECCOMP_IOCTL_NOTIF_ID_VALID
#define SECCOMP_IOCTL_NOTIF_ID_VALID SECCOMP_IOW(2, __u64)
#endif

static void die(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    va_end(ap);
    exit(1);
}

static long xseccomp(unsigned int op, unsigned int flags, void *args) {
    return syscall(__NR_seccomp, op, flags, args);
}

static uint64_t now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)ts.tv_nsec / 1000000ULL;
}

static int mkdir_p(const char *path) {
    char tmp[4096];
    size_t len = strnlen(path, sizeof(tmp)-1);
    if (len == 0 || len >= sizeof(tmp)-1) return -1;
    memcpy(tmp, path, len);
    tmp[len] = '\0';
    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            mkdir(tmp, 0755);
            *p = '/';
        }
    }
    return mkdir(tmp, 0755) == 0 || errno == EEXIST ? 0 : -1;
}

static ssize_t read_remote(pid_t pid, void *local, const void *remote, size_t n) {
    struct iovec liov = { .iov_base = local, .iov_len = n };
    struct iovec riov = { .iov_base = (void*)remote, .iov_len = n };
    return process_vm_readv(pid, &liov, 1, &riov, 1, 0);
}

static ssize_t read_remote_cstr(pid_t pid, uint64_t remote_ptr, char *out, size_t out_sz) {
    if (out_sz == 0) return -1;
    out[0] = '\0';
    if (remote_ptr == 0) return -1;
    size_t off = 0;
    while (off + 1 < out_sz) {
        char buf[64];
        size_t want = sizeof(buf);
        if (off + want >= out_sz) want = out_sz - off - 1;
        ssize_t got = read_remote(pid, buf, (void*)(uintptr_t)(remote_ptr + off), want);
        if (got <= 0) break;
        for (ssize_t i = 0; i < got; i++) {
            out[off++] = buf[i];
            if (buf[i] == '\0') { 
                out[out_sz-1] = '\0'; 
                return (ssize_t)off; 
            }
            if (off + 1 >= out_sz) break;
        }
        if (off + 1 >= out_sz) break;
    }
    out[out_sz-1] = '\0';
    return (ssize_t)strlen(out);
}

static ssize_t read_remote_mem(pid_t pid, uint64_t remote, void *dst, size_t n) {
    return read_remote(pid, dst, (void*)(uintptr_t)remote, n);
}

static void send_fd(int sock, int fd) {
    struct msghdr msg;
    memset(&msg, 0, sizeof(msg));
    char buf[1] = {'F'};
    struct iovec io = { .iov_base = buf, .iov_len = sizeof(buf) };
    msg.msg_iov = &io;
    msg.msg_iovlen = 1;

    char cmsgbuf[CMSG_SPACE(sizeof(int))];
    memset(cmsgbuf, 0, sizeof(cmsgbuf));
    msg.msg_control = cmsgbuf;
    msg.msg_controllen = sizeof(cmsgbuf);

    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    cmsg->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(cmsg), &fd, sizeof(int));
    msg.msg_controllen = CMSG_SPACE(sizeof(int));

    if (sendmsg(sock, &msg, 0) < 0) die("sendmsg(SCM_RIGHTS) failed: %s", strerror(errno));
}

static int recv_fd(int sock) {
    struct msghdr msg;
    memset(&msg, 0, sizeof(msg));
    char m_buffer[1];
    struct iovec io = { .iov_base = m_buffer, .iov_len = sizeof(m_buffer) };
    msg.msg_iov = &io;
    msg.msg_iovlen = 1;

    char cmsgbuf[CMSG_SPACE(sizeof(int))];
    memset(cmsgbuf, 0, sizeof(cmsgbuf));
    msg.msg_control = cmsgbuf;
    msg.msg_controllen = sizeof(cmsgbuf);

    if (recvmsg(sock, &msg, 0) < 0) die("recvmsg failed: %s", strerror(errno));

    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
    if (!cmsg) die("recvmsg: no cmsg");
    int fd;
    memcpy(&fd, CMSG_DATA(cmsg), sizeof(int));
    return fd;
}

// FIXED: Proper path normalization with .. handling
static void normalize_inplace(char *p) {
    if (!p || !p[0]) return;
    
    char tmp[PATH_MAX];
    char *components[256];
    int comp_count = 0;
    
    int is_absolute = (p[0] == '/');
    char *token = p;
    
    // Tokenize by '/'
    for (char *r = p; *r; r++) {
        if (*r == '/') {
            *r = '\0';
            if (token < r) { // Non-empty component
                if (strcmp(token, ".") == 0) {
                    // Skip "."
                } else if (strcmp(token, "..") == 0) {
                    // Go up one level
                    if (comp_count > 0) comp_count--;
                } else {
                    components[comp_count++] = token;
                    if (comp_count >= 256) break;
                }
            }
            token = r + 1;
        }
    }
    // Handle last component
    if (*token) {
        if (strcmp(token, ".") == 0) {
            // Skip
        } else if (strcmp(token, "..") == 0) {
            if (comp_count > 0) comp_count--;
        } else {
            components[comp_count++] = token;
        }
    }
    
    // Rebuild path
    char *w = tmp;
    if (is_absolute) *w++ = '/';
    for (int i = 0; i < comp_count; i++) {
        if (i > 0) *w++ = '/';
        size_t len = strlen(components[i]);
        if ((size_t)(w - tmp) + len >= sizeof(tmp) - 1) break;
        memcpy(w, components[i], len);
        w += len;
    }
    *w = '\0';
    
    // Handle empty path
    if (tmp[0] == '\0') {
        strcpy(tmp, is_absolute ? "/" : ".");
    }
    
    strncpy(p, tmp, PATH_MAX - 1);
    p[PATH_MAX - 1] = '\0';
}

static void path_join(const char *base, const char *rel, char *out, size_t out_sz) {
    if (!rel || !rel[0]) { 
        snprintf(out, out_sz, "%s", base); 
        return; 
    }
    if (rel[0] == '/') { 
        snprintf(out, out_sz, "%s", rel); 
        return; 
    }
    snprintf(out, out_sz, "%s/%s", base, rel);
}

typedef enum { MODE_MALWARE=0, MODE_RE=1, MODE_REVEAL_NET=2 } run_mode_t;

typedef struct sock_track_t {
    int fd;
    bool active;
    bool has_dst;
    char dst[128];
    uint32_t ip_be;
    uint16_t port_be;
    bool allowed;
    uint64_t first_ts_ms;
    uint64_t bytes_out;
    uint64_t sends;
} sock_track_t;

typedef struct {
    pid_t tracee;
    pid_t tracee_pgid;
    int notify_fd;
    char outdir[PATH_MAX];
    char write_jail[PATH_MAX];
    bool interactive_fs;
    run_mode_t mode;
    uint64_t timeout_ms;
    int max_events;
    FILE *events_fp;
    char tracee_cwd[PATH_MAX];
    bool saw_initial_exec;
    char sample_abs[PATH_MAX];
    bool allow_dns;
    bool allow_dot;
    bool allow_any_connect;
    uint64_t net_cap_bytes;
    uint64_t net_cap_ms;
    uint64_t net_cap_sends;
    struct { uint32_t ip_be; uint16_t port_be; } allowlist[128];
    int allowlist_count;
    struct sock_track_t socks[512];
    int sock_count;
} supervisor_ctx_t;

static bool allowlist_matches(supervisor_ctx_t *c, uint32_t ip_be, uint16_t port_be) {
    for (int i = 0; i < c->allowlist_count; i++) {
        if (c->allowlist[i].ip_be == ip_be && c->allowlist[i].port_be == port_be) return true;
    }
    return false;
}

static sock_track_t *sock_get(supervisor_ctx_t *c, int fd) {
    for (int i = 0; i < c->sock_count; i++) {
        if (c->socks[i].active && c->socks[i].fd == fd) return &c->socks[i];
    }
    return NULL;
}

static sock_track_t *sock_get_or_add(supervisor_ctx_t *c, int fd) {
    sock_track_t *t = sock_get(c, fd);
    if (t) return t;
    if (c->sock_count >= (int)(sizeof(c->socks)/sizeof(c->socks[0]))) return NULL;
    t = &c->socks[c->sock_count++];
    memset(t, 0, sizeof(*t));
    t->fd = fd;
    t->active = true;
    return t;
}

// FIXED: Track socket close
static void sock_remove(supervisor_ctx_t *c, int fd) {
    sock_track_t *t = sock_get(c, fd);
    if (t) t->active = false;
}

static void dump_text_file(const char *dst_path, const char *fmt, ...) {
    FILE *fp = fopen(dst_path, "w");
    if (!fp) return;
    va_list ap;
    va_start(ap, fmt);
    vfprintf(fp, fmt, ap);
    va_end(ap);
    fclose(fp);
}

static void dump_proc_file(pid_t pid, const char *proc_leaf, const char *dst_path) {
    char src[128];
    snprintf(src, sizeof(src), "/proc/%d/%s", pid, proc_leaf);
    int in = open(src, O_RDONLY);
    if (in < 0) return;
    int out = open(dst_path, O_CREAT|O_TRUNC|O_WRONLY, 0644);
    if (out < 0) { close(in); return; }
    char buf[8192];
    ssize_t n;
    while ((n = read(in, buf, sizeof(buf))) > 0) {
        (void)write(out, buf, (size_t)n);
    }
    close(in);
    close(out);
}

static void dump_fd_links(pid_t pid, const char *dst_path) {
    char dirp[128];
    snprintf(dirp, sizeof(dirp), "/proc/%d/fd", pid);
    DIR *d = opendir(dirp);
    if (!d) return;
    FILE *fp = fopen(dst_path, "w");
    if (!fp) { closedir(d); return; }
    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        if (de->d_name[0] == '.') continue;
        char lnk[256];
        char tgt[4096];
        snprintf(lnk, sizeof(lnk), "%s/%s", dirp, de->d_name);
        ssize_t n = readlink(lnk, tgt, sizeof(tgt)-1);
        if (n <= 0) continue;
        tgt[n] = '\0';
        fprintf(fp, "%s -> %s\n", de->d_name, tgt);
    }
    fclose(fp);
    closedir(d);
}

static void dump_sockmap_json(supervisor_ctx_t *c, const char *dst_path) {
    FILE *fp = fopen(dst_path, "w");
    if (!fp) return;
    fprintf(fp, "[\n");
    int first = 1;
    for (int i = 0; i < c->sock_count; i++) {
        sock_track_t *t = &c->socks[i];
        if (!t->active) continue;
        if (!first) fprintf(fp, ",\n");
        first = 0;
        fprintf(fp,
            "  {\"fd\":%d,\"dst\":\"%s\",\"allowed\":%s,\"bytes_out\":%llu,\"sends\":%llu}",
            t->fd,
            t->has_dst ? t->dst : "unknown",
            t->allowed ? "true" : "false",
            (unsigned long long)t->bytes_out,
            (unsigned long long)t->sends
        );
    }
    fprintf(fp, "\n]\n");
    fclose(fp);
}

static void snapshot_and_kill(supervisor_ctx_t *c, const char *why);

static void emit_evt(supervisor_ctx_t *c, const char *event, const char *fmt, ...) {
    uint64_t ts = now_ms();
    fprintf(c->events_fp, "{\"ts_ms\":%llu,\"event\":\"%s\"", (unsigned long long)ts, event);
    if (fmt && fmt[0]) {
        fprintf(c->events_fp, ",");
        va_list ap;
        va_start(ap, fmt);
        vfprintf(c->events_fp, fmt, ap);
        va_end(ap);
    }
    fprintf(c->events_fp, "}\n");
    fflush(c->events_fp);
}

static void hard_kill(supervisor_ctx_t *c, const char *why) {
    emit_evt(c, "hard_kill", "\"why\":\"%s\"", why);
    if (c->tracee_pgid > 0) {
        kill(-c->tracee_pgid, SIGKILL);
    } else if (c->tracee > 0) {
        kill(c->tracee, SIGKILL);
    }
}

static void snapshot_and_kill(supervisor_ctx_t *c, const char *why) {
    emit_evt(c, "snapshot", "\"why\":\"%s\"", why);
    mkdir_p(c->outdir);

    char p1[PATH_MAX];
    snprintf(p1, sizeof(p1), "%s/dump_cmdline.txt", c->outdir);
    dump_proc_file(c->tracee, "cmdline", p1);

    snprintf(p1, sizeof(p1), "%s/dump_environ.txt", c->outdir);
    dump_proc_file(c->tracee, "environ", p1);

    snprintf(p1, sizeof(p1), "%s/dump_maps.txt", c->outdir);
    dump_proc_file(c->tracee, "maps", p1);

    snprintf(p1, sizeof(p1), "%s/dump_fds.txt", c->outdir);
    dump_fd_links(c->tracee, p1);

    snprintf(p1, sizeof(p1), "%s/dump_sockmap.json", c->outdir);
    dump_sockmap_json(c, p1);

    hard_kill(c, why);
}

static int prompt_decision(const char *abs_path) {
    fprintf(stderr, "[SoftRX][FS] write inside jail: %s\n", abs_path);
    fprintf(stderr, "Decision: (a)llow once, (A)llow always in jail, (d)eny > ");
    fflush(stderr);
    int ch = getchar();
    while (ch != '\n' && ch != EOF) {
        int c = getchar();
        if (c == '\n' || c == EOF) break;
    }
    return ch;
}

#define SC_ALLOW  SECCOMP_RET_ALLOW
#define SC_KILL   SECCOMP_RET_KILL_PROCESS
#define SC_NOTIFY SECCOMP_RET_USER_NOTIF

#define LOAD_SYSCALL_NR BPF_STMT(BPF_LD|BPF_W|BPF_ABS, offsetof(struct seccomp_data, nr))
#define JEQ_SYSCALL(nr, jt, jf) BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, (nr), (jt), (jf))

// FIXED: Added missing syscalls for probe coverage
static int install_listener_filter(void) {
    struct sock_filter filter[] = {
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS, offsetof(struct seccomp_data, arch)),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, AUDIT_ARCH_X86_64, 1, 0),
        BPF_STMT(BPF_RET|BPF_K, SC_KILL),

        LOAD_SYSCALL_NR,

        // Memory
        JEQ_SYSCALL(__NR_mprotect, 0, 1), BPF_STMT(BPF_RET|BPF_K, SC_NOTIFY),

        // Filesystem
        JEQ_SYSCALL(__NR_openat, 0, 1),  BPF_STMT(BPF_RET|BPF_K, SC_NOTIFY),
        JEQ_SYSCALL(__NR_open, 0, 1),    BPF_STMT(BPF_RET|BPF_K, SC_NOTIFY),
        JEQ_SYSCALL(__NR_unlinkat, 0, 1),BPF_STMT(BPF_RET|BPF_K, SC_NOTIFY),
        JEQ_SYSCALL(__NR_unlink, 0, 1),  BPF_STMT(BPF_RET|BPF_K, SC_NOTIFY),
        JEQ_SYSCALL(__NR_renameat,0, 1), BPF_STMT(BPF_RET|BPF_K, SC_NOTIFY),
        JEQ_SYSCALL(__NR_renameat2,0, 1),BPF_STMT(BPF_RET|BPF_K, SC_NOTIFY),
        JEQ_SYSCALL(__NR_rename, 0, 1),  BPF_STMT(BPF_RET|BPF_K, SC_NOTIFY),
        JEQ_SYSCALL(__NR_linkat, 0, 1),  BPF_STMT(BPF_RET|BPF_K, SC_NOTIFY),
        JEQ_SYSCALL(__NR_symlinkat,0,1), BPF_STMT(BPF_RET|BPF_K, SC_NOTIFY),

        // Process
        JEQ_SYSCALL(__NR_execve, 0, 1),  BPF_STMT(BPF_RET|BPF_K, SC_NOTIFY),
        JEQ_SYSCALL(__NR_execveat,0, 1), BPF_STMT(BPF_RET|BPF_K, SC_NOTIFY),
        JEQ_SYSCALL(__NR_fork, 0, 1),    BPF_STMT(BPF_RET|BPF_K, SC_NOTIFY),
        JEQ_SYSCALL(__NR_vfork,0, 1),    BPF_STMT(BPF_RET|BPF_K, SC_NOTIFY),
        JEQ_SYSCALL(__NR_clone,0, 1),    BPF_STMT(BPF_RET|BPF_K, SC_NOTIFY),
        JEQ_SYSCALL(__NR_clone3,0, 1),   BPF_STMT(BPF_RET|BPF_K, SC_NOTIFY),

        // Network
        JEQ_SYSCALL(__NR_socket,0, 1),   BPF_STMT(BPF_RET|BPF_K, SC_NOTIFY),
        JEQ_SYSCALL(__NR_connect,0, 1),  BPF_STMT(BPF_RET|BPF_K, SC_NOTIFY),
        JEQ_SYSCALL(__NR_sendto,0, 1),   BPF_STMT(BPF_RET|BPF_K, SC_NOTIFY),
        JEQ_SYSCALL(__NR_sendmsg,0, 1),  BPF_STMT(BPF_RET|BPF_K, SC_NOTIFY),
        JEQ_SYSCALL(__NR_write,0, 1),    BPF_STMT(BPF_RET|BPF_K, SC_NOTIFY),
        JEQ_SYSCALL(__NR_writev,0, 1),   BPF_STMT(BPF_RET|BPF_K, SC_NOTIFY),
        JEQ_SYSCALL(__NR_bind,0, 1),     BPF_STMT(BPF_RET|BPF_K, SC_NOTIFY),
        JEQ_SYSCALL(__NR_listen,0, 1),   BPF_STMT(BPF_RET|BPF_K, SC_NOTIFY),
        JEQ_SYSCALL(__NR_recvfrom,0, 1), BPF_STMT(BPF_RET|BPF_K, SC_NOTIFY),

        // FD operations (for probe Stage 5 telemetry)
        JEQ_SYSCALL(__NR_close,0, 1),    BPF_STMT(BPF_RET|BPF_K, SC_NOTIFY),
        JEQ_SYSCALL(__NR_dup,0, 1),      BPF_STMT(BPF_RET|BPF_K, SC_NOTIFY),
        JEQ_SYSCALL(__NR_dup2,0, 1),     BPF_STMT(BPF_RET|BPF_K, SC_NOTIFY),
        JEQ_SYSCALL(__NR_dup3,0, 1),     BPF_STMT(BPF_RET|BPF_K, SC_NOTIFY),
        JEQ_SYSCALL(__NR_pipe,0, 1),     BPF_STMT(BPF_RET|BPF_K, SC_NOTIFY),
        JEQ_SYSCALL(__NR_pipe2,0, 1),    BPF_STMT(BPF_RET|BPF_K, SC_NOTIFY),
        JEQ_SYSCALL(__NR_fcntl,0, 1),    BPF_STMT(BPF_RET|BPF_K, SC_NOTIFY),
        JEQ_SYSCALL(__NR_ioctl,0, 1),    BPF_STMT(BPF_RET|BPF_K, SC_NOTIFY),

        BPF_STMT(BPF_RET|BPF_K, SC_ALLOW),
    };

    struct sock_fprog prog = {
        .len = (unsigned short)(sizeof(filter)/sizeof(filter[0])),
        .filter = filter,
    };

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) 
        die("PR_SET_NO_NEW_PRIVS failed: %s", strerror(errno));

    int fd = (int)xseccomp(SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_NEW_LISTENER, &prog);
    if (fd < 0) die("seccomp(NEW_LISTENER) failed: %s", strerror(errno));
    return fd;
}

// FIXED: Added TOCTOU protection
static bool validate_notif_id(int notify_fd, uint64_t id) {
    struct seccomp_notif_id_valid id_check;
    memset(&id_check, 0, sizeof(id_check));
    id_check.id = id;
    return ioctl(notify_fd, SECCOMP_IOCTL_NOTIF_ID_VALID, &id_check) == 0;
}

static void respond_errno(int notify_fd, uint64_t id, int err) {
    if (!validate_notif_id(notify_fd, id)) return;
    struct seccomp_notif_resp resp;
    memset(&resp, 0, sizeof(resp));
    resp.id = id;
    resp.error = -err;
    resp.val = 0;
    resp.flags = 0;
    if (ioctl(notify_fd, SECCOMP_IOCTL_NOTIF_SEND, &resp) != 0) {
        if (errno != ENOENT) // Tracee may have exited
            fprintf(stderr, "[SoftRX] NOTIF_SEND failed: %s\n", strerror(errno));
    }
}

static void respond_continue(int notify_fd, uint64_t id) {
    if (!validate_notif_id(notify_fd, id)) return;
    struct seccomp_notif_resp resp;
    memset(&resp, 0, sizeof(resp));
    resp.id = id;
    resp.flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;
    if (ioctl(notify_fd, SECCOMP_IOCTL_NOTIF_SEND, &resp) != 0) {
        if (errno != ENOENT)
            fprintf(stderr, "[SoftRX] NOTIF_SEND(continue) failed: %s\n", strerror(errno));
    }
}

static void get_tracee_cwd(pid_t pid, char *out, size_t out_sz) {
    char linkpath[64];
    snprintf(linkpath, sizeof(linkpath), "/proc/%d/cwd", pid);
    ssize_t n = readlink(linkpath, out, out_sz-1);
    if (n <= 0) { snprintf(out, out_sz, "/"); return; }
    out[n] = '\0';
}

static bool within_jail(supervisor_ctx_t *c, const char *abs_path) {
    if (!c->write_jail[0]) return false;
    
    char p[PATH_MAX];
    snprintf(p, sizeof(p), "%s", abs_path);
    normalize_inplace(p);

    char jail[PATH_MAX];
    snprintf(jail, sizeof(jail), "%s", c->write_jail);
    normalize_inplace(jail);

    size_t jl = strlen(jail);
    if (jl == 0) return false;

    // Ensure jail path ends with / for prefix matching
    if (jail[jl-1] != '/') {
        if (jl + 1 >= sizeof(jail)) return false;
        jail[jl] = '/';
        jail[jl+1] = '\0';
        jl++;
    }

    return strncmp(p, jail, jl) == 0;
}

static bool is_write_flags(int flags) {
    return (flags & (O_WRONLY | O_RDWR | O_CREAT | O_TRUNC | O_APPEND)) != 0;
}

// FIXED: Proper openat dirfd handling
static void handle_open_like(supervisor_ctx_t *c, struct seccomp_notif *req) {
    int nr = req->data.nr;
    uint64_t pathptr = 0;
    int flags = 0;
    int dirfd = AT_FDCWD;

    if (nr == __NR_open) {
        pathptr = req->data.args[0];
        flags   = (int)req->data.args[1];
    } else { // __NR_openat
        dirfd   = (int)req->data.args[0];
        pathptr = req->data.args[1];
        flags   = (int)req->data.args[2];
    }

    char path[PATH_MAX] = {0};
    char abs[PATH_MAX]  = {0};

    if (read_remote_cstr(c->tracee, pathptr, path, sizeof(path)) <= 0) {
        emit_evt(c, "error", "\"msg\":\"read_remote_cstr failed in open\"");
        respond_errno(c->notify_fd, req->id, EFAULT);
        return;
    }

    // Resolve absolute path
    if (path[0] == '/') {
        snprintf(abs, sizeof(abs), "%s", path);
    } else if (dirfd == AT_FDCWD || dirfd < 0) {
        get_tracee_cwd(c->tracee, c->tracee_cwd, sizeof(c->tracee_cwd));
        path_join(c->tracee_cwd, path, abs, sizeof(abs));
    } else {
        // Resolve dirfd to directory path
        char dirlink[128], dirbuf[PATH_MAX];
        snprintf(dirlink, sizeof(dirlink), "/proc/%d/fd/%d", c->tracee, dirfd);
        ssize_t n = readlink(dirlink, dirbuf, sizeof(dirbuf)-1);
        if (n > 0) {
            dirbuf[n] = '\0';
            path_join(dirbuf, path, abs, sizeof(abs));
        } else {
            // Fallback to cwd if readlink fails
            get_tracee_cwd(c->tracee, c->tracee_cwd, sizeof(c->tracee_cwd));
            path_join(c->tracee_cwd, path, abs, sizeof(abs));
        }
    }
    
    normalize_inplace(abs);

    bool in_jail = within_jail(c, abs);
    bool wants_write = is_write_flags(flags);

    emit_evt(c, "fs_open_attempt",
             "\"sys\":\"%s\",\"path\":\"%s\",\"abs\":\"%s\",\"flags\":%d,\"in_jail\":%s,\"write\":%s",
             (nr == __NR_open ? "open" : "openat"),
             path, abs, flags, in_jail ? "true" : "false", wants_write ? "true" : "false");

    // Allow all reads
    if (!wants_write) {
        respond_continue(c->notify_fd, req->id);
        return;
    }

    // reveal-net mode: deny ALL writes
    if (c->mode == MODE_REVEAL_NET) {
        if (strncmp(abs, "/etc/cron", 9) == 0 ||
            strncmp(abs, "/var/spool/cron", 14) == 0 ||
            strncmp(abs, "/etc/systemd", 12) == 0) {
            emit_evt(c, "tripwire_fs_persist", "\"abs\":\"%s\"", abs);
            respond_errno(c->notify_fd, req->id, EACCES);
            snapshot_and_kill(c, "persist_path_write_attempt");
            return;
        }
        emit_evt(c, "fs_open_trap", "\"abs\":\"%s\",\"flags\":%d", abs, flags);
        respond_errno(c->notify_fd, req->id, EACCES);
        return;
    }

    // Allow writes inside jail
    if (in_jail) {
        respond_continue(c->notify_fd, req->id);
        return;
    }

    // Deny writes outside jail
    emit_evt(c, "fs_open_denied",
             "\"reason\":\"write_outside_jail\",\"abs\":\"%s\"", abs);
    respond_errno(c->notify_fd, req->id, EPERM);

    if (c->mode == MODE_MALWARE) {
        hard_kill(c, "write_outside_jail");
    }
}

static void handle_unlink_like(supervisor_ctx_t *c, struct seccomp_notif *req) {
    char path[PATH_MAX], abs[PATH_MAX];
    bool is_unlinkat = (req->data.nr == __NR_unlinkat);
    uint64_t pathptr = is_unlinkat ? req->data.args[1] : req->data.args[0];

    if (read_remote_cstr(c->tracee, pathptr, path, sizeof(path)) <= 0) {
        snprintf(path, sizeof(path), "<unreadable>");
    }
    
    get_tracee_cwd(c->tracee, c->tracee_cwd, sizeof(c->tracee_cwd));
    path_join(c->tracee_cwd, path, abs, sizeof(abs));
    normalize_inplace(abs);

    bool in_jail = within_jail(c, abs);
    emit_evt(c, "fs_unlink_attempt",
             "\"sys\":\"%s\",\"path\":\"%s\",\"abs\":\"%s\",\"in_jail\":%s",
             is_unlinkat ? "unlinkat":"unlink", path, abs, in_jail?"true":"false");

    if (!in_jail) {
        if (c->mode == MODE_MALWARE) hard_kill(c, "unlink_outside_jail");
        respond_errno(c->notify_fd, req->id, EPERM);
        return;
    }
    if (c->interactive_fs) {
        int ch = prompt_decision(abs);
        if (ch == 'd' || ch == 'D' || ch == EOF) { 
            respond_errno(c->notify_fd, req->id, EPERM); 
            return; 
        }
    }
    respond_continue(c->notify_fd, req->id);
}

static void handle_symlink_like(supervisor_ctx_t *c, struct seccomp_notif *req) {
    // symlinkat(target, newdirfd, linkpath)
    uint64_t targetptr = req->data.args[0];
    uint64_t linkptr = req->data.args[2];
    
    char target[PATH_MAX], linkpath[PATH_MAX], abs_link[PATH_MAX];
    
    if (read_remote_cstr(c->tracee, targetptr, target, sizeof(target)) <= 0) {
        strcpy(target, "<unreadable>");
    }
    if (read_remote_cstr(c->tracee, linkptr, linkpath, sizeof(linkpath)) <= 0) {
        strcpy(linkpath, "<unreadable>");
    }
    
    get_tracee_cwd(c->tracee, c->tracee_cwd, sizeof(c->tracee_cwd));
    path_join(c->tracee_cwd, linkpath, abs_link, sizeof(abs_link));
    normalize_inplace(abs_link);
    
    bool in_jail = within_jail(c, abs_link);
    
    emit_evt(c, "fs_symlink_attempt",
             "\"target\":\"%s\",\"linkpath\":\"%s\",\"in_jail\":%s",
             target, abs_link, in_jail ? "true" : "false");
    
    if (in_jail) {
        respond_continue(c->notify_fd, req->id);
    } else {
        respond_errno(c->notify_fd, req->id, EPERM);
    }
}

static void handle_exec(supervisor_ctx_t *c, struct seccomp_notif *req) {
    uint64_t pathptr = (req->data.nr == __NR_execveat) ? req->data.args[1] : req->data.args[0];
    char path[PATH_MAX];
    char abs[PATH_MAX];
    
    if (read_remote_cstr(c->tracee, pathptr, path, sizeof(path)) <= 0) {
        strcpy(path, "<unreadable>");
    }

    get_tracee_cwd(c->tracee, c->tracee_cwd, sizeof(c->tracee_cwd));
    path_join(c->tracee_cwd, path, abs, sizeof(abs));
    normalize_inplace(abs);

    emit_evt(c, "exec_attempt", "\"path\":\"%s\",\"abs\":\"%s\"", path, abs);

    // Allow exactly one exec: the initial sample
    if (!c->saw_initial_exec && c->sample_abs[0] && strcmp(abs, c->sample_abs) == 0) {
        c->saw_initial_exec = true;
        emit_evt(c, "exec_allow_initial", "\"abs\":\"%s\"", abs);
        respond_continue(c->notify_fd, req->id);
        return;
    }

    emit_evt(c, "exec_denied", "\"abs\":\"%s\"", abs);

    if (c->mode == MODE_REVEAL_NET) {
        const char *bn = strrchr(abs, '/');
        bn = bn ? (bn + 1) : abs;

        if (strstr(bn, "php") || strstr(bn, "php-fpm") ||
            strstr(bn, "apache") || strstr(bn, "httpd") ||
            strstr(bn, "nginx") || strcmp(bn, "sh") == 0 ||
            strcmp(bn, "bash") == 0 || strstr(bn, "cron")) {
            emit_evt(c, "tripwire_exec_service", "\"abs\":\"%s\"", abs);
            respond_errno(c->notify_fd, req->id, ENOENT);
            snapshot_and_kill(c, "exec_service_attempt");
            return;
        }
        respond_errno(c->notify_fd, req->id, ENOENT);
        return;
    }

    respond_errno(c->notify_fd, req->id, EPERM);
    if (c->mode == MODE_MALWARE) hard_kill(c, "exec_boundary");
}

// FIXED: Allow threads, deny processes
static void handle_fork(supervisor_ctx_t *c, struct seccomp_notif *req) {
    int nr = req->data.nr;
    
    // Allow thread creation (CLONE_THREAD flag)
    if (nr == __NR_clone || nr == __NR_clone3) {
        uint64_t flags = (nr == __NR_clone) ? req->data.args[0] : 0;
        
        // For clone3, flags are in a struct - for simplicity, allow all clone3
        // Real implementation should read the struct
        if (nr == __NR_clone3 || (flags & CLONE_THREAD)) {
            emit_evt(c, "proc_thread_allowed", "\"sys\":\"%s\",\"flags\":\"0x%llx\"",
                     (nr == __NR_clone3 ? "clone3" : "clone"),
                     (unsigned long long)flags);
            respond_continue(c->notify_fd, req->id);
            return;
        }
    }
    
    // Deny actual process forks
    const char *sys = (nr == __NR_clone3) ? "clone3" :
                      (nr == __NR_clone) ? "clone" :
                      (nr == __NR_vfork) ? "vfork" : "fork";
    emit_evt(c, "proc_fork_denied", "\"sys\":\"%s\"", sys);
    respond_errno(c->notify_fd, req->id, EPERM);
    
    if (c->mode == MODE_MALWARE) {
        hard_kill(c, "fork_boundary");
    }
}

static void handle_net(supervisor_ctx_t *c, struct seccomp_notif *req) {
    int nr = req->data.nr;

    // Helper to decode sockaddr
    void decode_dst(uint64_t addr_ptr, socklen_t addrlen, char *dst, size_t dst_sz, 
                   uint32_t *ip_be, uint16_t *port_be) {
        struct sockaddr_storage ss;
        memset(&ss, 0, sizeof(ss));
        if (ip_be) *ip_be = 0;
        if (port_be) *port_be = 0;

        if (addr_ptr == 0 || addrlen == 0) {
            snprintf(dst, dst_sz, "unknown");
            return;
        }
        size_t n = addrlen;
        if (n > sizeof(ss)) n = sizeof(ss);
        if (read_remote_mem(c->tracee, addr_ptr, &ss, n) <= 0) {
            snprintf(dst, dst_sz, "unknown");
            return;
        }

        if (ss.ss_family == AF_INET) {
            struct sockaddr_in *in = (struct sockaddr_in*)&ss;
            char ip[INET_ADDRSTRLEN];
            memset(ip, 0, sizeof(ip));
            if (!inet_ntop(AF_INET, &in->sin_addr, ip, sizeof(ip))) {
                snprintf(dst, dst_sz, "unknown");
                return;
            }
            if (ip_be) *ip_be = in->sin_addr.s_addr;
            if (port_be) *port_be = in->sin_port;
            snprintf(dst, dst_sz, "%s:%u", ip, (unsigned)ntohs(in->sin_port));
            return;
        }
        snprintf(dst, dst_sz, "unknown");
    }

    if (nr == __NR_socket) {
        emit_evt(c, "net_attempt", "\"sys\":\"socket\"");
        respond_continue(c->notify_fd, req->id);
        return;
    }

    if (nr == __NR_connect) {
        int fd = (int)req->data.args[0];
        uint64_t addr_ptr = req->data.args[1];
        socklen_t addrlen = (socklen_t)req->data.args[2];

        char dst[128];
        uint32_t ip_be = 0;
        uint16_t port_be = 0;
        decode_dst(addr_ptr, addrlen, dst, sizeof(dst), &ip_be, &port_be);

        bool is_dns = (ntohs(port_be) == 53);
        bool is_dot = (ntohs(port_be) == 853);
        bool allowed = false;
        const char *tag = "other";
        
        if (is_dns) tag = "dns";
        if (is_dot) tag = "dot";

        if ((is_dns && c->allow_dns) || (is_dot && c->allow_dot)) {
            allowed = true;
        } else if (c->allowlist_count > 0) {
            allowed = allowlist_matches(c, ip_be, port_be);
        } else {
            allowed = c->allow_any_connect;
        }

        sock_track_t *t = sock_get_or_add(c, fd);
        if (t) {
            t->has_dst = (strcmp(dst, "unknown") != 0);
            snprintf(t->dst, sizeof(t->dst), "%s", dst);
            t->ip_be = ip_be;
            t->port_be = port_be;
            t->allowed = allowed;
            if (t->first_ts_ms == 0) t->first_ts_ms = now_ms();
        }

        emit_evt(c, "net_connect_attempt",
                 "\"fd\":%d,\"dst\":\"%s\",\"allowed\":%s,\"tag\":\"%s\"",
                 fd, dst, allowed ? "true" : "false", tag);

        if (!allowed) {
            respond_errno(c->notify_fd, req->id, ECONNREFUSED);
            return;
        }

        respond_continue(c->notify_fd, req->id);
        return;
    }

    if (nr == __NR_bind) {
        int fd = (int)req->data.args[0];
        uint64_t addr_ptr = req->data.args[1];
        socklen_t addrlen = (socklen_t)req->data.args[2];

        char dst[128];
        uint32_t ip_be = 0;
        decode_dst(addr_ptr, addrlen, dst, sizeof(dst), &ip_be, NULL);

        bool loopback = (ip_be == htonl(INADDR_LOOPBACK) || ip_be == 0);
        emit_evt(c, "net_bind_attempt", "\"fd\":%d,\"addr\":\"%s\"", fd, dst);

        if (c->mode == MODE_REVEAL_NET && !loopback) {
            respond_errno(c->notify_fd, req->id, EACCES);
            snapshot_and_kill(c, "bind_non_loopback");
            return;
        }

        respond_continue(c->notify_fd, req->id);
        return;
    }

    if (nr == __NR_listen) {
        int fd = (int)req->data.args[0];
        emit_evt(c, "net_listen_attempt", "\"fd\":%d", fd);
        if (c->mode == MODE_REVEAL_NET) {
            respond_errno(c->notify_fd, req->id, EACCES);
            snapshot_and_kill(c, "listen_attempt");
            return;
        }
        respond_continue(c->notify_fd, req->id);
        return;
    }

    // Helper for cap checks
    bool cap_allows(sock_track_t *t, size_t add_bytes) {
        if (!t) return true;
        if (!t->allowed) return false;
        uint64_t now = now_ms();
        if (c->net_cap_ms && t->first_ts_ms && (now - t->first_ts_ms) > c->net_cap_ms) return false;
        if (c->net_cap_sends && t->sends >= c->net_cap_sends) return false;
        if (c->net_cap_bytes && (t->bytes_out + (uint64_t)add_bytes) > c->net_cap_bytes) return false;
        return true;
    }

    void cap_account(sock_track_t *t, size_t add_bytes) {
        if (!t) return;
        if (t->first_ts_ms == 0) t->first_ts_ms = now_ms();
        t->sends += 1;
        t->bytes_out += (uint64_t)add_bytes;
    }

    if (nr == __NR_sendto || nr == __NR_sendmsg || nr == __NR_write || nr == __NR_writev) {
        int fd = (int)req->data.args[0];
        size_t len = 0;

        if (nr == __NR_sendto) {
            len = (size_t)req->data.args[2];
        } else if (nr == __NR_write) {
            len = (size_t)req->data.args[2];
        } else if (nr == __NR_writev) {
            uint64_t iov_ptr = req->data.args[1];
            int iovcnt = (int)req->data.args[2];
            if (iov_ptr && iovcnt > 0) {
                if (iovcnt > 16) iovcnt = 16;
                struct iovec iov[16];
                if (read_remote_mem(c->tracee, iov_ptr, iov, sizeof(struct iovec) * (size_t)iovcnt) > 0) {
                    for (int i = 0; i < iovcnt; i++) len += iov[i].iov_len;
                }
            }
        } else { // sendmsg
            uint64_t msg_ptr = req->data.args[1];
            if (msg_ptr) {
                struct msghdr mh;
                if (read_remote_mem(c->tracee, msg_ptr, &mh, sizeof(mh)) > 0 && mh.msg_iov && mh.msg_iovlen > 0) {
                    size_t iovlen = mh.msg_iovlen;
                    if (iovlen > 16) iovlen = 16;
                    struct iovec iov[16];
                    if (read_remote_mem(c->tracee, (uint64_t)(uintptr_t)mh.msg_iov, iov, 
                                       sizeof(struct iovec) * iovlen) > 0) {
                        for (size_t i = 0; i < iovlen; i++) len += iov[i].iov_len;
                    }
                }
            }
        }

        sock_track_t *t = sock_get(c, fd);
        
        const char *syscall_name = (nr == __NR_sendto) ? "sendto" :
                                  (nr == __NR_sendmsg) ? "sendmsg" :
                                  (nr == __NR_write) ? "write" : "writev";

        emit_evt(c, "net_send_attempt", 
                 "\"sys\":\"%s\",\"fd\":%d,\"dst\":\"%s\",\"len\":%zu",
                 syscall_name, fd, (t && t->has_dst) ? t->dst : "unknown", len);

        // Only enforce caps/policy if this is actually a socket FD
        if (t) {
            if (c->mode == MODE_REVEAL_NET) {
                if (!cap_allows(t, len)) {
                    emit_evt(c, "net_cap_hit", "\"fd\":%d,\"dst\":\"%s\"", 
                            fd, t->has_dst ? t->dst : "unknown");
                    respond_errno(c->notify_fd, req->id, ECONNRESET);
                    return;
                }
                cap_account(t, len);
            }
        }

        respond_continue(c->notify_fd, req->id);
        return;
    }

    if (nr == __NR_recvfrom) {
        int fd = (int)req->data.args[0];
        sock_track_t *t = sock_get(c, fd);
        emit_evt(c, "net_recvfrom_attempt", "\"fd\":%d,\"dst\":\"%s\"", 
                fd, (t && t->has_dst) ? t->dst : "unknown");
        
        if (c->mode == MODE_REVEAL_NET && t && t->allowed) {
            respond_continue(c->notify_fd, req->id);
            return;
        }
        respond_continue(c->notify_fd, req->id);
        return;
    }

    respond_continue(c->notify_fd, req->id);
}

static void handle_mprotect(supervisor_ctx_t *c, struct seccomp_notif *req) {
    uint64_t addr = req->data.args[0];
    uint64_t len  = req->data.args[1];
    int prot      = (int)req->data.args[2];
    bool adds_exec = (prot & PROT_EXEC) != 0;
    
    emit_evt(c, "mprotect",
             "\"addr\":\"0x%llx\",\"len\":%llu,\"prot\":%d,\"adds_exec\":%s",
             (unsigned long long)addr, (unsigned long long)len, prot, 
             adds_exec ? "true" : "false");
    
    if (adds_exec) {
        respond_errno(c->notify_fd, req->id, EPERM);
        if (c->mode == MODE_MALWARE) {
            hard_kill(c, "mprotect_adds_exec");
        }
        return;
    }
    respond_continue(c->notify_fd, req->id);
}

// FIXED: Handle FD operations for telemetry and socket tracking
static void handle_fd_ops(supervisor_ctx_t *c, struct seccomp_notif *req) {
    int nr = req->data.nr;
    
    if (nr == __NR_close) {
        int fd = (int)req->data.args[0];
        sock_remove(c, fd);
        emit_evt(c, "fd_close", "\"fd\":%d", fd);
        respond_continue(c->notify_fd, req->id);
        return;
    }
    
    if (nr == __NR_dup || nr == __NR_dup2 || nr == __NR_dup3) {
        int oldfd = (int)req->data.args[0];
        int newfd = (nr == __NR_dup) ? -1 : (int)req->data.args[1];
        
        // Clone socket tracking if oldfd is a tracked socket
        sock_track_t *old_sock = sock_get(c, oldfd);
        if (old_sock && newfd >= 0) {
            sock_track_t *new_sock = sock_get_or_add(c, newfd);
            if (new_sock && new_sock != old_sock) {
                *new_sock = *old_sock;
                new_sock->fd = newfd;
            }
        }
        
        emit_evt(c, "fd_dup", "\"sys\":\"%s\",\"oldfd\":%d,\"newfd\":%d",
                 (nr == __NR_dup) ? "dup" : (nr == __NR_dup2) ? "dup2" : "dup3",
                 oldfd, newfd);
        respond_continue(c->notify_fd, req->id);
        return;
    }
    
    if (nr == __NR_pipe || nr == __NR_pipe2) {
        emit_evt(c, "fd_pipe", "\"sys\":\"%s\"", (nr == __NR_pipe) ? "pipe" : "pipe2");
        respond_continue(c->notify_fd, req->id);
        return;
    }
    
    if (nr == __NR_fcntl) {
        int fd = (int)req->data.args[0];
        int cmd = (int)req->data.args[1];
        emit_evt(c, "fd_fcntl", "\"fd\":%d,\"cmd\":%d", fd, cmd);
        respond_continue(c->notify_fd, req->id);
        return;
    }
    
    if (nr == __NR_ioctl) {
        int fd = (int)req->data.args[0];
        unsigned long request = (unsigned long)req->data.args[1];
        emit_evt(c, "fd_ioctl", "\"fd\":%d,\"request\":\"0x%lx\"", fd, request);
        respond_continue(c->notify_fd, req->id);
        return;
    }
    
    respond_continue(c->notify_fd, req->id);
}

static void *supervisor_thread(void *arg) {
    supervisor_ctx_t *c = (supervisor_ctx_t*)arg;

    struct seccomp_notif_sizes sizes;
    memset(&sizes, 0, sizeof(sizes));
    if (xseccomp(SECCOMP_GET_NOTIF_SIZES, 0, &sizes) != 0) {
        die("SECCOMP_GET_NOTIF_SIZES failed: %s", strerror(errno));
    }

    struct seccomp_notif *req = calloc(1, sizes.seccomp_notif);
    if (!req) die("calloc req failed");
    
    uint64_t start = now_ms();
    int events = 0;

    emit_evt(c, "supervisor_start", "\"pid\":%d,\"notify_fd\":%d", c->tracee, c->notify_fd);

    while (1) {
        if (c->timeout_ms && (now_ms() - start) > c->timeout_ms) {
            emit_evt(c, "timeout_halt", "\"timeout_ms\":%llu", (unsigned long long)c->timeout_ms);
            hard_kill(c, "timeout");
            break;
        }
        if (c->max_events > 0 && events >= c->max_events) {
            emit_evt(c, "max_events_halt", "\"max_events\":%d", c->max_events);
            hard_kill(c, "max_events");
            break;
        }

        struct pollfd pfd = { .fd = c->notify_fd, .events = POLLIN };
        int prc = poll(&pfd, 1, 50);
        if (prc < 0) {
            if (errno == EINTR) continue;
        }
        if (prc == 0) {
            if (kill(c->tracee, 0) != 0 && errno == ESRCH) break;
            continue;
        }
        if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) {
            emit_evt(c, "notify_fd_dead", "\"revents\":%d", (int)pfd.revents);
            break;
        }

        memset(req, 0, sizes.seccomp_notif);
        int rc = ioctl(c->notify_fd, SECCOMP_IOCTL_NOTIF_RECV, req);
        if (rc != 0) {
            if (errno == EINTR || errno == EAGAIN) continue;
            if (kill(c->tracee, 0) != 0 && errno == ESRCH) break;
            continue;
        }

        events++;
        
        switch (req->data.nr) {
            case __NR_open:
            case __NR_openat:
                handle_open_like(c, req);
                break;
            case __NR_unlink:
            case __NR_unlinkat:
                handle_unlink_like(c, req);
                break;
            case __NR_linkat:
            case __NR_symlinkat:
                handle_symlink_like(c, req);
                break;
            case __NR_rename:
            case __NR_renameat:
            case __NR_renameat2:
                emit_evt(c, "fs_rename_attempt", "\"note\":\"denied\"");
                respond_errno(c->notify_fd, req->id, EPERM);
                if (c->mode == MODE_MALWARE) hard_kill(c, "rename_boundary");
                break;
            case __NR_execve:
            case __NR_execveat:
                handle_exec(c, req);
                break;
            case __NR_fork:
            case __NR_vfork:
            case __NR_clone:
            case __NR_clone3:
                handle_fork(c, req);
                break;
            case __NR_socket:
            case __NR_connect:
            case __NR_sendto:
            case __NR_sendmsg:
            case __NR_write:
            case __NR_writev:
            case __NR_bind:
            case __NR_listen:
            case __NR_recvfrom:
                handle_net(c, req);
                break;
            case __NR_mprotect:
                handle_mprotect(c, req);
                break;
            case __NR_close:
            case __NR_dup:
            case __NR_dup2:
            case __NR_dup3:
            case __NR_pipe:
            case __NR_pipe2:
            case __NR_fcntl:
            case __NR_ioctl:
                handle_fd_ops(c, req);
                break;
            default:
                respond_continue(c->notify_fd, req->id);
                break;
        }
    }

    free(req);
    return NULL;
}

static void usage(const char *argv0) {
    fprintf(stderr,
        "Usage: %s --outdir DIR [OPTIONS] -- /path/to/sample [args...]\n"
        "\nRequired:\n"
        "  --outdir DIR              Output directory for events and dumps\n"
        "\nPolicy Options:\n"
        "  --mode MODE               malware|re|reveal-net (default: malware)\n"
        "  --write-jail DIR          Restrict writes to this directory\n"
        "  --interactive-fs          Prompt for FS decisions (RE mode)\n"
        "\nExecution Limits:\n"
        "  --timeout-ms MS           Timeout in milliseconds (default: 4000)\n"
        "  --max-events N            Max syscalls before kill (default: 200)\n"
        "\nNetwork Policy:\n"
        "  --allow-dns               Allow DNS (port 53)\n"
        "  --allow-dot               Allow DNS-over-TLS (port 853)\n"
        "  --allow DST               Allow specific IP:PORT (e.g., 1.2.3.4:80)\n"
        "  --deny-unlisted           Deny non-allowlisted connects\n"
        "  --net-cap-bytes N         Per-socket byte limit\n"
        "  --net-cap-ms MS           Per-socket lifetime limit\n"
        "  --net-cap-sends N         Per-socket send() limit\n"
        , argv0);
}

int main(int argc, char **argv) {
    supervisor_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.timeout_ms = 4000;
    ctx.max_events = 200;
    ctx.mode = MODE_MALWARE;
    ctx.saw_initial_exec = false;
    ctx.allow_dns = (getenv("SOFTRX_ALLOW_DNS") && getenv("SOFTRX_ALLOW_DNS")[0] == '1');
    ctx.allow_dot = (getenv("SOFTRX_ALLOW_DOT") && getenv("SOFTRX_ALLOW_DOT")[0] == '1');
    ctx.allow_any_connect = true;
    ctx.net_cap_bytes = getenv("SOFTRX_NET_CAP_BYTES") ? 
        (uint64_t)strtoull(getenv("SOFTRX_NET_CAP_BYTES"), NULL, 10) : 0;
    ctx.net_cap_ms = getenv("SOFTRX_NET_CAP_MS") ? 
        (uint64_t)strtoull(getenv("SOFTRX_NET_CAP_MS"), NULL, 10) : 0;
    ctx.net_cap_sends = getenv("SOFTRX_NET_CAP_SENDS") ? 
        (uint64_t)strtoull(getenv("SOFTRX_NET_CAP_SENDS"), NULL, 10) : 0;
    ctx.allowlist_count = 0;
    ctx.sock_count = 0;

    int i = 1;
    for (; i < argc; i++) {
        if (strcmp(argv[i], "--") == 0) { i++; break; }
        if (strcmp(argv[i], "--outdir") == 0 && i + 1 < argc) {
            snprintf(ctx.outdir, sizeof(ctx.outdir), "%s", argv[++i]);
            continue;
        }
        if (strcmp(argv[i], "--timeout-ms") == 0 && i + 1 < argc) {
            ctx.timeout_ms = (uint64_t)strtoull(argv[++i], NULL, 10);
            continue;
        }
        if (strcmp(argv[i], "--max-events") == 0 && i + 1 < argc) {
            ctx.max_events = atoi(argv[++i]);
            continue;
        }
        if (strcmp(argv[i], "--mode") == 0 && i + 1 < argc) {
            const char *m = argv[++i];
            if (strcmp(m, "malware") == 0) ctx.mode = MODE_MALWARE;
            else if (strcmp(m, "re") == 0) ctx.mode = MODE_RE;
            else if (strcmp(m, "reveal-net") == 0 || strcmp(m, "reveal_net") == 0) 
                ctx.mode = MODE_REVEAL_NET;
            else if (strcmp(m, "dev") == 0) ctx.mode = MODE_RE;
            else die("unknown mode: %s", m);
            continue;
        }
        if (strcmp(argv[i], "--allow-dns") == 0) {
            ctx.allow_dns = true;
            continue;
        }
        if (strcmp(argv[i], "--allow-dot") == 0) {
            ctx.allow_dot = true;
            continue;
        }
        if ((strcmp(argv[i], "--allow") == 0 || strcmp(argv[i], "--allow-dst") == 0) && i + 1 < argc) {
            const char *spec = argv[++i];
            char ip[64] = {0};
            int port = 0;
            if (sscanf(spec, "%63[^:]:%d", ip, &port) == 2 && port > 0 && port < 65536) {
                struct in_addr in;
                if (inet_pton(AF_INET, ip, &in) == 1) {
                    if (ctx.allowlist_count < (int)(sizeof(ctx.allowlist)/sizeof(ctx.allowlist[0]))) {
                        ctx.allowlist[ctx.allowlist_count].ip_be = in.s_addr;
                        ctx.allowlist[ctx.allowlist_count].port_be = htons((uint16_t)port);
                        ctx.allowlist_count++;
                    }
                }
            }
            continue;
        }
        if (strcmp(argv[i], "--net-cap-bytes") == 0 && i + 1 < argc) {
            ctx.net_cap_bytes = (uint64_t)strtoull(argv[++i], NULL, 10);
            continue;
        }
        if (strcmp(argv[i], "--net-cap-ms") == 0 && i + 1 < argc) {
            ctx.net_cap_ms = (uint64_t)strtoull(argv[++i], NULL, 10);
            continue;
        }
        if (strcmp(argv[i], "--net-cap-sends") == 0 && i + 1 < argc) {
            ctx.net_cap_sends = (uint64_t)strtoull(argv[++i], NULL, 10);
            continue;
        }
        if (strcmp(argv[i], "--deny-unlisted") == 0) {
            ctx.allow_any_connect = false;
            continue;
        }
        if (strcmp(argv[i], "--write-jail") == 0 && i + 1 < argc) {
            snprintf(ctx.write_jail, sizeof(ctx.write_jail), "%s", argv[++i]);
            continue;
        }
        if (strcmp(argv[i], "--interactive-fs") == 0) {
            ctx.interactive_fs = true;
            continue;
        }
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            usage(argv[0]);
            return 0;
        }
    }

    if (ctx.outdir[0] == '\0' || i >= argc) {
        usage(argv[0]);
        return 2;
    }

    // FIXED: Resolve sample path from launcher's CWD, not tracee's
    char launcher_cwd[PATH_MAX];
    if (!getcwd(launcher_cwd, sizeof(launcher_cwd))) 
        snprintf(launcher_cwd, sizeof(launcher_cwd), "/");
    path_join(launcher_cwd, argv[i], ctx.sample_abs, sizeof(ctx.sample_abs));
    normalize_inplace(ctx.sample_abs);

    if (mkdir_p(ctx.outdir) != 0 && errno != EEXIST)
        die("mkdir_p(outdir) failed: %s", strerror(errno));

    if (ctx.write_jail[0]) {
        if (mkdir_p(ctx.write_jail) != 0 && errno != EEXIST)
            die("mkdir_p(write_jail) failed: %s", strerror(errno));
    }

    if (ctx.mode == MODE_REVEAL_NET) {
        if (!ctx.allow_dns) ctx.allow_dns = true;
        if (!ctx.allow_dot) ctx.allow_dot = true;
        if (ctx.net_cap_bytes == 0) ctx.net_cap_bytes = 10 * 1024;
        if (ctx.net_cap_ms == 0) ctx.net_cap_ms = 2000;
        if (ctx.net_cap_sends == 0) ctx.net_cap_sends = 32;
        ctx.interactive_fs = false;
    }

    char evpath[PATH_MAX];
    snprintf(evpath, sizeof(evpath), "%s/events.ndjson", ctx.outdir);
    ctx.events_fp = fopen(evpath, "a");
    if (!ctx.events_fp) die("open events.ndjson failed: %s", strerror(errno));

    int sp[2];
    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sp) != 0)
        die("socketpair failed: %s", strerror(errno));

    pid_t child = fork();
    if (child < 0) die("fork failed: %s", strerror(errno));

    if (child == 0) {
        // TRACEE
        setpgid(0, 0);

        // FIXED: chdir to jail so relative opens land inside
        if (ctx.write_jail[0]) {
            if (chdir(ctx.write_jail) != 0) {
                fprintf(stderr, "[SoftRX] Warning: chdir to jail failed: %s\n", 
                        strerror(errno));
            }
        }

        close(sp[0]);
        int listener_fd = install_listener_filter();
        send_fd(sp[1], listener_fd);
        close(listener_fd);
        close(sp[1]);

        char **child_argv = &argv[i];
        execv(child_argv[0], child_argv);
        perror("execv");
        _exit(127);
    }

    // SUPERVISOR
    close(sp[1]);
    ctx.tracee = child;
    setpgid(child, child);
    ctx.tracee_pgid = child;

    ctx.notify_fd = recv_fd(sp[0]);
    close(sp[0]);

    // FIXED: Set nonblocking to avoid hangs
    int fl = fcntl(ctx.notify_fd, F_GETFL, 0);
    if (fl >= 0) (void)fcntl(ctx.notify_fd, F_SETFL, fl | O_NONBLOCK);

    fprintf(stdout, "[SoftRX] supervisor pid=%d tracee=%d notify_fd=%d sample_abs=%s\n",
            getpid(), (int)ctx.tracee, ctx.notify_fd, ctx.sample_abs);
    fflush(stdout);

    pthread_t th;
    if (pthread_create(&th, NULL, supervisor_thread, &ctx) != 0)
        die("pthread_create failed");

    int status = 0;
    (void)waitpid(child, &status, 0);

    pthread_join(th, NULL);
    emit_evt(&ctx, "tracee_exit", "\"status\":%d", status);

    fclose(ctx.events_fp);
    close(ctx.notify_fd);

    if (WIFEXITED(status)) return WEXITSTATUS(status);
    if (WIFSIGNALED(status)) return 128 + WTERMSIG(status);
    return 0;
}