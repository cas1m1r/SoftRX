// softrx_launcher.c (seccomp USER_NOTIF via raw BPF + NEW_LISTENER)
// Drop-in replacement designed to work on Kali even when libseccomp notify helpers vary.
//
// Build:
//   cc -O2 -Wall -Wextra -o bin/softrx_launcher core/softrx_launcher.c -lpthread
//
// Requires Linux kernel with SECCOMP_USER_NOTIF (5.0+ recommended).

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>      // offsetof
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/socket.h>  // msghdr/cmsghdr, CMSG_*, SCM_RIGHTS, SOL_SOCKET, socketpair
#include <sys/uio.h>
#include <sys/ioctl.h>
#include <sys/mman.h>    // PROT_EXEC
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

static const char *SOFTRX_BUILD_TAG = "devtrace-2026-01-02";
#include <dirent.h>

#ifndef SECCOMP_FILTER_FLAG_NEW_LISTENER
#define SECCOMP_FILTER_FLAG_NEW_LISTENER (1UL << 3)
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

static void read_remote_cstr(pid_t pid, uint64_t remote_ptr, char *out, size_t out_sz) {
    if (out_sz == 0) return;
    out[0] = '\0';
    if (remote_ptr == 0) return;
    size_t off = 0;
    while (off + 1 < out_sz) {
        char buf[64];
        size_t want = sizeof(buf);
        if (off + want >= out_sz) want = out_sz - off - 1;
        ssize_t got = read_remote(pid, buf, (void*)(uintptr_t)(remote_ptr + off), want);
        if (got <= 0) break;
        for (ssize_t i = 0; i < got; i++) {
            out[off++] = buf[i];
            if (buf[i] == '\0') { out[out_sz-1] = '\0'; return; }
            if (off + 1 >= out_sz) break;
        }
        if (off + 1 >= out_sz) break;
    }
    out[out_sz-1] = '\0';
}


// Convenience helper for reading raw memory from the tracee.
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

static int recv_fd_timed(int sock, pid_t child, int timeout_ms) {
    // Wait for an FD via SCM_RIGHTS, but don't hang forever if the child dies
    // before sending it.
    int elapsed = 0;
    while (elapsed < timeout_ms) {
        // If child already exited, abort immediately.
        int st = 0;
        pid_t w = waitpid(child, &st, WNOHANG);
        if (w == child) {
            fprintf(stderr, "[SoftRX] child exited before sending listener fd (status=%d)\n", st);
            errno = ECHILD;
            return -1;
        }

        struct pollfd pfd = {0};
        pfd.fd = sock;
        pfd.events = POLLIN;
        int prc = poll(&pfd, 1, 100);
        if (prc < 0) {
            if (errno == EINTR) continue;
            fprintf(stderr, "[SoftRX] poll(sockpair) failed: %s\n", strerror(errno));
            return -1;
        }
        elapsed += 100;
        if (prc == 0) continue;

        if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) {
            fprintf(stderr, "[SoftRX] sockpair error while waiting for listener fd (revents=%d)\n", (int)pfd.revents);
            return -1;
        }

        // recvmsg the fd
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

        ssize_t r = recvmsg(sock, &msg, 0);
        if (r < 0) {
            if (errno == EINTR) continue;
            fprintf(stderr, "[SoftRX] recvmsg failed: %s\n", strerror(errno));
            return -1;
        }

        struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
        if (!cmsg || cmsg->cmsg_len != CMSG_LEN(sizeof(int))) {
            fprintf(stderr, "[SoftRX] recvmsg missing SCM_RIGHTS control message\n");
            return -1;
        }
        if (cmsg->cmsg_level != SOL_SOCKET || cmsg->cmsg_type != SCM_RIGHTS) {
            fprintf(stderr, "[SoftRX] recvmsg unexpected control message\n");
            return -1;
        }

        int fd;
        memcpy(&fd, CMSG_DATA(cmsg), sizeof(int));
        return fd;
    }

    fprintf(stderr, "[SoftRX] timed out waiting for listener fd from child\n");
    errno = ETIMEDOUT;
    return -1;
}

static void path_join(const char *cwd, const char *p, char *out, size_t out_sz) {
    if (!p || !p[0]) { snprintf(out, out_sz, "%s", cwd); return; }
    if (p[0] == '/') { snprintf(out, out_sz, "%s", p); return; }
    snprintf(out, out_sz, "%s/%s", cwd, p);
}

static void normalize_inplace(char *p) {
    // In-place normalization: collapse '//' and '/./' and handle '..' path segments lexically.
    // (Does not resolve symlinks.)
    if (!p || !*p) return;

    // Collapse repeated slashes and convert backslashes.
    {
        char *w = p;
        bool prev_slash = false;
        for (char *r = p; *r; r++) {
            char ch = *r;
            if (ch == '\\') ch = '/';
            if (ch == '/') {
                if (prev_slash) continue;
                prev_slash = true;
            } else {
                prev_slash = false;
            }
            *w++ = ch;
        }
        *w = '\0';
    }

    char tmp[4096];
    strncpy(tmp, p, sizeof(tmp)-1);
    tmp[sizeof(tmp)-1] = '\0';
    const bool is_abs = (tmp[0] == '/');

    const char *segs[1024];
    int top = 0;

    char *save = NULL;
    for (char *tok = strtok_r(tmp, "/", &save); tok; tok = strtok_r(NULL, "/", &save)) {
        if (tok[0] == '\0' || strcmp(tok, ".") == 0) continue;
        if (strcmp(tok, "..") == 0) {
            if (top > 0 && strcmp(segs[top-1], "..") != 0) {
                top--;
            } else if (!is_abs) {
                segs[top++] = tok;
            }
            continue;
        }
        segs[top++] = tok;
    }

    char *w = p;
    if (is_abs) *w++ = '/';
    for (int i = 0; i < top; i++) {
        size_t n = strlen(segs[i]);
        if ((w - p) + (int)n + 2 >= (int)sizeof(tmp)) break;
        memcpy(w, segs[i], n);
        w += n;
        if (i != top - 1) *w++ = '/';
    }
    *w = '\0';

    size_t n = strlen(p);
    if (n > 1 && p[n-1] == '/') p[n-1] = '\0';
}

typedef enum { MODE_MALWARE=0, MODE_RE=1, MODE_REVEAL_NET=2, MODE_DEV=3 } run_mode_t;

typedef struct sock_track_t {
    int fd;
    bool has_dst;
    char dst[128];            // "A.B.C.D:PORT" best-effort
    uint32_t ip_be;
    uint16_t port_be;
    bool allowed;
    uint64_t first_ts_ms;
    uint64_t bytes_out;
    uint64_t sends;
} sock_track_t;




// -------- quarantine tracking (simple linked list) --------
typedef struct taint_node_t {
    char *path;                 // absolute, normalized
    struct taint_node_t *next;
} taint_node_t;

typedef struct {
    pid_t tracee;
    pid_t tracee_pgid;
    pid_t cur_pid;
    uint64_t evt_idx;
    // Cached process identity (derived from /proc/<tid>/status)
    pid_t cache_tid;
    pid_t cache_pid;   // tgid
    pid_t cache_ppid;
    char  cache_comm[64];
    int notify_fd;
    char outdir[4096];
    char write_jail[4096];
    bool interactive_fs;
    run_mode_t mode;
    uint64_t timeout_ms;
    int max_events;
    FILE *events_fp;
    char tracee_cwd[4096];

    // Exec boundary tracking
    bool saw_initial_exec;
    char sample_abs[4096];

    // Network policy
    bool allow_dns;              // allow DNS (port 53)
    bool allow_dot;              // allow DNS-over-TLS (port 853)
    bool allow_any_connect;       // if true and allowlist is empty, allow connect() to any dst
    uint64_t net_cap_bytes;       // per-socket outbound byte cap (0 = unlimited)
    uint64_t net_cap_ms;          // per-socket lifetime cap in ms (0 = unlimited)
    uint64_t net_cap_sends;       // per-socket send syscall cap (0 = unlimited)

    // Exact allowlist for connect destinations (IP:PORT). If non-empty, only these (plus DNS/DoT) are allowed.
    struct { uint32_t ip_be; uint16_t port_be; } allowlist[128];
    int allowlist_count;

    // Socket FD tracking (best-effort; no forks in reveal-net mode, so PID is stable)
    struct sock_track_t socks[512];
    int sock_count;

    // Quarantine: prevent executing newly written (dropped) files while still tracing.
    bool quarantine_drops;
    taint_node_t *tainted_paths;
} supervisor_ctx_t;

static bool taint_has(const supervisor_ctx_t *c, const char *abs_path) {
    for (taint_node_t *n = c->tainted_paths; n; n = n->next) {
        if (n->path && strcmp(n->path, abs_path) == 0) return true;
    }
    return false;
}

static void taint_add(supervisor_ctx_t *c, const char *abs_path) {
    if (!abs_path || !*abs_path) return;
    if (taint_has(c, abs_path)) return;
    taint_node_t *n = (taint_node_t *)calloc(1, sizeof(*n));
    if (!n) return;
    n->path = strdup(abs_path);
    n->next = c->tainted_paths;
    c->tainted_paths = n;
}

static void taint_rename(supervisor_ctx_t *c, const char *old_abs, const char *new_abs) {
    if (!old_abs || !new_abs) return;
    if (!taint_has(c, old_abs)) return;
    taint_add(c, new_abs);
}




static bool allowlist_matches(supervisor_ctx_t *c, uint32_t ip_be, uint16_t port_be) {
    for (int i = 0; i < c->allowlist_count; i++) {
        if (c->allowlist[i].ip_be == ip_be && c->allowlist[i].port_be == port_be) return true;
    }
    return false;
}

static sock_track_t *sock_get(supervisor_ctx_t *c, int fd) {
    for (int i = 0; i < c->sock_count; i++) {
        if (c->socks[i].fd == fd) return &c->socks[i];
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
    return t;
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
    for (int i = 0; i < c->sock_count; i++) {
        sock_track_t *t = &c->socks[i];
        fprintf(fp,
            "  {\"fd\":%d,\"dst\":\"%s\",\"allowed\":%s,\"bytes_out\":%llu,\"sends\":%llu}%s\n",
            t->fd,
            t->has_dst ? t->dst : "unknown",
            t->allowed ? "true" : "false",
            (unsigned long long)t->bytes_out,
            (unsigned long long)t->sends,
            (i + 1 < c->sock_count) ? "," : ""
        );
    }
    fprintf(fp, "]\n");
    fclose(fp);
}

static void snapshot_and_kill(supervisor_ctx_t *c, const char *why);

static void json_escape(FILE *fp, const char *s) {
    if (!s) return;
    for (const unsigned char *p = (const unsigned char*)s; *p; ++p) {
        unsigned char ch = *p;
        switch (ch) {
            case '\\': fputs("\\\\", fp); break;
            case '"':  fputs("\\\"", fp); break;
            case '\n': fputs("\\n", fp); break;
            case '\r': fputs("\\r", fp); break;
            case '\t': fputs("\\t", fp); break;
            default:
                if (ch < 0x20) fprintf(fp, "\\u%04x", ch);
                else fputc(ch, fp);
        }
    }
}

static void cache_proc_identity(supervisor_ctx_t *c, pid_t tid) {
    if (tid <= 0) return;
    if (c->cache_tid == tid && c->cache_comm[0] != '\0') return;

    c->cache_tid = tid;
    c->cache_pid = tid;     // fallback if /proc parsing fails
    c->cache_ppid = -1;
    c->cache_comm[0] = '\0';

    char path[128];
    snprintf(path, sizeof(path), "/proc/%d/status", tid);
    FILE *fp = fopen(path, "r");
    if (!fp) return;

    char line[256];
    while (fgets(line, sizeof(line), fp)) {
        if (strncmp(line, "Name:", 5) == 0) {
            char name[64] = {0};
            if (sscanf(line + 5, "%63s", name) == 1) {
                strncpy(c->cache_comm, name, sizeof(c->cache_comm) - 1);
                c->cache_comm[sizeof(c->cache_comm) - 1] = '\0';
            }
        } else if (strncmp(line, "Tgid:", 5) == 0) {
            int tgid = 0;
            if (sscanf(line + 5, "%d", &tgid) == 1 && tgid > 0) c->cache_pid = (pid_t)tgid;
        } else if (strncmp(line, "PPid:", 5) == 0) {
            int ppid = 0;
            if (sscanf(line + 5, "%d", &ppid) == 1) c->cache_ppid = (pid_t)ppid;
        }
    }
    fclose(fp);
}

static void emit_evt(supervisor_ctx_t *c, const char *event, const char *fmt, ...) {
    uint64_t ts = now_ms();
    uint64_t idx = c->evt_idx++;

    // seccomp USER_NOTIF supplies a tid (req->pid). We store it in c->cur_pid.
    pid_t tid = c->cur_pid > 0 ? c->cur_pid : getpid();
    cache_proc_identity(c, tid);

    // Canonical identity: pid = TGID (process id), tid = thread id.
    fprintf(c->events_fp,
            "{\"ts_ms\":%llu,\"idx\":%llu,\"event\":\"%s\",\"pid\":%d,\"tid\":%d",
            (unsigned long long)ts,
            (unsigned long long)idx,
            event,
            (int)c->cache_pid,
            (int)tid);

    if (c->cache_ppid > 0) {
        fprintf(c->events_fp, ",\"ppid\":%d", (int)c->cache_ppid);
    }
    if (c->cache_comm[0]) {
        fprintf(c->events_fp, ",\"comm\":\"");
        json_escape(c->events_fp, c->cache_comm);
        fprintf(c->events_fp, "\"");
    }

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
    // Try to kill the whole process group (defense-in-depth against fork/spawn).
    if (c->tracee_pgid > 0) {
        kill(-c->tracee_pgid, SIGKILL);
    } else if (c->tracee > 0) {
        kill(c->tracee, SIGKILL);
    }
}

static void snapshot_and_kill(supervisor_ctx_t *c, const char *why) {
    emit_evt(c, "snapshot", "\"why\":\"%s\"", why);

    mkdir_p(c->outdir);

    char p1[4096];
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

// static bool is_write_flags(int flags) {
    // return (flags & (O_WRONLY|O_RDWR|O_CREAT|O_TRUNC|O_APPEND)) != 0;
// }

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

static int install_listener_filter(void) {
    struct sock_filter filter[] = {
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS, offsetof(struct seccomp_data, arch)),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, AUDIT_ARCH_X86_64, 1, 0),
        BPF_STMT(BPF_RET|BPF_K, SC_KILL),

        LOAD_SYSCALL_NR,

        JEQ_SYSCALL(__NR_mprotect, 0, 1), BPF_STMT(BPF_RET|BPF_K, SC_NOTIFY),

        JEQ_SYSCALL(__NR_openat, 0, 1),  BPF_STMT(BPF_RET|BPF_K, SC_NOTIFY),
        JEQ_SYSCALL(__NR_open, 0, 1),    BPF_STMT(BPF_RET|BPF_K, SC_NOTIFY),

        JEQ_SYSCALL(__NR_unlinkat, 0, 1),BPF_STMT(BPF_RET|BPF_K, SC_NOTIFY),
        JEQ_SYSCALL(__NR_unlink, 0, 1),  BPF_STMT(BPF_RET|BPF_K, SC_NOTIFY),

        JEQ_SYSCALL(__NR_renameat,0, 1), BPF_STMT(BPF_RET|BPF_K, SC_NOTIFY),
        JEQ_SYSCALL(__NR_rename, 0, 1),  BPF_STMT(BPF_RET|BPF_K, SC_NOTIFY),

        JEQ_SYSCALL(__NR_execve, 0, 1),  BPF_STMT(BPF_RET|BPF_K, SC_NOTIFY),
        JEQ_SYSCALL(__NR_execveat,0, 1), BPF_STMT(BPF_RET|BPF_K, SC_NOTIFY),

        JEQ_SYSCALL(__NR_fork, 0, 1),    BPF_STMT(BPF_RET|BPF_K, SC_NOTIFY),
        JEQ_SYSCALL(__NR_vfork,0, 1),    BPF_STMT(BPF_RET|BPF_K, SC_NOTIFY),
        JEQ_SYSCALL(__NR_clone,0, 1),    BPF_STMT(BPF_RET|BPF_K, SC_NOTIFY),
        JEQ_SYSCALL(__NR_clone3,0, 1),   BPF_STMT(BPF_RET|BPF_K, SC_NOTIFY),

        JEQ_SYSCALL(__NR_socket,0, 1),   BPF_STMT(BPF_RET|BPF_K, SC_NOTIFY),
        JEQ_SYSCALL(__NR_connect,0, 1),  BPF_STMT(BPF_RET|BPF_K, SC_NOTIFY),
        JEQ_SYSCALL(__NR_sendto,0, 1),   BPF_STMT(BPF_RET|BPF_K, SC_NOTIFY),
        JEQ_SYSCALL(__NR_sendmsg,0, 1),  BPF_STMT(BPF_RET|BPF_K, SC_ALLOW),  // bootstrap must be able to send listener fd
        JEQ_SYSCALL(__NR_recvmsg,0, 1),  BPF_STMT(BPF_RET|BPF_K, SC_NOTIFY),
        JEQ_SYSCALL(__NR_read,0, 1),     BPF_STMT(BPF_RET|BPF_K, SC_NOTIFY),
        JEQ_SYSCALL(__NR_readv,0, 1),    BPF_STMT(BPF_RET|BPF_K, SC_NOTIFY),
        JEQ_SYSCALL(__NR_ioctl,0, 1),    BPF_STMT(BPF_RET|BPF_K, SC_NOTIFY),
        JEQ_SYSCALL(__NR_fcntl,0, 1),    BPF_STMT(BPF_RET|BPF_K, SC_NOTIFY),
        JEQ_SYSCALL(__NR_dup,0, 1),      BPF_STMT(BPF_RET|BPF_K, SC_NOTIFY),
        JEQ_SYSCALL(__NR_dup2,0, 1),     BPF_STMT(BPF_RET|BPF_K, SC_NOTIFY),
        JEQ_SYSCALL(__NR_dup3,0, 1),     BPF_STMT(BPF_RET|BPF_K, SC_NOTIFY),
        JEQ_SYSCALL(__NR_close,0, 1),    BPF_STMT(BPF_RET|BPF_K, SC_NOTIFY),
        JEQ_SYSCALL(__NR_poll,0, 1),     BPF_STMT(BPF_RET|BPF_K, SC_NOTIFY),
        JEQ_SYSCALL(__NR_ppoll,0, 1),    BPF_STMT(BPF_RET|BPF_K, SC_NOTIFY),
        JEQ_SYSCALL(__NR_write,0, 1),    BPF_STMT(BPF_RET|BPF_K, SC_ALLOW),
        JEQ_SYSCALL(__NR_writev,0, 1),   BPF_STMT(BPF_RET|BPF_K, SC_ALLOW),
        JEQ_SYSCALL(__NR_bind,0, 1),     BPF_STMT(BPF_RET|BPF_K, SC_NOTIFY),
        JEQ_SYSCALL(__NR_listen,0, 1),   BPF_STMT(BPF_RET|BPF_K, SC_NOTIFY),
        JEQ_SYSCALL(__NR_recvfrom,0, 1), BPF_STMT(BPF_RET|BPF_K, SC_NOTIFY),

        BPF_STMT(BPF_RET|BPF_K, SC_ALLOW),
    };

    struct sock_fprog prog = {
        .len = (unsigned short)(sizeof(filter)/sizeof(filter[0])),
        .filter = filter,
    };

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) die("PR_SET_NO_NEW_PRIVS failed: %s", strerror(errno));

    int fd = (int)xseccomp(SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_NEW_LISTENER, &prog);
    if (fd < 0) die("seccomp(NEW_LISTENER) failed: %s", strerror(errno));
    return fd;
}

static void respond_errno(int notify_fd, uint64_t id, int err) {
    struct seccomp_notif_resp resp;
    memset(&resp, 0, sizeof(resp));
    resp.id = id;
    resp.error = -err;
    resp.val = 0;
    resp.flags = 0;
    if (ioctl(notify_fd, SECCOMP_IOCTL_NOTIF_SEND, &resp) != 0) {
        fprintf(stderr, "[SoftRX] NOTIF_SEND failed: %s\n", strerror(errno));
    }
}

static void respond_continue(int notify_fd, uint64_t id) {
    struct seccomp_notif_resp resp;
    memset(&resp, 0, sizeof(resp));
    resp.id = id;
    resp.flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;
    if (ioctl(notify_fd, SECCOMP_IOCTL_NOTIF_SEND, &resp) != 0) {
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
    char p[4096];
    snprintf(p, sizeof(p), "%s", abs_path);
    normalize_inplace(p);

    char jail[4096];
    snprintf(jail, sizeof(jail), "%s", c->write_jail);
    normalize_inplace(jail);

    size_t jl = strlen(jail);
    if (jl == 0) return false;

    char jailp[4096];
    snprintf(jailp, sizeof(jailp), "%s", jail);
    if (jailp[jl-1] != '/') { jailp[jl] = '/'; jailp[jl+1] = '\0'; jl++; }

    return strncmp(p, jailp, jl) == 0;
}

static bool is_write_flags(int flags) {
    // Covers most libc write opens: O_WRONLY, O_RDWR, O_CREAT, O_TRUNC, O_APPEND
    return (flags & (O_WRONLY | O_RDWR | O_CREAT | O_TRUNC | O_APPEND)) != 0;
}

static void handle_open_like(supervisor_ctx_t *c, struct seccomp_notif *req) {
    int nr = req->data.nr;

    uint64_t pathptr = 0;
    int flags = 0;

    if (nr == __NR_open) {
        pathptr = req->data.args[0];
        flags   = (int)req->data.args[1];
    } else { // __NR_openat
        pathptr = req->data.args[1];
        flags   = (int)req->data.args[2];
    }

    char path[1024] = {0};
    char abs[4096]  = {0};

    read_remote_cstr(c->tracee, pathptr, path, sizeof(path));

    // Resolve relative paths against tracee cwd (which you already cache each loop)
    if (path[0] == '/') {
        snprintf(abs, sizeof(abs), "%s", path);
    } else {
        path_join(c->tracee_cwd[0] ? c->tracee_cwd : "/", path, abs, sizeof(abs));
    }
    normalize_inplace(abs);

    // Determine jail membership
    bool in_jail = false;
    if (c->write_jail[0]) {
        // prefix match: abs starts with write_jail + "/" OR equals write_jail
        size_t jl = strlen(c->write_jail);
        if (strncmp(abs, c->write_jail, jl) == 0 &&
            (abs[jl] == '\0' || abs[jl] == '/')) {
            in_jail = true;
        }
    }

    // Log what happened
    emit_evt(c, "fs_open_attempt",
             "\"sys\":\"%s\",\"path\":\"%s\",\"abs\":\"%s\",\"flags\":%d,\"in_jail\":%s",
             (nr == __NR_open ? "open" : "openat"),
             path, abs, flags, in_jail ? "true" : "false");

    // Policy: allow reads anywhere, but writes only inside jail (unless you choose otherwise)
    bool wants_write = is_write_flags(flags);

    if (!wants_write) {
        respond_continue(c->notify_fd, req->id);
        return;
    }

    // DEV: trace everything, allow writes anywhere (still logged above)
    if (c->mode == MODE_DEV) {
        // Dev mode: allow all file opens so we can observe behavior,
        // but optionally mark "dropped" artifacts for exec quarantine.
        emit_evt(c, "fs_open_write_allowed_dev", "\"abs\":\"%s\",\"flags\":%d,\"in_jail\":%s", abs, flags, in_jail ? "true":"false");
        if (c->quarantine_drops && in_jail && wants_write) {
            taint_add(c, abs);
            emit_evt(c, "drop_mark", "\"abs\":\"%s\",\"why\":\"write_open\"", abs);
        }
        respond_continue(c->notify_fd, req->id);
        return;
    }

    // reveal-net: never allow writes (log intent, return EACCES), with persistence tripwires.
    if (c->mode == MODE_REVEAL_NET) {
        // Tripwire: obvious persistence surfaces
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

    // Other modes: allow writes inside jail, deny outside.
    if (in_jail) {
        respond_continue(c->notify_fd, req->id);
        return;
    }

    // write outside jail
    emit_evt(c, "fs_open_denied",
             "\"reason\":\"write_outside_jail\",\"abs\":\"%s\"", abs);

    if (c->mode == MODE_MALWARE) {
        respond_errno(c->notify_fd, req->id, EPERM);
        hard_kill(c, "write_outside_jail");
        return;
    }

    // Dev/RE: allow but log (lets probes write to their own workspace while still signaling escape).
    respond_continue(c->notify_fd, req->id);
}




static void handle_renameat(supervisor_ctx_t *c, struct seccomp_notif *req) {
    char oldp[PATH_MAX], newp[PATH_MAX];
    char oldabs[PATH_MAX], newabs[PATH_MAX];

    read_remote_cstr(c->tracee, req->data.args[1], oldp, sizeof(oldp));
    if (oldp[0] == '\0') {
        emit_evt(c, "rename_read_fail", "\"which\":\"old\"");
        respond_errno(c->notify_fd, req->id, EFAULT);
        return;
    }
    read_remote_cstr(c->tracee, req->data.args[3], newp, sizeof(newp));
    if (newp[0] == '\0') {
        emit_evt(c, "rename_read_fail", "\"which\":\"new\"");
        respond_errno(c->notify_fd, req->id, EFAULT);
        return;
    }

    path_join(c->tracee_cwd[0] ? c->tracee_cwd : "/", oldp, oldabs, sizeof(oldabs));
    path_join(c->tracee_cwd[0] ? c->tracee_cwd : "/", newp, newabs, sizeof(newabs));
    normalize_inplace(oldabs);
    normalize_inplace(newabs);

    bool old_in = within_jail(c, oldabs);
    bool new_in = within_jail(c, newabs);
    emit_evt(c, "fs_rename_attempt", "\"old\":\"%s\",\"new\":\"%s\",\"old_in_jail\":%s,\"new_in_jail\":%s",
             oldabs, newabs, old_in ? "true":"false", new_in ? "true":"false");

    if (c->mode == MODE_DEV) {
        if (c->quarantine_drops) {
            taint_rename(c, oldabs, newabs);
        }
        respond_continue(c->notify_fd, req->id);
        return;
    }

    // Keep strict defaults outside dev mode.
    emit_evt(c, "fs_rename_denied", "\"reason\":\"policy\",\"old\":\"%s\",\"new\":\"%s\"", oldabs, newabs);
    respond_errno(c->notify_fd, req->id, EPERM);
}

static void handle_unlink_like(supervisor_ctx_t *c, struct seccomp_notif *req) {
    char path[1024], abs[4096];
    bool is_unlinkat = (req->data.nr == __NR_unlinkat);
    uint64_t pathptr = is_unlinkat ? req->data.args[1] : req->data.args[0];

    read_remote_cstr(c->tracee, pathptr, path, sizeof(path));
    if (path[0] == '\0') snprintf(path, sizeof(path), "<unreadable>");
    path_join(c->tracee_cwd, path, abs, sizeof(abs));
    normalize_inplace(abs);

    bool in_jail = within_jail(c, abs);
    emit_evt(c, "fs_unlink_attempt",
             "\"sys\":\"%s\",\"path\":\"%s\",\"abs\":\"%s\",\"in_jail\":%s",
             is_unlinkat ? "unlinkat":"unlink", path, abs, in_jail?"true":"false");

    if (!in_jail) {
        if (c->mode == MODE_MALWARE) { hard_kill(c, "unlink_outside_jail"); respond_errno(c->notify_fd, req->id, EPERM); return; }
        // Dev/RE: allow but log
        respond_continue(c->notify_fd, req->id);
        return;
    }
    if (c->interactive_fs) {
        int ch = prompt_decision(abs);
        if (ch == 'd' || ch == 'D' || ch == EOF) { respond_errno(c->notify_fd, req->id, EPERM); return; }
        respond_continue(c->notify_fd, req->id);
        return;
    }
    if (c->mode == MODE_RE) { respond_continue(c->notify_fd, req->id); return; }
    respond_errno(c->notify_fd, req->id, EPERM);
}

static void handle_exec(supervisor_ctx_t *c, struct seccomp_notif *req) {
    uint64_t pathptr = (req->data.nr == __NR_execveat) ? req->data.args[1] : req->data.args[0];
    char path[1024];
    char abs[4096];
    read_remote_cstr(c->tracee, pathptr, path, sizeof(path));

    // Resolve absolute against current tracee cwd (cached before dispatch)
    path_join(c->tracee_cwd[0] ? c->tracee_cwd : "/", path, abs, sizeof(abs));
    normalize_inplace(abs);

emit_evt(c, "exec_attempt", "\"path\":\"%s\",\"abs\":\"%s\"", path, abs);

// In dev-like tracing, we normally allow exec so the sample can run,
// but optionally quarantine "dropped" binaries (files the tracee wrote),
// preventing second-stage execution while keeping the artifact on disk.
if (c->mode == MODE_DEV) {
    if (c->quarantine_drops && c->saw_initial_exec && taint_has(c, abs)) {
        emit_evt(c, "exec_denied_drop", "\"abs\":\"%s\"", abs);
        respond_errno(c->notify_fd, req->id, EPERM);
        return;
    }
    emit_evt(c, "exec_allow_dev", "\"abs\":\"%s\"", abs);
    respond_continue(c->notify_fd, req->id);
    return;
}


    // Allow exactly one initial exec: the target sample itself.
    if (!c->saw_initial_exec && c->sample_abs[0] && strcmp(abs, c->sample_abs) == 0) {
        c->saw_initial_exec = true;
        emit_evt(c, "exec_allow_initial", "\"abs\":\"%s\"", abs);
        respond_continue(c->notify_fd, req->id);
        return;
    }

    emit_evt(c, "exec_denied", "\"abs\":\"%s\"", abs);

    // reveal-net: sinkhole exec (log, return ENOENT) and optionally tripwire on service stack.
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

    // Other modes: EPERM and optionally kill for malware mode.
    respond_errno(c->notify_fd, req->id, EPERM);
    if (c->mode == MODE_MALWARE) hard_kill(c, "exec_boundary");
}

static void handle_fork(supervisor_ctx_t *c, struct seccomp_notif *req) {
    const char *sys = (req->data.nr == __NR_clone3) ? "clone3" :
                      (req->data.nr == __NR_clone) ? "clone" :
                      (req->data.nr == __NR_vfork) ? "vfork" : "fork";
    emit_evt(c, "proc_fork_attempt", "\"sys\":\"%s\"", sys);
    if (c->mode == MODE_MALWARE) {
        hard_kill(c, "fork_boundary");
        respond_errno(c->notify_fd, req->id, EPERM);
        return;
    }
    // In dev/RE modes, allow forks so test suites can complete; child inherits filter.
    respond_continue(c->notify_fd, req->id);
}



static void handle_net(supervisor_ctx_t *c, struct seccomp_notif *req) {
    int nr = req->data.nr;

    // Helper: decode IPv4 dst from sockaddr (best-effort).
    auto void decode_dst(uint64_t addr_ptr, socklen_t addrlen, char *dst, size_t dst_sz, uint32_t *ip_be, uint16_t *port_be) {
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

    // Always allow socket() creation; we gate on connect/send.
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

    // bind/listen tripwire: refuse services on non-loopback.
    if (nr == __NR_bind) {
        int fd = (int)req->data.args[0];
        uint64_t addr_ptr = req->data.args[1];
        socklen_t addrlen = (socklen_t)req->data.args[2];

        char dst[128];
        uint32_t ip_be = 0;
        uint16_t port_be = 0;
        decode_dst(addr_ptr, addrlen, dst, sizeof(dst), &ip_be, &port_be);

        bool loopback = (ip_be == htonl(INADDR_LOOPBACK) || ip_be == 0); // 0.0.0.0 treated as non-loopback risk
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

    // Unified outbound cap check (reveal-net)
    auto bool cap_allows(sock_track_t *t, size_t add_bytes) {
        if (!t) return true;
        if (!t->allowed) return false;

        uint64_t now = now_ms();
        if (c->net_cap_ms && t->first_ts_ms && (now - t->first_ts_ms) > c->net_cap_ms) return false;
        if (c->net_cap_sends && t->sends >= c->net_cap_sends) return false;
        if (c->net_cap_bytes && (t->bytes_out + (uint64_t)add_bytes) > c->net_cap_bytes) return false;
        return true;
    }

    auto void cap_account(sock_track_t *t, size_t add_bytes) {
        if (!t) return;
        if (t->first_ts_ms == 0) t->first_ts_ms = now_ms();
        t->sends += 1;
        t->bytes_out += (uint64_t)add_bytes;
    }

    if (nr == __NR_sendto) {
        int fd = (int)req->data.args[0];
        size_t len = (size_t)req->data.args[2];
        uint64_t addr_ptr = req->data.args[4];
        socklen_t addrlen = (socklen_t)req->data.args[5];

        char dst[128];
        uint32_t ip_be = 0;
        uint16_t port_be = 0;
        decode_dst(addr_ptr, addrlen, dst, sizeof(dst), &ip_be, &port_be);

        sock_track_t *t = sock_get_or_add(c, fd);
        if (t && strcmp(dst, "unknown") != 0) {
            t->has_dst = true;
            snprintf(t->dst, sizeof(t->dst), "%s", dst);
            t->ip_be = ip_be;
            t->port_be = port_be;
        }

        emit_evt(c, "net_sendto_attempt", "\"fd\":%d,\"dst\":\"%s\",\"len\":%zu", fd,
                 (t && t->has_dst) ? t->dst : dst, len);

        if (c->mode == MODE_REVEAL_NET) {
            if (!cap_allows(t, len)) {
                emit_evt(c, "net_cap_hit", "\"fd\":%d,\"dst\":\"%s\"", fd, (t && t->has_dst) ? t->dst : "unknown");
                respond_errno(c->notify_fd, req->id, ECONNRESET);
                return;
            }
            cap_account(t, len);
        } else {
            // Legacy behavior: only allow DNS if enabled.
            bool is_dns = (strstr(dst, ":53") != NULL);
            if (!(c->allow_dns && is_dns)) {
                respond_errno(c->notify_fd, req->id, EPERM);
                return;
            }
        }

        respond_continue(c->notify_fd, req->id);
        return;
    }

    if (nr == __NR_sendmsg) {
        int fd = (int)req->data.args[0];
        uint64_t msg_ptr = req->data.args[1];

        sock_track_t *t = sock_get_or_add(c, fd);

        size_t total = 0;
        if (msg_ptr) {
            struct msghdr mh;
            memset(&mh, 0, sizeof(mh));
            if (read_remote_mem(c->tracee, msg_ptr, &mh, sizeof(mh)) > 0 && mh.msg_iov && mh.msg_iovlen > 0) {
                size_t iovlen = mh.msg_iovlen;
                if (iovlen > 16) iovlen = 16;
                struct iovec iov[16];
                memset(iov, 0, sizeof(iov));
                if (read_remote_mem(c->tracee, (uint64_t)(uintptr_t)mh.msg_iov, iov, sizeof(struct iovec) * iovlen) > 0) {
                    for (size_t i = 0; i < iovlen; i++) total += iov[i].iov_len;
                }
            }
        }

        emit_evt(c, "net_sendmsg_attempt", "\"fd\":%d,\"dst\":\"%s\",\"len\":%zu", fd,
                 (t && t->has_dst) ? t->dst : "unknown", total);

        if (c->mode == MODE_REVEAL_NET) {
            if (!cap_allows(t, total)) {
                emit_evt(c, "net_cap_hit", "\"fd\":%d,\"dst\":\"%s\"", fd, (t && t->has_dst) ? t->dst : "unknown");
                respond_errno(c->notify_fd, req->id, ECONNRESET);
                return;
            }
            cap_account(t, total);
        } else {
            respond_errno(c->notify_fd, req->id, EPERM);
            return;
        }

        respond_continue(c->notify_fd, req->id);
        return;
    }

    if (nr == __NR_write) {
        int fd = (int)req->data.args[0];
        size_t len = (size_t)req->data.args[2];

        sock_track_t *t = sock_get(c, fd);
        if (!t) {
            respond_continue(c->notify_fd, req->id);
            return;
        }

        emit_evt(c, "net_write_attempt", "\"fd\":%d,\"dst\":\"%s\",\"len\":%zu", fd,
                 t->has_dst ? t->dst : "unknown", len);

        if (c->mode == MODE_REVEAL_NET) {
            if (!cap_allows(t, len)) {
                emit_evt(c, "net_cap_hit", "\"fd\":%d,\"dst\":\"%s\"", fd, t->has_dst ? t->dst : "unknown");
                respond_errno(c->notify_fd, req->id, ECONNRESET);
                return;
            }
            cap_account(t, len);
            respond_continue(c->notify_fd, req->id);
            return;
        }

        respond_errno(c->notify_fd, req->id, EPERM);
        return;
    }

    if (nr == __NR_writev) {
        int fd = (int)req->data.args[0];
        uint64_t iov_ptr = req->data.args[1];
        int iovcnt = (int)req->data.args[2];

        sock_track_t *t = sock_get(c, fd);
        if (!t) {
            respond_continue(c->notify_fd, req->id);
            return;
        }

        size_t total = 0;
        if (iov_ptr && iovcnt > 0) {
            if (iovcnt > 16) iovcnt = 16;
            struct iovec iov[16];
            memset(iov, 0, sizeof(iov));
            if (read_remote_mem(c->tracee, iov_ptr, iov, sizeof(struct iovec) * (size_t)iovcnt) > 0) {
                for (int i = 0; i < iovcnt; i++) total += iov[i].iov_len;
            }
        }

        emit_evt(c, "net_writev_attempt", "\"fd\":%d,\"dst\":\"%s\",\"len\":%zu", fd,
                 t->has_dst ? t->dst : "unknown", total);

        if (c->mode == MODE_REVEAL_NET) {
            if (!cap_allows(t, total)) {
                emit_evt(c, "net_cap_hit", "\"fd\":%d,\"dst\":\"%s\"", fd, t->has_dst ? t->dst : "unknown");
                respond_errno(c->notify_fd, req->id, ECONNRESET);
                return;
            }
            cap_account(t, total);
            respond_continue(c->notify_fd, req->id);
            return;
        }

        respond_errno(c->notify_fd, req->id, EPERM);
        return;
    }

    if (nr == __NR_recvfrom) {
        int fd = (int)req->data.args[0];
        sock_track_t *t = sock_get(c, fd);
        emit_evt(c, "net_recvfrom_attempt", "\"fd\":%d,\"dst\":\"%s\"", fd, (t && t->has_dst) ? t->dst : "unknown");
        if (c->mode == MODE_REVEAL_NET) {
            if (t && t->allowed) {
                respond_continue(c->notify_fd, req->id);
                return;
            }
            respond_errno(c->notify_fd, req->id, EPERM);
            return;
        }

        // Legacy: only DNS if enabled (best-effort)
        respond_errno(c->notify_fd, req->id, EPERM);
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
             (unsigned long long)addr, (unsigned long long)len, prot, adds_exec?"true":"false");

    if (adds_exec) {
        if (c->mode == MODE_DEV) {
            emit_evt(c, "mprotect_exec_allowed_dev", "");
            respond_continue(c->notify_fd, req->id);
            return;
        }
        hard_kill(c, "mprotect_adds_exec");
        respond_errno(c->notify_fd, req->id, EPERM);
        return;
    }

    respond_continue(c->notify_fd, req->id);
}

static void handle_fd(supervisor_ctx_t *c, struct seccomp_notif *req) {
    int nr = (int)req->data.nr;
    int fd = (int)req->data.args[0];

    switch (nr) {
        case __NR_read:
        case __NR_write: {
            size_t cnt = (size_t)req->data.args[2];
            emit_evt(c, (nr==__NR_read) ? "fd_read" : "fd_write",
                     "\"fd\":%d,\"count\":%zu", fd, cnt);
            break;
        }
        case __NR_readv:
        case __NR_writev: {
            int iovcnt = (int)req->data.args[2];
            emit_evt(c, (nr==__NR_readv) ? "fd_readv" : "fd_writev",
                     "\"fd\":%d,\"iovcnt\":%d", fd, iovcnt);
            break;
        }
        case __NR_close:
            emit_evt(c, "fd_close", "\"fd\":%d", fd);
            break;
        case __NR_fcntl: {
            long cmd = (long)req->data.args[1];
            emit_evt(c, "fd_fcntl", "\"fd\":%d,\"cmd\":%ld", fd, cmd);
            break;
        }
        case __NR_ioctl: {
            unsigned long cmd = (unsigned long)req->data.args[1];
            emit_evt(c, "fd_ioctl", "\"fd\":%d,\"cmd\":%lu", fd, (unsigned long)cmd);
            break;
        }
        case __NR_dup:
        case __NR_dup2:
        case __NR_dup3: {
            int oldfd = (int)req->data.args[0];
            int newfd = (nr==__NR_dup) ? -1 : (int)req->data.args[1];
            emit_evt(c, "fd_dup", "\"nr\":%d,\"oldfd\":%d,\"newfd\":%d",
                     nr, oldfd, newfd);
            break;
        }
        case __NR_poll:
        case __NR_ppoll:
            emit_evt(c, "fd_poll", "\"nr\":%d", nr);
            break;
        default:
            emit_evt(c, "fd_misc", "\"nr\":%d,\"fd\":%d", nr, fd);
            break;
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

    emit_evt(c, "supervisor_start", "\"notify_fd\":%d", c->notify_fd);

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

        // Poll so we can honor timeout/max_events even when the tracee is quiet.
        struct pollfd pfd = { .fd = c->notify_fd, .events = POLLIN };
        int prc = poll(&pfd, 1, 50 /*ms*/);
        if (prc < 0) {
            if (errno == EINTR) continue;
        }
        if (prc == 0) {
            // no event; loop back to check timeout/max_events
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

        c->cur_pid = (pid_t)req->pid;
        get_tracee_cwd(c->cur_pid, c->tracee_cwd, sizeof(c->tracee_cwd));

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
            case __NR_rename:
                    case __NR_renameat:
            handle_renameat(c, req);
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
            case __NR_read:
            case __NR_readv:
            case __NR_close:
            case __NR_fcntl:
            case __NR_ioctl:
            case __NR_dup:
            case __NR_dup2:
            case __NR_dup3:
            case __NR_poll:
            case __NR_ppoll:
                handle_fd(c, req);
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
        "Usage: %s --outdir DIR [--timeout-ms N] [--max-events N] [--mode malware|re|reveal-net|dev]\n"
        "          [--write-jail DIR] [--interactive-fs] [--quarantine-drops] -- /path/to/sample [args...]\n", argv0);
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
    ctx.net_cap_bytes = getenv("SOFTRX_NET_CAP_BYTES") ? (uint64_t)strtoull(getenv("SOFTRX_NET_CAP_BYTES"), NULL, 10) : 0;
    ctx.net_cap_ms    = getenv("SOFTRX_NET_CAP_MS") ? (uint64_t)strtoull(getenv("SOFTRX_NET_CAP_MS"), NULL, 10) : 0;
    ctx.net_cap_sends = getenv("SOFTRX_NET_CAP_SENDS") ? (uint64_t)strtoull(getenv("SOFTRX_NET_CAP_SENDS"), NULL, 10) : 0;
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
            else if (strcmp(m, "reveal-net") == 0 || strcmp(m, "reveal_net") == 0) ctx.mode = MODE_REVEAL_NET;
            else if (strcmp(m, "dev") == 0) ctx.mode = MODE_DEV;
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
            // format: A.B.C.D:PORT (IPv4 only, best-effort)
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

    // Resolve sample absolute path (for the "allow initial exec" boundary)
    char cwd[4096];
    if (!getcwd(cwd, sizeof(cwd))) snprintf(cwd, sizeof(cwd), "/");
    path_join(cwd, argv[i], ctx.sample_abs, sizeof(ctx.sample_abs));
    normalize_inplace(ctx.sample_abs);

    if (mkdir_p(ctx.outdir) != 0 && errno != EEXIST)
        die("mkdir_p(outdir) failed: %s", strerror(errno));

    if (ctx.write_jail[0]) {
        if (mkdir_p(ctx.write_jail) != 0 && errno != EEXIST)
            die("mkdir_p(write_jail) failed: %s", strerror(errno));
    }


    if (ctx.mode == MODE_REVEAL_NET) {
        // Operator-safe defaults for "reveal but don't work" networking.
        if (!ctx.allow_dns) ctx.allow_dns = true;
        if (!ctx.allow_dot) ctx.allow_dot = true;

        // Reasonable default caps if unset via args/env:
        if (ctx.net_cap_bytes == 0) ctx.net_cap_bytes = 10 * 1024;   // 10KB
        if (ctx.net_cap_ms == 0)    ctx.net_cap_ms = 2000;           // 2s per socket
        if (ctx.net_cap_sends == 0) ctx.net_cap_sends = 32;          // 32 send calls

        // In reveal-net we never allow filesystem writes; write_jail is ignored.
        ctx.interactive_fs = false;
    }

    if (ctx.mode == MODE_DEV) {
        // Dev mode: maximize visibility; allow program behavior but log everything.
        if (ctx.write_jail[0] == '\0') {
            snprintf(ctx.write_jail, sizeof(ctx.write_jail), "%s/fs", ctx.outdir);
        }
        ctx.interactive_fs = false;
        ctx.allow_any_connect = true;
    }

    // Open events.ndjson
    char evpath[8192];
    int n = snprintf(evpath, sizeof(evpath), "%s/events.ndjson", ctx.outdir);
    if (n < 0 || n >= (int)sizeof(evpath)) die("outdir too long for events path");
    ctx.events_fp = fopen(evpath, "a");
    if (!ctx.events_fp) die("open events.ndjson failed: %s", strerror(errno));

    emit_evt(&ctx, "launcher_start", "\"outdir\":\"%s\",\"mode\":%d,\"write_jail\":\"%s\",\"sample_abs\":\"%s\",\"build\":\"%s\"", ctx.outdir, (int)ctx.mode, ctx.write_jail, ctx.sample_abs, SOFTRX_BUILD_TAG);


    // Unix socketpair for SCM_RIGHTS passing of the listener FD
    int sp[2];
    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sp) != 0)
        die("socketpair failed: %s", strerror(errno));

    pid_t child = fork();
    if (child < 0) die("fork failed: %s", strerror(errno));

    if (child == 0) {
        // ---- TRACEe ----
        setpgid(0, 0);

        // **CRITICAL FIX**
        // Make relative file ops land inside jail (e.g., fopen("test.txt","w"))
        if (ctx.write_jail[0]) {
            (void)chdir(ctx.write_jail);
        }

        close(sp[0]);

        fprintf(stderr, "[SoftRX] child: installing seccomp listener...\n"); fflush(stderr);
        int listener_fd = install_listener_filter();
        fprintf(stderr, "[SoftRX] child: listener_fd=%d\n", listener_fd); fflush(stderr);
        fprintf(stderr, "[SoftRX] child: sending listener fd to parent...\n"); fflush(stderr);
        send_fd(sp[1], listener_fd);
        fprintf(stderr, "[SoftRX] child: sent listener fd\n"); fflush(stderr);
        close(listener_fd);
        close(sp[1]);

        char **child_argv = &argv[i];
        fprintf(stderr, "[SoftRX] child: execv(%s)\n", child_argv[0]); fflush(stderr);
        execv(child_argv[0], child_argv);

        perror("execv");
        _exit(127);
    }

    // ---- SUPERVISOR ----
    close(sp[1]);
    ctx.tracee = child;

    // Ensure we have a stable pgid to kill the whole group
    setpgid(child, child);
    ctx.tracee_pgid = child;

    ctx.notify_fd = recv_fd_timed(sp[0], child, 5000);
    if (ctx.notify_fd < 0) {
        emit_evt(&ctx, "listener_fd_error", "\"errno\":%d", errno);
        // Ensure child is reaped if it exited
        (void)kill(child, SIGKILL);
        int st=0; (void)waitpid(child, &st, 0);
        fclose(ctx.events_fp);
        return 1;
    }
    close(sp[0]);

    // **NONBLOCK FIX**: avoid supervisor hanging after tracee exits
    int fl = fcntl(ctx.notify_fd, F_GETFL, 0);
    if (fl >= 0) (void)fcntl(ctx.notify_fd, F_SETFL, fl | O_NONBLOCK);

    fprintf(stdout, "[SoftRX] supervisor pid=%d tracee=%d notify_fd=%d\n",
            getpid(), (int)ctx.tracee, ctx.notify_fd);
    fflush(stdout);

    pthread_t th;
    if (pthread_create(&th, NULL, supervisor_thread, &ctx) != 0)
        die("pthread_create failed");

    uint64_t start = now_ms();
	int status = 0;
	while (1) {
		pid_t w = waitpid(child, &status, WNOHANG);
		if (w == child) break;

		if (now_ms() - start > ctx.timeout_ms + 500) {
			emit_evt(&ctx, "waitpid_timeout", "\"note\":\"forcing kill\"");
			hard_kill(&ctx, "waitpid_timeout");
			// also close notify_fd to unblock a stuck seccomp-stop
			close(ctx.notify_fd);
			ctx.notify_fd = -1;
			// now do a final blocking wait to reap
			(void)waitpid(child, &status, 0);
			break;
		}
		usleep(10 * 1000);
	}


    pthread_join(th, NULL);
    emit_evt(&ctx, "tracee_exit", "\"status\":%d", status);

    fclose(ctx.events_fp);
    close(ctx.notify_fd);

    if (WIFEXITED(status)) return WEXITSTATUS(status);
    if (WIFSIGNALED(status)) return -WTERMSIG(status);
    return 0;
}
