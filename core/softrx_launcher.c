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

static void path_join(const char *cwd, const char *p, char *out, size_t out_sz) {
    if (!p || !p[0]) { snprintf(out, out_sz, "%s", cwd); return; }
    if (p[0] == '/') { snprintf(out, out_sz, "%s", p); return; }
    snprintf(out, out_sz, "%s/%s", cwd, p);
}

static void normalize_inplace(char *p) {
    char *w = p;
    for (char *r = p; *r; ) {
        if (r[0]=='/' && r[1]=='.' && r[2]=='/') { r += 2; continue; }
        *w++ = *r++;
    }
    *w = '\0';
    size_t n = strlen(p);
    if (n >= 2 && p[n-2]=='/' && p[n-1]=='.') p[n-1] = '\0';
}

typedef enum { MODE_MALWARE=0, MODE_RE=1 } run_mode_t;

typedef struct {
    pid_t tracee;
    pid_t tracee_pgid;
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
    bool allow_dns;            // if true, allow DNS traffic only (port 53)
    int dns_fds[64];
    int dns_fd_count;

} supervisor_ctx_t;

static bool dns_fd_is_allowed(supervisor_ctx_t *c, int fd) {
    for (int i = 0; i < c->dns_fd_count; i++) {
        if (c->dns_fds[i] == fd) return true;
    }
    return false;
}

static void dns_fd_allow(supervisor_ctx_t *c, int fd) {
    if (fd < 0 || dns_fd_is_allowed(c, fd)) return;
    if (c->dns_fd_count < (int)(sizeof(c->dns_fds)/sizeof(c->dns_fds[0]))) {
        c->dns_fds[c->dns_fd_count++] = fd;
    }
}

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
    // Try to kill the whole process group (defense-in-depth against fork/spawn).
    if (c->tracee_pgid > 0) {
        kill(-c->tracee_pgid, SIGKILL);
    } else if (c->tracee > 0) {
        kill(c->tracee, SIGKILL);
    }
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

        JEQ_SYSCALL(__NR_socket,0, 1),   BPF_STMT(BPF_RET|BPF_K, SC_NOTIFY),
        JEQ_SYSCALL(__NR_connect,0, 1),  BPF_STMT(BPF_RET|BPF_K, SC_NOTIFY),
        JEQ_SYSCALL(__NR_sendto,0, 1),   BPF_STMT(BPF_RET|BPF_K, SC_NOTIFY),
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

    if (in_jail) {
        respond_continue(c->notify_fd, req->id);
        return;
    }

    // write outside jail
    emit_evt(c, "fs_open_denied",
             "\"reason\":\"write_outside_jail\",\"abs\":\"%s\"", abs);
    respond_errno(c->notify_fd, req->id, EPERM);

    if (c->mode == MODE_MALWARE) {
        hard_kill(c, "write_outside_jail");
    }
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
        if (c->mode == MODE_MALWARE) hard_kill(c, "unlink_outside_jail");
        respond_errno(c->notify_fd, req->id, EPERM);
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

    // Allow exactly one initial exec: the target sample itself.
    if (!c->saw_initial_exec && c->sample_abs[0] && strcmp(abs, c->sample_abs) == 0) {
        c->saw_initial_exec = true;
        emit_evt(c, "exec_allow_initial", "\"abs\":\"%s\"", abs);
        respond_continue(c->notify_fd, req->id);
        return;
    }

    emit_evt(c, "exec_denied", "\"abs\":\"%s\"", abs);

    // Respond first so the tracee isn't left stuck in user-notify.
    respond_errno(c->notify_fd, req->id, EPERM);
    if (c->mode == MODE_MALWARE) hard_kill(c, "exec_boundary");
}

static void handle_fork(supervisor_ctx_t *c, struct seccomp_notif *req) {
    const char *sys = (req->data.nr == __NR_clone) ? "clone" :
                      (req->data.nr == __NR_vfork) ? "vfork" : "fork";
    emit_evt(c, "proc_fork_attempt", "\"sys\":\"%s\"", sys);
    hard_kill(c, "fork_boundary");
    respond_errno(c->notify_fd, req->id, EPERM);
}

static void handle_net(supervisor_ctx_t *c, struct seccomp_notif *req) {
    int nr = req->data.nr;

    // Always allow socket() creation; we gate actual egress on connect/sendto.
    if (nr == __NR_socket) {
        emit_evt(c, "net_attempt", "\"sys\":\"socket\"");
        respond_continue(c->notify_fd, req->id);
        return;
    }

    // Helper: try to decode IPv4 dst from sockaddr.
    auto void decode_dst(uint64_t addr_ptr, socklen_t addrlen, char *dst, size_t dst_sz) {
        struct sockaddr_storage ss;
        memset(&ss, 0, sizeof(ss));
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
            snprintf(dst, dst_sz, "%s:%u", ip, (unsigned)ntohs(in->sin_port));
            return;
        }

        // Best-effort; don't fail the supervisor if we can't parse.
        snprintf(dst, dst_sz, "unknown");
    }

    if (nr == __NR_connect) {
        int fd = (int)req->data.args[0];
        uint64_t addr_ptr = req->data.args[1];
        socklen_t addrlen = (socklen_t)req->data.args[2];

        char dst[128];
        decode_dst(addr_ptr, addrlen, dst, sizeof(dst));
        emit_evt(c, "net_connect_attempt", "\"fd\":%d,\"dst\":\"%s\"", fd, dst);

        // Allow DNS egress only if explicitly enabled and destination is :53.
        bool is_dns = (strstr(dst, ":53") != NULL);
        if (c->allow_dns && is_dns) {
            dns_fd_allow(c, fd);
            respond_continue(c->notify_fd, req->id);
        } else {
            respond_errno(c->notify_fd, req->id, ECONNREFUSED);
        }
        return;
    }

    if (nr == __NR_sendto) {
        int fd = (int)req->data.args[0];
        uint64_t addr_ptr = req->data.args[4];
        socklen_t addrlen = (socklen_t)req->data.args[5];

        char dst[128];
        decode_dst(addr_ptr, addrlen, dst, sizeof(dst));
        emit_evt(c, "net_sendto_attempt", "\"fd\":%d,\"dst\":\"%s\"", fd, dst);

        bool is_dns = (strstr(dst, ":53") != NULL);
        if (c->allow_dns && (dns_fd_is_allowed(c, fd) || is_dns)) {
            if (is_dns) dns_fd_allow(c, fd);
            respond_continue(c->notify_fd, req->id);
        } else {
            respond_errno(c->notify_fd, req->id, EPERM);
        }
        return;
    }

    if (nr == __NR_recvfrom) {
        int fd = (int)req->data.args[0];
        emit_evt(c, "net_recvfrom_attempt", "\"fd\":%d", fd);
        if (c->allow_dns && dns_fd_is_allowed(c, fd)) {
            respond_continue(c->notify_fd, req->id);
        } else {
            respond_errno(c->notify_fd, req->id, EPERM);
        }
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
        hard_kill(c, "mprotect_adds_exec");
        respond_errno(c->notify_fd, req->id, EPERM);
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

        get_tracee_cwd(c->tracee, c->tracee_cwd, sizeof(c->tracee_cwd));

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
                emit_evt(c, "fs_rename_attempt", "\"note\":\"denied\"");
                if (c->mode == MODE_MALWARE) hard_kill(c, "rename_boundary");
                respond_errno(c->notify_fd, req->id, EPERM);
                break;
            case __NR_execve:
            case __NR_execveat:
                handle_exec(c, req);
                break;
            case __NR_fork:
            case __NR_vfork:
            case __NR_clone:
                handle_fork(c, req);
                break;
            case __NR_socket:
            case __NR_connect:
            case __NR_sendto:
            case __NR_recvfrom:
                handle_net(c, req);
                break;
            case __NR_mprotect:
                handle_mprotect(c, req);
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
        "Usage: %s --outdir DIR [--timeout-ms N] [--max-events N] [--mode malware|re]\n"
        "          [--write-jail DIR] [--interactive-fs] -- /path/to/sample [args...]\n", argv0);
}

int main(int argc, char **argv) {
    supervisor_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.timeout_ms = 4000;
    ctx.max_events = 200;
    ctx.mode = MODE_MALWARE;
    ctx.saw_initial_exec = false;
    ctx.allow_dns = (getenv("SOFTRX_ALLOW_DNS") && getenv("SOFTRX_ALLOW_DNS")[0] == '1');
    ctx.dns_fd_count = 0;

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
            else if (strcmp(m, "dev") == 0) ctx.mode = MODE_RE; // treat dev as RE-lite
            else die("unknown mode: %s", m);
            continue;
        }
        if (strcmp(argv[i], "--allow-dns") == 0) {
            ctx.allow_dns = true;
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

    // Open events.ndjson
    char evpath[8192];
    int n = snprintf(evpath, sizeof(evpath), "%s/events.ndjson", ctx.outdir);
    if (n < 0 || n >= (int)sizeof(evpath)) die("outdir too long for events path");
    ctx.events_fp = fopen(evpath, "a");
    if (!ctx.events_fp) die("open events.ndjson failed: %s", strerror(errno));

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

        int listener_fd = install_listener_filter();
        send_fd(sp[1], listener_fd);
        close(listener_fd);
        close(sp[1]);

        char **child_argv = &argv[i];
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

    ctx.notify_fd = recv_fd(sp[0]);
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

    int status = 0;
    (void)waitpid(child, &status, 0);

    pthread_join(th, NULL);
    emit_evt(&ctx, "tracee_exit", "\"status\":%d", status);

    fclose(ctx.events_fp);
    close(ctx.notify_fd);

    if (WIFEXITED(status)) return WEXITSTATUS(status);
    if (WIFSIGNALED(status)) return -WTERMSIG(status);
    return 0;
}
