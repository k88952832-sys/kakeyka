/*
 * Standalone AArch64 injector: attaches to a running process via ptrace and
 * calls dlopen() inside it to load a given .so path.
 *
 * Must run as root (uid 0), e.g. via `su -c "./injector <pid> <lib_path>"`.
 * Does not do anything after dlopen() returns: if the loaded library has a
 * __attribute__((constructor)) entry point, that already ran by the time
 * dlopen() returns, because the dynamic linker runs constructors before
 * dlopen hands control back to the caller.
 *
 * Technique: find libc's load base in both our own process and the target's
 * (from /proc/<pid>/maps), resolve dlopen's address locally via dlsym, and
 * compute its address in the target as (local_dlopen - local_libc_base) +
 * remote_libc_base. This assumes the same libc build is mapped at a fixed
 * internal layout in both processes, which holds when both are the same
 * device/OS image, but is not verified against this specific device here.
 *
 * Not tested against a live game process. Treat the exit code and the
 * printed messages as the only evidence of what happened; nothing here
 * should be assumed to work until it has been run and its output read.
 */
#include <dlfcn.h>
#include <elf.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

/* AArch64 general-purpose register file, as exposed by PTRACE_GETREGSET /
 * PTRACE_SETREGSET with NT_PRSTATUS. Layout matches the kernel's
 * struct user_pt_regs for arm64: 31 general registers, then sp, pc, pstate. */
struct aarch64_regs {
    unsigned long long regs[31];
    unsigned long long sp;
    unsigned long long pc;
    unsigned long long pstate;
};

static int get_regs(pid_t pid, struct aarch64_regs *out) {
    struct iovec iov = {out, sizeof(*out)};
    return ptrace(PTRACE_GETREGSET, pid, (void *)NT_PRSTATUS, &iov);
}

static int set_regs(pid_t pid, struct aarch64_regs *in) {
    struct iovec iov = {in, sizeof(*in)};
    return ptrace(PTRACE_SETREGSET, pid, (void *)NT_PRSTATUS, &iov);
}

/* Writes `len` bytes to the target's memory at `addr`, word (8 byte) at a
 * time via PTRACE_POKEDATA. `addr` need not be 8-byte aligned; any partial
 * leading/trailing word is read-modify-written so bytes outside [addr,
 * addr+len) at the edges are preserved. */
static int write_remote(pid_t pid, unsigned long long addr, const void *buf, size_t len) {
    size_t i = 0;
    while (i < len) {
        unsigned long long word_addr = addr + i;
        unsigned long long aligned = word_addr & ~7ULL;
        size_t offset_in_word = word_addr - aligned;
        errno = 0;
        unsigned long long word = ptrace(PTRACE_PEEKDATA, pid, (void *)aligned, NULL);
        if (word == (unsigned long long)-1 && errno != 0) return -1;
        size_t chunk = 8 - offset_in_word;
        if (chunk > len - i) chunk = len - i;
        memcpy((char *)&word + offset_in_word, (const char *)buf + i, chunk);
        if (ptrace(PTRACE_POKEDATA, pid, (void *)aligned, (void *)word) != 0) return -1;
        i += chunk;
    }
    return 0;
}

/* Finds the lowest mapped start address of any region whose path in
 * /proc/<pid>/maps ends with `libname`. Returns 0 if not found. */
static unsigned long long find_module_base(pid_t pid, const char *libname) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/maps", pid);
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    char line[1024];
    unsigned long long base = 0;
    size_t namelen = strlen(libname);
    while (fgets(line, sizeof(line), f)) {
        char *nl = strchr(line, '\n');
        if (nl) *nl = 0;
        size_t linelen = strlen(line);
        if (linelen < namelen) continue;
        if (strcmp(line + linelen - namelen, libname) != 0) continue;
        unsigned long long start = strtoull(line, NULL, 16);
        if (base == 0 || start < base) base = start;
    }
    fclose(f);
    return base;
}

/* Prints every /proc/<pid>/maps line whose path ends with `libname`, with a
 * tag so local and remote output can be told apart. Pure diagnostics: does
 * not affect the injection logic. */
static void dump_matching_maps(pid_t pid, const char *libname, const char *tag) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/maps", pid);
    FILE *f = fopen(path, "r");
    if (!f) {
        printf("[%s] could not open %s\n", tag, path);
        return;
    }
    char line[1024];
    size_t namelen = strlen(libname);
    int count = 0;
    while (fgets(line, sizeof(line), f)) {
        char *nl = strchr(line, '\n');
        if (nl) *nl = 0;
        size_t linelen = strlen(line);
        if (linelen < namelen) continue;
        if (strcmp(line + linelen - namelen, libname) != 0) continue;
        printf("[%s] %s\n", tag, line);
        count++;
    }
    if (count == 0) printf("[%s] no line in %s ends with %s\n", tag, path, libname);
    fclose(f);
}

/* Returns 1 if `addr` falls inside a mapped region of pid's maps that has
 * the executable bit set, 0 if it falls in a mapped-but-not-executable
 * region, and -1 if it is not mapped at all (or maps could not be read). */
static int is_executable_at(pid_t pid, unsigned long long addr) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/maps", pid);
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    char line[1024];
    int result = -1;
    while (fgets(line, sizeof(line), f)) {
        unsigned long long start, end;
        char perms[8] = {0};
        if (sscanf(line, "%llx-%llx %7s", &start, &end, perms) != 3) continue;
        if (addr >= start && addr < end) {
            result = (strchr(perms, 'x') != NULL) ? 1 : 0;
            break;
        }
    }
    fclose(f);
    return result;
}

/* Calls `func_addr(arg0[, arg1])` inside the already-attached, already-stopped
 * `pid`, using `orig_regs` (the registers captured right after attaching) as
 * the base to restore sp/other state from for this one call. lr is set to 0
 * so the call's `ret` lands at pc==0, used as a catchable trap distinguishing
 * "the call returned" from "something else happened" (a crash, a signal).
 * On success, *out_result gets x0 and this returns 0; otherwise returns -1
 * and the target's registers may be left mid-call, so the caller must still
 * restore orig_regs itself afterwards regardless of this call's outcome. */
static int remote_call(pid_t pid, const struct aarch64_regs *orig_regs,
                        unsigned long long func_addr, unsigned long long arg0,
                        unsigned long long arg1, int nargs,
                        unsigned long long *out_result) {
    struct aarch64_regs call_regs = *orig_regs;
    unsigned long long scratch = (orig_regs->sp - 0x1000) & ~0xFULL;
    call_regs.regs[0] = arg0;
    if (nargs > 1) call_regs.regs[1] = arg1;
    call_regs.regs[30] = 0;
    call_regs.pc = func_addr;
    call_regs.sp = scratch;

    if (set_regs(pid, &call_regs) != 0) return -1;
    if (ptrace(PTRACE_CONT, pid, NULL, NULL) != 0) return -1;
    int status;
    if (waitpid(pid, &status, 0) < 0 || !WIFSTOPPED(status)) return -1;
    struct aarch64_regs after;
    if (get_regs(pid, &after) != 0 || after.pc != 0) return -1;
    *out_result = after.regs[0];
    return 0;
}

/* Reads a NUL-terminated string from the target's memory at `addr`, up to
 * bufsize-1 bytes. Returns 0 on success (buf is always NUL-terminated),
 * -1 if a PEEKDATA call failed (e.g. addr unmapped). */
static int read_remote_string(pid_t pid, unsigned long long addr, char *buf, size_t bufsize) {
    size_t i = 0;
    while (i + 8 < bufsize) {
        errno = 0;
        unsigned long long word = ptrace(PTRACE_PEEKDATA, pid, (void *)(addr + i), NULL);
        if (word == (unsigned long long)-1 && errno != 0) {
            buf[i] = 0;
            return -1;
        }
        memcpy(buf + i, &word, 8);
        for (int j = 0; j < 8; j++) {
            if (buf[i + j] == '\0') return 0;
        }
        i += 8;
    }
    buf[bufsize - 1] = 0;
    return 0;
}

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "usage: %s <target_pid> <path_to_lib.so>\n", argv[0]);
        return 2;
    }
    if (getuid() != 0) {
        fprintf(stderr, "must run as root (uid 0); got uid %d\n", getuid());
        return 2;
    }

    pid_t target = (pid_t)atoll(argv[1]);
    const char *lib_path = argv[2];
    size_t lib_path_len = strlen(lib_path) + 1; /* include NUL */

    /* --- Resolve dlopen's real address and its offset inside its own module ---
     * dlopen's documented, stable home in the Android NDK/bionic ABI is
     * libdl.so, which is what apps are supposed to link against; libc.so is
     * tried only as a fallback. Whichever module actually provides the
     * symbol is the one whose base must be used on both sides, or the
     * offset is meaningless. */
    const char *module_name = "libdl.so";
    void *mod_handle = dlopen(module_name, RTLD_NOW | RTLD_NOLOAD);
    if (!mod_handle) mod_handle = dlopen(module_name, RTLD_NOW);
    void *local_dlopen = mod_handle ? dlsym(mod_handle, "dlopen") : NULL;
    if (!local_dlopen) {
        module_name = "libc.so";
        mod_handle = dlopen(module_name, RTLD_NOW | RTLD_NOLOAD);
        if (!mod_handle) mod_handle = dlopen(module_name, RTLD_NOW);
        local_dlopen = mod_handle ? dlsym(mod_handle, "dlopen") : NULL;
    }
    if (!local_dlopen) {
        fprintf(stderr, "could not resolve dlopen from libdl.so or libc.so locally: %s\n", dlerror());
        return 1;
    }
    printf("resolved dlopen from %s at local address %p\n", module_name, local_dlopen);

    dump_matching_maps(getpid(), module_name, "local");
    dump_matching_maps(target, module_name, "remote");

    unsigned long long local_base = find_module_base(getpid(), module_name);
    if (local_base == 0) {
        fprintf(stderr, "could not find %s base in our own /proc/self/maps\n", module_name);
        return 1;
    }
    unsigned long long dlopen_offset = (unsigned long long)local_dlopen - local_base;

    unsigned long long remote_base = find_module_base(target, module_name);
    if (remote_base == 0) {
        fprintf(stderr, "could not find %s base for pid %d (is it running? permission?)\n", module_name, target);
        return 1;
    }
    unsigned long long remote_dlopen = remote_base + dlopen_offset;
    printf("local %s base=0x%llx remote %s base=0x%llx dlopen offset=0x%llx remote dlopen=0x%llx\n",
           module_name, local_base, module_name, remote_base, dlopen_offset, remote_dlopen);

    int exec_check = is_executable_at(target, remote_dlopen);
    if (exec_check != 1) {
        fprintf(stderr,
                "remote dlopen address is %s in the target (exec_check=%d); refusing to jump there. "
                "This means the offset computed from %s does not land on executable code in the "
                "target process; the base-matching technique needs rethinking for this device/build.\n",
                exec_check == 0 ? "mapped but NOT executable" : "not mapped at all", exec_check, module_name);
        return 1;
    }

    /* Also resolve dlerror from the same module, so that if dlopen returns
     * NULL we can ask the target *why* instead of just knowing that it did. */
    void *local_dlerror = dlsym(mod_handle, "dlerror");
    unsigned long long remote_dlerror = 0;
    if (local_dlerror) {
        unsigned long long dlerror_offset = (unsigned long long)local_dlerror - local_base;
        remote_dlerror = remote_base + dlerror_offset;
        if (is_executable_at(target, remote_dlerror) != 1) {
            printf("remote dlerror address not executable in target; skipping dlerror diagnostics\n");
            remote_dlerror = 0;
        }
    } else {
        printf("dlsym(dlerror) failed locally; skipping dlerror diagnostics\n");
    }

    /* --- Attach --- */
    if (ptrace(PTRACE_ATTACH, target, NULL, NULL) != 0) {
        fprintf(stderr, "PTRACE_ATTACH(%d) failed: %s\n", target, strerror(errno));
        return 1;
    }
    int status;
    if (waitpid(target, &status, 0) < 0 || !WIFSTOPPED(status)) {
        fprintf(stderr, "waitpid after attach did not report stopped (status=0x%x)\n", status);
        ptrace(PTRACE_DETACH, target, NULL, NULL);
        return 1;
    }

    struct aarch64_regs orig_regs;
    if (get_regs(target, &orig_regs) != 0) {
        fprintf(stderr, "PTRACE_GETREGSET failed: %s\n", strerror(errno));
        ptrace(PTRACE_DETACH, target, NULL, NULL);
        return 1;
    }

    /* String argument goes below the call's own scratch stack area (which
     * remote_call derives from orig_regs.sp), so it isn't clobbered by the
     * call itself. */
    unsigned long long str_addr = ((orig_regs.sp - 0x1000) & ~0xFULL) - 0x200;

    int ok = 0;
    unsigned long long remote_handle = 0;
    if (write_remote(target, str_addr, lib_path, lib_path_len) != 0) {
        fprintf(stderr, "failed writing library path into target memory\n");
    } else if (remote_call(target, &orig_regs, remote_dlopen, str_addr, 2, 2, &remote_handle) != 0) {
        fprintf(stderr, "dlopen call did not land cleanly (crash, signal, or ptrace error); "
                        "see dmesg/logcat on the device for what the target did\n");
    } else {
        ok = 1;
    }

    /* If dlopen reported failure, ask it why, while still attached. */
    if (ok && remote_handle == 0 && remote_dlerror != 0) {
        unsigned long long err_ptr = 0;
        if (remote_call(target, &orig_regs, remote_dlerror, 0, 0, 0, &err_ptr) == 0 && err_ptr != 0) {
            char msg[256];
            if (read_remote_string(target, err_ptr, msg, sizeof(msg)) == 0) {
                printf("dlerror() in target says: %s\n", msg);
            } else {
                printf("dlerror() returned a pointer (0x%llx) but it could not be read from target memory\n", err_ptr);
            }
        } else {
            printf("dlerror() call itself did not return cleanly, or returned NULL\n");
        }
    }

    /* Always restore original registers and detach, success or not, so the
     * game process is left runnable either way. */
    set_regs(target, &orig_regs);
    ptrace(PTRACE_DETACH, target, NULL, NULL);

    if (!ok) {
        fprintf(stderr, "injection failed\n");
        return 1;
    }
    if (remote_handle == 0) {
        fprintf(stderr, "remote dlopen returned NULL: see the dlerror() message above for the "
                        "actual reason (common causes: SELinux denying the target process access "
                        "to this file path, wrong ELF class/ABI, or a missing dependency)\n");
        return 1;
    }
    printf("remote dlopen succeeded, handle=0x%llx\n", remote_handle);
    return 0;
}
