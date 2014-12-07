/*
 * Copyright (c) 1993 Branko Lankester <branko@hacktic.nl>
 * Copyright (c) 1993, 1994, 1995 Rick Sladkey <jrs@world.std.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "dummy.h"

/* common syscalls */

int sys_accept(tcb*);
int sys_accept4(tcb*);
int sys_access(tcb*);
int sys_add_key(tcb*);
int sys_adjtimex(tcb*);
int sys_arch_prctl(tcb*);
int sys_bind(tcb*);
int sys_brk(tcb*);
int sys_capget(tcb*);
int sys_capset(tcb*);
int sys_chdir(tcb*);
int sys_chmod(tcb*);
int sys_chown(tcb*);
int sys_clock_adjtime(tcb*);
int sys_clock_gettime(tcb*);
int sys_clock_nanosleep(tcb*);
int sys_clock_settime(tcb*);
int sys_clone(tcb*);
int sys_close(tcb*);
int sys_connect(tcb*);
int sys_creat(tcb*);
int sys_create_module(tcb*);
int sys_delete_module(tcb*);
int sys_dup(tcb*);
int sys_dup2(tcb*);
int sys_dup3(tcb*);
int sys_epoll_create(tcb*);
int sys_epoll_create1(tcb*);
int sys_epoll_ctl(tcb*);
int sys_epoll_pwait(tcb*);
int sys_epoll_wait(tcb*);
int sys_eventfd(tcb*);
int sys_eventfd2(tcb*);
int sys_execve(tcb*);
int sys_exit(tcb*);
int sys_faccessat(tcb*);
int sys_fadvise64(tcb*);
int sys_fadvise64_64(tcb*);
int sys_fallocate(tcb*);
int sys_fanotify_init(tcb*);
int sys_fanotify_mark(tcb*);
int sys_fchmod(tcb*);
int sys_fchmodat(tcb*);
int sys_fchown(tcb*);
int sys_fchownat(tcb*);
int sys_fcntl(tcb*);
int sys_fgetxattr(tcb*);
int sys_finit_module(tcb*);
int sys_flistxattr(tcb*);
int sys_flock(tcb*);
int sys_fork(tcb*);
int sys_fremovexattr(tcb*);
int sys_fsetxattr(tcb*);
int sys_fstat(tcb*);
int sys_fstat64(tcb*);
int sys_fstatfs(tcb*);
int sys_fstatfs64(tcb*);
int sys_ftruncate(tcb*);
int sys_ftruncate64(tcb*);
int sys_futex(tcb*);
int sys_futimesat(tcb*);
int sys_get_mempolicy(tcb*);
int sys_get_robust_list(tcb*);
int sys_get_thread_area(tcb*);
int sys_getcpu(tcb*);
int sys_getcwd(tcb*);
int sys_getdents(tcb*);
int sys_getdents64(tcb*);
int sys_getdtablesize(tcb*);
int sys_getgroups(tcb*);
int sys_getgroups32(tcb*);
int sys_gethostname(tcb*);
int sys_getitimer(tcb*);
int sys_getpeername(tcb*);
int sys_getpmsg(tcb*); /* TODO: non-Linux, remove? */
int sys_getpriority(tcb*);
int sys_getresuid(tcb*);
int sys_getrlimit(tcb*);
int sys_getrusage(tcb*);
int sys_getsockname(tcb*);
int sys_getsockopt(tcb*);
int sys_gettimeofday(tcb*);
int sys_getuid(tcb*);
int sys_getxattr(tcb*);
int sys_init_module(tcb*);
int sys_inotify_add_watch(tcb*);
int sys_inotify_init1(tcb*);
int sys_inotify_rm_watch(tcb*);
int sys_io_cancel(tcb*);
int sys_io_destroy(tcb*);
int sys_io_getevents(tcb*);
int sys_io_setup(tcb*);
int sys_io_submit(tcb*);
int sys_ioctl(tcb*);
int sys_ioprio_get(tcb*);
int sys_ioprio_set(tcb*);
int sys_ipc(tcb*);
int sys_keyctl(tcb*);
int sys_kexec_load(tcb*);
int sys_kill(tcb*);
int sys_link(tcb*);
int sys_linkat(tcb*);
int sys_listen(tcb*);
int sys_listxattr(tcb*);
int sys_llseek(tcb*);
int sys_lseek(tcb*);
int sys_madvise(tcb*);
int sys_mbind(tcb*);
int sys_migrate_pages(tcb*);
int sys_mincore(tcb*);
int sys_mkdir(tcb*);
int sys_mkdirat(tcb*);
int sys_mknod(tcb*);
int sys_mknodat(tcb*);
int sys_mlockall(tcb*);
int sys_mmap(tcb*);
int sys_mmap_pgoff(tcb*);
int sys_mmap_4koff(tcb*);
int sys_modify_ldt(tcb*);
int sys_mount(tcb*);
int sys_move_pages(tcb*);
int sys_mprotect(tcb*);
int sys_mq_getsetattr(tcb*);
int sys_mq_notify(tcb*);
int sys_mq_open(tcb*);
int sys_mq_timedreceive(tcb*);
int sys_mq_timedsend(tcb*);
int sys_mremap(tcb*);
int sys_msgctl(tcb*);
int sys_msgget(tcb*);
int sys_msgrcv(tcb*);
int sys_msgsnd(tcb*);
int sys_msync(tcb*);
int sys_munmap(tcb*);
int sys_nanosleep(tcb*);
int sys_newfstatat(tcb*);
int sys_old_mmap(tcb*);
int sys_old_mmap_pgoff(tcb*);
int sys_oldfstat(tcb*);
int sys_oldselect(tcb*);
int sys_oldstat(tcb*);
int sys_open(tcb*);
int sys_openat(tcb*);
int sys_perf_event_open(tcb*);
int sys_personality(tcb*);
int sys_pipe(tcb*);
int sys_pipe2(tcb*);
int sys_poll(tcb*);
int sys_poll(tcb*);
int sys_ppoll(tcb*);
int sys_prctl(tcb*);
int sys_pread(tcb*);
int sys_preadv(tcb*);
int sys_prlimit64(tcb*);
int sys_process_vm_readv(tcb*);
int sys_process_vm_writev(tcb*);
int sys_pselect6(tcb*);
int sys_ptrace(tcb*);
int sys_putpmsg(tcb*); /* TODO: non-Linux, remove? */
int sys_pwrite(tcb*);
int sys_pwritev(tcb*);
int sys_query_module(tcb*);
int sys_quotactl(tcb*);
int sys_read(tcb*);
int sys_readahead(tcb*);
int sys_readdir(tcb*);
int sys_readlink(tcb*);
int sys_readlinkat(tcb*);
int sys_readv(tcb*);
int sys_reboot(tcb*);
int sys_recv(tcb*);
int sys_recvfrom(tcb*);
int sys_recvmmsg(tcb*);
int sys_recvmsg(tcb*);
int sys_remap_file_pages(tcb*);
int sys_removexattr(tcb*);
int sys_renameat(tcb*);
int sys_renameat2(tcb*);
int sys_request_key(tcb*);
int sys_restart_syscall(tcb*);
int sys_rt_sigaction(tcb*);
int sys_rt_sigpending(tcb*);
int sys_rt_sigprocmask(tcb*);
int sys_rt_sigqueueinfo(tcb*);
int sys_rt_sigsuspend(tcb*);
int sys_rt_sigtimedwait(tcb*);
int sys_rt_tgsigqueueinfo(tcb*);
int sys_sched_get_priority_min(tcb*);
int sys_sched_getaffinity(tcb*);
int sys_sched_getparam(tcb*);
int sys_sched_getscheduler(tcb*);
int sys_sched_rr_get_interval(tcb*);
int sys_sched_setaffinity(tcb*);
int sys_sched_setparam(tcb*);
int sys_sched_setscheduler(tcb*);
int sys_select(tcb*);
int sys_semctl(tcb*);
int sys_semget(tcb*);
int sys_semop(tcb*);
int sys_semtimedop(tcb*);
int sys_send(tcb*);
int sys_sendfile(tcb*);
int sys_sendfile64(tcb*);
int sys_sendmmsg(tcb*);
int sys_sendmsg(tcb*);
int sys_sendto(tcb*);
int sys_set_mempolicy(tcb*);
int sys_set_thread_area(tcb*);
int sys_setdomainname(tcb*);
int sys_setfsuid(tcb*);
int sys_setgroups(tcb*);
int sys_setgroups32(tcb*);
int sys_sethostname(tcb*);
int sys_setitimer(tcb*);
int sys_setns(tcb*);
int sys_setpriority(tcb*);
int sys_setresuid(tcb*);
int sys_setreuid(tcb*);
int sys_setrlimit(tcb*);
int sys_setsockopt(tcb*);
int sys_settimeofday(tcb*);
int sys_setuid(tcb*);
int sys_setxattr(tcb*);
int sys_shmat(tcb*);
int sys_shmctl(tcb*);
int sys_shmdt(tcb*);
int sys_shmget(tcb*);
int sys_shutdown(tcb*);
int sys_sigaction(tcb*);
int sys_sigaltstack(tcb*);
int sys_siggetmask(tcb*);
int sys_signal(tcb*);
int sys_signalfd(tcb*);
int sys_signalfd4(tcb*);
int sys_sigpending(tcb*);
int sys_sigprocmask(tcb*);
int sys_sigreturn(tcb*);
int sys_sigsetmask(tcb*);
int sys_sigsuspend(tcb*);
int sys_socket(tcb*);
int sys_socketcall(tcb*);
int sys_socketpair(tcb*);
int sys_splice(tcb*);
int sys_stat(tcb*);
int sys_stat64(tcb*);
int sys_statfs(tcb*);
int sys_statfs64(tcb*);
int sys_stime(tcb*);
int sys_swapon(tcb*);
int sys_symlinkat(tcb*);
int sys_sync_file_range(tcb*);
int sys_sync_file_range2(tcb*);
int sys_sysctl(tcb*);
int sys_sysinfo(tcb*);
int sys_syslog(tcb*);
int sys_tee(tcb*);
int sys_tgkill(tcb*);
int sys_time(tcb*);
int sys_timer_create(tcb*);
int sys_timer_gettime(tcb*);
int sys_timer_settime(tcb*);
int sys_timerfd(tcb*);
int sys_timerfd_create(tcb*);
int sys_timerfd_gettime(tcb*);
int sys_timerfd_settime(tcb*);
int sys_times(tcb*);
int sys_truncate(tcb*);
int sys_truncate64(tcb*);
int sys_umask(tcb*);
int sys_umount2(tcb*);
int sys_uname(tcb*);
int sys_unlinkat(tcb*);
int sys_unshare(tcb*);
int sys_utime(tcb*);
int sys_utimensat(tcb*);
int sys_utimes(tcb*);
int sys_vmsplice(tcb*);
int sys_wait4(tcb*);
int sys_waitid(tcb*);
int sys_waitpid(tcb*);
int sys_write(tcb*);
int sys_writev(tcb*);

/* architecture-specific calls */
#ifdef ALPHA
int osf_statfs(tcb*);
int osf_fstatfs(tcb*);
int sys_osf_getitimer(tcb*);
int sys_osf_getrusage(tcb*);
int sys_osf_gettimeofday(tcb*);
int sys_osf_select(tcb*);
int sys_osf_setitimer(tcb*);
int sys_osf_settimeofday(tcb*);
int sys_osf_utimes(tcb*);
int sys_osf_wait4(tcb*);
#endif

#if defined(ALPHA) || defined(IA64) || defined(SPARC) || defined(SPARC64)
int sys_getpagesize(tcb*);
#endif

#ifdef MIPS
int sys_sysmips(tcb*);
#endif

#if defined M68K || defined SH
int sys_cacheflush(tcb*);
#endif

#if defined OR1K
int sys_or1k_atomic(tcb*);
#endif

#ifdef POWERPC
int sys_subpage_prot(tcb*);
#endif

#ifdef BFIN
int sys_cacheflush(tcb*);
int sys_sram_alloc(tcb*);
#endif

#if defined SPARC || defined SPARC64
#include "sparc/syscall1.h"
int sys_execv(tcb*);
int sys_getmsg(tcb*);
int sys_putmsg(tcb*);
#endif
