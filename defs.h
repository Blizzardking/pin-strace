/*
 * Copyright (c) 1991, 1992 Paul Kranenburg <pk@cs.few.eur.nl>
 * Copyright (c) 1993 Branko Lankester <branko@hacktic.nl>
 * Copyright (c) 1993, 1994, 1995, 1996 Rick Sladkey <jrs@world.std.com>
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

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#ifdef MIPS
# include <sgidefs.h>
# if _MIPS_SIM == _MIPS_SIM_ABI64
#  define LINUX_MIPSN64
# elif _MIPS_SIM == _MIPS_SIM_NABI32
#  define LINUX_MIPSN32
# elif _MIPS_SIM == _MIPS_SIM_ABI32
#  define LINUX_MIPSO32
# else
#  error Unsupported _MIPS_SIM
# endif
#endif

#include <features.h>
#ifdef HAVE_STDBOOL_H
# include <stdbool.h>
#endif
#include <stdint.h>
#include <inttypes.h>
#include <sys/types.h>
#ifdef STDC_HEADERS
# include <stddef.h>
#endif
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
/* Open-coding isprint(ch) et al proved more efficient than calling
 * generalized libc interface. We don't *want* to do non-ASCII anyway.
 */
/* #include <ctype.h> */
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <sys/time.h>
#include <sys/syscall.h>

#if !defined __GNUC__
# define __attribute__(x) /*nothing*/
#endif

#ifndef offsetof
# define offsetof(type, member)	\
	(((char *) &(((type *) NULL)->member)) - ((char *) (type *) NULL))
#endif

#define ARRAY_SIZE(a) \
  ((sizeof(a) / sizeof(*(a))) / \
  static_cast<size_t>(!(sizeof(a) % sizeof(*(a)))))

/* macros */
#ifndef MAX
# define MAX(a, b)		(((a) > (b)) ? (a) : (b))
#endif
#ifndef MIN
# define MIN(a, b)		(((a) < (b)) ? (a) : (b))
#endif


/* Configuration section */
#ifndef DEFAULT_STRLEN
/* default maximum # of bytes printed in `printstr', change with -s switch */
# define DEFAULT_STRLEN	32
#endif
#ifndef DEFAULT_ACOLUMN
# define DEFAULT_ACOLUMN	40	/* default alignment column for results */
#endif



























#define CLAMP(val, min, max) MIN(MAX(min, val), max)

/* Glibc has an efficient macro for sigemptyset
 * (it just does one or two assignments of 0 to internal vector of longs).
 */
#if defined(__GLIBC__) && defined(__sigemptyset) && !defined(sigemptyset)
# define sigemptyset __sigemptyset
#endif

/* Configuration section */
#ifndef DEFAULT_STRLEN
/* default maximum # of bytes printed in `printstr', change with -s switch */
# define DEFAULT_STRLEN	32
#endif
#ifndef DEFAULT_ACOLUMN
# define DEFAULT_ACOLUMN	40	/* default alignment column for results */
#endif
/*
 * Maximum number of args to a syscall.
 *
 * Make sure that all entries in all syscallent.h files have nargs <= MAX_ARGS!
 * linux/<ARCH>/syscallent*.h:
 *	all have nargs <= 6 except mips o32 which has nargs <= 7.
 */
#ifndef MAX_ARGS
# ifdef LINUX_MIPSO32
#  define MAX_ARGS	7
# else
#  define MAX_ARGS	6
# endif
#endif
/* default sorting method for call profiling */
#ifndef DEFAULT_SORTBY
# define DEFAULT_SORTBY "time"
#endif
/*
 * Experimental code using PTRACE_SEIZE can be enabled here.
 * This needs Linux kernel 3.4.x or later to work.
 */
#define USE_SEIZE 1
/* To force NOMMU build, set to 1 */
#define NOMMU_SYSTEM 0
/*
 * Set to 1 to use speed-optimized vfprintf implementation.
 * It results in strace using about 5% less CPU in user space
 * (compared to glibc version).
 * But strace spends a lot of time in kernel space,
 * so overall it does not appear to be a significant win.
 * Thus disabled by default.
 */
#define USE_CUSTOM_PRINTF 0

#ifdef NEED_PTRACE_PROTOTYPE_WORKAROUND
# define ptrace xptrace
# include <sys/ptrace.h>
# undef ptrace
extern long ptrace(int, int, char *, long);
#else
# include <sys/ptrace.h>
#endif

#if defined(POWERPC)
# include <asm/ptrace.h>
#endif

#if defined(TILE)
# include <asm/ptrace.h>  /* struct pt_regs */
#endif

#ifndef ERESTARTSYS
# define ERESTARTSYS    512
#endif
#ifndef ERESTARTNOINTR
# define ERESTARTNOINTR 513
#endif
#ifndef ERESTARTNOHAND
# define ERESTARTNOHAND 514
#endif
#ifndef ERESTART_RESTARTBLOCK
# define ERESTART_RESTARTBLOCK 516
#endif

#if !HAVE_DECL_PTRACE_SETOPTIONS
# define PTRACE_SETOPTIONS	0x4200
#endif
#if !HAVE_DECL_PTRACE_GETEVENTMSG
# define PTRACE_GETEVENTMSG	0x4201
#endif
#if !HAVE_DECL_PTRACE_GETSIGINFO
# define PTRACE_GETSIGINFO	0x4202
#endif

#if !HAVE_DECL_PTRACE_O_TRACESYSGOOD
# define PTRACE_O_TRACESYSGOOD	0x00000001
#endif
#if !HAVE_DECL_PTRACE_O_TRACEFORK
# define PTRACE_O_TRACEFORK	0x00000002
#endif
#if !HAVE_DECL_PTRACE_O_TRACEVFORK
# define PTRACE_O_TRACEVFORK	0x00000004
#endif
#if !HAVE_DECL_PTRACE_O_TRACECLONE
# define PTRACE_O_TRACECLONE	0x00000008
#endif
#if !HAVE_DECL_PTRACE_O_TRACEEXEC
# define PTRACE_O_TRACEEXEC	0x00000010
#endif
#if !HAVE_DECL_PTRACE_O_TRACEEXIT
# define PTRACE_O_TRACEEXIT	0x00000040
#endif

#if !HAVE_DECL_PTRACE_EVENT_FORK
# define PTRACE_EVENT_FORK	1
#endif
#if !HAVE_DECL_PTRACE_EVENT_VFORK
# define PTRACE_EVENT_VFORK	2
#endif
#if !HAVE_DECL_PTRACE_EVENT_CLONE
# define PTRACE_EVENT_CLONE	3
#endif
#if !HAVE_DECL_PTRACE_EVENT_EXEC
# define PTRACE_EVENT_EXEC	4
#endif
#if !HAVE_DECL_PTRACE_EVENT_VFORK_DONE
# define PTRACE_EVENT_VFORK_DONE	5
#endif
#if !HAVE_DECL_PTRACE_EVENT_EXIT
# define PTRACE_EVENT_EXIT	6
#endif

#if !HAVE_DECL_PTRACE_PEEKUSER
# define PTRACE_PEEKUSER PTRACE_PEEKUSR
#endif
#if !HAVE_DECL_PTRACE_POKEUSER
# define PTRACE_POKEUSER PTRACE_POKEUSR
#endif

#undef PTRACE_SEIZE
#define PTRACE_SEIZE		0x4206
#undef PTRACE_INTERRUPT
#define PTRACE_INTERRUPT	0x4207
#undef PTRACE_LISTEN
#define PTRACE_LISTEN		0x4208
#undef PTRACE_EVENT_STOP
#define PTRACE_EVENT_STOP	128

#ifdef ALPHA
# define REG_R0 0
# define REG_A0 16
# define REG_A3 19
# define REG_FP 30
# define REG_PC 64
#endif /* ALPHA */
#ifdef MIPS
# define REG_V0 2
# define REG_A0 4
# define REG_A3 7
# define REG_SP 29
# define REG_EPC 64
#endif /* MIPS */
#ifdef HPPA
# define PT_GR20 (20*4)
# define PT_GR26 (26*4)
# define PT_GR28 (28*4)
# define PT_IAOQ0 (106*4)
# define PT_IAOQ1 (107*4)
#endif /* HPPA */
#ifdef SH64
   /* SH64 Linux - this code assumes the following kernel API for system calls:
          PC           Offset 0
          System Call  Offset 16 (actually, (syscall no.) | (0x1n << 16),
                       where n = no. of parameters.
          Other regs   Offset 24+

          On entry:    R2-7 = parameters 1-6 (as many as necessary)
          On return:   R9   = result. */

   /* Offset for peeks of registers */
# define REG_OFFSET         (24)
# define REG_GENERAL(x)     (8*(x)+REG_OFFSET)
# define REG_PC             (0*8)
# define REG_SYSCALL        (2*8)
#endif /* SH64 */
#ifdef AARCH64
struct arm_pt_regs {
        int uregs[18];
};
# define ARM_cpsr       uregs[16]
# define ARM_pc         uregs[15]
# define ARM_lr         uregs[14]
# define ARM_sp         uregs[13]
# define ARM_ip         uregs[12]
# define ARM_fp         uregs[11]
# define ARM_r10        uregs[10]
# define ARM_r9         uregs[9]
# define ARM_r8         uregs[8]
# define ARM_r7         uregs[7]
# define ARM_r6         uregs[6]
# define ARM_r5         uregs[5]
# define ARM_r4         uregs[4]
# define ARM_r3         uregs[3]
# define ARM_r2         uregs[2]
# define ARM_r1         uregs[1]
# define ARM_r0         uregs[0]
# define ARM_ORIG_r0    uregs[17]
#endif /* AARCH64 */

#if defined(SPARC) || defined(SPARC64)
/* Indexes into the pt_regs.u_reg[] array -- UREG_XX from kernel are all off
 * by 1 and use Ix instead of Ox.  These work for both 32 and 64 bit Linux. */
# define U_REG_G1 0
# define U_REG_O0 7
# define U_REG_O1 8
# define PERSONALITY0_WORDSIZE 4
# define PERSONALITY1_WORDSIZE 4
# if defined(SPARC64)
#  include <asm/psrcompat.h>
#  define SUPPORTED_PERSONALITIES 3
#  define PERSONALITY2_WORDSIZE 8
# else
#  include <asm/psr.h>
#  define SUPPORTED_PERSONALITIES 2
# endif /* SPARC64 */
#endif /* SPARC[64] */

#ifdef X86_64
# define SUPPORTED_PERSONALITIES 3
# define PERSONALITY0_WORDSIZE 8
# define PERSONALITY1_WORDSIZE 4
# define PERSONALITY2_WORDSIZE 4
#endif

#ifdef X32
# define SUPPORTED_PERSONALITIES 2
# define PERSONALITY0_WORDSIZE 4
# define PERSONALITY1_WORDSIZE 4
#endif

#ifdef ARM
/* one personality */
#endif

#ifdef AARCH64
/* The existing ARM personality, then AArch64 */
# define SUPPORTED_PERSONALITIES 2
# define PERSONALITY0_WORDSIZE 4
# define PERSONALITY1_WORDSIZE 8
# define DEFAULT_PERSONALITY 1
#endif

#ifdef POWERPC64
# define SUPPORTED_PERSONALITIES 2
# define PERSONALITY0_WORDSIZE 8
# define PERSONALITY1_WORDSIZE 4
#endif

#ifdef TILE
# define SUPPORTED_PERSONALITIES 2
# define PERSONALITY0_WORDSIZE 8
# define PERSONALITY1_WORDSIZE 4
# ifdef __tilepro__
#  define DEFAULT_PERSONALITY 1
# endif
#endif

#ifndef SUPPORTED_PERSONALITIES
# define SUPPORTED_PERSONALITIES 1
#endif
#ifndef DEFAULT_PERSONALITY
# define DEFAULT_PERSONALITY 0
#endif
#ifndef PERSONALITY0_WORDSIZE
# define PERSONALITY0_WORDSIZE SIZEOF_LONG
#endif

#if defined(I386) || defined(X86_64)
extern uint32_t *const i386_esp_ptr;
#elif defined(IA64)
extern bool ia64_ia32mode;
#elif defined(SPARC) || defined(SPARC64)
extern struct pt_regs sparc_regs;
#elif defined(ARM)
extern struct pt_regs arm_regs;
#elif defined(TILE)
extern struct pt_regs tile_regs;
#elif defined(POWERPC)
extern struct pt_regs ppc_regs;
#endif


struct xlat {
    int val;
    const char *str;
};

#define XLAT(x) { x, #x }
#define XLAT_END { 0, NULL }

extern const struct xlat open_mode_flags[];
extern const struct xlat addrfams[];
extern const struct xlat struct_user_offsets[];
extern const struct xlat open_access_modes[];
extern const struct xlat whence_codes[];

/* Format of syscall return values */
#define RVAL_DECIMAL	000	/* decimal format */
#define RVAL_HEX	001	/* hex format */
#define RVAL_OCTAL	002	/* octal format */
#define RVAL_UDECIMAL	003	/* unsigned decimal format */
#if defined(LINUX_MIPSN32) || defined(X32)
# if 0 /* unused so far */
#  define RVAL_LDECIMAL	004	/* long decimal format */
#  define RVAL_LHEX	005	/* long hex format */
#  define RVAL_LOCTAL	006	/* long octal format */
# endif
# define RVAL_LUDECIMAL	007	/* long unsigned decimal format */
#endif
#define RVAL_FD		010	/* file descriptor */
#define RVAL_MASK	017	/* mask for these values */

#define RVAL_STR	020	/* Print `auxstr' field after return val */
#define RVAL_NONE	040	/* Print nothing */

#define TRACE_FILE	001	/* Trace file-related syscalls. */
#define TRACE_IPC	002	/* Trace IPC-related syscalls. */
#define TRACE_NETWORK	004	/* Trace network-related syscalls. */
#define TRACE_PROCESS	010	/* Trace process-related syscalls. */
#define TRACE_SIGNAL	020	/* Trace signal-related syscalls. */
#define TRACE_DESC	040	/* Trace file descriptor-related syscalls. */
#define TRACE_MEMORY	0100	/* Trace memory mapping-related syscalls. */
#define SYSCALL_NEVER_FAILS	0200	/* Syscall is always successful. */
#define STACKTRACE_INVALIDATE_CACHE 0400  /* Trigger proc/maps cache updating */
#define STACKTRACE_CAPTURE_ON_ENTER 01000 /* Capture stacktrace on "entering" stage */



typedef enum {
	CFLAG_NONE = 0,
	CFLAG_ONLY_STATS,
	CFLAG_BOTH
} cflag_t;
extern cflag_t cflag;
extern bool debug_flag;
extern bool Tflag;
extern bool iflag;
extern bool count_wallclock;
extern unsigned int qflag;
extern bool not_failing_only;
extern unsigned int show_fd_path;
extern bool hide_log_until_execve;
/* are we filtering traces based on paths? */
extern const char **paths_selected;
#define tracing_paths (paths_selected != NULL)
extern bool need_fork_exec_workarounds;
extern unsigned xflag;
extern unsigned followfork;
#ifdef USE_LIBUNWIND
/* if this is true do the stack trace for every system call */
extern bool stack_trace_enabled;
#endif
extern unsigned ptrace_setoptions;
extern unsigned max_strlen;
extern unsigned os_release;

#undef KERNEL_VERSION
#define KERNEL_VERSION(a,b,c) (((a) << 16) + ((b) << 8) + (c))

enum bitness_t { BITNESS_CURRENT = 0, BITNESS_32 };

void error_msg(const char *fmt, ...) __attribute__ ((format(printf, 1, 2)));
void perror_msg(const char *fmt, ...) __attribute__ ((format(printf, 1, 2)));
void error_msg_and_die(const char *fmt, ...) __attribute__ ((noreturn, format(printf, 1, 2)));
void perror_msg_and_die(const char *fmt, ...) __attribute__ ((noreturn, format(printf, 1, 2)));
void die_out_of_memory(void) __attribute__ ((noreturn));

# define strace_vfprintf vfprintf

#ifdef __STDC__
#define P(args) args
#else
#define P(args) ()
#endif

#define entering(tcp)	1
#define exiting(tcp)	1
#define syserror(tcp)	((tcp)->u_error != 0)
#define verbose(tcp) 1
#define abbrev(tcp) 1	
#define filtered(tcp)  0
/*
 * Maximum number of args to a syscall.
 *
 * Make sure that all entries in all syscallent.h files have nargs <= MAX_ARGS!
 * linux/<ARCH>/syscallent*.h:
 *	all have nargs <= 6 except mips o32 which has nargs <= 7.
 */
#ifndef MAX_ARGS
# ifdef LINUX_MIPSO32
#  define MAX_ARGS	7
# else
#  define MAX_ARGS	6
# endif
#endif

struct tcb;

typedef struct sysent {
	unsigned nargs;
	int	sys_flags;
	int	(*sys_func)(struct tcb*);
	const char *sys_name;
} struct_sysent;

typedef struct ioctlent {
	const char *doth;
	const char *symbol;
	unsigned long code;
} struct_ioctlent;

struct tcb {
    int pid;
	int u_error;		/* Error code */
	long scno;		/* System call number */
	long u_arg[MAX_ARGS];	/* System call arguments */
    long u_rval;		/* Return value */
    FILE *outf;
    
	int curcol;		/* Output column for this process */
    const char *auxstr;	/* Auxiliary info from syscall (see RVAL_STR) */
	const struct_sysent *s_ent; /* sysent[scno] or dummy struct for bad scno */
	struct timeval stime;	/* System time usage as of last process wait */
	struct timeval dtime;	/* Delta for system time usage */
	struct timeval etime;	/* Syscall entry time */
				/* Support for tracing forked processes: */
	long inst[2];		/* Saved clone args (badly named) */
};

/* TCB flags */
/* We have attached to this process, but did not see it stopping yet */
#define TCB_STARTUP		0x01
#define TCB_IGNORE_ONE_SIGSTOP	0x02	/* Next SIGSTOP is to be ignored */

extern unsigned current_wordsize;


void printleader(struct tcb *);
void line_ended(void);
void tabto(void);
void tprintf(const char *fmt, ...) __attribute__ ((format (printf, 1, 2)));
void tprints(const char *str);

# define set_personality(personality) ((void)0)
# define current_personality 0

int umoven(struct tcb *, long, int, char *);
#define umove(pid, addr, objp)	\
	umoven((pid), (addr), sizeof(*(objp)), (char *) (objp))
int umovestr(struct tcb *, long, int, char *);
int upeek(int pid, long, long *);
#if defined(SPARC) || defined(SPARC64) || defined(IA64) || defined(SH)
long getrval2(struct tcb *);
#endif
/*
 * On Linux, "setbpt" is a misnomer: we don't set a breakpoint
 * (IOW: no poking in user's text segment),
 * instead we change fork/vfork/clone into clone(CLONE_PTRACE).
 * On newer kernels, we use PTRACE_O_TRACECLONE/TRACE[V]FORK instead.
 */
int setbpt(struct tcb *);
int clearbpt(struct tcb *);

const char *signame(int);
void pathtrace_select(const char *);
int pathtrace_match(struct tcb *);
int getfdpath(struct tcb *, int, char *, unsigned);

const char *xlookup(const struct xlat *, int); 

int string_to_uint(const char *str);
int string_quote(const char *, char *, long, int);
int next_set_bit(const void *bit_array, unsigned cur_bit, unsigned size_bits);

/* a refers to the lower numbered u_arg,
 * b refers to the higher numbered u_arg
 */
#if HAVE_LITTLE_ENDIAN_LONG_LONG
# define LONG_LONG(a,b) \
	((long long)((unsigned long long)(unsigned)(a) | ((unsigned long long)(b)<<32)))
#else
# define LONG_LONG(a,b) \
	((long long)((unsigned long long)(unsigned)(b) | ((unsigned long long)(a)<<32)))
#endif
int printllval(struct tcb *, const char *, int);

void printxval(const struct xlat *, int, const char *);
int printargs(struct tcb *);
int printargs_lu(struct tcb *);
int printargs_ld(struct tcb *);
void addflags(const struct xlat *, int);
int printflags(const struct xlat *, int, const char *);
const char *sprintflags(const char *, const struct xlat *, int);
void dumpiov(struct tcb *, int, long);
void dumpstr(struct tcb *, long, int);
void printstr(struct tcb *, long, long);
void printnum(struct tcb *, long, const char *);
void printnum_int(struct tcb *, long, const char *);
void printpath(struct tcb *, long);
void printpathn(struct tcb *, long, int);

#define TIMESPEC_TEXT_BUFSIZE (sizeof(long)*3 * 2 + sizeof("{%u, %u}"))
#define TIMEVAL_TEXT_BUFSIZE  TIMESPEC_TEXT_BUFSIZE
void printtv_bitness(struct tcb *, long, enum bitness_t, int);
#define printtv(tcp, addr)	\
	printtv_bitness((tcp), (addr), BITNESS_CURRENT, 0)
#define printtv_special(tcp, addr)	\
	printtv_bitness((tcp), (addr), BITNESS_CURRENT, 1)
char *sprinttv(char *, struct tcb *, long, enum bitness_t, int special);
void print_timespec(struct tcb *, long);
void sprint_timespec(char *, struct tcb *, long);
#ifdef HAVE_SIGINFO_T
void printsiginfo(siginfo_t *, int);
void printsiginfo_at(struct tcb *tcp, long addr);
#endif
void printfd(struct tcb *, int);
void print_dirfd(struct tcb *, int);
void printsock(struct tcb *, long, int);
void print_sock_optmgmt(struct tcb *, long, int);
void printrusage(struct tcb *, long);
#ifdef ALPHA
void printrusage32(struct tcb *, long);
#endif
void printuid(const char *, unsigned long);
void print_sigset_addr_len(struct tcb *, long, long);
void printsignal(int);
void tprint_iov(struct tcb *, unsigned long, unsigned long, int decode_iov);
void tprint_iov_upto(struct tcb *, unsigned long, unsigned long, int decode_iov, unsigned long);
void tprint_open_modes(mode_t);
const char *sprint_open_modes(mode_t);
void print_loff_t(struct tcb *, long);

const struct_ioctlent *ioctl_lookup(long);
const struct_ioctlent *ioctl_next_match(const struct_ioctlent *);
int ioctl_decode(struct tcb *, long, long);
int term_ioctl(struct tcb *, long, long);
int sock_ioctl(struct tcb *, long, long);
int proc_ioctl(struct tcb *, int, int);
int rtc_ioctl(struct tcb *, long, long);
int scsi_ioctl(struct tcb *, long, long);
int block_ioctl(struct tcb *, long, long);
int mtd_ioctl(struct tcb *, long, long);
int ubi_ioctl(struct tcb *, long, long);
int loop_ioctl(struct tcb *, long, long);
int ptp_ioctl(struct tcb *, long, long);

int tv_nz(const struct timeval *);
int tv_cmp(const struct timeval *, const struct timeval *);
double tv_float(const struct timeval *);
void tv_add(struct timeval *, const struct timeval *, const struct timeval *);
void tv_sub(struct timeval *, const struct timeval *, const struct timeval *);
void tv_mul(struct timeval *, const struct timeval *, int);
void tv_div(struct timeval *, const struct timeval *, int);

#ifdef USE_LIBUNWIND
void unwind_init(void);
void unwind_tcb_init(struct tcb *tcp);
void unwind_tcb_fin(struct tcb *tcp);
void unwind_cache_invalidate(struct tcb* tcp);
void unwind_print_stacktrace(struct tcb* tcp);
void unwind_capture_stacktrace(struct tcb* tcp);
#endif

/* In many, many places we play fast and loose and use
 * tprintf("%d", (int) tcp->u_arg[N]) to print fds, pids etc.
 * We probably need to use widen_to_long() instead:
 */
#if SUPPORTED_PERSONALITIES > 1 && SIZEOF_LONG > 4
# define widen_to_long(v) (current_wordsize == 4 ? (long)(int32_t)(v) : (long)(v))
#else
# define widen_to_long(v) ((long)(v))
#endif

extern const struct_sysent sysent0[];
extern const char *const errnoent0[];
extern const char *const signalent0[];
extern const struct_ioctlent ioctlent0[];

extern const struct_sysent *sysent;
extern const char *const *errnoent;
extern const char *const *signalent;
extern const struct_ioctlent *ioctlent;

extern unsigned nsyscalls;
extern unsigned nerrnos;
extern unsigned nsignals;
extern unsigned nioctlents;
extern unsigned num_quals;

/*
 * If you need non-NULL sysent[scno].sys_func and sysent[scno].sys_name
 */
#define SCNO_IS_VALID(scno) \
	((unsigned long)(scno) < nsyscalls && sysent[scno].sys_func)

/* Only ensures that sysent[scno] isn't out of range */
#define SCNO_IN_RANGE(scno) \
	((unsigned long)(scno) < nsyscalls)
