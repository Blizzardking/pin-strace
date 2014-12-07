/*BEGIN_LEGAL 
Intel Open Source License 

Copyright (c) 2002-2014 Intel Corporation. All rights reserved.
 
Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

Redistributions of source code must retain the above copyright notice,
this list of conditions and the following disclaimer.  Redistributions
in binary form must reproduce the above copyright notice, this list of
conditions and the following disclaimer in the documentation and/or
other materials provided with the distribution.  Neither the name of
the Intel Corporation nor the names of its contributors may be used to
endorse or promote products derived from this software without
specific prior written permission.
 
THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE INTEL OR
ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
END_LEGAL */
/*
 *  This file contains an ISA-portable PIN tool for tracing system calls
 */

#include "pin.H"
#include "defs.h"

#ifdef __STDC__
#include <stdarg.h>
#define VA_START(a, b) va_start(a, b)
#else
#include <varargs.h>
#define VA_START(a, b) va_start(a)
#endif

#include <sys/user.h>
#include <sys/param.h>
#include <fcntl.h>
#include <sys/uio.h>

#include "syscall.h"
#include <sys/resource.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <pwd.h>
#include <grp.h>
#include <dirent.h>
#include <sys/utsname.h>
#ifdef HAVE_PRCTL
# include <sys/prctl.h>
#endif
#include <sys/ptrace.h>
#if defined(IA64)
# include <asm/ptrace_offsets.h>
#endif
/* In some libc, these aren't declared. Do it ourself: */
extern char **environ;
extern int optind;
extern char *optarg;

#ifdef USE_LIBUNWIND
/* if this is true do the stack trace for every system call */
bool stack_trace_enabled = false;
#endif

#if defined __NR_tkill
# define my_tkill(tid, sig) syscall(__NR_tkill, (tid), (sig))
#else
   /* kill() may choose arbitrarily the target task of the process group
      while we later wait on a that specific TID.  PID process waits become
      TID task specific waits for a process under ptrace(2).  */
# warning "tkill(2) not available, risk of strace hangs!"
# define my_tkill(tid, sig) kill((tid), (sig))
#endif

/* Glue for systems without a MMU that cannot provide fork() */
#if !defined(HAVE_FORK)
# undef NOMMU_SYSTEM
# define NOMMU_SYSTEM 1
#endif
#if NOMMU_SYSTEM
# define fork() vfork()
#endif

cflag_t cflag = CFLAG_NONE;
unsigned int followfork = 0;
unsigned int ptrace_setoptions = 0;
unsigned int xflag = 0;
bool need_fork_exec_workarounds = 0;
bool debug_flag = 0;
bool Tflag = 0;
bool iflag = 0;
bool count_wallclock = 0;
unsigned int qflag = 0;
/* Which WSTOPSIG(status) value marks syscall traps? */
static unsigned int syscall_trap_sig __attribute__ ((unused)) = SIGTRAP;
static unsigned int tflag  __attribute__ ((unused)) = 0;
static bool rflag  __attribute__ ((unused)) = 0;
static bool print_pid_pfx  __attribute__ ((unused)) = 0;

/* -I n */
enum {
    INTR_NOT_SET        = 0,
    INTR_ANYWHERE       = 1, /* don't block/ignore any signals */
    INTR_WHILE_WAIT     = 2, /* block fatal signals while decoding syscall. default */
    INTR_NEVER          = 3, /* block fatal signals. default if '-o FILE PROG' */
    INTR_BLOCK_TSTP_TOO = 4, /* block fatal signals and SIGTSTP (^Z) */
    NUM_INTR_OPTS
};
static int opt_intr __attribute__ ((unused));
/* We play with signal mask only if this mode is active: */
#define interactive (opt_intr == INTR_WHILE_WAIT)

/*
 * daemonized_tracer supports -D option.
 * With this option, strace forks twice.
 * Unlike normal case, with -D *grandparent* process exec's,
 * becoming a traced process. Child exits (this prevents traced process
 * from having children it doesn't expect to have), and grandchild
 * attaches to grandparent similarly to strace -p PID.
 * This allows for more transparent interaction in cases
 * when process and its parent are communicating via signals,
 * wait() etc. Without -D, strace process gets lodged in between,
 * disrupting parent<->child link.
 */
static bool daemonized_tracer  __attribute__ ((unused))  = 0;

#if USE_SEIZE
static int post_attach_sigstop  __attribute__ ((unused)) = TCB_IGNORE_ONE_SIGSTOP;
# define use_seize (post_attach_sigstop == 0)
#else
# define post_attach_sigstop TCB_IGNORE_ONE_SIGSTOP
# define use_seize 0
#endif

/* Sometimes we want to print only succeeding syscalls. */
bool not_failing_only = 0;

/* Show path associated with fd arguments */
unsigned int show_fd_path = 0;

static bool detach_on_execve  __attribute__ ((unused)) = 0;
/* Are we "strace PROG" and need to skip detach on first execve? */
static bool skip_one_b_execve  __attribute__ ((unused)) = 0;
/* Are we "strace PROG" and need to hide everything until execve? */
bool hide_log_until_execve = 0;

static int exit_code  __attribute__ ((unused)) = 0;
static int strace_child  __attribute__ ((unused)) = 0;
static int strace_tracer_pid  __attribute__ ((unused)) = 0;

static char *username __attribute__ ((unused)) = NULL;
static uid_t run_uid  __attribute__ ((unused)) ;
static gid_t run_gid  __attribute__ ((unused)) ;
/* Define these shorthand notations to simplify the syscallent files. */
#define TD TRACE_DESC
#define TF TRACE_FILE
#define TI TRACE_IPC
#define TN TRACE_NETWORK
#define TP TRACE_PROCESS
#define TS TRACE_SIGNAL
#define TM TRACE_MEMORY
#define NF SYSCALL_NEVER_FAILS
#define MA MAX_ARGS
#define SI STACKTRACE_INVALIDATE_CACHE
#define SE STACKTRACE_CAPTURE_ON_ENTER
const struct_sysent sysent0[] = {
#include "syscallent.h"
};
/* Now undef them since short defines cause wicked namespace pollution. */
#undef TD
#undef TF
#undef TI
#undef TN
#undef TP
#undef TS
#undef TM
#undef NF
#undef MA
#undef SI
#undef SE
const char *const errnoent0[] = {
#include "errnoent.h"
};
const char *const signalent0[] = {
#include "signalent.h"
};
const struct_ioctlent ioctlent0[] = {
#include "ioctlent.h"
};

unsigned nsyscalls0 = ARRAY_SIZE(sysent0);
unsigned nerrnos0 = ARRAY_SIZE(errnoent0);
unsigned nsignals0 = ARRAY_SIZE(signalent0);
unsigned nioctlents0 = ARRAY_SIZE(ioctlent0);
unsigned nsyscalls = nsyscalls0;
unsigned nerrnos = nerrnos0;
unsigned nsignals = nsignals0;
unsigned nioctlents = nioctlents0;
unsigned num_quals = nsyscalls;
const struct_sysent *sysent = sysent0;
const char *const *errnoent = errnoent0;
const char *const *signalent = signalent0;
const struct_ioctlent *ioctlent = ioctlent0;
static const char *outfname = "mystrace.out";
unsigned int max_strlen = DEFAULT_STRLEN;
static int acolumn = DEFAULT_ACOLUMN;
static char *acolumn_spaces;
static const char *progname;
unsigned os_release; /* generated from uname()'s u.release */
static struct tcb current_tcp;

unsigned current_wordsize = 4;
static char* undefined_scno_name(struct tcb *tcp);
// Print syscall number and arguments
VOID SysBefore(ADDRINT ip, ADDRINT num, ADDRINT arg0, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4, ADDRINT arg5)
{
#if defined(TARGET_LINUX) && defined(TARGET_IA32) 
    // On ia32 Linux, there are only 5 registers for passing system call arguments, 
    // but mmap needs 6. For mmap on ia32, the first argument to the system call 
    // is a pointer to an array of the 6 arguments
    if (num == SYS_mmap)
    {
        ADDRINT * mmapArgs = reinterpret_cast<ADDRINT *>(arg0);
        arg0 = mmapArgs[0];
        arg1 = mmapArgs[1];
        arg2 = mmapArgs[2];
        arg3 = mmapArgs[3];
        arg4 = mmapArgs[4];
        arg5 = mmapArgs[5];
    }
#endif
    tprintf("syscall_num(%ld): ", (unsigned long) num);
    static struct tcb *tcp = &current_tcp;
    tcp->pid = (int)PIN_GetPid();
    tcp->scno = num; 
    tcp->u_arg[0] = arg0;
    tcp->u_arg[1] = arg1;
    tcp->u_arg[2] = arg2;
    tcp->u_arg[3] = arg3;
    tcp->u_arg[4] = arg4;
    tcp->u_arg[5] = arg5;
    if (SCNO_IS_VALID(tcp->scno)) {
		tcp->s_ent = &sysent[tcp->scno];
	} else {
		static const struct_sysent unknown = {
			.nargs = MAX_ARGS,
			.sys_flags = 0,
			.sys_func = printargs,
			.sys_name = "unknown", /* not used */
		};
		tcp->s_ent = &unknown;
	}
    if (tcp->s_ent == NULL)
		tprintf("%s(", undefined_scno_name(tcp));
	else
		tprintf("%s(", tcp->s_ent->sys_name);

    tcp->s_ent->sys_func(tcp); 

}

// Print the return value of the system call
VOID SysAfter(ADDRINT ret)
{
    tprintf(") =  0x%lx\n", (unsigned long)ret);
    line_ended();
}

VOID SyscallEntry(THREADID threadIndex, CONTEXT *ctxt, SYSCALL_STANDARD std, VOID *v)
{
    SysBefore(PIN_GetContextReg(ctxt, REG_INST_PTR),
        PIN_GetSyscallNumber(ctxt, std),
        PIN_GetSyscallArgument(ctxt, std, 0),
        PIN_GetSyscallArgument(ctxt, std, 1),
        PIN_GetSyscallArgument(ctxt, std, 2),
        PIN_GetSyscallArgument(ctxt, std, 3),
        PIN_GetSyscallArgument(ctxt, std, 4),
        PIN_GetSyscallArgument(ctxt, std, 5));
}

VOID SyscallExit(THREADID threadIndex, CONTEXT *ctxt, SYSCALL_STANDARD std, VOID *v)
{
    SysAfter(PIN_GetSyscallReturn(ctxt, std));
}

// Is called for every instruction and instruments syscalls
VOID Instruction(INS ins, VOID *v)
{
    // For O/S's (Mac) that don't support PIN_AddSyscallEntryFunction(),
    // instrument the system call instruction.

    if (INS_IsSyscall(ins) && INS_HasFallThrough(ins))
    {
        // Arguments and syscall number is only available before
        INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(SysBefore),
                       IARG_INST_PTR, IARG_SYSCALL_NUMBER,
                       IARG_SYSARG_VALUE, 0, IARG_SYSARG_VALUE, 1,
                       IARG_SYSARG_VALUE, 2, IARG_SYSARG_VALUE, 3,
                       IARG_SYSARG_VALUE, 4, IARG_SYSARG_VALUE, 5,
                       IARG_END);

        // return value only available after
        INS_InsertCall(ins, IPOINT_AFTER, AFUNPTR(SysAfter),
                       IARG_SYSRET_VALUE,
                       IARG_END);
    }
}

VOID Fini(INT32 code, VOID *v)
{
    tprintf("+++ exited with %d +++\n", code);
    fclose(current_tcp.outf);
}

/* ===================================================================== */
/* Print Help Message                                                    */
/* ===================================================================== */

INT32 Usage()
{
    PIN_ERROR("This tool prints a log of system calls" 
                + KNOB_BASE::StringKnobSummary() + "\n");
    return -1;
}

void
tprintf(const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	int n = strace_vfprintf(current_tcp.outf, fmt, args);
	if (n < 0) {
		if (current_tcp.outf != stderr)
			perror_msg("%s", outfname);
	} else
		current_tcp.curcol += n;
	va_end(args);
}

#ifndef HAVE_FPUTS_UNLOCKED
# define fputs_unlocked fputs
#endif

void
tprints(const char *str)
{
	int n = fputs_unlocked(str, current_tcp.outf);
	if (n >= 0) {
		current_tcp.curcol += strlen(str);
		return;
	}
	if (current_tcp.outf != stderr)
		perror_msg("%s", outfname);
}

void
line_ended(void)
{
	current_tcp.curcol = 0;
	fflush(current_tcp.outf);
}

void
tabto(void)
{
	if (current_tcp.curcol < acolumn)
		tprints(acolumn_spaces + current_tcp.curcol);
}

void
printleader(struct tcb *tcp)
{
	current_tcp.curcol = 0;
}

static void die(void) __attribute__ ((noreturn));
static void die(void)
{
	exit(1);
}

static void verror_msg(int err_no, const char *fmt, va_list p)
{
	char *msg;

	fflush(NULL);

	/* We want to print entire message with single fprintf to ensure
	 * message integrity if stderr is shared with other programs.
	 * Thus we use vasprintf + single fprintf.
	 */
	msg = NULL;
	if (vasprintf(&msg, fmt, p) >= 0) {
		if (err_no)
			fprintf(stderr, "%s: %s: %s\n", progname, msg, strerror(err_no));
		else
			fprintf(stderr, "%s: %s\n", progname, msg);
		free(msg);
	} else {
		/* malloc in vasprintf failed, try it without malloc */
		fprintf(stderr, "%s: ", progname);
		vfprintf(stderr, fmt, p);
		if (err_no)
			fprintf(stderr, ": %s\n", strerror(err_no));
		else
			putc('\n', stderr);
	}
	/* We don't switch stderr to buffered, thus fprintf(stderr)
	 * always flushes its output and this is not necessary: */
	/* fflush(stderr); */
}

void error_msg(const char *fmt, ...)
{
	va_list p;
	va_start(p, fmt);
	verror_msg(0, fmt, p);
	va_end(p);
}

void error_msg_and_die(const char *fmt, ...)
{
	va_list p;
	va_start(p, fmt);
	verror_msg(0, fmt, p);
	die();
}

void perror_msg(const char *fmt, ...)
{
	va_list p;
	va_start(p, fmt);
	verror_msg(errno, fmt, p);
	va_end(p);
}

void perror_msg_and_die(const char *fmt, ...)
{
	va_list p;
	va_start(p, fmt);
	verror_msg(errno, fmt, p);
	die();
}

void die_out_of_memory(void)
{
	static bool recursed = 0;
	if (recursed)
		exit(1);
	recursed = 1;
	error_msg_and_die("Out of memory");
}

# define shuffle_scno(scno) ((long)(scno))

static char*
undefined_scno_name(struct tcb *tcp)
{
	static char buf[sizeof("syscall_%lu") + sizeof(long)*3];

	sprintf(buf, "syscall_%lu", shuffle_scno(tcp->scno));
	return buf;
}

static unsigned
get_os_release(void)
{
	unsigned rel;
	const char *p;
	struct utsname u;
	if (uname(&u) < 0)
		perror_msg_and_die("uname");
	/* u.release has this form: "3.2.9[-some-garbage]" */
	rel = 0;
	p = u.release;
	for (;;) {
		if (!(*p >= '0' && *p <= '9'))
			error_msg_and_die("Bad OS release string: '%s'", u.release);
		/* Note: this open-codes KERNEL_VERSION(): */
		rel = (rel << 8) | atoi(p);
		if (rel >= KERNEL_VERSION(1,0,0))
			break;
		while (*p >= '0' && *p <= '9')
			p++;
		if (*p != '.') {
			if (rel >= KERNEL_VERSION(0,1,0)) {
				/* "X.Y-something" means "X.Y.0" */
				rel <<= 8;
				break;
			}
			error_msg_and_die("Bad OS release string: '%s'", u.release);
		}
		p++;
	}
	return rel;
}

/* ===================================================================== */
/* Main                                                                  */
/* ===================================================================== */

int main(int argc, char *argv[])
{
    if (PIN_Init(argc, argv)) return Usage();

    current_tcp.outf = fopen(outfname, "w");
    acolumn_spaces = (char *)malloc(acolumn + 1);
	if (!acolumn_spaces)
		die_out_of_memory();
	memset(acolumn_spaces, ' ', acolumn);
	acolumn_spaces[acolumn] = '\0';
    fprintf(stderr, "this is HAVE_CONFIG_H: %d",HAVE_CONFIG_H);
    progname = argv[1] ? argv[1] : "strace";
    os_release = get_os_release();

    INS_AddInstrumentFunction(Instruction, 0);
    PIN_AddSyscallEntryFunction(SyscallEntry, 0);
    PIN_AddSyscallExitFunction(SyscallExit, 0);

    PIN_AddFiniFunction(Fini, 0);

    // Never returns
    PIN_StartProgram();
    
    return 0;
}

