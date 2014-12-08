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
#include <stdarg.h>
#include <sys/param.h>
#include <fcntl.h>
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
#if defined(IA64)
# include <asm/ptrace_offsets.h>
#endif
#include "syscall.h"
/* In some libc, these aren't declared. Do it ourself: */
extern char **environ;
extern int optind;
extern char *optarg;


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

unsigned int max_strlen = DEFAULT_STRLEN;
static int acolumn = DEFAULT_ACOLUMN;
static char *acolumn_spaces;

static const char *outfname = "mystrace.out";
/* If -ff, points to stderr. Else, it's our common output log */
static FILE *shared_log;

struct tcb *printing_tcp = NULL;
static struct tcb *current_tcp;

static struct tcb **tcbtab;
static unsigned int nprocs, tcbtabsize;
static const char *progname;

unsigned os_release; /* generated from uname()'s u.release */

static void interrupt(int sig);
static sigset_t empty_set, blocked_set;

#ifdef HAVE_SIG_ATOMIC_T
static volatile sig_atomic_t interrupted;
#else
static volatile int interrupted;
#endif

#ifndef HAVE_STRERROR

#if !HAVE_DECL_SYS_ERRLIST
extern int sys_nerr;
extern char *sys_errlist[];
#endif

const char *
strerror(int err_no)
{
	static char buf[sizeof("Unknown error %d") + sizeof(int)*3];

	if (err_no < 1 || err_no >= sys_nerr) {
		sprintf(buf, "Unknown error %d", err_no);
		return buf;
	}
	return sys_errlist[err_no];
}

#endif /* HAVE_STERRROR */

static void
usage(FILE *ofp, int exitval)
{
	fprintf(ofp, "\
usage: strace [-CdffhiqrtttTvVxxy] [-I n] [-e expr]...\n\
              [-a column] [-o file] [-s strsize] [-P path]...\n\
              -p pid... / [-D] [-E var=val]... [-u username] PROG [ARGS]\n\
   or: strace -c[df] [-I n] [-e expr]... [-O overhead] [-S sortby]\n\
              -p pid... / [-D] [-E var=val]... [-u username] PROG [ARGS]\n\
-c -- count time, calls, and errors for each syscall and report summary\n\
-C -- like -c but also print regular output\n\
-w -- summarise syscall latency (default is system time)\n\
-d -- enable debug output to stderr\n\
-D -- run tracer process as a detached grandchild, not as parent\n\
-f -- follow forks, -ff -- with output into separate files\n\
-i -- print instruction pointer at time of syscall\n\
-q -- suppress messages about attaching, detaching, etc.\n\
-r -- print relative timestamp, -t -- absolute timestamp, -tt -- with usecs\n\
-T -- print time spent in each syscall\n\
-v -- verbose mode: print unabbreviated argv, stat, termios, etc. args\n\
-x -- print non-ascii strings in hex, -xx -- print all strings in hex\n\
-y -- print paths associated with file descriptor arguments\n\
-h -- print help message, -V -- print version\n\
-a column -- alignment COLUMN for printing syscall results (default %d)\n\
-b execve -- detach on this syscall\n\
-e expr -- a qualifying expression: option=[!]all or option=[!]val1[,val2]...\n\
   options: trace, abbrev, verbose, raw, signal, read, write\n\
-I interruptible --\n\
   1: no signals are blocked\n\
   2: fatal signals are blocked while decoding syscall (default)\n\
   3: fatal signals are always blocked (default if '-o FILE PROG')\n\
   4: fatal signals and SIGTSTP (^Z) are always blocked\n\
      (useful to make 'strace -o FILE PROG' not stop on ^Z)\n\
-o file -- send trace output to FILE instead of stderr\n\
-O overhead -- set overhead for tracing syscalls to OVERHEAD usecs\n\
-p pid -- trace process with process id PID, may be repeated\n\
-s strsize -- limit length of print strings to STRSIZE chars (default %d)\n\
-S sortby -- sort syscall counts by: time, calls, name, nothing (default %s)\n\
-u username -- run command as username handling setuid and/or setgid\n\
-E var=val -- put var=val in the environment for command\n\
-E var -- remove var from the environment for command\n\
-P path -- trace accesses to path\n\
"
#ifdef USE_LIBUNWIND
"-k obtain stack trace between each syscall (experimental)\n\
"
#endif
/* ancient, no one should use it
-F -- attempt to follow vforks (deprecated, use -f)\n\
 */
/* this is broken, so don't document it
-z -- print only succeeding syscalls\n\
 */
, DEFAULT_ACOLUMN, DEFAULT_STRLEN, DEFAULT_SORTBY);
	exit(exitval);
}

static void die(void) __attribute__ ((noreturn));
static void die(void)
{
	if (strace_tracer_pid == getpid()) {
		cflag = (cflag_t)0;
	}
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

static void
error_opt_arg(int opt, const char *arg)
{
	error_msg_and_die("Invalid -%c argument: '%s'", opt, arg);
}

static void
set_cloexec_flag(int fd)
{
	int flags, newflags;

	flags = fcntl(fd, F_GETFD);
	if (flags < 0) {
		/* Can happen only if fd is bad.
		 * Should never happen: if it does, we have a bug
		 * in the caller. Therefore we just abort
		 * instead of propagating the error.
		 */
		perror_msg_and_die("fcntl(%d, F_GETFD)", fd);
	}

	newflags = flags | FD_CLOEXEC;
	if (flags == newflags)
		return;

	fcntl(fd, F_SETFD, newflags); /* never fails */
}

static void kill_save_errno(pid_t pid, int sig)
{
	int saved_errno = errno;

	(void) kill(pid, sig);
	errno = saved_errno;
}

/*
 * When strace is setuid executable, we have to swap uids
 * before and after filesystem and process management operations.
 */
static void
swap_uid(void)
{
	int euid = geteuid(), uid = getuid();

	if (euid != uid && setreuid(euid, uid) < 0) {
		perror_msg_and_die("setreuid");
	}
}

#ifdef _LARGEFILE64_SOURCE
# ifdef HAVE_FOPEN64
#  define fopen_for_output fopen64
# else
#  define fopen_for_output fopen
# endif
# define struct_stat struct stat64
# define stat_file stat64
# define struct_dirent struct dirent64
# define read_dir readdir64
# define struct_rlimit struct rlimit64
# define set_rlimit setrlimit64
#else
# define fopen_for_output fopen
# define struct_stat struct stat
# define stat_file stat
# define struct_dirent struct dirent
# define read_dir readdir
# define struct_rlimit struct rlimit
# define set_rlimit setrlimit
#endif

static FILE *
strace_fopen(const char *path)
{
	FILE *fp;

	swap_uid();
	fp = fopen_for_output(path, "w");
	if (!fp)
		perror_msg_and_die("Can't fopen '%s'", path);
	swap_uid();
	set_cloexec_flag(fileno(fp));
	return fp;
}

static int popen_pid = 0;

#ifndef _PATH_BSHELL
# define _PATH_BSHELL "/bin/sh"
#endif

/*
 * We cannot use standard popen(3) here because we have to distinguish
 * popen child process from other processes we trace, and standard popen(3)
 * does not export its child's pid.
 */
static FILE *
strace_popen(const char *command)
{
	FILE *fp;
	int pid;
	int fds[2];

	swap_uid();
	if (pipe(fds) < 0)
		perror_msg_and_die("pipe");

	set_cloexec_flag(fds[1]); /* never fails */

	pid = vfork();
	if (pid < 0)
		perror_msg_and_die("vfork");

	if (pid == 0) {
		/* child */
		close(fds[1]);
		if (fds[0] != 0) {
			if (dup2(fds[0], 0))
				perror_msg_and_die("dup2");
			close(fds[0]);
		}
		execl(_PATH_BSHELL, "sh", "-c", command, NULL);
		perror_msg_and_die("Can't execute '%s'", _PATH_BSHELL);
	}

	/* parent */
	popen_pid = pid;
	close(fds[0]);
	swap_uid();
	fp = fdopen(fds[1], "w");
	if (!fp)
		die_out_of_memory();
	return fp;
}

void
tprintf(const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	if (current_tcp) {
		int n = strace_vfprintf(current_tcp->outf, fmt, args);
		if (n < 0) {
			if (current_tcp->outf != stderr)
				perror_msg("%s", outfname);
		} else
			current_tcp->curcol += n;
	}
	va_end(args);
}

#ifndef HAVE_FPUTS_UNLOCKED
# define fputs_unlocked fputs
#endif

void
tprints(const char *str)
{
	if (current_tcp) {
		int n = fputs_unlocked(str, current_tcp->outf);
		if (n >= 0) {
			current_tcp->curcol += strlen(str);
			return;
		}
		if (current_tcp->outf != stderr)
			perror_msg("%s", outfname);
	}
}

void
line_ended(void)
{
	if (current_tcp) {
		current_tcp->curcol = 0;
		fflush(current_tcp->outf);
	}
	if (printing_tcp) {
		printing_tcp->curcol = 0;
		printing_tcp = NULL;
	}
}

void
printleader(struct tcb *tcp)
{
	/* If -ff, "previous tcb we printed" is always the same as current,
	 * because we have per-tcb output files.
	 */
	if (followfork >= 2)
		printing_tcp = tcp;

	if (printing_tcp) {
		current_tcp = printing_tcp;
		if (printing_tcp->curcol != 0 && (followfork < 2 || printing_tcp == tcp)) {
			/*
			 * case 1: we have a shared log (i.e. not -ff), and last line
			 * wasn't finished (same or different tcb, doesn't matter).
			 * case 2: split log, we are the same tcb, but our last line
			 * didn't finish ("SIGKILL nuked us after syscall entry" etc).
			 */
			tprints(" <unfinished ...>\n");
			printing_tcp->curcol = 0;
		}
	}

	printing_tcp = tcp;
	current_tcp = tcp;
	current_tcp->curcol = 0;

	if (print_pid_pfx)
		tprintf("%-5d ", tcp->pid);
	else if (nprocs > 1 && !outfname)
		tprintf("[pid %5u] ", tcp->pid);

	if (tflag) {
		char str[sizeof("HH:MM:SS")];
		struct timeval tv, dtv;
		static struct timeval otv;

		gettimeofday(&tv, NULL);
		if (rflag) {
			if (otv.tv_sec == 0)
				otv = tv;
			tv_sub(&dtv, &tv, &otv);
			tprintf("%6ld.%06ld ",
				(long) dtv.tv_sec, (long) dtv.tv_usec);
			otv = tv;
		}
		else if (tflag > 2) {
			tprintf("%ld.%06ld ",
				(long) tv.tv_sec, (long) tv.tv_usec);
		}
		else {
			time_t local = tv.tv_sec;
			strftime(str, sizeof(str), "%T", localtime(&local));
			if (tflag > 1)
				tprintf("%s.%06ld ", str, (long) tv.tv_usec);
			else
				tprintf("%s ", str);
		}
	}
	if (iflag)
		print_pc(tcp);
}

void
tabto(void)
{
	if (current_tcp->curcol < acolumn)
		tprints(acolumn_spaces + current_tcp->curcol);
}

/* Should be only called directly *after successful attach* to a tracee.
 * Otherwise, "strace -oFILE -ff -p<nonexistant_pid>"
 * may create bogus empty FILE.<nonexistant_pid>, and then die.
 */
static void
newoutf(struct tcb *tcp)
{
	tcp->outf = shared_log; /* if not -ff mode, the same file is for all */
	if (followfork >= 2) {
		char name[520 + sizeof(int) * 3];
		sprintf(name, "%.512s.%u", outfname, tcp->pid);
		tcp->outf = strace_fopen(name);
	}
}

static void
expand_tcbtab(void)
{
	/* Allocate some more TCBs and expand the table.
	   We don't want to relocate the TCBs because our
	   callers have pointers and it would be a pain.
	   So tcbtab is a table of pointers.  Since we never
	   free the TCBs, we allocate a single chunk of many.  */
	int i = tcbtabsize;
	struct tcb *newtcbs = (struct tcb*)calloc(tcbtabsize, sizeof(newtcbs[0]));
	struct tcb **newtab = (struct tcb**)realloc(tcbtab, tcbtabsize * 2 * sizeof(tcbtab[0]));
	if (!newtab || !newtcbs)
		die_out_of_memory();
	tcbtabsize *= 2;
	tcbtab = newtab;
	while (i < tcbtabsize)
		tcbtab[i++] = newtcbs++;
}

static struct tcb *
alloctcb(int pid)
{
	int i;
	struct tcb *tcp;

	if (nprocs == tcbtabsize)
		expand_tcbtab();

	for (i = 0; i < tcbtabsize; i++) {
		tcp = tcbtab[i];
		if (!tcp->pid) {
			memset(tcp, 0, sizeof(*tcp));
			tcp->pid = pid;
#if SUPPORTED_PERSONALITIES > 1
			tcp->currpers = current_personality;
#endif

#ifdef USE_LIBUNWIND
			if (stack_trace_enabled)
				unwind_tcb_init(tcp);
#endif

			nprocs++;
			if (debug_flag)
				fprintf(stderr, "new tcb for pid %d, active tcbs:%d\n", tcp->pid, nprocs);
			return tcp;
		}
	}
	error_msg_and_die("bug in alloctcb");
}

static void
droptcb(struct tcb *tcp)
{
	if (tcp->pid == 0)
		return;

#ifdef USE_LIBUNWIND
	if (stack_trace_enabled) {
		unwind_tcb_fin(tcp);
	}
#endif

	nprocs--;
	if (debug_flag)
		fprintf(stderr, "dropped tcb for pid %d, %d remain\n", tcp->pid, nprocs);

	if (tcp->outf) {
		if (followfork >= 2) {
			if (tcp->curcol != 0)
				fprintf(tcp->outf, " <detached ...>\n");
			fclose(tcp->outf);
		} else {
			if (printing_tcp == tcp && tcp->curcol != 0)
				fprintf(tcp->outf, " <detached ...>\n");
			fflush(tcp->outf);
		}
	}

	if (current_tcp == tcp)
		current_tcp = NULL;
	if (printing_tcp == tcp)
		printing_tcp = NULL;

	memset(tcp, 0, sizeof(*tcp));
}

static void
process_opt_p_list(char *opt)
{
	while (*opt) {
		/*
		 * We accept -p PID,PID; -p "`pidof PROG`"; -p "`pgrep PROG`".
		 * pidof uses space as delim, pgrep uses newline. :(
		 */
		int pid;
		char *delim = opt + strcspn(opt, ", \n\t");
		char c = *delim;

		*delim = '\0';
		pid = string_to_uint(opt);
		if (pid <= 0) {
			error_msg_and_die("Invalid process id: '%s'", opt);
		}
		if (pid == strace_tracer_pid) {
			error_msg_and_die("I'm sorry, I can't let you do that, Dave.");
		}
		*delim = c;
		alloctcb(pid);
		if (c == '\0')
			break;
		opt = delim + 1;
	}
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

/*
 * Initialization part of main() was eating much stack (~0.5k),
 * which was unused after init.
 * We can reuse it if we move init code into a separate function.
 *
 * Don't want main() to inline us and defeat the reason
 * we have a separate function.
 */
static void __attribute__ ((noinline))
init(int argc, char *argv[])
{
	struct tcb *tcp;
	int c;
	int optF = 0;
	struct sigaction sa;

	progname = argv[0] ? argv[0] : "strace";

	/* Make sure SIGCHLD has the default action so that waitpid
	   definitely works without losing track of children.  The user
	   should not have given us a bogus state to inherit, but he might
	   have.  Arguably we should detect SIG_IGN here and pass it on
	   to children, but probably noone really needs that.  */
	signal(SIGCHLD, SIG_DFL);

	strace_tracer_pid = getpid();

	os_release = get_os_release();

	/* Allocate the initial tcbtab.  */
	tcbtabsize = argc;	/* Surely enough for all -p args.  */
	tcbtab = (struct tcb**)calloc(tcbtabsize, sizeof(tcbtab[0]));
	if (!tcbtab)
		die_out_of_memory();
	tcp = (struct tcb*)calloc(tcbtabsize, sizeof(*tcp));
	if (!tcp)
		die_out_of_memory();
	for (c = 0; c < tcbtabsize; c++)
		tcbtab[c] = tcp++;

	shared_log = stderr;
	set_sortby(DEFAULT_SORTBY);
	set_personality(DEFAULT_PERSONALITY);
	qualify("trace=all");
	qualify("abbrev=all");
	qualify("verbose=all");
#if DEFAULT_QUAL_FLAGS != (QUAL_TRACE | QUAL_ABBREV | QUAL_VERBOSE)
# error Bug in DEFAULT_QUAL_FLAGS
#endif
	qualify("signal=all");

	argv += 6;
	/* argc -= optind; - no need, argc is not used below */

	acolumn_spaces = (char*)malloc(acolumn + 1);
	if (!acolumn_spaces)
		die_out_of_memory();
	memset(acolumn_spaces, ' ', acolumn);
	acolumn_spaces[acolumn] = '\0';

	/* Must have PROG [ARGS], or -p PID. Not both. */
	if (!argv[0] == !nprocs)
		usage(stderr, 1);

	if (nprocs != 0 && daemonized_tracer) {
		error_msg_and_die("-D and -p are mutually exclusive");
	}

	if (!followfork)
		followfork = optF;

	if (followfork >= 2 && cflag) {
		error_msg_and_die("(-c or -C) and -ff are mutually exclusive");
	}

	if (count_wallclock && !cflag) {
		error_msg_and_die("-w must be given with (-c or -C)");
	}

	if (cflag == CFLAG_ONLY_STATS) {
		if (iflag)
			error_msg("-%c has no effect with -c", 'i');
#ifdef USE_LIBUNWIND
		if (stack_trace_enabled)
			error_msg("-%c has no effect with -c", 'k');
#endif
		if (rflag)
			error_msg("-%c has no effect with -c", 'r');
		if (tflag)
			error_msg("-%c has no effect with -c", 't');
		if (Tflag)
			error_msg("-%c has no effect with -c", 'T');
		if (show_fd_path)
			error_msg("-%c has no effect with -c", 'y');
	}

#ifdef USE_LIBUNWIND
	if (stack_trace_enabled)
		unwind_init();
#endif

	/* See if they want to run as another user. */
	if (username != NULL) {
		struct passwd *pent;

		if (getuid() != 0 || geteuid() != 0) {
			error_msg_and_die("You must be root to use the -u option");
		}
		pent = getpwnam(username);
		if (pent == NULL) {
			error_msg_and_die("Cannot find user '%s'", username);
		}
		run_uid = pent->pw_uid;
		run_gid = pent->pw_gid;
	}
	else {
		run_uid = getuid();
		run_gid = getgid();
	}

	/* Check if they want to redirect the output. */
	if (outfname) {
		/* See if they want to pipe the output. */
		if (outfname[0] == '|' || outfname[0] == '!') {
			/*
			 * We can't do the <outfname>.PID funny business
			 * when using popen, so prohibit it.
			 */
			if (followfork >= 2)
				error_msg_and_die("Piping the output and -ff are mutually exclusive");
			shared_log = strace_popen(outfname + 1);
		}
		else if (followfork < 2)
			shared_log = strace_fopen(outfname);
	} else {
		/* -ff without -o FILE is the same as single -f */
		if (followfork >= 2)
			followfork = 1;
	}

	if (!outfname || outfname[0] == '|' || outfname[0] == '!') {
		char *buf = (char*)malloc(BUFSIZ);
		if (!buf)
			die_out_of_memory();
		setvbuf(shared_log, buf, _IOLBF, BUFSIZ);
	}
	if (outfname && argv[0]) {
		if (!opt_intr)
			opt_intr = INTR_NEVER;
		qflag = 1;
	}
	if (!opt_intr)
		opt_intr = INTR_WHILE_WAIT;

	/* argv[0]	-pPID	-oFILE	Default interactive setting
	 * yes		0	0	INTR_WHILE_WAIT
	 * no		1	0	INTR_WHILE_WAIT
	 * yes		0	1	INTR_NEVER
	 * no		1	1	INTR_WHILE_WAIT
	 */

	sigemptyset(&empty_set);
	sigemptyset(&blocked_set);

	/* startup_child() must be called before the signal handlers get
	 * installed below as they are inherited into the spawned process.
	 * Also we do not need to be protected by them as during interruption
	 * in the startup_child() mode we kill the spawned process anyway.
	 */
	if (argv[0]) {
		if (!NOMMU_SYSTEM || daemonized_tracer)
			hide_log_until_execve = 1;
		skip_one_b_execve = 1;
	}

	sa.sa_handler = SIG_IGN;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	sigaction(SIGTTOU, &sa, NULL); /* SIG_IGN */
	sigaction(SIGTTIN, &sa, NULL); /* SIG_IGN */
	if (opt_intr != INTR_ANYWHERE) {
		if (opt_intr == INTR_BLOCK_TSTP_TOO)
			sigaction(SIGTSTP, &sa, NULL); /* SIG_IGN */
		/*
		 * In interactive mode (if no -o OUTFILE, or -p PID is used),
		 * fatal signals are blocked while syscall stop is processed,
		 * and acted on in between, when waiting for new syscall stops.
		 * In non-interactive mode, signals are ignored.
		 */
		if (opt_intr == INTR_WHILE_WAIT) {
			sigaddset(&blocked_set, SIGHUP);
			sigaddset(&blocked_set, SIGINT);
			sigaddset(&blocked_set, SIGQUIT);
			sigaddset(&blocked_set, SIGPIPE);
			sigaddset(&blocked_set, SIGTERM);
			sa.sa_handler = interrupt;
		}
		/* SIG_IGN, or set handler for these */
		sigaction(SIGHUP, &sa, NULL);
		sigaction(SIGINT, &sa, NULL);
		sigaction(SIGQUIT, &sa, NULL);
		sigaction(SIGPIPE, &sa, NULL);
		sigaction(SIGTERM, &sa, NULL);
	}

	/* Do we want pids printed in our -o OUTFILE?
	 * -ff: no (every pid has its own file); or
	 * -f: yes (there can be more pids in the future); or
	 * -p PID1,PID2: yes (there are already more than one pid)
	 */
	print_pid_pfx = (outfname && followfork < 2 && (followfork == 1 || nprocs > 1));
}

static struct tcb *
pid2tcb(int pid)
{
	int i;

	if (pid <= 0)
		return NULL;

	for (i = 0; i < tcbtabsize; i++) {
		struct tcb *tcp = tcbtab[i];
		if (tcp->pid == pid)
			return tcp;
	}

	return NULL;
}

static void
interrupt(int sig)
{
	interrupted = sig;
}


VOID SysBefore(ADDRINT ip, ADDRINT scno, ADDRINT arg0, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4, ADDRINT arg5)
{
#if defined(TARGET_LINUX) && defined(TARGET_IA32) 
    // On ia32 Linux, there are only 5 registers for passing system call arguments, 
    // but mmap needs 6. For mmap on ia32, the first argument to the system call 
    // is a pointer to an array of the 6 arguments
    if (scno == SYS_mmap)
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
    static struct tcb *tcp = current_tcp;

    tcp->scno = scno; 
    tcp->u_arg[0] = (long)arg0;
    tcp->u_arg[1] = (long)arg1;
    tcp->u_arg[2] = (long)arg2;
    tcp->u_arg[3] = (long)arg3;
    tcp->u_arg[4] = (long)arg4;
    tcp->u_arg[5] = (long)arg5;
    if (SCNO_IS_VALID(tcp->scno)) {
		tcp->s_ent = &sysent[tcp->scno];
        tcp->qual_flg = qual_flags[tcp->scno];
	} else {
		static const struct_sysent unknown = {
			.nargs = MAX_ARGS,
			.sys_flags = 0,
			.sys_func = printargs,
			.sys_name = "unknown", /* not used */
		};
		tcp->s_ent = &unknown;
        tcp->qual_flg = UNDEFINED_SCNO | QUAL_RAW | DEFAULT_QUAL_FLAGS;
	}
    tcp->flags &= ~TCB_FILTERED;
    printleader(tcp);
/*   if (tcp->s_ent == NULL)
		tprintf("%s(", undefined_scno_name(tcp));
	else
		tprintf("%s(", tcp->s_ent->sys_name);

    tcp->s_ent->sys_func(tcp); 
    tprintf("========================");
    printargs(tcp);*/
    if (tcp->qual_flg & UNDEFINED_SCNO)
		tprintf("%s(", undefined_scno_name(tcp));
	else
		tprintf("%s(", tcp->s_ent->sys_name);
	if ((tcp->qual_flg & QUAL_RAW) && tcp->s_ent->sys_func != sys_exit)
		printargs(tcp);
	else{
		tcp->s_ent->sys_func(tcp);
	}

	fflush(tcp->outf);
    tcp->flags |= TCB_INSYSCALL;
}

// Print the return value of the system call
VOID SysAfter(ADDRINT scno, ADDRINT arg0, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4, ADDRINT arg5, ADDRINT error, ADDRINT ret)
{
#if defined(TARGET_LINUX) && defined(TARGET_IA32) 
    // On ia32 Linux, there are only 5 registers for passing system call arguments, 
    // but mmap needs 6. For mmap on ia32, the first argument to the system call 
    // is a pointer to an array of the 6 arguments
    if (scno == SYS_mmap)
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
    static struct tcb *tcp = current_tcp;

    tcp->scno = scno; 
    tcp->u_arg[0] = (long)arg0;
    tcp->u_arg[1] = (long)arg1;
    tcp->u_arg[2] = (long)arg2;
    tcp->u_arg[3] = (long)arg3;
    tcp->u_arg[4] = (long)arg4;
    tcp->u_arg[5] = (long)arg5;
    tcp->u_rval = (long)ret;
    int sys_res = 0;
    int u_error;
    int check_errno = 1;
    if (tcp->s_ent->sys_flags & SYSCALL_NEVER_FAILS) {
		check_errno = 0;
	}
    tcp->u_error = error;
	tcp->u_rval = (long)ret;
	printing_tcp = tcp;
	
	if (tcp->qual_flg & QUAL_RAW) {
		/* sys_res = printargs(tcp); - but it's nop on sysexit */
	} else {
	/* FIXME: not_failing_only (IOW, option -z) is broken:
	 * failure of syscall is known only after syscall return.
	 * Thus we end up with something like this on, say, ENOENT:
	 *     open("doesnt_exist", O_RDONLY <unfinished ...>
	 *     {next syscall decode}
	 * whereas the intended result is that open(...) line
	 * is not shown at all.
	 */
		if (not_failing_only && tcp->u_error)
			goto ret;	/* ignore failed syscalls */
//        tprintf("**%d**",entering(tcp));
		sys_res = tcp->s_ent->sys_func(tcp);
	}
    tprints(") ");
	tabto();
	u_error = tcp->u_error;
	if (tcp->qual_flg & QUAL_RAW) {
		if (u_error)
			tprintf("= -1 (errno %ld)", u_error);
		else
			tprintf("= %#lx", tcp->u_rval);
	}
	else if (!(sys_res & RVAL_NONE) && u_error) {
		switch (u_error) {
		/* Blocked signals do not interrupt any syscalls.
		 * In this case syscalls don't return ERESTARTfoo codes.
		 *
		 * Deadly signals set to SIG_DFL interrupt syscalls
		 * and kill the process regardless of which of the codes below
		 * is returned by the interrupted syscall.
		 * In some cases, kernel forces a kernel-generated deadly
		 * signal to be unblocked and set to SIG_DFL (and thus cause
		 * death) if it is blocked or SIG_IGNed: for example, SIGSEGV
		 * or SIGILL. (The alternative is to leave process spinning
		 * forever on the faulty instruction - not useful).
		 *
		 * SIG_IGNed signals and non-deadly signals set to SIG_DFL
		 * (for example, SIGCHLD, SIGWINCH) interrupt syscalls,
		 * but kernel will always restart them.
		 */
		case ERESTARTSYS:
			/* Most common type of signal-interrupted syscall exit code.
			 * The system call will be restarted with the same arguments
			 * if SA_RESTART is set; otherwise, it will fail with EINTR.
			 */
			tprints("= ? ERESTARTSYS (To be restarted if SA_RESTART is set)");
			break;
		case ERESTARTNOINTR:
			/* Rare. For example, fork() returns this if interrupted.
			 * SA_RESTART is ignored (assumed set): the restart is unconditional.
			 */
			tprints("= ? ERESTARTNOINTR (To be restarted)");
			break;
		case ERESTARTNOHAND:
			/* pause(), rt_sigsuspend() etc use this code.
			 * SA_RESTART is ignored (assumed not set):
			 * syscall won't restart (will return EINTR instead)
			 * even after signal with SA_RESTART set. However,
			 * after SIG_IGN or SIG_DFL signal it will restart
			 * (thus the name "restart only if has no handler").
			 */
			tprints("= ? ERESTARTNOHAND (To be restarted if no handler)");
			break;
		case ERESTART_RESTARTBLOCK:
			/* Syscalls like nanosleep(), poll() which can't be
			 * restarted with their original arguments use this
			 * code. Kernel will execute restart_syscall() instead,
			 * which changes arguments before restarting syscall.
			 * SA_RESTART is ignored (assumed not set) similarly
			 * to ERESTARTNOHAND. (Kernel can't honor SA_RESTART
			 * since restart data is saved in "restart block"
			 * in task struct, and if signal handler uses a syscall
			 * which in turn saves another such restart block,
			 * old data is lost and restart becomes impossible)
			 */
			tprints("= ? ERESTART_RESTARTBLOCK (Interrupted by signal)");
			break;
		default:
			if (u_error < 0)
				tprintf("= -1 E??? (errno %ld)", u_error);
			else if (u_error < nerrnos)
				tprintf("= -1 %s (%s)", errnoent[u_error],
					strerror(u_error));
			else
				tprintf("= -1 ERRNO_%ld (%s)", u_error,
					strerror(u_error));
			break;
		}
		if ((sys_res & RVAL_STR) && tcp->auxstr)
			tprintf(" (%s)", tcp->auxstr);
	}
	else {
		if (sys_res & RVAL_NONE)
			tprints("= ?");
		else {
			switch (sys_res & RVAL_MASK) {
			case RVAL_HEX:
				tprintf("= %#lx", tcp->u_rval);
				break;
			case RVAL_OCTAL:
				tprintf("= %#lo", tcp->u_rval);
				break;
			case RVAL_UDECIMAL:
				tprintf("= %lu", tcp->u_rval);
				break;
			case RVAL_DECIMAL:
				tprintf("= %ld", tcp->u_rval);
				break;
			case RVAL_FD:
				if (show_fd_path) {
					tprints("= ");
					printfd(tcp, tcp->u_rval);
				}
				else
					tprintf("= %ld", tcp->u_rval);
				break;
#if defined(LINUX_MIPSN32) || defined(X32)
			/*
			case RVAL_LHEX:
				tprintf("= %#llx", tcp->u_lrval);
				break;
			case RVAL_LOCTAL:
				tprintf("= %#llo", tcp->u_lrval);
				break;
			*/
			case RVAL_LUDECIMAL:
				tprintf("= %llu", tcp->u_lrval);
				break;
			/*
			case RVAL_LDECIMAL:
				tprintf("= %lld", tcp->u_lrval);
				break;
			*/
#endif
			default:
				fprintf(stderr,
					"invalid rval format\n");
				break;
			}
		}
		if ((sys_res & RVAL_STR) && tcp->auxstr)
			tprintf(" (%s)", tcp->auxstr);
	}
	tprints("\n");
	dumpio(tcp);
	line_ended();

 ret:
	tcp->flags &= ~TCB_INSYSCALL;  
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
    SysAfter(PIN_GetSyscallNumber(ctxt, std),
			 PIN_GetSyscallArgument(ctxt, std, 0),
	         PIN_GetSyscallArgument(ctxt, std, 1),
		     PIN_GetSyscallArgument(ctxt, std, 2),
			 PIN_GetSyscallArgument(ctxt, std, 3),
			 PIN_GetSyscallArgument(ctxt, std, 4),
			 PIN_GetSyscallArgument(ctxt, std, 5),
			 PIN_GetSyscallErrno(ctxt,std),
             PIN_GetSyscallReturn(ctxt, std));
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


/* ===================================================================== */
/* Main                                                                  */
/* ===================================================================== */

int main(int argc, char *argv[])
{
	if (PIN_Init(argc, argv)) return Usage();
	init(argc, argv);
    struct tcb *tcp;
	tcp = alloctcb((int)PIN_GetPid());
	if (!NOMMU_SYSTEM)
		tcp->flags |= TCB_ATTACHED | TCB_STARTUP | post_attach_sigstop;
	else
		tcp->flags |= TCB_ATTACHED | TCB_STARTUP;
	newoutf(tcp);
	/* Set current output file */
	current_tcp = tcp;
	
    INS_AddInstrumentFunction(Instruction, 0);
    PIN_AddSyscallEntryFunction(SyscallEntry, 0);
    PIN_AddSyscallExitFunction(SyscallExit, 0);

    PIN_AddFiniFunction(Fini, 0);

    // Never returns
    PIN_StartProgram();

	fflush(NULL);
	if (shared_log != stderr)
		fclose(shared_log);
	if (popen_pid) {
		while (waitpid(popen_pid, NULL, 0) < 0 && errno == EINTR)
			;
	}
	if (exit_code > 0xff) {
		/* Avoid potential core file clobbering.  */
		struct_rlimit rlim = {0, 0};
		set_rlimit(RLIMIT_CORE, &rlim);

		/* Child was killed by a signal, mimic that.  */
		exit_code &= 0xff;
		signal(exit_code, SIG_DFL);
		raise(exit_code);
		/* Paranoia - what if this signal is not fatal?
		   Exit with 128 + signo then.  */
		exit_code += 128;
	}

	return exit_code;
}
	


