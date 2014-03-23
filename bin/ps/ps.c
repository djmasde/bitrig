/*	$OpenBSD: ps.c,v 1.59 2013/11/21 15:54:45 deraadt Exp $	*/
/*	$NetBSD: ps.c,v 1.15 1995/05/18 20:33:25 mycroft Exp $	*/

/*-
 * Copyright (c) 1990, 1993, 1994
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/param.h>
#include <sys/sysctl.h>
#include <sys/user.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/proc.h>
#include <sys/stat.h>
#include <sys/ioctl.h>

#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <kvm.h>
#include <nlist.h>
#include <paths.h>
#include <grp.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>

#include "ps.h"

extern char *__progname;

struct varent_list vhead = SIMPLEQ_HEAD_INITIALIZER(vhead);

int	eval;			/* exit value */
int	rawcpu;			/* -C */
int	sumrusage;		/* -S */
int	termwidth;		/* width of screen (0 == infinity) */
int	totwidth;		/* calculated width of requested variables */

int	needcomm, needenv, neednlist, commandonly;

enum sort { DEFAULT, SORTMEM, SORTCPU } sortby = DEFAULT;

static char	*kludge_oldps_options(char *);
static int	 pscomp(const void *, const void *);
static void	 hiersort(PINFO **, int);
static void	 scanvars(void);
static void	 usage(void);

char dfmt[] = "pid tt state time command";
char tfmt[] = "pid tid tt state time command";
char jfmt[] = "user pid ppid pgid sess jobc state tt time command";
char lfmt[] = "uid pid ppid cpu pri nice vsz rss wchan state tt time command";
char   o1[] = "pid";
char   o2[] = "tt state time command";
char ufmt[] = "user pid %cpu %mem vsz rss tt state start time command";
char vfmt[] = "pid state time sl re pagein vsz rss lim tsiz %cpu %mem command";

kvm_t *kd;
int kvm_sysctl_only;

int
main(int argc, char *argv[])
{
	struct kinfo_proc *kp;
	struct pinfo **pinfo;
	struct varent *vent;
	struct winsize ws;

	gid_t *gids;
	pid_t *pids;
	dev_t *ttys;
	uid_t *uids;
	size_t ngids, npids, nttys, nuids;
	int all, ch, flag, i, j, k, fmt, lineno, nentries;
	int prtheader, showthreads, dflg, wflag, kflag, what, xflg;
	char *nlistf, *memf, *swapf, errbuf[_POSIX2_LINE_MAX];

	if ((ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == -1 &&
	    ioctl(STDERR_FILENO, TIOCGWINSZ, &ws) == -1 &&
	    ioctl(STDIN_FILENO,  TIOCGWINSZ, &ws) == -1) ||
	    ws.ws_col == 0)
		termwidth = 79;
	else
		termwidth = ws.ws_col - 1;

	if (argc > 1)
		argv[1] = kludge_oldps_options(argv[1]);

	all = fmt = prtheader = showthreads = 0;
	dflg = wflag = kflag = xflg = 0;
	gids = NULL;
	pids = NULL;
	ttys = NULL;
	uids = NULL;
	ngids = npids = nttys = nuids = 0;
	memf = nlistf = swapf = NULL;
	while ((ch = getopt(argc, argv,
	    "AaCcdeG:gHhjkLlM:mN:O:o:p:rSTt:U:uvW:wx")) != -1)
		switch (ch) {
		case 'A':
			all = 1;
			xflg = 1;
			break;
		case 'a':
			all = 1;
			break;
		case 'C':
			rawcpu = 1;
			break;
		case 'c':
			commandonly = 1;
			break;
		case 'd':
			dflg = 1;
			break;
		case 'e':			/* XXX set ufmt */
			needenv = 1;
			break;
		case 'G': {
			struct group *grp;
			char *group;
			const char *errstr;

			while ((group = strsep(&optarg, " ,")) != NULL) {
				if (SIZE_MAX / ++ngids < sizeof(*gids))
					errx(1, "too many groups");
				gids = realloc(gids, ngids * sizeof(*gids));
				if (gids == NULL)
					err(1, NULL);

				gids[ngids - 1] =
				    strtonum(group, 0, GID_MAX, &errstr);
				if (errstr) {
					grp = getgrnam(group);
					if (grp == NULL)
						errx(1, "%s: no such group", group);
					gids[ngids - 1] = grp->gr_gid;
				}
			}
			xflg = 1;
			endgrent();
			break;
		}
		case 'g':
			break;			/* no-op */
		case 'H':
			showthreads = 1;
			break;
		case 'h':
			prtheader = ws.ws_row > 5 ? ws.ws_row : 22;
			break;
		case 'j':
			parsefmt(jfmt);
			fmt = 1;
			jfmt[0] = '\0';
			break;
		case 'k':
			kflag++;
			break;
		case 'L':
			showkey();
			exit(0);
		case 'l':
			parsefmt(lfmt);
			fmt = 1;
			lfmt[0] = '\0';
			break;
		case 'M':
			memf = optarg;
			break;
		case 'm':
			sortby = SORTMEM;
			break;
		case 'N':
			nlistf = optarg;
			break;
		case 'O':
			parsefmt(o1);
			parsefmt(optarg);
			parsefmt(o2);
			o1[0] = o2[0] = '\0';
			fmt = 1;
			break;
		case 'o':
			parsefmt(optarg);
			fmt = 1;
			break;
		case 'p': {
			char *pid;

			while ((pid = strsep(&optarg, " ,")) != NULL) {
				if (SIZE_MAX / ++npids < sizeof(*pids))
					errx(1, "too many pids");
				pids = realloc(pids, npids * sizeof(*pids));
				if (pids == NULL)
					err(1, NULL);
				pids[npids - 1] = atol(pid);
			}
			xflg = 1;
			break;
		}
		case 'r':
			sortby = SORTCPU;
			break;
		case 'S':
			sumrusage = 1;
			break;
		case 'T':
			if ((optarg = ttyname(STDIN_FILENO)) == NULL)
				errx(1, "stdin: not a terminal");
			/* FALLTHROUGH */
		case 't': {
			struct stat sb;
			char *ttypath, pathbuf[MAXPATHLEN], *tmp;

			while ((tmp = strsep(&optarg, " ,")) != NULL) {
				if (SIZE_MAX / ++nttys < sizeof(*uids))
					errx(1, "too many ttys");
				ttys = realloc(ttys, nttys * sizeof(*ttys));
				if (ttys == NULL)
					err(1, NULL);

				if (strcmp(tmp, "co") == 0)
					ttypath = _PATH_CONSOLE;
				else if (*tmp != '/')
					(void)snprintf(ttypath = pathbuf,
					    sizeof(pathbuf), "%s%s", _PATH_TTY, tmp);
				else
					ttypath = tmp;
				if (stat(ttypath, &sb) == -1)
					err(1, "%s", ttypath);
				if (!S_ISCHR(sb.st_mode))
					errx(1, "%s: not a terminal", ttypath);
				ttys[nttys - 1] = sb.st_rdev;
			}
			break;
		}
		case 'U': {
			struct passwd *pwd;
			char *user;
			const char *errstr;

			while ((user = strsep(&optarg, " ,")) != NULL) {
				if (SIZE_MAX / ++nuids < sizeof(*uids))
					errx(1, "too many users");
				uids = realloc(uids, nuids * sizeof(*uids));
				if (uids == NULL)
					err(1, NULL);

				uids[nuids - 1] =
				    strtonum(user, 0, UID_MAX, &errstr);
				if (errstr) {
					pwd = getpwnam(user);
					if (pwd == NULL)
						errx(1, "%s: no such user", user);
					uids[nuids - 1] = pwd->pw_uid;
				}

			}
			xflg = 1;
			endpwent();
			break;
		}
		case 'u':
			parsefmt(ufmt);
			sortby = SORTCPU;
			fmt = 1;
			ufmt[0] = '\0';
			break;
		case 'v':
			parsefmt(vfmt);
			sortby = SORTMEM;
			fmt = 1;
			vfmt[0] = '\0';
			break;
		case 'W':
			swapf = optarg;
			break;
		case 'w':
			if (wflag)
				termwidth = UNLIMITED;
			else if (termwidth < 131)
				termwidth = 131;
			wflag++;
			break;
		case 'x':
			xflg = 1;
			break;
		default:
			usage();
		}
	argc -= optind;
	argv += optind;

#define	BACKWARD_COMPATIBILITY
#ifdef	BACKWARD_COMPATIBILITY
	if (*argv) {
		nlistf = *argv;
		if (*++argv) {
			memf = *argv;
			if (*++argv)
				swapf = *argv;
		}
	}
#endif

	if (nlistf == NULL && memf == NULL && swapf == NULL) {
		kd = kvm_openfiles(NULL, NULL, NULL, KVM_NO_FILES, errbuf);
		kvm_sysctl_only = 1;
	} else {
		kd = kvm_openfiles(nlistf, memf, swapf, O_RDONLY, errbuf);
	}
	if (kd == NULL)
		errx(1, "%s", errbuf);

	if (!fmt) {
		if (showthreads)
			parsefmt(tfmt);
		else
			parsefmt(dfmt);
	}

	/* XXX - should be cleaner */
	if (!all && !ngids && !npids && !nttys && !nuids) {
		if ((uids = calloc(1, sizeof(*uids))) == NULL)
			err(1, NULL);
		uids[0] = getuid();
		nuids = 1;
	}

	/*
	 * scan requested variables, noting what structures are needed,
	 * and adjusting header widths as appropriate.
	 */
	scanvars();

	if (neednlist && !nlistread)
		(void) donlist();

	/*
	 * get proc list
	 */
	what = kflag ? KERN_PROC_KTHREAD : KERN_PROC_ALL;
	flag = 0;
	if (!kflag && nuids + nttys + npids == 1) {
		if (gids) {
			what = KERN_PROC_RGID;
			flag = gids[0];
		} else if (pids) {
			what = KERN_PROC_PID;
			flag = pids[0];
		} else if (ttys) {
			what = KERN_PROC_TTY;
			flag = ttys[0];
		} else if (uids) {
			what = KERN_PROC_RUID;
			flag = uids[0];
		}
	}
	if (showthreads)
		what |= KERN_PROC_SHOW_THREADS;

	/*
	 * select procs
	 */
	kp = kvm_getprocs(kd, what, flag, sizeof(*kp), &nentries);
	if (kp == NULL)
		errx(1, "%s", kvm_geterr(kd));

	if ((pinfo = calloc(nentries, sizeof(*pinfo))) == NULL)
		err(1, NULL);

	for (i = j = 0; i < nentries; i++) {
		if (xflg == 0 && ((int)kp[i].p_tdev == NODEV ||
		    (kp[i].p_psflags & PS_CONTROLT) == 0))
			continue;
		if (showthreads && kp[i].p_tid == -1)
			continue;

		if (all || (!ngids && !npids && !nttys && !nuids))
			goto take;
		for (k = 0; k < ngids; k++) {
			if (gids[k] == kp[i].p_rgid)
				goto take;
		}
		for (k = 0; k < npids; k++) {
			if (pids[k] == kp[i].p_pid)
				goto take;
		}
		for (k = 0; k < nttys; k++) {
			if (ttys[k] == kp[i].p_tdev)
				goto take;
		}
		for (k = 0; k < nuids; k++) {
			if (uids[k] == kp[i].p_ruid)
				goto take;
		}
		continue;

take:
		if ((pinfo[j] = calloc(1, sizeof(PINFO))) == NULL)
			err(1, NULL);
		pinfo[j++]->ki = &kp[i];
	}
	nentries = j;

	free(gids);
	free(ttys);
	free(pids);
	free(uids);

	qsort(pinfo, nentries, sizeof(*pinfo), pscomp);
	if (dflg)
		hiersort(pinfo, nentries);

	/*
	 * print header
	 */
	printheader();
	if (nentries == 0)
		exit(1);

	/*
	 * for each proc, call each variable output function.
	 */
	for (i = lineno = 0; i < nentries; i++) {
		SIMPLEQ_FOREACH(vent, &vhead, entries) {
			(vent->var->oproc)(pinfo[i], vent);
			if (SIMPLEQ_NEXT(vent, entries) != SIMPLEQ_END(&vhead))
				(void)putchar(' ');
		}
		(void)putchar('\n');
		if (prtheader && lineno++ == prtheader - 4) {
			(void)putchar('\n');
			printheader();
			lineno = 0;
		}
	}
	for (i = 0; i < nentries; i++) {
		free(pinfo[i]->siblings);
		free(pinfo[i]);
	}
	free(pinfo);
	exit(eval);
}

static void
scanvars(void)
{
	struct varent *vent;
	VAR *v;
	int i;

	SIMPLEQ_FOREACH(vent, &vhead, entries) {
		v = vent->var;
		i = strlen(v->header);
		if (v->width < i)
			v->width = i;
		totwidth += v->width + 1;	/* +1 for space */
		if (v->flag & COMM)
			needcomm = 1;
		if (v->flag & NLIST)
			neednlist = 1;
	}
	totwidth--;
}

static int
pscomp(const void *v1, const void *v2)
{
	const PINFO *pi1 = *(const PINFO **)v1;
	const PINFO *pi2 = *(const PINFO **)v2;
	int i;
#define VSIZE(k) ((k)->p_vm_dsize + (k)->p_vm_ssize + (k)->p_vm_tsize)

	if (sortby == SORTCPU && (i = getpcpu(pi2) - getpcpu(pi1)) != 0)
		return (i);
	if (sortby == SORTMEM && (i = VSIZE(pi2->ki) - VSIZE(pi1->ki)) != 0)
		return (i);
	if ((i = pi1->ki->p_tdev - pi2->ki->p_tdev) == 0 &&
	    (i = pi1->ki->p_ustart_sec - pi2->ki->p_ustart_sec) == 0)
		i = pi1->ki->p_ustart_usec - pi2->ki->p_ustart_usec;
	return (i);
}

/*
 * Hierarchically sort processes while maintaining their relative order on
 * each hierarchy level. Populate level and siblings variables per process.
 */
static void
hiersort(PINFO **pinfo, int nentries)
{
	size_t i, j, k, level, nhier;
	PINFO *tmp;
	pid_t *hier;

	level = 0;
	nhier = 16;	/* expected maximum nesting level */
	if ((hier = calloc(nhier, sizeof(*hier))) == NULL)
		err(1, NULL);

	for (i = 0; i < nentries; i++) {
		/*
		 * Find the next child on the current nesting level. If there
		 * is none, move up to the parent level and try again until we
		 * find one.
		 */
		for (; level; level--) {
			for (j = i; j < nentries; j++)
				if (pinfo[j]->ki->p_ppid == hier[level-1])
					goto done;
		}

		/* Find the next orphan process. */
		for (j = i; j < nentries; j++) {
			if (pinfo[j]->ki->p_pid == pinfo[j]->ki->p_ppid)
				goto done;

			for (k = i; k < nentries; k++) {
				if (pinfo[k]->ki->p_pid == pinfo[j]->ki->p_ppid)
					break;
			}
			if (k == nentries)
				goto done;
		}

done:
		if (j != i) {
			tmp = pinfo[i];
			pinfo[i] = pinfo[j];
			pinfo[j] = tmp;
		}
		pinfo[i]->level = level;

		level++;
		if (nhier < level) {
			nhier *= 2;
			if (nhier < level || SIZE_MAX / sizeof(*hier) < nhier)
				errx(1, "hierarchy too deep");
			hier = realloc(hier, nhier * sizeof(*hier));
			if (hier == NULL)
				err(1, NULL);
		}
		hier[level-1] = pinfo[i]->ki->p_pid;

		/* Populate siblings field. */
		if (!pinfo[i]->level)
			continue;

		pinfo[i]->siblings =
		    calloc(pinfo[i]->level/8 + 1, sizeof(uint8_t));
		if (pinfo[i]->siblings == NULL)
			err(1, NULL);

		for (j = i; j > 0; j--) {
			if (pinfo[j - 1]->level < pinfo[i]->level)
				break;
			SETSIB(pinfo[j - 1], pinfo[i]->level);
		}
	}
	free(hier);
}

/*
 * ICK (all for getopt), would rather hide the ugliness
 * here than taint the main code.
 *
 *  ps foo -> ps -foo
 *  ps 34 -> ps -p34
 *
 * The old convention that 't' with no trailing tty arg means the users
 * tty, is only supported if argv[1] doesn't begin with a '-'.  This same
 * feature is available with the option 'T', which takes no argument.
 */
static char *
kludge_oldps_options(char *s)
{
	size_t len;
	char *newopts, *ns, *cp;

	len = strlen(s);
	if ((newopts = ns = malloc(2 + len + 1)) == NULL)
		err(1, NULL);
	/*
	 * options begin with '-'
	 */
	if (*s != '-')
		*ns++ = '-';	/* add option flag */

	/*
	 * gaze to end of argv[1]
	 */
	cp = s + len - 1;
	/*
	 * if last letter is a 't' flag with no argument (in the context
	 * of the oldps options -- option string NOT starting with a '-' --
	 * then convert to 'T' (meaning *this* terminal, i.e. ttyname(0)).
	 */
	if (*cp == 't' && *s != '-')
		*cp = 'T';
	else {
		/*
		 * otherwise check for trailing number, which *may* be a
		 * pid.
		 */
		while (cp >= s && isdigit((unsigned char)*cp))
			--cp;
	}
	cp++;
	memmove(ns, s, (size_t)(cp - s));	/* copy up to trailing number */
	ns += cp - s;
	/*
	 * if there's a trailing number, and not a preceding 'p' (pid) or
	 * 't' (tty) flag, then assume it's a pid and insert a 'p' flag.
	 */
	if (isdigit((unsigned char)*cp) &&
	    (cp == s || (cp[-1] != 't' && cp[-1] != 'p' &&
	    (cp - 1 == s || cp[-2] != 't'))))
		*ns++ = 'p';
	/* and append the number */
	(void)strlcpy(ns, cp, newopts + len + 3 - ns);

	return (newopts);
}

static void
usage(void)
{
	(void)fprintf(stderr,
	    "usage: %s [-AaCcdeHhjkLlmrSTuvwx] [-G groups] [-M core] [-N system]\n"
	    "%-*s[-O fmt] [-o fmt] [-p pids] [-t ttys] [-U users] [-W swap]\n",
	    __progname,  (int)strlen(__progname) + 8, "");
	exit(1);
}
