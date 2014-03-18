/*	$OpenBSD: extern.h,v 1.16 2011/12/29 17:13:55 guenther Exp $	*/
/*	$NetBSD: extern.h,v 1.10 1995/05/21 13:38:27 mycroft Exp $	*/

/*-
 * Copyright (c) 1991, 1993, 1994
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
 *
 *	@(#)extern.h	8.3 (Berkeley) 4/2/94
 */

struct nlist;
struct var;
struct varent;
struct varent_list;

extern fixpt_t ccpu;
extern int eval, fscale, nlistread, rawcpu, maxslp;
extern u_int mempages;
extern int sumrusage, termwidth, totwidth, kvm_sysctl_only, needheader;
extern VAR var[];
extern struct varent_list vhead;

__BEGIN_DECLS
void	 command(const PINFO *, VARENT *);
void	 cputime(const PINFO *, VARENT *);
int	 donlist(void);
void	 emulname(const PINFO *, VARENT *);
void	 fmt_puts(const char *, int *);
void	 fmt_putc(int, int *);
double	 getpcpu(const PINFO *);
double	 getpmem(const PINFO *);
void	 gname(const PINFO *, VARENT *);
void	 logname(const PINFO *, VARENT *);
void	 longtname(const PINFO *, VARENT *);
void	 lstarted(const PINFO *, VARENT *);
void	 maxrss(const PINFO *, VARENT *);
void	 nlisterr(struct nlist *);
void	 p_rssize(const PINFO *, VARENT *);
void	 pagein(const PINFO *, VARENT *);
void	 parsefmt(char *);
void	 pcpu(const PINFO *, VARENT *);
void	 pmem(const PINFO *, VARENT *);
void	 pri(const PINFO *, VARENT *);
void	 printheader(void);
void	 pvar(const PINFO *kp, VARENT *);
void	 pnice(const PINFO *kp, VARENT *);
void	 rgname(const PINFO *, VARENT *);
void	 rssize(const PINFO *, VARENT *);
void	 runame(const PINFO *, VARENT *);
void	 showkey(void);
void	 started(const PINFO *, VARENT *);
void	 state(const PINFO *, VARENT *);
void	 tdev(const PINFO *, VARENT *);
void	 tname(const PINFO *, VARENT *);
void	 tsize(const PINFO *, VARENT *);
void	 dsize(const PINFO *, VARENT *);
void	 ssize(const PINFO *, VARENT *);
void	 ucomm(const PINFO *, VARENT *);
void	 curwd(const PINFO *, VARENT *);
void	 euname(const PINFO *, VARENT *);
void	 vsize(const PINFO *, VARENT *);
void	 wchan(const PINFO *, VARENT *);
__END_DECLS
