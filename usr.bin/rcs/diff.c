/*	$OpenBSD: diff.c,v 1.20 2007/05/30 03:30:21 ray Exp $	*/
/*
 * Copyright (C) Caldera International Inc.  2001-2002.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code and documentation must retain the above
 *    copyright notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed or owned by Caldera
 *	International, Inc.
 * 4. Neither the name of Caldera International, Inc. nor the names of other
 *    contributors may be used to endorse or promote products derived from
 *    this software without specific prior written permission.
 *
 * USE OF THE SOFTWARE PROVIDED FOR UNDER THIS LICENSE BY CALDERA
 * INTERNATIONAL, INC. AND CONTRIBUTORS ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL CALDERA INTERNATIONAL, INC. BE LIABLE FOR ANY DIRECT,
 * INDIRECT INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
/*-
 * Copyright (c) 1991, 1993
 *	The Regents of the University of California.  All rights reserved.
 * Copyright (c) 2004 Jean-Francois Brousseau.  All rights reserved.
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
 *	@(#)diffreg.c   8.1 (Berkeley) 6/6/93
 */
/*
 *	Uses an algorithm due to Harold Stone, which finds
 *	a pair of longest identical subsequences in the two
 *	files.
 *
 *	The major goal is to generate the match vector J.
 *	J[i] is the index of the line in file1 corresponding
 *	to line i file0. J[i] = 0 if there is no
 *	such line in file1.
 *
 *	Lines are hashed so as to work in core. All potential
 *	matches are located by sorting the lines of each file
 *	on the hash (called ``value''). In particular, this
 *	collects the equivalence classes in file1 together.
 *	Subroutine equiv replaces the value of each line in
 *	file0 by the index of the first element of its
 *	matching equivalence in (the reordered) file1.
 *	To save space equiv squeezes file1 into a single
 *	array member in which the equivalence classes
 *	are simply concatenated, except that their first
 *	members are flagged by changing sign.
 *
 *	Next the indices that point into member are unsorted into
 *	array class according to the original order of file0.
 *
 *	The cleverness lies in routine stone. This marches
 *	through the lines of file0, developing a vector klist
 *	of "k-candidates". At step i a k-candidate is a matched
 *	pair of lines x,y (x in file0 y in file1) such that
 *	there is a common subsequence of length k
 *	between the first i lines of file0 and the first y
 *	lines of file1, but there is no such subsequence for
 *	any smaller y. x is the earliest possible mate to y
 *	that occurs in such a subsequence.
 *
 *	Whenever any of the members of the equivalence class of
 *	lines in file1 matable to a line in file0 has serial number
 *	less than the y of some k-candidate, that k-candidate
 *	with the smallest such y is replaced. The new
 *	k-candidate is chained (via pred) to the current
 *	k-1 candidate so that the actual subsequence can
 *	be recovered. When a member has serial number greater
 *	that the y of all k-candidates, the klist is extended.
 *	At the end, the longest subsequence is pulled out
 *	and placed in the array J by unravel
 *
 *	With J in hand, the matches there recorded are
 *	check'ed against reality to assure that no spurious
 *	matches have crept in due to hashing. If they have,
 *	they are broken, and "jackpot" is recorded--a harmless
 *	matter except that a true match for a spuriously
 *	mated line may now be unnecessarily reported as a change.
 *
 *	Much of the complexity of the program comes simply
 *	from trying to minimize core utilization and
 *	maximize the range of doable problems by dynamically
 *	allocating what is needed and reusing what is not.
 *	The core requirements for problems larger than somewhat
 *	are (in words) 2*length(file0) + length(file1) +
 *	3*(number of k-candidates installed),  typically about
 *	6n words for files of length n.
 */

#include <sys/param.h>
#include <sys/stat.h>

#include <ctype.h>
#include <err.h>
#include <limits.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "buf.h"
#include "diff.h"
#include "xmalloc.h"

struct cand {
	int	x;
	int	y;
	int	pred;
};

struct line {
	int	serial;
	int	value;
} *file[2];

/*
 * The following struct is used to record change information when
 * doing a "context" or "unified" diff.  (see routine "change" to
 * understand the highly mnemonic field names)
 */
struct context_vec {
	int	a;		/* start line in old file */
	int	b;		/* end line in old file */
	int	c;		/* start line in new file */
	int	d;		/* end line in new file */
};

static void	 output(FILE *, FILE *, int);
static void	 check(FILE *, FILE *, int);
static void	 range(int, int, char *);
static void	 uni_range(int, int);
static void	 dump_context_vec(FILE *, FILE *, int);
static void	 dump_unified_vec(FILE *, FILE *, int);
static int	 prepare(int, FILE *, off_t, int);
static void	 prune(void);
static void	 equiv(struct line *, int, struct line *, int, int *);
static void	 unravel(int);
static void	 unsort(struct line *, int, int *);
static void	 change(FILE *, FILE *, int, int, int, int, int);
static void	 sort(struct line *, int);
static int	 ignoreline(char *);
static int	 asciifile(FILE *);
static void	 fetch(long *, int, int, FILE *, int, int, int);
static int	 newcand(int, int, int);
static int	 search(int *, int, int);
static int	 skipline(FILE *);
static int	 isqrt(int);
static int	 stone(int *, int, int *, int *, int);
static int	 readhash(FILE *, int);
static int	 files_differ(FILE *, FILE *);
static char	*match_function(const long *, int, FILE *);
static char	*preadline(int, size_t, off_t);


int diff_context = 3;
int diff_format = D_NORMAL;
char *diff_file = NULL;
RCSNUM *diff_rev1 = NULL;
RCSNUM *diff_rev2 = NULL;
char diffargs[512]; /* XXX */
static struct stat stb1, stb2;
static char *ifdefname;
regex_t *diff_ignore_re;

static int  *J;			/* will be overlaid on class */
static int  *class;		/* will be overlaid on file[0] */
static int  *klist;		/* will be overlaid on file[0] after class */
static int  *member;		/* will be overlaid on file[1] */
static int   clen;
static int   inifdef;		/* whether or not we are in a #ifdef block */
static int   diff_len[2];
static int   pref, suff;	/* length of prefix and suffix */
static int   slen[2];
static int   anychange;
static long *ixnew;		/* will be overlaid on file[1] */
static long *ixold;		/* will be overlaid on klist */
static struct cand *clist;	/* merely a free storage pot for candidates */
static int   clistlen;		/* the length of clist */
static struct line *sfile[2];	/* shortened by pruning common prefix/suffix */
static u_char *chrtran;		/* translation table for case-folding */
static struct context_vec *context_vec_start;
static struct context_vec *context_vec_end;
static struct context_vec *context_vec_ptr;

#define FUNCTION_CONTEXT_SIZE	55
static char lastbuf[FUNCTION_CONTEXT_SIZE];
static int lastline;
static int lastmatchline;
BUF  *diffbuf = NULL;

/*
 * chrtran points to one of 2 translation tables: cup2low if folding upper to
 * lower case clow2low if not folding case
 */
u_char clow2low[256] = {
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
	0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
	0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
	0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b,
	0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36,
	0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40, 0x41,
	0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c,
	0x4d, 0x4e, 0x4f, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
	0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f, 0x60, 0x61, 0x62,
	0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d,
	0x6e, 0x6f, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78,
	0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f, 0x80, 0x81, 0x82, 0x83,
	0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e,
	0x8f, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99,
	0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f, 0xa0, 0xa1, 0xa2, 0xa3, 0xa4,
	0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
	0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba,
	0xbb, 0xbc, 0xbd, 0xbe, 0xbf, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5,
	0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf, 0xd0,
	0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xd9, 0xda, 0xdb,
	0xdc, 0xdd, 0xde, 0xdf, 0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6,
	0xe7, 0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee, 0xef, 0xf0, 0xf1,
	0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc,
	0xfd, 0xfe, 0xff
};

u_char cup2low[256] = {
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
	0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
	0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
	0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b,
	0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36,
	0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x60, 0x61,
	0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c,
	0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77,
	0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f, 0x60, 0x61, 0x62,
	0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d,
	0x6e, 0x6f, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78,
	0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f, 0x80, 0x81, 0x82, 0x83,
	0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e,
	0x8f, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99,
	0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f, 0xa0, 0xa1, 0xa2, 0xa3, 0xa4,
	0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
	0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba,
	0xbb, 0xbc, 0xbd, 0xbe, 0xbf, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5,
	0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf, 0xd0,
	0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xd9, 0xda, 0xdb,
	0xdc, 0xdd, 0xde, 0xdf, 0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6,
	0xe7, 0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee, 0xef, 0xf0, 0xf1,
	0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc,
	0xfd, 0xfe, 0xff
};

int
rcs_diffreg(const char *file1, const char *file2, BUF *out, int flags)
{
	FILE *f1, *f2;
	int i, rval;

	f1 = f2 = NULL;
	rval = D_SAME;
	anychange = 0;
	lastline = 0;
	lastmatchline = 0;
	context_vec_ptr = context_vec_start - 1;
	if (flags & D_IGNORECASE)
		chrtran = cup2low;
	else
		chrtran = clow2low;
	if (out != NULL)
		diffbuf = out;

	f1 = fopen(file1, "r");
	if (f1 == NULL) {
		warn("%s", file1);
		goto closem;
	}

	f2 = fopen(file2, "r");
	if (f2 == NULL) {
		warn("%s", file2);
		goto closem;
	}

	if (fstat(fileno(f1), &stb1) < 0) {
		warn("%s", file1);
		goto closem;
	}

	if (fstat(fileno(f2), &stb2) < 0) {
		warn("%s", file2);
		goto closem;
	}

	switch (files_differ(f1, f2)) {
	case 1:
		break;
	case -1:
		rval = D_ERROR;
		/* FALLTHROUGH */
	case 0:
		goto closem;
	default:
		errx(D_ERROR, "files_differ: invalid case");
	}

	if ((flags & D_FORCEASCII) == 0 &&
	    (!asciifile(f1) || !asciifile(f2))) {
		rval = D_ERROR;
		goto closem;
	}

	if (prepare(0, f1, stb1.st_size, flags) < 0 ||
	    prepare(1, f2, stb2.st_size, flags) < 0) {
		goto closem;
	}

	prune();
	sort(sfile[0], slen[0]);
	sort(sfile[1], slen[1]);

	member = (int *)file[1];
	equiv(sfile[0], slen[0], sfile[1], slen[1], member);
	member = xrealloc(member, slen[1] + 2, sizeof(*member));

	class = (int *)file[0];
	unsort(sfile[0], slen[0], class);
	class = xrealloc(class, slen[0] + 2, sizeof(*class));

	klist = xcalloc(slen[0] + 2, sizeof(*klist));
	clen = 0;
	clistlen = 100;
	clist = xcalloc(clistlen, sizeof(*clist));

	if ((i = stone(class, slen[0], member, klist, flags)) < 0)
		goto closem;

	xfree(member);
	xfree(class);

	J = xrealloc(J, diff_len[0] + 2, sizeof(*J));
	unravel(klist[i]);
	xfree(clist);
	xfree(klist);

	ixold = xrealloc(ixold, diff_len[0] + 2, sizeof(*ixold));

	ixnew = xrealloc(ixnew, diff_len[1] + 2, sizeof(*ixnew));
	check(f1, f2, flags);
	output(f1, f2, flags);

closem:
	if (anychange == 1) {
		if (rval == D_SAME)
			rval = D_DIFFER;
	}
	if (f1 != NULL)
		fclose(f1);
	if (f2 != NULL)
		fclose(f2);

	return (rval);
}

/*
 * Check to see if the given files differ.
 * Returns 0 if they are the same, 1 if different, and -1 on error.
 * XXX - could use code from cmp(1) [faster]
 */
static int
files_differ(FILE *f1, FILE *f2)
{
	char buf1[BUFSIZ], buf2[BUFSIZ];
	size_t i, j;

	if (stb1.st_size != stb2.st_size)
		return (1);
	for (;;) {
		i = fread(buf1, 1, sizeof(buf1), f1);
		j = fread(buf2, 1, sizeof(buf2), f2);
		if (i != j)
			return (1);
		if (i == 0 && j == 0) {
			if (ferror(f1) || ferror(f2))
				return (-1);
			return (0);
		}
		if (memcmp(buf1, buf2, i) != 0)
			return (1);
	}
}

static int
prepare(int i, FILE *fd, off_t filesize, int flags)
{
	struct line *p;
	int j, h;
	size_t sz;

	rewind(fd);

	sz = ((size_t)filesize <= SIZE_MAX ? (size_t)filesize : SIZE_MAX) / 25;
	if (sz < 100)
		sz = 100;

	p = xcalloc(sz + 3, sizeof(*p));
	for (j = 0; (h = readhash(fd, flags));) {
		if (j == (int)sz) {
			sz = sz * 3 / 2;
			p = xrealloc(p, sz + 3, sizeof(*p));
		}
		p[++j].value = h;
	}
	diff_len[i] = j;
	file[i] = p;

	return (0);
}

static void
prune(void)
{
	int i, j;

	for (pref = 0; pref < diff_len[0] && pref < diff_len[1] &&
	    file[0][pref + 1].value == file[1][pref + 1].value;
	    pref++)
		;
	for (suff = 0;
	    (suff < diff_len[0] - pref) && (suff < diff_len[1] - pref) &&
	    (file[0][diff_len[0] - suff].value ==
	    file[1][diff_len[1] - suff].value);
	    suff++)
		;
	for (j = 0; j < 2; j++) {
		sfile[j] = file[j] + pref;
		slen[j] = diff_len[j] - pref - suff;
		for (i = 0; i <= slen[j]; i++)
			sfile[j][i].serial = i;
	}
}

static void
equiv(struct line *a, int n, struct line *b, int m, int *c)
{
	int i, j;

	i = j = 1;
	while (i <= n && j <= m) {
		if (a[i].value < b[j].value)
			a[i++].value = 0;
		else if (a[i].value == b[j].value)
			a[i++].value = j;
		else
			j++;
	}
	while (i <= n)
		a[i++].value = 0;
	b[m + 1].value = 0;
	j = 0;
	while (++j <= m) {
		c[j] = -b[j].serial;
		while (b[j + 1].value == b[j].value) {
			j++;
			c[j] = b[j].serial;
		}
	}
	c[j] = -1;
}

/* Code taken from ping.c */
static int
isqrt(int n)
{
	int y, x = 1;

	if (n == 0)
		return (0);

	do { /* newton was a stinker */
		y = x;
		x = n / x;
		x += y;
		x /= 2;
	} while (x - y > 1 || x - y < -1);

	return (x);
}

static int
stone(int *a, int n, int *b, int *c, int flags)
{
	int ret;
	int i, k, y, j, l;
	int oldc, tc, oldl;
	u_int numtries;

	/* XXX move the isqrt() out of the macro to avoid multiple calls */
	const u_int bound = (flags & D_MINIMAL) ? UINT_MAX :
	    MAX(256, (u_int)isqrt(n));

	k = 0;
	if ((ret = newcand(0, 0, 0)) < 0)
		return (-1);
	c[0] = ret;
	for (i = 1; i <= n; i++) {
		j = a[i];
		if (j == 0)
			continue;
		y = -b[j];
		oldl = 0;
		oldc = c[0];
		numtries = 0;
		do {
			if (y <= clist[oldc].y)
				continue;
			l = search(c, k, y);
			if (l != oldl + 1)
				oldc = c[l - 1];
			if (l <= k) {
				if (clist[c[l]].y <= y)
					continue;
				tc = c[l];
				if ((ret = newcand(i, y, oldc)) < 0)
					return (-1);
				c[l] = ret;
				oldc = tc;
				oldl = l;
				numtries++;
			} else {
				if ((ret = newcand(i, y, oldc)) < 0)
					return (-1);
				c[l] = ret;
				k++;
				break;
			}
		} while ((y = b[++j]) > 0 && numtries < bound);
	}
	return (k);
}

static int
newcand(int x, int y, int pred)
{
	struct cand *q;

	if (clen == clistlen) {
		clistlen = clistlen * 11 / 10;
		clist = xrealloc(clist, clistlen, sizeof(*clist));
	}
	q = clist + clen;
	q->x = x;
	q->y = y;
	q->pred = pred;
	return (clen++);
}

static int
search(int *c, int k, int y)
{
	int i, j, l, t;

	if (clist[c[k]].y < y)	/* quick look for typical case */
		return (k + 1);
	i = 0;
	j = k + 1;
	for (;;) {
		l = (i + j) / 2;
		if (l <= i)
			break;
		t = clist[c[l]].y;
		if (t > y)
			j = l;
		else if (t < y)
			i = l;
		else
			return (l);
	}
	return (l + 1);
}

static void
unravel(int p)
{
	struct cand *q;
	int i;

	for (i = 0; i <= diff_len[0]; i++)
		J[i] = i <= pref ? i :
		    i > diff_len[0] - suff ? i + diff_len[1] - diff_len[0] : 0;
	for (q = clist + p; q->y != 0; q = clist + q->pred)
		J[q->x + pref] = q->y + pref;
}

/*
 * Check does double duty:
 *  1.	ferret out any fortuitous correspondences due
 *	to confounding by hashing (which result in "jackpot")
 *  2.  collect random access indexes to the two files
 */
static void
check(FILE *f1, FILE *f2, int flags)
{
	int i, j, jackpot, c, d;
	long ctold, ctnew;

	rewind(f1);
	rewind(f2);
	j = 1;
	ixold[0] = ixnew[0] = 0;
	jackpot = 0;
	ctold = ctnew = 0;
	for (i = 1; i <= diff_len[0]; i++) {
		if (J[i] == 0) {
			ixold[i] = ctold += skipline(f1);
			continue;
		}
		while (j < J[i]) {
			ixnew[j] = ctnew += skipline(f2);
			j++;
		}
		if (flags & (D_FOLDBLANKS|D_IGNOREBLANKS|D_IGNORECASE)) {
			for (;;) {
				c = getc(f1);
				d = getc(f2);
				/*
				 * GNU diff ignores a missing newline
				 * in one file for -b or -w.
				 */
				if ((flags & (D_FOLDBLANKS|D_IGNOREBLANKS)) &&
				    ((c == EOF && d == '\n') ||
				    (c == '\n' && d == EOF))) {
					break;
				}
				ctold++;
				ctnew++;
				if ((flags & D_FOLDBLANKS) && isspace(c) &&
				    isspace(d)) {
					do {
						if (c == '\n')
							break;
						ctold++;
					} while (isspace(c = getc(f1)));
					do {
						if (d == '\n')
							break;
						ctnew++;
					} while (isspace(d = getc(f2)));
				} else if ((flags & D_IGNOREBLANKS)) {
					while (isspace(c) && c != '\n') {
						c = getc(f1);
						ctold++;
					}
					while (isspace(d) && d != '\n') {
						d = getc(f2);
						ctnew++;
					}
				}
				if (chrtran[c] != chrtran[d]) {
					jackpot++;
					J[i] = 0;
					if (c != '\n' && c != EOF)
						ctold += skipline(f1);
					if (d != '\n' && c != EOF)
						ctnew += skipline(f2);
					break;
				}
				if (c == '\n' || c == EOF)
					break;
			}
		} else {
			for (;;) {
				ctold++;
				ctnew++;
				if ((c = getc(f1)) != (d = getc(f2))) {
					/* jackpot++; */
					J[i] = 0;
					if (c != '\n' && c != EOF)
						ctold += skipline(f1);
					if (d != '\n' && c != EOF)
						ctnew += skipline(f2);
					break;
				}
				if (c == '\n' || c == EOF)
					break;
			}
		}
		ixold[i] = ctold;
		ixnew[j] = ctnew;
		j++;
	}
	for (; j <= diff_len[1]; j++)
		ixnew[j] = ctnew += skipline(f2);
	/*
	 * if (jackpot != 0)
	 *	printf("jackpot\n");
	 */
}

/* shellsort CACM #201 */
static void
sort(struct line *a, int n)
{
	struct line *ai, *aim, w;
	int j, m = 0, k;

	if (n == 0)
		return;
	for (j = 1; j <= n; j *= 2)
		m = 2 * j - 1;
	for (m /= 2; m != 0; m /= 2) {
		k = n - m;
		for (j = 1; j <= k; j++) {
			for (ai = &a[j]; ai > a; ai -= m) {
				aim = &ai[m];
				if (aim < ai)
					break;	/* wraparound */
				if (aim->value > ai[0].value ||
				    (aim->value == ai[0].value &&
					aim->serial > ai[0].serial))
					break;
				w.value = ai[0].value;
				ai[0].value = aim->value;
				aim->value = w.value;
				w.serial = ai[0].serial;
				ai[0].serial = aim->serial;
				aim->serial = w.serial;
			}
		}
	}
}

static void
unsort(struct line *f, int l, int *b)
{
	int *a, i;

	a = xcalloc(l + 1, sizeof(*a));
	for (i = 1; i <= l; i++)
		a[f[i].serial] = f[i].value;
	for (i = 1; i <= l; i++)
		b[i] = a[i];
	xfree(a);
}

static int
skipline(FILE *f)
{
	int i, c;

	for (i = 1; (c = getc(f)) != '\n' && c != EOF; i++)
		continue;
	return (i);
}

static void
output(FILE *f1, FILE *f2, int flags)
{
	int m, i0, i1, j0, j1;

	rewind(f1);
	rewind(f2);
	m = diff_len[0];
	J[0] = 0;
	J[m + 1] = diff_len[1] + 1;
	for (i0 = 1; i0 <= m; i0 = i1 + 1) {
		while (i0 <= m && J[i0] == J[i0 - 1] + 1)
			i0++;
		j0 = J[i0 - 1] + 1;
		i1 = i0 - 1;
		while (i1 < m && J[i1 + 1] == 0)
			i1++;
		j1 = J[i1 + 1] - 1;
		J[i1] = j1;
		change(f1, f2, i0, i1, j0, j1, flags);
	}
	if (m == 0)
		change(f1, f2, 1, 0, 1, diff_len[1], flags);
	if (diff_format == D_IFDEF) {
		for (;;) {
#define	c i0
			if ((c = getc(f1)) == EOF)
				return;
			diff_output("%c", c);
		}
#undef c
	}
	if (anychange != 0) {
		if (diff_format == D_CONTEXT)
			dump_context_vec(f1, f2, flags);
		else if (diff_format == D_UNIFIED)
			dump_unified_vec(f1, f2, flags);
	}
}

static void
range(int a, int b, char *separator)
{
	diff_output("%d", a > b ? b : a);
	if (a < b)
		diff_output("%s%d", separator, b);
}

static void
uni_range(int a, int b)
{
	if (a < b)
		diff_output("%d,%d", a, b - a + 1);
	else if (a == b)
		diff_output("%d", b);
	else
		diff_output("%d,0", b);
}

static char *
preadline(int fd, size_t rlen, off_t off)
{
	char *line;
	ssize_t nr;

	line = xmalloc(rlen + 1);
	if ((nr = pread(fd, line, rlen, off)) < 0) {
		warn("preadline failed");
		xfree(line);
		return (NULL);
	}
	line[nr] = '\0';
	return (line);
}

static int
ignoreline(char *line)
{
	int ret;

	ret = regexec(diff_ignore_re, line, 0, NULL, 0);
	xfree(line);
	return (ret == 0);	/* if it matched, it should be ignored. */
}

/*
 * Indicate that there is a difference between lines a and b of the from file
 * to get to lines c to d of the to file.  If a is greater then b then there
 * are no lines in the from file involved and this means that there were
 * lines appended (beginning at b).  If c is greater than d then there are
 * lines missing from the to file.
 */
static void
change(FILE *f1, FILE *f2, int a, int b, int c, int d, int flags)
{
	int i;
	static size_t max_context = 64;
	char buf[64];
	struct tm *t;

	if (diff_format != D_IFDEF && a > b && c > d)
		return;
	if (diff_ignore_re != NULL) {
		char *line;
		/*
		 * All lines in the change, insert, or delete must
		 * match an ignore pattern for the change to be
		 * ignored.
		 */
		if (a <= b) {		/* Changes and deletes. */
			for (i = a; i <= b; i++) {
				line = preadline(fileno(f1),
				    ixold[i] - ixold[i - 1], ixold[i - 1]);
				if (!ignoreline(line))
					goto proceed;
			}
		}
		if (a > b || c <= d) {	/* Changes and inserts. */
			for (i = c; i <= d; i++) {
				line = preadline(fileno(f2),
				    ixnew[i] - ixnew[i - 1], ixnew[i - 1]);
				if (!ignoreline(line))
					goto proceed;
			}
		}
		return;
	}
proceed:
	if (diff_format == D_CONTEXT || diff_format == D_UNIFIED) {
		/*
		 * Allocate change records as needed.
		 */
		if (context_vec_ptr == context_vec_end - 1) {
			ptrdiff_t offset = context_vec_ptr - context_vec_start;
			max_context <<= 1;
			context_vec_start = xrealloc(context_vec_start,
			    max_context, sizeof(*context_vec_start));
			context_vec_end = context_vec_start + max_context;
			context_vec_ptr = context_vec_start + offset;
		}
		if (anychange == 0) {
			/*
			 * Print the context/unidiff header first time through.
			 */
			t = localtime(&stb1.st_mtime);
			(void)strftime(buf, sizeof(buf),
			    "%Y/%m/%d %H:%M:%S", t);

			diff_output("%s %s	%s",
			    diff_format == D_CONTEXT ? "***" : "---", diff_file,
			    buf);

			if (diff_rev1 != NULL) {
				rcsnum_tostr(diff_rev1, buf, sizeof(buf));
				diff_output("\t%s", buf);
			}

			printf("\n");

			t = localtime(&stb2.st_mtime);
			(void)strftime(buf, sizeof(buf),
			    "%Y/%m/%d %H:%M:%S", t);

			diff_output("%s %s	%s",
			    diff_format == D_CONTEXT ? "---" : "+++", diff_file,
			    buf);

			if (diff_rev2 != NULL) {
				rcsnum_tostr(diff_rev2, buf, sizeof(buf));
				diff_output("\t%s", buf);
			}

			printf("\n");
			anychange = 1;
		} else if (a > context_vec_ptr->b + (2 * diff_context) + 1 &&
		    c > context_vec_ptr->d + (2 * diff_context) + 1) {
			/*
			 * If this change is more than 'diff_context' lines
			 * from the previous change, dump the record and reset it.
			 */
			if (diff_format == D_CONTEXT)
				dump_context_vec(f1, f2, flags);
			else
				dump_unified_vec(f1, f2, flags);
		}
		context_vec_ptr++;
		context_vec_ptr->a = a;
		context_vec_ptr->b = b;
		context_vec_ptr->c = c;
		context_vec_ptr->d = d;
		return;
	}
	if (anychange == 0)
		anychange = 1;
	switch (diff_format) {
	case D_BRIEF:
		return;
	case D_NORMAL:
		range(a, b, ",");
		diff_output("%c", a > b ? 'a' : c > d ? 'd' : 'c');
		if (diff_format == D_NORMAL)
			range(c, d, ",");
		diff_output("\n");
		break;
	case D_RCSDIFF:
		if (a > b)
			diff_output("a%d %d\n", b, d - c + 1);
		else {
			diff_output("d%d %d\n", a, b - a + 1);

			if (!(c > d))	/* add changed lines */
				diff_output("a%d %d\n", b, d - c + 1);
		}
		break;
	}
	if (diff_format == D_NORMAL || diff_format == D_IFDEF) {
		fetch(ixold, a, b, f1, '<', 1, flags);
		if (a <= b && c <= d && diff_format == D_NORMAL)
			diff_output("---\n");
	}
	fetch(ixnew, c, d, f2, diff_format == D_NORMAL ? '>' : '\0', 0, flags);
	if (inifdef) {
		diff_output("#endif /* %s */\n", ifdefname);
		inifdef = 0;
	}
}

static void
fetch(long *f, int a, int b, FILE *lb, int ch, int oldfile, int flags)
{
	long j, nc;
	int i, c, col;

	/*
	 * When doing #ifdef's, copy down to current line
	 * if this is the first file, so that stuff makes it to output.
	 */
	if (diff_format == D_IFDEF && oldfile) {
		long curpos = ftell(lb);
		/* print through if append (a>b), else to (nb: 0 vs 1 orig) */
		nc = f[a > b ? b : a - 1] - curpos;
		for (i = 0; i < nc; i++)
			diff_output("%c", getc(lb));
	}
	if (a > b)
		return;
	if (diff_format == D_IFDEF) {
		if (inifdef) {
			diff_output("#else /* %s%s */\n",
			    oldfile == 1 ? "!" : "", ifdefname);
		} else {
			if (oldfile)
				diff_output("#ifndef %s\n", ifdefname);
			else
				diff_output("#ifdef %s\n", ifdefname);
		}
		inifdef = 1 + oldfile;
	}
	for (i = a; i <= b; i++) {
		fseek(lb, f[i - 1], SEEK_SET);
		nc = f[i] - f[i - 1];
		if (diff_format != D_IFDEF && ch != '\0') {
			diff_output("%c", ch);
			if (diff_format != D_UNIFIED)
				diff_output(" ");
		}
		col = 0;
		for (j = 0; j < nc; j++) {
			if ((c = getc(lb)) == EOF) {
				if (diff_format == D_RCSDIFF)
					warn("No newline at end of file");
				else
					diff_output("\n\\ No newline at end of "
					    "file");
				return;
			}
			if (c == '\t' && (flags & D_EXPANDTABS)) {
				do {
					diff_output(" ");
				} while (++col & 7);
			} else {
				diff_output("%c", c);
				col++;
			}
		}
	}
}

/*
 * Hash function taken from Robert Sedgewick, Algorithms in C, 3d ed., p 578.
 */
static int
readhash(FILE *f, int flags)
{
	int i, t, space;
	int sum;

	sum = 1;
	space = 0;
	if ((flags & (D_FOLDBLANKS|D_IGNOREBLANKS)) == 0) {
		if (flags & D_IGNORECASE)
			for (i = 0; (t = getc(f)) != '\n'; i++) {
				if (t == EOF) {
					if (i == 0)
						return (0);
					break;
				}
				sum = sum * 127 + chrtran[t];
			}
		else
			for (i = 0; (t = getc(f)) != '\n'; i++) {
				if (t == EOF) {
					if (i == 0)
						return (0);
					break;
				}
				sum = sum * 127 + t;
			}
	} else {
		for (i = 0;;) {
			switch (t = getc(f)) {
			case '\t':
			case ' ':
				space++;
				continue;
			default:
				if (space && (flags & D_IGNOREBLANKS) == 0) {
					i++;
					space = 0;
				}
				sum = sum * 127 + chrtran[t];
				i++;
				continue;
			case EOF:
				if (i == 0)
					return (0);
				/* FALLTHROUGH */
			case '\n':
				break;
			}
			break;
		}
	}
	/*
	 * There is a remote possibility that we end up with a zero sum.
	 * Zero is used as an EOF marker, so return 1 instead.
	 */
	return (sum == 0 ? 1 : sum);
}

static int
asciifile(FILE *f)
{
	char buf[BUFSIZ];
	size_t i, cnt;

	if (f == NULL)
		return (1);

	rewind(f);
	cnt = fread(buf, 1, sizeof(buf), f);
	for (i = 0; i < cnt; i++)
		if (!isprint(buf[i]) && !isspace(buf[i]))
			return (0);
	return (1);
}

#define begins_with(s, pre) (strncmp(s, pre, sizeof(pre)-1) == 0)

static char*
match_function(const long *f, int pos, FILE *fp)
{
	unsigned char buf[FUNCTION_CONTEXT_SIZE];
	size_t nc;
	int last = lastline;
	char *p;
	char *state = NULL;

	lastline = pos;
	while (pos > last) {
		fseek(fp, f[pos - 1], SEEK_SET);
		nc = f[pos] - f[pos - 1];
		if (nc >= sizeof(buf))
			nc = sizeof(buf) - 1;
		nc = fread(buf, 1, nc, fp);
		if (nc > 0) {
			buf[nc] = '\0';
			p = strchr((const char *)buf, '\n');
			if (p != NULL)
				*p = '\0';
			if (isalpha(buf[0]) || buf[0] == '_' || buf[0] == '$') {
				if (begins_with(buf, "private:")) {
					if (!state)
						state = " (private)";
				} else if (begins_with(buf, "protected:")) {
					if (!state)
						state = " (protected)";
				} else if (begins_with(buf, "public:")) {
					if (!state)
						state = " (public)";
				} else {
					if (strlcpy(lastbuf, (const char *)buf,
					    sizeof(lastbuf)) >= sizeof(lastbuf))
						errx(1,
						    "match_function: strlcpy");
					lastmatchline = pos;
					return lastbuf;
				}
			}
		}
		pos--;
	}
	return (lastmatchline > 0) ? lastbuf : NULL;
}


/* dump accumulated "context" diff changes */
static void
dump_context_vec(FILE *f1, FILE *f2, int flags)
{
	struct context_vec *cvp = context_vec_start;
	int lowa, upb, lowc, upd, do_output;
	int a, b, c, d;
	char ch, *f;

	if (context_vec_start > context_vec_ptr)
		return;

	b = d = 0;		/* gcc */
	lowa = MAX(1, cvp->a - diff_context);
	upb = MIN(diff_len[0], context_vec_ptr->b + diff_context);
	lowc = MAX(1, cvp->c - diff_context);
	upd = MIN(diff_len[1], context_vec_ptr->d + diff_context);

	diff_output("***************");
	if ((flags & D_PROTOTYPE)) {
		f = match_function(ixold, lowa - 1, f1);
		if (f != NULL) {
			diff_output(" ");
			diff_output("%s", f);
		}
	}
	diff_output("\n*** ");
	range(lowa, upb, ",");
	diff_output(" ****\n");

	/*
	 * Output changes to the "old" file.  The first loop suppresses
	 * output if there were no changes to the "old" file (we'll see
	 * the "old" lines as context in the "new" list).
	 */
	do_output = 0;
	for (; cvp <= context_vec_ptr; cvp++)
		if (cvp->a <= cvp->b) {
			cvp = context_vec_start;
			do_output++;
			break;
		}
	if (do_output != 0) {
		while (cvp <= context_vec_ptr) {
			a = cvp->a;
			b = cvp->b;
			c = cvp->c;
			d = cvp->d;

			if (a <= b && c <= d)
				ch = 'c';
			else
				ch = (a <= b) ? 'd' : 'a';

			if (ch == 'a')
				fetch(ixold, lowa, b, f1, ' ', 0, flags);
			else {
				fetch(ixold, lowa, a - 1, f1, ' ', 0, flags);
				fetch(ixold, a, b, f1,
				    ch == 'c' ? '!' : '-', 0, flags);
			}
			lowa = b + 1;
			cvp++;
		}
		fetch(ixold, b + 1, upb, f1, ' ', 0, flags);
	}
	/* output changes to the "new" file */
	diff_output("--- ");
	range(lowc, upd, ",");
	diff_output(" ----\n");

	do_output = 0;
	for (cvp = context_vec_start; cvp <= context_vec_ptr; cvp++)
		if (cvp->c <= cvp->d) {
			cvp = context_vec_start;
			do_output++;
			break;
		}
	if (do_output != 0) {
		while (cvp <= context_vec_ptr) {
			a = cvp->a;
			b = cvp->b;
			c = cvp->c;
			d = cvp->d;

			if (a <= b && c <= d)
				ch = 'c';
			else
				ch = (a <= b) ? 'd' : 'a';

			if (ch == 'd')
				fetch(ixnew, lowc, d, f2, ' ', 0, flags);
			else {
				fetch(ixnew, lowc, c - 1, f2, ' ', 0, flags);
				fetch(ixnew, c, d, f2,
				    ch == 'c' ? '!' : '+', 0, flags);
			}
			lowc = d + 1;
			cvp++;
		}
		fetch(ixnew, d + 1, upd, f2, ' ', 0, flags);
	}
	context_vec_ptr = context_vec_start - 1;
}

/* dump accumulated "unified" diff changes */
static void
dump_unified_vec(FILE *f1, FILE *f2, int flags)
{
	struct context_vec *cvp = context_vec_start;
	int lowa, upb, lowc, upd;
	int a, b, c, d;
	char ch, *f;

	if (context_vec_start > context_vec_ptr)
		return;

	b = d = 0;		/* gcc */
	lowa = MAX(1, cvp->a - diff_context);
	upb = MIN(diff_len[0], context_vec_ptr->b + diff_context);
	lowc = MAX(1, cvp->c - diff_context);
	upd = MIN(diff_len[1], context_vec_ptr->d + diff_context);

	diff_output("@@ -");
	uni_range(lowa, upb);
	diff_output(" +");
	uni_range(lowc, upd);
	diff_output(" @@");
	if ((flags & D_PROTOTYPE)) {
		f = match_function(ixold, lowa - 1, f1);
		if (f != NULL) {
			diff_output(" ");
			diff_output("%s", f);
		}
	}
	diff_output("\n");

	/*
	 * Output changes in "unified" diff format--the old and new lines
	 * are printed together.
	 */
	for (; cvp <= context_vec_ptr; cvp++) {
		a = cvp->a;
		b = cvp->b;
		c = cvp->c;
		d = cvp->d;

		/*
		 * c: both new and old changes
		 * d: only changes in the old file
		 * a: only changes in the new file
		 */
		if (a <= b && c <= d)
			ch = 'c';
		else
			ch = (a <= b) ? 'd' : 'a';

		switch (ch) {
		case 'c':
			fetch(ixold, lowa, a - 1, f1, ' ', 0, flags);
			fetch(ixold, a, b, f1, '-', 0, flags);
			fetch(ixnew, c, d, f2, '+', 0, flags);
			break;
		case 'd':
			fetch(ixold, lowa, a - 1, f1, ' ', 0, flags);
			fetch(ixold, a, b, f1, '-', 0, flags);
			break;
		case 'a':
			fetch(ixnew, lowc, c - 1, f2, ' ', 0, flags);
			fetch(ixnew, c, d, f2, '+', 0, flags);
			break;
		}
		lowa = b + 1;
		lowc = d + 1;
	}
	fetch(ixnew, d + 1, upd, f2, ' ', 0, flags);

	context_vec_ptr = context_vec_start - 1;
}

void
diff_output(const char *fmt, ...)
{
	va_list vap;
	int i;
	char *str;

	va_start(vap, fmt);
	i = vasprintf(&str, fmt, vap);
	va_end(vap);
	if (i == -1)
		err(1, "diff_output");
	if (diffbuf != NULL)
		rcs_buf_append(diffbuf, str, strlen(str));
	else
		printf("%s", str);
	xfree(str);
}
