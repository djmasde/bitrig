/*	$OpenBSD: panel.c,v 1.7 1999/11/28 17:49:19 millert Exp $	*/

/****************************************************************************
 * Copyright (c) 1998 Free Software Foundation, Inc.                        *
 *                                                                          *
 * Permission is hereby granted, free of charge, to any person obtaining a  *
 * copy of this software and associated documentation files (the            *
 * "Software"), to deal in the Software without restriction, including      *
 * without limitation the rights to use, copy, modify, merge, publish,      *
 * distribute, distribute with modifications, sublicense, and/or sell       *
 * copies of the Software, and to permit persons to whom the Software is    *
 * furnished to do so, subject to the following conditions:                 *
 *                                                                          *
 * The above copyright notice and this permission notice shall be included  *
 * in all copies or substantial portions of the Software.                   *
 *                                                                          *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS  *
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF               *
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.   *
 * IN NO EVENT SHALL THE ABOVE COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,   *
 * DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR    *
 * OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR    *
 * THE USE OR OTHER DEALINGS IN THE SOFTWARE.                               *
 *                                                                          *
 * Except as contained in this notice, the name(s) of the above copyright   *
 * holders shall not be used in advertising or otherwise to promote the     *
 * sale, use or other dealings in this Software without prior written       *
 * authorization.                                                           *
 ****************************************************************************/

/****************************************************************************
 *  Author: Zeyd M. Ben-Halim <zmbenhal@netcom.com> 1995                    *
 *     and: Eric S. Raymond <esr@snark.thyrsus.com>                         *
 ****************************************************************************/

/* panel.c -- implementation of panels library, some core routines */
#include "panel.priv.h"

MODULE_ID("$From: panel.c,v 1.18 1999/09/29 15:22:32 juergen Exp $")

#ifdef TRACE
#ifndef TRACE_TXT
const char *_nc_my_visbuf(const void *ptr)
{
	char temp[32];
	if (ptr != 0)
		snprintf(temp, sizeof(temp), "ptr:%p", ptr);
	else
		strcpy(temp, "<null>");
	return _nc_visbuf(temp);
}
#endif
#endif


/*+-------------------------------------------------------------------------
	dPanel(text,pan)
--------------------------------------------------------------------------*/
#ifdef TRACE
void
_nc_dPanel(const char *text, const PANEL *pan)
{
	_tracef("%s id=%s b=%s a=%s y=%d x=%d",
		text, USER_PTR(pan->user),
		(pan->below) ?  USER_PTR(pan->below->user) : "--",
		(pan->above) ?  USER_PTR(pan->above->user) : "--",
		PSTARTY(pan), PSTARTX(pan));
}
#endif

/*+-------------------------------------------------------------------------
	dStack(fmt,num,pan)
--------------------------------------------------------------------------*/
#ifdef TRACE
void
_nc_dStack(const char *fmt, int num, const PANEL *pan)
{
  char s80[80];

  snprintf(s80,sizeof(s80),fmt,num,pan);
  _tracef("%s b=%s t=%s",s80,
	  (_nc_bottom_panel) ?  USER_PTR(_nc_bottom_panel->user) : "--",
	  (_nc_top_panel)    ?  USER_PTR(_nc_top_panel->user)    : "--");
  if(pan)
    _tracef("pan id=%s", USER_PTR(pan->user));
  pan = _nc_bottom_panel;
  while(pan)
    {
      dPanel("stk",pan);
      pan = pan->above;
    }
}
#endif

/*+-------------------------------------------------------------------------
	Wnoutrefresh(pan) - debugging hook for wnoutrefresh
--------------------------------------------------------------------------*/
#ifdef TRACE
void
_nc_Wnoutrefresh(const PANEL *pan)
{
  dPanel("wnoutrefresh",pan);
  wnoutrefresh(pan->win);
}
#endif

/*+-------------------------------------------------------------------------
	Touchpan(pan)
--------------------------------------------------------------------------*/
#ifdef TRACE
void
_nc_Touchpan(const PANEL *pan)
{
  dPanel("Touchpan",pan);
  touchwin(pan->win);
}
#endif

/*+-------------------------------------------------------------------------
	Touchline(pan,start,count)
--------------------------------------------------------------------------*/
#ifdef TRACE
void
_nc_Touchline(const PANEL *pan, int start, int count)
{
  char s80[80];
  snprintf(s80,sizeof(s80),"Touchline s=%d c=%d",start,count);
  dPanel(s80,pan);
  touchline(pan->win,start,count);
}
#endif

#ifndef TRACE
#  ifndef __GNUC__
     /* Some C compilers need something defined in a source file */
     static char GCC_UNUSED dummy;
#  endif
#endif
