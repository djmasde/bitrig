/* $OpenBSD$ */
/*
 * Copyright (c) 2007, 2009, 2012 Dale Rahn <drahn@dalerahn.com>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#define	CM_FCLKEN1_CORE         0x0a00
#define	CM_FCLKEN1_CORE_MSK     0x41fffe00
#define	CM_FCLKEN2_CORE		0x0a04
#define	CM_FCLKEN2_CORE_MSK     0x00000000
#define	CM_FCLKEN3_CORE		0x0a08
#define	CM_FCLKEN3_CORE_MSK     0x00000007

#define	O4_PRCM_REG_CORE_CLK1_FADDR	CM_FCLKEN1_CORE
#define	O4_PRCM_REG_CORE_CLK1_IADDR	CM_ICLKEN1_CORE
#define	O4_PRCM_REG_CORE_CLK1_FMASK	CM_FCLKEN1_CORE_MSK
#define	O4_PRCM_REG_CORE_CLK1_IMASK	CM_ICLKEN1_CORE_MSK

#define	O4_PRCM_REG_CORE_CLK2_FADDR	CM_FCLKEN2_CORE
#define	O4_PRCM_REG_CORE_CLK2_IADDR	CM_ICLKEN2_CORE
#define	O4_PRCM_REG_CORE_CLK2_FMASK	CM_FCLKEN2_CORE_MSK
#define	O4_PRCM_REG_CORE_CLK2_IMASK	CM_ICLKEN2_CORE_MSK

#define	O4_PRCM_REG_CORE_CLK3_FADDR	CM_FCLKEN3_CORE
#define	O4_PRCM_REG_CORE_CLK3_IADDR	CM_ICLKEN3_CORE
#define	O4_PRCM_REG_CORE_CLK3_FMASK	CM_FCLKEN3_CORE_MSK
#define	O4_PRCM_REG_CORE_CLK3_IMASK	CM_ICLKEN3_CORE_MSK

#define	O4_PRCM_REG_USBHOST_FADDR	0x1400
#define	O4_PRCM_REG_USBHOST_IADDR	0x1410
#define	O4_PRCM_REG_USBHOST_FMASK	0x3
#define	O4_PRCM_REG_USBHOST_IMASK	0x1

#define	O4_PRCM_REG_MAX	4

#define O4_L3INIT_CM2_OFFSET              0x00001300
#define O4_CLKCTRL_MODULEMODE_MASK       0x00000003
#define O4_CLKCTRL_MODULEMODE_DISABLE    0x00000000
#define O4_CLKCTRL_MODULEMODE_AUTO       0x00000001
#define O4_CLKCTRL_MODULEMODE_ENABLE     0x00000001

int prcm_hsusbhost_deactivate_omap4(int type);
int prcm_hsusbhost_activate_omap4(int type);
