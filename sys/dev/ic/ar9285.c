/*	$OpenBSD: ar9285.c,v 1.1 2009/11/14 16:55:11 damien Exp $	*/

/*-
 * Copyright (c) 2009 Damien Bergamini <damien.bergamini@free.fr>
 * Copyright (c) 2008-2009 Atheros Communications Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
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

/*
 * Driver for Atheros 802.11a/g/n chipsets.
 * Routines for AR9285 chipsets.
 */

#include "bpfilter.h"

#include <sys/param.h>
#include <sys/sockio.h>
#include <sys/sysctl.h>
#include <sys/mbuf.h>
#include <sys/kernel.h>
#include <sys/socket.h>
#include <sys/systm.h>
#include <sys/malloc.h>
#include <sys/queue.h>
#include <sys/timeout.h>
#include <sys/conf.h>
#include <sys/device.h>

#include <machine/bus.h>
#include <machine/endian.h>
#include <machine/intr.h>

#if NBPFILTER > 0
#include <net/bpf.h>
#endif
#include <net/if.h>
#include <net/if_arp.h>
#include <net/if_dl.h>
#include <net/if_media.h>
#include <net/if_types.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/in_var.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>

#include <net80211/ieee80211_var.h>
#include <net80211/ieee80211_amrr.h>
#include <net80211/ieee80211_radiotap.h>

#include <dev/ic/athnreg.h>
#include <dev/ic/athnvar.h>

#include <dev/ic/ar9280reg.h>
#include <dev/ic/ar9285reg.h>

int	ar9285_attach(struct athn_softc *);
void	ar9285_setup(struct athn_softc *);
void	ar9285_swap_rom(struct athn_softc *);
const	struct ar_spur_chan *ar9285_get_spur_chans(struct athn_softc *, int);
void	ar9285_init_from_rom(struct athn_softc *, struct ieee80211_channel *,
	    struct ieee80211_channel *);
void	ar9285_pa_calib(struct athn_softc *);
int	ar9285_1_2_init_calib(struct athn_softc *, struct ieee80211_channel *,
	    struct ieee80211_channel *);
void	ar9285_get_pdadcs(struct athn_softc *, struct ieee80211_channel *,
	    int, uint8_t, uint8_t *, uint8_t *);
void	ar9285_set_power_calib(struct athn_softc *,
	    struct ieee80211_channel *);
void	ar9285_set_txpower(struct athn_softc *, struct ieee80211_channel *,
	    struct ieee80211_channel *);

int
ar9285_attach(struct athn_softc *sc)
{
	sc->eep_base = AR9285_EEP_START_LOC;
	sc->eep_size = sizeof (struct ar9285_eeprom);
	sc->def_nf = AR9285_PHY_CCA_MAX_GOOD_VALUE;
	sc->ngpiopins = 12;
	sc->workaround = AR9285_WA_DEFAULT;
	sc->ops.setup = ar9285_setup;
	sc->ops.swap_rom = ar9285_swap_rom;
	sc->ops.init_from_rom = ar9285_init_from_rom;
	sc->ops.set_txpower = ar9285_set_txpower;
	sc->ops.set_synth = ar9280_set_synth;
	sc->ops.spur_mitigate = ar9280_spur_mitigate;
	sc->ops.get_spur_chans = ar9285_get_spur_chans;
	sc->ops.olpc_init = NULL;
	if (AR_SREV_9285_12_OR_LATER(sc))
		sc->ini = &ar9285_1_2_ini;
	else
		sc->ini = &ar9285_1_0_ini;
	sc->serdes = ar9280_2_0_serdes;
	return (0);
}

void
ar9285_setup(struct athn_softc *sc)
{
	const struct ar9285_eeprom *eep = sc->eep;
	uint8_t type;

	if (AR_SREV_9285_12(sc)) {
		/* Select initialization values based on ROM. */
		type = eep->baseEepHeader.txGainType;
		DPRINTF(("Tx gain type=0x%x\n", type));
		if (type == AR_EEP_TXGAIN_HIGH_POWER)
			sc->tx_gain = &ar9285_1_2_tx_gain_high_power;
		else
			sc->tx_gain = &ar9285_1_2_tx_gain;
	}
}

void
ar9285_swap_rom(struct athn_softc *sc)
{
	struct ar9285_eeprom *eep = sc->eep;
	int i;

	eep->modalHeader.antCtrlCommon =
	    swap32(eep->modalHeader.antCtrlCommon);
	eep->modalHeader.antCtrlChain =
	    swap32(eep->modalHeader.antCtrlChain);

	for (i = 0; i < AR_EEPROM_MODAL_SPURS; i++) {
		eep->modalHeader.spurChans[i].spurChan =
		    swap16(eep->modalHeader.spurChans[i].spurChan);
	}
}

const struct ar_spur_chan *
ar9285_get_spur_chans(struct athn_softc *sc, int is2ghz)
{
	const struct ar9285_eeprom *eep = sc->eep;

	KASSERT(is2ghz);
	return eep->modalHeader.spurChans;
}

void
ar9285_init_from_rom(struct athn_softc *sc, struct ieee80211_channel *c,
    struct ieee80211_channel *extc)
{
	const struct ar9285_eeprom *eep = sc->eep;
	const struct ar9285_modal_eep_header *modal = &eep->modalHeader;
	uint32_t reg, offset = 0x1000;
	uint8_t ob[5], db1[5], db2[5];
	uint8_t txRxAtten;

	AR_WRITE(sc, AR_PHY_SWITCH_COM, modal->antCtrlCommon & 0xffff);
	AR_WRITE(sc, AR_PHY_SWITCH_CHAIN_0, modal->antCtrlChain);

	reg = AR_READ(sc, AR_PHY_TIMING_CTRL4_0);
	reg = RW(reg, AR_PHY_TIMING_CTRL4_IQCORR_Q_I_COFF, modal->iqCalI);
	reg = RW(reg, AR_PHY_TIMING_CTRL4_IQCORR_Q_Q_COFF, modal->iqCalQ);
	AR_WRITE(sc, AR_PHY_TIMING_CTRL4_0, reg);

	if (sc->eep_rev >= AR_EEP_MINOR_VER_3) {
		reg = AR_READ(sc, AR_PHY_GAIN_2GHZ);
		reg = RW(reg, AR_PHY_GAIN_2GHZ_XATTEN1_MARGIN,
		    modal->bswMargin);
		reg = RW(reg, AR_PHY_GAIN_2GHZ_XATTEN1_DB,
		    modal->bswAtten);
		reg = RW(reg, AR_PHY_GAIN_2GHZ_XATTEN2_MARGIN,
		    modal->xatten2Margin);
		reg = RW(reg, AR_PHY_GAIN_2GHZ_XATTEN2_DB,
		    modal->xatten2Db);
		AR_WRITE(sc, AR_PHY_GAIN_2GHZ, reg);

		/* Duplicate values of chain 0 for chain 1. */
		reg = AR_READ(sc, AR_PHY_GAIN_2GHZ + offset);
		reg = RW(reg, AR_PHY_GAIN_2GHZ_XATTEN1_MARGIN,
		    modal->bswMargin);
		reg = RW(reg, AR_PHY_GAIN_2GHZ_XATTEN1_DB,
		    modal->bswAtten);
		reg = RW(reg, AR_PHY_GAIN_2GHZ_XATTEN2_MARGIN,
		    modal->xatten2Margin);
		reg = RW(reg, AR_PHY_GAIN_2GHZ_XATTEN2_DB,
		    modal->xatten2Db);
		AR_WRITE(sc, AR_PHY_GAIN_2GHZ + offset, reg);
	}
	if (sc->eep_rev >= AR_EEP_MINOR_VER_3)
		txRxAtten = modal->txRxAtten;
	else	/* Workaround for ROM versions < 14.3. */
		txRxAtten = 23;
	reg = AR_READ(sc, AR_PHY_RXGAIN);
	reg = RW(reg, AR9280_PHY_RXGAIN_TXRX_ATTEN, txRxAtten);
	reg = RW(reg, AR9280_PHY_RXGAIN_TXRX_MARGIN, modal->rxTxMargin);
	AR_WRITE(sc, AR_PHY_RXGAIN, reg);

	/* Duplicate values of chain 0 for chain 1. */
	reg = AR_READ(sc, AR_PHY_RXGAIN + offset);
	reg = RW(reg, AR9280_PHY_RXGAIN_TXRX_ATTEN, txRxAtten);
	reg = RW(reg, AR9280_PHY_RXGAIN_TXRX_MARGIN, modal->rxTxMargin);
	AR_WRITE(sc, AR_PHY_RXGAIN + offset, reg);

	if (AR_SREV_9285_11(sc))
		AR_WRITE(sc, AR9285_AN_TOP4, AR9285_AN_TOP4_DEFAULT | 0x14);

	if (modal->version >= 3) {
		/* Setup antenna diversity from ROM. */
		reg = AR_READ(sc, AR_PHY_MULTICHAIN_GAIN_CTL);
		reg = RW(reg, AR9285_PHY_ANT_DIV_CTL_ALL, 0);
		reg = RW(reg, AR9285_PHY_ANT_DIV_CTL,
		    (modal->ob_234  >> 12) & 0x1);
		reg = RW(reg, AR9285_PHY_ANT_DIV_ALT_LNACONF,
		    (modal->db1_234 >> 12) & 0x3);
		reg = RW(reg, AR9285_PHY_ANT_DIV_MAIN_LNACONF,
		    (modal->db1_234 >> 14) & 0x1);
		reg = RW(reg, AR9285_PHY_ANT_DIV_ALT_GAINTB,
		    (modal->ob_234  >> 13) & 0x1);
		reg = RW(reg, AR9285_PHY_ANT_DIV_MAIN_GAINTB,
		    (modal->ob_234  >> 14) & 0x1);
		AR_WRITE(sc, AR_PHY_MULTICHAIN_GAIN_CTL, reg);
		reg = AR_READ(sc, AR_PHY_MULTICHAIN_GAIN_CTL);	/* Flush. */

		reg = AR_READ(sc, AR_PHY_CCK_DETECT);
		if (modal->ob_234 & (1 << 15))
			reg |= AR_PHY_CCK_DETECT_BB_ENABLE_ANT_FAST_DIV;
		else
			reg &= ~AR_PHY_CCK_DETECT_BB_ENABLE_ANT_FAST_DIV;
		AR_WRITE(sc, AR_PHY_CCK_DETECT, reg);
		reg = AR_READ(sc, AR_PHY_CCK_DETECT);		/* Flush. */
	}
	if (modal->version >= 2) {
		ob [0] = (modal->ob_01   >> 0) & 0xf;
		ob [1] = (modal->ob_01   >> 4) & 0xf;
		ob [2] = (modal->ob_234  >> 0) & 0xf;
		ob [3] = (modal->ob_234  >> 4) & 0xf;
		ob [4] = (modal->ob_234  >> 8) & 0xf;

		db1[0] = (modal->db1_01  >> 0) & 0xf;
		db1[1] = (modal->db1_01  >> 4) & 0xf;
		db1[2] = (modal->db1_234 >> 0) & 0xf;
		db1[3] = (modal->db1_234 >> 4) & 0xf;
		db1[4] = (modal->db1_234 >> 8) & 0xf;

		db2[0] = (modal->db2_01  >> 0) & 0xf;
		db2[1] = (modal->db2_01  >> 4) & 0xf;
		db2[2] = (modal->db2_234 >> 0) & 0xf;
		db2[3] = (modal->db2_234 >> 4) & 0xf;
		db2[4] = (modal->db2_234 >> 8) & 0xf;

	} else if (modal->version == 1) {
		ob [0] = (modal->ob_01   >> 0) & 0xf;
		ob [1] = (modal->ob_01   >> 4) & 0xf;
		/* Field ob_234 does not exist, use ob_01. */
		ob [2] = ob [3] = ob [4] = ob [1];

		db1[0] = (modal->db1_01  >> 0) & 0xf;
		db1[1] = (modal->db1_01  >> 4) & 0xf;
		/* Field db1_234 does not exist, use db1_01. */
		db1[2] = db1[3] = db1[4] = db1[1];

		db2[0] = (modal->db2_01  >> 0) & 0xf;
		db2[1] = (modal->db2_01  >> 4) & 0xf;
		/* Field db2_234 does not exist, use db2_01. */
		db2[2] = db2[3] = db2[4] = db2[1];

	} else {
		ob [0] = modal->ob_01;
		ob [1] = ob [2] = ob [3] = ob [4] = ob [0];

		db1[0] = modal->db1_01;
		db1[1] = db1[2] = db1[3] = db1[4] = db1[0];

		/* Field db2_01 does not exist, use db1_01. */
		db2[0] = modal->db1_01;
		db2[1] = db2[2] = db2[3] = db2[4] = db2[0];
	}
	reg = AR_READ(sc, AR9285_AN_RF2G3);
	reg = RW(reg, AR9285_AN_RF2G3_OB_0,  ob [0]);
	reg = RW(reg, AR9285_AN_RF2G3_OB_1,  ob [1]);
	reg = RW(reg, AR9285_AN_RF2G3_OB_2,  ob [2]);
	reg = RW(reg, AR9285_AN_RF2G3_OB_3,  ob [3]);
	reg = RW(reg, AR9285_AN_RF2G3_OB_4,  ob [4]);
	reg = RW(reg, AR9285_AN_RF2G3_DB1_0, db1[0]);
	reg = RW(reg, AR9285_AN_RF2G3_DB1_1, db1[1]);
	reg = RW(reg, AR9285_AN_RF2G3_DB1_2, db1[2]);
	AR_WRITE(sc, AR9285_AN_RF2G3, reg);
	DELAY(100);
	reg = AR_READ(sc, AR9285_AN_RF2G4);
	reg = RW(reg, AR9285_AN_RF2G4_DB1_3, db1[3]);
	reg = RW(reg, AR9285_AN_RF2G4_DB1_4, db1[4]);
	reg = RW(reg, AR9285_AN_RF2G4_DB2_0, db2[0]);
	reg = RW(reg, AR9285_AN_RF2G4_DB2_1, db2[1]);
	reg = RW(reg, AR9285_AN_RF2G4_DB2_2, db2[2]);
	reg = RW(reg, AR9285_AN_RF2G4_DB2_3, db2[3]);
	reg = RW(reg, AR9285_AN_RF2G4_DB2_4, db2[4]);
	AR_WRITE(sc, AR9285_AN_RF2G4, reg);
	DELAY(100);

	if (AR_SREV_9285_11(sc))
		AR_WRITE(sc, AR9285_AN_TOP4, AR9285_AN_TOP4_DEFAULT);

	reg = AR_READ(sc, AR_PHY_SETTLING);
	reg = RW(reg, AR_PHY_SETTLING_SWITCH, modal->switchSettling);
	AR_WRITE(sc, AR_PHY_SETTLING, reg);

	reg = AR_READ(sc, AR_PHY_DESIRED_SZ);
	reg = RW(reg, AR_PHY_DESIRED_SZ_ADC, modal->adcDesiredSize);
	AR_WRITE(sc, AR_PHY_DESIRED_SZ, reg);

	reg =  SM(AR_PHY_RF_CTL4_TX_END_XPAA_OFF, modal->txEndToXpaOff);
	reg |= SM(AR_PHY_RF_CTL4_TX_END_XPAB_OFF, modal->txEndToXpaOff);
	reg |= SM(AR_PHY_RF_CTL4_FRAME_XPAA_ON, modal->txFrameToXpaOn);
	reg |= SM(AR_PHY_RF_CTL4_FRAME_XPAB_ON, modal->txFrameToXpaOn);
	AR_WRITE(sc, AR_PHY_RF_CTL4, reg);

	reg = AR_READ(sc, AR_PHY_RF_CTL3);
	reg = RW(reg, AR_PHY_TX_END_TO_A2_RX_ON, modal->txEndToRxOn);
	AR_WRITE(sc, AR_PHY_RF_CTL3, reg);

	reg = AR_READ(sc, AR_PHY_CCA(0));
	reg = RW(reg, AR9280_PHY_CCA_THRESH62, modal->thresh62);
	AR_WRITE(sc, AR_PHY_CCA(0), reg);

	reg = AR_READ(sc, AR_PHY_EXT_CCA0);
	reg = RW(reg, AR_PHY_EXT_CCA0_THRESH62, modal->thresh62);
	AR_WRITE(sc, AR_PHY_EXT_CCA0, reg);

	if (sc->eep_rev >= AR_EEP_MINOR_VER_2) {
		reg = AR_READ(sc, AR_PHY_RF_CTL2);
		reg = RW(reg, AR_PHY_TX_END_PA_ON,
		    modal->txFrameToPaOn);
		reg = RW(reg, AR_PHY_TX_END_DATA_START,
		    modal->txFrameToDataStart);
		AR_WRITE(sc, AR_PHY_RF_CTL2, reg);
	}
#ifndef IEEE80211_NO_HT
	if (sc->eep_rev >= AR_EEP_MINOR_VER_3 && extc != NULL) {
		reg = AR_READ(sc, AR_PHY_SETTLING);
		reg = RW(reg, AR_PHY_SETTLING_SWITCH, modal->swSettleHt40);
		AR_WRITE(sc, AR_PHY_SETTLING, reg);
	}
#endif
}

void
ar9285_pa_calib(struct athn_softc *sc)
{
	/* List of registers that need to be saved/restored. */
	static const uint16_t regs[] = {
		AR9285_AN_TOP3,
		AR9285_AN_RXTXBB1,
		AR9285_AN_RF2G1,
		AR9285_AN_RF2G2,
		AR9285_AN_TOP2,
		AR9285_AN_RF2G8,
		AR9285_AN_RF2G7
	};
	uint32_t svg[7], reg, ccomp_svg;
	int i;

	/* No PA calibration needed for high power solutions. */
	if (AR_SREV_9285(sc) &&
	    ((struct ar9285_base_eep_header *)sc->eep)->txGainType ==
	     AR_EEP_TXGAIN_HIGH_POWER)	/* XXX AR9287? */
		return;

	if (AR_SREV_9285_11(sc)) {
		/* XXX magic 0x14. */
		AR_WRITE(sc, AR9285_AN_TOP4, AR9285_AN_TOP4_DEFAULT | 0x14);
		DELAY(10);
	}

	/* Save registers. */
	for (i = 0; i < nitems(regs); i++)
		svg[i] = AR_READ(sc, regs[i]);

	AR_CLRBITS(sc, AR9285_AN_RF2G6, 1);
	AR_SETBITS(sc, AR_PHY(2), 1 << 27);

	AR_SETBITS(sc, AR9285_AN_TOP3, AR9285_AN_TOP3_PWDDAC);
	AR_SETBITS(sc, AR9285_AN_RXTXBB1, AR9285_AN_RXTXBB1_PDRXTXBB1);
	AR_SETBITS(sc, AR9285_AN_RXTXBB1, AR9285_AN_RXTXBB1_PDV2I);
	AR_SETBITS(sc, AR9285_AN_RXTXBB1, AR9285_AN_RXTXBB1_PDDACIF);
	AR_CLRBITS(sc, AR9285_AN_RF2G2, AR9285_AN_RF2G2_OFFCAL);
	AR_CLRBITS(sc, AR9285_AN_RF2G7, AR9285_AN_RF2G7_PWDDB);
	AR_CLRBITS(sc, AR9285_AN_RF2G1, AR9285_AN_RF2G1_ENPACAL);
	/* Power down PA drivers. */
	AR_CLRBITS(sc, AR9285_AN_RF2G1, AR9285_AN_RF2G1_PDPADRV1);
	AR_CLRBITS(sc, AR9285_AN_RF2G1, AR9285_AN_RF2G1_PDPADRV2);
	AR_CLRBITS(sc, AR9285_AN_RF2G1, AR9285_AN_RF2G1_PDPAOUT);

	reg = AR_READ(sc, AR9285_AN_RF2G8);
	reg = RW(reg, AR9285_AN_RF2G8_PADRVGN2TAB0, 7);
	AR_WRITE(sc, AR9285_AN_RF2G8, reg);

	reg = AR_READ(sc, AR9285_AN_RF2G7);
	reg = RW(reg, AR9285_AN_RF2G7_PADRVGN2TAB0, 0);
	AR_WRITE(sc, AR9285_AN_RF2G7, reg);

	reg = AR_READ(sc, AR9285_AN_RF2G6);
	/* Save compensation capacitor value. */
	ccomp_svg = MS(reg, AR9285_AN_RF2G6_CCOMP);
	/* Program compensation capacitor for dynamic PA. */
	reg = RW(reg, AR9285_AN_RF2G6_CCOMP, 0xf);
	AR_WRITE(sc, AR9285_AN_RF2G6, reg);

	AR_WRITE(sc, AR9285_AN_TOP2, AR9285_AN_TOP2_DEFAULT);
	DELAY(30);

	/* Clear offsets 6-1. */
	AR_CLRBITS(sc, AR9285_AN_RF2G6, AR9285_AN_RF2G6_OFFS_6_1);
	/* Clear offset 0. */
	AR_CLRBITS(sc, AR9285_AN_RF2G3, AR9285_AN_RF2G3_PDVCCOMP);

	/* Set offsets 6-1. */
	for (i = 6; i >= 1; i--) {
		AR_SETBITS(sc, AR9285_AN_RF2G6, AR9285_AN_RF2G6_OFFS(i));
		DELAY(1);
		if (AR_READ(sc, AR9285_AN_RF2G9) & AR9285_AN_RXTXBB1_SPARE9) {
			AR_SETBITS(sc, AR9285_AN_RF2G6,
			    AR9285_AN_RF2G6_OFFS(i));
		} else {
			AR_CLRBITS(sc, AR9285_AN_RF2G6,
			    AR9285_AN_RF2G6_OFFS(i));
		}
	}
	/* Set offset 0. */
	AR_SETBITS(sc, AR9285_AN_RF2G3, AR9285_AN_RF2G3_PDVCCOMP);
	DELAY(1);
	if (AR_READ(sc, AR9285_AN_RF2G9) & AR9285_AN_RXTXBB1_SPARE9)
		AR_SETBITS(sc, AR9285_AN_RF2G3, AR9285_AN_RF2G3_PDVCCOMP);
	else
		AR_CLRBITS(sc, AR9285_AN_RF2G3, AR9285_AN_RF2G3_PDVCCOMP);

	AR_SETBITS(sc, AR9285_AN_RF2G6, 1);
	AR_CLRBITS(sc, AR_PHY(2), 1 << 27);

	/* Restore registers. */
	for (i = 0; i < nitems(regs); i++)
		AR_WRITE(sc, regs[i], svg[i]);

	/* Restore compensation capacitor value. */
	reg = AR_READ(sc, AR9285_AN_RF2G6);
	reg = RW(reg, AR9285_AN_RF2G6_CCOMP, ccomp_svg);
	AR_WRITE(sc, AR9285_AN_RF2G6, reg);

	if (AR_SREV_9285_11(sc))
		AR_WRITE(sc, AR9285_AN_TOP4, AR9285_AN_TOP4_DEFAULT);
}

/*
 * Carrier Leak Calibration (>= AR9285 1.2 only.)
 */
int
ar9285_1_2_init_calib(struct athn_softc *sc, struct ieee80211_channel *c,
    struct ieee80211_channel *extc)
{
	int ntries;

	AR_SETBITS(sc, AR_PHY_CL_CAL_CTL, AR_PHY_CL_CAL_ENABLE);
	if (extc == NULL) {	/* XXX IS_CHAN_HT20!! */
		AR_SETBITS(sc, AR_PHY_CL_CAL_CTL, AR_PHY_PARALLEL_CAL_ENABLE);
		AR_SETBITS(sc, AR_PHY_TURBO, AR_PHY_FC_DYN2040_EN);
		AR_CLRBITS(sc, AR_PHY_AGC_CONTROL,
		    AR_PHY_AGC_CONTROL_FLTR_CAL); 
		AR_CLRBITS(sc, AR_PHY_TPCRG1, AR_PHY_TPCRG1_PD_CAL_ENABLE);
		AR_SETBITS(sc, AR_PHY_AGC_CONTROL, AR_PHY_AGC_CONTROL_CAL);
		for (ntries = 0; ntries < 10000; ntries++) {
			if (!(AR_READ(sc, AR_PHY_AGC_CONTROL) &
			    AR_PHY_AGC_CONTROL_CAL))
				break;
			DELAY(10);
		}
		if (ntries == 10000)
			return (ETIMEDOUT);
		AR_CLRBITS(sc, AR_PHY_TURBO, AR_PHY_FC_DYN2040_EN);
		AR_CLRBITS(sc, AR_PHY_CL_CAL_CTL, AR_PHY_PARALLEL_CAL_ENABLE);
		AR_CLRBITS(sc, AR_PHY_CL_CAL_CTL, AR_PHY_CL_CAL_ENABLE);
	}
	AR_CLRBITS(sc, AR_PHY_ADC_CTL, AR_PHY_ADC_CTL_OFF_PWDADC);
	AR_SETBITS(sc, AR_PHY_AGC_CONTROL, AR_PHY_AGC_CONTROL_FLTR_CAL);
	AR_SETBITS(sc, AR_PHY_TPCRG1, AR_PHY_TPCRG1_PD_CAL_ENABLE);
	AR_SETBITS(sc, AR_PHY_AGC_CONTROL, AR_PHY_AGC_CONTROL_CAL);
	for (ntries = 0; ntries < 10000; ntries++) {
		if (!(AR_READ(sc, AR_PHY_AGC_CONTROL) &
		    AR_PHY_AGC_CONTROL_CAL))
			break;
		DELAY(10);
	}
	if (ntries == 10000)
		return (ETIMEDOUT);
	AR_SETBITS(sc, AR_PHY_ADC_CTL, AR_PHY_ADC_CTL_OFF_PWDADC);
	AR_CLRBITS(sc, AR_PHY_CL_CAL_CTL, AR_PHY_CL_CAL_ENABLE);
	AR_CLRBITS(sc, AR_PHY_AGC_CONTROL, AR_PHY_AGC_CONTROL_FLTR_CAL);
	return (0);
}

void
ar9285_get_pdadcs(struct athn_softc *sc, struct ieee80211_channel *c,
    int nxpdgains, uint8_t overlap, uint8_t *boundaries, uint8_t *pdadcs)
{
	const struct ar9285_eeprom *eep = sc->eep;
	const struct ar9285_cal_data_per_freq *pierdata;
	const uint8_t *pierfreq;
	struct athn_pier lopier, hipier;
	uint8_t fbin;
	int i, lo, hi, npiers;

	pierfreq = eep->calFreqPier2G;
	pierdata = eep->calPierData2G;
	npiers = AR9285_NUM_2G_CAL_PIERS;

	/* Find channel in ROM pier table. */
	fbin = athn_chan2fbin(c);
	athn_get_pier_ival(fbin, pierfreq, npiers, &lo, &hi);

	lopier.fbin = pierfreq[lo];
	hipier.fbin = pierfreq[hi];
	for (i = 0; i < nxpdgains; i++) {
		lopier.pwr[i] = pierdata[lo].pwrPdg[i];
		lopier.vpd[i] = pierdata[lo].vpdPdg[i];
		hipier.pwr[i] = pierdata[lo].pwrPdg[i];
		hipier.vpd[i] = pierdata[lo].vpdPdg[i];
	}
	athn_get_pdadcs(sc, fbin, &lopier, &hipier, nxpdgains,
	    AR9285_PD_GAIN_ICEPTS, overlap, boundaries, pdadcs);
}

void
ar9285_set_power_calib(struct athn_softc *sc, struct ieee80211_channel *c)
{
	const struct ar9285_eeprom *eep = sc->eep;
	uint8_t boundaries[AR_PD_GAINS_IN_MASK];
	uint8_t pdadcs[AR_NUM_PDADC_VALUES];
	uint8_t xpdgains[AR9285_NUM_PD_GAINS];
	uint8_t overlap;
	uint32_t reg;
	int i, nxpdgains;

	if (sc->eep_rev < AR_EEP_MINOR_VER_2) {
		overlap = MS(AR_READ(sc, AR_PHY_TPCRG5),
		    AR_PHY_TPCRG5_PD_GAIN_OVERLAP);
	} else
		overlap = eep->modalHeader.pdGainOverlap;

	nxpdgains = 0;
	memset(xpdgains, 0, sizeof xpdgains);
	for (i = AR9285_PD_GAINS_IN_MASK - 1; i >= 0; i--) {
		if (nxpdgains >= AR9285_NUM_PD_GAINS)
			break;
		if (eep->modalHeader.xpdGain & (1 << i))
			xpdgains[nxpdgains++] = i;
	}
	reg = AR_READ(sc, AR_PHY_TPCRG1);
	reg = RW(reg, AR_PHY_TPCRG1_NUM_PD_GAIN, nxpdgains - 1);
	reg = RW(reg, AR_PHY_TPCRG1_PD_GAIN_1, xpdgains[0]);
	reg = RW(reg, AR_PHY_TPCRG1_PD_GAIN_2, xpdgains[1]);
	AR_WRITE(sc, AR_PHY_TPCRG1, reg);

	/* NB: No open loop power control for AR9285. */
	ar9285_get_pdadcs(sc, c, nxpdgains, overlap, boundaries, pdadcs);

	/* Write boundaries. */
	reg  = SM(AR_PHY_TPCRG5_PD_GAIN_OVERLAP, overlap);
	reg |= SM(AR_PHY_TPCRG5_PD_GAIN_BOUNDARY_1, boundaries[0]);
	reg |= SM(AR_PHY_TPCRG5_PD_GAIN_BOUNDARY_2, boundaries[1]);
	reg |= SM(AR_PHY_TPCRG5_PD_GAIN_BOUNDARY_3, boundaries[2]);
	reg |= SM(AR_PHY_TPCRG5_PD_GAIN_BOUNDARY_4, boundaries[3]);
	AR_WRITE(sc, AR_PHY_TPCRG5, reg);

	/* Write PDADC values. */
	for (i = 0; i < AR_NUM_PDADC_VALUES; i += 4) {
		AR_WRITE(sc, AR_PHY_PDADC_TBL_BASE + i,
		    pdadcs[i + 0] <<  0 |
		    pdadcs[i + 1] <<  8 |
		    pdadcs[i + 2] << 16 |
		    pdadcs[i + 3] << 24);
	}
}

void
ar9285_set_txpower(struct athn_softc *sc, struct ieee80211_channel *c,
    struct ieee80211_channel *extc)
{
	const struct ar9285_eeprom *eep = sc->eep;
	const struct ar9285_modal_eep_header *modal = &eep->modalHeader;
	uint8_t tpow_cck[4], tpow_ofdm[4];
	uint8_t tpow_cck_ext[4], tpow_ofdm_ext[4];
	uint8_t tpow_ht20[8], tpow_ht40[8];
	int16_t max_ant_gain, power[ATHN_POWER_COUNT];
	uint8_t ht40inc;
	int i;

	ar9285_set_power_calib(sc, c);

	/* Compute transmit power reduction due to antenna gain. */
	max_ant_gain = modal->antennaGain;
	/* XXX */

	/* Get CCK target powers. */
	athn_get_lg_tpow(sc, c, AR_CTL_11B, eep->calTargetPowerCck,
	    AR9285_NUM_2G_CCK_TARGET_POWERS, tpow_cck);

	/* Get OFDM target powers. */
	athn_get_lg_tpow(sc, c, AR_CTL_11G, eep->calTargetPower2G,
	    AR9285_NUM_2G_20_TARGET_POWERS, tpow_ofdm);

#ifndef IEEE80211_NO_HT
	/* Get HT-20 target powers. */
	athn_get_ht_tpow(sc, c, AR_CTL_2GHT20, eep->calTargetPower2GHT20,
	    AR9285_NUM_2G_20_TARGET_POWERS, tpow_ht20);

	if (extc != NULL) {
		/* Get HT-40 target powers. */
		athn_get_ht_tpow(sc, c, AR_CTL_2GHT40,
		    eep->calTargetPower2GHT40, AR9285_NUM_2G_40_TARGET_POWERS,
		    tpow_ht40);

		/* Get secondary channel CCK target powers. */
		athn_get_lg_tpow(sc, extc, AR_CTL_11B, eep->calTargetPowerCck,
		    AR9285_NUM_2G_CCK_TARGET_POWERS, tpow_cck_ext);

		/* Get secondary channel OFDM target powers. */
		athn_get_lg_tpow(sc, extc, AR_CTL_11G,
		    eep->calTargetPower2G, AR9285_NUM_2G_20_TARGET_POWERS,
		    tpow_ofdm_ext);
	}
#endif

	memset(power, 0, sizeof power);
	/* Shuffle target powers accross transmit rates. */
	power[ATHN_POWER_OFDM6   ] =
	power[ATHN_POWER_OFDM9   ] =
	power[ATHN_POWER_OFDM12  ] =
	power[ATHN_POWER_OFDM18  ] =
	power[ATHN_POWER_OFDM24  ] = tpow_ofdm[0];
	power[ATHN_POWER_OFDM36  ] = tpow_ofdm[1];
	power[ATHN_POWER_OFDM48  ] = tpow_ofdm[2];
	power[ATHN_POWER_OFDM54  ] = tpow_ofdm[3];
	power[ATHN_POWER_XR      ] = tpow_ofdm[0];
	power[ATHN_POWER_CCK1_LP ] = tpow_cck[0];
	power[ATHN_POWER_CCK2_LP ] =
	power[ATHN_POWER_CCK2_SP ] = tpow_cck[1];
	power[ATHN_POWER_CCK55_LP] =
	power[ATHN_POWER_CCK55_SP] = tpow_cck[2];
	power[ATHN_POWER_CCK11_LP] =
	power[ATHN_POWER_CCK11_SP] = tpow_cck[3];
#ifndef IEEE80211_NO_HT
	for (i = 0; i < nitems(tpow_ht20); i++)
		power[ATHN_POWER_HT20(i)] = tpow_ht20[i];
	if (extc != NULL) {
		/* Correct PAR difference between HT40 and HT20/Legacy. */
		if (sc->eep_rev >= AR_EEP_MINOR_VER_2)
			ht40inc = modal->ht40PowerIncForPdadc;
		else
			ht40inc = AR_HT40_POWER_INC_FOR_PDADC;
		for (i = 0; i < nitems(tpow_ht40); i++)
			power[ATHN_POWER_HT40(i)] = tpow_ht40[i] + ht40inc;
		power[ATHN_POWER_OFDM_DUP] = tpow_ht40[0];
		power[ATHN_POWER_CCK_DUP ] = tpow_ht40[0];
		power[ATHN_POWER_OFDM_EXT] = tpow_ofdm_ext[0];
		power[ATHN_POWER_CCK_EXT ] = tpow_cck_ext[0];
	}
#endif

	for (i = 0; i < ATHN_POWER_COUNT; i++) {
		power[i] -= AR_PWR_TABLE_OFFSET_DB * 2;	/* In half dB. */
		if (power[i] > AR_MAX_RATE_POWER)
			power[i] = AR_MAX_RATE_POWER;
	}

	/* Commit transmit power values to hardware. */
	athn_write_txpower(sc, power);
}
