/* Copyright (c) 2011, TrafficLab, Ericsson Research, Hungary
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *   * Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *   * Neither the name of the Ericsson Research nor the names of its
 *     contributors may be used to endorse or promote products derived from
 *     this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 *
 * Author: Zoltán Lajos Kis <zoltan.lajos.kis@ericsson.com>
 */

#include <stdbool.h>
#include <string.h>
#include "match_std.h"
#include "oflib/ofl-structs.h"


/* Returns true if the given field is set in the wildcard field */
static inline bool
wc(uint32_t wildcards, uint32_t field) {
    return (wildcards & field) != 0;
}

/* Two matches overlap, if there exists a packet,
   which both match structures match on. */
bool
match_std_overlap(struct ofl_match_standard *a, struct ofl_match_standard *b) {
	return match_std_nonstrict(a, b) || match_std_nonstrict(b, a);
}

/* Two matches strictly match, if their wildcard fields are the same, and all the
 * non-wildcarded fields match on the same exact values.
 * NOTE: Handling of bitmasked fields is not specified. In this implementation
 * masked fields are checked for equality, and only unmasked bits are compared
 * in the field.
 */
static inline bool
strict_wild8(uint8_t a, uint8_t b, uint32_t aw, uint32_t bw, uint32_t f) {
	return (wc(aw, f) && wc(bw, f)) ||
	      (~wc(aw, f) && ~wc(bw, f) && a == b);
}

static inline bool
strict_wild16(uint16_t a, uint16_t b, uint32_t aw, uint32_t bw, uint32_t f) {
	return (wc(aw, f) && wc(bw, f)) ||
	      (~wc(aw, f) && ~wc(bw, f) && a == b);
}

static inline bool
strict_wild32(uint32_t a, uint32_t b, uint32_t aw, uint32_t bw, uint32_t f) {
	return (wc(aw, f) && wc(bw, f)) ||
	      (~wc(aw, f) && ~wc(bw, f) && a == b);
}

static inline bool
strict_mask16(uint16_t a, uint16_t b, uint16_t am, uint16_t bm) {
	return (am == bm) && ((a ^ b) & ~am) == 0;
}

static inline bool
strict_mask32(uint32_t a, uint32_t b, uint32_t am, uint32_t bm) {
	return (am == bm) && ((a ^ b) & ~am) == 0;
}

static inline bool
strict_mask64(uint64_t a, uint64_t b, uint64_t am, uint64_t bm) {
	return (am == bm) && ((a ^ b) & ~am) == 0;
}

static inline bool
strict_dladdr(uint8_t *a, uint8_t *b, uint8_t *am, uint8_t *bm) {
	return strict_mask32(*((uint32_t *)a), *((uint32_t *)b), *((uint32_t *)am), *((uint32_t *)bm)) &&
		   strict_mask16(*((uint16_t *)(a+4)), *((uint16_t *)(b+4)), *((uint16_t *)(am+4)), *((uint16_t *)(bm+4)));}


bool
match_std_strict(struct ofl_match_standard *a, struct ofl_match_standard *b) {
	return strict_wild32(a->in_port, b->in_port, a->wildcards, b->wildcards, OFPFW_IN_PORT) &&
           strict_dladdr(a->dl_src, b->dl_src, a->dl_src_mask, b->dl_src_mask) &&
		   strict_dladdr(a->dl_dst, b->dl_dst, a->dl_dst_mask, b->dl_dst_mask) &&
		   strict_wild16(a->dl_vlan, b->dl_vlan, a->wildcards, b->wildcards, OFPFW_DL_VLAN) &&
		   strict_wild16(a->dl_vlan_pcp, b->dl_vlan_pcp, a->wildcards, b->wildcards, OFPFW_DL_VLAN_PCP) &&
		   strict_wild16(a->dl_type, b->dl_type, a->wildcards, b->wildcards, OFPFW_DL_TYPE) &&
		   strict_wild8 (a->nw_tos, b->nw_tos, a->wildcards, b->wildcards, OFPFW_NW_TOS) &&
		   strict_wild8 (a->nw_proto, b->nw_proto, a->wildcards, b->wildcards, OFPFW_NW_PROTO) &&
		   strict_mask32(a->nw_src, b->nw_src, a->nw_src_mask, b->nw_src_mask) &&
		   strict_mask32(a->nw_dst, b->nw_dst, a->nw_dst_mask, b->nw_dst_mask) &&
		   strict_wild16(a->tp_src, b->tp_src, a->wildcards, b->wildcards, OFPFW_TP_SRC) &&
		   strict_wild16(a->tp_dst, b->tp_dst, a->wildcards, b->wildcards, OFPFW_TP_DST) &&
		   strict_wild32(a->mpls_label, b->mpls_label, a->wildcards, b->wildcards, OFPFW_MPLS_LABEL) &&
		   strict_wild8 (a->mpls_tc, b->mpls_tc, a->wildcards, b->wildcards, OFPFW_MPLS_TC) &&
		   strict_mask64(a->metadata, b->metadata, a->metadata_mask, b->metadata_mask);
}


/* A match (a) non-strictly matches match (b), if for each field they are both
 * wildcarded, or (a) is wildcarded, and (b) isn't, or if neither is wildcarded
 * and they match on the same value.
 * NOTE: Handling of bitmasked fields is not specified. In this implementation
 * a masked field of (a) matches the field of (b) if all masked bits of (b) are
 * also masked in (a), and for each unmasked bits of (b) , the bit is either
 * masked in (a), or is set to the same value in both matches.
 * NOTE: This function is also used for flow matching on packets, where in packets
 * all wildcards and masked fields are set to zero.
 */
static inline bool
nonstrict_wild8(uint8_t a, uint8_t b, uint32_t aw, uint32_t bw, uint32_t f) {
	return (wc(bw, f) && wc(aw, f)) ||
	      (~wc(bw, f) && (wc(aw, f) || a == b));
}

static inline bool
nonstrict_wild16(uint16_t a, uint16_t b, uint32_t aw, uint32_t bw, uint32_t f) {
	return (wc(bw, f) && wc(aw, f)) ||
	      (~wc(bw, f) && (wc(aw, f) || a == b));
}

static inline bool
nonstrict_wild32(uint32_t a, uint32_t b, uint32_t aw, uint32_t bw, uint32_t f) {
	return (wc(bw, f) && wc(aw, f)) ||
	      (~wc(bw, f) && (wc(aw, f) || a == b));
}

static inline bool
nonstrict_mask16(uint16_t a, uint16_t b, uint16_t am, uint16_t bm) {
	return (~am & (~a | ~b | bm) & (a | b | bm)) == 0;
}

static inline bool
nonstrict_mask32(uint32_t a, uint32_t b, uint32_t am, uint32_t bm) {
	return (~am & (~a | ~b | bm) & (a | b | bm)) == 0;
}

static inline bool
nonstrict_mask64(uint64_t a, uint64_t b, uint64_t am, uint64_t bm) {
	return (~am & (~a | ~b | bm) & (a | b | bm)) == 0;
}

static inline bool
nonstrict_dladdr(uint8_t *a, uint8_t *b, uint8_t *am, uint8_t *bm) {
	return nonstrict_mask32(*((uint32_t *)a), *((uint32_t *)b), *((uint32_t *)am), *((uint32_t *)bm)) &&
		   nonstrict_mask16(*((uint16_t *)(a+4)), *((uint16_t *)(b+4)), *((uint16_t *)(am+4)), *((uint16_t *)(bm+4)));
}

static inline bool
nonstrict_dlvlan(uint16_t a, uint16_t b, uint32_t aw, uint32_t bw) {
	uint32_t f = OFPFW_DL_VLAN;
	return (wc(bw, f) && wc(aw, f)) ||
	      (~wc(bw, f) && (wc(aw, f) || (a == OFPVID_ANY && b != OFPVID_NONE) || a == b));
}

static inline bool
nonstrict_dlvpcp(uint16_t avlan, uint16_t apcp, uint16_t bvlan, uint16_t bpcp, uint32_t aw, uint32_t bw) {
	uint32_t f = OFPFW_DL_VLAN_PCP;
	return (wc(bw, f) && wc(aw, f)) ||
	      (~wc(bw, f) && (wc(aw, f) || (avlan == OFPVID_NONE && bvlan == OFPVID_NONE) || apcp == bpcp));
}

bool
match_std_nonstrict(struct ofl_match_standard *a, struct ofl_match_standard *b) {
	return nonstrict_wild32(a->in_port, b->in_port, a->wildcards, b->wildcards, OFPFW_IN_PORT) &&
           nonstrict_dladdr(a->dl_src, b->dl_src, a->dl_src_mask, b->dl_src_mask) &&
		   nonstrict_dladdr(a->dl_dst, b->dl_dst, a->dl_dst_mask, b->dl_dst_mask) &&
		   nonstrict_dlvlan(a->dl_vlan, b->dl_vlan, a->wildcards, b->wildcards) &&
		   nonstrict_dlvpcp(a->dl_vlan, a->dl_vlan_pcp, b->dl_vlan, b->dl_vlan_pcp, a->wildcards, b->wildcards) &&
		   nonstrict_wild16(a->dl_type, b->dl_type, a->wildcards, b->wildcards, OFPFW_DL_TYPE) &&
		   nonstrict_wild8 (a->nw_tos, b->nw_tos, a->wildcards, b->wildcards, OFPFW_NW_TOS) &&
		   nonstrict_wild8 (a->nw_proto, b->nw_proto, a->wildcards, b->wildcards, OFPFW_NW_PROTO) &&
		   nonstrict_mask32(a->nw_src, b->nw_src, a->nw_src_mask, b->nw_src_mask) &&
		   nonstrict_mask32(a->nw_dst, b->nw_dst, a->nw_dst_mask, b->nw_dst_mask) &&
		   nonstrict_wild16(a->tp_src, b->tp_src, a->wildcards, b->wildcards, OFPFW_TP_SRC) &&
		   nonstrict_wild16(a->tp_dst, b->tp_dst, a->wildcards, b->wildcards, OFPFW_TP_DST) &&
		   nonstrict_wild32(a->mpls_label, b->mpls_label, a->wildcards, b->wildcards, OFPFW_MPLS_LABEL) &&
		   nonstrict_wild8 (a->mpls_tc, b->mpls_tc, a->wildcards, b->wildcards, OFPFW_MPLS_TC) &&
		   nonstrict_mask64(a->metadata, b->metadata, a->metadata_mask, b->metadata_mask);
}



/* A special match, where it is assumed that the wildcards and masks of (b) are
 * not used. Specifically used for matching on packets. */
static inline bool
pkt_wild8(uint8_t a, uint8_t b, uint32_t aw, uint32_t f) {
	return wc(aw, f) || a == b;
}

static inline bool
pkt_wild16(uint16_t a, uint16_t b, uint32_t aw, uint32_t f) {
	return wc(aw, f) || a == b;
}

static inline bool
pkt_wild32(uint32_t a, uint32_t b, uint32_t aw, uint32_t f) {
	return wc(aw, f) || a == b;
}

static inline bool
pkt_mask16(uint16_t a, uint16_t b, uint16_t am) {
	return (~am & (a^b)) == 0;
}

static inline bool
pkt_mask32(uint32_t a, uint32_t b, uint32_t am) {
	return (~am & (a^b)) == 0;
}

static inline bool
pkt_mask64(uint64_t a, uint64_t b, uint64_t am) {
	return (~am & (a^b)) == 0;
}

static inline bool
pkt_dladdr(uint8_t *a, uint8_t *b, uint8_t *am) {
	return pkt_mask32(*((uint32_t *)a), *((uint32_t *)b), *((uint32_t *)am)) &&
		   pkt_mask16(*((uint16_t *)(a+4)), *((uint16_t *)(b+4)), *((uint16_t *)(am+4)));
}

static inline bool
pkt_dlvlan(uint16_t a, uint16_t b, uint32_t aw) {
	uint32_t f = OFPFW_DL_VLAN;
	return wc(aw, f) || (a == OFPVID_ANY && b != OFPVID_NONE) || a == b;
}

static inline bool
pkt_dlvpcp(uint16_t avlan, uint16_t apcp, uint16_t bvlan, uint16_t bpcp, uint32_t aw) {
	uint32_t f = OFPFW_DL_VLAN_PCP;
	return wc(aw, f) || (avlan == OFPVID_NONE && bvlan == OFPVID_NONE) || apcp == bpcp;
}

bool
match_std_pkt(struct ofl_match_standard *a, struct ofl_match_standard *b) {
	return pkt_wild32(a->in_port, b->in_port, a->wildcards, OFPFW_IN_PORT) &&
           pkt_dladdr(a->dl_src, b->dl_src, a->dl_src_mask) &&
		   pkt_dladdr(a->dl_dst, b->dl_dst, a->dl_dst_mask) &&
		   pkt_dlvlan(a->dl_vlan, b->dl_vlan, a->wildcards) &&
		   pkt_dlvpcp(a->dl_vlan, a->dl_vlan_pcp, b->dl_vlan, b->dl_vlan_pcp, a->wildcards) &&
		   pkt_wild16(a->dl_type, b->dl_type, a->wildcards, OFPFW_DL_TYPE) &&
		   pkt_wild8 (a->nw_tos, b->nw_tos, a->wildcards, OFPFW_NW_TOS) &&
		   pkt_wild8 (a->nw_proto, b->nw_proto, a->wildcards, OFPFW_NW_PROTO) &&
		   pkt_mask32(a->nw_src, b->nw_src, a->nw_src_mask) &&
		   pkt_mask32(a->nw_dst, b->nw_dst, a->nw_dst_mask) &&
		   pkt_wild16(a->tp_src, b->tp_src, a->wildcards, OFPFW_TP_SRC) &&
		   pkt_wild16(a->tp_dst, b->tp_dst, a->wildcards, OFPFW_TP_DST) &&
		   pkt_wild32(a->mpls_label, b->mpls_label, a->wildcards, OFPFW_MPLS_LABEL) &&
		   pkt_wild8 (a->mpls_tc, b->mpls_tc, a->wildcards, OFPFW_MPLS_TC) &&
		   pkt_mask64(a->metadata, b->metadata, a->metadata_mask);
}
