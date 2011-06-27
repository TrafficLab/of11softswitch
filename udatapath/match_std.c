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

bool
match_std_strict(struct ofl_match_standard *a, struct ofl_match_standard *b) {
    return (a->in_port == b->in_port && a->wildcards == b->wildcards &&
            memcmp(a->dl_src, b->dl_src, OFP_ETH_ALEN) == 0 &&
            memcmp(a->dl_src_mask, b->dl_src_mask, OFP_ETH_ALEN) == 0 &&
            memcmp(a->dl_dst, b->dl_dst, OFP_ETH_ALEN) == 0 &&
            memcmp(a->dl_dst_mask, b->dl_dst_mask, OFP_ETH_ALEN) == 0 &&
            a->dl_vlan == b->dl_vlan && a->dl_vlan_pcp == b->dl_vlan_pcp &&
            a->dl_type == b->dl_type &&
            a->nw_tos == b->nw_tos && a->nw_proto == b-> nw_proto &&
            a->nw_src == b->nw_src && a->nw_dst == b->nw_dst &&
            a->tp_src == b->tp_src && a->tp_dst == b->tp_dst &&
            a->mpls_label == b->mpls_label && a->mpls_tc == b->mpls_tc &&
            a->metadata == b->metadata &&
            a->metadata_mask == b->metadata_mask);
}

/* Returns true if the two ethernet addresses match, considering their masks. */
static bool
eth_matches(uint8_t *a, uint8_t *am, uint8_t *b, uint8_t *bm) {
    return (((~am[0] & ~bm[0] & (a[0] ^ b[0])) == 0x00) &&
            ((~am[1] & ~bm[1] & (a[1] ^ b[1])) == 0x00) &&
            ((~am[2] & ~bm[2] & (a[2] ^ b[2])) == 0x00) &&
            ((~am[3] & ~bm[3] & (a[3] ^ b[3])) == 0x00) &&
            ((~am[4] & ~bm[4] & (a[4] ^ b[4])) == 0x00) &&
            ((~am[5] & ~bm[5] & (a[5] ^ b[5])) == 0x00));
}

/* Returns true if the given field is set among the wildcards */
static inline bool
wc(uint32_t wildcards, uint32_t field) {
    return ((wildcards & field) != 0);
}

/* Returns true if the given field is set in either wildcard field */
static inline bool
wc2(uint32_t wildcards_a, uint32_t wildcards_b, uint32_t field) {
    return (wc(wildcards_a, field) || wc(wildcards_b, field));
}
bool
match_std_nonstrict(struct ofl_match_standard *a, struct ofl_match_standard *b) {
    return ((wc2(a->wildcards, b->wildcards, OFPFW_IN_PORT) || a->in_port == b->in_port) &&
            eth_matches(a->dl_src, a->dl_src_mask, b->dl_src, b->dl_src_mask) &&
            eth_matches(a->dl_dst, a->dl_dst_mask, b->dl_dst, b->dl_dst_mask) &&
            (wc2(a->wildcards, b->wildcards, OFPFW_DL_VLAN) ||
                    (a->dl_vlan == OFPVID_ANY && b->dl_vlan != OFPVID_NONE) ||
                    (b->dl_vlan == OFPVID_ANY && a->dl_vlan != OFPVID_NONE) ||
                    (a->dl_vlan == b->dl_vlan)) &&
            (wc2(a->wildcards, b->wildcards, OFPFW_DL_VLAN_PCP) ||
                    (a->dl_vlan == OFPVID_NONE && b->dl_vlan == OFPVID_NONE) ||
                    (a->dl_vlan_pcp == b->dl_vlan_pcp)) &&
            (wc2(a->wildcards, b->wildcards, OFPFW_DL_TYPE) || a->dl_type == b->dl_type) &&
            (wc2(a->wildcards, b->wildcards, OFPFW_NW_TOS) || a->nw_tos == b->nw_tos) &&
            (wc2(a->wildcards, b->wildcards, OFPFW_NW_PROTO) || a->nw_proto == b-> nw_proto) &&
            ((~a->nw_src_mask & ~b->nw_src_mask & (a->nw_src ^ b->nw_src)) == 0) &&
            ((~a->nw_dst_mask & ~b->nw_dst_mask & (a->nw_dst ^ b->nw_dst)) == 0) &&
            (wc2(a->wildcards, b->wildcards, OFPFW_TP_SRC) || a->tp_src == b->tp_src) &&
            (wc2(a->wildcards, b->wildcards, OFPFW_TP_DST) || a->tp_dst == b->tp_dst) &&
            (wc2(a->wildcards, b->wildcards, OFPFW_MPLS_LABEL) || a->mpls_label == b->mpls_label) &&
            (wc2(a->wildcards, b->wildcards, OFPFW_MPLS_TC) || a->mpls_tc == b->mpls_tc) &&
            ((~a->metadata_mask & ~b->metadata_mask & (a->metadata ^ b->metadata)) == 0));
}

