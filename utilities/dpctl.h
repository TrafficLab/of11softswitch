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

#ifndef DPCTL_H
#define DPCTL_H 1

#include "openflow/openflow.h"

struct names8 {
    uint8_t   code;
    char     *name;
};

struct names16 {
    uint16_t   code;
    char      *name;
};

struct names32 {
    uint32_t   code;
    char      *name;
};



static struct names32 port_names[] = {
        {OFPP_IN_PORT,    "in_port"},
        {OFPP_TABLE,      "table"},
        {OFPP_NORMAL,     "normal"},
        {OFPP_FLOOD,      "flood"},
        {OFPP_ALL,        "all"},
        {OFPP_CONTROLLER, "ctrl"},
        {OFPP_LOCAL,      "local"},
        {OFPP_ANY,        "any"}
};

static struct names32 queue_names[] = {
        {OFPQ_ALL, "all"}
};

static struct names32 group_names[] = {
        {OFPG_ALL, "all"},
        {OFPG_ANY, "any"}
};

static struct names8 group_type_names[] = {
        {OFPGT_ALL,      "all"},
        {OFPGT_SELECT,   "sel"},
        {OFPGT_INDIRECT, "ind"},
        {OFPGT_FF,       "ff"}
};

static struct names16 group_mod_cmd_names[] = {
        {OFPGC_ADD,    "add"},
        {OFPGC_MODIFY, "mod"},
        {OFPGC_DELETE, "del"}
};

static struct names8 table_names[] = {
        {0xff, "all"}
};

static struct names16 inst_names[] = {
        {OFPIT_GOTO_TABLE,     "goto"},
        {OFPIT_WRITE_METADATA, "meta"},
        {OFPIT_WRITE_ACTIONS,  "write"},
        {OFPIT_APPLY_ACTIONS,  "apply"},
        {OFPIT_CLEAR_ACTIONS,  "clear"}
};

static struct names8 flow_mod_cmd_names[] = {
        {OFPFC_ADD,           "add"},
        {OFPFC_MODIFY,        "mod"},
        {OFPFC_MODIFY_STRICT, "mods"},
        {OFPFC_DELETE,        "del"},
        {OFPFC_DELETE_STRICT, "dels"}
};

static struct names32 buffer_names[] = {
        {0xffffffff, "none"}
};


static struct names32 wildcard_names[] = {
        {OFPFW_IN_PORT,     "in_port"},
        {OFPFW_DL_VLAN,     "dl_vlan"},
        {OFPFW_DL_VLAN_PCP, "dl_vlan_pcp"},
        {OFPFW_DL_TYPE,     "dl_type"},
        {OFPFW_NW_TOS,      "nw_tos"},
        {OFPFW_NW_PROTO,    "nw_proto"},
        {OFPFW_TP_SRC,      "tp_src"},
        {OFPFW_TP_DST,      "tp_dst"},
        {OFPFW_MPLS_LABEL,  "mpls_label"},
        {OFPFW_MPLS_TC,     "mpls_tc"},
        {OFPFW_ALL,         "all"}
};


static struct names16 vlan_vid_names[] = {
        {OFPVID_ANY,  "any"},
        {OFPVID_NONE, "none"}
};


static struct names16 action_names[] = {
        {OFPAT_OUTPUT,         "output"},
        {OFPAT_SET_VLAN_VID,   "vlan_vid"},
        {OFPAT_SET_VLAN_PCP,   "vlan_pcp"},
        {OFPAT_SET_DL_SRC,     "dl_src"},
        {OFPAT_SET_DL_DST,     "dl_dst"},
        {OFPAT_SET_NW_SRC,     "nw_src"},
        {OFPAT_SET_NW_DST,     "nw_dst"},
        {OFPAT_SET_NW_TOS,     "nw_tos"},
        {OFPAT_SET_NW_ECN,     "nw_ecn"},
        {OFPAT_SET_TP_SRC,     "tp_src"},
        {OFPAT_SET_TP_DST,     "tp_dst"},
        {OFPAT_COPY_TTL_OUT,   "ttl_out"},
        {OFPAT_COPY_TTL_IN,    "ttl_in"},
        {OFPAT_SET_MPLS_LABEL, "mpls_label"},
        {OFPAT_SET_MPLS_TC,    "mpls_tc"},
        {OFPAT_SET_MPLS_TTL,   "mpls_ttl"},
        {OFPAT_DEC_MPLS_TTL,   "mpls_dec"},
        {OFPAT_PUSH_VLAN,      "push_vlan"},
        {OFPAT_POP_VLAN,       "pop_vlan"},
        {OFPAT_PUSH_MPLS,      "push_mpls"},
        {OFPAT_POP_MPLS,       "pop_mpls"},
        {OFPAT_SET_QUEUE,      "queue"},
        {OFPAT_GROUP,          "group"},
        {OFPAT_SET_NW_TTL,     "nw_ttl"},
        {OFPAT_DEC_NW_TTL,     "nw_dec"}
};

#define FLOW_MOD_COMMAND       "cmd"
#define FLOW_MOD_COOKIE        "cookie"
#define FLOW_MOD_COOKIE_MASK   "cookie_mask"
#define FLOW_MOD_TABLE_ID      "table"
#define FLOW_MOD_IDLE          "idle"
#define FLOW_MOD_HARD          "hard"
#define FLOW_MOD_PRIO          "prio"
#define FLOW_MOD_BUFFER        "buffer"
#define FLOW_MOD_OUT_PORT      "out_port"
#define FLOW_MOD_OUT_GROUP     "out_group"
#define FLOW_MOD_FLAGS         "flags"
#define FLOW_MOD_MATCH         "match"


#define MATCH_IN_PORT       "in_port"
#define MATCH_WILDCARDS     "wildcards"
#define MATCH_DL_SRC        "dl_src"
#define MATCH_DL_SRC_MASK   "dl_src_mask"
#define MATCH_DL_DST        "dl_dst"
#define MATCH_DL_DST_MASK   "dl_dst_mask"
#define MATCH_DL_VLAN       "vlan"
#define MATCH_DL_VLAN_PCP   "vlan_pcp"
#define MATCH_DL_TYPE       "dl_type"
#define MATCH_NW_TOS        "nw_tos"
#define MATCH_NW_PROTO      "nw_proto"
#define MATCH_NW_SRC        "nw_src"
#define MATCH_NW_SRC_MASK   "nw_src_mask"
#define MATCH_NW_DST        "nw_dst"
#define MATCH_NW_DST_MASK   "nw_dst_mask"
#define MATCH_TP_SRC        "tp_src"
#define MATCH_TP_DST        "tp_dst"
#define MATCH_MPLS_LABEL    "mpls_label"
#define MATCH_MPLS_TC       "mpls_tc"
#define MATCH_METADATA      "meta"
#define MATCH_METADATA_MASK "meta_mask"


#define GROUP_MOD_COMMAND "cmd"
#define GROUP_MOD_TYPE    "type"
#define GROUP_MOD_GROUP   "group"


#define BUCKET_WEIGHT       "weight"
#define BUCKET_WATCH_PORT   "port"
#define BUCKET_WATCH_GROUP  "group"


#define CONFIG_FLAGS "flags"
#define CONFIG_MISS  "miss"


#define PORT_MOD_PORT      "port"
#define PORT_MOD_HW_ADDR   "addr"
#define PORT_MOD_HW_CONFIG "conf"
#define PORT_MOD_MASK      "mask"
#define PORT_MOD_ADVERTISE "adv"


#define TABLE_MOD_TABLE  "table"
#define TABLE_MOD_CONFIG "conf"

#define KEY_VAL    "="
#define KEY_VAL2   ":"
#define KEY_SEP    ","

#define WILDCARD_ADD   '+'
#define WILDCARD_SUB   '-'



#define NUM_ELEMS( x )   (sizeof(x) / sizeof(x[0]))


#endif /* DPCTL_H */
