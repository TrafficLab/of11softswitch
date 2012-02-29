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

#include <netinet/in.h>
#include "csum.h"
#include "dp_exp.h"
#include "dp_actions.h"
#include "dp_buffers.h"
#include "datapath.h"
#include "oflib/ofl.h"
#include "oflib/ofl-actions.h"
#include "oflib/ofl-log.h"
#include "packet.h"
#include "packets.h"
#include "pipeline.h"
#include "util.h"

#define LOG_MODULE VLM_dp_acts

static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(60, 60);

/* Note: if the packet has multiple match handlers, they must all be updated
 * or invalidated by the actions. Also if the buffer might be reallocated,
 * e.g. because of a push action, the action implementations must make sure
 * that any internal pointers of the handler structures are also updated, or
 * invalidated.
 */

/* Executes an output action. */
static void
output(struct packet *pkt, struct ofl_action_output *action) {
    pkt->out_port = action->port;

    if (action->port == OFPP_CONTROLLER) {
        pkt->out_port_max_len = action->max_len;
    }
}

/* Executes a set vlan vid action. */
static void
set_vlan_vid(struct packet *pkt, struct ofl_action_vlan_vid *act) {
    packet_handle_std_validate(pkt->handle_std);
    if (pkt->handle_std->proto->vlan != NULL) {
        struct vlan_header *vlan = pkt->handle_std->proto->vlan;

        vlan->vlan_tci = htons((ntohs(vlan->vlan_tci) & ~VLAN_VID_MASK) |
                               (act->vlan_vid & VLAN_VID_MASK));

        pkt->handle_std->match->dl_vlan = act->vlan_vid;
    } else {
        VLOG_WARN_RL(LOG_MODULE, &rl, "Trying to execute SET_VLAN_VID action on packet with no vlan.");
    }
}

/* Executes set vlan pcp action. */
static void
set_vlan_pcp(struct packet *pkt, struct ofl_action_vlan_pcp *act) {
    packet_handle_std_validate(pkt->handle_std);
    if (pkt->handle_std->proto->vlan != NULL) {
        struct vlan_header *vlan = pkt->handle_std->proto->vlan;

        vlan->vlan_tci = (vlan->vlan_tci & ~htons(VLAN_PCP_MASK)) | htons(act->vlan_pcp << VLAN_PCP_SHIFT);

        pkt->handle_std->match->dl_vlan_pcp = act->vlan_pcp;
    } else {
        VLOG_WARN_RL(LOG_MODULE, &rl, "Trying to execute SET_VLAN_PCP action on packet with no vlan.");
    }
}

/* Executes set dl src action. */
static void
set_dl_src(struct packet *pkt, struct ofl_action_dl_addr *act) {
    packet_handle_std_validate(pkt->handle_std);
    if (pkt->handle_std->proto->eth != NULL) {
        struct eth_header *eth = pkt->handle_std->proto->eth;

        memcpy(eth->eth_src, act->dl_addr, ETH_ADDR_LEN);

        memcpy(&pkt->handle_std->match->dl_src, act->dl_addr, ETH_ADDR_LEN);
    } else {
        VLOG_WARN_RL(LOG_MODULE, &rl, "Trying to execute SET_DL_SRC action on packet with no dl.");
    }
}

/* Executes set dl dst action. */
static void
set_dl_dst(struct packet *pkt, struct ofl_action_dl_addr *act) {
    packet_handle_std_validate(pkt->handle_std);
    if (pkt->handle_std->proto->eth != NULL) {
        struct eth_header *eth = pkt->handle_std->proto->eth;

        memcpy(eth->eth_dst, act->dl_addr, ETH_ADDR_LEN);

        memcpy(&pkt->handle_std->match->dl_dst, act->dl_addr, ETH_ADDR_LEN);
    } else {
        VLOG_WARN_RL(LOG_MODULE, &rl, "Trying to execute SET_DL_DST action on packet with no dl.");
    }
}

/* Executes set nw src action. */
static void
set_nw_src(struct packet *pkt, struct ofl_action_nw_addr *act) {
    packet_handle_std_validate(pkt->handle_std);
    if (pkt->handle_std->proto->ipv4 != NULL) {
        struct ip_header *ipv4 = pkt->handle_std->proto->ipv4;

        // update TCP/UDP checksum
        if (pkt->handle_std->proto->tcp != NULL) {
            struct tcp_header *tcp = pkt->handle_std->proto->tcp;

            tcp->tcp_csum = recalc_csum32(tcp->tcp_csum, ipv4->ip_src, act->nw_addr);
        } else if (pkt->handle_std->proto->udp != NULL) {
            struct udp_header *udp = pkt->handle_std->proto->udp;

            udp->udp_csum = recalc_csum32(udp->udp_csum, ipv4->ip_src, act->nw_addr);
        }

        ipv4->ip_csum = recalc_csum32(ipv4->ip_csum, ipv4->ip_src, act->nw_addr);
        ipv4->ip_src = act->nw_addr;

        pkt->handle_std->match->nw_src = act->nw_addr;

    } else {
        VLOG_WARN_RL(LOG_MODULE, &rl, "Trying to execute SET_NW_SRC action on packet with no nw.");
    }
}

/* Executes set nw dst action. */
static void
set_nw_dst(struct packet *pkt, struct ofl_action_nw_addr *act) {
    packet_handle_std_validate(pkt->handle_std);
    if (pkt->handle_std->proto->ipv4 != NULL) {
        struct ip_header *ipv4 = pkt->handle_std->proto->ipv4;

        // update TCP/UDP checksum
        if (pkt->handle_std->proto->tcp != NULL) {
            struct tcp_header *tcp = pkt->handle_std->proto->tcp;

            tcp->tcp_csum = recalc_csum32(tcp->tcp_csum, ipv4->ip_dst, act->nw_addr);
        } else if (pkt->handle_std->proto->udp != NULL) {
            struct udp_header *udp = pkt->handle_std->proto->udp;

            udp->udp_csum = recalc_csum32(udp->udp_csum, ipv4->ip_dst, act->nw_addr);
        }

        ipv4->ip_csum = recalc_csum32(ipv4->ip_csum, ipv4->ip_dst, act->nw_addr);
        ipv4->ip_dst = act->nw_addr;

        pkt->handle_std->match->nw_dst = act->nw_addr;
    } else {
        VLOG_WARN_RL(LOG_MODULE, &rl, "Trying to execute SET_NW_DST action on packet with no nw.");
    }
}

/* Executes set tp src action. */
static void
set_tp_src(struct packet *pkt, struct ofl_action_tp_port *act) {
    packet_handle_std_validate(pkt->handle_std);
    if (pkt->handle_std->proto->tcp != NULL) {
        struct tcp_header *tcp = pkt->handle_std->proto->tcp;

        tcp->tcp_csum = recalc_csum16(tcp->tcp_csum, tcp->tcp_src, htons(act->tp_port));
        tcp->tcp_src = htons(act->tp_port);

        pkt->handle_std->match->tp_src = act->tp_port;

    } else if (pkt->handle_std->proto->udp != NULL) {
        struct udp_header *udp = pkt->handle_std->proto->udp;

        udp->udp_csum = recalc_csum16(udp->udp_csum, udp->udp_src, htons(act->tp_port));
        udp->udp_src = htons(act->tp_port);

        pkt->handle_std->match->tp_src = act->tp_port;

    } else {
        VLOG_WARN_RL(LOG_MODULE, &rl, "Trying to execute SET_TP_SRC action on packet with no tp.");
    }
}


/* Executes set tp dst action. */
static void
set_tp_dst(struct packet *pkt, struct ofl_action_tp_port *act) {
    packet_handle_std_validate(pkt->handle_std);
    if (pkt->handle_std->proto->tcp != NULL) {
        struct tcp_header *tcp = pkt->handle_std->proto->tcp;

        tcp->tcp_csum = recalc_csum16(tcp->tcp_csum, tcp->tcp_dst, htons(act->tp_port));
        tcp->tcp_dst = htons(act->tp_port);

        pkt->handle_std->match->tp_dst = act->tp_port;

    } else if (pkt->handle_std->proto->udp != NULL) {
        struct udp_header *udp = pkt->handle_std->proto->udp;

        udp->udp_csum = recalc_csum16(udp->udp_csum, udp->udp_dst, htons(act->tp_port));
        udp->udp_dst = htons(act->tp_port);

        // update packet match (assuming it is of type ofl_match_standard)
        pkt->handle_std->match->tp_dst = act->tp_port;

    } else {
        VLOG_WARN_RL(LOG_MODULE, &rl, "Trying to execute SET_TP_DST action on packet with no tp.");
    }
}

/* Executes copy ttl out action. */
static void
copy_ttl_out(struct packet *pkt, struct ofl_action_header *act UNUSED) {
    packet_handle_std_validate(pkt->handle_std);
    if (pkt->handle_std->proto->mpls != NULL) {
        struct mpls_header *mpls = pkt->handle_std->proto->mpls;

        if ((ntohl(mpls->fields) & MPLS_S_MASK) == 0) {
            // There is an inner MPLS header
            struct mpls_header *in_mpls = (struct mpls_header *)((uint8_t *)mpls + MPLS_HEADER_LEN);

            mpls->fields = (mpls->fields & ~htonl(MPLS_TTL_MASK)) | (in_mpls->fields & htonl(MPLS_TTL_MASK));

        } else if (pkt->buffer->size >= ETH_HEADER_LEN + MPLS_HEADER_LEN + IP_HEADER_LEN) {
            // Assumes an IPv4 header follows, if there is place for it
            struct ip_header *ipv4 = (struct ip_header *)((uint8_t *)mpls + MPLS_HEADER_LEN);

            mpls->fields = (mpls->fields & ~htonl(MPLS_TTL_MASK)) | htonl((uint32_t)ipv4->ip_ttl & MPLS_TTL_MASK);

        } else {
            VLOG_WARN_RL(LOG_MODULE, &rl, "Trying to execute copy ttl in action on packet with only one mpls.");
        }
    } else {
        VLOG_WARN_RL(LOG_MODULE, &rl, "Trying to execute COPY_TTL_OUT action on packet with no mpls.");
    }
}

/* Executes copy ttl in action. */
static void
copy_ttl_in(struct packet *pkt, struct ofl_action_header *act UNUSED) {
    packet_handle_std_validate(pkt->handle_std);
    if (pkt->handle_std->proto->mpls != NULL) {
        struct mpls_header *mpls = pkt->handle_std->proto->mpls;

        if ((ntohl(mpls->fields) & MPLS_S_MASK) == 0) {
            // There is an inner MPLS header
            struct mpls_header *in_mpls = (struct mpls_header *)((uint8_t *)mpls + MPLS_HEADER_LEN);

            in_mpls->fields = (in_mpls->fields & ~htonl(MPLS_TTL_MASK)) | (mpls->fields & htonl(MPLS_TTL_MASK));

        } else if (pkt->buffer->size >= ETH_HEADER_LEN + MPLS_HEADER_LEN + IP_HEADER_LEN) {
            // Assumes an IPv4 header follows, if there is place for it
            struct ip_header *ipv4 = (struct ip_header *)((uint8_t *)mpls + MPLS_HEADER_LEN);

            uint8_t new_ttl = (ntohl(mpls->fields) & MPLS_TTL_MASK) >> MPLS_TTL_SHIFT;
            uint16_t old_val = htons((ipv4->ip_proto) + (ipv4->ip_ttl<<8));
            uint16_t new_val = htons((ipv4->ip_proto) + (new_ttl<<8));
            ipv4->ip_csum = recalc_csum16(ipv4->ip_csum, old_val, new_val); 
            ipv4->ip_ttl = new_ttl;

        } else {
            VLOG_WARN_RL(LOG_MODULE, &rl, "Trying to execute copy ttl in action on packet with only one mpls.");
        }
    } else {
        VLOG_WARN_RL(LOG_MODULE, &rl, "Trying to execute COPY_TTL_IN action on packet with no mpls.");
    }
}

/* Executes set mpls label action. */
static void
set_mpls_label(struct packet *pkt, struct ofl_action_mpls_label *act) {
    packet_handle_std_validate(pkt->handle_std);
    if (pkt->handle_std->proto->mpls != NULL) {
        struct mpls_header *mpls = pkt->handle_std->proto->mpls;

        mpls->fields = (mpls->fields & ~ntohl(MPLS_LABEL_MASK)) | ntohl((act->mpls_label << MPLS_LABEL_SHIFT) & MPLS_LABEL_MASK);

        pkt->handle_std->match->mpls_label = act->mpls_label;

    } else {
        VLOG_WARN_RL(LOG_MODULE, &rl, "Trying to execute SET_MPLS_LABEL action on packet with no mpls.");
    }
}

/* Executes set mpls tc action. */
static void
set_mpls_tc(struct packet *pkt, struct ofl_action_mpls_tc *act) {
    packet_handle_std_validate(pkt->handle_std);
    if (pkt->handle_std->proto->mpls != NULL) {
        struct mpls_header *mpls = pkt->handle_std->proto->mpls;

        mpls->fields = (mpls->fields & ~ntohl(MPLS_TC_MASK)) | ntohl((act->mpls_tc << MPLS_TC_SHIFT) & MPLS_TC_MASK);

        pkt->handle_std->match->mpls_tc = act->mpls_tc;

    } else {
        VLOG_WARN_RL(LOG_MODULE, &rl, "Trying to execute SET_MPLS_TC action on packet with no mpls.");
    }
}

/* Executes set nw tos action. */
static void
set_nw_tos(struct packet *pkt, struct ofl_action_nw_tos *act) {
    packet_handle_std_validate(pkt->handle_std);
    if (pkt->handle_std->proto->ipv4 != NULL) {
        struct ip_header *ipv4 = pkt->handle_std->proto->ipv4;
        uint8_t new_value;

        new_value = (ipv4->ip_tos & IP_ECN_MASK) | (act->nw_tos & IP_DSCP_MASK);
        /* jklee : ip tos field is not included in TCP pseudo header.
         * Need magic as update_csum() don't work with 8 bits. */
        ipv4->ip_csum = recalc_csum16(ipv4->ip_csum, (uint16_t)(ipv4->ip_tos), (uint16_t)new_value);
        ipv4->ip_tos = new_value;

        pkt->handle_std->match->nw_tos = act->nw_tos;
    } else {
        VLOG_WARN_RL(LOG_MODULE, &rl, "Trying to execute SET_NW_TOS action on packet with no tp.");
    }
}

/* Executes set nw ecn action. */
static void
set_nw_ecn(struct packet *pkt, struct ofl_action_nw_ecn *act) {
    packet_handle_std_validate(pkt->handle_std);
    if (pkt->handle_std->proto->ipv4 != NULL) {
        struct ip_header *ipv4 = pkt->handle_std->proto->ipv4;
        uint8_t new_value;

        new_value = (ipv4->ip_tos & IP_DSCP_MASK) | (act->nw_ecn & IP_ECN_MASK);
        /* jklee : ip tos field is not included in TCP pseudo header.
         * Need magic as update_csum() don't work with 8 bits. */
        ipv4->ip_csum = recalc_csum16(ipv4->ip_csum, (uint16_t)(ipv4->ip_tos), (uint16_t)new_value);
        ipv4->ip_tos = new_value;
    } else {
        VLOG_WARN_RL(LOG_MODULE, &rl, "Trying to execute SET_NW_ECN action on packet with no tp.");
    }
}

/* Executes push vlan action. */
static void
push_vlan(struct packet *pkt, struct ofl_action_push *act) {
    // TODO Zoltan: if 802.3, check if new length is still valid
    packet_handle_std_validate(pkt->handle_std);
    if (pkt->handle_std->proto->eth != NULL) {
        struct eth_header  *eth,  *new_eth;
        struct snap_header *snap, *new_snap;
        struct vlan_header *vlan, *new_vlan, *push_vlan;
        size_t eth_size;

        eth = pkt->handle_std->proto->eth;
        snap = pkt->handle_std->proto->eth_snap;
        vlan = pkt->handle_std->proto->vlan;

        eth_size = snap == NULL
                   ? ETH_HEADER_LEN
                   : ETH_HEADER_LEN + LLC_HEADER_LEN + SNAP_HEADER_LEN;

        if (ofpbuf_headroom(pkt->buffer) >= VLAN_HEADER_LEN) {
            // there is available space in headroom, move eth backwards
            pkt->buffer->data = (uint8_t *)(pkt->buffer->data) - VLAN_HEADER_LEN;
            pkt->buffer->size += VLAN_HEADER_LEN;

            memmove(pkt->buffer->data, eth, eth_size);

            new_eth = (struct eth_header *)(pkt->buffer->data);
            new_snap = snap == NULL ? NULL
                                   : (struct snap_header *)((uint8_t *)new_eth
                                        + ETH_HEADER_LEN + LLC_HEADER_LEN);
            push_vlan = (struct vlan_header *)((uint8_t *)new_eth + eth_size);
            new_vlan = vlan;

        } else {
            // not enough headroom, use tailroom of the packet

            // Note: ofpbuf_put_uninit might relocate the whole packet
            ofpbuf_put_uninit(pkt->buffer, VLAN_HEADER_LEN);

            new_eth = (struct eth_header *)(pkt->buffer->data);
            new_snap = snap == NULL ? NULL
                                   : (struct snap_header *)((uint8_t *)new_eth
                                        + ETH_HEADER_LEN + LLC_HEADER_LEN);
            push_vlan = (struct vlan_header *)((uint8_t *)new_eth + eth_size);

            // push data to create space for new vlan tag
            memmove((uint8_t *)push_vlan + VLAN_HEADER_LEN, push_vlan,
                    pkt->buffer->size - eth_size);

            new_vlan = vlan == NULL ? NULL
              : (struct vlan_header *)((uint8_t *)push_vlan + VLAN_HEADER_LEN);
        }

        push_vlan->vlan_tci = new_vlan == NULL ? 0x0000 : new_vlan->vlan_tci;

        if (new_snap != NULL) {
            push_vlan->vlan_next_type = new_snap->snap_type;
            new_snap->snap_type = ntohs(act->ethertype);
            new_eth->eth_type = htons(ntohs(new_eth->eth_type) + VLAN_HEADER_LEN);
        } else {
            push_vlan->vlan_next_type = new_eth->eth_type;
            new_eth->eth_type = ntohs(act->ethertype);
        }

        // TODO Zoltan: This could be faster if VLAN match is updated
        //              and proto pointers are shifted in case of realloc, ...
        pkt->handle_std->valid = false;

    } else {
        VLOG_WARN_RL(LOG_MODULE, &rl, "Trying to execute push vlan action on packet with no eth.");
    }
}

/* Executes pop vlan action. */
static void
pop_vlan(struct packet *pkt, struct ofl_action_header *act UNUSED) {
    packet_handle_std_validate(pkt->handle_std);
    if (pkt->handle_std->proto->eth != NULL && pkt->handle_std->proto->vlan != NULL) {
        struct eth_header *eth = pkt->handle_std->proto->eth;
        struct snap_header *eth_snap = pkt->handle_std->proto->eth_snap;
        struct vlan_header *vlan = pkt->handle_std->proto->vlan;
        size_t move_size;

        if (eth_snap != NULL) {
            eth_snap->snap_type = vlan->vlan_next_type;
            eth->eth_type = htons(ntohs(eth->eth_type) - VLAN_HEADER_LEN);
        } else {
            eth->eth_type = vlan->vlan_next_type;
        }

        move_size = (uint8_t *)vlan - (uint8_t *)eth;

        pkt->buffer->data = (uint8_t *)pkt->buffer->data + VLAN_HEADER_LEN;
        pkt->buffer->size -= VLAN_HEADER_LEN;

        memmove(pkt->buffer->data, eth, move_size);

        //TODO Zoltan: revalidating might not be necessary in all cases
        pkt->handle_std->valid = false;
    } else {
        VLOG_WARN_RL(LOG_MODULE, &rl, "Trying to execute POP_VLAN action on packet with no eth/vlan.");
    }
}


/* Executes set mpls ttl action. */
static void
set_mpls_ttl(struct packet *pkt, struct ofl_action_mpls_ttl *act) {
    packet_handle_std_validate(pkt->handle_std);
    if (pkt->handle_std->proto->mpls != NULL) {
        struct mpls_header *mpls = pkt->handle_std->proto->mpls;

        mpls->fields = (mpls->fields & ~ntohl(MPLS_TTL_MASK)) | ntohl((act->mpls_ttl << MPLS_TTL_SHIFT) & MPLS_TTL_MASK);

    } else {
        VLOG_WARN_RL(LOG_MODULE, &rl, "Trying to execute SET_MPLS_TTL action on packet with no mpls.");
    }
}

/* Executes dec mpls label action. */
static void
dec_mpls_ttl(struct packet *pkt, struct ofl_action_header *act UNUSED) {
    packet_handle_std_validate(pkt->handle_std);
    if (pkt->handle_std->proto->mpls != NULL) {
        struct mpls_header *mpls = pkt->handle_std->proto->mpls;

        uint32_t ttl = ntohl(mpls->fields) & MPLS_TTL_MASK;

        if (ttl > 0) { ttl--; }
        mpls->fields = (mpls->fields & ~ntohl(MPLS_TTL_MASK)) | htonl(ttl);

    } else {
        VLOG_WARN_RL(LOG_MODULE, &rl, "Trying to execute DEC_MPLS_TTL action on packet with no mpls.");
    }
}

/* Executes push mpls action. */
static void
push_mpls(struct packet *pkt, struct ofl_action_push *act) {
    // TODO Zoltan: if 802.3, check if new length is still valid
    packet_handle_std_validate(pkt->handle_std);
    if (pkt->handle_std->proto->eth != NULL) {
        struct eth_header  *eth,  *new_eth;
        struct snap_header *snap, *new_snap;
        struct vlan_header *vlan, *new_vlan;
        struct mpls_header *mpls, *new_mpls, *push_mpls;
        struct ip_header   *ipv4, *new_ipv4;
        size_t eth_size, head_offset;

        eth = pkt->handle_std->proto->eth;
        snap = pkt->handle_std->proto->eth_snap;
        vlan = pkt->handle_std->proto->vlan_last;
        mpls = pkt->handle_std->proto->mpls;
        ipv4 = pkt->handle_std->proto->ipv4;

        eth_size = snap == NULL
                   ? ETH_HEADER_LEN
                   : ETH_HEADER_LEN + LLC_HEADER_LEN + SNAP_HEADER_LEN;

        head_offset = vlan == NULL ? eth_size
              : (uint8_t *)vlan - (uint8_t *)eth + VLAN_HEADER_LEN;

        if (ofpbuf_headroom(pkt->buffer) >= MPLS_HEADER_LEN) {
            // there is available space in headroom, move eth backwards
            pkt->buffer->data = (uint8_t *)(pkt->buffer->data) - MPLS_HEADER_LEN;
            pkt->buffer->size += MPLS_HEADER_LEN;

            memmove(pkt->buffer->data, eth, head_offset);
            new_eth = (struct eth_header *)(pkt->buffer->data);
            new_snap = snap == NULL ? NULL
                    : (struct snap_header *)((uint8_t *)snap - MPLS_HEADER_LEN);
            new_vlan = vlan == NULL ? NULL
                    : (struct vlan_header *)((uint8_t *)vlan - MPLS_HEADER_LEN);
            push_mpls = (struct mpls_header *)((uint8_t *)new_eth + head_offset);
            new_mpls = mpls;
            new_ipv4 = ipv4;

        } else {
            // Note: ofpbuf_put_uninit might relocate the whole packet
            ofpbuf_put_uninit(pkt->buffer, VLAN_HEADER_LEN);

            new_eth = (struct eth_header *)(pkt->buffer->data);
            new_snap = snap == NULL ? NULL
                    : (struct snap_header *)((uint8_t *)snap - (uint8_t *)eth + (uint8_t *)new_eth);
            new_vlan = vlan == NULL ? NULL
                    : (struct vlan_header *)((uint8_t *)vlan - (uint8_t *)eth + (uint8_t *)new_eth);
            push_mpls = (struct mpls_header *)((uint8_t *)new_eth + head_offset);

            // push data to create space for new vlan tag
            memmove((uint8_t *)push_mpls + MPLS_HEADER_LEN, push_mpls,
                    pkt->buffer->size - head_offset);

            new_mpls = mpls == NULL ? NULL
                    : (struct mpls_header *)((uint8_t *)push_mpls + MPLS_HEADER_LEN);
            // Note: if ipv4 was not null, then there was no MPLS header in 1.1
            new_ipv4 = ipv4 == NULL ? NULL
                    : (struct ip_header *)((uint8_t *)push_mpls + MPLS_HEADER_LEN);
        }

        if (new_mpls != NULL) {
            push_mpls->fields = new_mpls->fields & ~htonl(MPLS_S_MASK);
        } else if (new_ipv4 != NULL) {
            // copy IP TTL to MPLS TTL (rest is zero), and set S bit
            push_mpls->fields = htonl((uint32_t)new_ipv4->ip_ttl & MPLS_TTL_MASK) | htonl(MPLS_S_MASK);
        } else {
            push_mpls->fields = htonl(MPLS_S_MASK);
        }

        if (new_vlan != NULL) {
            new_vlan->vlan_next_type = htons(act->ethertype);
        } else if (new_snap != NULL) {
            new_snap->snap_type = htons(act->ethertype);
        } else {
            new_eth->eth_type = htons(act->ethertype);
        }

        if (new_snap != NULL) {
            new_eth->eth_type = htons(ntohs(new_eth->eth_type) + MPLS_HEADER_LEN);
        }

        // in 1.1 all proto but eth and mpls will be hidden,
        // so revalidating won't be a tedious work (probably)
        pkt->handle_std->valid = false;
    } else {
        VLOG_WARN_RL(LOG_MODULE, &rl, "Trying to execute PUSH_MPLS action on packet with no eth.");
    }
}

/* Executes pop mpls action. */
static void
pop_mpls(struct packet *pkt, struct ofl_action_pop_mpls *act) {
    packet_handle_std_validate(pkt->handle_std);
    if (pkt->handle_std->proto->eth != NULL && pkt->handle_std->proto->mpls != NULL) {
        struct eth_header *eth = pkt->handle_std->proto->eth;
        struct snap_header *snap = pkt->handle_std->proto->eth_snap;
        struct vlan_header *vlan_last = pkt->handle_std->proto->vlan_last;
        struct mpls_header *mpls = pkt->handle_std->proto->mpls;
        size_t move_size;

        if (vlan_last != NULL) {
            vlan_last->vlan_next_type = htons(act->ethertype);
        } else if (snap != NULL) {
            snap->snap_type = htons(act->ethertype);
        } else {
            eth->eth_type = htons(act->ethertype);
        }

        move_size = (uint8_t *)mpls - (uint8_t *)eth;

        pkt->buffer->data = (uint8_t *)pkt->buffer->data + MPLS_HEADER_LEN;
        pkt->buffer->size -= MPLS_HEADER_LEN;

        memmove(pkt->buffer->data, eth, move_size);

        if (snap != NULL) {
            struct eth_header *new_eth = (struct eth_header *)(pkt->buffer->data);
            new_eth->eth_type = htons(ntohs(new_eth->eth_type) + MPLS_HEADER_LEN);
        }

        //TODO Zoltan: revalidating might not be necessary at all cases
        pkt->handle_std->valid = false;
    } else {
        VLOG_WARN_RL(LOG_MODULE, &rl, "Trying to execute POP_MPLS action on packet with no eth/mpls.");
    }
}


/* Executes set queue action. */
static void
set_queue(struct packet *pkt UNUSED, struct ofl_action_set_queue *act) {
    pkt->out_queue = act->queue_id;
}

/* Executes group action. */
static void
group(struct packet *pkt, struct ofl_action_group *act) {
    pkt->out_group = act->group_id;
}

/* Executes set nw ttl action. */
static void
set_nw_ttl(struct packet *pkt, struct ofl_action_set_nw_ttl *act) {
    packet_handle_std_validate(pkt->handle_std);
    if (pkt->handle_std->proto->ipv4 != NULL) {
        struct ip_header *ipv4 = pkt->handle_std->proto->ipv4;

        uint16_t old_val = htons((ipv4->ip_proto) + (ipv4->ip_ttl<<8));
        uint16_t new_val = htons((ipv4->ip_proto) + (act->nw_ttl<<8));
        ipv4->ip_csum = recalc_csum16(ipv4->ip_csum, old_val, new_val);
        ipv4->ip_ttl = act->nw_ttl;
    } else {
        VLOG_WARN_RL(LOG_MODULE, &rl, "Trying to execute SET_NW_TTL action on packet with no ipv4.");
    }
}

/* Executes dec nw ttl action. */
static void
dec_nw_ttl(struct packet *pkt, struct ofl_action_header *act UNUSED) {
    packet_handle_std_validate(pkt->handle_std);
    if (pkt->handle_std->proto->ipv4 != NULL) {

        struct ip_header *ipv4 = pkt->handle_std->proto->ipv4;

        if (ipv4->ip_ttl > 0) {
            uint8_t new_ttl = ipv4->ip_ttl - 1;
            uint16_t old_val = htons((ipv4->ip_proto) + (ipv4->ip_ttl<<8));
            uint16_t new_val = htons((ipv4->ip_proto) + (new_ttl<<8));
            ipv4->ip_csum = recalc_csum16(ipv4->ip_csum, old_val, new_val);
            ipv4->ip_ttl = new_ttl;
        }
    } else {
        VLOG_WARN_RL(LOG_MODULE, &rl, "Trying to execute DEC_NW_TTL action on packet with no ipv4.");
    }
}


void
dp_execute_action(struct packet *pkt,
               struct ofl_action_header *action) {

    if (VLOG_IS_DBG_ENABLED(LOG_MODULE)) {
        char *a = ofl_action_to_string(action, pkt->dp->exp);
        VLOG_DBG_RL(LOG_MODULE, &rl, "executing action %s.", a);
        free(a);
    }

    switch (action->type) {
        case (OFPAT_OUTPUT): {
            output(pkt, (struct ofl_action_output *)action);
            break;
        }
        case (OFPAT_SET_VLAN_VID): {
            set_vlan_vid(pkt, (struct ofl_action_vlan_vid *)action);
            break;
        }
        case (OFPAT_SET_VLAN_PCP): {
            set_vlan_pcp(pkt, (struct ofl_action_vlan_pcp *)action);
            break;
        }
        case (OFPAT_SET_DL_SRC): {
            set_dl_src(pkt, (struct ofl_action_dl_addr *)action);
            break;
        }
        case (OFPAT_SET_DL_DST): {
            set_dl_dst(pkt, (struct ofl_action_dl_addr *)action);
            break;
        }
        case (OFPAT_SET_NW_SRC): {
            set_nw_src(pkt, (struct ofl_action_nw_addr *)action);
            break;
        }
        case (OFPAT_SET_NW_DST): {
            set_nw_dst(pkt, (struct ofl_action_nw_addr *)action);
            break;
        }
        case (OFPAT_SET_NW_TOS): {
            set_nw_tos(pkt, (struct ofl_action_nw_tos *)action);
            break;
        }
        case (OFPAT_SET_NW_ECN): {
            set_nw_ecn(pkt, (struct ofl_action_nw_ecn *)action);
            break;
        }
        case (OFPAT_SET_TP_SRC): {
            set_tp_src(pkt, (struct ofl_action_tp_port *)action);
            break;
        }
        case (OFPAT_SET_TP_DST): {
            set_tp_dst(pkt, (struct ofl_action_tp_port *)action);
            break;
        }
        case (OFPAT_COPY_TTL_OUT): {
            copy_ttl_out(pkt, action);
            break;
        }
        case (OFPAT_COPY_TTL_IN): {
            copy_ttl_in(pkt, action);
            break;
        }
        case (OFPAT_SET_MPLS_LABEL): {
            set_mpls_label(pkt, (struct ofl_action_mpls_label *)action);
            break;
        }
        case (OFPAT_SET_MPLS_TC): {
            set_mpls_tc(pkt, (struct ofl_action_mpls_tc *)action);
            break;
        }
        case (OFPAT_SET_MPLS_TTL): {
            set_mpls_ttl(pkt, (struct ofl_action_mpls_ttl *)action);
            break;
        }
        case (OFPAT_DEC_MPLS_TTL): {
            dec_mpls_ttl(pkt, action);
            break;
        }
        case (OFPAT_PUSH_VLAN): {
            push_vlan(pkt, (struct ofl_action_push *)action);
            break;
        }
        case (OFPAT_POP_VLAN): {
            pop_vlan(pkt, action);
            break;
        }
        case (OFPAT_PUSH_MPLS): {
            push_mpls(pkt, (struct ofl_action_push *)action);
            break;
        }
        case (OFPAT_POP_MPLS): {
            pop_mpls(pkt, (struct ofl_action_pop_mpls *)action);
            break;
        }
        case (OFPAT_SET_QUEUE): {
            set_queue(pkt, (struct ofl_action_set_queue *)action);
            break;
        }
        case (OFPAT_GROUP): {
            group(pkt, (struct ofl_action_group *)action);
            break;
        }
        case (OFPAT_SET_NW_TTL): {
            set_nw_ttl(pkt, (struct ofl_action_set_nw_ttl *)action);
            break;
        }
        case (OFPAT_DEC_NW_TTL): {
            dec_nw_ttl(pkt, action);
            break;
        }
        case (OFPAT_EXPERIMENTER): {
        	dp_exp_action(pkt, (struct ofl_action_experimenter *)action);
            break;
        }
        default: {
            VLOG_WARN_RL(LOG_MODULE, &rl, "Trying to execute unknown action type (%u).", action->type);
        }
    }
    if (VLOG_IS_DBG_ENABLED(LOG_MODULE)) {
        char *p = packet_to_string(pkt);
        VLOG_DBG_RL(LOG_MODULE, &rl, "action result: %s", p);
        free(p);
    }

}



void
dp_execute_action_list(struct packet *pkt,
                size_t actions_num, struct ofl_action_header **actions) {
    size_t i;

    VLOG_DBG_RL(LOG_MODULE, &rl, "Executing action list.");

    for (i=0; i < actions_num; i++) {
        dp_execute_action(pkt, actions[i]);

        if (pkt->out_group != OFPG_ANY) {
            uint32_t group = pkt->out_group;
            pkt->out_group = OFPG_ANY;
            VLOG_DBG_RL(LOG_MODULE, &rl, "Group action; executing group (%u).", group);
            group_table_execute(pkt->dp->groups, pkt, group);

        } else if (pkt->out_port != OFPP_ANY) {
            uint32_t port = pkt->out_port;
            uint32_t queue = pkt->out_queue;
            uint16_t max_len = pkt->out_port_max_len;
            pkt->out_port = OFPP_ANY;
            pkt->out_port_max_len = 0;
            pkt->out_queue = 0;
            VLOG_DBG_RL(LOG_MODULE, &rl, "Port action; sending to port (%u).", port);
            dp_actions_output_port(pkt, port, queue, max_len);
        }

    }
}


void
dp_actions_output_port(struct packet *pkt, uint32_t out_port, uint32_t out_queue, uint16_t max_len) {

    switch (out_port) {
        case (OFPP_TABLE): {
            if (pkt->packet_out) {
                // NOTE: hackish; makes sure packet cannot be resubmit to pipeline again.
                pkt->packet_out = false;
                pipeline_process_packet(pkt->dp->pipeline, pkt);
            } else {
                VLOG_WARN_RL(LOG_MODULE, &rl, "Trying to resubmit packet to pipeline.");
            }
            break;
        }
        case (OFPP_IN_PORT): {
            dp_ports_output(pkt->dp, pkt->buffer, pkt->in_port, 0);
            break;
        }
        case (OFPP_CONTROLLER): {
            dp_buffers_save(pkt->dp->buffers, pkt);

            {
                struct ofl_msg_packet_in msg =
                        {{.type = OFPT_PACKET_IN},
                         .buffer_id   = pkt->buffer_id,
                         .in_port     = pkt->in_port,
                         .in_phy_port = pkt->in_port, // TODO: how to get phy port for v.port?
                         .total_len   = pkt->buffer->size,
                         .reason      = OFPR_ACTION,
                         .table_id    = pkt->table_id,
                         .data_length = MIN(max_len, pkt->buffer->size),
                         .data        = pkt->buffer->data};

                dp_send_message(pkt->dp, (struct ofl_msg_header *)&msg, NULL);
            }
            break;
        }
        case (OFPP_FLOOD):
        case (OFPP_ALL): {
            dp_ports_output_all(pkt->dp, pkt->buffer, pkt->in_port, out_port == OFPP_FLOOD);
            break;
        }
        case (OFPP_NORMAL):
            // TODO Zoltan: Implement
        case (OFPP_LOCAL):
        default: {
            if (pkt->in_port == out_port) {
                VLOG_WARN_RL(LOG_MODULE, &rl, "can't directly forward to input port.");
            } else {
                VLOG_DBG_RL(LOG_MODULE, &rl, "Outputting packet on port %u.", out_port);
                dp_ports_output(pkt->dp, pkt->buffer, out_port, out_queue);
            }
        }
    }
}

bool
dp_actions_list_has_out_port(size_t actions_num, struct ofl_action_header **actions, uint32_t port) {
    size_t i;

    for (i=0; i < actions_num; i++) {
        if (actions[i]->type == OFPAT_OUTPUT) {
            struct ofl_action_output *ao = (struct ofl_action_output *)actions[i];
            if (ao->port == port) {
                return true;
            }
        }
    }
    return false;
}

bool
dp_actions_list_has_out_group(size_t actions_num, struct ofl_action_header **actions, uint32_t group) {
    size_t i;

    for (i=0; i < actions_num; i++) {
        if (actions[i]->type == OFPAT_GROUP) {
            struct ofl_action_group *ag = (struct ofl_action_group *)actions[i];
            if (ag->group_id == group) {
                return true;
            }
        }
    }
    return false;
}

ofl_err
dp_actions_validate(struct datapath *dp, size_t actions_num, struct ofl_action_header **actions) {
    size_t i;

    for (i=0; i < actions_num; i++) {
        if (actions[i]->type == OFPAT_OUTPUT) {
            struct ofl_action_output *ao = (struct ofl_action_output *)actions[i];

            if (ao->port <= OFPP_MAX && dp_ports_lookup(dp, ao->port) == NULL) {
                VLOG_WARN_RL(LOG_MODULE, &rl, "Output action for invalid port (%u).", ao->port);
                return ofl_error(OFPET_BAD_ACTION, OFPBAC_BAD_OUT_PORT);
            }
        }
        if (actions[i]->type == OFPAT_GROUP) {
            struct ofl_action_group *ag = (struct ofl_action_group *)actions[i];

            if (ag->group_id <= OFPG_MAX && group_table_find(dp->groups, ag->group_id) == NULL) {
                VLOG_WARN_RL(LOG_MODULE, &rl, "Group action for invalid group (%u).", ag->group_id);
                return ofl_error(OFPET_BAD_ACTION, OFPBAC_BAD_OUT_GROUP);
            }
        }
    }

    return 0;
}
