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
#include <sys/types.h>
#include <stdlib.h>
#include <string.h>
#include "ofl.h"
#include "ofl-utils.h"
#include "ofl-actions.h"
#include "ofl-structs.h"
#include "ofl-messages.h"
#include "ofl-print.h"
#include "ofl-packets.h"
#include "ofl-log.h"
#include "openflow/openflow.h"

#define LOG_MODULE ofl_act_u
OFL_LOG_INIT(LOG_MODULE)


ofl_err
ofl_actions_unpack(struct ofp_action_header *src, size_t *len, struct ofl_action_header **dst, struct ofl_exp *exp) {

    if (*len < sizeof(struct ofp_action_header)) {
        OFL_LOG_WARN(LOG_MODULE, "Received action is too short (%zu).", *len);
        return ofl_error(OFPET_BAD_ACTION, OFPBAC_BAD_LEN);
    }

    if (*len < ntohs(src->len)) {
        OFL_LOG_WARN(LOG_MODULE, "Received action has invalid length (set to %u, but only %zu received).", ntohs(src->len), *len);
        return ofl_error(OFPET_BAD_ACTION, OFPBAC_BAD_LEN);
    }

    if ((ntohs(src->len) % 8) != 0) {
        OFL_LOG_WARN(LOG_MODULE, "Received action length is not a multiple of 64 bits (%u).", ntohs(src->len));
        return ofl_error(OFPET_BAD_ACTION, OFPBAC_BAD_LEN);
    }

    switch (ntohs(src->type)) {
        case OFPAT_OUTPUT: {
            struct ofp_action_output *sa;
            struct ofl_action_output *da;

            if (*len < sizeof(struct ofp_action_output)) {
                OFL_LOG_WARN(LOG_MODULE, "Received OUTPUT action has invalid length (%zu).", *len);
                return ofl_error(OFPET_BAD_ACTION, OFPBAC_BAD_LEN);
            }

            sa = (struct ofp_action_output *)src;

            if (ntohl(sa->port) == 0 ||
                (ntohl(sa->port) > OFPP_MAX && ntohl(sa->port) < OFPP_IN_PORT) ||
                ntohl(sa->port) == OFPP_ANY) {
                if (OFL_LOG_IS_WARN_ENABLED(LOG_MODULE)) {
                    char *ps = ofl_port_to_string(ntohl(sa->port));
                    OFL_LOG_WARN(LOG_MODULE, "Received OUTPUT action has invalid port (%s).", ps);
                    free(ps);
                }
                return ofl_error(OFPET_BAD_ACTION, OFPBAC_BAD_OUT_PORT);
            }

            da = (struct ofl_action_output *)malloc(sizeof(struct ofl_action_output));
            da->port = ntohl(sa->port);
            da->max_len = ntohs(sa->max_len);

            *len -= sizeof(struct ofp_action_output);
            *dst = (struct ofl_action_header *)da;
            break;
        }

        case OFPAT_SET_VLAN_VID: {
            struct ofp_action_vlan_vid *sa;
            struct ofl_action_vlan_vid *da;

            if (*len < sizeof(struct ofp_action_vlan_vid)) {
                OFL_LOG_WARN(LOG_MODULE, "Received SET_VLAN_VID action has invalid length (%zu).", *len);
                return ofl_error(OFPET_BAD_ACTION, OFPBAC_BAD_LEN);
            }

            sa = (struct ofp_action_vlan_vid *)src;

            if (ntohs(sa->vlan_vid) > VLAN_VID_MAX) {
                if (OFL_LOG_IS_WARN_ENABLED(LOG_MODULE)) {
                    char *vs = ofl_vlan_vid_to_string(ntohs(sa->vlan_vid));
                    OFL_LOG_WARN(LOG_MODULE, "Received SET_VLAN_VID action has invalid vid (%s).", vs);
                    free(vs);
                }
                return ofl_error(OFPET_BAD_ACTION, OFPBAC_BAD_ARGUMENT);
            }

            da = (struct ofl_action_vlan_vid *)malloc(sizeof(struct ofl_action_vlan_vid));
            da->vlan_vid = ntohs(sa->vlan_vid);

            *len -= sizeof(struct ofp_action_vlan_vid);
            *dst = (struct ofl_action_header *)da;
            break;
        }

        case OFPAT_SET_VLAN_PCP: {
            struct ofp_action_vlan_pcp *sa;
            struct ofl_action_vlan_pcp *da;

            if (*len < sizeof(struct ofp_action_vlan_pcp)) {
                OFL_LOG_WARN(LOG_MODULE, "Received SET_VLAN_PCP action has invalid length (%zu).", *len);
                return ofl_error(OFPET_BAD_ACTION, OFPBAC_BAD_LEN);
            }

            sa = (struct ofp_action_vlan_pcp *)src;

            if (sa->vlan_pcp > VLAN_PCP_MAX) {
                OFL_LOG_WARN(LOG_MODULE, "Received SET_VLAN_PCP action has invalid pcp (%u).", sa->vlan_pcp);
                return ofl_error(OFPET_BAD_ACTION, OFPBAC_BAD_ARGUMENT);
            }

            da = (struct ofl_action_vlan_pcp *)malloc(sizeof(struct ofl_action_vlan_pcp));
            da->vlan_pcp = sa->vlan_pcp;

            *len -= sizeof(struct ofp_action_vlan_pcp);
            *dst = (struct ofl_action_header *)da;
            break;
        }

        case OFPAT_SET_DL_SRC:
        case OFPAT_SET_DL_DST: {
            struct ofp_action_dl_addr *sa;
            struct ofl_action_dl_addr *da;

            if (*len < sizeof(struct ofp_action_dl_addr)) {
                OFL_LOG_WARN(LOG_MODULE, "Received SET_DL_SRC/DST action has invalid length (%zu).", *len);
                return ofl_error(OFPET_BAD_ACTION, OFPBAC_BAD_LEN);
            }

            sa = (struct ofp_action_dl_addr *)src;

            da = (struct ofl_action_dl_addr *)malloc(sizeof(struct ofl_action_dl_addr));
            memcpy(&(da->dl_addr), &(sa->dl_addr), OFP_ETH_ALEN);

            *len -= sizeof(struct ofp_action_dl_addr);
            *dst = (struct ofl_action_header *)da;
            break;
        }
        case OFPAT_SET_NW_SRC:
        case OFPAT_SET_NW_DST: {
            struct ofp_action_nw_addr *sa;
            struct ofl_action_nw_addr *da;

            if (*len < sizeof(struct ofp_action_nw_addr)) {
                OFL_LOG_WARN(LOG_MODULE, "Received SET_NW_SRC/DST action has invalid length (%zu).", *len);
                return ofl_error(OFPET_BAD_ACTION, OFPBAC_BAD_LEN);
            }

            sa = (struct ofp_action_nw_addr *)src;

            da = (struct ofl_action_nw_addr *)malloc(sizeof(struct ofl_action_nw_addr));
            da->nw_addr = sa->nw_addr;

            *len -= sizeof(struct ofp_action_nw_addr);
            *dst = (struct ofl_action_header *)da;
            break;
        }
        case OFPAT_SET_NW_TOS: {
            struct ofp_action_nw_tos *sa;
            struct ofl_action_nw_tos *da;

            if (*len < sizeof(struct ofp_action_nw_tos)) {
                OFL_LOG_WARN(LOG_MODULE, "Received SET_NW_TOS action has invalid length (%zu).", *len);
                return ofl_error(OFPET_BAD_ACTION, OFPBAC_BAD_LEN);
            }

            sa = (struct ofp_action_nw_tos *)src;

            if (sa->nw_tos > IP_DSCP_MASK) {
                OFL_LOG_WARN(LOG_MODULE, "Received SET_NW_TOS action has invalid tos value (%u).", sa->nw_tos);
                return ofl_error(OFPET_BAD_ACTION, OFPBAC_BAD_ARGUMENT);
            }

            da = (struct ofl_action_nw_tos *)malloc(sizeof(struct ofl_action_nw_tos));
            da->nw_tos = sa->nw_tos;

            *len -= sizeof(struct ofp_action_nw_tos);
            *dst = (struct ofl_action_header *)da;
            break;
        }

        case OFPAT_SET_NW_ECN: {
            struct ofp_action_nw_ecn *sa;
            struct ofl_action_nw_ecn *da;

            if (*len < sizeof(struct ofp_action_nw_ecn)) {
                OFL_LOG_WARN(LOG_MODULE, "Received SET_NW_ECN action has invalid length (%zu).", *len);
                return ofl_error(OFPET_BAD_ACTION, OFPBAC_BAD_LEN);
            }

            sa = (struct ofp_action_nw_ecn *)src;

            if (sa->nw_ecn > IP_ECN_MASK) {
                OFL_LOG_WARN(LOG_MODULE, "Received SET_NW_ECN action has invalid ecn value (%u).", sa->nw_ecn);
                return ofl_error(OFPET_BAD_ACTION, OFPBAC_BAD_ARGUMENT);
            }

            da = (struct ofl_action_nw_ecn *)malloc(sizeof(struct ofl_action_nw_ecn));
            da->nw_ecn = sa->nw_ecn;

            *len -= sizeof(struct ofp_action_nw_ecn);
            *dst = (struct ofl_action_header *)da;
            break;
        }

        case OFPAT_SET_TP_SRC:
        case OFPAT_SET_TP_DST: {
            struct ofp_action_tp_port *sa;
            struct ofl_action_tp_port *da;

            if (*len < sizeof(struct ofp_action_tp_port)) {
                OFL_LOG_WARN(LOG_MODULE, "Received SET_TP_SRC/DST action has invalid length (%zu).", *len);
                return ofl_error(OFPET_BAD_ACTION, OFPBAC_BAD_LEN);
            }

            sa = (struct ofp_action_tp_port *)src;

            da = (struct ofl_action_tp_port *)malloc(sizeof(struct ofl_action_tp_port));
            da->tp_port = ntohs(sa->tp_port);

            *len -= sizeof(struct ofp_action_tp_port);
            *dst = (struct ofl_action_header *)da;
            break;
        }

        case OFPAT_COPY_TTL_OUT: {
            //ofp_action_header length was already checked
            *len -= sizeof(struct ofp_action_header);
            *dst = (struct ofl_action_header *)malloc(sizeof(struct ofl_action_header));
            break;
        }

        case OFPAT_COPY_TTL_IN: {
            //ofp_action_header length was already checked
            *len -= sizeof(struct ofp_action_header);
            *dst = (struct ofl_action_header *)malloc(sizeof(struct ofl_action_header));
            break;
        }

        case OFPAT_SET_MPLS_LABEL: {
            struct ofp_action_mpls_label *sa;
            struct ofl_action_mpls_label *da;

            if (*len < sizeof(struct ofp_action_mpls_label)) {
                OFL_LOG_WARN(LOG_MODULE, "Received SET_MPLS_LABEL action has invalid length (%zu).", *len);
                return ofl_error(OFPET_BAD_ACTION, OFPBAC_BAD_LEN);
            }

            sa = (struct ofp_action_mpls_label *)src;

            if (ntohl(sa->mpls_label) > MPLS_LABEL_MAX) {
                OFL_LOG_WARN(LOG_MODULE, "Received SET_MPLS_LABEL action has invalid label value (%u).", ntohl(sa->mpls_label));
                return ofl_error(OFPET_BAD_ACTION, OFPBAC_BAD_ARGUMENT);
            }

            da = (struct ofl_action_mpls_label *)malloc(sizeof(struct ofl_action_mpls_label));
            da->mpls_label = ntohl(sa->mpls_label);

            *len -= sizeof(struct ofp_action_mpls_label);
            *dst = (struct ofl_action_header *)da;
            break;
        }

        case OFPAT_SET_MPLS_TC: {
            struct ofp_action_mpls_tc *sa;
            struct ofl_action_mpls_tc *da;

            if (*len < sizeof(struct ofp_action_mpls_tc)) {
                OFL_LOG_WARN(LOG_MODULE, "Received SET_MPLS_TC action has invalid length (%zu).", *len);
                return ofl_error(OFPET_BAD_ACTION, OFPBAC_BAD_LEN);
            }

            sa = (struct ofp_action_mpls_tc *)src;

            if (sa->mpls_tc > MPLS_TC_MAX) {
                OFL_LOG_WARN(LOG_MODULE, "Received SET_MPLS_TC action has invalid tc value (%u).", sa->mpls_tc);
                return ofl_error(OFPET_BAD_ACTION, OFPBAC_BAD_ARGUMENT);
            }

            da = (struct ofl_action_mpls_tc *)malloc(sizeof(struct ofl_action_mpls_tc));
            da->mpls_tc = sa->mpls_tc;

            *len -= sizeof(struct ofp_action_mpls_tc);
            *dst = (struct ofl_action_header *)da;
            break;
        }

        case OFPAT_SET_MPLS_TTL: {
            struct ofp_action_mpls_ttl *sa;
            struct ofl_action_mpls_ttl *da;

            if (*len < sizeof(struct ofp_action_mpls_ttl)) {
                OFL_LOG_WARN(LOG_MODULE, "Received SET_MPLS_TTL action has invalid length (%zu).", *len);
                return ofl_error(OFPET_BAD_ACTION, OFPBAC_BAD_LEN);
            }

            sa = (struct ofp_action_mpls_ttl *)src;

            da = (struct ofl_action_mpls_ttl *)malloc(sizeof(struct ofl_action_mpls_ttl));
            da->mpls_ttl = sa->mpls_ttl;

            *len -= sizeof(struct ofp_action_mpls_ttl);
            *dst = (struct ofl_action_header *)da;
            break;
        }

        case OFPAT_DEC_MPLS_TTL: {
            //ofp_action_header length was already checked
            *len -= sizeof(struct ofp_action_mpls_ttl);
            *dst = (struct ofl_action_header *)malloc(sizeof(struct ofl_action_header));
            break;
        }

        case OFPAT_PUSH_VLAN:
        case OFPAT_PUSH_MPLS: {
            struct ofp_action_push *sa;
            struct ofl_action_push *da;

            if (*len < sizeof(struct ofp_action_push)) {
                OFL_LOG_WARN(LOG_MODULE, "Received PUSH_VLAN/MPLS action has invalid length (%zu).", *len);
                return ofl_error(OFPET_BAD_ACTION, OFPBAC_BAD_LEN);
            }

            sa = (struct ofp_action_push *)src;

            if (((ntohs(src->type) == OFPAT_PUSH_VLAN) &&
                    (ntohs(sa->ethertype) != ETH_TYPE_VLAN &&
                     ntohs(sa->ethertype) != ETH_TYPE_VLAN_PBB)) ||
                ((ntohs(src->type) == OFPAT_PUSH_MPLS) &&
                    (ntohs(sa->ethertype) != ETH_TYPE_MPLS &&
                     ntohs(sa->ethertype) != ETH_TYPE_MPLS_MCAST))) {
                OFL_LOG_WARN(LOG_MODULE, "Received PUSH_VLAN/MPLS has invalid eth type. (%u)", ntohs(sa->ethertype));
                return ofl_error(OFPET_BAD_ACTION, OFPBAC_BAD_ARGUMENT);
            }

            da = (struct ofl_action_push *)malloc(sizeof(struct ofl_action_push));
            da->ethertype = ntohs(sa->ethertype);

            *len -= sizeof(struct ofp_action_push);
            *dst = (struct ofl_action_header *)da;
            break;
        }

        case OFPAT_POP_VLAN: {
            //ofp_action_header length was already checked
            *len -= sizeof(struct ofp_action_header);
            *dst = (struct ofl_action_header *)malloc(sizeof(struct ofl_action_header));
            break;
        }

        case OFPAT_POP_MPLS: {
            struct ofp_action_pop_mpls *sa;
            struct ofl_action_pop_mpls *da;

            if (*len < sizeof(struct ofp_action_pop_mpls)) {
                OFL_LOG_WARN(LOG_MODULE, "Received POP_MPLS action has invalid length (%zu).", *len);
                return ofl_error(OFPET_BAD_ACTION, OFPBAC_BAD_LEN);
            }

            sa = (struct ofp_action_pop_mpls *)src;

            da = (struct ofl_action_pop_mpls *)malloc(sizeof(struct ofl_action_pop_mpls));
            da->ethertype = ntohs(sa->ethertype);

            *len -= sizeof(struct ofp_action_pop_mpls);
            *dst = (struct ofl_action_header *)da;
            break;
        }

        case OFPAT_SET_QUEUE: {
            struct ofp_action_set_queue *sa;
            struct ofl_action_set_queue *da;

            if (*len < sizeof(struct ofp_action_set_queue)) {
                OFL_LOG_WARN(LOG_MODULE, "Received SET_QUEUE action has invalid length (%zu).", *len);
                return ofl_error(OFPET_BAD_ACTION, OFPBAC_BAD_LEN);
            }

            sa = (struct ofp_action_set_queue *)src;

            da = (struct ofl_action_set_queue *)malloc(sizeof(struct ofl_action_set_queue));
            da->queue_id = ntohl(sa->queue_id);

            *len -= sizeof(struct ofp_action_set_queue);
            *dst = (struct ofl_action_header *)da;
            break;
        }

        case OFPAT_GROUP: {
            struct ofp_action_group *sa;
            struct ofl_action_group *da;

            if (*len < sizeof(struct ofp_action_group)) {
                OFL_LOG_WARN(LOG_MODULE, "Received GROUP action has invalid length (%zu).", *len);
                return ofl_error(OFPET_BAD_ACTION, OFPBAC_BAD_LEN);
            }

            sa = (struct ofp_action_group *)src;

            if (ntohl(sa->group_id) > OFPG_MAX) {
                if (OFL_LOG_IS_WARN_ENABLED(LOG_MODULE)) {
                    char *gs = ofl_group_to_string(ntohl(sa->group_id));
                    OFL_LOG_WARN(LOG_MODULE, "Received GROUP action has invalid group id (%s).", gs);
                    free(gs);
                }
                return ofl_error(OFPET_BAD_ACTION, OFPBAC_BAD_ARGUMENT);
            }

            da = (struct ofl_action_group *)malloc(sizeof(struct ofl_action_group));
            da->group_id = ntohl(sa->group_id);

            *len -= sizeof(struct ofp_action_group);
            *dst = (struct ofl_action_header *)da;
            break;
        }

        case OFPAT_SET_NW_TTL: {
            struct ofp_action_nw_ttl *sa;
            struct ofl_action_set_nw_ttl *da;

            if (*len < sizeof(struct ofp_action_nw_ttl)) {
                OFL_LOG_WARN(LOG_MODULE, "Received SET_NW_TTL action has invalid length (%zu).", *len);
                return ofl_error(OFPET_BAD_ACTION, OFPBAC_BAD_LEN);
            }

            sa = (struct ofp_action_nw_ttl *)src;

            da = (struct ofl_action_set_nw_ttl *)malloc(sizeof(struct ofl_action_set_nw_ttl));
            da->nw_ttl = ntohs(sa->nw_ttl);

            *len -= sizeof(struct ofp_action_nw_ttl);
            *dst = (struct ofl_action_header *)da;
            break;
        }

        case OFPAT_DEC_NW_TTL: {
            //ofp_action_header length was already checked
            *len -= sizeof(struct ofp_action_header);
            *dst = (struct ofl_action_header *)malloc(sizeof(struct ofl_action_header));
            break;
        }

        case OFPAT_EXPERIMENTER: {
            ofl_err error;

            if (*len < sizeof(struct ofp_action_experimenter_header)) {
                OFL_LOG_WARN(LOG_MODULE, "Received EXPERIMENTER action has invalid length (%zu).", *len);
                return ofl_error(OFPET_BAD_ACTION, OFPBAC_BAD_LEN);
            }

            if (exp == NULL || exp->act == NULL || exp->act->unpack == NULL) {
                OFL_LOG_WARN(LOG_MODULE, "Received EXPERIMENTER action, but no callback is given.");
                return ofl_error(OFPET_BAD_ACTION, OFPBAC_BAD_EXPERIMENTER);
            }
            error = exp->act->unpack(src, len, dst);
            if (error) {
                return error;
            }
            break;
        }

        default: {
            OFL_LOG_WARN(LOG_MODULE, "Received unknown action type (%u).", ntohs(src->type));
            return ofl_error(OFPET_BAD_ACTION, OFPBAC_BAD_TYPE);
        }
    }

    (*dst)->type = (enum ofp_action_type)ntohs(src->type);
    return 0;
}
