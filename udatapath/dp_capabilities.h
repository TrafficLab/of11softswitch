/* Copyright (c) 2008 The Board of Trustees of The Leland Stanford
 * Junior University
 *
 * We are making the OpenFlow specification and associated documentation
 * (Software) available for public use and benefit with the expectation
 * that others will use, modify and enhance the Software and contribute
 * those enhancements back to the community. However, since we would
 * like to make the Software available for broadest use, with as few
 * restrictions as possible permission is hereby granted, free of
 * charge, to any person obtaining a copy of this Software to deal in
 * the Software under the copyrights without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT.  IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 * The name and trademarks of copyright holder(s) may NOT be used in
 * advertising or publicity pertaining to the Software or any
 * derivatives without specific, written prior permission.
 */

#ifndef DP_CAPABILITIES_H
#define DP_CAPABILITIES_H 1


#include "openflow/openflow.h"


/****************************************************************************
 * Datapath capabilities.
 ****************************************************************************/


#define DP_SUPPORTED_CAPABILITIES ( OFPC_FLOW_STATS        \
                               | OFPC_TABLE_STATS          \
                               | OFPC_PORT_STATS           \
                               | OFPC_GROUP_STATS          \
                            /* | OFPC_IP_REASM       */    \
                               | OFPC_QUEUE_STATS          \
                               | OFPC_ARP_MATCH_IP )

#define DP_SUPPORTED_INSTRUCTIONS ( (1 << OFPIT_GOTO_TABLE)         \
                                  | (1 << OFPIT_WRITE_METADATA)     \
                                  | (1 << OFPIT_WRITE_ACTIONS)      \
                                  | (1 << OFPIT_APPLY_ACTIONS)      \
                                  | (1 << OFPIT_CLEAR_ACTIONS) )

#define DP_SUPPORTED_ACTIONS ( (1 << OFPAT_OUTPUT)          \
                             | (1 << OFPAT_SET_VLAN_VID)    \
                             | (1 << OFPAT_SET_VLAN_PCP)    \
                             | (1 << OFPAT_SET_DL_SRC)      \
                             | (1 << OFPAT_SET_DL_DST)      \
                             | (1 << OFPAT_SET_NW_SRC)      \
                             | (1 << OFPAT_SET_NW_DST)      \
                             | (1 << OFPAT_SET_NW_TOS)      \
                             | (1 << OFPAT_SET_NW_ECN)      \
                             | (1 << OFPAT_SET_TP_SRC)      \
                             | (1 << OFPAT_SET_TP_DST)      \
                             | (1 << OFPAT_COPY_TTL_OUT)    \
                             | (1 << OFPAT_COPY_TTL_IN)     \
                             | (1 << OFPAT_SET_MPLS_LABEL)  \
                             | (1 << OFPAT_SET_MPLS_TC)     \
                             | (1 << OFPAT_SET_MPLS_TTL)    \
                             | (1 << OFPAT_DEC_MPLS_TTL)    \
                             | (1 << OFPAT_PUSH_VLAN)       \
                             | (1 << OFPAT_POP_VLAN)        \
                             | (1 << OFPAT_PUSH_MPLS)       \
                             | (1 << OFPAT_POP_MPLS)        \
                             | (1 << OFPAT_SET_QUEUE)       \
                             | (1 << OFPAT_GROUP)           \
                             | (1 << OFPAT_SET_NW_TTL)      \
                             | (1 << OFPAT_DEC_NW_TTL) )

#define DP_SUPPORTED_WILDCARDS    OFPFW_ALL

#define DP_SUPPORTED_MATCH_FIELDS ( OFPFMF_IN_PORT        \
                                  | OFPFMF_DL_VLAN        \
                                  | OFPFMF_DL_VLAN_PCP    \
                                  | OFPFMF_DL_TYPE        \
                                  | OFPFMF_NW_TOS         \
                                  | OFPFMF_NW_PROTO       \
                                  | OFPFMF_TP_SRC         \
                                  | OFPFMF_TP_DST         \
                                  | OFPFMF_MPLS_LABEL     \
                                  | OFPFMF_MPLS_TC        \
                                  | OFPFMF_TYPE           \
                                  | OFPFMF_DL_SRC         \
                                  | OFPFMF_DL_DST         \
                                  | OFPFMF_NW_SRC         \
                                  | OFPFMF_NW_SRC         \
                                  | OFPFMF_NW_DST         \
                                  | OFPFMF_METADATA )


#endif /* DP_CAPABILITIES_H */
