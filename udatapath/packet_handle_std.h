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

#ifndef PACKET_HANDLE_STD_H
#define PACKET_HANDLE_STD_H 1

#include <stdbool.h>
#include <stdio.h>
#include "packet.h"
#include "packets.h"
#include "oflib/ofl-structs.h"

/****************************************************************************
 * A handler processing a datapath packet for standard matches.
 ****************************************************************************/

/* A structure holding references to supported protocols within the packet. */
struct protocols_std {
    struct eth_header      *eth;
    struct snap_header     *eth_snap; /* points to SNAP header if eth is 802.3 */
    struct vlan_header     *vlan;
    struct vlan_header     *vlan_last; /* points to the last VLAN header */
    struct mpls_header     *mpls;
    struct ip_header       *ipv4;
    struct arp_eth_header  *arp;
    struct tcp_header      *tcp;
    struct udp_header      *udp;
    struct sctp_header     *sctp;
    struct icmp_header     *icmp;
};

/* The data associated with the handler */
struct packet_handle_std {
    struct packet              *pkt;
    struct protocols_std       *proto;
    struct ofl_match_standard  *match; /* Match fields extracted from the packet
                                            are also stored in a match structure
                                            for convenience */
    bool                        valid; /* Set to true if the handler data is valid.
                                            if false, it is revalidated before
                                            executing any methods. */
};

/* Creates a handler */
struct packet_handle_std *
packet_handle_std_create(struct packet *pkt);

/* Destroys a handler */
void
packet_handle_std_destroy(struct packet_handle_std *handle);

/* Returns true if the TTL fields of the supported protocols are valid. */
bool
packet_handle_std_is_ttl_valid(struct packet_handle_std *handle);

/* Returns true if the packet is a fragment (IPv4). */
bool
packet_handle_std_is_fragment(struct packet_handle_std *handle);

/* Returns true if the packet matches the given standard match structure. */
bool
packet_handle_std_match(struct packet_handle_std *handle, struct ofl_match_standard *match);

/* Converts the packet to a string representation */
char *
packet_handle_std_to_string(struct packet_handle_std *handle);

void
packet_handle_std_print(FILE *stream, struct packet_handle_std *handle);

/* Clones the handler, and associates it with the new packet. */
struct packet_handle_std *
packet_handle_std_clone(struct packet *pkt, struct packet_handle_std *handle);

/* Revalidates the handler data */
void
packet_handle_std_validate(struct packet_handle_std *handle);


#endif /* PACKET_HANDLE_STD_H */
