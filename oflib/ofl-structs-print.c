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
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include <inttypes.h>
#include "openflow/openflow.h"

#include "ofl.h"
#include "ofl-actions.h"
#include "ofl-structs.h"
#include "ofl-print.h"
#include "ofl-packets.h"


#define ETH_ADDR_FMT                                                    \
    "%02"PRIx8":%02"PRIx8":%02"PRIx8":%02"PRIx8":%02"PRIx8":%02"PRIx8
#define ETH_ADDR_ARGS(ea)                                   \
    (ea)[0], (ea)[1], (ea)[2], (ea)[3], (ea)[4], (ea)[5]

#define IP_FMT "%"PRIu8".%"PRIu8".%"PRIu8".%"PRIu8
#define IP_ARGS(ip)                             \
        ((uint8_t *) ip)[0],                    \
        ((uint8_t *) ip)[1],                    \
        ((uint8_t *) ip)[2],                    \
        ((uint8_t *) ip)[3]


static uint8_t mask_all[8]  = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
static uint8_t mask_none[8] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};


char *
ofl_structs_port_to_string(struct ofl_port *port) {
        char *str;
    size_t str_size;
    FILE *stream = open_memstream(&str, &str_size);
    ofl_structs_port_print(stream, port);
    fclose(stream);
    return str;
}

void
ofl_structs_port_print(FILE *stream, struct ofl_port *port) {
    fprintf(stream, "{no=\"");
    ofl_port_print(stream, port->port_no);
    fprintf(stream, "\", hw_addr=\""ETH_ADDR_FMT"\", name=\"%s\", "
                          "config=\"0x%"PRIx32"\", state=\"0x%"PRIx32"\", curr=\"0x%"PRIx32"\", "
                          "adv=\"0x%"PRIx32"\", supp=\"0x%"PRIx32"\", peer=\"0x%"PRIx32"\", "
                          "curr_spd=\"%ukbps\", max_spd=\"%ukbps\"}",
                  ETH_ADDR_ARGS(port->hw_addr), port->name,
                  port->config, port->state, port->curr,
                  port->advertised, port->supported, port->peer,
                  port->curr_speed, port->max_speed);
}

char *
ofl_structs_instruction_to_string(struct ofl_instruction_header *inst, struct ofl_exp *exp) {
        char *str;
    size_t str_size;
    FILE *stream = open_memstream(&str, &str_size);
    ofl_structs_instruction_print(stream, inst, exp);
    fclose(stream);
    return str;
}

void
ofl_structs_instruction_print(FILE *stream, struct ofl_instruction_header *inst, struct ofl_exp *exp) {
    ofl_instruction_type_print(stream, inst->type);

    switch(inst->type) {
        case (OFPIT_GOTO_TABLE): {
            struct ofl_instruction_goto_table *i = (struct ofl_instruction_goto_table *)inst;

            fprintf(stream, "{table=\"%u\"}", i->table_id);

            break;
        }
        case (OFPIT_WRITE_METADATA): {
            struct ofl_instruction_write_metadata *i = (struct ofl_instruction_write_metadata *)inst;

            fprintf(stream, "{meta=\"0x%"PRIx64"\", mask=\"0x%"PRIx64"\"}",
                          i->metadata, i->metadata_mask);

            break;
        }
        case (OFPIT_WRITE_ACTIONS):
        case (OFPIT_APPLY_ACTIONS): {
            struct ofl_instruction_actions *i = (struct ofl_instruction_actions *)inst;
            size_t j;

            fprintf(stream, "{acts=[");
            for(j=0; j<i->actions_num; j++) {
                ofl_action_print(stream, i->actions[j], exp);
                if (j < i->actions_num - 1) { fprintf(stream, ", "); }
            }
            fprintf(stream, "]}");

            break;
        }
        case (OFPIT_CLEAR_ACTIONS): {
            break;
        }
        case (OFPIT_EXPERIMENTER): {
            if (exp == NULL || exp->inst == NULL || exp->inst->to_string == NULL) {
                struct ofl_instruction_experimenter *i = (struct ofl_instruction_experimenter *)inst;

                fprintf(stream, "{id=\"0x%"PRIx32"\"}", i->experimenter_id);
            } else {
                char *c = exp->inst->to_string(inst);
                fprintf(stream, "%s", c);
                free (c);
            }
            break;
        }
    }

}

char *
ofl_structs_match_to_string(struct ofl_match_header *match, struct ofl_exp *exp) {
        char *str;
    size_t str_size;
    FILE *stream = open_memstream(&str, &str_size);
    ofl_structs_match_print(stream, match, exp);
    fclose(stream);
    return str;
}

void
ofl_structs_match_print(FILE *stream, struct ofl_match_header *match, struct ofl_exp *exp) {

    switch (match->type) {
        case (OFPMT_STANDARD): {
            struct ofl_match_standard *m = (struct ofl_match_standard *)match;

            fprintf(stream, "std{wc=\"0x%"PRIx32"\"", m->wildcards);

            if ((m->wildcards & OFPFW_IN_PORT) == 0) {
                fprintf(stream, ", port=\"");
                ofl_port_print(stream, m->in_port);
                fprintf(stream, "\"");
            }
            if (memcmp(m->dl_src_mask, mask_all, ETH_ADDR_LEN) == 0) {
                fprintf(stream, ", dlsrcm=\"all\"");
            } else {
                fprintf(stream, ", dlsrc=\""ETH_ADDR_FMT"\"", ETH_ADDR_ARGS(m->dl_src));
                if (memcmp(m->dl_src_mask, mask_none, ETH_ADDR_LEN) != 0) {
                    fprintf(stream, ", dlsrcm=\""ETH_ADDR_FMT"\"", ETH_ADDR_ARGS(m->dl_src_mask));
                }
            }
            if (memcmp(m->dl_dst_mask, mask_all, ETH_ADDR_LEN) == 0) {
                fprintf(stream, ", dldstm=\"all\"");
            } else {
                fprintf(stream, ", dldst=\""ETH_ADDR_FMT"\"", ETH_ADDR_ARGS(m->dl_dst));
                if (memcmp(m->dl_dst_mask, mask_none, ETH_ADDR_LEN) != 0) {
                    fprintf(stream, ", dldstm=\""ETH_ADDR_FMT"\"", ETH_ADDR_ARGS(m->dl_dst_mask));
                }
            }
            if ((m->wildcards & OFPFW_DL_VLAN) == 0) {
                fprintf(stream, ", vlan=\"");
                ofl_vlan_vid_print(stream, m->dl_vlan);
                fprintf(stream, "\"");
            }
            if ((m->wildcards & OFPFW_DL_VLAN_PCP) == 0) {
                fprintf(stream, ", vlanpcp=\"%u\"", m->dl_vlan_pcp);
            }
            if ((m->wildcards & OFPFW_DL_TYPE) == 0) {
                fprintf(stream, ", dltype=\"0x%"PRIx16"\"", m->dl_type);
            }
            if ((m->wildcards & OFPFW_NW_TOS) == 0) {
                fprintf(stream, ", nwtos=\"%u\"", m->nw_tos);
            }
            if ((m->wildcards & OFPFW_NW_PROTO) == 0) {
                fprintf(stream, ", nwprt=\"0x%04"PRIx16"\"", m->nw_proto);
            }
            if ((m->nw_src_mask == 0xffffffff)) {
                fprintf(stream, ", nwsrcm=\"all\"");
            } else {
                fprintf(stream, ", nwsrc=\""IP_FMT"\"", IP_ARGS(&m->nw_src));
                if ((m->nw_src_mask != 0x00000000)) {
                    fprintf(stream, ", nwsrcm=\""IP_FMT"\"", IP_ARGS(&m->nw_src_mask));
                }
            }
            if ((m->nw_dst_mask == 0xffffffff)) {
                fprintf(stream, ", nwdstm=\"all\"");
            } else {
                fprintf(stream, ", nwdst=\""IP_FMT"\"", IP_ARGS(&m->nw_dst));
                if ((m->nw_dst_mask != 0x00000000)) {
                    fprintf(stream, ", nwdstm=\""IP_FMT"\"", IP_ARGS(&m->nw_dst_mask));
                }
            }
            if ((m->wildcards & OFPFW_TP_SRC) == 0) {
                fprintf(stream, ", tpsrc=\"%u\"", m->tp_src);
            }
            if ((m->wildcards & OFPFW_TP_DST) == 0) {
                fprintf(stream, ", tpdst=\"%u\"", m->tp_dst);
            }
            if ((m->wildcards & OFPFW_MPLS_LABEL) == 0) {
                fprintf(stream, ", mplslbl=\"0x%05"PRIx32"\"", m->mpls_label);
            }
            if ((m->wildcards & OFPFW_MPLS_TC) == 0) {
                fprintf(stream, ", mplstc=\"%u\"", m->mpls_tc);
            }
            if (memcmp(&m->metadata_mask, mask_all, 8) == 0) {
                fprintf(stream, ", metam=\"all\"");
            } else {
                fprintf(stream, ", meta=\"0x%"PRIx64"\"", m->metadata);
                if (memcmp(&m->metadata_mask, mask_none, 8) != 0) {
                    fprintf(stream, ", metam=\"0x%"PRIx64"\"", m->metadata_mask);
                }
            }
            fprintf(stream, "}");

            break;
        }
        default: {
            if (exp == NULL || exp->match == NULL || exp->match->to_string == NULL) {
                fprintf(stream, "?(%u)", match->type);
            } else {
                char *c = exp->match->to_string(match);
                fprintf(stream, "%s", c);
                free(c);
            }
        }
    }
}


char *
ofl_structs_config_to_string(struct ofl_config *c) {
        char *str;
    size_t str_size;
    FILE *stream = open_memstream(&str, &str_size);
    ofl_structs_config_print(stream, c);
    fclose(stream);
    return str;
}

void
ofl_structs_config_print(FILE *stream, struct ofl_config *c) {
    fprintf(stream, "{flags=\"0x%"PRIx16"\", mlen=\"%u\"}",
                  c->flags, c->miss_send_len);
}

char *
ofl_structs_bucket_to_string(struct ofl_bucket *b, struct ofl_exp *exp) {
        char *str;
    size_t str_size;
    FILE *stream = open_memstream(&str, &str_size);
    ofl_structs_bucket_print(stream, b, exp);
    fclose(stream);
    return str;
}

void
ofl_structs_bucket_print(FILE *stream, struct ofl_bucket *b, struct ofl_exp *exp) {
    size_t i;

    fprintf(stream, "{w=\"%u\", wprt=\"", b->weight);
    ofl_port_print(stream, b->watch_port);
    fprintf(stream, "\", wgrp=\"");
    ofl_group_print(stream, b->watch_group);
    fprintf(stream, "\", acts=[");

    for (i=0; i<b->actions_num; i++) {
        ofl_action_print(stream, b->actions[i], exp);
        if (i < b->actions_num - 1) { fprintf(stream, ", "); }
    }

    fprintf(stream, "]}");
}

char *
ofl_structs_queue_to_string(struct ofl_packet_queue *q) {
        char *str;
    size_t str_size;
    FILE *stream = open_memstream(&str, &str_size);
    ofl_structs_queue_print(stream, q);
    fclose(stream);
    return str;
}

void
ofl_structs_queue_print(FILE *stream, struct ofl_packet_queue *q) {
    size_t i;

    fprintf(stream, "{q=\"");
    ofl_queue_print(stream, q->queue_id);
    fprintf(stream, "\", props=[");

    for (i=0; i<q->properties_num; i++) {
        ofl_structs_queue_prop_print(stream, q->properties[i]);
        if (i < q->properties_num - 1) { fprintf(stream, ", "); }
    }

    fprintf(stream, "]}");
}

char *
ofl_structs_queue_prop_to_string(struct ofl_queue_prop_header *p) {
        char *str;
    size_t str_size;
    FILE *stream = open_memstream(&str, &str_size);
    ofl_structs_queue_prop_print(stream, p);
    fclose(stream);
    return str;
}

void
ofl_structs_queue_prop_print(FILE *stream, struct ofl_queue_prop_header *p) {
    ofl_queue_prop_type_print(stream, p->type);

    switch(p->type) {
        case (OFPQT_MIN_RATE): {
            struct ofl_queue_prop_min_rate *pm = (struct ofl_queue_prop_min_rate *)p;

            fprintf(stream, "{rate=\"%u\"}", pm->rate);
            break;
        }
        case (OFPQT_NONE): {
            break;
        }
    }

}

char *
ofl_structs_flow_stats_to_string(struct ofl_flow_stats *s, struct ofl_exp *exp) {
        char *str;
    size_t str_size;
    FILE *stream = open_memstream(&str, &str_size);
    ofl_structs_flow_stats_print(stream, s, exp);
    fclose(stream);
    return str;
}

void
ofl_structs_flow_stats_print(FILE *stream, struct ofl_flow_stats *s, struct ofl_exp *exp) {
    size_t i;

    fprintf(stream, "{table=\"");
    ofl_table_print(stream, s->table_id);
    fprintf(stream, "\", match=\"");
    ofl_structs_match_print(stream, s->match, exp);
    fprintf(stream, "\", dur_s=\"%u\", dur_ns=\"%u\", prio=\"%u\", "
                          "idle_to=\"%u\", hard_to=\"%u\", cookie=\"0x%"PRIx64"\", "
                          "pkt_cnt=\"%"PRIu64"\", byte_cnt=\"%"PRIu64"\", insts=[",
                  s->duration_sec, s->duration_nsec, s->priority,
                  s->idle_timeout, s->hard_timeout, s->cookie,
                  s->packet_count, s->byte_count);

    for (i=0; i<s->instructions_num; i++) {
        ofl_structs_instruction_print(stream, s->instructions[i], exp);
        if (i < s->instructions_num - 1) { fprintf(stream, ", "); };
    }

    fprintf(stream, "]}");
}

char *
ofl_structs_bucket_counter_to_string(struct ofl_bucket_counter *s) {
        char *str;
    size_t str_size;
    FILE *stream = open_memstream(&str, &str_size);
    ofl_structs_bucket_counter_print(stream, s);
    fclose(stream);
    return str;
}

void
ofl_structs_bucket_counter_print(FILE *stream, struct ofl_bucket_counter *c) {
    fprintf(stream, "{pkt_cnt=\"%"PRIu64"\", byte_cnt=\"%"PRIu64"\"}",
                  c->packet_count, c->byte_count);
}

char *
ofl_structs_group_stats_to_string(struct ofl_group_stats *s) {
        char *str;
    size_t str_size;
    FILE *stream = open_memstream(&str, &str_size);
    ofl_structs_group_stats_print(stream, s);
    fclose(stream);
    return str;
}

void
ofl_structs_group_stats_print(FILE *stream, struct ofl_group_stats *s) {
    size_t i;

    fprintf(stream, "{group=\"");
    ofl_group_print(stream, s->group_id);
    fprintf(stream, "\", ref_cnt=\"%u\", pkt_cnt=\"%"PRIu64"\", byte_cnt=\"%"PRIu64"\", cntrs=[",
                  s->ref_count, s->packet_count, s->byte_count);

    for (i=0; i<s->counters_num; i++) {
        ofl_structs_bucket_counter_print(stream, s->counters[i]);
        if (i < s->counters_num - 1) { fprintf(stream, ", "); };
    }

    fprintf(stream, "]}");
}

char *
ofl_structs_table_stats_to_string(struct ofl_table_stats *s) {
    char *str;
    size_t str_size;
    FILE *stream = open_memstream(&str, &str_size);

    ofl_structs_table_stats_print(stream, s);

    fclose(stream);
    return str;
}

void
ofl_structs_table_stats_print(FILE *stream, struct ofl_table_stats *s) {
    fprintf(stream, "{table=\"");
    ofl_table_print(stream, s->table_id);
    fprintf(stream, "\", name=\"%s\", wcards=\"0x%"PRIx32"\", match=\"0x%"PRIx32"\", "
                          "insts=\"0x%"PRIx32"\", w_acts=\"0x%"PRIx32"\", a_acts=\"0x%"PRIx32"\", "
                          "conf=\"0x%"PRIx32"\", max=\"%u\", active=\"%u\", "
                          "lookup=\"%"PRIu64"\", match=\"%"PRIu64"\"",
                  s->name, s->wildcards, s->match,
                  s->instructions, s->write_actions, s->apply_actions,
                  s->config, s->max_entries, s->active_count,
                  s->lookup_count, s->matched_count);
}

char *
ofl_structs_port_stats_to_string(struct ofl_port_stats *s) {
        char *str;
    size_t str_size;
    FILE *stream = open_memstream(&str, &str_size);
    ofl_structs_port_stats_print(stream, s);
    fclose(stream);
    return str;
}

void
ofl_structs_port_stats_print(FILE *stream, struct ofl_port_stats *s) {

    fprintf(stream, "{port=\"");
    ofl_port_print(stream, s->port_no);
    fprintf(stream, "\", rx_pkt=\"%"PRIu64"\", tx_pkt=\"%"PRIu64"\", "
                          "rx_bytes=\"%"PRIu64"\", tx_bytes=\"%"PRIu64"\", "
                          "rx_drops=\"%"PRIu64"\", tx_drops=\"%"PRIu64"\", "
                          "rx_errs=\"%"PRIu64"\", tx_errs=\"%"PRIu64"\", "
                          "rx_frm=\"%"PRIu64"\", rx_over=\"%"PRIu64"\", "
                          "rx_crc=\"%"PRIu64"\", coll=\"%"PRIu64"\"}",
                  s->rx_packets, s->tx_packets,
                  s->rx_bytes, s->tx_bytes,
                  s->rx_dropped, s->tx_dropped,
                  s->rx_errors, s->tx_errors,
                  s->rx_frame_err, s->rx_over_err,
                  s->rx_crc_err, s->collisions);
};

char *
ofl_structs_queue_stats_to_string(struct ofl_queue_stats *s) {
        char *str;
    size_t str_size;
    FILE *stream = open_memstream(&str, &str_size);
    ofl_structs_queue_stats_print(stream, s);
    fclose(stream);
    return str;
}

void
ofl_structs_queue_stats_print(FILE *stream, struct ofl_queue_stats *s) {

    fprintf(stream, "{port=\"");
    ofl_port_print(stream, s->port_no);
    fprintf(stream, "\", q=\"");
    ofl_queue_print(stream, s->queue_id);
    fprintf(stream, "\", tx_bytes=\"%"PRIu64"\", "
                          "tx_pkt=\"%"PRIu64"\", tx_err=\"%"PRIu64"\"}",
                  s->tx_bytes, s->tx_packets, s->tx_errors);
};

char *
ofl_structs_group_desc_stats_to_string(struct ofl_group_desc_stats *s, struct ofl_exp *exp) {
        char *str;
    size_t str_size;
    FILE *stream = open_memstream(&str, &str_size);
    ofl_structs_group_desc_stats_print(stream, s, exp);
    fclose(stream);
    return str;
}

void
ofl_structs_group_desc_stats_print(FILE *stream, struct ofl_group_desc_stats *s, struct ofl_exp *exp) {
    size_t i;

    fprintf(stream, "{type=\"");
    ofl_group_type_print(stream, s->type);
    fprintf(stream, "\", group=\"");
    ofl_group_print(stream, s->group_id);
    fprintf(stream, "\", buckets=[");

    for (i=0; i<s->buckets_num; i++) {
        ofl_structs_bucket_print(stream, s->buckets[i], exp);
        if (i < s->buckets_num - 1) { fprintf(stream, ", "); };
    }

    fprintf(stream, "]}");
}
