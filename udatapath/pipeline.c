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

#include <sys/types.h>
#include <stdbool.h>
#include <stdlib.h>

#include "action_set.h"
#include "compiler.h"
#include "dp_actions.h"
#include "dp_buffers.h"
#include "dp_exp.h"
#include "dp_ports.h"
#include "datapath.h"
#include "packet.h"
#include "pipeline.h"
#include "flow_table.h"
#include "flow_entry.h"
#include "oflib/ofl.h"
#include "oflib/ofl-structs.h"
#include "util.h"
#include "vlog.h"

#define LOG_MODULE VLM_pipeline

static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(60, 60);

static void
execute_entry(struct pipeline *pl, struct flow_entry *entry,
              struct flow_table **table, struct packet *pkt);

static void
execute_table(struct pipeline *pl, struct flow_table *table,
              struct flow_table **next_table, struct packet *pkt);

struct pipeline *
pipeline_create(struct datapath *dp) {
    struct pipeline *pl;
    int i;

    pl = xmalloc(sizeof(struct pipeline));
    for (i=0; i<PIPELINE_TABLES; i++) {
        pl->tables[i] = flow_table_create(dp, i);
    }
    pl->dp = dp;

    return pl;
}

/* Sends a packet to the controller in a packet_in message */
static void
send_packet_to_controller(struct pipeline *pl, struct packet *pkt, uint8_t table_id, uint8_t reason) {
    dp_buffers_save(pl->dp->buffers, pkt);

    {
        struct ofl_msg_packet_in msg =
                {{.type = OFPT_PACKET_IN},
                 .buffer_id   = pkt->buffer_id,
                 .in_port     = pkt->in_port,
                 .in_phy_port = pkt->in_port, // TODO: how to get phy port for v.port?
                 .total_len   = pkt->buffer->size,
                 .reason      = reason,
                 .table_id    = table_id,
                 .data_length = MIN(pl->dp->config.miss_send_len, pkt->buffer->size),
                 .data        = pkt->buffer->data};

        dp_send_message(pl->dp, (struct ofl_msg_header *)&msg, NULL);
    }
}

void
pipeline_process_packet(struct pipeline *pl, struct packet *pkt) {
    struct flow_table *table, *next_table;

    if (VLOG_IS_DBG_ENABLED(LOG_MODULE)) {
        char *pkt_str = packet_to_string(pkt);
        VLOG_DBG_RL(LOG_MODULE, &rl, "processing packet: %s", pkt_str);
        free(pkt_str);
    }

    if (!packet_handle_std_is_ttl_valid(pkt->handle_std)) {
        if ((pl->dp->config.flags & OFPC_INVALID_TTL_TO_CONTROLLER) != 0) {
            VLOG_DBG_RL(LOG_MODULE, &rl, "Packet has invalid TTL, sending to controller.");

            /* NOTE: no valid reason for invalid ttl in spec. */
            send_packet_to_controller(pl, pkt, 0/*table_id*/, OFPR_NO_MATCH);
        } else {
            VLOG_DBG_RL(LOG_MODULE, &rl, "Packet has invalid TTL, dropping.");
        }
        packet_destroy(pkt);
        return;
    }

    next_table = pl->tables[0];

    while (next_table != NULL) {
        struct flow_entry *entry;

        VLOG_DBG_RL(LOG_MODULE, &rl, "trying table %u.", next_table->stats->table_id);

        pkt->table_id = next_table->stats->table_id;
        table         = next_table;
        next_table    = NULL;

        entry = flow_table_lookup(table, pkt);

        if (entry != NULL) {
            if (VLOG_IS_DBG_ENABLED(LOG_MODULE)) {
                char *m = ofl_structs_flow_stats_to_string(entry->stats, pkt->dp->exp);
                VLOG_DBG_RL(LOG_MODULE, &rl, "found matching entry: %s.", m);
                free(m);
            }

            execute_entry(pl, entry, &next_table, pkt);

            if (next_table == NULL) {
                action_set_execute(pkt->action_set, pkt);
                packet_destroy(pkt);
                return;
            }

        } else {
			VLOG_DBG_RL(LOG_MODULE, &rl, "no matching entry found. executing table conf.");
			execute_table(pl, table, &next_table, pkt);
			if (next_table == NULL) {
				packet_destroy(pkt);
				return;
			}
        }
    }
    VLOG_WARN_RL(LOG_MODULE, &rl, "Reached outside of pipeline processing cycle.");
}


ofl_err
pipeline_handle_flow_mod(struct pipeline *pl, struct ofl_msg_flow_mod *msg,
                                                const struct sender *sender UNUSED) {
    /* Note: the result of using table_id = 0xff is undefined in the spec.
     *       for now it is accepted for delete commands, meaning to delete
     *       from all tables */
    ofl_err error;
    size_t i;

    bool match_kept = false;
    bool insts_kept = false;

    // Validate actions in flow_mod
    for (i=0; i< msg->instructions_num; i++) {
        if (msg->instructions[i]->type == OFPIT_APPLY_ACTIONS ||
            msg->instructions[i]->type == OFPIT_WRITE_ACTIONS) {
            struct ofl_instruction_actions *ia = (struct ofl_instruction_actions *)msg->instructions[i];

            error = dp_actions_validate(pl->dp, ia->actions_num, ia->actions);
            if (error) {
                return error;
            }
        }
    }

    if (msg->table_id == 0xff) {
        if (msg->command == OFPFC_DELETE || msg->command == OFPFC_DELETE_STRICT) {
            size_t i;

            error = 0;
            for (i=0; i < PIPELINE_TABLES; i++) {
                error = flow_table_flow_mod(pl->tables[i], msg, &match_kept, &insts_kept);
                if (error) {
                    break;
                }
            }
            if (error) {
                return error;
            } else {
                ofl_msg_free_flow_mod(msg, !match_kept, !insts_kept, pl->dp->exp);
                return 0;
            }
        } else {
            return ofl_error(OFPET_FLOW_MOD_FAILED, OFPFMFC_BAD_TABLE_ID);
        }
    } else {
        error = flow_table_flow_mod(pl->tables[msg->table_id], msg, &match_kept, &insts_kept);
        if (error) {
            return error;
        }
        if ((msg->command == OFPFC_ADD || msg->command == OFPFC_MODIFY || msg->command == OFPFC_MODIFY_STRICT) &&
                            msg->buffer_id != NO_BUFFER) {
            /* run buffered message through pipeline */
            struct packet *pkt;

            pkt = dp_buffers_retrieve(pl->dp->buffers, msg->buffer_id);

            if (pkt != NULL) {
                pipeline_process_packet(pl, pkt);
            } else {
                VLOG_WARN_RL(LOG_MODULE, &rl, "The buffer flow_mod referred to was empty (%u).", msg->buffer_id);
            }
        }

        ofl_msg_free_flow_mod(msg, !match_kept, !insts_kept, pl->dp->exp);
        return 0;
    }

}

ofl_err
pipeline_handle_table_mod(struct pipeline *pl,
                          struct ofl_msg_table_mod *msg,
                          const struct sender *sender UNUSED) {
    if (msg->table_id == 0xff) {
        size_t i;

        for (i=0; i<PIPELINE_TABLES; i++) {
            pl->tables[i]->stats->config = msg->config;
        }
    } else {
        pl->tables[msg->table_id]->stats->config = msg->config;
    }

    ofl_msg_free((struct ofl_msg_header *)msg, pl->dp->exp);
    return 0;
}

ofl_err
pipeline_handle_stats_request_flow(struct pipeline *pl,
                                   struct ofl_msg_stats_request_flow *msg,
                                   const struct sender *sender) {

    struct ofl_flow_stats **stats = xmalloc(sizeof(struct ofl_flow_stats *));
    size_t stats_size = 1;
    size_t stats_num = 0;

    if (msg->table_id == 0xff) {
        size_t i;
        for (i=0; i<PIPELINE_TABLES; i++) {
            flow_table_stats(pl->tables[i], msg, &stats, &stats_size, &stats_num);
        }
    } else {
        flow_table_stats(pl->tables[msg->table_id], msg, &stats, &stats_size, &stats_num);
    }

    {
        struct ofl_msg_stats_reply_flow reply =
                {{{.type = OFPT_STATS_REPLY},
                  .type = OFPST_FLOW, .flags = 0x0000},
                 .stats     = stats,
                 .stats_num = stats_num
                };

        dp_send_message(pl->dp, (struct ofl_msg_header *)&reply, sender);
    }

    free(stats);
    ofl_msg_free((struct ofl_msg_header *)msg, pl->dp->exp);
    return 0;
}

ofl_err
pipeline_handle_stats_request_table(struct pipeline *pl,
                                    struct ofl_msg_stats_request_header *msg UNUSED,
                                    const struct sender *sender) {
    struct ofl_table_stats **stats;
    size_t i;

    stats = xmalloc(sizeof(struct ofl_table_stats *) * PIPELINE_TABLES);

    for (i=0; i<PIPELINE_TABLES; i++) {
        stats[i] = pl->tables[i]->stats;
    }

    {
        struct ofl_msg_stats_reply_table reply =
                {{{.type = OFPT_STATS_REPLY},
                  .type = OFPST_TABLE, .flags = 0x0000},
                 .stats     = stats,
                 .stats_num = PIPELINE_TABLES};

        dp_send_message(pl->dp, (struct ofl_msg_header *)&reply, sender);
    }

    free(stats);
    ofl_msg_free((struct ofl_msg_header *)msg, pl->dp->exp);
    return 0;
}

ofl_err
pipeline_handle_stats_request_aggregate(struct pipeline *pl,
                                  struct ofl_msg_stats_request_flow *msg,
                                  const struct sender *sender) {
    struct ofl_msg_stats_reply_aggregate reply =
            {{{.type = OFPT_STATS_REPLY},
              .type = OFPST_AGGREGATE, .flags = 0x0000},
              .packet_count = 0,
              .byte_count   = 0,
              .flow_count   = 0};

    if (msg->table_id == 0xff) {
        size_t i;

        for (i=0; i<PIPELINE_TABLES; i++) {
            flow_table_aggregate_stats(pl->tables[i], msg,
                                       &reply.packet_count, &reply.byte_count, &reply.flow_count);
        }

    } else {
        flow_table_aggregate_stats(pl->tables[msg->table_id], msg,
                                   &reply.packet_count, &reply.byte_count, &reply.flow_count);
    }

    dp_send_message(pl->dp, (struct ofl_msg_header *)&reply, sender);

    ofl_msg_free((struct ofl_msg_header *)msg, pl->dp->exp);
    return 0;
}


void
pipeline_destroy(struct pipeline *pl) {
    struct flow_table *table;
    int i;

    for (i=0; i<PIPELINE_TABLES; i++) {
        table = pl->tables[i];
        if (table != NULL) {
            flow_table_destroy(table);
        }
    }
    free(pl);
}


void
pipeline_timeout(struct pipeline *pl) {
    int i;

    for (i = 0; i < PIPELINE_TABLES; i++) {
        flow_table_timeout(pl->tables[i]);
    }
}


/* Returns the instruction with the given type from the set of instructions. */
static struct ofl_instruction_header *
get_instruction(size_t insts_num, struct ofl_instruction_header **insts, uint16_t type) {
    size_t i;

    for (i=0; i < insts_num; i++) {
        if (insts[i]->type == type) {
            return insts[i];
        }
    }

    return NULL;
}


/* Executes the instructions associated with a flow entry */
static void
execute_entry(struct pipeline *pl, struct flow_entry *entry,
              struct flow_table **next_table, struct packet *pkt) {
    /* NOTE: CLEAR instruction must be executed before WRITE_ACTIONS;
     *       GOTO instruction must be executed last according to spec. */
    struct ofl_instruction_header *inst, *cinst;
    size_t i;
    bool clear_execd = false;

    for (i=0; i < entry->stats->instructions_num; i++) {
        inst = entry->stats->instructions[i];

        switch (inst->type) {
            case OFPIT_GOTO_TABLE: {
                struct ofl_instruction_goto_table *gi = (struct ofl_instruction_goto_table *)inst;

                *next_table = pl->tables[gi->table_id];
                break;
            }
            case OFPIT_WRITE_METADATA: {
                struct ofl_instruction_write_metadata *wi = (struct ofl_instruction_write_metadata *)inst;
                struct ofl_match_standard *m;

                /* NOTE: Hackish solution. If packet had multiple handles, metadata
                 *       should be updated in all. */
                packet_handle_std_validate(pkt->handle_std);
                m = (struct ofl_match_standard *)pkt->handle_std->match;

                m->metadata =
                        (m->metadata & ~wi->metadata_mask) | (wi->metadata & wi->metadata_mask);
                break;
            }
            case OFPIT_WRITE_ACTIONS: {
                struct ofl_instruction_actions *wa = (struct ofl_instruction_actions *)inst;

                /* If no clear action was executed before, check if there is one,
                   and execute it out of order */
                if (!clear_execd) {
                    cinst = get_instruction(entry->stats->instructions_num, entry->stats->instructions, OFPIT_CLEAR_ACTIONS);
                    if (cinst != NULL) {
                        action_set_clear_actions(pkt->action_set);
                        clear_execd = true;
                    }
                    action_set_write_actions(pkt->action_set, wa->actions_num, wa->actions);
                }
                break;
            }
            case OFPIT_APPLY_ACTIONS: {
                struct ofl_instruction_actions *ia = (struct ofl_instruction_actions *)inst;

                dp_execute_action_list(pkt, ia->actions_num, ia->actions);
                break;
            }
            case OFPIT_CLEAR_ACTIONS: {
                /* Only execute clear if it has not been executed out of order */
                if (!clear_execd) {
                    action_set_clear_actions(pkt->action_set);
                    clear_execd = true;
                }
                break;
            }
            case OFPIT_EXPERIMENTER: {
                dp_exp_inst(pkt, (struct ofl_instruction_experimenter *)inst);
                break;
            }
        }
    }
}

/* Executes the instructions associated to the flow table, if no matching flow
 * entry was found. */
static void
execute_table(struct pipeline *pl, struct flow_table *table,
              struct flow_table **next_table, struct packet *pkt) {
    if ((table->stats->config & OFPTC_TABLE_MISS_CONTINUE) != 0) {
        // send to next table, if exists
        if (table->stats->table_id < PIPELINE_TABLES - 1) {
            (*next_table) = pl->tables[table->stats->table_id + 1];
        } else {
            VLOG_WARN_RL(LOG_MODULE, &rl, "Last flow table is set to miss continue.");
        }

    } else if ((table->stats->config & OFPTC_TABLE_MISS_DROP) != 0) {
        VLOG_DBG_RL(LOG_MODULE, &rl, "Table set to drop packet.");

    } else { // OFPTC_TABLE_MISS_CONTROLLER
        struct sw_port *p;

        p = pkt->in_port == OFPP_LOCAL ? pl->dp->local_port
                                     : dp_ports_lookup(pl->dp, pkt->in_port);

        if (p == NULL) {
            VLOG_WARN_RL(LOG_MODULE, &rl, "Packet received on non-existing port (%u).", pkt->in_port);
            return;
        }

        if ((p->conf->config & OFPPC_NO_PACKET_IN) != 0) {
            VLOG_DBG_RL(LOG_MODULE, &rl, "Packet-in disabled on port (%u)", p->stats->port_no);
            return;
        }

        send_packet_to_controller(pl, pkt, table->stats->table_id, OFPR_NO_MATCH);
    }
}
