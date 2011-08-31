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
#include "compiler.h"
#include "group_table.h"
#include "datapath.h"
#include "dp_actions.h"
#include "hmap.h"
#include "packet.h"
#include "util.h"
#include "openflow/openflow.h"
#include "oflib/ofl.h"
#include "oflib/ofl-messages.h"

#include "vlog.h"
#define LOG_MODULE VLM_group_t

static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(60, 60);

static bool
is_loop_free(struct group_table *table, struct group_entry *mod_entry);


struct group_entry *
group_table_find(struct group_table *table, uint32_t group_id) {
    struct hmap_node *hnode;

    hnode = hmap_first_with_hash(&table->entries, group_id);

    if (hnode == NULL) {
        return NULL;
    }

    return CONTAINER_OF(hnode, struct group_entry, node);
}

/* Handles group mod messages with ADD command. */
static ofl_err
group_table_add(struct group_table *table, struct ofl_msg_group_mod *mod) {

    struct group_entry *entry;

    if (hmap_first_with_hash(&table->entries, mod->group_id) != NULL) {
        return ofl_error(OFPET_GROUP_MOD_FAILED, OFPGMFC_GROUP_EXISTS);
    }

    if (table->entries_num == GROUP_TABLE_MAX_ENTRIES) {
        return ofl_error(OFPET_GROUP_MOD_FAILED, OFPGMFC_OUT_OF_GROUPS);
    }

    if (table->buckets_num + mod->buckets_num > GROUP_TABLE_MAX_BUCKETS) {
        return ofl_error(OFPET_GROUP_MOD_FAILED, OFPGMFC_OUT_OF_BUCKETS);
    }

    entry = group_entry_create(table->dp, table, mod);

    hmap_insert(&table->entries, &entry->node, entry->stats->group_id);

    table->entries_num++;
    table->buckets_num += entry->desc->buckets_num;

    ofl_msg_free_group_mod(mod, false, table->dp->exp);
    return 0;
}

/* Handles group_mod messages with MODIFY command. */
static ofl_err
group_table_modify(struct group_table *table, struct ofl_msg_group_mod *mod) {
    struct group_entry *entry, *new_entry;

    entry = group_table_find(table, mod->group_id);
    if (entry == NULL) {
        return ofl_error(OFPET_GROUP_MOD_FAILED, OFPGMFC_UNKNOWN_GROUP);
    }

    if (table->buckets_num - entry->desc->buckets_num + mod->buckets_num > GROUP_TABLE_MAX_BUCKETS) {
        return ofl_error(OFPET_GROUP_MOD_FAILED, OFPGMFC_OUT_OF_BUCKETS);
    }

    if (!is_loop_free(table, entry)) {
        return ofl_error(OFPET_GROUP_MOD_FAILED, OFPGMFC_LOOP);
    }

    new_entry = group_entry_create(table->dp, table, mod);

    hmap_remove(&table->entries, &entry->node);
    hmap_insert_fast(&table->entries, &new_entry->node, mod->group_id);

    table->buckets_num = table->buckets_num - entry->desc->buckets_num + new_entry->desc->buckets_num;

    /* keep flow references from old group entry */
    list_replace(&new_entry->flow_refs, &entry->flow_refs);
    list_init(&entry->flow_refs);

    group_entry_destroy(entry);

    ofl_msg_free_group_mod(mod, false, table->dp->exp);
    return 0;
}

/* Handles group mod messages with DELETE command. */
static ofl_err
group_table_delete(struct group_table *table, struct ofl_msg_group_mod *mod) {
    if (mod->group_id == OFPG_ALL) {
        struct group_entry *entry, *next;

        HMAP_FOR_EACH_SAFE(entry, next, struct group_entry, node, &table->entries) {
            group_entry_destroy(entry);
        }
        hmap_destroy(&table->entries);
        hmap_init(&table->entries);

        table->entries_num = 0;
        table->buckets_num = 0;

        ofl_msg_free_group_mod(mod, true, table->dp->exp);
        return 0;

    } else {
        struct group_entry *entry, *e;

        entry = group_table_find(table, mod->group_id);

        if (entry != NULL) {

            /* NOTE: The spec. does not define what happens when groups refer to groups
                     which are being deleted. For now deleting such a group is not allowed. */
            HMAP_FOR_EACH(e, struct group_entry, node, &table->entries) {
                if (group_entry_has_out_group(e, entry->stats->group_id)) {
                    return ofl_error(OFPET_GROUP_MOD_FAILED, OFPGMFC_CHAINING_UNSUPPORTED);
                }
            }

            table->entries_num--;
            table->buckets_num -= entry->desc->buckets_num;

            hmap_remove(&table->entries, &entry->node);
            group_entry_destroy(entry);
        }

        /* NOTE: In 1.1 no error should be sent, if delete is for a non-existing group. */

        ofl_msg_free_group_mod(mod, true, table->dp->exp);
        return 0;
    }
}

ofl_err
group_table_handle_group_mod(struct group_table *table, struct ofl_msg_group_mod *mod,
                                                          const struct sender *sender UNUSED) {
    ofl_err error;
    size_t i;

    for (i=0; i< mod->buckets_num; i++) {
        error = dp_actions_validate(table->dp, mod->buckets[i]->actions_num, mod->buckets[i]->actions);
        if (error) {
            return error;
        }
    }

    switch (mod->command) {
        case (OFPGC_ADD): {
            return group_table_add(table, mod);
        }
        case (OFPGC_MODIFY): {
            return group_table_modify(table, mod);
        }
        case (OFPGC_DELETE): {
            return group_table_delete(table, mod);
        }
        default: {
            return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_SUBTYPE);
        }
    }
}

ofl_err
group_table_handle_stats_request_group(struct group_table *table,
                                  struct ofl_msg_stats_request_group *msg,
                                  const struct sender *sender UNUSED) {
    struct group_entry *entry;

    if (msg->group_id == OFPG_ALL) {
        entry = NULL;
    } else {
        entry = group_table_find(table, msg->group_id);

        if (entry == NULL) {
            return ofl_error(OFPET_GROUP_MOD_FAILED, OFPGMFC_UNKNOWN_GROUP);
        }
    }

    {
        struct ofl_msg_stats_reply_group reply =
                {{{.type = OFPT_STATS_REPLY},
                  .type = OFPST_GROUP, .flags = 0x0000},
                 .stats_num = msg->group_id == OFPG_ALL ? table->entries_num : 1,
                 .stats     = xmalloc(sizeof(struct ofl_group_stats *) * (msg->group_id == OFPG_ALL ? table->entries_num : 1))
                };

        if (msg->group_id == OFPG_ALL) {
            struct group_entry *e;
            size_t i = 0;

            HMAP_FOR_EACH(e, struct group_entry, node, &table->entries) {
                 reply.stats[i] = e->stats;
                 i++;
             }

        } else {
            reply.stats[0] = entry->stats;
        }

        dp_send_message(table->dp, (struct ofl_msg_header *)&reply, sender);

        free(reply.stats);
        ofl_msg_free((struct ofl_msg_header *)msg, table->dp->exp);
        return 0;
    }
}

ofl_err
group_table_handle_stats_request_group_desc(struct group_table *table,
                                  struct ofl_msg_stats_request_header *msg UNUSED,
                                  const struct sender *sender) {
    struct group_entry *entry;
    size_t i = 0;

    struct ofl_msg_stats_reply_group_desc reply =
            {{{.type = OFPT_STATS_REPLY},
              .type = OFPST_GROUP_DESC, .flags = 0x0000},
             .stats_num = table->entries_num,
             .stats     = xmalloc(sizeof(struct ofl_group_desc_stats *) * table->entries_num)
            };

    HMAP_FOR_EACH(entry, struct group_entry, node, &table->entries) {
        reply.stats[i] = entry->desc;
        i++;
    }
    dp_send_message(table->dp, (struct ofl_msg_header *)&reply, sender);

    free(reply.stats);
    ofl_msg_free((struct ofl_msg_header *)msg, table->dp->exp);
    return 0;
}

void
group_table_execute(struct group_table *table, struct packet *packet, uint32_t group_id) {
    struct group_entry *entry;

    entry = group_table_find(table, group_id);

    if (entry == NULL) {
        VLOG_WARN_RL(LOG_MODULE, &rl, "Trying to execute non-existing group (%u).", group_id);
        return;
    }

   group_entry_execute(entry, packet);
}

struct group_table *
group_table_create(struct datapath *dp) {
    struct group_table *table;

    table = xmalloc(sizeof(struct group_table));
    table->dp = dp;
    table->entries_num = 0;
    hmap_init(&table->entries);
    table->buckets_num = 0;

    return table;
}

void
group_table_destroy(struct group_table *table) {
    struct group_entry *entry, *next;

    HMAP_FOR_EACH_SAFE(entry, next, struct group_entry, node, &table->entries) {
        group_entry_destroy(entry);
    }

    free(table);
}



static bool
is_loop_free(struct group_table *table, struct group_entry *mod_entry) {
/* Note: called when a modify is called on group. Table is the actual
 *       table, and entry is the modified entry. Returns true if the
 *       table would remain loop free after the modification
 */
    struct group_entry *entry, *e;
    uint32_t *removed;
    size_t removed_num, i;
    bool group_found, leaf_found, removed_found;

    removed = xmalloc(sizeof(uint32_t) * table->entries_num);
    removed_num = 0;

    for (;;) {
        group_found = false;
        leaf_found = false;

        HMAP_FOR_EACH(e, struct group_entry, node, &table->entries) {
            removed_found = false;
            entry = e->stats->group_id == mod_entry->stats->group_id ? mod_entry : e;

            for (i=0; i<removed_num; i++) {
                if (removed[i] == entry->stats->group_id) {
                    removed_found = true;
                    continue;
                }

            }

            if (removed_found) {
                continue;
            }

            group_found = true;
            if (group_entry_is_leaf(entry)) {
                leaf_found = true;
                removed[removed_num] = entry->stats->group_id;
                removed_num++;
                break;
            }
        }

        if (!group_found) {
            free(removed);
            return true;
        }
        if (!leaf_found) {
            free(removed);
            return false;
        }
    }
}
