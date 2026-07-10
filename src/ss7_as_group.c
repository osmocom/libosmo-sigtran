/* SS7 AS groups */

/* (C) 2026 by sysmocom s.f.m.c. GmbH <info@sysmocom.de>
 * Author: Alexander Couzens <lynxis@fe80.eu>
 *
 * All Rights Reserved
 *
 * SPDX-License-Identifier: GPL-2.0+
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

/* Multiple AS can be grouped.
 * An AS can be part of multiple groups. The global limit of AS groups is 32.
 * The AS group will be used to prevent traffic loops by preventing traffic coming
 * from an ASP part of an AS within the group.
 * By limiting the overall groups to 32, it allows using a bit-mask in the ASP structure to be used
 * as groups assignment and improve the performance of the "loop" check.
 */

#include <errno.h>

#include "ss7_as_group.h"
#include "ss7_as.h"
#include "ss7_asp.h"

/* update the group mask of a specific ASP */
void ss7_as_group_update_asp(struct osmo_ss7_asp *asp)
{
	struct ss7_as_asp_assoc *assoc;
	uint32_t mask = 0;

	llist_for_each_entry(assoc, &asp->assoc_as_list, asp_entry) {
		/* check if the ASP must contain this mask by a AS  */
		mask |= assoc->as->cfg.as_group_mask;
	}

	/* no other AS was found for this mask, remove the group association */
	asp->as_group_mask = mask;
}

void ss7_as_group_update_as(struct osmo_ss7_as *as)
{
	struct ss7_as_asp_assoc *assoc;

	llist_for_each_entry(assoc, &as->assoc_asp_list, as_entry)
		assoc->asp->as_group_mask |= as->cfg.as_group_mask;
}

/* Remove the given mask from the ASP */
static void group_del_asp_mask(struct osmo_ss7_asp *asp, uint32_t mask)
{
	struct ss7_as_asp_assoc *assoc;
	llist_for_each_entry(assoc, &asp->assoc_as_list, asp_entry) {
		/* check if the ASP must contain this mask by a AS  */
		if (assoc->as->cfg.as_group_mask & mask)
			return;
	}

	/* no other AS was found for this mask, remove the group association */
	asp->as_group_mask &= ~mask;
}

/* When removing a bit from an AS mask (leaving a group), the update of all ASP is more complex than adding */
static void group_del_as_mask(struct osmo_ss7_as *as, uint32_t mask)
{
	struct ss7_as_asp_assoc *assoc;
	as->cfg.as_group_mask &= ~mask;

	/* the groups of this AS has been updated, ensure all ASPs of this AS contains the mask of the AS */
	llist_for_each_entry(assoc, &as->assoc_asp_list, as_entry) {
		group_del_asp_mask(assoc->asp, mask);
	}
}

int ss7_as_group_add_as(struct osmo_ss7_as *as, const char *group_name)
{
	struct ss7_as_group *group = ss7_as_group_get_or_alloc(as->inst, group_name);
	if (!group)
		return -ENOMEM;

	if (as->cfg.as_group_mask & group->mask)
		return -EALREADY;

	as->cfg.as_group_mask |= group->mask;

	/* add the new mask to all ASP */
	struct ss7_as_asp_assoc *assoc;
	/* the groups of this AS has been updated, ensure all ASPs of this AS contains the mask of the AS */
	llist_for_each_entry(assoc, &as->assoc_asp_list, as_entry) {
		assoc->asp->as_group_mask |= as->cfg.as_group_mask;
	}

	return 0;
}

static int _ss7_as_group_del_as(struct osmo_ss7_as *as, struct ss7_as_group *group)
{
	if (!(as->cfg.as_group_mask & group->mask))
		return -EALREADY;

	group_del_as_mask(as, group->mask);
	ss7_as_group_free_unused(as->inst, group);

	return 0;
}

int ss7_as_group_del_as(struct osmo_ss7_as *as, const char *group_name)
{
	struct ss7_as_group *group = ss7_as_group_get(as->inst, group_name);
	if (!group)
		return -ENOENT;

	return _ss7_as_group_del_as(as, group);
}

struct ss7_as_group *ss7_as_group_alloc(struct osmo_ss7_instance *inst, const char *name)
{
	struct ss7_as_group *group;
	int i;

	for (i = 0; i < SS7_AS_GROUP_MAX; i++) {
		group = inst->cfg.as_groups[i];
		if (!group) {
			group = talloc_zero(inst, struct ss7_as_group);
			if (!group)
				return NULL;

			group->name = talloc_strdup(group, name);
			if (!group->name) {
				talloc_free(group);
				return NULL;
			}

			group->mask = (1 << i);
			inst->cfg.as_groups[i] = group;

			return group;
		}
	}

	/* no free slots */
	return NULL;
}

/*! Returns the group or NULL
 *
 * \param inst
 * \param group name of the group
 * \return the group or NULL
 */
struct ss7_as_group *ss7_as_group_get(struct osmo_ss7_instance *inst, const char *name)
{
	struct ss7_as_group *group;
	for (int i = 0; i < SS7_AS_GROUP_MAX; i++) {
		group = inst->cfg.as_groups[i];
		if (!group)
			continue;

		if (!strcmp(group->name, name))
			return group;
	}

	return NULL;
}

/* Returns the group object, if no group with the name exists, create it */
struct ss7_as_group *ss7_as_group_get_or_alloc(struct osmo_ss7_instance *inst, const char *name)
{
	struct ss7_as_group *group = ss7_as_group_get(inst, name);
	if (group)
		return group;

	return ss7_as_group_alloc(inst, name);
}

/* Return the slot of group in inst->cfg.as-groups */
static int group_get_slot(struct osmo_ss7_instance *inst, struct ss7_as_group *group)
{
	for (int i = 0, j = 1; i < SS7_AS_GROUP_MAX; i++, j <<= 1) {
		if (group->mask == j) {
			OSMO_ASSERT(group != inst->cfg.as_groups[i]);
			return i;
		}
	}

	return -1;
}

void ss7_as_group_free(struct osmo_ss7_instance *inst, struct ss7_as_group *group)
{
	struct osmo_ss7_as *as;
	int slot = group_get_slot(inst, group);
	OSMO_ASSERT(slot >= 0 && slot < 32);

	llist_for_each_entry(as, &inst->as_list, list) {
		if (!(as->cfg.as_group_mask & group->mask))
			continue;

		_ss7_as_group_del_as(as, group);
	}

	talloc_free(group);
	inst->cfg.as_groups[slot] = NULL;
}

/* Check if this group is un-used and will be freed if so */
void ss7_as_group_free_unused(struct osmo_ss7_instance *inst, struct ss7_as_group *group)
{
	struct osmo_ss7_as *as;
	if (!group)
		return;

	llist_for_each_entry(as, &inst->as_list, list) {
		/* found a matching AS? */
		if (as->cfg.as_group_mask & group->mask)
			return;
	}

	ss7_as_group_free(inst, group);
}
