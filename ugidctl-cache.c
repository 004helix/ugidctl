/*
 * This file is released under the GPL.
 */

#include <linux/types.h>
#include <linux/rbtree.h>
#include <linux/slab.h>
#include <linux/pid.h>

#include "ugidctl.h"

int ugidctl_add_uid(struct ugidctl_context *ctx, uid_t uid)
{
	struct ugidctl_uid_node *node, *this;
	struct rb_node **new, *parent = NULL;

	if (ctx->uids_total >= UGIDCTL_UIDSMAX)
		return -ENOSPC;

	node = kmem_cache_alloc(uid_cache, GFP_KERNEL);
	if (!node)
		return -ENOMEM;

	node->uid = uid;

	new = &ctx->uids.rb_node;
	while (*new) {
		parent = *new;
		this = rb_entry(parent, struct ugidctl_uid_node, node);

		if (uid < this->uid) {
			new = &((*new)->rb_left);
		} else if (uid > this->uid) {
			new = &((*new)->rb_right);
		} else {
			kmem_cache_free(uid_cache, node);
			return 0;
		}
	}

	rb_link_node(&node->node, parent, new);
	rb_insert_color(&node->node, &ctx->uids);

	ctx->uids_total++;

	return 0;
}

int ugidctl_add_gid(struct ugidctl_context *ctx, gid_t gid)
{
	struct ugidctl_gid_node *node, *this;
	struct rb_node **new, *parent = NULL;

	if (ctx->gids_total >= UGIDCTL_GIDSMAX)
		return -ENOSPC;

	node = kmem_cache_alloc(gid_cache, GFP_KERNEL);
	if (!node)
		return -ENOMEM;

	node->gid = gid;

	new = &ctx->gids.rb_node;
	while (*new) {
		parent = *new;
		this = rb_entry(parent, struct ugidctl_gid_node, node);

		if (gid < this->gid) {
			new = &((*new)->rb_left);
		} else if (gid > this->gid) {
			new = &((*new)->rb_right);
		} else {
			kmem_cache_free(gid_cache, node);
			return 0;
		}
	}

	rb_link_node(&node->node, parent, new);
	rb_insert_color(&node->node, &ctx->gids);

	ctx->gids_total++;

	return 0;
}

int ugidctl_find_uid(struct ugidctl_context *ctx, uid_t uid)
{
	struct ugidctl_uid_node *uidnode;
	struct rb_node *rbnode;

	rbnode = ctx->uids.rb_node;
	while (rbnode) {
		uidnode = rb_entry(rbnode, struct ugidctl_uid_node, node);

		if (uid < uidnode->uid) {
			rbnode = rbnode->rb_left;
		} else if (uid > uidnode->uid) {
			rbnode = rbnode->rb_right;
		} else {
			return 0;
		}
	}

	return -ENOENT;
}

int ugidctl_find_gid(struct ugidctl_context *ctx, gid_t gid)
{
	struct ugidctl_gid_node *gidnode;
	struct rb_node *rbnode;

	rbnode = ctx->gids.rb_node;
	while (rbnode) {
		gidnode = rb_entry(rbnode, struct ugidctl_gid_node, node);

		if (gid < gidnode->gid) {
			rbnode = rbnode->rb_left;
		} else if (gid > gidnode->gid) {
			rbnode = rbnode->rb_right;
		} else {
			return 0;
		}
	}

	return -ENOENT;
}

void ugidctl_flush_uids(struct ugidctl_context *ctx)
{
	struct ugidctl_uid_node *node;
	struct rb_node *next;

	next = rb_first(&ctx->uids);
	while (next) {
		node = rb_entry(next, struct ugidctl_uid_node, node);
		next = rb_next(&node->node);
		rb_erase(&node->node, &ctx->uids);
		kmem_cache_free(uid_cache, node);
	}

	ctx->uids = RB_ROOT;
	ctx->uids_total = 0;
	return;
}

void ugidctl_flush_gids(struct ugidctl_context *ctx)
{
	struct ugidctl_gid_node *node;
	struct rb_node *next;

	next = rb_first(&ctx->gids);
	while (next) {
		node = rb_entry(next, struct ugidctl_gid_node, node);
		next = rb_next(&node->node);
		rb_erase(&node->node, &ctx->gids);
		kmem_cache_free(gid_cache, node);
	}

	ctx->gids = RB_ROOT;
	ctx->gids_total = 0;
	return;
}
