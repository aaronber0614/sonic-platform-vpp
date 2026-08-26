// SPDX-License-Identifier: GPL-2.0

#include <linux/module.h>
#include <linux/netlink.h>
#include <linux/skbuff.h>
#include <linux/types.h>
#include <net/genetlink.h>

#define SONIC_STEL_FAMILY_NAME "sonic_stel"
#define SONIC_STEL_FAMILY_VERSION 1
#define SONIC_STEL_IPFIX_VERSION 10
#define SONIC_STEL_IPFIX_HEADER_LEN 16
#define SONIC_STEL_MAX_IPFIX_LEN (U16_MAX - NLA_HDRLEN)

enum sonic_stel_command {
	SONIC_STEL_CMD_UNSPEC,
	SONIC_STEL_CMD_PUBLISH,
	__SONIC_STEL_CMD_MAX,
};

#define SONIC_STEL_CMD_MAX (__SONIC_STEL_CMD_MAX - 1)

enum sonic_stel_attribute {
	SONIC_STEL_ATTR_UNSPEC,
	SONIC_STEL_ATTR_IPFIX,
	__SONIC_STEL_ATTR_MAX,
};

#define SONIC_STEL_ATTR_MAX (__SONIC_STEL_ATTR_MAX - 1)

enum sonic_stel_multicast_group {
	SONIC_STEL_MCGRP_IPFIX,
};

struct sonic_stel_ipfix_header {
	__be16 version;
	__be16 length;
	u8 remainder[SONIC_STEL_IPFIX_HEADER_LEN - 4];
} __packed;

static const struct nla_policy sonic_stel_policy[SONIC_STEL_ATTR_MAX + 1] = {
	[SONIC_STEL_ATTR_IPFIX] = {
		.type = NLA_BINARY,
		.len = SONIC_STEL_MAX_IPFIX_LEN,
	},
};

static const struct genl_multicast_group sonic_stel_groups[] = {
	[SONIC_STEL_MCGRP_IPFIX] = {
		.name = "ipfix",
	},
};

static struct genl_family sonic_stel_family;

static int sonic_stel_publish(struct sk_buff *request, struct genl_info *info)
{
	const struct sonic_stel_ipfix_header *header;
	struct nlattr *attribute;
	struct sk_buff *message;
	void *genl_header;
	u16 encoded_length;
	size_t payload_length;

	attribute = info->attrs[SONIC_STEL_ATTR_IPFIX];
	if (!attribute)
		return -EINVAL;

	payload_length = nla_len(attribute);
	if (payload_length < SONIC_STEL_IPFIX_HEADER_LEN ||
	    payload_length > SONIC_STEL_MAX_IPFIX_LEN)
		return -EMSGSIZE;

	header = nla_data(attribute);
	if (be16_to_cpu(header->version) != SONIC_STEL_IPFIX_VERSION)
		return -EPROTO;

	encoded_length = be16_to_cpu(header->length);
	if (encoded_length != payload_length)
		return -EMSGSIZE;

	message = genlmsg_new(payload_length, GFP_KERNEL);
	if (!message)
		return -ENOMEM;

	genl_header = genlmsg_put(message, 0, 0, &sonic_stel_family, 0,
				  SONIC_STEL_CMD_PUBLISH);
	if (!genl_header) {
		nlmsg_free(message);
		return -EMSGSIZE;
	}

	skb_put_data(message, nla_data(attribute), payload_length);
	genlmsg_end(message, genl_header);

	return genlmsg_multicast(&sonic_stel_family, message, 0,
				 SONIC_STEL_MCGRP_IPFIX, GFP_KERNEL);
}

static const struct genl_ops sonic_stel_ops[] = {
	{
		.cmd = SONIC_STEL_CMD_PUBLISH,
		.flags = GENL_ADMIN_PERM,
		.policy = sonic_stel_policy,
		.doit = sonic_stel_publish,
	},
};

static struct genl_family sonic_stel_family = {
	.name = SONIC_STEL_FAMILY_NAME,
	.version = SONIC_STEL_FAMILY_VERSION,
	.maxattr = SONIC_STEL_ATTR_MAX,
	.module = THIS_MODULE,
	.ops = sonic_stel_ops,
	.n_ops = ARRAY_SIZE(sonic_stel_ops),
	.mcgrps = sonic_stel_groups,
	.n_mcgrps = ARRAY_SIZE(sonic_stel_groups),
};

static int __init sonic_stel_init(void)
{
	return genl_register_family(&sonic_stel_family);
}

static void __exit sonic_stel_exit(void)
{
	genl_unregister_family(&sonic_stel_family);
}

module_init(sonic_stel_init);
module_exit(sonic_stel_exit);

MODULE_DESCRIPTION("SONiC streaming telemetry Generic Netlink provider");
MODULE_AUTHOR("SONiC");
MODULE_LICENSE("GPL");
