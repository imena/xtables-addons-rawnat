/*
 * 'rawpost' table, which is the very last hooked in at POST_ROUTING.
 *
 * Based on iptable_raw.c
 * Copyright (C) 2003 Jozsef Kadlecsik <kadlec@blackhole.kfki.hu>
 *
 * https://github.com/torvalds/linux/blob/master/net/ipv4/netfilter/iptable_raw.c
 * https://github.com/torvalds/linux/blob/master/net/ipv4/netfilter/iptable_nat.c
 */
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#include <linux/module.h>
#include <linux/netfilter_ipv4/ip_tables.h>
#include <linux/slab.h>
#include <net/ip.h>

static const struct xt_table packet_rawpost = {
	.name = "rawpost",                           /* A unique name. Up to 32 chars */
	.valid_hooks = 1 << NF_INET_POST_ROUTING,    /* list of Chains (POSTROUTING) */
	.me = THIS_MODULE,                           /* Set this to THIS_MODULE if you are a module, otherwise NULL */
	.af = NFPROTO_IPV4,                          /* address/protocol family (IPv4) */
	.priority = NF_IP_PRI_LAST,                  /* hook order */
};

/* The work comes in here from netfilter.c. */
static unsigned int iptable_rawpost_hook(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
	return ipt_do_table(skb, state, priv);
}

static struct nf_hook_ops *rawposttable_ops __read_mostly;

static int iptable_rawpost_table_init(struct net *net)
{
	struct ipt_replace *repl;
	const struct xt_table *table = &packet_rawpost;
	int ret;

	repl = ipt_alloc_initial_table(table);
	if (repl == NULL)
		return -ENOMEM;
	ret = ipt_register_table(net, table, repl, rawposttable_ops);
	kfree(repl);
	return ret;
}

static void __net_exit iptable_rawpost_net_pre_exit(struct net *net)
{
	ipt_unregister_table_pre_exit(net, "rawpost");
}

static void __net_exit iptable_rawpost_net_exit(struct net *net)
{
	ipt_unregister_table_exit(net, "rawpost");
}

static struct pernet_operations iptable_rawpost_net_ops = {
	.pre_exit = iptable_rawpost_net_pre_exit,
	.exit = iptable_rawpost_net_exit,
};

static int __init iptable_rawpost_init(void)
{
	int ret;
	const struct xt_table *table = &packet_rawpost;

	ret = xt_register_template(table,
				   iptable_rawpost_table_init);
	if (ret < 0)
		return ret;

	rawposttable_ops = xt_hook_ops_alloc(table, iptable_rawpost_hook);
	if (IS_ERR(rawposttable_ops)) {
		xt_unregister_template(table);
		return PTR_ERR(rawposttable_ops);
	}

	ret = register_pernet_subsys(&iptable_rawpost_net_ops);
	if (ret < 0) {
		xt_unregister_template(table);
		kfree(rawposttable_ops);
		return ret;
	}

	return ret;
}

static void __exit iptable_rawpost_fini(void)
{
	unregister_pernet_subsys(&iptable_rawpost_net_ops);
	kfree(rawposttable_ops);
	xt_unregister_template(&packet_rawpost);
}

module_init(iptable_rawpost_init);
module_exit(iptable_rawpost_fini);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("iptables legacy rawpost table");
