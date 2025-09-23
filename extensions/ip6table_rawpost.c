/*
 * IPv6 rawpost table
 *
 * Based on ip6table_raw.c
 * Copyright (C) 2003 Jozsef Kadlecsik <kadlec@blackhole.kfki.hu>
 *
 * https://github.com/torvalds/linux/blob/master/net/ipv6/netfilter/ip6table_raw.c
 */
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#include <linux/module.h>
#include <linux/netfilter_ipv6/ip6_tables.h>
#include <linux/slab.h>

static const struct xt_table packet_rawpost = {
	.name = "rawpost",
	.valid_hooks = 1 << NF_INET_POST_ROUTING,
	.me = THIS_MODULE,
	.af = NFPROTO_IPV6,
	.priority = NF_IP6_PRI_LAST,
};

static struct nf_hook_ops *rawposttable_ops __read_mostly;

static int ip6table_rawpost_table_init(struct net *net)
{
	struct ip6t_replace *repl;
	const struct xt_table *table = &packet_rawpost;
	int ret;

	repl = ip6t_alloc_initial_table(table);
	if (repl == NULL)
		return -ENOMEM;
	ret = ip6t_register_table(net, table, repl, rawposttable_ops);
	kfree(repl);
	return ret;
}

static void __net_exit ip6table_rawpost_net_pre_exit(struct net *net)
{
	ip6t_unregister_table_pre_exit(net, "rawpost");
}

static void __net_exit ip6table_rawpost_net_exit(struct net *net)
{
	ip6t_unregister_table_exit(net, "rawpost");
}

static struct pernet_operations ip6table_rawpost_net_ops = {
	.pre_exit = ip6table_rawpost_net_pre_exit,
	.exit = ip6table_rawpost_net_exit,
};

static int __init ip6table_rawpost_init(void)
{
	const struct xt_table *table = &packet_rawpost;
	int ret;

	ret = xt_register_template(table, ip6table_rawpost_table_init);
	if (ret < 0)
		return ret;

	/* Register hooks */
	rawposttable_ops = xt_hook_ops_alloc(table, ip6t_do_table);
	if (IS_ERR(rawposttable_ops)) {
		xt_unregister_template(table);
		return PTR_ERR(rawposttable_ops);
	}

	ret = register_pernet_subsys(&ip6table_rawpost_net_ops);
	if (ret < 0) {
		kfree(rawposttable_ops);
		xt_unregister_template(table);
		return ret;
	}

	return ret;
}

static void __exit ip6table_rawpost_fini(void)
{
	unregister_pernet_subsys(&ip6table_rawpost_net_ops);
	xt_unregister_template(&packet_rawpost);
	kfree(rawposttable_ops);
}

module_init(ip6table_rawpost_init);
module_exit(ip6table_rawpost_fini);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Ip6tables legacy rawpost table");
