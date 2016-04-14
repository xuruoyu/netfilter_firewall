#include </home/my_firewall/my_firewall.h>

int mem_open(struct inode *inode,struct file *filp)
{
	return 0;
}

int mem_release(struct inode *inode,struct file *filp)
{
    	return 0;
}

long memdev_ioctl(struct file *filp,unsigned int cmd,unsigned long arg)
{
	int ret = 0;
	int ioarg = 0;
	int i;

	printk(KERN_DEBUG "my_firewall:in memdev ioctl\n");

	switch(cmd)
	{
	case 0:
		get_user(ioarg, (int *)arg);
		printk(KERN_DEBUG "my_firewall:ioarg=%x\n",ioarg);
		for(i=0; i<MAX_NR; i++)
		{
			if(*(deny_ip+i) == 0)
			{
				*(deny_ip+i) = ioarg;
				flag = 0;
				printk(KERN_DEBUG "my_firewall:-----------ADD_IP---------%s-----\n",inet_ntoa(htonl(*(deny_ip+i))));
				break;
			}
		}
		break;
	case 1:
		get_user(ioarg, (int *)arg);
		for(i=0; i<MAX_NR; i++)
		{
			if(*(deny_ip+i) == ioarg)
			{
				*(deny_ip+i) = 0;
				flag = 0;
				printk(KERN_DEBUG "my_firewall:-----------DEL_IP----------%s----\n",inet_ntoa(htonl(ioarg)));
				break;
			}
		}
		break;
	case 3:
		get_user(ioarg, (int *)arg);
		for(i=0; i<MAX_NR; i++)
		{
			if(*(deny_port+i) == 0)
			{
				*(deny_port+i) = ioarg;
				flag = 1;
				printk(KERN_DEBUG "my_firewall:---------ADD_PORT--------%d-----\n",*(deny_port+i));
				break;
			}
		}
		break;
	case 4:
		get_user(ioarg,(int *)arg);
		for(i=0; i<MAX_NR; i++)
		{
			if(*(deny_port+i) == ioarg);
			{
				*(deny_port+i) = 0;
				flag = 1;
				printk(KERN_DEBUG"my_firewall:--------DEL_PORT-------%d-----\n", ioarg);
				break;
			}
		}
		break;
	default :
		printk(KERN_DEBUG "my_firewall:--------CMD is error---------\n");
		return -ENOTTY;
	}
	return ret;
}


__be16 find_nat_entry(__be32 saddr, __be16 sport)
{
	int i = 0;
	unsigned int t = 0;
	for(i = 0; i < MAX_NAT_ENTRIES; i++)
	{
		if((nat_table[i].lan_ipaddr == saddr) && (nat_table[i].lan_port == sport) && nat_table[i].valid)
		{
			t = (get_seconds() - nat_table[i].sec);
			if(t > timeout)
			{
				printk("NAT Entry timeout\n");
				nat_table[i].valid = 0;
				return 0;
			}	
			return i;
		}
	}
	return 0;
}

u16 checksum(u8 *buf, int len)
{
	u32 sum = 0;
	u16 *cbuf;

	cbuf = (u16 *)buf;

	while (len > 1){
		sum += *cbuf++;
		len -= 2;
	}

	if(len)
		sum += *(u8 *)cbuf;

	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);

	return -sum;
}

void update_tcp_ip_checksum(struct sk_buff *skb, struct tcphdr *tcph, 
	struct iphdr *iph)
{
		
	int len;
	if (!skb || !iph || !tcph) return ;
	len = skb->len;
	
/*update ip checksum*/
	iph->check = 0;
	iph->check = ip_fast_csum((unsigned char *)iph, iph->ihl);
/*update tcp checksum */
	tcph->check = 0;
	tcph->check = tcp_v4_check(
			len - 4*iph->ihl,
			iph->saddr, iph->daddr,
			csum_partial((char *)tcph, len-4*iph->ihl,
				0));
	return;
	
}

void update_icmp_ip_checksum(struct sk_buff *skb, struct icmphdr *icmph, 
	struct iphdr *iph)
{
		
	int len;
	if (!skb || !iph || !icmph) return ;
	len = skb->len;
	
/*update ip checksum*/
	printk("my_firewall:----iph->check=%x\n",iph->check);
	iph->check = 0;
	iph->check = ip_fast_csum((unsigned char *)iph, iph->ihl);

	printk("my_firewall:----iph->check(new)=%x\n",iph->check);
/*update icmp checksum */
	printk("my_firewall:----icmph->checksum=%x\n",icmph->checksum);
	icmph->checksum = checksum((u8 *)icmph, len);
	printk("my_firewall:----icmph->checksum(new)=%x\n",icmph->checksum);
	// printk("my_firewall:----icmph->checksum=%x\n",icmph->checksum);
	// icmph->check = icmp_v4_check(
	// 		len - 4*iph->ihl,
	// 		iph->saddr, iph->daddr,
	// 		csum_partial((char *)icmph, len-4*iph->ihl,
	// 			0));
	return;
	
}


/*转发hook 函数的实现*/
unsigned int packet_route_pre(unsigned int hooknum,
				struct sk_buff *skb,
				const struct net_device *in,
				const struct net_device *out,
				int (*okfn)(struct sk_buff *)){


	int ret = NF_ACCEPT;
	struct iphdr *iph;
	struct tcphdr *tcph;
	struct udphdr *udph;
	struct icmphdr *icmph;

	__be16 lan_port;

	if(skb == NULL)
	{
		printk("my_firewall:%s\n","*skb is NULL");
		return NF_ACCEPT;
	}
	// printk("my_firewall:packet_route_pre");

	iph = ip_hdr(skb);
	if (!iph) return NF_ACCEPT;

	if (iph->protocol==IPPROTO_TCP)
	{
		// printk("my_firewall:IPPROTO_TCP--------%s->%s\n",inet_ntoa_n(iph->saddr),inet_ntoa(htonl(iph->daddr)));
		if(iph->daddr == myip)
		{
			tcph = (struct tcphdr*)((char *)iph + iph->ihl*4);
			if(!tcph) return NF_ACCEPT;
			if(nat_table[tcph->dest].valid == SET_ENTRY)
			{
				/*lazy checking of stale entries*/
				if((get_seconds() - nat_table[tcph->dest].sec) > timeout)
				{
					/*stale entry which means we do not have a NAT entry for this packet*/
					nat_table[tcph->dest].valid = 0;
					return NF_ACCEPT;
				}
				/*translate ip addr and port*/
				lan_port = nat_table[tcph->dest].lan_port;
				iph->daddr = nat_table[tcph->dest].lan_ipaddr;
				tcph->dest = lan_port;
				//re-calculate checksum
				update_tcp_ip_checksum(skb, tcph, iph);
			}
		}
	}
	if (iph->protocol==IPPROTO_UDP)
	{
		udph = (struct udphdr*)((char *)iph + iph->ihl*4);
		if(!udph) return NF_ACCEPT;
	}
	if (iph->protocol==IPPROTO_ICMP)
	{
		icmph = (struct icmpdr*)((char *)iph + iph->ihl*4);
		if(!icmph) return NF_ACCEPT;
		// iph->saddr = myip;
		// update_icmp_ip_checksum(skb, icmph, iph);
		printk("my_firewall:(pre-)IPPROTO_ICMP--------%s->%s\n",inet_ntoa_n(iph->saddr),inet_ntoa(htonl(iph->daddr)));
	}

	// printk(KERN_DEBUG "my_firewall:route_pre:saddr=%s,daddr=%s\n"\
	// 	,inet_ntoa_n(iph->saddr),inet_ntoa(htonl(iph->daddr)));


	return ret;
}

unsigned int packet_route_post(unsigned int hooknum,
				struct sk_buff *skb,
				const struct net_device *in,
				const struct net_device *out,
				int (*okfn)(struct sk_buff *)){
	int ret = NF_ACCEPT;
	struct iphdr *iph;
	struct tcphdr *tcph;
	struct udphdr *udph;
	struct icmphdr *icmph;

	__be32 oldip, newip;
	__be16  newport;
	int len = 0;

	if(start == 0)
		return NF_ACCEPT;
	if (!skb) return NF_ACCEPT;

	iph = ip_hdr(skb);
	len = skb->len;
	if (!iph) return NF_ACCEPT;

	printk("my_firewall:(post)IPPROTO_ICMP--------%s->%s\n",inet_ntoa_n(iph->saddr),inet_ntoa(htonl(iph->daddr)));
	if (iph->protocol==IPPROTO_TCP)
	{
		oldip = iph->saddr;
		/*Is this packet from given LAN range*/
		if((oldip & priv_ip_mask) == priv_ip_first)
		{
			tcph = (struct tcphdr*)((char *)iph + iph->ihl*4);
			if(!tcph) return NF_ACCEPT;
			newport = find_nat_entry(iph->saddr, tcph->source);
			if(newport)
			{
				/*NAT entry already exists*/
				tcph->source = newport;
			}
			else
			{
				/*Make a new NAT entry choose port numbers > 10000*/
				newport = htons(port++);
				if(port == 0) port = 10000;
				nat_table[newport].valid = SET_ENTRY;
				nat_table[newport].lan_ipaddr = iph->saddr;
				nat_table[newport].lan_port = tcph->source;
				nat_table[newport].sec = get_seconds();
				tcph->source = newport;
				
			}
			iph->saddr = myip;	
			newip = iph->saddr;
			update_tcp_ip_checksum(skb, tcph, iph);	
		}

	}
	if (iph->protocol==IPPROTO_ICMP)
	{
		icmph = (struct icmpdr*)((char *)iph + iph->ihl*4);
		if(!icmph) return NF_ACCEPT;
		printk("my_firewall:(post)IPPROTO_ICMP--------%s->%s\n",inet_ntoa_n(iph->saddr),inet_ntoa(htonl(iph->daddr)));
	}
	return ret;
}

/*hook 函数的实现*/
unsigned int packet_filter(unsigned int hooknum,
				struct sk_buff *skb,
				const struct net_device *in,
				const struct net_device *out,
				int (*okfn)(struct sk_buff *))
				{
	int ret = NF_DROP;
	struct iphdr *iph;
	iph = ip_hdr(skb);

	if(skb == NULL)
	{
		printk("my_firewall:%s\n","*skb is NULL");
		return NF_ACCEPT;
	}

	if(flag == 0)
	{
		ret = check_ip_packet(skb);
		if(ret != NF_ACCEPT)
		{
			return ret;
		}
	}
	else if(flag == 1)
	{
		ret = check_port_packet(skb);
		if(ret != NF_ACCEPT)
			return ret;
	}

	return NF_ACCEPT;

}

/* check ip*/
static int check_ip_packet(struct sk_buff *skb)
{
	int i;
	struct iphdr *iph;
	iph = ip_hdr(skb);

	if(!skb) return NF_ACCEPT;

	if(!ip_hdr(skb)) return NF_ACCEPT;

	for(i=0; i<MAX_NR; i++)
	{
		if(iph->saddr == *(deny_ip+i) && *(deny_ip+i) != 0)
		{
			printk(KERN_DEBUG"my_firewall:------------->%s ip is drop<-------\n",inet_ntoa(htonl(*(deny_ip+i))));
			printk(KERN_DEBUG"my_firewall:------------->%s iph->saddr is drop<-------\n",inet_ntoa(htonl(iph->saddr)));
			printk(KERN_DEBUG"my_firewall:------------->%s iph->daddr is drop<-------\n",inet_ntoa(htonl(iph->daddr)));
			printk(KERN_DEBUG"my_firewall:------------->%s iph->protocol is drop<-------\n",inet_ntoa(htonl(iph->protocol)));
			return NF_DROP;
		}
	}
	return NF_ACCEPT;
}

/* check port*/
static int check_port_packet(struct sk_buff *skb)
{
	int i;
	struct iphdr *iph;
	struct tcphdr *tcph;
	struct udphdr *udph;

	iph = ip_hdr(skb);

	if(!skb) return NF_ACCEPT;

	if(!ip_hdr(skb)) return NF_ACCEPT;

	switch(iph->protocol)
	{
		case IPPROTO_TCP:
			tcph = (struct tcphdr *)(skb->data + (iph->ihl * 4));
			for(i=0; i<MAX_NR; i++)
			{
				if((ntohs(tcph->dest) == *(deny_port+i)) && *(deny_port+i) != 0 )
				{
					printk(KERN_DEBUG "my_firewall:----------->%d tcp port is drop<--------\n",*(deny_port+i));
					printk(KERN_DEBUG "my_firewall:----------->%s tcph->source port is drop<--------\n",inet_ntoa(ntohs(tcph->source)));
					printk(KERN_DEBUG "my_firewall:----------->%s tcph->dest port is drop<--------\n",inet_ntoa(ntohs(tcph->dest)));
					return NF_DROP;
				}
			}
			break;

		case IPPROTO_UDP:
			udph = (struct udphdr *)(skb->data + (iph->ihl * 4));
			for(i=0; i<MAX_NR; i++)
			{
				if((ntohs(udph->dest) == *(deny_port+i)) && *(deny_port+i) != 0)
				{
					printk(KERN_DEBUG "my_firewall:----------->%d udp port is drop<--------\n",*(deny_port+i));
					printk(KERN_DEBUG "my_firewall:----------->%s udph->source port is drop<--------\n",inet_ntoa(ntohs(udph->source)));
					printk(KERN_DEBUG "my_firewall:----------->%s udph->dest port is drop<--------\n",inet_ntoa(ntohs(udph->source)));
					return NF_DROP;
				}
			}
			break;
		default :
		return -ENOTTY;
	}

	return NF_ACCEPT;
}

/*netfilter init module */
static int filter_init(void)
{
	int err;
	int result = 0;
	dev_t devno;

	/*Regiser the control device, /dev/netfilter */
	if(mem_major)
	{
		result = register_chrdev_region(devno,1,"my_filter");
	}
	else
	{
		result = alloc_chrdev_region(&devno,0,1,"my_filter");
		mem_major = MAJOR(devno);
	}

	if(result < 0)
		return result;

	//初始化cdev结构，并传递file_operations结构指针。
	devno = MKDEV(mem_major, 0);
	printk(KERN_DEBUG"my_firewall:major=%d\n", MAJOR(devno));
	printk(KERN_DEBUG"my_firewall:-----major is %d-----------\n", MAJOR(devno));
	printk(KERN_DEBUG"my_firewall:-----minor is %d-----------\n", MINOR(devno));
	cdev_init(&cdev, &netfilter_fops);
	cdev.owner = THIS_MODULE;
	cdev.ops = &netfilter_fops;

	//注册字符设备。
	err = cdev_add(&cdev, MKDEV(mem_major, 0), 1);
	if(err != 0)
	{
		printk(KERN_DEBUG"--------cdev_add error--------\n");
	}

	printk(KERN_DEBUG"my_firewall: Control device successfully registered.\n");

	priv_ip_first = htonl(ip_asc_to_int(PRIV_IP_FIRST));
	myip = htonl(ip_asc_to_int(MY_IP));

	/*Register the network hooks*/
	nf_register_hook(&packet_filter_opt);
	nf_register_hook(&packet_route_pre_opt);
	nf_register_hook(&packet_route_post_opt);
	//nf_register_hooks(packet_filter_opt, ARRAY_SIZE(packet_filter_opt)); // register hook
	printk(KERN_DEBUG"my_firewall: Network hooks successfully installed.\n");

	deny_ip = (unsigned int*)kmalloc(sizeof(unsigned int)*MAX_NR, GFP_KERNEL);
	deny_port = (unsigned short*)kmalloc(sizeof(unsigned short)*MAX_NR, GFP_KERNEL);

	if((deny_ip == NULL) || (deny_port == NULL))
	{
		return -ENOMEM;
		goto fail_malloc;
	}
	memset(deny_ip, 0, sizeof(unsigned int)*MAX_NR);
	memset(deny_port, 0, sizeof(unsigned short)*MAX_NR);

	fail_malloc:
		unregister_chrdev_region(MKDEV(mem_major,0),2);

	printk(KERN_DEBUG"my_firewall: Module installation successful.\n");

	return 0;

}

/*netfilter exit module*/
static void filter_exit(void)
{
	/* Remove IPV4 hook */
	//nf_unregister_hooks(packet_filter_opt, ARRAY_SIZE(packet_filter_opt)); // unregister hook
	nf_unregister_hook(&packet_filter_opt);
	nf_unregister_hook(&packet_route_pre_opt);
	nf_unregister_hook(&packet_route_post_opt);
	//注销设备
	cdev_del(&cdev);
	unregister_chrdev_region(MKDEV(mem_major,0),2);

	//释放设备结构体内存
	kfree(deny_ip);
	kfree(deny_port);

	printk(KERN_DEBUG"my_firewall:Remove of Module from Kernel successful!.\n");
}

MODULE_LICENSE("GPL");
module_init(filter_init); // insmod module
module_exit(filter_exit); // rmmod module
