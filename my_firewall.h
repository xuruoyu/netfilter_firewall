#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/skbuff.h>
#include <linux/net.h>
#include <linux/in.h>
#include <linux/ip.h>

#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>

#include <linux/netdevice.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/string.h>
#include <linux/slab.h>                 //kmalloc>


#include <linux/ioctl.h>
#include <linux/device.h>
#include <linux/types.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <asm/uaccess.h>
#include <asm/errno.h>

#include <linux/socket.h>
#include <net/tcp.h>
#include <net/udp.h>
#include <net/icmp.h>
#include <net/sock.h>

#define MEMDEV_MAJOR 254

#define NF_IP_PRE_ROUTING 0
#define NF_IP_LOCAL_IN 1
#define NF_IP_FORWARD 2
#define NF_IP_LOCAL_OUT 3
#define NF_IP_POST_ROUTING 4

/**
enum nf_ip_hook_priorities {
 NF_IP_PRI_FIRST = INT_MIN,
 NF_IP_PRI_CONNTRACK = -200,  // 连接跟踪
 NF_IP_PRI_MANGLE = -150,     // mangle table
 NF_IP_PRI_NAT_DST = -100,    // DNAT
 NF_IP_PRI_FILTER = 0,        // filter table
 NF_IP_PRI_NAT_SRC = 100,     // SNAT
 NF_IP_PRI_LAST = INT_MAX,
};
**/

#define ADD_IP 0
#define DEL_IP 1
#define ADD_PORT 3
#define DEL_PORT 4

#define MAC_FMT "%02x:%02x:%02x:%02x:%02x:%02x"
#define MAC_ARG(x) ((u8*)(x))[0],((u8*)(x))[1],((u8*)(x))[2],((u8*)(x))[3],((u8*)(x))[4],((u8*)(x))[5]

#define MAX_NR 100
int mem_open(struct inode *inode,struct file *filp);
int mem_release(struct inode *inode,struct file *filp);
long memdev_ioctl(struct file *filp,unsigned int cmd,unsigned long arg);

/*声明五个钩子*/
const char* hooks[] ={ "NF_IP_PRE_ROUTING",
                             "NF_IP_LOCAL_IN",
                             "NF_IP_FORWARD",
                             "NF_IP_LOCAL_OUT",
                             "NF_IP_POST_ROUTING"};

unsigned int packet_filter(unsigned int hooknum,
				struct sk_buff *skb,
				const struct net_device *in,
				const struct net_device *out,
				int (*okfn)(struct sk_buff *));

/*注册转发钩子*/
unsigned int packet_route_pre(unsigned int hooknum,
				struct sk_buff *skb,
				const struct net_device *in,
				const struct net_device *out,
				int (*okfn)(struct sk_buff *));
unsigned int packet_route_post(unsigned int hooknum,
				struct sk_buff *skb,
				const struct net_device *in,
				const struct net_device *out,
				int (*okfn)(struct sk_buff *));

static int check_ip_packet(struct sk_buff *skb);
static int check_port_packet(struct sk_buff *skb);

//sttic char *deny_if = NULL;
static unsigned int *deny_ip = 0;
static unsigned short *deny_port = 0;
static unsigned int *route_ip = 0;
static int flag = -1;

#define MAX_NAT_ENTRIES 65535
#define SET_ENTRY 133
#define RWPERM 0644
#define MY_IP "192.168.57.2"
#define PRIV_IP_FIRST "192.168.58.0"
/* NAT 结构*/
struct nat_entry {
	__be32 lan_ipaddr;
	__be16 lan_port;
//	__be16 nat_port;
	unsigned long sec;	/*timestamp in seconds*/
	u_int8_t valid;
};

/*声明NAT表*/
static struct nat_entry nat_table[MAX_NAT_ENTRIES];


//路由IP
static __be32 myip;
static __be32 priv_ip_mask;
static __be32 priv_ip_first;
static int start = 0;
static int timeout = 60;
static char lanstr[20] = "192.168.58.0/24";
static u_int16_t port = 10000;




static int mem_major = 0;

struct cdev cdev;


static struct nf_hook_ops packet_filter_opt =
{
	.hook = packet_filter,
	.owner = THIS_MODULE,
	.pf = PF_INET,			  /*IPv4 protocol hook*/
	.hooknum = NF_IP_PRE_ROUTING,     /*First stage hook*/
	.priority = NF_IP_PRI_FIRST,      /*Hook to come first*/
};

static struct nf_hook_ops packet_route_pre_opt =
{
	.hook = packet_route_pre,
	.owner = THIS_MODULE,
	.pf = PF_INET,			  /*IPv4 protocol hook*/
	.hooknum = NF_IP_PRE_ROUTING,     /*First stage hook*/
	.priority = NF_IP_PRI_FIRST,      /*Hook to come first*/
};

static struct nf_hook_ops packet_route_post_opt =
{
	.hook = packet_route_post,
	.owner = THIS_MODULE,
	.pf = PF_INET,			  /*IPv4 protocol hook*/
	.hooknum = NF_IP_POST_ROUTING,     /*First stage hook*/
	.priority = NF_IP_PRI_FIRST,      /*Hook to come first*/
};

/*文件操作结构体*/
static const struct file_operations netfilter_fops =
{
	.owner = THIS_MODULE,
	.open = mem_open,
	.release = mem_release,
	.unlocked_ioctl = memdev_ioctl,
};

/*IP转换*/
char * inet_ntoa(int ina)
{
        static char buf[4*sizeof "123"];
        unsigned char *ucp = (unsigned char *)&ina;

         sprintf(buf, "%d.%d.%d.%d",
               ucp[3] & 0xff,
               ucp[2] & 0xff,
               ucp[1] & 0xff,
               ucp[0] & 0xff);
        return buf;
}

/*IP转换*/
char * inet_ntoa_n(int ina)
{
        static char buf[4*sizeof "123"];
        unsigned char *ucp = (unsigned char *)&ina;

         sprintf(buf, "%d.%d.%d.%d",
               ucp[0] & 0xff,
               ucp[1] & 0xff,
               ucp[2] & 0xff,
               ucp[3] & 0xff);
        return buf;
}

/*IP从*.*.*.*转换为数字*/
unsigned long ip_asc_to_int(char *strip) 
{
	unsigned long ip;
        unsigned int a[4];

        sscanf(strip, "%u.%u.%u.%u", &a[0], &a[1], &a[2], &a[3]);
        ip = (a[0] << 24)+(a[1] << 16)+(a[2] << 8)+a[3] ;
	return ip;
}


/*从路由表中查询端口转换*/
__be16 find_nat_entry(__be32 saddr, __be16 sport);

/*重新计算TCP校验和*/
void update_tcp_ip_checksum(struct sk_buff *skb, struct tcphdr *tcph, 
	struct iphdr *iph);
/*重新计算ICMP校验和*/
void update_icmp_ip_checksum(struct sk_buff *skb, struct icmphdr *icmph, 
	struct iphdr *iph);

u16 checksum(u8 *buf, int len);