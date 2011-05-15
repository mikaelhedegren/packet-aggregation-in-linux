/*
	Copyright 2008 Jonas Brolin and Mikael Hedegren
    This file is part of Packet Aggregation for Linux.

    Packet Aggregation for Linux is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Packet Aggregation for Linux is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Packet Aggregation for Linux.  If not, see <http://www.gnu.org/licenses/>.
 */
/*
 * net/sched/deaggregate.c	
 */

#ifndef _KAU_KERNEL_
#define _KAU_KERNEL_
#endif

#include <net/kau_agg.h>


struct nf_hook_ops deaggregate;

static unsigned int deaggregation(unsigned int hooknum, struct sk_buff **skb, const struct net_device *in,
									const struct net_device *out, int (*okfn)(struct sk_buff *) )
{
 	unsigned char *pos = (*skb)->data - MAC_LENGTH; // pos points to start of mac header
	struct iphdr *iphead;
	struct iphdr *currentHead;
	struct sk_buff *nskb;

	__be16 remaining;

	pos = pos + MAC_LENGTH; // Move the pointer past the mac header, we're now at ip header
	iphead = (struct iphdr *) pos; // save our header in iphead

	if(iphead->protocol != PROTOCOL_VALUE)
		return NF_ACCEPT; // We don't like this packet, it's not a meta packet

	pos += 20; //pos = start of the first ip header in the meta packet

	remaining = ntohs(iphead->tot_len) - 20; //(remaining = total size of ip packet - size of meta header)
	while(remaining != 0) {
		currentHead = (struct iphdr *) pos; //save the first 'real' header
		if(currentHead == NULL)
			goto fail;
		nskb = dev_alloc_skb(ntohs(currentHead->tot_len) + MAC_LENGTH );
		if(nskb == NULL)
			goto fail; //We can't allocate that memory so we leave
		if(nskb->tail + MAC_LENGTH + ntohs(currentHead->tot_len) <= nskb->end){	

			nskb->data = skb_put(nskb, (MAC_LENGTH + ntohs(currentHead->tot_len))); // allocated all the memory we need
			memcpy(nskb->data,(*skb)->mac_header, MAC_LENGTH); //Put the mac header in place
			nskb->mac_header = nskb->data; //Save the mac header location
			nskb->network_header = nskb->data + MAC_LENGTH; //Move the pointer to where the network header will be
			memcpy(nskb->network_header, pos, ntohs(currentHead->tot_len)); //save the ip + payload
			
			nskb->data = nskb->network_header;
			nskb->transport_header = nskb->network_header + (currentHead->ihl * 4);
		
			//netif_receive_skb will set these, if they're null
			nskb->tstamp.tv64 = 0;
			nskb->dst = NULL;
			nskb->iif = 0;
			nskb->dev = (*skb)->dev;

			/* Specific values that our SKB needs */
			nskb->pkt_type = PACKET_HOST; //pkt_host = 0;
			nskb->protocol = htons(ETH_P_IP); 

			nskb->ip_summed = CHECKSUM_NONE; /* Personal Comment: YEAY! */

			nskb->data_len = 0; //Must be set to 0
			nskb->mac_len = MAC_LENGTH;

			remaining = remaining - ntohs(currentHead->tot_len);
			if(remaining > 0)
				pos = pos + ntohs(currentHead->tot_len); //Move our pointer past this ip packet

			netif_rx(nskb);

		}else {
			printk(KERN_INFO" Deagg: skb size failiure, pkt drop\n");
			kfree_skb(nskb);	
			goto fail;
		}
	}
	kfree_skb(*skb);
    return NF_STOLEN;

fail:
	printk(KERN_INFO" Deaggregate Module: Could not allocate a new SKB, incoming aggregated packet dropped!\n");
	kfree_skb(*skb);
	return NF_DROP;
	
}

static int __init deagg_module_init(void)
{
	deaggregate.hook = deaggregation;
	deaggregate.pf = PF_INET;
	deaggregate.priority = NF_IP_PRI_FIRST;
	deaggregate.hooknum = NF_IP_PRE_ROUTING;
	deaggregate.owner = THIS_MODULE;
	printk(KERN_INFO" Deagg: modeule_loaded\n");
	return nf_register_hook(&deaggregate);
}

static void __exit deagg_module_exit(void)
{
	nf_unregister_hook(&deaggregate);
	printk(KERN_INFO" Deagg: module unloaded\n");
}


module_init(deagg_module_init)
module_exit(deagg_module_exit)

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Mikael Hedegren and Jonas Brolin");

EXPORT_SYMBOL(deaggregate);

