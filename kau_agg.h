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
#ifndef _KAU_AGG_
#define _KAU_AGG_

#ifdef _KAU_KERNEL_

#include <linux/module.h>
#include <linux/bitops.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/skbuff.h>
#include <net/pkt_sched.h>
#include <linux/ktime.h>
#include <net/route.h>
#include <net/ip.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <asm/byteorder.h>
#include <linux/if_packet.h>
#include <linux/netdevice.h>
#include <linux/netpoll.h>
#include <linux/rtnetlink.h>
#include <linux/if_arp.h>

#endif

#define MARK 6003
#define RR_VER "20080122"
#define AGG_MAX_LENGTH 1500
#define TIME_PAD 50
#define ROUTE_LENGTH 4
#define AGG_MIN_LENGTH 200
#define PROTOCOL_VALUE 254
#define MAC_LENGTH 14
#define IP_LENGTH 20
#define KAU_FNAME "Kau_Stat"

extern struct Qdisc_ops aggregate_qdisc_ops;

struct tc_simplerr_qopt{
	unsigned int agg_timeout_max; 	//how long before a packet is 'considered old'
	unsigned int agg_min_size;		//minimum size before we consider to aggregate	
	unsigned int agg_max_size;		//maximum size allowed for the new aggregated value. 
							//Set to 0 to allow marking. Set to 1 to use default AGG_MAX (check KAU_AGG.h).
};

struct agg_mark{
    unsigned short aggmark;
    unsigned short aggsize;
};

#ifdef _KAU_KERNEL_
struct aggregation_statistics{
    __u32            aggpackets; //total aggregated packets.
    __u32            metaaggpkt; //total aggregation packets sent over network.
    __u32            unaggpkt;   //total unaggrgated packets.
    __u32            aggbytes;   //total aggregated bytes.
    __u32            aggtotbytes;//-"- as seen on network.
    __u32            unaggbytes; //total unaggregated bytes. 
    __u16            aggdelayed; //how often packets are delayed. (deaqueued from old)
    psched_time_t   starttime;  //to keep track of print times.  
};
#endif

#endif
