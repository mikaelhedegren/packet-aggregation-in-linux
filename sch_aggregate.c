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
 * net/sched/sch_aggregate.c	
 */
#ifndef _KAU_KERNEL_
#define _KAU_KERNEL_
#endif
#include <net/kau_agg.h>
#include <linux/proc_fs.h>

#define TRUE 1
#define FALSE 0
#define KAUPROCSTR "Aggregated packeges: %d\nMetapackets sent: %d\nUnaggregated packets: %d\nAggragated bytes: %d\nAggregated bytes on network:%d\nUnaggregated bytes: %d\nPackages sent due to timeout: %d\nTime: %d\n"

struct aggregation_statistics agg_stat;
struct proc_dir_entry *kau_proc_file; //proc_fs file for statistics	

struct agg_queue
{
	__be32			dest; 		//destination addr (unsigned char :( )
	__u32 			currSize;	//the combined size of all packets in the skb
	__u32 			maxSize;	//maximum size
	psched_time_t		timestamp;	//timestamp 
	struct agg_queue	*next;		//next agg_queue struct (null if nothing)
	struct sk_buff_head 	skb_head;	//begining of the list
};

struct agg_skb_cb {
	psched_time_t		timestamp;
};

void add(struct agg_queue* head,struct agg_queue* newInfo)
{
	struct agg_queue *curr = head;
	if(head == NULL)
		goto Exit;
Next:	
	if(curr->next == NULL)
	{
		curr->next = newInfo;
		goto Exit;
	}
	curr = curr->next;
	goto Next;
Exit:
	return;
}

void addSkb(struct agg_queue* head, struct sk_buff *skb, __be32 *dest)
{
	struct agg_queue *curr = head;
	
	if(head == NULL)
		goto exit;
	if(dest == NULL || &curr->dest == NULL){
		goto exit;
	}
next:
	if(memcmp(dest, &curr->dest, ROUTE_LENGTH) == 0)
	{
		curr->currSize = curr->currSize + skb->len - MAC_LENGTH;
		__skb_queue_tail(&curr->skb_head,skb);
		goto exit;
	}		
	if(curr->next == NULL)
		goto exit;
	curr = curr->next;
	goto next;
exit:
	return;
}

int exist(struct agg_queue *head, __be32 *dest)
{
	struct agg_queue *curr = head;

	if(dest == NULL || &curr->dest == NULL){
		return FALSE;
	}
	
	while(curr != NULL){
		if(memcmp(&curr->dest, dest, ROUTE_LENGTH) == 0)
			return TRUE;
		curr = curr->next;
	}

	return FALSE;
}

int remove(struct agg_queue **head, __be32 *dest)
{
	struct agg_queue *prev = *head;
	struct agg_queue *curr;
		
	if(*head == NULL)//Nothing to remove
		return FALSE; //time to leave

	if(dest == NULL) //Hmm, this shouldn't be!
		return FALSE;

	curr = (*head)->next;
	//Special case : remove the first element
	if(memcmp(&(*head)->dest, dest, ROUTE_LENGTH) == 0)
	{
		skb_queue_purge(&(*head)->skb_head);
		kfree(*head);
		*head = curr;
		return TRUE;		
	}

nextItem:
	if(curr == NULL)
		goto exit; //time to leave
	if(memcmp(&curr->dest,dest, ROUTE_LENGTH) == 0)
	{
		prev->next = curr->next;
		skb_queue_purge(&curr->skb_head);
		kfree(curr);
		return TRUE;	
	}
	prev = curr; //keep the old value
	curr = curr->next;
	goto nextItem;
	
exit:
	return FALSE;
}

void mark_update(struct agg_queue* head)
{
	struct sk_buff *skb;
	skb = skb_peek_tail(&head->skb_head);
	head->maxSize = skb->mark >> 2;
}

struct agg_queue* getDequeue(struct agg_queue* head, unsigned int min_aggregation, unsigned int do_mark_update)
{
	struct agg_queue *curr = head;

	struct agg_queue *old = NULL, *size = head;

	psched_time_t max_timeout = psched_get_time(); //Get current time!

	if(head == NULL)
		goto exit;
nextItem:
	if(curr->timestamp <= max_timeout) //If something is old...
		if(old == NULL || old->timestamp < curr->timestamp) //if it's also older than the current oldest
			old = curr; //it's WAY old
	if(size->currSize < curr->currSize)
		size = curr;	//Make sure we have the largest pkt
	if(curr->next == NULL)
		goto exit;

	curr = curr->next;
	goto nextItem;
exit:	

/*		if old is set something is considered old and we return it,
		else we return size if it is considered large enough, and if	
		nothing passes the criterias, null is returned */

	if (old){
	    agg_stat.aggdelayed++;
        if(do_mark_update) mark_update(old);
        return old;
    }
	else if (size && do_mark_update) mark_update(size);
	return(size->currSize > min_aggregation)? size : NULL;
}

void agg_destroy(struct agg_queue** head)
{
	struct agg_queue *node;
	struct agg_queue *next;
	if(head == NULL)
		goto exit; //Nothing to remove, yeay!

	node = (*head)->next;
	skb_queue_purge(&(*head)->skb_head);
	kfree(*head);
    *head = NULL;
nextNode:
	if(node == NULL)
		goto exit; //done!
	next = node->next;
	skb_queue_purge(&node->skb_head);
	kfree(node);
	node = next;
	goto nextNode;

exit:
	return;
}

struct aggregate_sched_data
{

    unsigned int       	agg_min_size; 
	unsigned int		agg_max_size;
	unsigned int		agg_max_timeout;
	unsigned char       stat;
	struct agg_queue	*agg_queue_hdr;
	
};

static int aggregate_change(struct Qdisc *sch, struct rtattr *opt)
{
   struct aggregate_sched_data *q = qdisc_priv(sch);
   struct tc_simplerr_qopt *ctl;

	if (opt == NULL) {
		q->agg_min_size = AGG_MIN_LENGTH;
		q->agg_max_size = AGG_MAX_LENGTH;
		q->agg_max_timeout = TIME_PAD;
	} else {
		ctl = RTA_DATA(opt);
		if (RTA_PAYLOAD(opt) < sizeof(*ctl))
			return -EINVAL;

		q->agg_max_timeout = ctl->agg_timeout_max ? ctl->agg_timeout_max : TIME_PAD;
		q->agg_max_size = ((ctl->agg_max_size < 100) || (ctl->agg_max_size > 2048)) ? (ctl->agg_max_size == 0 ? 0 : AGG_MAX_LENGTH) : ctl->agg_max_size; 
		q->agg_min_size = ctl->agg_min_size ? ctl->agg_min_size : AGG_MIN_LENGTH;
	}
	return 0;
}

static void agg_stat_init(struct aggregation_statistics *agg)
{
    memset(agg,0,sizeof(struct aggregation_statistics));
    agg->starttime = psched_get_time();
}


static int agg_init(struct Qdisc *sch,struct rtattr *opt)
{
    struct aggregate_sched_data *q = qdisc_priv(sch);
	int ret = 0;
	
    agg_stat_init(&agg_stat);	
	ret = aggregate_change(sch,opt);
    q->agg_queue_hdr = NULL;
    return ret;
}



static int aggregate_enqueue(struct sk_buff *skb, struct Qdisc* sch)
{

    struct aggregate_sched_data *q = qdisc_priv(sch);
    struct agg_skb_cb *cb;
    struct agg_queue *node;	
    if(q->agg_queue_hdr == NULL) //Nothing in the list!
    {				 /* So we need to add the first element, *special case, head is unset* */
		q->agg_queue_hdr = kmalloc(sizeof(struct agg_queue),GFP_ATOMIC);
		if(q->agg_queue_hdr == NULL){
			printk(KERN_INFO" Aggregate Module: Couldn't allocate memory for agg_queue head\n");
			return NET_XMIT_DROP;
		}
		q->agg_queue_hdr->currSize = skb->len - MAC_LENGTH;
		q->agg_queue_hdr->maxSize =  q->agg_max_size ? q->agg_max_size : (skb->mark >> 2);
		cb = (struct agg_skb_cb* )skb->cb;
		cb->timestamp = psched_get_time() + q->agg_max_timeout;	
		q->agg_queue_hdr->timestamp = cb->timestamp;
		q->agg_queue_hdr->next = NULL;
		q->agg_queue_hdr->dest = ((struct rtable*)skb->dst)->rt_gateway;// destination address of next hop
		skb_queue_head_init(&(q->agg_queue_hdr->skb_head)); //Initialize our skblist
		__skb_queue_tail(&q->agg_queue_hdr->skb_head,skb); //add the new skb to our skblist
    }
	else{ /* our head is set*/
		__be32 dest = ((struct rtable*)skb->dst)->rt_gateway; 
		if(exist(q->agg_queue_hdr,&dest) == TRUE) /* We're already tracking this addr */
		{
			cb = (struct agg_skb_cb *)skb->cb;
			cb->timestamp = psched_get_time() + q->agg_max_timeout;		
			addSkb(q->agg_queue_hdr, skb, &dest);
		}
		else{ /* This is a new address, we need to create a agg_queue struct and add it */
			node = kmalloc(sizeof(struct agg_queue),GFP_ATOMIC);
			if(node == NULL){
				printk(KERN_INFO" Aggregate Module: Couldn't allocate memory for agg_queue node\n");
				return NET_XMIT_DROP;
			}
			node->currSize = skb->len - MAC_LENGTH;
			node->maxSize = q->agg_max_size ? q->agg_max_size : (skb->mark >> 2);
			cb = (struct agg_skb_cb *)skb->cb;
			cb->timestamp = psched_get_time() + q->agg_max_timeout;	
			node->timestamp = cb->timestamp;
			node->next = NULL;
			node->dest = ((struct rtable*)skb->dst)->rt_gateway;
			skb_queue_head_init(&(node->skb_head));
			__skb_queue_tail(&node->skb_head,skb); //add the new skb to our skblist
			add(q->agg_queue_hdr,node); //Add it to the end of our agglist
		}  
    }

    return NET_XMIT_SUCCESS;
}

static int procfile_read(char *buffer,
              char **buffer_location,
              off_t offset, int buffer_length, int *eof, void *data)
{
        int ret=0;
          if (offset > 0) {
          /* we have finished to read, return 0 */
          ret = 0;
  } else {
          /* fill the buffer, return the buffer size */
          ret = sprintf(buffer,KAUPROCSTR,agg_stat.aggpackets,agg_stat.metaaggpkt,agg_stat.unaggpkt,agg_stat.aggbytes,agg_stat.aggtotbytes,agg_stat.unaggbytes,agg_stat.aggdelayed,(int)(psched_get_time()-agg_stat.starttime));
         
  }
  return ret;
}


static struct sk_buff *aggregate_dequeue(struct Qdisc *sch)
{
    struct aggregate_sched_data *q = qdisc_priv(sch);
    struct sk_buff *skb, *temp;
    __be32 dest;
    __u16 tot_len = 0;
    int max_size;
    struct agg_queue *node;
	struct iphdr iph; //used as meta header!
	struct iphdr *iphead = NULL; 
	unsigned char *old_tail, *data, *old_mac;
    
    if(q->agg_queue_hdr == NULL)
		return NULL; //queue isn't initialized so there's nothing to dequeue
   
    node = getDequeue(q->agg_queue_hdr, q->agg_min_size, (q->agg_max_size ? 0 : 1));    	
    if(node == NULL){
		return NULL; //getDequeue doesn't feel there's anything to dequeue;
	}

    if(unlikely(skb_queue_len(&node->skb_head) == 1)){
        skb = __skb_dequeue(&node->skb_head);
		if(skb == NULL) 
			return NULL;
	    if(likely(q->stat)){
            agg_stat.unaggpkt++;
            agg_stat.unaggbytes += skb->len;
            }
    }
    else{
        temp = __skb_dequeue(&node->skb_head); 

		if(temp == NULL) //Technically, this shouldn't happen!
			return NULL;

		if(node->currSize + MAC_LENGTH > node->maxSize)
			max_size = node->maxSize;
		else
			max_size = node->currSize + MAC_LENGTH;

		max_size = max_size - sizeof(struct iphdr); //we need room to add our meta header, and that room is a part of max_size		

        skb = skb_copy_expand(temp, skb_headroom(temp) + sizeof(struct iphdr) ,skb_tailroom(temp)+max_size- temp->len,GFP_ATOMIC);
		if(skb == NULL) //unable to allocate more memory
		{
			skb = temp;
	
			/* STATS */
			if(likely(q->stat)){
                agg_stat.unaggpkt++;
                agg_stat.unaggbytes += skb->len;
            }

			goto leave; //leave current scope
		}
		kfree_skb(temp);  //Remove the old skb(temp), we're keeping it in skb now

		/* 	Okay, now we know that atleast two packages are in need of aggregation. So we need to fill up our own 
			header for our new meta packet! */
		iphead = (struct iphdr *) skb_network_header(skb);
		if(iphead == NULL){

			/* STATS */
			if(likely(q->stat)){
                agg_stat.unaggpkt++;
                agg_stat.unaggbytes += skb->len;
            }

			goto leave; //If we can't get the ipheader, we're sending the SKB as-is
		}

		old_mac = skb->data;

		iph.version = iphead->version;
		iph.ihl = 5;
		iph.tos = iphead->tos;
		tot_len = ntohs(iphead->tot_len)+IP_LENGTH;//we want to get the total lenght right for later
		iph.id = iphead->id;
		iph.frag_off = iphead->frag_off;
		iph.ttl = iphead->ttl;
		iph.protocol = PROTOCOL_VALUE;
		iph.check = 0;
		iph.saddr = iphead->saddr; // FIXME Should be host address!
		iph.daddr = ((struct rtable*)skb->dst)->rt_gateway;

		data = skb_push(skb, sizeof(struct iphdr)); //move the datapointer to make room for meta header
		node->currSize = node->currSize + sizeof(struct iphdr); //Make room for ipheader in our currsize

		memcpy(data, old_mac, MAC_LENGTH); //Copy old mac to new position
		data = data + MAC_LENGTH; //Move our pointer past the mac address.

		memcpy(data, &iph, sizeof(struct iphdr)); //Copy our new meta header into position
		
		iphead = (struct iphdr *) data; // Now this is the location of our meta header

		/* STATS */
		if(likely(q->stat)){
			agg_stat.aggtotbytes += skb->len; //skb->len = [macheader][metaheader][org_ip_header][payload]....
            agg_stat.metaaggpkt++; //This counts the number of aggregated packets that are to be sent
		    agg_stat.aggpackets++;  //This counts the number of packets that are to be aggregated
		    agg_stat.aggbytes += (skb->len - MAC_LENGTH - sizeof(struct iphdr)); // sizeof(org_ip_header + payload)
        }
        while(skb->end - skb->tail >= node->skb_head.next->len - MAC_LENGTH){
            temp = __skb_dequeue(&node->skb_head);
			if(temp == NULL)
				goto out; //nothing more to play with! break current scope
			if(skb->tail + temp->len - MAC_LENGTH <= skb->end) //if this exceeds the endpointer, we're trying to go outside our buffer
	            old_tail = skb_put(skb,temp->len - MAC_LENGTH); //This changes the position of skb->tail, to include space of len long, returns old tail position
			else{
				__skb_queue_head(&node->skb_head, temp); //We can't play with this skb, reinsert it to maintain structure
				goto out; //We're leaving since we've apparently filled up our allocated buffer
			}
		/* 	if temp doesn't fit into our old_tail, the function will
			return a fault error, but we've already checked if it will
			it into our buffer before we did skb_put, so we're ignoring
			this possibility */
            skb_copy_bits(temp,MAC_LENGTH,old_tail,temp->len - MAC_LENGTH); 														
			tot_len = tot_len + temp->len - MAC_LENGTH;

            /* STATS */
            if(likely(q->stat)){
                agg_stat.aggpackets++;
                agg_stat.aggbytes += (temp->len - MAC_LENGTH);
                agg_stat.aggtotbytes += (temp->len - MAC_LENGTH);  
            }
            kfree_skb(temp);
           
		}
out:
		iphead->tot_len = htons(tot_len);
		ip_send_check(iphead); 
	}
leave:
    node->currSize = node->currSize - skb->len + MAC_LENGTH;	
    if(node->currSize == 0)
    {
		dest = ((struct rtable*)skb->dst)->rt_gateway;
		remove(&q->agg_queue_hdr, &dest);
	}
	else{
		node->timestamp = ((struct agg_skb_cb *) node->skb_head.next->cb)->timestamp;
	}
    return skb;
}

static int aggregate_requeue(struct sk_buff *skb, struct Qdisc *sch)
{
    return -EINVAL;
}

static unsigned int aggregate_queue_drop(struct Qdisc *sch)
{
	return NET_XMIT_DROP;
}

static void aggregate_reset(struct Qdisc *sch){

 	struct aggregate_sched_data *q = qdisc_priv(sch);
	agg_destroy(&q->agg_queue_hdr);
    agg_stat_init(&agg_stat);
    q->agg_queue_hdr = NULL;

}


static int aggregate_dump(struct Qdisc *sch, struct sk_buff *skb)
{
	return -1;
}

struct Qdisc_ops aggregate_qdisc_ops = {
	.next 		=	NULL,
	.id			=	"aggregate",
	.priv_size	=	sizeof(struct aggregate_sched_data),
	.enqueue	=	aggregate_enqueue,
	.dequeue	=	aggregate_dequeue,
	.requeue	=	aggregate_requeue,
	.drop		=	aggregate_queue_drop,
	.init		=	agg_init,
	.reset		=	aggregate_reset,
	.change		=	aggregate_change,
	.dump		=	aggregate_dump,
	.owner		=	THIS_MODULE,
};


static int __init agg_module_init(void)
{
	/* Initialise stat in /proc filesystem*/
    kau_proc_file = create_proc_entry(KAU_FNAME, 0644, NULL);
    if (kau_proc_file == NULL) {
        remove_proc_entry(KAU_FNAME, &proc_root);
        printk(KERN_ALERT "Error: Could not initialize /proc/%s\n",
            KAU_FNAME);
    }
    else{
        kau_proc_file->read_proc = procfile_read;
        kau_proc_file->owner     = THIS_MODULE;
        kau_proc_file->mode      = S_IFREG | S_IRUGO;
        kau_proc_file->uid       = 0;
        kau_proc_file->gid       = 0;
        kau_proc_file->size      = 512;
        printk(KERN_INFO "/proc/%s created\n", KAU_FNAME);
    }
    
    return register_qdisc(&aggregate_qdisc_ops);
}

static void __exit agg_module_exit(void)
{   
    remove_proc_entry(KAU_FNAME, &proc_root);
	unregister_qdisc(&aggregate_qdisc_ops);
}


module_init(agg_module_init)
module_exit(agg_module_exit)

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Mikael Hedegren and Jonas Brolin");

EXPORT_SYMBOL(aggregate_qdisc_ops);

