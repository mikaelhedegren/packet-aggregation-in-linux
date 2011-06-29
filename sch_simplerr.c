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
/* *VERY* light implementation of a Round Robin Queue dicipline
We really only want it to work in a very specific scenario, and we're very short on time, so this is 
probably not usefull to anyone but us.

It will insert incoming skb messages to either a fifo queue or our own aggregation queue, depending on the
value of skb->mark.

This scheduler will alternate between dequeuing the fifo or aggregation queue.

-Mikael
*/

#ifndef _KAU_KERNEL_
#define _KAU_KERNEL_
#endif
#include <net/kau_agg.h>
#include <net/sch_generic.h>

//extern int qdisc_change(struct Qdisc *sch, struct rtattr **tca);

/****************************************************************************************************/
/*
	Our Qdisc
 */

struct rr_sched_data {
	struct Qdisc 	*qFifo; //fifo
	struct Qdisc 	*qAgg;  //Aggregation

	int 		turn;  //switch q->turns
};

static int rr_init(struct Qdisc *sch, struct rtattr *opt)
{
	struct rr_sched_data *q = qdisc_priv(sch);
   struct tc_simplerr_qopt *ctl;

	int ret = 0;	

	if(!opt)
		return -EINVAL;

	ctl = RTA_DATA(opt);
	
	printk(KERN_INFO"opt: timout : %d max size : %d min size : %d\n", ctl->agg_timeout_max, ctl->agg_max_size, ctl->agg_min_size);

	
	q->turn  = 0;

	q->qFifo = qdisc_create_dflt(sch->dev,&pfifo_qdisc_ops, 
				     TC_H_MAKE(sch->handle, 1));

	q->qAgg =  qdisc_create_dflt(sch->dev, &aggregate_qdisc_ops,
				     TC_H_MAKE(sch->handle, 2));

	if(!q->qFifo || !q->qAgg)
	{
		return -ENOMEM;
	}
	ret = q->qAgg->ops->change(q->qAgg,opt);

	return ret;
}

static void rr_reset(struct Qdisc *sch)
{
	struct rr_sched_data *q = qdisc_priv(sch);
	q->turn = 0;
}

static int rr_enqueue(struct sk_buff *skb, struct Qdisc *sch)
{
	struct rr_sched_data *q = qdisc_priv(sch);
	int len = skb->len;
	int ret;
	unsigned int aggMark = 0;
	aggMark = ((unsigned int) skb ->mark & MARK_MASK);

	if(aggMark == MARK_MASK){

		ret = q->qAgg->enqueue(skb, q->qAgg);
	}
	else{

		ret = q->qFifo->enqueue(skb,q->qFifo);
	}
	if(ret == NET_XMIT_SUCCESS){
		sch->q.qlen++;
		sch->qstats.backlog += len;
		sch->bstats.packets++;
		sch->bstats.bytes+=len;
		return ret;
	}

	sch->qstats.drops++;
	return ret;
}

static struct sk_buff *rr_dequeue(struct Qdisc *sch)
{
	struct rr_sched_data *q = qdisc_priv(sch);
	struct sk_buff *skb;
	int agg_backlog = 0;
	int agg_qlen = 0;

	if(q->turn == 0){
		q->turn = 1;

		skb = q->qFifo->dequeue(q->qFifo);
		if(skb == NULL){
			agg_backlog = q->qAgg->qstats.backlog;
			agg_qlen = q->qAgg->q.qlen;
			skb = q->qAgg->dequeue(q->qAgg);				
			if(skb){
				sch->qstats.backlog = sch->qstats.backlog - (agg_backlog - q->qAgg->qstats.backlog);					
				sch->q.qlen = sch->q.qlen - (agg_qlen - q->qAgg->q.qlen);			
			}
		}
		else{
			sch->qstats.backlog -= skb->len;		
			sch->q.qlen--;
		}
	}
	else{
		q->turn = 0;
		agg_backlog = q->qAgg->qstats.backlog;
		agg_qlen = q->qAgg->q.qlen;
		skb = q->qAgg->dequeue(q->qAgg);
		if(skb == NULL){
			skb = q->qFifo->dequeue(q->qFifo);
			if(skb){
				sch->qstats.backlog -= skb->len;
				sch->q.qlen--; //YES!
			}
		}
		else{
			sch->q.qlen = sch->q.qlen - (agg_qlen - q->qAgg->q.qlen);			
			sch->qstats.backlog = sch->qstats.backlog - (agg_backlog - q->qAgg->qstats.backlog);					
		}
	}

	return skb;
}

static int rr_requeue(struct sk_buff *skb, struct Qdisc *sch)
{
	struct rr_sched_data *q = qdisc_priv(sch);
	int ret = -1;
	
	ret = q->qFifo->enqueue(skb,q->qFifo); /*If we get it back, it's either already been
						 aggregated, or it is not supposed to be aggregated
						 so we let the fifo queue handle it from here */
	
	if(ret == 0){
		//sch->q.qlen++;
		sch->qstats.requeues++;
		return ret;
	}

	//sch->q.qlen++;
	sch->qstats.drops++;
	return ret;
}	

static void rr_destroy(struct Qdisc *sch)
{
	struct rr_sched_data *q = qdisc_priv(sch);
	q->turn = 0;
}

static unsigned int rr_drop(struct Qdisc *sch)
{
	//Very unsure what this is expected to do, drop from all queues or from a specific one?
	// Right now, it just drops from one, assuming this works at all.
/*	struct rr_sched_data *q = qdisc_priv(sch);
	int len;
	if(q->qFifo->ops->drop && (len = q->qFifo->ops->drop(q->qFifo)) != 0){
		sch->q.qlen--;
		sch->qstats.drops++;
	}
	return len;*/
	return 0;
}

/*
	Regarding the coming functions:
	everything between "" tells us what the function is supposed to do

	every other comment tells us what it does
	(in most cases nothing)
*/

/*
"returns output configuration parameters and statistics of a
queueing discipline."

- We don't care, so this does nothing
*/
static int rr_dump(struct Qdisc *sch, struct sk_buff *skb)
{
	return -1;
}

/* AKA change
"Changes the parameters of a queuing discipline"

-We only allow the aggregation queue to be changed.
*/
static int rr_tune(struct Qdisc *sch, struct rtattr *opt)
{
	struct rr_sched_data *q = qdisc_priv(sch);
	int ret = 0;
//	ret = qdisc_change(q->qAgg, &opt);
	ret = q->qAgg->ops->change(q->qAgg,opt);
	return ret;
}

/* Replace a class with another 
"binds a queueing discipline to a class"

- We have already bound our classes and we just want those
*/
static int rr_graft(struct Qdisc *sch, unsigned long arg, struct Qdisc *new,
		     struct Qdisc **old)
{
	return 0;
}

/* returns the qdisc for a class 
"returns a pointer to the queueing discipline currently bound to the class"

- We are the queueing discipline?
*/
static struct Qdisc *rr_leaf(struct Qdisc *sch, unsigned long arg)
{
	return NULL;
}

/*
"maps the classid to the internal identification and increments the reference
counter by one."

- We only have queue 0(fifo) and 1(aggregation), and we're not letting anyone change this
  so we return a strange value;
*/
static unsigned long rr_get(struct Qdisc *sch, u32 classid)
{
	return -1;
}

/*
 "decrements the usage counter."

- does nothing
*/
static void rr_put(struct Qdisc *q, unsigned long cl)
{
	
}

/*
 "checks if the class is not referenced; and if not, deletes the class"

 -We don't want to remove any of our two queues, so we wont
*/
static int rr_delete(struct Qdisc *sch, unsigned long cl)
{
	return 0;
}

/*
 "gives configuration and statistics data of a class."

 - We don't want to let this be configurable, and currently 
   we don't care about statistics, so we don't see a use 
   of the function. This will probably change though...
*/
static int rr_dump_class(struct Qdisc *sch, unsigned long cl,
			  struct sk_buff *skb, struct tcmsg *tcm)
{
	return -1;
}

/* 
	"changes the class parameters"

	- We don't want them changed.
*/
static int rr_change(struct Qdisc *sch, u32 handle, u32 parent,
		      struct rtattr **tca, unsigned long *arg)
{
	return -EINVAL;
}
/*
"walks through the linked list of the all the classes of a queueing discipline and
invokes the associated callback functions to obtain configuration/statistics data."

-We should probably make this work ...
*/
static void rr_walk(struct Qdisc *sch, struct qdisc_walker *arg)
{
	return;
}

/*
 "returns a pointer to the linked list for the filter bound to the class."

  - we have no filter class
*/
static struct tcf_proto **rr_find_tcf(struct Qdisc *sch, unsigned long cl)
{
	return NULL;
}

/*
 "binds a filter to a class"
 -we don't want a filter class
*/
static unsigned long rr_bind(struct Qdisc *sch,
			      unsigned long parent, u32 classid)
{
	return 0;
}

/*
 * General
 */

static struct Qdisc_class_ops rr_class_ops = {
	.graft = rr_graft,
	.leaf = rr_leaf,
	.get = rr_get,
	.put = rr_put,
	.change = rr_change,
	.delete = rr_delete,
	.walk = rr_walk,
	.tcf_chain = rr_find_tcf,
	.bind_tcf = rr_bind,
	.unbind_tcf = rr_put,
	.dump = rr_dump_class,
};

static struct Qdisc_ops rr_qdisc_ops = {
	.next = NULL,
	.cl_ops = &rr_class_ops,
	.id = "simplerr",
	.priv_size = sizeof(struct rr_sched_data),
	.enqueue = rr_enqueue,
	.dequeue = rr_dequeue,
	.requeue = rr_requeue,
	.drop = rr_drop,
	.init = rr_init,
	.reset = rr_reset,
	.destroy = rr_destroy,
	.change = rr_tune,
	.dump = rr_dump,
	.owner = THIS_MODULE,
};

static int __init rr_module_init(void)
{
	return register_qdisc(&rr_qdisc_ops);
}

static void __exit rr_module_exit(void)
{
	unregister_qdisc(&rr_qdisc_ops);
}

module_init(rr_module_init)
module_exit(rr_module_exit)

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Mikael Hedegren And Jonas Brolin");

EXPORT_SYMBOL(rr_qdisc_ops);
