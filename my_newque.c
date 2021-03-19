
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/rculist.h>
#include <linux/spinlock.h>
#include <linux/preempt.h>
#include<linux/rhashtable.h>
#include<linux/radix-tree.h>
#include<linux/idr.h>

#include <linux/capability.h>
#include <linux/msg.h>
#include <linux/spinlock.h>
#include <linux/init.h>
#include <linux/mm.h>
#include <linux/proc_fs.h>
#include <linux/list.h>
#include <linux/security.h>
#include <linux/sched/wake_q.h>
#include <linux/syscalls.h>
#include <linux/audit.h>
#include <linux/seq_file.h>
#include <linux/rwsem.h>
#include <linux/nsproxy.h>
#include <linux/ipc_namespace.h>
#include <linux/rhashtable.h>

#include <asm/current.h>
#include <linux/uaccess.h>
#include "util.h"
#include "my_newque.h"
#include <linux/rcupdate.h>



static void msg_rcu_free(struct rcu_head *head)
{
	struct kern_ipc_perm *p = container_of(head, struct kern_ipc_perm, rcu);
	struct msg_queue *msq = container_of(p, struct msg_queue, q_perm);
	kvfree(msq);
}


int my_newque(struct ipc_ids *ids, struct ipc_params * params){

	printk("ENTRATO 1 : \n");
	int retval;
	struct msg_queue *msq;

	msq = kvmalloc(sizeof(*msq), GFP_KERNEL);
	if (unlikely(!msq))
		return -ENOMEM;

	msq->q_perm.mode = params->flg;
	msq->q_perm.key = params->key;

	retval = ipc_addid(ids, &msq->q_perm, 5);

	printk("valore funzione 1 : %d %d \n",msq->q_perm.id, params->key);
	if (retval < 0) {
		printk("errore IPC ADDID  \n");
		call_rcu(&msq->q_perm.rcu, msg_rcu_free);
		return retval;
	}
	ipc_unlock_object(&msq->q_perm);
	//ipc_unlock_object(&msq->q_perm);
	rcu_read_unlock();
	return msq->q_perm.id;

}


