
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
#include "../util/util.h"
#include "../include/my_newque.h"
#include <linux/rcupdate.h>



static void msg_rcu_free(struct rcu_head *head)
{
	struct kern_ipc_perm *p = container_of(head, struct kern_ipc_perm, rcu);
	struct msg_queue *msq = container_of(p, struct msg_queue, q_perm);
	kvfree(msq);
}

elem* alloc_and_fill_tag_service(void) {
    int i;
    elem *new = kmalloc(sizeof(struct _tag_elem), GFP_KERNEL);
    new->level = (level *) kmalloc(32 * sizeof(struct _tag_level), GFP_KERNEL);

    //inizializzo le 32 wait queue
    printk(" prima aver inizializzato awake:\n" );

    spin_lock_init(&new->tag_lock);
    for (i = 0; i < 32; i++) {
        new->level[i].group = kmalloc(sizeof(struct _tag_level_group), GFP_KERNEL);
        spin_lock_init(&new->level[i].queue_lock);
        spin_lock_init(&new->level[i].group->lock_presence_counter);

        new->level[i].group->awake = 1;
        init_waitqueue_head(&new->level[i].my_queue);

    }
    printk(" dpo aver inizializzato awake: %d \n", new->level[3].group->awake);
    return new;
}

int my_newque(struct ipc_params * params){

	printk("ENTRATO 1 : \n");
	int retval;
	elem *msq;

	//msq = kvmalloc(sizeof(*msq), GFP_KERNEL);
    msq= alloc_and_fill_tag_service();
	if (unlikely(!msq))
		return -ENOMEM;

	msq->q_perm.mode = params->flg;
	msq->q_perm.key = params->key;

	retval = ipc_addid( &msq->q_perm, 5);

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


