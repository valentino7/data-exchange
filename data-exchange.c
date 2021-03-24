/*
* 
* This is free software; you can redistribute it and/or modify it under the
* terms of the GNU General Public License as published by the Free Software
* Foundation; either version 3 of the License, or (at your option) any later
* version.
* 
* This module is distributed in the hope that it will be useful, but WITHOUT ANY
* WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
* A PARTICULAR PURPOSE. See the GNU General Public License for more details.
* 
* @file usctm.c 
* @brief This is the main source for the Linux Kernel Module which implements
* 	 the runtime discovery of the syscall table position and of free entries (those 
* 	 pointing to sys_ni_syscall) 
*
* @author Francesco Quaglia
*
* @date November 22, 2020
*/

#define EXPORT_SYMTAB
#define REMOVE 0
#define AWAKE_ALL 1
#define RESTRICT 0
#define NO_RESTRICT 1
#define CREATE 0
#define OPEN 1
//#define IPC_PRIVATE 0


#include <linux/rculist.h>
#include <linux/preempt.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/errno.h>
#include <linux/device.h>
#include <linux/kprobes.h>
#include <linux/mutex.h>
#include <linux/mm.h>
#include <linux/sched.h>

#include <linux/ipc_namespace.h>
#include <linux/rhashtable.h>

#include <asm/current.h>
#include <linux/uaccess.h>
#include <linux/rwsem.h>
#include <linux/slab.h>
#include <linux/version.h>
#include <linux/interrupt.h>
#include <linux/time.h>
#include <linux/string.h>
#include <linux/vmalloc.h>
#include <asm/page.h>
#include <asm/cacheflush.h>
#include <asm/apic.h>
#include <linux/syscalls.h>
#include <linux/cred.h>
#include <linux/list.h>
#include <linux/security.h>
#include <linux/lsm_hooks.h>

#include <linux/workqueue.h>
#include <linux/slab.h>
#include <linux/moduleparam.h>
#include <linux/wait.h>
#include <linux/spinlock.h>
#include <linux/msg.h>
#include "./util/util.h"
#include <asm/unistd.h>
//TODO TEST
#include <linux/delay.h>
//#include "./include/vtpmo.h"


MODULE_LICENSE("GPL");
MODULE_AUTHOR("Valentino Perrone <perrone.valentino@gmail.com>");
MODULE_DESCRIPTION("DATA_EXCHANGE");

#define MODNAME "DATA-EXCHANGE"
static DEFINE_MUTEX(log_get_mutex);

unsigned long *hacked_ni_syscall=NULL;
unsigned long **hacked_syscall_tbl=NULL;
#define ENTRIES_TO_EXPLORE 256
char  kernel_buff[MAX_MSG_SIZE];

//extern int sys_vtpmo(unsigned long vaddr);
//
//
//#define ADDRESS_MASK 0xfffffffffffff000//to migrate
//
//#define START 			0xffffffff00000000ULL		// use this as starting address --> this is a biased search since does not start from 0xffff000000000000
//#define MAX_ADDR		0xfffffffffff00000ULL
//#define FIRST_NI_SYSCALL	134
//#define SECOND_NI_SYSCALL	174
//#define THIRD_NI_SYSCALL	182
//#define FOURTH_NI_SYSCALL	183
//#define FIFTH_NI_SYSCALL	214
//#define SIXTH_NI_SYSCALL	215
//#define SEVENTH_NI_SYSCALL	236
//
//#define ENTRIES_TO_EXPLORE 256
//
//
//unsigned long *hacked_ni_syscall=NULL;
//unsigned long **hacked_syscall_tbl=NULL;
//
//unsigned long sys_call_table_address = 0x0;
//module_param(sys_call_table_address, ulong, 0660);
//
//unsigned long sys_ni_syscall_address = 0x0;
//module_param(sys_ni_syscall_address, ulong, 0660);
//
//
//int good_area(unsigned long * addr){
//
//	int i;
//
//	for(i=1;i<FIRST_NI_SYSCALL;i++){
//		if(addr[i] == addr[FIRST_NI_SYSCALL]) goto bad_area;
//	}
//
//	return 1;
//
//bad_area:
//
//	return 0;
//
//}



///* This routine checks if the page contains the begin of the syscall_table.  */
//int validate_page(unsigned long *addr){
//	int i = 0;
//	unsigned long page 	= (unsigned long) addr;
//	unsigned long new_page 	= (unsigned long) addr;
//	for(; i < PAGE_SIZE; i+=sizeof(void*)){
//		new_page = page+i+SEVENTH_NI_SYSCALL*sizeof(void*);
//
//		// If the table occupies 2 pages check if the second one is materialized in a frame
//		if(
//			( (page+PAGE_SIZE) == (new_page & ADDRESS_MASK) )
//			&& sys_vtpmo(new_page) == NO_MAP
//		)
//			break;
//		// go for patter matching
//		addr = (unsigned long*) (page+i);
//		if(
//			   ( (addr[FIRST_NI_SYSCALL] & 0x3  ) == 0 )
//			   && (addr[FIRST_NI_SYSCALL] != 0x0 )			// not points to 0x0
//			   && (addr[FIRST_NI_SYSCALL] > 0xffffffff00000000 )	// not points to a locatio lower than 0xffffffff00000000
//	//&& ( (addr[FIRST_NI_SYSCALL] & START) == START )
//			&&   ( addr[FIRST_NI_SYSCALL] == addr[SECOND_NI_SYSCALL] )
//			&&   ( addr[FIRST_NI_SYSCALL] == addr[THIRD_NI_SYSCALL]	 )
//			&&   ( addr[FIRST_NI_SYSCALL] == addr[FOURTH_NI_SYSCALL] )
//			&&   ( addr[FIRST_NI_SYSCALL] == addr[FIFTH_NI_SYSCALL] )
//			&&   ( addr[FIRST_NI_SYSCALL] == addr[SIXTH_NI_SYSCALL] )
//			&&   ( addr[FIRST_NI_SYSCALL] == addr[SEVENTH_NI_SYSCALL] )
//			&&   (good_area(addr))
//		){
//			hacked_ni_syscall = (void*)(addr[FIRST_NI_SYSCALL]);				// save ni_syscall
//			sys_ni_syscall_address = (unsigned long)hacked_ni_syscall;
//			hacked_syscall_tbl = (void*)(addr);				// save syscall_table address
//			sys_call_table_address = (unsigned long) hacked_syscall_tbl;
//			return 1;
//		}
//	}
//	return 0;
//}
//
///* This routines looks for the syscall table.  */
//void syscall_table_finder(void){
//	unsigned long k; // current page
//	unsigned long candidate; // current page
//
//	for(k=START; k < MAX_ADDR; k+=4096){
//		candidate = k;
//		if(
//			(sys_vtpmo(candidate) != NO_MAP)
//		){
//			// check if candidate maintains the syscall_table
//			if(validate_page( (unsigned long *)(candidate)) ){
//				printk("%s: syscall table found at %px\n",MODNAME,(void*)(hacked_syscall_tbl));
//				printk("%s: sys_ni_syscall found at %px\n",MODNAME,(void*)(hacked_ni_syscall));
//				break;
//			}
//		}
//	}
//
//}

extern int syscall_table_finder(unsigned long **, unsigned long ***);

//long sys_tag_get(int, int, int);
//int sys_tag_send(int, int, char*, size_t);
//int sys_tag_receive(int, int, char*, size_t);
//int sys_tag_cmd(int, int);

#define MAX_FREE 4
int free_entries[MAX_FREE];
module_param_array(free_entries,int,NULL,0660);//default array size already known - here we expose what entries are free
//unsigned long new_sys_call_array[] = {(unsigned long)sys_tag_get,(unsigned long)sys_tag_send,(unsigned long)sys_tag_receive,(unsigned long)sys_tag_cmd};
//#define HACKED_ENTRIES (int)(sizeof(new_sys_call_array)/sizeof(int))
#define HACKED_ENTRIES 4
int restore[HACKED_ENTRIES] = {[0 ... (HACKED_ENTRIES-1)] -1};
unsigned long new_sys_call_array[4];
//struttura TAG
//static int enable_sleep = 1;// this can be configured at run time via the sys file system - 1 meas any sleeping thread is freezed
//module_param(enable_sleep,int,0660);
//
//unsigned long count __attribute__((aligned(8)));//this is used to audit how many threads are still sleeping onto the sleep/wakeup queue
//module_param(count,ulong,0660);




typedef struct _packed_work{
    void* buffer;
    long code;
    struct work_struct the_work;
} packed_work;

//elem head = {NULL,-1,-1,NULL,NULL,NULL,NULL};
//elem tail = {NULL,-1,-1,NULL,NULL,NULL,NULL};

//lista RCU
static LIST_HEAD(list_tag_rcu);
static spinlock_t list_tag_lock;


struct ipc_ids *ids;


static void tag_reclaim_callback(struct rcu_head *rcu) {
    struct _tag_elem *p = container_of(rcu, struct _tag_elem, rcu);

    /**
     * Why print preemt_count??
     *
     * To check whether this callback is atomic context or not.
     * preempt_count here is more than 0. Because it is irq context.
    */
    pr_info("callback free : %lx, preempt_count : %d\n", (unsigned long)p, preempt_count());
    kfree(p);
}

void free_mem(unsigned long data){

    printk("free mem da implementare");
//    kfree((void*)container_of(data,packed_work,the_work));
//    module_put(THIS_MODULE);

}

char* load_msg(char* buffer, int size){
    int ret;
    char* addr;

    addr = (void *) get_zeroed_page(GFP_KERNEL);

    if (addr == NULL) return NULL;

    ret = copy_from_user((char *) addr, (char *) buffer, size);//returns the number of bytes NOT copied

    return addr;
}
void awake_all( int tag){
    int i;

}

static void msg_rcu_free(struct rcu_head *head)
{
    struct kern_ipc_perm *p = container_of(head, struct kern_ipc_perm, rcu);
    msg_queue *msq = container_of(p, msg_queue, q_perm);

//    security_msg_queue_free(msq);
    printk("prima rimozione %d \n", msq->q_perm.key);

    kfree(msq);
    printk("fine rimozione %d \n", msq->q_perm.key);

}
/*
 * freeque() wakes up waiters on the sender and receiver waiting queue,
 * removes the message queue from message queue ID IDR, and cleans up all the
 * messages associated with this queue.
 *
 * msg_ids.rwsem (writer) and the spinlock for this message queue are held
 * before freeque() is called. msg_ids.rwsem remains locked on exit.
 */
static void freeque( struct kern_ipc_perm *ipcp)
{

    msg_queue *msq = container_of(ipcp,  msg_queue, q_perm);

    /* DEFINE_WAKE_Q(wake_q);

     expunge_all(msq, -EIDRM, &wake_q);
     ss_wakeup(msq, &wake_q, true);*/

    ipc_rmid( &msq->q_perm);

  //  ipc_unlock_object(&msq->q_perm);
//    wake_up_q(&wake_q);
    rcu_read_unlock();

   /* list_for_each_entry_safe(msg, t, &msq->q_messages, m_list) {
        atomic_dec(&ns->msg_hdrs);
        free_msg(msg);
    }
    atomic_sub(msq->q_cbytes, &ns->msg_bytes);*/

    //reclamo memoria quando i read lock che intaccano questa struttura sono finiti
    ipc_rcu_putref(&msq->q_perm, msg_rcu_free);

    call_rcu(&msq->q_perm.rcu, msg_rcu_free);
}





int remove_tag(int tag){

/*    spin_lock(&p->tag_lock);
    //check se contator è -1
    if (p->num_thread_per_tag != 0){
        printk("%s: ci sono waiters \n", MODNAME);
        spin_unlock(&p->tag_lock);
        return -1;
    }
    spin_unlock(&p->tag_lock);*/
    //incremento contatore atomic per tag di accessi
    struct kern_ipc_perm *ipcp;
    msg_queue *msq;
    int err;
    down_write(&ids->rwsem);
    rcu_read_lock();

    ipcp = ipcctl_obtain_check( tag);
    if (IS_ERR(ipcp)) {
        err = PTR_ERR(ipcp);
        rcu_read_unlock();
        up_write(&ids->rwsem);
        return err;
//        goto out_unlock1;
    }

    msq = container_of(ipcp, msg_queue, q_perm);

   /* err = security_msg_queue_msgctl(msq, cmd);
    if (err)
        goto out_unlock1;*/

//    ipc_lock_object(&msq->q_perm);

    //se non ci sonor reader chiudo il gate d entrata nella receive
    //i receiver che arrivano falliscono perche sto eliminando il nodo
    if( atomic_cmpxchg(&msq->q_perm.refcount.refs, 1, -1) == -1){
        /* freeque unlocks the ipc object and rcu */
        freeque( ipcp);

        //goto out_up;
//    rcu_read_unlock();
        up_write(&ids->rwsem);
    }else{
   // if(refcount_read(&msq->q_perm.refcount) != 1){
        printk("ci sono waiters");
        //ipc_unlock_object(&msq->q_perm);
        rcu_read_unlock();
        up_write(&ids->rwsem);
        return -1;
    }



    return 1;
}

int check_and_get_tag_if_key_exists(int key) {
    struct _tag_elem *p;
    int tag=-1;
    rcu_read_lock();
//    for (p=&head; p!= NULL && p->next!=NULL;  p=p->next){
//
//        if (p->key == key)
//            return p->tag;
//    }
    list_for_each_entry(p, &list_tag_rcu, node) {
        if(p->key== key) {
            tag=p->tag;
            break;
        }
    }
    rcu_read_unlock();
    return tag;
}


int atomic_add_if_positive(atomic_t * v){
    int ret;
    unsigned long flags;

    raw_local_irq_save(flags);
    ret = -1;
    if (likely(v->counter > 0))
        v->counter = v->counter+1;
    raw_local_irq_restore(flags);

    return ret;

}


void add_elem(struct _tag_elem* p) {
//    elem *aux;

//
//    new->next=NULL;
//    new->prev=NULL;
//    aux = &tail;
//
//
//    aux->prev->next = new;
//    new->prev = aux->prev;
//    aux->prev = new;
//    new->next = aux;
//    printk("%s nodo attaccato\n",MODNAME);




    //list_head * new, list_head *head
    //aggiungo il nodo alla lista rcu
    list_add_rcu(&p->node, &list_tag_rcu);
}

struct _tag_elem* check_and_get_tag_if_exists(int id){
    struct kern_ipc_perm *ipcp = ipc_obtain_object_idr(id);

    if (IS_ERR(ipcp))
        return ERR_CAST(ipcp);

    return container_of(ipcp, struct _tag_elem, q_perm);
}

#ifdef CONFIG_PROC_FS
static int sysvipc_msg_proc_show(struct seq_file *s, void *it)
{
	struct user_namespace *user_ns = seq_user_ns(s);
	struct kern_ipc_perm *ipcp = it;
	struct _tag_elem *msq = container_of(ipcp, struct _tag_elem, q_perm);

	seq_printf(s,
		   "%10d %10d  \n",
		   msq->q_perm.key,
		   msq->q_perm.id
		 );

	return 0;
}
#endif

/*void free_list(void)
{
    int i;
    struct list_head *p,*node;
    elem l;
    elem* tmp_elem;
    //position n head, n è una struttura list_head temporanea per usarla come storage temporaneo
    list_for_each_safe(p, node, &l.node) {
        tmp_elem = list_entry(p, elem, node);
        list_del(p);
        for (i = 0; i < 32; i++) {
            kfree(tmp_elem->level[i].group);
        }
        kfree(tmp_elem->level);
        kfree(tmp_elem);
    }*/


//    elem *n = head.next;
//    elem *n1;
//    printk("%s:LIBERO MEMORIA 1\n", MODNAME);
//
//    head.next=NULL;
//    printk("%s:LIBERO MEMORIA 1\n", MODNAME);
//
//    while(n!=NULL ){
//        printk("%s:LIBERO MEMORIA 2\n", MODNAME);
//
//        n->prev=NULL;
//        printk("%s:LIBERO MEMORIA 3\n", MODNAME);
//
//        n1 = n;
//        printk("%s:LIBERO MEMORIA 4\n", MODNAME);
//
//        n = n->next;
//        printk("%s:LIBERO MEMORIA 5\n", MODNAME);
//
//        //se sono arrivato alla tail è statica e quindi non faccio la free
//        if (n !=NULL){
//            printk("%s:LIBERO MEMORIA 6\n", MODNAME);
//            kfree(n1);
//        }
//        printk("%s:LIBERO MEMORIA 7\n", MODNAME);
//
//    }
//    printk("%s:LIBERO MEMORIA\n", MODNAME);
//}



#define SYS_CALL_INSTALL

#ifdef SYS_CALL_INSTALL
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
__SYSCALL_DEFINEx(3, _tag_get, int, key, int, command, int, permission){
#else
asmlinkage int sys_tag_get(int key, int command, int permission){
#endif
    int result;
    if (permission != RESTRICT && permission != NO_RESTRICT ){
        printk("%s: permission non valido %d\n",MODNAME,current->cred->euid);
        return -1;
    }



//controllare se restrict
//check se non è ne open ne esclusive
//TODO valore di ritorno -1
//todo allocare messaggio
    struct ipc_params params;
    params.key=key;
    params.flg=command;
    result = ipcget(&params);
    printk("risultato id %d \n ", result);
    return result;


 /*   int tag;
    elem* p;

    printk("%s: tag-params sys-call has been called %d %d %d  \n",MODNAME,key,command,permission);
    printk("%s: tag user id %d\n",MODNAME,current->cred->euid);


    if (permission != RESTRICT && permission != NO_RESTRICT ){
        printk("%s: permission non valido %d\n",MODNAME,current->cred->euid);
        return -1;
    }


    if(command == OPEN){
        tag = check_and_get_tag_if_key_exists(key);
        if (tag==-1) {
            printk("%s: tag non aperto error%d\n", MODNAME, current->cred->euid);
            return -1;
        }
        return tag;
    }else if (command == CREATE){
        p = alloc_tag_service(key);
        // se il nodo non esiste qualcuno potrebbe inserire lo stesso nel mentre dopo il check e quindi devo bloccare le insert
        spin_lock(&list_tag_lock);
        //TODO NON FARE READ LOCK QUI
        tag = check_and_get_tag_if_key_exists(key);
        if(tag!=-1) {
            printk("%s: tag gia esiste %d\n", MODNAME, current->cred->euid);
            spin_unlock(&list_tag_lock);
            return tag;
        }
        //spinlock per serializzare gli scrittori
        add_elem(p);
        spin_unlock(&list_tag_lock);

        //rilascio lock
        return tag;
    }else{
        printk("%s: command non valido %d\n",MODNAME,current->cred->euid);
        return -1;
    }
*/


    //caso di errore
    return -1;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
static unsigned long sys_tag_get = (unsigned long) __x64_sys_tag_get;
#else
#endif



#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
__SYSCALL_DEFINEx(4, _tag_send, int, tag, int, level, char*, buffer, size_t, size){
#else
    /*scrivo area condivisa
     * lock on wait queue e leggo atomic counter svegliando poi i thread dormienti e unlock
     * while var local atomic counter == version reader*/
asmlinkage int sys_tag_send(int tag, int level, char* buffer, size_t size){
#endif
    struct _tag_elem* msq;
    unsigned long ret;
    void* addr;
    int err;
    struct _tag_level_group* copy;
    printk("%s: send-params sys-call has been called %d %d %s %zu  \n",MODNAME,tag,level,buffer,size);
//    p->level[level].awake=0;

    //read lock sulla lettura
    //TODO CHECK SULLA PERMISSION

    //trade off tra sicurezza e velocità
    if (size >= (MAX_MSG_SIZE - 1) || (long) size < 0 || tag < 0) goto bad_size;//leave 1 byte for string terminator

    addr = load_msg(buffer, size);

    //GET TAG FROM IPC STRUCT
    rcu_read_lock();

    msq= check_and_get_tag_if_exists(tag);

    if (IS_ERR(msq)) {
        err = PTR_ERR(msq);
        goto out_unlock1;
    }

    //INIZIO LAVORO PER SVEGLIARE I THREAD
    //PRENDO IL LOCK SUL GROUP CAMBIO LA VISTA DEL PUNTATORE A GROUP

    spin_lock(&msq->level[level].queue_lock);
    copy = msq->level[level].group;
    msq->level[level].group = kmalloc(sizeof(struct _tag_level_group), GFP_KERNEL);
    msq->level[level].group->awake = 1;
    spin_unlock(&msq->level[level].queue_lock);
    rcu_read_unlock();
    //SCRIVO MEMORIA CONDIVISA
//    mutex_lock(&log_get_mutex);
    memcpy((char *) copy->kernel_buff, (char *) addr, size - ret);

    copy->kernel_buff[size - ret] = '\0';
    printk("%s: kernel buffer updated content is: %s\n", MODNAME, copy->kernel_buff);
    //    valid = size - ret;
//    mutex_unlock(&log_get_mutex);
    free_pages((unsigned long) addr, 0);

    //INFINE SVEGLIO I THREAD
    copy->awake = 0;
//        printk("%s numero thread %d\n",MODNAME,local_num_thread);
    wake_up(&msq->level[level].my_queue);
//    rcu_read_unlock();

    //TODO devo implementare la parte che fa la free e aspetta che tutti i thread abbiano letto


    return size - ret;


bad_size:
    return -1;

out_unlock1:
    rcu_read_unlock();
    if (msq != NULL)
        free_pages((unsigned long) addr, 0);
    return err;

}
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
static unsigned long sys_tag_send = (unsigned long) __x64_sys_tag_send;
#else
#endif



#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
__SYSCALL_DEFINEx(4, _tag_receive, int, tag, int, level, char*, buffer, size_t, size){
#else
asmlinkage int sys_tag_receive(int tag, int level, char* buffer, size_t size){
#endif

    struct _tag_elem * msq;
    struct _tag_level_group* copy;
    unsigned long ret;
    int err;

    void* addr;
    //packed_work *the_task;

    //TODO PERMISSION CHECK
    rcu_read_lock();
    msq= check_and_get_tag_if_exists(tag);
    if (IS_ERR(msq)) {
        //TODO USARE REFERENCE COUNT
//        atomic_dec((atomic_t*)&msq->num_thread_per_tag);
        printk("errore check and get");
        rcu_read_unlock();
        return PTR_ERR(msq);
        // goto out_unlock;
    }

    //serve read lock perchè se dealloco la struttura p, non posso piu accedere alla variabile lock
    //sezione critica condivisa con remover con contatore atomico per tag di accessi
//    spin_lock(&msq->q_perm.);
   //TODO attenzione ipc_lock_object(&msq->q_perm);

    if( atomic_add_if_positive(&msq->q_perm.refcount.refs) ) {
        /* raced with RMID? */
//        if (!ipc_valid_object(&msq->q_perm)) {
//            printk("errore ipc invalid");
//            err = -EIDRM;
//            //TODO attenzione ipc_unlock_object(&msq->q_perm);
//            rcu_read_unlock();
//
//            return err;
//        }
//        if (!ipc_rcu_getref(&msq->q_perm)) {
//            printk("errore ipc get ref");
//            err = -EIDRM;
//            //TODO attenzione ipc_unlock_object(&msq->q_perm);
//            rcu_read_unlock();
//            return err;
//        }

        // check se contator è -1 serve per fare la remove atomica che
        /*  if (msq->num_thread_per_tag == -1){
              printk("%s: tag not found \n", MODNAME);
              ipc_unlock_object(msq->q_perm);
              // rcu_read_unlock();
              return -1;
          }*/
        //incremento contatore atomic per tag di accessi
//    msq->num_thread_per_tag++;
        //TODO attenzione ipc_unlock_object(&msq->q_perm);


        printk("%s: valore tag stampato nella receive %d %d\n", MODNAME, msq->tag, msq->level[level].group->awake);

        //COPIO AREA DI MEMORIA
        spin_lock(&msq->level[level].queue_lock);
        copy = msq->level[level].group ;
        spin_unlock(&msq->level[level].queue_lock);

        //SBLOCCO LE AREE


//        atomic_inc((atomic_t*)&p->level[level].num_thread);//a new sleeper
        wait_event_interruptible(msq->level[level].my_queue, copy->awake == 0);
//        spin_unlock(&p->level[level].queue_lock);
        if(copy->awake == 1){
            printk("%s: thread exiting sleep for signal\n",MODNAME);
            return -EINTR;
        }

        //prima leggo poi decremento
//        atomic_dec((atomic_t*)&p->level[level].num_thread);//finally awaken
        printk("%s: BUONGIORNOOOOOOOOO\n", MODNAME);

        //posso incrementare il reference anche qui perchè i tag non intaccano la memoria copiata
        ipc_rcu_putref(&msq->q_perm, msg_rcu_free);


        //INIZIO LETTURA MEMORIA CONDIVISA
        //TODO : LETTURA E INCREMENTO NUMERO READERS

        // atomic_inc((atomic_t*)&copy->num_thread);//a new reader

        if(size > MAX_MSG_SIZE) goto bad_size;

        addr = (void*)get_zeroed_page(GFP_KERNEL);

        if (addr == NULL) return -1;

//    mutex_lock(&log_get_mutex);
//    if (size > valid) size = valid;
        memcpy((char*)addr,(char*)copy->kernel_buff,size);
        printk("%s: SONO NELLA RECEIVE - %s\n",MODNAME,copy->kernel_buff);
//    mutex_unlock(&log_get_mutex);




//    spin_lock(&msq->tag_lock);
//    p->num_thread_per_tag--;
//    spin_unlock(&msq->tag_lock);
        //rcu_read_unlock();


        ret = copy_to_user((char*)buffer,(char*)addr,size);
        free_pages((unsigned long)addr,0);


//        the_task = kzalloc(sizeof(packed_work),GFP_ATOMIC);//non blocking memory allocation

        /* if (the_task == NULL) {
             printk("%s: tasklet buffer allocation failure\n",MODNAME);
             module_put(THIS_MODULE);
             return -1;
         }
     */
//        the_task->code = request_code;

        //TODO SLEEPER PER GROUP
//    atomic_dec((atomic_t*)&copy->num_thread);//a new sleeper
//    spin_lock(&copy->lock_presence_counter);
        /* if (copy->num_thread==0){
             the_task->buffer = copy;
             __INIT_WORK(&(the_task->the_work),(void*)free_mem,&(the_task->the_work));
             schedule_work(&the_task->the_work);
         }*/
        //spin_unlock(&copy->lock_presence_counter);




        printk("%s: sys_get_message copy to user returned %d\n",MODNAME,(int)ret);
        return size - ret;
        bad_size:

        return -1;


//    printk("%s: receive-params sys-call has been called %d %d %s %zu  \n",MODNAME,tag,level,buffer,size);
        //mi attesto su un nodo
        //stampo tutti i nodi
//    print_list_tag(tag);

        //vado in sleep al livello level

    }else{
        rcu_read_unlock();
    }

}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
static unsigned long sys_tag_receive = (unsigned long) __x64_sys_tag_receive;
#else
#endif




#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
__SYSCALL_DEFINEx(2, _tag_cmd, int, tag, int, command){
#else
asmlinkage int sys_tag_cmd(int tag, int command){
#endif
    //TODO PERMISSION CHECK
    //struct _tag_elem* p;
    //rcu_read_lock();
    //p= check_and_get_tag_if_exists(tag);
    //rcu_read_unlock();


    //if (p!=NULL) {
    switch (command) {
        case AWAKE_ALL:
            awake_all(tag);
            printk("%s: awake all \n", MODNAME);

            break;
        case REMOVE:
            printk("%s: remove tag \n", MODNAME);

            if (remove_tag(tag)==-1){
                printk("%s: non rimovibile \n", MODNAME);
                return -1;
            }
            return 1;
            break;
    }
//    }else{
//        printk("%s: tag not found \n", MODNAME);
//    }


//    printk("%s: cmd-params sys-call has been called %d %d \n",MODNAME,tag,command);
    return 0;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
static unsigned long sys_tag_cmd = (unsigned long) __x64_sys_tag_cmd;
#else
#endif


unsigned long cr0;

static inline void
write_cr0_forced(unsigned long val)
{
    unsigned long __force_order;

    /* __asm__ __volatile__( */
    asm volatile(
    "mov %0, %%cr0"
    : "+r"(val), "+m"(__force_order));
}

static inline void
protect_memory(void)
{
    write_cr0_forced(cr0);
}

static inline void
unprotect_memory(void)
{
    write_cr0_forced(cr0 & ~X86_CR0_WP);
}



#else
#endif


int init_module(void) {

	int i,j;


    ipc_init_ids();
	printk("%s: initializing\n",MODNAME);


//    ipc_init_proc_interface("sysvipc/dataExchange","       key      msqid \n", sysvipc_msg_proc_show);
    spin_lock_init(&list_tag_lock);

    //Doppio puntatore che punta all'array che mantiene dentro le system call libere
    syscall_table_finder(&hacked_ni_syscall, &hacked_syscall_tbl);

	if(!hacked_syscall_tbl){
		printk("%s: failed to find the sys_call_table\n",MODNAME);
		return -1;
	}

	j=0;
	for(i=0;i<ENTRIES_TO_EXPLORE;i++)
		if(hacked_syscall_tbl[i] == hacked_ni_syscall){
			printk("%s: found sys_ni_syscall entry at syscall_table[%d]\n",MODNAME,i);
			free_entries[j++] = i;
			if(j>=MAX_FREE) break;
		}

#ifdef SYS_CALL_INSTALL
	cr0 = read_cr0();
	unprotect_memory();
    hacked_syscall_tbl[free_entries[0]] = (unsigned long*)sys_tag_get;
    hacked_syscall_tbl[free_entries[1]] = (unsigned long*)sys_tag_send;
    hacked_syscall_tbl[free_entries[2]] = (unsigned long*)sys_tag_receive;
    hacked_syscall_tbl[free_entries[3]] = (unsigned long*)sys_tag_cmd;
 	/*for(i=0;i<HACKED_ENTRIES;i++){
                ((unsigned long *)hacked_syscall_tbl)[free_entries[i]] = (unsigned long*)new_sys_call_array[i];
                printk("%s: sys call numero  %d\n",MODNAME,free_entries[i]);

    }*/
 	protect_memory();
	//printk("%s: a sys_call with 2 parameters has been installed as a trial on the sys_call_table at displacement %d\n",MODNAME,FIRST_NI_SYSCALL);	
#else
#endif

    printk("%s: module correctly mounted\n",MODNAME);
    return 0;

}

void cleanup_module(void) {
    int i;
#ifdef SYS_CALL_INSTALL
	cr0 = read_cr0();
        unprotect_memory();
        //hacked_syscall_tbl[FIRST_NI_SYSCALL] = (unsigned long*)hacked_ni_syscall;

 	for(i=0;i<HACKED_ENTRIES;i++){
                ((unsigned long *)hacked_syscall_tbl)[free_entries[i]] = (unsigned long)hacked_ni_syscall;
        }
        protect_memory();
#else
#endif
//    free_list();
//    print_list_tag(8);
    printk("%s: shutting down\n",MODNAME);
        
}
