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
* @author Valentino Perrone
*
*/

#define EXPORT_SYMTAB
#define REMOVE 0
#define AWAKE_ALL 1
#define RESTRICT 0
#define NO_RESTRICT 1
#define CREATE 0
#define OPEN 1
//#define IPC_PRIVATE 0

#include <linux/capability.h>
#include <linux/proc_fs.h>
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
#include <linux/delay.h>
//#include "./include/vtpmo.h"


MODULE_LICENSE("GPL");
MODULE_AUTHOR("Valentino Perrone <perrone.valentino@gmail.com>");
MODULE_DESCRIPTION("DATA_EXCHANGE");

#define MODNAME "DATA-EXCHANGE"
static DEFINE_MUTEX(log_get_mutex);





int send_msg(int, int, char*, size_t);
struct _tag_elem* check_and_get_tag_if_exists(int);
int tag_ctl(int, int);
int tag_get(struct ipc_params);
int tag_receive(int, int, char*, size_t);
void remove_all(void);



//Rimozione di tutti i tag aperti
void remove_all(){

    idr_for_each(&(ids->ipcs_idr), &remove_object, NULL);
    rhashtable_destroy(&(ids->key_ht));

}





int check_permission(int permission,  kuid_t euid){
    kuid_t ceuid;
    ceuid = current_euid();


    if( (permission==RESTRICT &&  uid_eq(euid, ceuid)) || permission == NO_RESTRICT)
        return 1;
    return -1;

}

struct _tag_elem* check_and_get_tag_if_exists(int id){
    struct kern_ipc_perm *ipcp = ipc_obtain_object_idr(id);
    if (IS_ERR(ipcp)){
        printk("non esiste");
        return ERR_CAST(ipcp);
    }
    //prendo l'ultimo bit con &1
    //restituisco errore in caso non ci siano permessi
    if(check_permission(ipcp->mode&1, ipcp-> cuid ) == -1) {
        return  ERR_PTR(-EPERM);
    }

    return container_of(ipcp, struct _tag_elem, q_perm);
}

char* load_msg(char* buffer, int size){
    int ret;
    char* addr;

    addr = (void *) get_zeroed_page(GFP_KERNEL);

    if (addr == NULL) return NULL;

    ret = copy_from_user((char *) addr, (char *) buffer, size);//returns the number of bytes NOT copied

    return addr;
}

/* Implementazione della sys-call send
 *
*/
int tag_get(struct ipc_params params) {
    return ipcget(&params);
}


/* Implementazione della sys-call send
 *
*/
int send_msg(int tag, int level, char* buffer, size_t size){

    void* addr;
    struct _tag_elem* msq;
    struct _tag_level_group* copy;
    int err;
    int count;
    unsigned long ret;
    struct _tag_level_group *new_group;

    addr = load_msg(buffer, size);

    ///////////////////////////////////////////////////////////////////////////////////////////////////////////////
    //GET TAG FROM IPC STRUCT
    rcu_read_lock();

    msq = check_and_get_tag_if_exists(tag);

    if (IS_ERR(msq)) {
        err = PTR_ERR(msq);
        goto out_unlock;
    }

    ///////////////////////////////////////////////////////////////////////////////////////////////////////////////

    ///////////////////////////////////////////////////////////////////////////////////////////////////////////////
    //INIZIO LAVORO PER SVEGLIARE I THREAD
    //PRENDO IL LOCK DEL LIVELLO PER CAMBIARE LA VISTA DEL PUNTATORE A GROUP

    new_group = kmalloc(sizeof(struct _tag_level_group), GFP_KERNEL);
    if (new_group == NULL)
    {
        err = -ENOMEM;
        goto out_unlock;
    }
    write_lock(&(msq->level[level].level_lock));
    //controllo se il tag è stato eliminato
    count = atomic_read(&msq->q_perm.refcount.refs);
    if(count== -1 || count==1){
        //NON CI SONO THREAD IN ATTESA
        write_unlock(&msq->level[level].level_lock);
        err = 0;
        goto out_unlock;
    }

    copy = msq->level[level].group;
    msq->level[level].group = new_group;

    msq->level[level].group->awake = 1;
    init_waitqueue_head(&msq->level[level].group->my_queue);
    write_unlock(&(msq->level[level].level_lock));

    rcu_read_unlock();

    //SCRIVO MEMORIA CONDIVISA
    memcpy((char *) copy->kernel_buff, (char *) addr, size - ret);

    copy->kernel_buff[size - ret] = '\0';

    free_pages((unsigned long) addr, 0);

    //INFINE SVEGLIO I THREAD
    copy->awake = 0;
    wake_up(&(copy->my_queue));

    return size - ret;


//    bad_size:
//    return -1;

    out_unlock:
    rcu_read_unlock();
    if (msq != NULL)
        free_pages((unsigned long) addr, 0);
    return err;
}

//static void msg_rcu_free(struct rcu_head *head)
//{
//    struct kern_ipc_perm *p = container_of(head, struct kern_ipc_perm, rcu);
//    msg_queue *msq = container_of(p, msg_queue, q_perm);
//
////    security_msg_queue_free(msq);
//
//    kfree(msq);
//
//}

/*
 * freeque() wakes up waiters on the sender and receiver waiting queue,
 * removes the message queue from message queue ID IDR, and cleans up all the
 * messages associated with this queue.
 *
 * msg_ids.rwsem (writer) and the spinlock for this message queue are held
 * before freeque() is called. msg_ids.rwsem remains locked on exit.
 */
static void freeque( struct kern_ipc_perm *ipcp, msg_queue *msq)
{

//    msg_queue *msq = container_of(ipcp,  msg_queue, q_perm);

    /* DEFINE_WAKE_Q(wake_q);

     expunge_all(msq, -EIDRM, &wake_q);
     ss_wakeup(msq, &wake_q, true);*/
    ipc_rmid( &(msq->q_perm));
    //  ipc_unlock_object(&msq->q_perm);
//    wake_up_q(&wake_q);
    write_unlock(&(msq->tag_lock));
    rcu_read_unlock();

    /* list_for_each_entry_safe(msg, t, &msq->q_messages, m_list) {
         atomic_dec(&ns->msg_hdrs);
         free_msg(msg);
     }
     atomic_sub(msq->q_cbytes, &ns->msg_bytes);*/

    //reclamo memoria quando i read lock che intaccano questa struttura sono finiti
    ipc_rcu_putref(&(msq->q_perm), msg_rcu_free);


}
int remove_tag(int tag){

    //incremento contatore atomic per tag di accessi
    struct kern_ipc_perm *ipcp;
    msg_queue *msq;
    int err;
    down_write(&(ids->rwsem));
    rcu_read_lock();

    msq = check_and_get_tag_if_exists(tag);

    if (IS_ERR(msq) || msq == NULL) {
        err = PTR_ERR(msq);
        rcu_read_unlock();
        up_write(&(ids->rwsem));
        return err;
    }

    /* err = security_msg_queue_msgctl(msq, cmd);
     if (err)
         goto out_unlock1;*/

//    ipc_lock_object(&msq->q_perm);

    //se non ci sonor reader chiudo il gate d entrata nella receive
    //i receiver che arrivano falliscono perche sto eliminando il nodo
    if (!write_trylock(&(msq->tag_lock))) {
        //lock occupato dai waiters
        rcu_read_unlock();
        up_write(&(ids->rwsem));
        return -1;
    }
    //se c è solo un reader posso eliminare
    if( atomic_cmpxchg(&(msq->q_perm.refcount.refs), 1, -1) == 1){
        /* freeque unlocks the ipc object and rcu */
        freeque(ipcp, msq);
        up_write(&(ids->rwsem));
    }else{
        // if(refcount_read(&msq->q_perm.refcount) != 1){
        //ipc_unlock_object(&msq->q_perm);
        write_unlock(&(msq->tag_lock));
        rcu_read_unlock();
        up_write(&(ids->rwsem));
        return -1;
    }
    return 1;
}

int awake_all(int tag){
//    struct global_data gd;
//    struct task_struct *kthread;
    int i;
//    int ret;

    for(i=0; i!=32; i++) {
        send_msg(tag, i, "\0", 0);
    }
//    init_waitqueue_head(&gd.wq);
//    for(i=0; i!=32; i++){
//        atomic_inc(&gd.thread_count);
//        kthread = kthread_run(wrapper_thread_send, &gd, "send kthreads");
//        if (IS_ERR(kthread)) {
//            ret = PTR_ERR(kthread);
//            if(atomic_read(&gd.thread_count) != 0)
//                wait_event_interruptible(gd.wq, atomic_read(&gd.thread_count) == 0);
//            return ret;
//        }
//    }
//    wait_event_interruptible(gd.wq, atomic_read(&gd.thread_count) == 0);
//    /* final cleanup */
//    //se ho ricevuto un errore ritorno awake all error
//    for(i=0; i!=32; i++) {
//        if (gd.error[i] < 0)
//            return -1;
//    }

    return 1;
}
/* Implementazione della sys-call tag_ctl
 *
*/
int tag_ctl(int command, int tag){
    switch (command) {
        case AWAKE_ALL:
            return awake_all(tag);

        case REMOVE:
            return remove_tag(tag);
    }
    return -1;
}

/* Implementazione della sys-call tag_receive
 *
*/
int tag_receive(int tag, int level, char* buffer, size_t size){

    struct _tag_elem *msq;
    struct _tag_level_group* copy;
    int err;
    int ret;
    void* addr;

    rcu_read_lock();
    /////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    //Viene acquisita la message queue se esiste
    msq= check_and_get_tag_if_exists(tag);


    if (IS_ERR(msq)) {
        //TODO USARE REFERENCE COUNT
        //atomic_dec((atomic_t*)&msq->num_thread_per_tag);
        err = PTR_ERR(msq);
        goto out_unlock;
    }
    /////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    /////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    //BLOCCO IN COMUNE CON CHI ELIMINA

    //serve read lock perchè se dealloco la struttura p, non posso piu accedere alla variabile lock
    //sezione critica condivisa con remover con contatore atomico per tag di accessi
//    spin_lock(&msq->q_perm.);
    //TODO attenzione ipc_lock_object(&msq->q_perm);
    while(!read_trylock(&(msq->tag_lock))) {
        //lock occupato dall eliminatore
        //controllo se il tag è stato eliminato, in caso positivo termino
        if(atomic_read(&(msq->q_perm.refcount.refs))==-1){
            err = -1;
            goto out_unlock;
        }
    }
    /////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////


    /* raced with RMID? */
//        if (!ipc_valid_object(&msq->q_perm)) {
//            err = -EIDRM;
//            //TODO attenzione ipc_unlock_object(&msq->q_perm);
//            rcu_read_unlock();
//
//            return err;
//        }

    /////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    //INCREMENTO REF se va tutto bene
    if (!ipc_rcu_getref(&(msq->q_perm))) {
        err = -EIDRM;
        //TODO attenzione ipc_unlock_object(&msq->q_perm);
        read_unlock(&(msq->tag_lock));
        goto out_unlock;
    }

    // check se contator è -1 serve per fare la remove atomica che
    /*  if (msq->num_thread_per_tag == -1){
          ipc_unlock_object(msq->q_perm);
          // rcu_read_unlock();
          return -1;
      }*/
    //incremento contatore atomic per tag di accessi
//    msq->num_thread_per_tag++;
    //TODO attenzione ipc_unlock_object(&msq->q_perm);

    /////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////


    /////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    //COPIATURA DELL'AREA DI MEMORIA
    read_lock(&(msq->level[level].level_lock));
    copy = msq->level[level].group ;
    //LETTURA E INCREMENTO NUMERO READERS PER IL GROUP PER IPLEMENTARE IL RILASCIO DELLA MEMORIA


    atomic_inc((atomic_t*)&copy->num_thread);//a new reader
    read_unlock(&(msq->level[level].level_lock));
    /////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////



    //SBLOCCO LE AREE

    //atomic_inc((atomic_t*)&p->level[level].num_thread);//a new sleeper
    wait_event_interruptible(copy->my_queue, copy->awake == 0);
    //spin_unlock(&p->level[level].level_lock);
    if(copy->awake == 1){

        read_unlock(&(msq->tag_lock));
        err = -EINTR;
        goto out_unlock;
    }

    //prima leggo poi decremento
//        atomic_dec((atomic_t*)&p->level[level].num_thread);//finally awaken
    printk("%s: BUONGIORNOOOOOOOOO\n", MODNAME);

    //posso incrementare il reference anche qui perchè i tag non intaccano la memoria copiata
    //TODO da ragionare sulla posizione di questi rilasci
    //decremento il refcount


    read_unlock(&(msq->tag_lock));
    rcu_read_unlock();

    /////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    //INIZIO LETTURA MEMORIA CONDIVISA


    addr = (void*)get_zeroed_page(GFP_KERNEL);
    if (addr == NULL) return -1;

//    mutex_lock(&log_get_mutex);
    memcpy((char*)addr,(char*)copy->kernel_buff,size);


    atomic_dec((atomic_t*)&copy->num_thread);
//    mutex_unlock(&log_get_mutex);




//    spin_lock(&msq->tag_lock);
//    p->num_thread_per_tag--;
//    spin_unlock(&msq->tag_lock);
    //rcu_read_unlock();

    //returns the number of bytes NOT copied
    ret = copy_to_user((char*)buffer,(char*)addr,size);
    free_pages((unsigned long)addr,0);


//        the_task = kzalloc(sizeof(packed_work),GFP_ATOMIC);//non blocking memory allocation

    /* if (the_task == NULL) {
         module_put(THIS_MODULE);
         return -1;
     }
 */
//        the_task->code = request_code;

    //ULtimo chiude la porta (rimuove la memoria).
    if(atomic_dec_and_test((atomic_t*)&copy->num_thread) ){
        kvfree(copy);
    }//a new sleeper
//    spin_lock(&copy->lock_presence_counter);
    /* if (copy->num_thread==0){
         the_task->buffer = copy;
         __INIT_WORK(&(the_task->the_work),(void*)free_mem,&(the_task->the_work));
         schedule_work(&the_task->the_work);
     }*/
    //spin_unlock(&copy->lock_presence_counter);

    return size - ret;

    out_unlock:
    rcu_read_unlock();
    return err;
}