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


MODULE_LICENSE("GPL");
MODULE_AUTHOR("Valentino Perrone <perrone.valentino@gmail.com>");
MODULE_DESCRIPTION("DATA_EXCHANGE");

#define MODNAME "DATA-EXCHANGE"

static DEFINE_MUTEX(log_get_mutex);

unsigned long *hacked_ni_syscall=NULL;
unsigned long **hacked_syscall_tbl=NULL;
#define ENTRIES_TO_EXPLORE 256
char  kernel_buff[MAX_MSG_SIZE];


extern int syscall_table_finder(unsigned long **, unsigned long ***);
extern int send_msg(int, int, char*, size_t);
extern struct _tag_elem* check_and_get_tag_if_exists(int);
extern int tag_ctl(int, int);
extern int tag_get(struct ipc_params);
extern int tag_receive(int, int, char*, size_t);
extern int remove_all(void);


#define MAX_FREE 4
int free_entries[MAX_FREE];
module_param_array(free_entries,int,NULL,0660);//default array size already known - here we expose what entries are free
//unsigned long new_sys_call_array[] = {(unsigned long)sys_tag_get,(unsigned long)sys_tag_send,(unsigned long)sys_tag_receive,(unsigned long)sys_tag_cmd};
//#define HACKED_ENTRIES (int)(sizeof(new_sys_call_array)/sizeof(int))
#define HACKED_ENTRIES 4
int restore[HACKED_ENTRIES] = {[0 ... (HACKED_ENTRIES-1)] -1};
unsigned long new_sys_call_array[4];





struct ipc_ids *ids;




void free_mem(unsigned long data){

    printk("free mem da implementare");
//    kfree((void*)container_of(data,packed_work,the_work));
//    module_put(THIS_MODULE);

}


#ifdef CONFIG_PROC_FS
int sysvipc_msg_proc_show(struct seq_file *s, void *it)
{
//	struct user_namespace *user_ns = seq_user_ns(s);
	struct kern_ipc_perm *ipcp = it;
	struct _tag_elem *msq = container_of(ipcp, struct _tag_elem, q_perm);
    int i=0;
    for (i = 0; i<32; i++){
        seq_printf(s,
               "%10d %10d %10d %10ld  \n",
               msq->q_perm.key,
               msq->pid_creator,
               i,
               msq->level[i].group->num_thread
             );
    }

	return 0;
}
#endif



#define SYS_CALL_INSTALL

#ifdef SYS_CALL_INSTALL
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
__SYSCALL_DEFINEx(3, _tag_get, int, key, int, command, int, permission){
#else
asmlinkage int sys_tag_get(int key, int command, int permission){
#endif
    int result;
    int cmd_permission;
    struct ipc_params params;


    try_module_get(THIS_MODULE);
    if (permission != RESTRICT && permission != NO_RESTRICT ){
        return -1;
    }

    params.key=key;
    //shift di uno il command per salvare insieme anche le permission
    command = command <<1;
    cmd_permission = command + permission;
    params.flg = cmd_permission;

    result = tag_get(params);

    module_put(THIS_MODULE);
    return result;

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
    int result;
    try_module_get(THIS_MODULE);

    //void* addr;


//    p->level[level].awake=0;

    //read lock sulla lettura
    //TODO CHECK SULLA PERMISSION

    //trade off tra sicurezza e velocità
    if (size >= (MAX_MSG_SIZE - 1) || (long) size < 0 || tag < 0 || level > 31 || level < 0)
//        goto bad_size;//leave 1 byte for string terminator
        return -1;
    result = send_msg(tag, level, buffer, size);

    module_put(THIS_MODULE);
    return result;

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

    int result;
    try_module_get(THIS_MODULE);
    //packed_work *the_task;


    //trade off tra sicurezza e velocità
    if (size >= (MAX_MSG_SIZE - 1) || (long) size < 0 || tag < 0 || level > 31 || level < 0)
        return -1;//leave 1 byte for string terminator


    //mi attesto su un nodo
    //stampo tutti i nodi
//    print_list_tag(tag);



    result = tag_receive(tag, level, buffer, size);

    module_put(THIS_MODULE);
    return result;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
static unsigned long sys_tag_receive = (unsigned long) __x64_sys_tag_receive;
#else
#endif




#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
__SYSCALL_DEFINEx(2, _tag_ctl, int, tag, int, command){
#else
asmlinkage int sys_tag_ctl(int tag, int command){
#endif
    int result;
    //TODO PERMISSION CHECK
    //struct _tag_elem* p;
    //rcu_read_lock();
    //rcu_read_unlock();
//    int err;

//TODO decommentare
    try_module_get(THIS_MODULE);
    result = tag_ctl(command, tag);
    module_put(THIS_MODULE);
    return result;
//    remove_all();
//    return 0;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
static unsigned long sys_tag_ctl = (unsigned long) __x64_sys_tag_ctl;
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

    ipc_init_proc_interface("sysvipc/dataExchange","       TAG-key TAG-creator TAG-level Waiting-threads \n", sysvipc_msg_proc_show);

//    ipc_init_proc_interface("sysvipc/dataExchange","       TAG-key      msqid\n", sysvipc_msg_proc_show);
    //spin_lock_init(&list_tag_lock);

    //Doppio puntatore che punta all'array che mantiene dentro le system call libere
    syscall_table_finder(&hacked_ni_syscall, &hacked_syscall_tbl);

	if(!hacked_syscall_tbl){
		return -1;
	}

	j=0;
	for(i=0;i<ENTRIES_TO_EXPLORE;i++)
		if(hacked_syscall_tbl[i] == hacked_ni_syscall){
			free_entries[j++] = i;
			if(j>=MAX_FREE) break;
		}

#ifdef SYS_CALL_INSTALL
	cr0 = read_cr0();
	unprotect_memory();
    hacked_syscall_tbl[free_entries[0]] = (unsigned long*)sys_tag_get;
    hacked_syscall_tbl[free_entries[1]] = (unsigned long*)sys_tag_send;
    hacked_syscall_tbl[free_entries[2]] = (unsigned long*)sys_tag_receive;
    hacked_syscall_tbl[free_entries[3]] = (unsigned long*)sys_tag_ctl;
 	/*for(i=0;i<HACKED_ENTRIES;i++){
                ((unsigned long *)hacked_syscall_tbl)[free_entries[i]] = (unsigned long*)new_sys_call_array[i];

    }*/
 	protect_memory();
#else
#endif

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
     remove_all();
     printk("%s: shutting down\n",MODNAME);
     remove_proc_entry("sysvipc/dataExchange",NULL);
}
