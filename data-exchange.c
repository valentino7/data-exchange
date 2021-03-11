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
#define MAX_MSG_SIZE 4096
#define RESTRICT 0
#define NO_RESTRICT 1


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

#include <linux/slab.h>
#include <linux/moduleparam.h>
#include <linux/wait.h>
#include <linux/spinlock.h>
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

int sys_tag_get(int, int, int);
int sys_tag_send(int, int, char*, size_t);
int sys_tag_receive(int, int, char*, size_t);
int sys_tag_cmd(int, int);

#define MAX_FREE 15
int free_entries[MAX_FREE];
module_param_array(free_entries,int,NULL,0660);//default array size already known - here we expose what entries are free
unsigned long new_sys_call_array[] = {(unsigned long)sys_tag_get,(unsigned long)sys_tag_send,(unsigned long)sys_tag_receive,(unsigned long)sys_tag_cmd};
#define HACKED_ENTRIES (int)(sizeof(new_sys_call_array)/sizeof(unsigned long))


//struttura TAG
//static int enable_sleep = 1;// this can be configured at run time via the sys file system - 1 meas any sleeping thread is freezed
//module_param(enable_sleep,int,0660);
//
//unsigned long count __attribute__((aligned(8)));//this is used to audit how many threads are still sleeping onto the sleep/wakeup queue
//module_param(count,ulong,0660);

typedef struct _tag_level_group{
    int awake  ;
    unsigned long num_thread __attribute__((aligned(8)));
    char kernel_buff[MAX_MSG_SIZE];
} group;

typedef struct _tag_level{
    int awake  ;
    unsigned long num_thread __attribute__((aligned(8)));
    wait_queue_head_t my_queue;
    struct _tag_level_group* group;
    spinlock_t queue_lock;


} level;

//almeno 256 servizi runnabili
typedef struct _tag_elem{
    struct _tag_level* level;
    int tag;
    int key;

    struct _tag_elem * next;
    struct _tag_elem * prev;
    //tid creator
} elem;

elem head = {NULL,-1,-1,NULL,NULL};
elem tail = {NULL,-1,-1,NULL,NULL};

//funzione test da togliere
void printList(void){
    struct _tag_elem *p;
    printk("%s: inizio print list  \n",MODNAME);

    for (p=&head; p!= NULL && p->next!=NULL;  p=p->next){
        printk("%s: PRINT LIST: %d  \n",MODNAME,p->tag);
    }
    printk("%s: fine print list  \n",MODNAME);

}

void print_list_tag(int tag){
    struct _tag_elem *p;
    for (p=&head; p!= NULL && p->next!=NULL;  p=p->next){
        if (p->tag == tag){
            printk("%s: STAMPO ER TAG NELLA RECEIVE: %d  \n",MODNAME,p->tag);
//            printk("%s: tag: %d  \n",MODNAME,p->level[0].awake);
//            printk("%s: tag: %d  \n",MODNAME,tag);
            return;
        }
    }
}



void awake_all(elem* p, int tag){
    int i;
    for (i = 0; i < 32; i++){
        p->level[i].awake=0;
        wake_up(&p->level[i].my_queue);
    }
}

int remove_tag(elem* p, int tag){
    int i;
    printList();
    for (i = 0; i < 32; i++){
        if ( waitqueue_active(&p->level[i].my_queue))
            return -1;
    }
    //lockare
    p->prev->next=p->next;
    p->next->prev=p->prev;
    kfree(p);

    printList();
    return 1;
}

int check_and_get_if_key_exists(int key) {
    struct _tag_elem *p;
    for (p=&head; p!= NULL && p->next!=NULL;  p=p->next){
        if (p->key == key)
            return p->tag;
    }
    return -1;
}

void add_elem(int key) {
    elem *aux;
    int i;

    elem* new = kmalloc(sizeof (struct _tag_elem), GFP_KERNEL);
    new->level= (level*)kmalloc(32*sizeof (struct _tag_level), GFP_KERNEL);

    new->key = key;
    new->tag = key;
    //inizializzo le 32 wait qeue
    printk("%s: prima aver inizializzato awake:\n",MODNAME);


    for (i = 0; i < 32; i++){
        new->level[i].group = kmalloc(sizeof (struct _tag_level_group), GFP_KERNEL);
        spin_lock_init(&new->level[i].queue_lock);
        new->level[i].awake = 1;
        new->level[i].group->awake = 1;
        init_waitqueue_head(&new->level[i].my_queue);

//        new->level[i].num_thread=0;
    }
    printk("%s: dpo aver inizializzato awake: %d \n",MODNAME, new->level[3].group->awake );

//        new.level[i].awake = i;
//    wait_queue_head_t the_queue;
//    init_waitqueue_head(&new->queue);
//    DECLARE_WAIT_QUEUE_HEAD(the_queue);
    new->next=NULL;
    new->prev=NULL;
    aux = &tail;


    aux->prev->next = new;
    new->prev = aux->prev;
    aux->prev = new;
    new->next = aux;
    printk("%s nodo attaccato\n",MODNAME);

}

elem* check_and_get_tag_if_exists(int tag){
    elem *p;
    for (p=&head; p!= NULL && p->next!=NULL;  p=p->next){
        if (p->tag == tag){
            return p;
        }
    }
    return NULL;
}



void free_list(void)
{
    elem *n = head.next;
    elem *n1;
    printk("%s:LIBERO MEMORIA 1\n", MODNAME);

    head.next=NULL;
    printk("%s:LIBERO MEMORIA 1\n", MODNAME);

    while(n!=NULL ){
        printk("%s:LIBERO MEMORIA 2\n", MODNAME);

        n->prev=NULL;
        printk("%s:LIBERO MEMORIA 3\n", MODNAME);

        n1 = n;
        printk("%s:LIBERO MEMORIA 4\n", MODNAME);

        n = n->next;
        printk("%s:LIBERO MEMORIA 5\n", MODNAME);

        //se sono arrivato alla tail è statica e quindi non faccio la free
        if (n !=NULL){
            printk("%s:LIBERO MEMORIA 6\n", MODNAME);
            kfree(n1);
        }
        printk("%s:LIBERO MEMORIA 7\n", MODNAME);

    }
    printk("%s:LIBERO MEMORIA\n", MODNAME);
}



#define SYS_CALL_INSTALL

#ifdef SYS_CALL_INSTALL
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
__SYSCALL_DEFINEx(3, _tag_get, int, key, int, command, int, permission){
#else
asmlinkage int sys_tag_get(int key, int command, int permission){
#endif
    printk("%s: tag-params sys-call has been called %d %d %d  \n",MODNAME,key,command,permission);
//    int t = check_and_get_if_exists(key);
    //cerco se il nodo già esiste scorrendo la lista
    printk("%s: tag user id %d\n",MODNAME,current->cred->euid);

    if (check_and_get_if_key_exists(key)==-1) {
        //se non esiste aggiungo nodo
        printk("%s: check %d\n", MODNAME, check_and_get_if_key_exists(key));
        add_elem(key);
        printk("%s: esiste adesso il nodo? %d\n", MODNAME, check_and_get_if_key_exists(key));

        printList();
        return key;
    }else{
        //se esiste ritorno il nodo esistente
        return check_and_get_if_key_exists(key);
    }
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
    elem* p;
    unsigned long ret;
    void* addr;
    group* copy;
    printk("%s: send-params sys-call has been called %d %d %s %zu  \n",MODNAME,tag,level,buffer,size);
//    p->level[level].awake=0;

    p= check_and_get_tag_if_exists(tag);
    if(p!=NULL) {

        if (size >= (MAX_MSG_SIZE - 1)) goto bad_size;//leave 1 byte for string terminator

        addr = (void *) get_zeroed_page(GFP_KERNEL);

        if (addr == NULL) return -1;

        ret = copy_from_user((char *) addr, (char *) buffer, size);//returns the number of bytes NOT copied



        //INIZIO LAVORO PER SVEGLIARE I THREAD
        //PRENDO IL LOCK SUL GROUP CAMBIO LA VISTA DEL PUNTATORE A GROUP

        spin_lock(&p->level[level].queue_lock);
        copy = p->level[level].group;
        p->level[level].group = kmalloc(sizeof(struct _tag_level_group), GFP_KERNEL);
        p->level[level].group->awake = 1;
        spin_unlock(&p->level[level].queue_lock);

        //SCRIVO MEMORIA CONDIVISA
//        mutex_lock(&log_get_mutex);
        memcpy((char *) copy->kernel_buff, (char *) addr, size - ret);
        copy->kernel_buff[size - ret] = '\0';
        printk("%s: kernel buffer updated content is: %s\n", MODNAME, copy->kernel_buff);
        //    valid = size - ret;
        mutex_unlock(&log_get_mutex);
        free_pages((unsigned long) addr, 0);

        //INFINE SVEGLIO I THREAD
        copy->awake = 0;
        printk("%s la lista è vuota? %d\n", MODNAME, waitqueue_active(&p->level[level].my_queue));
//        printk("%s numero thread %d\n",MODNAME,local_num_thread);
        wake_up(&p->level[level].my_queue);

        //TODO devo implementare la parte che fa la free e aspetta che tutti i thread abbiano letto


        return size - ret;
    }else{
            printk("%s: tag not found \n", MODNAME);
            return -1;
        }


    bad_size:
        return -1;


//    while (test_and_set(p->level[level].num_thread)!=0);

    return 0;
}
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
static unsigned long sys_tag_send = (unsigned long) __x64_sys_tag_send;
#else
#endif



#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
__SYSCALL_DEFINEx(4, _tag_receive, int, tag, int, leve, char*, buffer, size_t, size){
#else
asmlinkage int sys_tag_receive(int tag, int level, char* buffer, size_t size){
#endif
    struct _tag_elem *p;
    group* copy;
    unsigned long ret;
    void* addr;
    p= check_and_get_tag_if_exists(tag);

    if(p!=NULL) {
        //
        printk("%s: valore tag stampato nella receive %d %d\n", MODNAME, p->tag, p->level[level].group->awake);


        spin_lock(&p->level[level].queue_lock);
        copy = p->level[level].group ;
        spin_unlock(&p->level[level].queue_lock);

//        atomic_inc((atomic_t*)&p->level[level].num_thread);//a new sleeper
        wait_event_interruptible(p->level[level].my_queue, copy->awake == 0);
//        spin_unlock(&p->level[level].queue_lock);
        if(copy->awake == 1){
            printk("%s: thread exiting sleep for signal\n",MODNAME);
            return -EINTR;
        }

        //prima leggo poi decremento
//        atomic_dec((atomic_t*)&p->level[level].num_thread);//finally awaken
        printk("%s: BUONGIORNOOOOOOOOO\n", MODNAME);


        //INIZIO LETTURA MEMORIA CONDIVISA
        //TODO : LETTURA E INCREMENTO NUMERO READERS


//        char  kernel_buff[MAX_MSG_SIZE];



        if(size > MAX_MSG_SIZE) goto bad_size;

        addr = (void*)get_zeroed_page(GFP_KERNEL);

        if (addr == NULL) return -1;

        mutex_lock(&log_get_mutex);
    //    if (size > valid) size = valid;
        memcpy((char*)addr,(char*)copy->kernel_buff,size);

        printk("%s: SONO NELLA RECEIVE - %s\n",MODNAME,copy->kernel_buff);


        mutex_unlock(&log_get_mutex);

        ret = copy_to_user((char*)buffer,(char*)addr,size);
        free_pages((unsigned long)addr,0);

        printk("%s: sys_get_message copy to user returned %d\n",MODNAME,(int)ret);
        return size - ret;
        bad_size:

        return -1;

    }else{
        printk("%s: tag not found \n", MODNAME);
        return -1;
    }

//    printk("%s: receive-params sys-call has been called %d %d %s %zu  \n",MODNAME,tag,level,buffer,size);
    //mi attesto su un nodo
    //stampo tutti i nodi
//    print_list_tag(tag);

    //vado in sleep al livello level


    return 0;
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
    elem *p = check_and_get_tag_if_exists(tag);
    printk("%s: sono nel command %d %d\n", MODNAME, command, p->tag);

    if (p!=NULL) {
        switch (command) {
            case AWAKE_ALL:
                awake_all(p, tag);
                printk("%s: awake all \n", MODNAME);

                break;
            case REMOVE:
                printk("%s: remove tag \n", MODNAME);
                if (remove_tag(p, tag)==-1)
                    printk("%s: non rimovibile \n", MODNAME);
                break;
        }
    }else{
        printk("%s: tag not found \n", MODNAME);
    }


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
		
	printk("%s: initializing\n",MODNAME);
    head.next = &tail;// setup initial double linked list
    tail.prev = &head;
	syscall_table_finder(&hacked_ni_syscall, &hacked_syscall_tbl);

	if(!hacked_syscall_tbl){
		printk("%s: failed to find the sys_call_table\n",MODNAME);
		return -1;
	}

	j=0;
	for(i=0;i<ENTRIES_TO_EXPLORE;i++)
		if(hacked_syscall_tbl[i] == hacked_ni_syscall){
			//printk("%s: found sys_ni_syscall entry at syscall_table[%d]\n",MODNAME,i);
			free_entries[j++] = i;
			if(j>=MAX_FREE) break;
		}

#ifdef SYS_CALL_INSTALL
	cr0 = read_cr0();
        unprotect_memory();
        /*hacked_syscall_tbl[FIRST_NI_SYSCALL] = (unsigned long*)sys_tag_get;
	hacked_syscall_tbl[SECOND_NI_SYSCALL] = (unsigned long*)sys_tag_send;
	hacked_syscall_tbl[THIRD_NI_SYSCALL] = (unsigned long*)sys_tag_receive;
	hacked_syscall_tbl[FOURTH_NI_SYSCALL] = (unsigned long*)sys_tag_cmd;*/
 	for(i=0;i<HACKED_ENTRIES;i++){
                ((unsigned long *)hacked_syscall_tbl)[free_entries[i]] = (unsigned long)new_sys_call_array[i];
                printk("%s: sys call numero  %d\n",MODNAME,free_entries[i]);

    }
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
    free_list();
//    print_list_tag(8);
    printk("%s: shutting down\n",MODNAME);
        
}
