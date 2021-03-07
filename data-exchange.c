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

#include <linux/slab.h>
#include <linux/moduleparam.h>
#include <linux/wait.h>
#include <linux/spinlock.h>
//#include "./include/vtpmo.h"


MODULE_LICENSE("GPL");
MODULE_AUTHOR("Francesco Quaglia <framcesco.quaglia@uniroma2.it>");
MODULE_DESCRIPTION("USCTM");

#define MODNAME "DATA-EXCHANGE"

unsigned long *hacked_ni_syscall=NULL;
unsigned long **hacked_syscall_tbl=NULL;
#define ENTRIES_TO_EXPLORE 256


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

typedef struct _tag_level{
    int awake  ;
    wait_queue_head_t my_queue;
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
spinlock_t queue_lock;

int check_and_get_if_exists(int key) {
    struct _tag_elem *p;
    for (p=&head; p!= NULL && p->next!=NULL;  p=p->next){
        if (p->key == key)
            return p->tag;
    }
    return -1;
}

void add_elem(int key) {
    elem* new = kmalloc(sizeof (struct _tag_elem), GFP_KERNEL);
    new->level= (level*)kmalloc(32*sizeof (struct _tag_level), GFP_KERNEL);
    elem *aux;

    new->key = key;
    new->tag = key;
    //inizializzo le 32 wait qeue
    printk("%s: prima aver inizializzato awake:\n",MODNAME);

    int i;
    for (i = 0; i < 32; i++){
        new->level[i].awake = 1;
        init_waitqueue_head(&new->level[i].my_queue);
    }
    printk("%s: dpo aver inizializzato awake: %d \n",MODNAME, new->level[3].awake = 1);

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
    printk("%s: nodo attaccato\n",MODNAME);

}

elem* get_tag_byTagAndLevel(int tag){
    elem *p;
    for (p=&head; p!= NULL && p->next!=NULL;  p=p->next){
        if (p->tag == tag){
            return p;
        }
    }
    return NULL;
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
    if (check_and_get_if_exists(key)==-1) {
        //se non esiste aggiungo nodo
        printk("%s: check %d\n", MODNAME, check_and_get_if_exists(key));
        add_elem(key);
        printk("%s: esiste adesso il nodo? %d\n", MODNAME, check_and_get_if_exists(key));
        return key;
    }else{
        //se esiste ritorno il nodo esistente
        return check_and_get_if_exists(key);
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
asmlinkage int sys_tag_send(int tag, int level, char* buffer, size_t size){
#endif
        printk("%s: send-params sys-call has been called %d %d %s %zu  \n",MODNAME,tag,level,buffer,size);
        elem* p = get_tag_byTagAndLevel(tag);
        p->level[level].awake=0;
        wake_up(&p->level[level].my_queue);
//        wake_up(&p->level[level].my_queue);
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
    printk("%s: receive-params sys-call has been called %d %d %s %zu  \n",MODNAME,tag,level,buffer,size);
    //mi attesto su un nodo
    //stampo tutti i nodi
//    print_list_tag(tag);

    //vado in sleep al livello level
    elem *p = get_tag_byTagAndLevel(tag);
//
    printk("%s: valore tag stampato nella receive %d\n", MODNAME, p->level[3].awake);


    wait_event_interruptible(p->level[level].my_queue, p->level[level].awake ==0);
//    printk("%s: BUONGIORNOOOOOOOOO\n", MODNAME);

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
    printk("%s: cmd-params sys-call has been called %d %d \n",MODNAME,tag,command);
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
        printk("%s: shutting down\n",MODNAME);
        
}
