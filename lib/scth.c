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
* @file scth.c 
* @brief This is the main source for the Linux Kernel Lib  which implements
* 	 the dynamis discovery of the position of the sys_call_table and the identifiction of
* 	 entries pointing to sys_ni_syscall - these entries are returned together with the address
* 	 of the sys_call_table and the address of sys_ni_syscall so that they can be exploited for
* 	 rewriting sys_call_table and adding new system calls to Linux
*
* @author Valentino Perrone
*
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
#include "../include/vtpmo.h"


MODULE_LICENSE("GPL");
MODULE_AUTHOR("Valentino Perrone <perrone.valentino@gmail.com>");
MODULE_DESCRIPTION("DATA_EXCHANGE");

#define MODNAME "DATA-EXCHANGE"


#define LIBNAME "SCTH"


#define AUDIT if(1)
#define LEVEL3_AUDIT if(0)

#define MAX_ACQUIRES 4


/*unsigned long *get_syscall_table(void)
{
        unsigned long *syscall_table;
        unsigned long int i;

        for (i = (unsigned long int)sys_close; i < ULONG_MAX; i += sizeof(void *)) {
                syscall_table = (unsigned long *)i;

                if (syscall_table[__NR_close] == (unsigned long)sys_close)
                        return syscall_table;
        }
        return NULL;
}


int get_entries(int entry_ids[], int num_acquires, unsigned long *sys_call_table, unsigned long *sys_ni_sys_call) {

        unsigned long * p;
        unsigned long addr;
        unsigned long table_addr;
        int i,j,z,k; //stuff to discover memory contents
        int ret = 0;
	int restore[MAX_ACQUIRES] = {[0 ... (MAX_ACQUIRES-1)] -1};


        printk("%s: trying to get %d entries from the sys-call table\n",LIBNAME,num_acquires);
	if(num_acquires < 1){
       		 printk("%s: less than 1 sys-call table entry requested\n",LIBNAME);
		 return -1;
	}
	if(num_acquires > MAX_ACQUIRES){
       		 printk("%s: more than %d sys-call table entries requested\n",LIBNAME, MAX_ACQUIRES);
		 return -1;
	}

	p = get_syscall_table();

	if(p == NULL){
		printk("%s: cannot locate the system_call_table\n",LIBNAME);
		return -1;
	}

	table_addr = (unsigned long)p;

        printk("%s: system call table correctly located - address is %p\n",LIBNAME,p);

        j = -1;
        for (i=0; i<256; i++){
		for(z=i+1; z<256; z++){
			if(p[i] == p[z]){
				AUDIT{
                        		printk("%s: table entries %d and %d keep the same address\n",LIBNAME,i,z);
                        		printk("%s: sys_ni_syscall correctly located at %p\n",LIBNAME,(void*)p[i]);
				}
				addr = p[i];
                        	if(j < (num_acquires-1)){
				       	restore[++j] = i;
					ret++;
                        		printk("%s: acquiring table entry %d\n",LIBNAME,i);
				}
                        	if(j < (num_acquires-1)){
                        		restore[++j] = z;
					ret++;
                        		printk("%s: acquiring table entry %d\n",LIBNAME,z);
				}
				for(k=z+1;k<256 && j < (num_acquires-1); k++){
					if(p[i] == p[k]){
                        			printk("%s: acquiring table entry %d\n",LIBNAME,k);
                        			restore[++j] = k;
						ret++;
					}
				}
				if(ret == num_acquires){
					goto found_available_entries;
				}
				return -1;
			}
                }
        }

        printk("%s: could not locate %d available entries in the sys-call table\n",LIBNAME,num_acquires);

	return -1;

found_available_entries:
	memcpy((char*)entry_ids,(char*)restore,ret*sizeof(int));
	*sys_ni_sys_call = addr;
	*sys_call_table = table_addr;

	return ret;

}*/



//FUNZIONI PER NEW DISCOVERY SYS CALL
extern int sys_vtpmo(unsigned long vaddr);


#define ADDRESS_MASK 0xfffffffffffff000//to migrate

#define START 			0xffffffff00000000ULL		// use this as starting address --> this is a biased search since does not start from 0xffff000000000000
#define MAX_ADDR		0xfffffffffff00000ULL
#define FIRST_NI_SYSCALL	134
#define SECOND_NI_SYSCALL	156
#define THIRD_NI_SYSCALL	174
#define FOURTH_NI_SYSCALL	177
#define FIFTH_NI_SYSCALL	180
#define SIXTH_NI_SYSCALL	181
#define SEVENTH_NI_SYSCALL	182





unsigned long sys_call_table_address = 0x0;
module_param(sys_call_table_address, ulong, 0660);

unsigned long sys_ni_syscall_address = 0x0;
module_param(sys_ni_syscall_address, ulong, 0660);


int good_area(unsigned long * addr){

    int i;

    for(i=1;i<FIRST_NI_SYSCALL;i++){
        if(addr[i] == addr[FIRST_NI_SYSCALL]) goto bad_area;
    }

    return 1;

    bad_area:

    return 0;

}
/* This routine checks if the page contains the begin of the syscall_table.  */
int validate_page(unsigned long *addr, unsigned long*** hacked_syscall_tbl, unsigned long** hacked_ni_syscall){
    int i = 0;
    unsigned long page 	= (unsigned long) addr;
    unsigned long new_page 	= (unsigned long) addr;
    for(; i < PAGE_SIZE; i+=sizeof(void*)){
        new_page = page+i+SEVENTH_NI_SYSCALL*sizeof(void*);

        // If the table occupies 2 pages check if the second one is materialized in a frame
        if(
                ( (page+PAGE_SIZE) == (new_page & ADDRESS_MASK) )
                && sys_vtpmo(new_page) == NO_MAP
                )
            break;
        // go for patter matching
        addr = (unsigned long*) (page+i);
        if(
                ( (addr[FIRST_NI_SYSCALL] & 0x3  ) == 0 )
                && (addr[FIRST_NI_SYSCALL] != 0x0 )			// not points to 0x0
                && (addr[FIRST_NI_SYSCALL] > 0xffffffff00000000 )	// not points to a locatio lower than 0xffffffff00000000
                //&& ( (addr[FIRST_NI_SYSCALL] & START) == START )
                &&   ( addr[FIRST_NI_SYSCALL] == addr[SECOND_NI_SYSCALL] )
                &&   ( addr[FIRST_NI_SYSCALL] == addr[THIRD_NI_SYSCALL]	 )
                &&   ( addr[FIRST_NI_SYSCALL] == addr[FOURTH_NI_SYSCALL] )
                &&   ( addr[FIRST_NI_SYSCALL] == addr[FIFTH_NI_SYSCALL] )
                &&   ( addr[FIRST_NI_SYSCALL] == addr[SIXTH_NI_SYSCALL] )
                &&   ( addr[FIRST_NI_SYSCALL] == addr[SEVENTH_NI_SYSCALL] )
                &&   (good_area(addr))
                ){
            *hacked_ni_syscall = (void*)(addr[FIRST_NI_SYSCALL]);				// save ni_syscall
            sys_ni_syscall_address = (unsigned long)*hacked_ni_syscall;
            *hacked_syscall_tbl = (void*)(addr);				// save syscall_table address
            sys_call_table_address = (unsigned long) *hacked_syscall_tbl;
            return 1;
        }
    }
    return 0;
}

/* This routines looks for the syscall table.  */
void syscall_table_finder(unsigned long ** hacked_ni_syscall, unsigned long*** hacked_syscall_tbl){
    unsigned long k; // current page
    unsigned long candidate; // current page

    for(k=START; k < MAX_ADDR; k+=4096){
        candidate = k;
        if(
                (sys_vtpmo(candidate) != NO_MAP)
                ){
            // check if candidate maintains the syscall_table
            if(validate_page( (unsigned long *)candidate, hacked_syscall_tbl, hacked_ni_syscall) ){
                printk("%s: syscall table found at %px\n",MODNAME,(void*)(*hacked_syscall_tbl));
                printk("%s: sys_ni_syscall found at %px\n",MODNAME,(void*)(*hacked_ni_syscall));
                break;
            }
        }
    }

}