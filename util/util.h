/* SPDX-License-Identifier: GPL-2.0 */
/*
 * linux/ipc/util.h
 * Copyright (C) 1999 Christoph Rohland
 *
 * ipc helper functions (c) 1999 Manfred Spraul <manfred@colorfullife.com>
 * namespaces support.      2006 OpenVZ, SWsoft Inc.
 *                               Pavel Emelianov <xemul@openvz.org>
 */
#ifndef _IPC_UTIL_H
#define _IPC_UTIL_H

#include <linux/unistd.h>
#include <linux/err.h>
#include <linux/ipc_namespace.h>
#include <linux/ipc.h>

/*
 * The IPC ID contains 2 separate numbers - index and sequence number.
 * By default,
 *   bits  0-14: index (32k, 15 bits)
 *   bits 15-30: sequence number (64k, 16 bits)
 *
 * When IPCMNI extension mode is turned on, the composition changes:
 *   bits  0-23: index (16M, 24 bits)
 *   bits 24-30: sequence number (128, 7 bits)
 */
#define IPCMNI_SHIFT		15
#define IPCMNI_EXTEND_SHIFT	24
#define IPCMNI_EXTEND_MIN_CYCLE	(RADIX_TREE_MAP_SIZE * RADIX_TREE_MAP_SIZE)
#define IPCMNI			(1 << IPCMNI_SHIFT)
#define IPCMNI_EXTEND		(1 << IPCMNI_EXTEND_SHIFT)

#ifdef CONFIG_SYSVIPC_SYSCTL
//extern int ipc_mni = IPCMNI ;
//extern int ipc_mni_shift = IPCMNI_SHIFT;
//extern ipc_min_cycle = RADIX_TREE_MAP_SIZE;

#define ipcmni_seq_shift()	IPCMNI_SHIFT
#define IPCMNI_IDX_MASK		((1 << IPCMNI_SHIFT) - 1)

#else /* CONFIG_SYSVIPC_SYSCTL */

#define ipc_mni			IPCMNI
#define ipc_min_cycle		((int)RADIX_TREE_MAP_SIZE)
#define ipcmni_seq_shift()	IPCMNI_SHIFT
#define IPCMNI_IDX_MASK		((1 << IPCMNI_SHIFT) - 1)
#endif /* CONFIG_SYSVIPC_SYSCTL */
#define MAXIMUM_TAGS 3




#define SEQ_MULTIPLIER	(IPCMNI)

int sem_init(void);
int msg_init(void);
void shm_init(void);


#ifdef CONFIG_POSIX_MQUEUE
extern void mq_clear_sbinfo(struct ipc_namespace *ns);
extern void mq_put_mnt(struct ipc_namespace *ns);
#else
static inline void mq_clear_sbinfo(struct ipc_namespace *ns) { }
static inline void mq_put_mnt(struct ipc_namespace *ns) { }
#endif

#ifdef CONFIG_SYSVIPC
void sem_init_ns(struct ipc_namespace *ns);
void msg_init_ns(struct ipc_namespace *ns);
void shm_init_ns(struct ipc_namespace *ns);

void sem_exit_ns(struct ipc_namespace *ns);
void msg_exit_ns(struct ipc_namespace *ns);
void shm_exit_ns(struct ipc_namespace *ns);
#else
static inline void sem_init_ns(struct ipc_namespace *ns) {  }
static inline void msg_init_ns(struct ipc_namespace *ns) {  }
static inline void shm_init_ns(struct ipc_namespace *ns) {  }

static inline void sem_exit_ns(struct ipc_namespace *ns) { }
static inline void msg_exit_ns(struct ipc_namespace *ns) { }
static inline void shm_exit_ns(struct ipc_namespace *ns) { }
#endif

/*
 * Structure that holds the parameters needed by the ipc operations
 * (see after)
 */
struct ipc_params {
	key_t key;
	int flg;
	union {
		size_t size;	/* for shared memories */
		int nsems;	/* for semaphores */
	} u;			/* holds the getnew() specific param */
};
#define MAX_MSG_SIZE 4096
struct _tag_level_group{
    int awake  ;
    unsigned long num_thread __attribute__((aligned(8)));
    char kernel_buff[MAX_MSG_SIZE];
    spinlock_t lock_presence_counter;
};

struct _tag_level{
    int level_awake  ;
    unsigned long num_thread __attribute__((aligned(8)));
    wait_queue_head_t my_queue;
    struct _tag_level_group* group;
    //spinlock_t queue_lock;
    rwlock_t level_lock;

};

//almeno 256 servizi runnabili
typedef struct _tag_elem{
    struct kern_ipc_perm q_perm;
    struct _tag_level* level;
    int num_thread_per_tag __attribute__((aligned(8)));
    rwlock_t tag_lock;
    pid_t pid_creator;
//    int tag;
//    int key;

    //lock per rimuovere in manierea sicura
//    spinlock_t tag_lock;
    //contatore accessi


//    struct list_head node;
//    struct rcu_head rcu;
//    struct _tag_elem * next;
//    struct _tag_elem * prev;
    //tid creator
} msg_queue;

extern struct ipc_ids *ids;

int my_newque(struct ipc_params * params);




struct seq_file;

int ipc_init_ids(void);
#ifdef CONFIG_PROC_FS
void ipc_init_proc_interface(const char *path, const char *header, int (*show)(struct seq_file *, void *));
#else
#define ipc_init_proc_interface(path, header, show) do {} while (0)
#endif

//void ipc_init_proc_interface(const char *path, const char *header, int ids, int (*show)(struct seq_file *, void *));
static int sysvipc_proc_show(struct seq_file *s , void * it);
void ipc_init(void);


#define ipcid_to_idx(id)  ((id) & IPCMNI_IDX_MASK)
#define ipcid_to_seqx(id) ((id) >> ipcmni_seq_shift())
#define ipcid_seq_max()	  (INT_MAX >> ipcmni_seq_shift())

/* must be called with ids->rwsem acquired for writing */
int ipc_addid(struct kern_ipc_perm *, int);

/* must be called with both locks acquired. */
void ipc_rmid( struct kern_ipc_perm *);

/* must be called with both locks acquired. */
void ipc_set_key_private( struct kern_ipc_perm *);

/* must be called with ipcp locked */
int ipcperms(struct ipc_namespace *ns, struct kern_ipc_perm *ipcp, short flg);

/**
 * ipc_get_maxidx - get the highest assigned index
 * @ids: ipc identifier set
 *
 * Called with ipc_ids.rwsem held for reading.
 */
static inline int ipc_get_maxidx(struct ipc_ids *ids)
{
    if (ids->in_use == 0)
        return -1;

    if (ids->in_use == IPCMNI)
        return IPCMNI - 1;

    return ids->max_idx;
}

/*
 * For allocation that need to be freed by RCU.
 * Objects are reference counted, they start with reference count 1.
 * getref increases the refcount, the putref call that reduces the recount
 * to 0 schedules the rcu destruction. Caller must guarantee locking.
 *
 * refcount is initialized by ipc_addid(), before that point call_rcu()
 * must be used.
 */
bool ipc_rcu_getref(struct kern_ipc_perm *ptr);
void ipc_rcu_putref(struct kern_ipc_perm *ptr,
			void (*func)(struct rcu_head *head));



struct kern_ipc_perm *ipc_obtain_object_idr( int id);

struct kern_ipc_perm *ipcctl_obtain_check( int id);

void kernel_to_ipc64_perm(struct kern_ipc_perm *in, struct ipc64_perm *out);
void ipc64_perm_to_ipc_perm(struct ipc64_perm *in, struct ipc_perm *out);
int ipc_update_perm(struct ipc64_perm *in, struct kern_ipc_perm *out);



//struct kern_ipc_perm *ipcctl_pre_down_nolock( int id);

#ifndef CONFIG_ARCH_WANT_IPC_PARSE_VERSION
/* On IA-64, we always use the "64-bit version" of the IPC structures.  */
# define ipc_parse_version(cmd)	IPC_64
#else
int ipc_parse_version(int *cmd);
#endif

/*extern void free_msg(struct msg_msg *msg);
extern struct msg_msg *load_msg(const void __user *src, size_t len);
extern struct msg_msg *copy_msg(struct msg_msg *src, struct msg_msg *dst);
extern int store_msg(void __user *dest, struct msg_msg *msg, size_t len);*/

static inline int ipc_checkid(struct kern_ipc_perm *ipcp, int id)
{
    return ipcid_to_seqx(id) != ipcp->seq;
}

static inline void ipc_lock_object(struct kern_ipc_perm *perm)
{
    spin_lock(&perm->lock);
}

static inline void ipc_unlock_object(struct kern_ipc_perm *perm)
{
    spin_unlock(&perm->lock);
}

static inline void ipc_assert_locked_object(struct kern_ipc_perm *perm)
{
    assert_spin_locked(&perm->lock);
}

static inline void ipc_unlock(struct kern_ipc_perm *perm)
{
    ipc_unlock_object(perm);
    rcu_read_unlock();
}



/*
 * ipc_valid_object() - helper to sort out IPC_RMID races for codepaths
 * where the respective ipc_ids.rwsem is not being held down.
 * Checks whether the ipc object is still around or if it's gone already, as
 * ipc_rmid() may have already freed the ID while the ipc lock was spinning.
 * Needs to be called with kern_ipc_perm.lock held -- exception made for one
 * checkpoint case at sys_semtimedop() as noted in code commentary.
 */
static inline bool ipc_valid_object(struct kern_ipc_perm *perm)
{
	return !perm->deleted;
}

struct kern_ipc_perm *ipc_obtain_object_check(int id);
int ipcget(  struct ipc_params *params);
void free_ipcs(struct ipc_namespace *ns,
		void (*free)(struct ipc_namespace *, struct kern_ipc_perm *));

#ifdef CONFIG_COMPAT
#include <linux/compat.h>
struct compat_ipc_perm {
	key_t key;
	__compat_uid_t uid;
	__compat_gid_t gid;
	__compat_uid_t cuid;
	__compat_gid_t cgid;
	compat_mode_t mode;
	unsigned short seq;
};

void to_compat_ipc_perm(struct compat_ipc_perm *, struct ipc64_perm *);
void to_compat_ipc64_perm(struct compat_ipc64_perm *, struct ipc64_perm *);
int get_compat_ipc_perm(struct ipc64_perm *, struct compat_ipc_perm __user *);
int get_compat_ipc64_perm(struct ipc64_perm *,
			  struct compat_ipc64_perm __user *);

static inline int compat_ipc_parse_version(int *cmd)
{
#ifdef	CONFIG_ARCH_WANT_COMPAT_IPC_PARSE_VERSION
	int version = *cmd & IPC_64;
	*cmd &= ~IPC_64;
	return version;
#else
	return IPC_64;
#endif
}
#endif
#endif

