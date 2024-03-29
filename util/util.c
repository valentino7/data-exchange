
#include <linux/mm.h>
#include <linux/shm.h>
#include <linux/init.h>
#include <linux/msg.h>
#include <linux/vmalloc.h>
#include <linux/slab.h>
#include <linux/notifier.h>
#include <linux/capability.h>
#include <linux/highuid.h>
#include <linux/security.h>
#include <linux/rcupdate.h>
#include <linux/workqueue.h>
#include <linux/seq_file.h>
#include <linux/proc_fs.h>
#include <linux/nsproxy.h>
#include <linux/rwsem.h>
#include <linux/memory.h>
#include <linux/ipc_namespace.h>
#include <linux/idr.h>
#include "util.h"
#include <linux/rhashtable.h>
#include <asm/unistd.h>



#define RESTRICT 0
#define NO_RESTRICT 1

extern struct ipc_ids *ids;
int ipc_min_cycle = RADIX_TREE_MAP_SIZE;

struct ipc_proc_iface {
	const char *path;
	const char *header;
	int (*show)(struct seq_file *, void *);
};

/**
 * ipc_init - initialise ipc subsystem
 *
 * The various sysv ipc resources (semaphores, messages and shared
 * memory) are initialised.
 *
 * A callback routine is registered into the memory hotplug notifier
 * chain: since msgmni scales to lowmem this callback routine will be
 * called upon successful memory add / remove to recompute msmgni.
 */


static const struct rhashtable_params ipc_kht_params = {
        .head_offset		= offsetof(struct kern_ipc_perm, khtnode),
        .key_offset		= offsetof(struct kern_ipc_perm, key),
        .key_len		= sizeof_field(struct kern_ipc_perm, key),
        .automatic_shrinking	= true,
};
/**
 * ipc_init_ids	- initialise ipc identifiers
 *
 * Set up the sequence range to use for the ipc identifier range (limited
 * below IPCMNI) then initialise the keys hashtable and ids idr.
 */
int ipc_init_ids(void)
{
	int err;

    ids = kmalloc(sizeof(struct ipc_ids), GFP_KERNEL);

	ids->in_use = 0;
	ids->seq = 0;
	init_rwsem(&(ids->rwsem));
	err = rhashtable_init(&(ids->key_ht), &(ipc_kht_params));
	if (err)
		return err;
	idr_init(&(ids->ipcs_idr));
	ids->max_idx = -1;
    ids->last_idx = -1;
#ifdef CONFIG_CHECKPOINT_RESTORE
	ids->next_id = -1;
#endif
	return 0;
}


#ifdef CONFIG_PROC_FS
static const struct proc_ops sysvipc_proc_ops;
/**
 * ipc_init_proc_interface -  create a proc interface for sysipc types using a seq_file interface.
 * @path: Path in procfs
 * @header: Banner to be printed at the beginning of the file.
 * @ids: ipc id table to iterate.
 * @show: show routine.
 */
void ipc_init_proc_interface(const char *path, const char *header, int (*show)(struct seq_file *, void *))
{
	struct proc_dir_entry *pde;
	struct ipc_proc_iface *iface;

	iface = kmalloc(sizeof(*iface), GFP_KERNEL);
	if (!iface)
		return;
	iface->path	= path;
	iface->header	= header;
//	iface->ids	= ids;
	iface->show	= show;

	pde = proc_create_data(path,
			       S_IRUGO,        /* world readable */
			       NULL,           /* parent dir */
			       &sysvipc_proc_ops,
			       iface);
	if (!pde)
		kfree(iface);
}
#endif


/**
 * ipc_findkey	- find a key in an ipc identifier set
 * @key: key to find
 *
 * Returns the locked pointer to the ipc structure if found or NULL
 * otherwise. If key is found ipc points to the owning ipc structure
 *
 * Called with writer ipc_ids.rwsem held.
 */
static struct kern_ipc_perm *ipc_findkey( key_t key)
{

    struct kern_ipc_perm *ipcp;

    //rcu lock all interno
    ipcp = rhashtable_lookup_fast(&(ids->key_ht), &(key),
                                  ipc_kht_params);
    if (!ipcp)
        return NULL;

    rcu_read_lock();
    ipc_lock_object(ipcp);
    return ipcp;
}

/*
 * Insert new IPC object into idr tree, and set sequence number and id
 * in the correct order.
 * Especially:
 * - the sequence number must be set before inserting the object into the idr,
 *   because the sequence number is accessed without a lock.
 * - the id can/must be set after inserting the object into the idr.
 *   All accesses must be done after getting kern_ipc_perm.lock.
 *
 * The caller must own kern_ipc_perm.lock.of the new object.
 * On error, the function returns a (negative) error code.
 *
 * To conserve sequence number space, especially with extended ipc_mni,
 * the sequence number is incremented only when the returned ID is less than
 * the last one.
 */
static inline int ipc_idr_alloc(struct kern_ipc_perm *new)
{
    int idx, next_id = -1;

#ifdef CONFIG_CHECKPOINT_RESTORE
    next_id = ids->next_id;
	ids->next_id = -1;
#endif

    /*
     * As soon as a new object is inserted into the idr,
     * ipc_obtain_object_idr() or ipc_obtain_object_check() can find it,
     * and the lockless preparations for ipc operations can start.
     * This means especially: permission checks, audit calls, allocation
     * of undo structures, ...
     *
     * Thus the object must be fully initialized, and if something fails,
     * then the full tear-down sequence must be followed.
     * (i.e.: set new->deleted, reduce refcount, call_rcu())
     */

    if (next_id < 0) { /* !CHECKPOINT_RESTORE or next_id is unset */
        int max_idx;

        max_idx = max(ids->in_use*3/2, ipc_min_cycle);
        max_idx = min(max_idx, IPCMNI);

        /* allocate the idx, with a NULL struct kern_ipc_perm */
        idx = idr_alloc_cyclic(&(ids->ipcs_idr), NULL, 0, max_idx,
                               GFP_NOWAIT);

        if (idx >= 0) {
            /*
             * idx got allocated successfully.
             * Now calculate the sequence number and set the
             * pointer for real.
             */
            if (idx <= ids->last_idx) {
                ids->seq++;
                if (ids->seq >= ipcid_seq_max())
                    ids->seq = 0;
            }
            ids->last_idx = idx;

            new->seq = ids->seq;
            /* no need for smp_wmb(), this is done
             * inside idr_replace, as part of
             * rcu_assign_pointer
             */
            idr_replace(&(ids->ipcs_idr), new, idx);
        }
    } else {
        new->seq = ipcid_to_seqx(next_id);
        idx = idr_alloc(&(ids->ipcs_idr), new, ipcid_to_idx(next_id),
                        0, GFP_NOWAIT);
    }
    if (idx >= 0)
        new->id = (new->seq << ipcmni_seq_shift()) + idx;
    return idx;
}



/**
 * ipc_addid - add an ipc identifier
 * @new: new ipc permission set
 * @limit: limit for the number of used ids
 *
 * Add an entry 'new' to the ipc ids idr. The permissions object is
 * initialised and the first free entry is set up and the index assigned
 * is returned. The 'new' entry is returned in a locked state on success.
 *
 * On failure the entry is not locked and a negative err-code is returned.
 * The caller must use ipc_rcu_putref() to free the identifier.
 *
 * Called with writer ipc_ids.rwsem held.
 */
int ipc_addid( struct kern_ipc_perm *new, int limit)
{
	kuid_t euid;
	kgid_t egid;
	int idx, err;

    /* 1) Initialize the refcount so that ipc_rcu_putref works */
    refcount_set(&(new->refcount), 1);
    if (limit > IPCMNI)
        limit = IPCMNI;

    if (ids->in_use >= limit)
        return -ENOSPC;

    idr_preload(GFP_KERNEL);

    spin_lock_init(&(new->lock));
    rcu_read_lock();
    spin_lock(&(new->lock));


	current_euid_egid(&euid, &egid);
	new->cuid = new->uid = euid;
	new->gid = new->cgid = egid;


    new->deleted = false;

    idx = ipc_idr_alloc(new);
    idr_preload_end();

    if (idx >= 0 && new->key != IPC_PRIVATE) {
        /*params:
         * hashtable
         * obj
         * hashtable parameters
         */
        err = rhashtable_insert_fast(&(ids->key_ht), &(new->khtnode),
                                     ipc_kht_params);
        if (err < 0) {
            idr_remove(&ids->ipcs_idr, idx);
            idx = err;
        }
    }
    if (idx < 0) {
        new->deleted = true;
        spin_unlock(&(new->lock));
        rcu_read_unlock();
        return idx;
    }

    ids->in_use++;
    if (idx > ids->max_idx)
        ids->max_idx = idx;
    return idx;

}


msg_queue* alloc_and_fill_tag_service(void) {
    int i;
    struct _tag_elem *new = kmalloc(sizeof(struct _tag_elem), GFP_KERNEL);
    if(new==NULL){
        return ERR_PTR(-ENOMEM);
    }

    new->pid_creator = current->pid;
    new->level = (struct _tag_level *) kmalloc(32 * sizeof(struct _tag_level), GFP_KERNEL);

    if(new->level==NULL){
        return ERR_PTR(-ENOMEM);
    }



    //inizializzo le 32 wait queue
    rwlock_init(&(new->tag_lock));

    for (i = 0; i < 32; i++) {

        new->level[i].group = kmalloc(sizeof(struct _tag_level_group), GFP_KERNEL);

        if(new->level[i].group == NULL){

            return ERR_PTR(-ENOMEM);
        }

        rwlock_init(&(new->level[i].level_lock));


        new->level[i].group->awake = 1;
        init_waitqueue_head(&(new->level[i].group->my_queue));

    }
    return new;
}

int my_newque(struct ipc_params * params){

    int retval;
    msg_queue *msq;

    msq= alloc_and_fill_tag_service();
    if (unlikely(!msq))
        return -ENOMEM;

    msq->q_perm.mode = params->flg;
    msq->q_perm.key = params->key;

    retval = ipc_addid( &(msq->q_perm), MAXIMUM_TAGS);

    if (retval < 0) {
        ipc_rcu_putref(&(msq->q_perm), msg_rcu_free);
        return retval;
    }
    ipc_unlock_object(&(msq->q_perm));
    rcu_read_unlock();
    return msq->q_perm.id;

}

/**
 * ipcget_new -	create a new ipc object
 * @params: its parameters
 *
 * This routine is called by sys_tag_get
 * when the key is IPC_PRIVATE.
 */
static int ipcget_new( struct ipc_params *params)
{
	int err = -1;
    int flg = params->flg>>1;

    if(flg == (IPC_CREAT | IPC_EXCL) || flg == (IPC_CREAT) || flg == (IPC_EXCL) ){
        down_write(&(ids->rwsem));
        err = my_newque(params);
        up_write(&(ids->rwsem));
    }


	return err;
}


/**
 * ipcget_public - get an ipc object or create a new one
 * @params: its parameters
 *
 * This routine is called by sys_tag_get
 * when the key is not IPC_PRIVATE.
 * It adds a new entry if the key is not found and does some permission
 * / security checkings if the key is found.
 *
 * On success, the ipc id is returned.
 */
static int ipcget_public(struct ipc_params * params)
{
	struct kern_ipc_perm *ipcp;
	int flg = params->flg>>1;
	int err;
    int old_permission;
    int new_permission;

	/*
	 * Take the lock as a writer since we are potentially going to add
	 * a new entry + read locks are not "upgradable"
	 */
	err=-1;
    //semaforo condiviso, non accedo finche chi rimuove non ha finito
	down_write(&(ids->rwsem));
	ipcp = ipc_findkey(params->key);

    if(flg == (IPC_CREAT | IPC_EXCL) || flg == (IPC_CREAT) || flg == (IPC_EXCL) ){
        if (ipcp == NULL) {
            /* key not used */
            //l and torna falso quando tutti i bit sono diversi
            if (!(flg & IPC_CREAT))
                err = -ENOENT;
            else
                err = my_newque( params);
        } else {


            kuid_t ceuid;
            ceuid = current_euid();


            // ipc object has been locked by ipc_findkey()
            //se esiste già un tag devo controllare se non sto cambiando le restrizioni
            old_permission = ipcp->mode&1;
            new_permission = params->flg&1;

            if( (old_permission == RESTRICT &&   new_permission == NO_RESTRICT) || (old_permission == NO_RESTRICT &&  new_permission == RESTRICT) ) {
                err = -EPERM;
            }
            //se esiste già un tag devo controllare che il euid è conforme alle restrizioni
            else if( old_permission == RESTRICT &&  ceuid.val != ipcp-> cuid.val) {
                err = -EPERM;
            }
            else if (flg & IPC_CREAT && flg & IPC_EXCL)
                err = -EEXIST;
            else {
                err=ipcp->id;
            }

            ipc_unlock(ipcp);
        }
    }else
        ipc_unlock(ipcp);


    up_write(&(ids->rwsem));

	return err;
}

/**
 * ipc_kht_remove - remove an ipc from the key hashtable
 * @ids: ipc identifier set
 * @ipcp: ipc perm structure containing the key to remove
 *
 * ipc_ids.rwsem (as a writer) and the spinlock for this ID are held
 * before this function is called, and remain locked on the exit.
 */
static void ipc_kht_remove( struct kern_ipc_perm *ipcp)
{
	if (ipcp->key != IPC_PRIVATE)
		rhashtable_remove_fast(&(ids->key_ht), &(ipcp->khtnode),
				       ipc_kht_params);
}

void free_item(void *ptr, void* arg){
    kvfree(ptr);
    ptr=NULL;
}

int remove_object(int id, void* p, void* data){

    struct kern_ipc_perm *ipcp = p;
    msg_queue *msq = container_of(p, msg_queue, q_perm);

    printk("cancello \n");
    ipc_rmid(ipcp);
    kvfree(msq->level);
    kvfree(msq);

    return 0;
}


/**
 * ipc_rmid - remove an ipc identifier
 * @ipcp: ipc perm structure containing the identifier to remove
 *
 * ipc_ids.rwsem (as a writer) and the spinlock for this ID are held
 * before this function is called, and remain locked on the exit.
 */
void ipc_rmid( struct kern_ipc_perm *ipcp)
{
    int idx = ipcid_to_idx(ipcp->id);

    idr_remove(&(ids->ipcs_idr), idx);
    ipc_kht_remove(ipcp);
    ids->in_use--;
    ipcp->deleted = true;

    if (unlikely(idx == ids->max_idx)) {
        do {
            idx--;
            if (idx == -1)
                break;
        } while (!idr_find(&(ids->ipcs_idr), idx));
        ids->max_idx = idx;
    }
}

/**
 * ipc_set_key_private - switch the key of an existing ipc to IPC_PRIVATE
 * @ipcp: ipc perm structure containing the key to modify
 *
 * ipc_ids.rwsem (as a writer) and the spinlock for this ID are held
 * before this function is called, and remain locked on the exit.
 */
void ipc_set_key_private( struct kern_ipc_perm *ipcp)
{
	ipc_kht_remove(ipcp);
	ipcp->key = IPC_PRIVATE;
}

bool ipc_rcu_getref(struct kern_ipc_perm *ptr)
{
	return refcount_inc_not_zero(&(ptr->refcount));
}

void msg_rcu_free(struct rcu_head *head)
{
    struct kern_ipc_perm *p = container_of(head, struct kern_ipc_perm, rcu);
    msg_queue *msq = container_of(p, msg_queue, q_perm);


    kvfree(msq->level);
    kvfree(msq);
    printk("sono nella call rcu");
}
void ipc_rcu_putref(struct kern_ipc_perm *ptr,
			void (*func)(struct rcu_head *head))
{
    //True se  risultato è 0
    int count = atomic_read(&(ptr->refcount.refs));
    printk("refcount %d \n", count);

    //remove_tag ha messo -1 per indicare che il tag è stato rimosso
	if (count != 1 && count != -1){
        printk("sono tornato \n");
        return;
    }
    printk("sono prima della call rcu");
	call_rcu(&ptr->rcu, func);
}



/**
 * kernel_to_ipc64_perm	- convert kernel ipc permissions to user
 * @in: kernel permissions
 * @out: new style ipc permissions
 *
 * Turn the kernel object @in into a set of permissions descriptions
 * for returning to userspace (@out).
 */
void kernel_to_ipc64_perm(struct kern_ipc_perm *in, struct ipc64_perm *out)
{
    out->key	= in->key;
    out->uid	= from_kuid_munged(current_user_ns(), in->uid);
    out->gid	= from_kgid_munged(current_user_ns(), in->gid);
    out->cuid	= from_kuid_munged(current_user_ns(), in->cuid);
    out->cgid	= from_kgid_munged(current_user_ns(), in->cgid);
    out->mode	= in->mode;
    out->seq	= in->seq;
}
/**
 * ipc64_perm_to_ipc_perm - convert new ipc permissions to old
 * @in: new style ipc permissions
 * @out: old style ipc permissions
 *
 * Turn the new style permissions object @in into a compatibility
 * object and store it into the @out pointer.
 */
void ipc64_perm_to_ipc_perm(struct ipc64_perm *in, struct ipc_perm *out)
{
    out->key	= in->key;
    SET_UID(out->uid, in->uid);
    SET_GID(out->gid, in->gid);
    SET_UID(out->cuid, in->cuid);
    SET_GID(out->cgid, in->cgid);
    out->mode	= in->mode;
    out->seq	= in->seq;
}


/**
 * ipc_obtain_object_idr
 * @id: ipc id to look for
 *
 * Look for an id in the ipc ids idr and return associated ipc object.
 *
 * Call inside the RCU critical section.
 * The ipc object is *not* locked on exit.
 */
struct kern_ipc_perm *ipc_obtain_object_idr(int id)
{
    struct kern_ipc_perm *out;
    int idx = ipcid_to_idx(id);

    out = idr_find(&(ids->ipcs_idr), idx);


    if (!out)
        return ERR_PTR(-EINVAL);

    return out;
}

/**
 * ipc_lock - lock an ipc structure without rwsem held
 * @id: ipc id to look for
 *
 * Look for an id in the ipc ids idr and lock the associated ipc object.
 *
 * The ipc object is locked on successful exit.
 */
struct kern_ipc_perm *ipc_lock( int id)
{
	struct kern_ipc_perm *out;

	rcu_read_lock();
	out = ipc_obtain_object_idr( id);
	if (IS_ERR(out))
		goto err;

	spin_lock(&(out->lock));

	/*
	 * ipc_rmid() may have already freed the ID while ipc_lock()
	 * was spinning: here verify that the structure is still valid.
	 * Upon races with RMID, return -EIDRM, thus indicating that
	 * the ID points to a removed identifier.
	 */
	if (ipc_valid_object(out))
		return out;

	spin_unlock(&(out->lock));
	out = ERR_PTR(-EIDRM);
err:
	rcu_read_unlock();
	return out;
}

/**
 * ipc_obtain_object_check
 * @id: ipc id to look for
 *
 * Similar to ipc_obtain_object_idr() but also checks
 * the ipc object reference counter.
 *
 * Call inside the RCU critical section.
 * The ipc object is *not* locked on exit.
 */
struct kern_ipc_perm *ipc_obtain_object_check( int id)
{
	struct kern_ipc_perm *out = ipc_obtain_object_idr( id);

	if (IS_ERR(out))
		goto out;

	if (ipc_checkid(out, id))
		return ERR_PTR(-EINVAL);
out:
	return out;
}

/**
 * ipcctl_obtain_check - retrieve an ipc object and check permissions
 * @ns:  ipc namespace
 * @ids:  the table of ids where to look for the ipc
 * @id:   the id of the ipc to retrieve
 * @cmd:  the cmd to check
 * @perm: the permission to set
 * @extra_perm: one extra permission parameter used by msq
 *
 * This function does some common audit and permissions check for some IPC_XXX
 * cmd and is called from semctl_down, shmctl_down and msgctl_down.
 *
 * It:
 *   - retrieves the ipc object with the given id in the given table.
 *   - performs some audit and permission check, depending on the given cmd
 *   - returns a pointer to the ipc object or otherwise, the corresponding
 *     error.
 *
 * Call holding the both the rwsem and the rcu read lock.
 */
struct kern_ipc_perm *ipcctl_obtain_check(int id)
{
    int err = -EPERM;
    struct kern_ipc_perm *ipcp;

    ipcp = ipc_obtain_object_check(id);
    if (IS_ERR(ipcp)) {
        err = PTR_ERR(ipcp);
        goto err;
    }
    return ipcp;
    err:
    return ERR_PTR(err);
}


/**
 * ipcget - Common sys_*get() code
 * @params: the parameters needed by the previous operations.
 *
 * Common routine called by sys_tag_get()
 */
int ipcget(struct ipc_params *params)
{
	if (params->key == IPC_PRIVATE){
        return ipcget_new( params);
    }
	else{
        return ipcget_public( params);
    }

}



#ifdef CONFIG_ARCH_WANT_IPC_PARSE_VERSION


/**
 * ipc_parse_version - ipc call version
 * @cmd: pointer to command
 *
 * Return IPC_64 for new style IPC and IPC_OLD for old style IPC.
 * The @cmd value is turned from an encoding command and version into
 * just the command code.
 */
int ipc_parse_version(int *cmd)
{
	if (*cmd & IPC_64) {
		*cmd ^= IPC_64;
		return IPC_64;
	} else {
		return IPC_OLD;
	}
}

#endif /* CONFIG_ARCH_WANT_IPC_PARSE_VERSION */

#ifdef CONFIG_PROC_FS
struct ipc_proc_iter {
	struct ipc_proc_iface *iface;
};

/*
 * This routine locks the ipc structure found at least at position pos.
 */
static struct kern_ipc_perm *sysvipc_find_ipc( loff_t pos,
					      loff_t *new_pos)
{
	struct kern_ipc_perm *ipc;
	int total, id;

	total = 0;
	for (id = 0; id < pos && total < ids->in_use; id++) {
		ipc = idr_find(&(ids->ipcs_idr), id);
		if (ipc != NULL)
			total++;
	}

	ipc = NULL;
	if (total >= ids->in_use)
		goto out;

	for (; pos < IPCMNI; pos++) {
		ipc = idr_find(&(ids->ipcs_idr), pos);
		if (ipc != NULL) {
			rcu_read_lock();
			break;
		}
	}
out:
	*new_pos = pos + 1;
	return ipc;
}

static void *sysvipc_proc_next(struct seq_file *s, void *it, loff_t *pos)
{

	return sysvipc_find_ipc( *pos, pos);
}

/*
 * File positions: pos 0 -> header, pos n -> ipc id = n - 1.
 * SeqFile iterator: iterator value locked ipc pointer or SEQ_TOKEN_START.
 */
static void *sysvipc_proc_start(struct seq_file *s, loff_t *pos)
{

	/*
	 * Take the lock - this will be released by the corresponding
	 * call to stop().
	 */
	down_read(&(ids->rwsem));

	/* pos < 0 is invalid */
	if (*pos < 0)
		return NULL;

	/* pos == 0 means header */
	if (*pos == 0)
		return SEQ_START_TOKEN;

	/* Find the (pos-1)th ipc */
	return sysvipc_find_ipc( *pos - 1, pos);
}

static void sysvipc_proc_stop(struct seq_file *s, void *it)
{
	up_read(&(ids->rwsem));
}

int sysvipc_proc_show(struct seq_file *s, void *it)
{
	struct ipc_proc_iter *iter = s->private;
	struct ipc_proc_iface *iface = iter->iface;

	if (it == SEQ_START_TOKEN) {
		seq_puts(s, iface->header);
		return 0;
	}

	return iface->show(s, it);
}

static const struct seq_operations sysvipc_proc_seqops = {
	.start = sysvipc_proc_start,
	.stop  = sysvipc_proc_stop,
	.next  = sysvipc_proc_next,
	.show  = sysvipc_proc_show,
};

static int sysvipc_proc_open(struct inode *inode, struct file *file)
{
	struct ipc_proc_iter *iter;

	iter = __seq_open_private(file, &(sysvipc_proc_seqops), sizeof(*iter));
	if (!iter)
		return -ENOMEM;

	iter->iface = PDE_DATA(inode);
	return 0;
}

static int sysvipc_proc_release(struct inode *inode, struct file *file)
{
	return seq_release_private(inode, file);
}

static const struct proc_ops sysvipc_proc_ops = {
	.proc_flags	= PROC_ENTRY_PERMANENT,
	.proc_open	= sysvipc_proc_open,
	.proc_read	= seq_read,
	.proc_lseek	= seq_lseek,
	.proc_release	= sysvipc_proc_release,
};
#endif /* CONFIG_PROC_FS */

