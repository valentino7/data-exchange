#include "../util/util.h"

int my_newque(struct ipc_params * params);

#define MAX_MSG_SIZE 4096

typedef struct _tag_level_group{
    int awake  ;
    unsigned long num_thread __attribute__((aligned(8)));
    char kernel_buff[MAX_MSG_SIZE];
    spinlock_t lock_presence_counter;
} group;

typedef struct _tag_level{
    int level_awake  ;
    unsigned long num_thread __attribute__((aligned(8)));
    wait_queue_head_t my_queue;
    struct _tag_level_group* group;
    spinlock_t queue_lock;
} level;

//almeno 256 servizi runnabili
typedef struct _tag_elem{
    struct kern_ipc_perm q_perm;

    struct _tag_level* level;
    int tag;
    int key;

    spinlock_t tag_lock;

    int num_thread_per_tag __attribute__((aligned(8)));


    struct list_head node;
    struct rcu_head rcu;

    struct _tag_elem * next;
    struct _tag_elem * prev;
    //tid creator
} elem;

struct ipc_ids *ids;
