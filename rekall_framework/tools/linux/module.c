/*
  This module does absolutely nothing at all. We just build it with debugging
  symbols and then read the DWARF symbols from it.  */

#include <linux/kconfig.h>

#include <linux/module.h>
#include <linux/version.h>

#include <linux/fs_struct.h>
#include <linux/fs.h>
#include <linux/proc_fs.h>
#include <linux/utsname.h>
#include <net/tcp.h>
#include <net/route.h>
#include <net/udp.h>
#include <net/sock.h>
#include <asm/alternative.h>
#include <linux/mount.h>
#include <linux/inetdevice.h>
/* used for SYSTEM V shared memory */
#include <linux/shm.h>
#include <linux/ipc.h>
/* SYSTEM V END */

/* included for vm_area_struct's anon_vma and anon_vma_chain members */
#include <linux/rmap.h>
/* anon_vma END */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,26)
#include <linux/fdtable.h>
#include <linux/elf.h>
#else
#include <linux/file.h>
#endif

#include <net/ip_fib.h>
#include <net/af_unix.h>
#include <linux/pid.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,20)
#include <linux/pid_namespace.h>
struct pid_namespace pid_namespace;
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,18)
#include <linux/clocksource.h>
#include <linux/ktime.h>
#endif


#include <linux/radix-tree.h>
#include <linux/netfilter.h>
#include <linux/netfilter/x_tables.h>
#include <net/tcp.h>
#include <net/udp.h>

#include <linux/termios.h>
#include <asm/termbits.h>

#include <linux/notifier.h>
struct atomic_notifier_head atomic_notifier_head;

#include <linux/tty_driver.h>
struct tty_driver tty_driver;

#include <linux/tty.h>
struct tty_struct tty_struct;

struct udp_seq_afinfo udp_seq_afinfo;
struct tcp_seq_afinfo tcp_seq_afinfo;

struct files_struct files_struct;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,19)
struct uts_namespace uts_namespace;
#endif

struct socket_alloc socket_alloc;
struct sock sock;
struct inet_sock inet_sock;
struct vfsmount vfsmount;
struct in_device in_device;
struct fib_table fib_table;
struct unix_sock unix_sock;
struct pid pid;
struct radix_tree_root radix_tree_root;
#ifdef CONFIG_NETFILTER
struct nf_hook_ops nf_hook_ops;
struct nf_sockopt_ops nf_sockopt_ops;
#endif

/* Elf structures. We use the names from the ELF standard:

http://downloads.openwatcom.org/ftp/devel/docs/elf-64-gen.pdf
*/
Elf64_Ehdr A1;
Elf64_Shdr A2;
Elf64_Sym A3;
Elf64_Rel A4;
Elf64_Rela A5;
Elf64_Phdr A6;
Elf64_Dyn A7;
Elf64_Nhdr A8;

struct xt_table xt_table;

/********************************************************************
The following structs are not defined in headers, so we cant import
them. Hopefully they dont change too much.
*********************************************************************/

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,24)
#include <net/net_namespace.h>
#endif

#include <net/ip.h>
#include <net/protocol.h>
#include <net/sock.h>
#include <net/ip_fib.h>
#include <linux/compiler.h>

#define EMBEDDED_HASH_SIZE (L1_CACHE_BYTES / sizeof(struct hlist_head))

#define __rcu

struct fn_zone {
  struct fn_zone     *fz_next;       /* Next not empty zone  */
  struct hlist_head  *fz_hash;       /* Hash table pointer   */
  seqlock_t               fz_lock;
  u32                     fz_hashmask;    /* (fz_divisor - 1)     */
  u8                      fz_order;       /* Zone order (0..32)   */
  u8                      fz_revorder;    /* 32 - fz_order        */
  __be32                  fz_mask;        /* inet_make_mask(order) */

  struct hlist_head       fz_embedded_hash[EMBEDDED_HASH_SIZE];

  int                     fz_nent;        /* Number of entries    */
  int                     fz_divisor;     /* Hash size (mask+1)   */
} fn_zone;

struct fn_hash {
  struct fn_zone    *fn_zones[33];
  struct fn_zone    *fn_zone_list;
} fn_hash;

struct fib_alias
{
    struct list_head        fa_list;
    struct fib_info         *fa_info;
    u8                      fa_tos;
    u8                      fa_type;
    u8                      fa_scope;
    u8                      fa_state;
#ifdef CONFIG_IP_FIB_TRIE
        struct rcu_head         rcu;
#endif
};

struct fib_node
{
    struct hlist_node       fn_hash;
    struct list_head        fn_alias;
    __be32                  fn_key;
    struct fib_alias        fn_embedded_alias;
};


struct fib_node fib_node;
struct fib_alias fib_alias;

/****************************************
 * RADIX_TREE START
 ****************************************/

struct rt_hash_bucket {
  struct rtable __rcu     *chain;
} rt_hash_bucket;


/* RedHat Enterprise kernels moved the radix_tree_node definition out of
   lib/radix-tree.c earlier than 3.15 so a simple LINUX_VERSION_CODE check
   doesn't work. We resort to checking if RADIX_TREE_MAP_SHIFT is defined
   instead as it's very closely related to struct radix_tree_node existing.
*/
#ifndef RADIX_TREE_MAP_SHIFT

#define RADIX_TREE_MAP_SHIFT    (CONFIG_BASE_SMALL ? 4 : 6)
#define RADIX_TREE_MAP_SIZE     (1UL << RADIX_TREE_MAP_SHIFT)
#define RADIX_TREE_MAP_MASK     (RADIX_TREE_MAP_SIZE-1)
#define RADIX_TREE_TAG_LONGS    ((RADIX_TREE_MAP_SIZE + BITS_PER_LONG - 1) / BITS_PER_LONG)

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,3,0)
struct radix_tree_node {
    unsigned int    height;         /* Height from the bottom */
    unsigned int    count;
    union {
        struct radix_tree_node *parent; /* Used when ascending tree */
        struct rcu_head rcu_head;       /* Used when freeing node */
    };
    void            *slots[RADIX_TREE_MAP_SIZE];
    unsigned long   tags[RADIX_TREE_MAX_TAGS][RADIX_TREE_TAG_LONGS];
};

#else

struct radix_tree_node {
    unsigned int    height;         /* Height from the bottom */
    unsigned int    count;
    struct rcu_head rcu_head;
    void            *slots[RADIX_TREE_MAP_SIZE];
    unsigned long   tags[RADIX_TREE_MAX_TAGS][RADIX_TREE_TAG_LONGS];
};
#endif

#endif

/****************************************
 * RADIX_TREE END
 ****************************************/


#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,25)
struct module_sect_attr
{
        struct module_attribute mattr;
        char *name;
        unsigned long address;
};

struct module_sect_attrs
{
        struct attribute_group grp;
        unsigned int nsections;
        struct module_sect_attr attrs[0];
};
#endif

struct module_sect_attrs module_sect_attrs;

#ifdef CONFIG_SLAB

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,31)

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,22)
/*
 * struct kmem_cache
 *
 * manages a cache.
 */

struct kmem_cache {
/* 1) per-cpu data, touched during every alloc/free */
        struct array_cache *array[NR_CPUS];
/* 2) Cache tunables. Protected by cache_chain_mutex */
        unsigned int batchcount;
        unsigned int limit;
        unsigned int shared;

        unsigned int buffer_size;
        u32 reciprocal_buffer_size;
/* 3) touched by every alloc & free from the backend */

        unsigned int flags;             /* constant flags */
        unsigned int num;               /* # of objs per slab */

/* 4) cache_grow/shrink */
        /* order of pgs per slab (2^n) */
        unsigned int gfporder;

        /* force GFP flags, e.g. GFP_DMA */
        gfp_t gfpflags;

        size_t colour;                  /* cache colouring range */
        unsigned int colour_off;        /* colour offset */
        struct kmem_cache *slabp_cache;
        unsigned int slab_size;
        unsigned int dflags;            /* dynamic flags */

        /* constructor func */
        void (*ctor)(void *obj);

/* 5) cache creation/removal */
        const char *name;
        struct list_head next;

/* 6) statistics */
#if STATS
        unsigned long num_active;
        unsigned long num_allocations;
        unsigned long high_mark;
        unsigned long grown;
        unsigned long reaped;
        unsigned long errors;
        unsigned long max_freeable;
        unsigned long node_allocs;
        unsigned long node_frees;
        unsigned long node_overflow;
        atomic_t allochit;
        atomic_t allocmiss;
        atomic_t freehit;
        atomic_t freemiss;
#endif
#if DEBUG
        /*
         * If debugging is enabled, then the allocator can add additional
         * fields and/or padding to every object. buffer_size contains the total
         * object size including these internal fields, the following two
         * variables contain the offset to the user object and its size.
         */
        int obj_offset;
        int obj_size;
#endif
        /*
         * We put nodelists[] at the end of kmem_cache, because we want to size
         * this array to nr_node_ids slots instead of MAX_NUMNODES
         * (see kmem_cache_init())
         * We still use [MAX_NUMNODES] and not [1] or [0] because cache_cache
         * is statically defined, so we reserve the max number of nodes.
         */
        struct kmem_list3 *nodelists[MAX_NUMNODES];
        /*
         * Do not add fields after nodelists[]
         */
};
#else

struct kmem_cache {
/* 1) per-cpu data, touched during every alloc/free */
        struct array_cache *array[NR_CPUS];
/* 2) Cache tunables. Protected by cache_chain_mutex */
        unsigned int batchcount;
        unsigned int limit;
        unsigned int shared;

        unsigned int buffer_size;
/* 3) touched by every alloc & free from the backend */
        struct kmem_list3 *nodelists[MAX_NUMNODES];

        unsigned int flags;             /* constant flags */
        unsigned int num;               /* # of objs per slab */

/* 4) cache_grow/shrink */
        /* order of pgs per slab (2^n) */
        unsigned int gfporder;

        /* force GFP flags, e.g. GFP_DMA */
        gfp_t gfpflags;

        size_t colour;                  /* cache colouring range */
        unsigned int colour_off;        /* colour offset */
        struct kmem_cache *slabp_cache;
        unsigned int slab_size;
        unsigned int dflags;            /* dynamic flags */

        /* constructor func */
        void (*ctor) (void *, struct kmem_cache *, unsigned long);

        /* de-constructor func */
        void (*dtor) (void *, struct kmem_cache *, unsigned long);

/* 5) cache creation/removal */
        const char *name;
        struct list_head next;

/* 6) statistics */
#if STATS
        unsigned long num_active;
        unsigned long num_allocations;
        unsigned long high_mark;
        unsigned long grown;
        unsigned long reaped;
        unsigned long errors;
        unsigned long max_freeable;
        unsigned long node_allocs;
        unsigned long node_frees;
        unsigned long node_overflow;
        atomic_t allochit;
        atomic_t allocmiss;
        atomic_t freehit;
        atomic_t freemiss;
#endif
#if DEBUG
        /*
         * If debugging is enabled, then the allocator can add additional
         * fields and/or padding to every object. buffer_size contains the total
         * object size including these internal fields, the following two
         * variables contain the offset to the user object and its size.
         */
        int obj_offset;
        int obj_size;
#endif
};

#endif /*kmem_cache decl*/

struct kmem_cache kmem_cache;
#endif

struct kmem_list3 {
         struct list_head slabs_partial; /* partial list first, better asm code */
         struct list_head slabs_full;
         struct list_head slabs_free;
        unsigned long free_objects;
         unsigned int free_limit;
         unsigned int colour_next;       /* Per-node cache coloring */
         spinlock_t list_lock;
         struct array_cache *shared;     /* shared per node */
         struct array_cache **alien;     /* on other nodes */
         unsigned long next_reap;        /* updated without locking */
         int free_touched;               /* updated without locking */
};

struct kmem_list3 kmem_list3;

struct slab {
     struct list_head list;
     unsigned long colouroff;
     void *s_mem;            /* including colour offset */
     unsigned int inuse;     /* num of objs active in slab */
     unsigned int free;
     unsigned short nodeid;
 };

struct slab slab;
#endif


/****************************************
 * TIMEKEEPING START
 ****************************************/

#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 9, 54)
#define cycle_t u64
#endif

#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 11, 7)

struct tk_read_base {
  struct clocksource      *clock;
  u64                     mask;
  u64                     cycle_last;
  u32                     mult;
  u32                     shift;
  u64                     xtime_nsec;
  ktime_t                 base;
};

struct timekeeper {
  struct tk_read_base     tkr_mono;
  struct tk_read_base     tkr_raw;
  u64                     xtime_sec;
  unsigned long           ktime_sec;
  struct timespec64       wall_to_monotonic;
  ktime_t                 offs_real;
  ktime_t                 offs_boot;
  ktime_t                 offs_tai;
  s32                     tai_offset;
  unsigned int            clock_was_set_seq;
  u8                      cs_was_changed_seq;
  ktime_t                 next_leap_ktime;
  struct timespec64       raw_time;

  /* The following members are for timekeeping internal use */
  u64                     cycle_interval;
  u64                     xtime_interval;
  s64                     xtime_remainder;
  u64                     raw_interval;
  /* The ntp_tick_length() value currently being used.
   * This cached copy ensures we consistently apply the tick
   * length for an entire tick, as ntp_tick_length may change
   * mid-tick, and we don't want to apply that new value to
   * the tick in progress.
   */
  u64                     ntp_tick;
  /* Difference between accumulated time and NTP time in ntp
   * shifted nano seconds. */
  s64                     ntp_error;
  u32                     ntp_error_shift;
  u32                     ntp_err_mult;
  #ifdef CONFIG_DEBUG_TIMEKEEPING
  long                    last_warning;
  /*
   * These simple flag variables are managed
   * without locks, which is racy, but they are
   * ok since we don't really care about being
   * super precise about how many events were
   * seen, just that a problem was observed.
   */
  int                     underflow_seen;
  int                     overflow_seen;
  #endif
};

#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3,17,0)
struct tk_read_base {
        struct clocksource      *clock;
        cycle_t                 (*read)(struct clocksource *cs);
        cycle_t                 mask;
        cycle_t                 cycle_last;
        u32                     mult;
        u32                     shift;
        u64                     xtime_nsec;
        ktime_t                 base_mono;
};

struct timekeeper {
        struct tk_read_base     tkr;
        u64                     xtime_sec;
        struct timespec64       wall_to_monotonic;
        ktime_t                 offs_real;
        ktime_t                 offs_boot;
        ktime_t                 offs_tai;
        s32                     tai_offset;
        ktime_t                 base_raw;
        struct timespec64       raw_time;

        /* The following members are for timekeeping internal use */
        cycle_t                 cycle_interval;
        u64                     xtime_interval;
        s64                     xtime_remainder;
        u32                     raw_interval;
        /* The ntp_tick_length() value currently being used.
         * This cached copy ensures we consistently apply the tick
         * length for an entire tick, as ntp_tick_length may change
         * mid-tick, and we don't want to apply that new value to
         * the tick in progress.
         */
        u64                     ntp_tick;
        /* Difference between accumulated time and NTP time in ntp
         * shifted nano seconds. */
        s64                     ntp_error;
        u32                     ntp_error_shift;
        u32                     ntp_err_mult;
};

#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)
struct timekeeper {
        /* Current clocksource used for timekeeping. */
        struct clocksource      *clock;
        /* NTP adjusted clock multiplier */
        u32                     mult;
        /* The shift value of the current clocksource. */
        u32                     shift;
        /* Number of clock cycles in one NTP interval. */
        cycle_t                 cycle_interval;
        /* Last cycle value (also stored in clock->cycle_last) */
        cycle_t                 cycle_last;
        /* Number of clock shifted nano seconds in one NTP interval. */
        u64                     xtime_interval;
        /* shifted nano seconds left over when rounding cycle_interval */
        s64                     xtime_remainder;
        /* Raw nano seconds accumulated per NTP interval. */
        u32                     raw_interval;

        /* Current CLOCK_REALTIME time in seconds */
        u64                     xtime_sec;
        /* Clock shifted nano seconds */
        u64                     xtime_nsec;

        /* Difference between accumulated time and NTP time in ntp
         * shifted nano seconds. */
        s64                     ntp_error;
        /* Shift conversion between clock shifted nano seconds and
         * ntp shifted nano seconds. */
        u32                     ntp_error_shift;

        /*
         * wall_to_monotonic is what we need to add to xtime (or xtime corrected
         * for sub jiffie times) to get to monotonic time.  Monotonic is pegged
         * at zero at system boot time, so wall_to_monotonic will be negative,
         * however, we will ALWAYS keep the tv_nsec part positive so we can use
         * the usual normalization.
         *
         * wall_to_monotonic is moved after resume from suspend for the
         * monotonic time not to jump. We need to add total_sleep_time to
         * wall_to_monotonic to get the real boot based time offset.
         *
         * - wall_to_monotonic is no longer the boot time, getboottime must be
         * used instead.
         */
        struct timespec         wall_to_monotonic;
        /* Offset clock monotonic -> clock realtime */
        ktime_t                 offs_real;
        /* time spent in suspend */
        struct timespec         total_sleep_time;
        /* Offset clock monotonic -> clock boottime */
        ktime_t                 offs_boot;
        /* The raw monotonic time for the CLOCK_MONOTONIC_RAW posix clock. */
        struct timespec         raw_time;
        /* The current UTC to TAI offset in seconds */
        s32                     tai_offset;
        /* Offset clock monotonic -> clock tai */
        ktime_t                 offs_tai;

};
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3,7,0)
struct timekeeper {
        /* Current clocksource used for timekeeping. */
        struct clocksource      *clock;
        /* NTP adjusted clock multiplier */
        u32                     mult;
        /* The shift value of the current clocksource. */
        u32                     shift;
        /* Number of clock cycles in one NTP interval. */
        cycle_t                 cycle_interval;
        /* Number of clock shifted nano seconds in one NTP interval. */
        u64                     xtime_interval;
        /* shifted nano seconds left over when rounding cycle_interval */
        s64                     xtime_remainder;
        /* Raw nano seconds accumulated per NTP interval. */
        u32                     raw_interval;

        /* Current CLOCK_REALTIME time in seconds */
        u64                     xtime_sec;
        /* Clock shifted nano seconds */
        u64                     xtime_nsec;

        /* Difference between accumulated time and NTP time in ntp
         * shifted nano seconds. */
        s64                     ntp_error;
        /* Shift conversion between clock shifted nano seconds and
         * ntp shifted nano seconds. */
        u32                     ntp_error_shift;

        /*
         * wall_to_monotonic is what we need to add to xtime (or xtime corrected
         * for sub jiffie times) to get to monotonic time.  Monotonic is pegged
         * at zero at system boot time, so wall_to_monotonic will be negative,
         * however, we will ALWAYS keep the tv_nsec part positive so we can use
         * the usual normalization.
         *
         * wall_to_monotonic is moved after resume from suspend for the
         * monotonic time not to jump. We need to add total_sleep_time to
         * wall_to_monotonic to get the real boot based time offset.
         *
         * - wall_to_monotonic is no longer the boot time, getboottime must be
         * used instead.
         */
        struct timespec         wall_to_monotonic;
        /* Offset clock monotonic -> clock realtime */
        ktime_t                 offs_real;
        /* time spent in suspend */
        struct timespec         total_sleep_time;
        /* Offset clock monotonic -> clock boottime */
        ktime_t                 offs_boot;
        /* The raw monotonic time for the CLOCK_MONOTONIC_RAW posix clock. */
        struct timespec         raw_time;
        /* Seqlock for all timekeeper values */
        seqlock_t               lock;
};
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3,6,0)
struct timekeeper {
        /* Current clocksource used for timekeeping. */
        struct clocksource      *clock;
        /* NTP adjusted clock multiplier */
        u32                     mult;
        /* The shift value of the current clocksource. */
        u32                     shift;
        /* Number of clock cycles in one NTP interval. */
        cycle_t                 cycle_interval;
        /* Number of clock shifted nano seconds in one NTP interval. */
        u64                     xtime_interval;
        /* shifted nano seconds left over when rounding cycle_interval */
        s64                     xtime_remainder;
        /* Raw nano seconds accumulated per NTP interval. */
        u32                     raw_interval;

        /* Current CLOCK_REALTIME time in seconds */
        u64                     xtime_sec;
        /* Clock shifted nano seconds */
        u64                     xtime_nsec;

        /* Difference between accumulated time and NTP time in ntp
         * shifted nano seconds. */
        s64                     ntp_error;
        /* Shift conversion between clock shifted nano seconds and
         * ntp shifted nano seconds. */
        u32                     ntp_error_shift;

        /*
         * wall_to_monotonic is what we need to add to xtime (or xtime corrected
         * for sub jiffie times) to get to monotonic time.  Monotonic is pegged
         * at zero at system boot time, so wall_to_monotonic will be negative,
         * however, we will ALWAYS keep the tv_nsec part positive so we can use
         * the usual normalization.
         *
         * wall_to_monotonic is moved after resume from suspend for the
         * monotonic time not to jump. We need to add total_sleep_time to
         * wall_to_monotonic to get the real boot based time offset.
         *
         * - wall_to_monotonic is no longer the boot time, getboottime must be
         * used instead.
         */
        struct timespec         wall_to_monotonic;
        /* Offset clock monotonic -> clock realtime */
        ktime_t                 offs_real;
        /* time spent in suspend */
        struct timespec         total_sleep_time;
        /* Offset clock monotonic -> clock boottime */
        ktime_t                 offs_boot;
        /* The raw monotonic time for the CLOCK_MONOTONIC_RAW posix clock. */
        struct timespec         raw_time;
        /* Seqlock for all timekeeper values */
        seqlock_t               lock;
};
#elif LINUX_VERSION_CODE > KERNEL_VERSION(2,6,31)

struct timekeeper {
        /* Current clocksource used for timekeeping. */
        struct clocksource *clock;
        /* NTP adjusted clock multiplier */
        u32     mult;
        /* The shift value of the current clocksource. */
        int     shift;

        /* Number of clock cycles in one NTP interval. */
        cycle_t cycle_interval;
        /* Number of clock shifted nano seconds in one NTP interval. */
        u64     xtime_interval;
        /* shifted nano seconds left over when rounding cycle_interval */
        s64     xtime_remainder;
        /* Raw nano seconds accumulated per NTP interval. */
        u32     raw_interval;

        /* Clock shifted nano seconds remainder not stored in xtime.tv_nsec. */
        u64     xtime_nsec;
        /* Difference between accumulated time and NTP time in ntp
         * shifted nano seconds. */
        s64     ntp_error;
        /* Shift conversion between clock shifted nano seconds and
         * ntp shifted nano seconds. */
        int     ntp_error_shift;

        /* The current time */
        struct timespec xtime;
        /*
         * wall_to_monotonic is what we need to add to xtime (or xtime corrected
         * for sub jiffie times) to get to monotonic time.  Monotonic is pegged
         * at zero at system boot time, so wall_to_monotonic will be negative,
         * however, we will ALWAYS keep the tv_nsec part positive so we can use
         * the usual normalization.
         *
         * wall_to_monotonic is moved after resume from suspend for the
         * monotonic time not to jump. We need to add total_sleep_time to
         * wall_to_monotonic to get the real boot based time offset.
         *
         * - wall_to_monotonic is no longer the boot time, getboottime must be
         * used instead.
         */
        struct timespec wall_to_monotonic;
        /* time spent in suspend */
        struct timespec total_sleep_time;
        /* The raw monotonic time for the CLOCK_MONOTONIC_RAW posix clock. */
        struct timespec raw_time;

        /* Offset clock monotonic -> clock realtime */
        ktime_t offs_real;

        /* Offset clock monotonic -> clock boottime */
        ktime_t offs_boot;

        /* Seqlock for all timekeeper values */
        seqlock_t lock;
};
#endif

struct timekeeper my_timekeeper;

/****************************************
 * TIMEKEEPING END
 ****************************************/

struct log {
         u64 ts_nsec;            /* timestamp in nanoseconds */
         u16 len;                /* length of entire record */
         u16 text_len;           /* length of text buffer */
         u16 dict_len;           /* length of dictionary buffer */
         u8 facility;            /* syslog facility */
         u8 flags:5;             /* internal record flags */
         u8 level:3;             /* syslog level */
};

struct log my_log;


/****************************************
 * MOUNT POINTS START
 ****************************************/

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,15,0)
struct mnt_namespace {
        atomic_t                count;
        unsigned int            proc_inum;
        struct mount *  root;
        struct list_head        list;
        struct user_namespace   *user_ns;
        u64                     seq;    /* Sequence number to prevent loops */
        wait_queue_head_t poll;
        u64 event;
};

struct mnt_pcp {
        int mnt_count;
        int mnt_writers;
};

struct mountpoint {
        struct hlist_node m_hash;
        struct dentry *m_dentry;
        int m_count;
};

struct mount {
        struct hlist_node mnt_hash;
        struct mount *mnt_parent;
        struct dentry *mnt_mountpoint;
        struct vfsmount mnt;
        struct rcu_head mnt_rcu;
#ifdef CONFIG_SMP
        struct mnt_pcp __percpu *mnt_pcp;
#else
        int mnt_count;
        int mnt_writers;
#endif
        struct list_head mnt_mounts;    /* list of children, anchored here */
        struct list_head mnt_child;     /* and going through their mnt_child */
        struct list_head mnt_instance;  /* mount instance on sb->s_mounts */
        const char *mnt_devname;        /* Name of device e.g. /dev/dsk/hda1 */
        struct list_head mnt_list;
        struct list_head mnt_expire;    /* link in fs-specific expiry list */
        struct list_head mnt_share;     /* circular list of shared mounts */
        struct list_head mnt_slave_list;/* list of slave mounts */
        struct list_head mnt_slave;     /* slave list entry */
        struct mount *mnt_master;       /* slave is on master->mnt_slave_list */
        struct mnt_namespace *mnt_ns;   /* containing namespace */
        struct mountpoint *mnt_mp;      /* where is it mounted */
#ifdef CONFIG_FSNOTIFY
        struct hlist_head mnt_fsnotify_marks;
        __u32 mnt_fsnotify_mask;
#endif
        int mnt_id;                     /* mount identifier */
        int mnt_group_id;               /* peer group identifier */
        int mnt_expiry_mark;            /* true if marked for expiry */
        int mnt_pinned;
        struct path mnt_ex_mountpoint;
};
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3,14,0)
struct mnt_namespace {
        atomic_t                count;
        unsigned int            proc_inum;
        struct mount *  root;
        struct list_head        list;
        struct user_namespace   *user_ns;
        u64                     seq;    /* Sequence number to prevent loops */
        wait_queue_head_t poll;
        int event;
};

struct mnt_pcp {
        int mnt_count;
        int mnt_writers;
};

struct mountpoint {
        struct hlist_node m_hash;
        struct dentry *m_dentry;
        int m_count;
};

struct mount {
        struct hlist_node mnt_hash;
        struct mount *mnt_parent;
        struct dentry *mnt_mountpoint;
        struct vfsmount mnt;
        struct rcu_head mnt_rcu;
#ifdef CONFIG_SMP
        struct mnt_pcp __percpu *mnt_pcp;
#else
        int mnt_count;
        int mnt_writers;
#endif
        struct list_head mnt_mounts;    /* list of children, anchored here */
        struct list_head mnt_child;     /* and going through their mnt_child */
        struct list_head mnt_instance;  /* mount instance on sb->s_mounts */
        const char *mnt_devname;        /* Name of device e.g. /dev/dsk/hda1 */
        struct list_head mnt_list;
        struct list_head mnt_expire;    /* link in fs-specific expiry list */
        struct list_head mnt_share;     /* circular list of shared mounts */
        struct list_head mnt_slave_list;/* list of slave mounts */
        struct list_head mnt_slave;     /* slave list entry */
        struct mount *mnt_master;       /* slave is on master->mnt_slave_list */
        struct mnt_namespace *mnt_ns;   /* containing namespace */
        struct mountpoint *mnt_mp;      /* where is it mounted */
#ifdef CONFIG_FSNOTIFY
        struct hlist_head mnt_fsnotify_marks;
        __u32 mnt_fsnotify_mask;
#endif
        int mnt_id;                     /* mount identifier */
        int mnt_group_id;               /* peer group identifier */
        int mnt_expiry_mark;            /* true if marked for expiry */
        int mnt_pinned;
        struct path mnt_ex_mountpoint;
};
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3,13,0)
struct mnt_namespace {
        atomic_t                count;
        unsigned int            proc_inum;
        struct mount *  root;
        struct list_head        list;
        struct user_namespace   *user_ns;
        u64                     seq;    /* Sequence number to prevent loops */
        wait_queue_head_t poll;
        int event;
};

struct mnt_pcp {
        int mnt_count;
        int mnt_writers;
};

struct mountpoint {
        struct list_head m_hash;
        struct dentry *m_dentry;
        int m_count;
};

struct mount {
        struct list_head mnt_hash;
        struct mount *mnt_parent;
        struct dentry *mnt_mountpoint;
        struct vfsmount mnt;
        struct rcu_head mnt_rcu;
#ifdef CONFIG_SMP
        struct mnt_pcp __percpu *mnt_pcp;
#else
        int mnt_count;
        int mnt_writers;
#endif
        struct list_head mnt_mounts;    /* list of children, anchored here */
        struct list_head mnt_child;     /* and going through their mnt_child */
        struct list_head mnt_instance;  /* mount instance on sb->s_mounts */
        const char *mnt_devname;        /* Name of device e.g. /dev/dsk/hda1 */
        struct list_head mnt_list;
        struct list_head mnt_expire;    /* link in fs-specific expiry list */
        struct list_head mnt_share;     /* circular list of shared mounts */
        struct list_head mnt_slave_list;/* list of slave mounts */
        struct list_head mnt_slave;     /* slave list entry */
        struct mount *mnt_master;       /* slave is on master->mnt_slave_list */
        struct mnt_namespace *mnt_ns;   /* containing namespace */
        struct mountpoint *mnt_mp;      /* where is it mounted */
#ifdef CONFIG_FSNOTIFY
        struct hlist_head mnt_fsnotify_marks;
        __u32 mnt_fsnotify_mask;
#endif
        int mnt_id;                     /* mount identifier */
        int mnt_group_id;               /* peer group identifier */
        int mnt_expiry_mark;            /* true if marked for expiry */
        int mnt_pinned;
        struct path mnt_ex_mountpoint;
};
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)
struct mnt_namespace {
        atomic_t                count;
        unsigned int            proc_inum;
        struct mount *  root;
        struct list_head        list;
        struct user_namespace   *user_ns;
        u64                     seq;    /* Sequence number to prevent loops */
        wait_queue_head_t poll;
        int event;
};

struct mnt_pcp {
        int mnt_count;
        int mnt_writers;
};

struct mountpoint {
        struct list_head m_hash;
        struct dentry *m_dentry;
        int m_count;
};

struct mount {
        struct list_head mnt_hash;
        struct mount *mnt_parent;
        struct dentry *mnt_mountpoint;
        struct vfsmount mnt;
#ifdef CONFIG_SMP
        struct mnt_pcp __percpu *mnt_pcp;
#else
        int mnt_count;
        int mnt_writers;
#endif
        struct list_head mnt_mounts;    /* list of children, anchored here */
        struct list_head mnt_child;     /* and going through their mnt_child */
        struct list_head mnt_instance;  /* mount instance on sb->s_mounts */
        const char *mnt_devname;        /* Name of device e.g. /dev/dsk/hda1 */
        struct list_head mnt_list;
        struct list_head mnt_expire;    /* link in fs-specific expiry list */
        struct list_head mnt_share;     /* circular list of shared mounts */
        struct list_head mnt_slave_list;/* list of slave mounts */
        struct list_head mnt_slave;     /* slave list entry */
        struct mount *mnt_master;       /* slave is on master->mnt_slave_list */
        struct mnt_namespace *mnt_ns;   /* containing namespace */
        struct mountpoint *mnt_mp;      /* where is it mounted */
#ifdef CONFIG_FSNOTIFY
        struct hlist_head mnt_fsnotify_marks;
        __u32 mnt_fsnotify_mask;
#endif
        int mnt_id;                     /* mount identifier */
        int mnt_group_id;               /* peer group identifier */
        int mnt_expiry_mark;            /* true if marked for expiry */
        int mnt_pinned;
        int mnt_ghosts;
};
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3,8,0)
struct mnt_namespace {
        atomic_t                count;
        unsigned int            proc_inum;
        struct mount *  root;
        struct list_head        list;
        struct user_namespace   *user_ns;
        u64                     seq;    /* Sequence number to prevent loops */
        wait_queue_head_t poll;
        int event;
};

struct mnt_pcp {
        int mnt_count;
        int mnt_writers;
};

struct mount {
        struct list_head mnt_hash;
        struct mount *mnt_parent;
        struct dentry *mnt_mountpoint;
        struct vfsmount mnt;
#ifdef CONFIG_SMP
        struct mnt_pcp __percpu *mnt_pcp;
#else
        int mnt_count;
        int mnt_writers;
#endif
        struct list_head mnt_mounts;    /* list of children, anchored here */
        struct list_head mnt_child;     /* and going through their mnt_child */
        struct list_head mnt_instance;  /* mount instance on sb->s_mounts */
        const char *mnt_devname;        /* Name of device e.g. /dev/dsk/hda1 */
        struct list_head mnt_list;
        struct list_head mnt_expire;    /* link in fs-specific expiry list */
        struct list_head mnt_share;     /* circular list of shared mounts */
        struct list_head mnt_slave_list;/* list of slave mounts */
        struct list_head mnt_slave;     /* slave list entry */
        struct mount *mnt_master;       /* slave is on master->mnt_slave_list */
        struct mnt_namespace *mnt_ns;   /* containing namespace */
#ifdef CONFIG_FSNOTIFY
        struct hlist_head mnt_fsnotify_marks;
        __u32 mnt_fsnotify_mask;
#endif
        int mnt_id;                     /* mount identifier */
        int mnt_group_id;               /* peer group identifier */
        int mnt_expiry_mark;            /* true if marked for expiry */
        int mnt_pinned;
        int mnt_ghosts;
};
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3,6,0)
struct mnt_namespace {
        atomic_t                count;
        struct mount *  root;
        struct list_head        list;
        wait_queue_head_t poll;
        int event;
};

struct mnt_pcp {
        int mnt_count;
        int mnt_writers;
};

struct mount {
        struct list_head mnt_hash;
        struct mount *mnt_parent;
        struct dentry *mnt_mountpoint;
        struct vfsmount mnt;
#ifdef CONFIG_SMP
        struct mnt_pcp __percpu *mnt_pcp;
#else
        int mnt_count;
        int mnt_writers;
#endif
        struct list_head mnt_mounts;    /* list of children, anchored here */
        struct list_head mnt_child;     /* and going through their mnt_child */
        struct list_head mnt_instance;  /* mount instance on sb->s_mounts */
        const char *mnt_devname;        /* Name of device e.g. /dev/dsk/hda1 */
        struct list_head mnt_list;
        struct list_head mnt_expire;    /* link in fs-specific expiry list */
        struct list_head mnt_share;     /* circular list of shared mounts */
        struct list_head mnt_slave_list;/* list of slave mounts */
        struct list_head mnt_slave;     /* slave list entry */
        struct mount *mnt_master;       /* slave is on master->mnt_slave_list */
        struct mnt_namespace *mnt_ns;   /* containing namespace */
#ifdef CONFIG_FSNOTIFY
        struct hlist_head mnt_fsnotify_marks;
        __u32 mnt_fsnotify_mask;
#endif
        int mnt_id;                     /* mount identifier */
        int mnt_group_id;               /* peer group identifier */
        int mnt_expiry_mark;            /* true if marked for expiry */
        int mnt_pinned;
        int mnt_ghosts;
};

#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3,3,0)
struct mnt_namespace {
        atomic_t                count;
        struct mount *  root;
        struct list_head        list;
        wait_queue_head_t poll;
        int event;
};

struct mnt_pcp {
        int mnt_count;
        int mnt_writers;
};

struct mount {
        struct list_head mnt_hash;
        struct mount *mnt_parent;
        struct dentry *mnt_mountpoint;
        struct vfsmount mnt;
#ifdef CONFIG_SMP
        struct mnt_pcp __percpu *mnt_pcp;
        atomic_t mnt_longterm;          /* how many of the refs are longterm */
#else
        int mnt_count;
        int mnt_writers;
#endif
        struct list_head mnt_mounts;    /* list of children, anchored here */
        struct list_head mnt_child;     /* and going through their mnt_child */
        struct list_head mnt_instance;  /* mount instance on sb->s_mounts */
        const char *mnt_devname;        /* Name of device e.g. /dev/dsk/hda1 */
        struct list_head mnt_list;
        struct list_head mnt_expire;    /* link in fs-specific expiry list */
        struct list_head mnt_share;     /* circular list of shared mounts */
        struct list_head mnt_slave_list;/* list of slave mounts */
        struct list_head mnt_slave;     /* slave list entry */
        struct mount *mnt_master;       /* slave is on master->mnt_slave_list */
        struct mnt_namespace *mnt_ns;   /* containing namespace */
#ifdef CONFIG_FSNOTIFY
        struct hlist_head mnt_fsnotify_marks;
        __u32 mnt_fsnotify_mask;
#endif
        int mnt_id;                     /* mount identifier */
        int mnt_group_id;               /* peer group identifier */
        int mnt_expiry_mark;            /* true if marked for expiry */
        int mnt_pinned;
        int mnt_ghosts;
};
#endif

/****************************************
 * MOUNT POINTS END
 ****************************************/


/****************************************
 * PROC START
 ****************************************/
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)
struct proc_dir_entry {
        unsigned int low_ino;
        umode_t mode;
        nlink_t nlink;
        kuid_t uid;
        kgid_t gid;
        loff_t size;
        const struct inode_operations *proc_iops;
        const struct file_operations *proc_fops;
        struct proc_dir_entry *next, *parent, *subdir;
        void *data;
        atomic_t count;         /* use count */
        atomic_t in_use;        /* number of callers into module in progress; */
                                /* negative -> it's going away RSN */
        struct completion *pde_unload_completion;
        struct list_head pde_openers;   /* who did ->open, but not ->release */
        spinlock_t pde_unload_lock; /* proc_fops checks and pde_users bumps */
        u8 namelen;
        char name[];
};
#else
/** Before 3.10, proc_dir_entry is defined in <linux/proc_fs.h> **/
#endif
/****************************************
 * PROC END
 ****************************************/


/****************************************
 * SYSTEM V shared memory
 ****************************************/
#if LINUX_VERSION_CODE > KERNEL_VERSION(4,16,0)
struct shmid_kernel /* private to the kernel */
{
	struct kern_ipc_perm	shm_perm;
	struct file		*shm_file;
	unsigned long		shm_nattch;
	unsigned long		shm_segsz;
	time64_t		shm_atim;
	time64_t		shm_dtim;
	time64_t		shm_ctim;
	struct pid		*shm_cprid;
	struct pid		*shm_lprid;
	struct user_struct	*mlock_user;

	/* The task created the shm object.  NULL if the task is dead. */
	struct task_struct	*shm_creator;
	struct list_head	shm_clist;	/* list by creator */
} __randomize_layout;

/* shm_mode upper byte flags */
#define SHM_DEST	01000	/* segment will be destroyed on last detach */
#define SHM_LOCKED	02000   /* segment will not be swapped */

struct shm_file_data {
	int id;
	struct ipc_namespace *ns;
	struct file *file;
	const struct vm_operations_struct *vm_ops;
};
#endif
struct kern_ipc_perm kern_ipc_perm;
struct shmid_kernel shmid_kernel;
/****************************************
 * SYSTEM V END
 ****************************************/


/****************************************
 * anon_vma START
 ****************************************/
struct anon_vma anon_vma;
struct anon_vma_chain anon_vma_chain;
/****************************************
 * anon_vma END
 ****************************************/
