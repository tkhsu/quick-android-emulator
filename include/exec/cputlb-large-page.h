/*
 * Public Functions:
 * void     init_large_page_list (large_page_list_t *l);
 *
 * Static Functions used in cputlb.c
 * large_page_t *find_large_page (large_page_list_t *l, target_ulong vaddr, target_ulong size);
 * large_page_t  *new_large_page (large_page_list_t *l, target_ulong vaddr, target_ulong size);
 * void          free_large_page (large_page_list_t *l, large_page_t *p)
 * void            add_tlb_entry (large_page_list_t *l, large_page_t *p, CPUTLBEntry *e);
 */
#ifndef CPUTLB_LARGE_PAGE_H
#define CPUTLB_LARGE_PAGE_H
#if defined(CONFIG_SOFTMMU)
#define DP(...) (fprintf(stderr, __VA_ARGS__), fprintf(stderr, "\n"))
#define panic(...) (DP(__VA_ARGS__), exit(2))

typedef struct tlb_entry_t {
    struct CPUTLBEntry *entry;
    struct tlb_entry_t *next;
} tlb_entry_t;

typedef struct large_page_t {
    target_ulong vaddr;
    target_ulong mask;
    hwaddr paddr;
    int prot;
    struct large_page_t *next;
    /* entries within this large page */
    tlb_entry_t *entry_list;
} large_page_t;

/* Pool structure for a specific data structure.
 * Two assumptions:
 * 1. Users don't need to free allocated memory.
 * 2. Simple garbage collection by freeing all allocated memory.
 */
/* #define PROFILE_POOL */
#define MAX_POOL_NODE (32)
typedef struct pool_node_t {
    uint8_t *head;
    size_t size;
} pool_node_t;

typedef struct pool_t {
    uint8_t *cur;
    uint8_t *tail;
    unsigned member_size;
    int cur_node_index;
    /* maximum support base_size * 1.5 ^ 33*/
    pool_node_t pool_nodes[MAX_POOL_NODE];
#ifdef PROFILE_POOL
    long n_total_allocation;
    long n_allocation;
    long n_reset;
    long max_allocation_per_seesion;
#endif
} pool_t;

static inline unsigned next_highest_power_of_2(unsigned v)
{
    v--;
    v |= v >> 1;
    v |= v >> 2;
    v |= v >> 4;
    v |= v >> 8;
    v |= v >> 16;
    v++;
    return v;
}

static inline void pool_reset(pool_t *p);
static inline void pool_dump(pool_t *p);
static inline void pool_init(pool_t *p, unsigned member_size, size_t base_size)
{
    pool_node_t *I, *E;
    /* initialize pool nodes */
    size_t N = base_size;
    for (I = p->pool_nodes, E = I + MAX_POOL_NODE; I != E; ++I, N = (N / 2) * 3) {
        if (I->head != 0)
            free(I->head);
        I->head = 0;
        I->size = N;
    }
    p->pool_nodes[0].head = g_malloc(base_size);
    p->member_size = next_highest_power_of_2(member_size);
    pool_reset(p);
#ifdef PROFILE_POOL
    p->n_total_allocation = 0;
    p->n_allocation = 0;
    p->n_reset = 0;
    p->max_allocation_per_seesion = -1;
    pool_dump(p);
#endif
}

static inline void *pool_alloc(pool_t *p)
{
    pool_node_t *I;
    uint8_t *allocated;
    if (unlikely((p->tail - p->cur) < p->member_size)) {
        p->cur_node_index++;
        I = &p->pool_nodes[p->cur_node_index];
        if (unlikely(I->head == NULL)) {
            I->head = g_malloc(I->size);
        }
        p->cur = I->head;
        p->tail = I->head + I->size;
    }
    allocated = p->cur;
    p->cur += p->member_size;
#ifdef PROFILE_POOL
    p->n_allocation++;
#endif
    return allocated;
}

static inline void pool_reset(pool_t *p)
{
    p->cur_node_index = 0;
    p->cur = p->pool_nodes[0].head;
    p->tail = p->cur + p->pool_nodes[0].size;
#ifdef PROFILE_POOL
    p->n_total_allocation += p->n_allocation;
    p->n_reset++;
    if (p->n_allocation > p->max_allocation_per_seesion)
        p->max_allocation_per_seesion = p->n_allocation;
    p->n_allocation = 0;
#endif
}

static inline void pool_dump(pool_t *p)
{
    unsigned i;
    size_t N = 0;
    for (i = 0; i != MAX_POOL_NODE; ++i) {
        if (p->pool_nodes[i].head == 0)
            break;
        N += p->pool_nodes[i].size;
    }
    DP("member_size = %u", p->member_size);
    DP("tail = %p", p->tail);
    DP("cur  = %p", p->cur);
    DP("malloc'd size = %zd", N);
    DP("member_size = %x", p->member_size);
#ifdef PROFILE_POOL
    DP("average allocation = %lf", p->n_total_allocation/(p->n_reset+1.0));
    DP("n_total_allocation = %ld", p->n_total_allocation);
    DP("n_allocation = %ld", p->n_allocation);
    DP("n_reset = %ld", p->n_reset);
    DP("max_allocation_per_seesion = %ld", p->max_allocation_per_seesion);
#endif
}

#define LARGE_PAGE_HASH_BITS 8
#define LARGE_PAGE_HASH_SIZE (1u << LARGE_PAGE_HASH_BITS)
#define LARGE_PAGE_HASH_MASK (LARGE_PAGE_HASH_SIZE - 1)
typedef struct large_page_list_t {
    large_page_t *allocated[NB_MMU_MODES][LARGE_PAGE_HASH_SIZE];
    pool_t large_page_pool;
    pool_t tlb_entry_pool;
} large_page_list_t;

/* Called when VCPU allocated */
void large_page_list_init (large_page_list_t *l);

static inline target_ulong large_page_hash_func(target_ulong vaddr)
{
    const int LARGE_PAGE_HASH_SHIFT = 15;
    return (vaddr >> LARGE_PAGE_HASH_SHIFT) & LARGE_PAGE_HASH_MASK;
}

/* Called in cputlb.c and softmmu_template.h */
static inline large_page_t *find_large_page(large_page_list_t *l,
                                            target_ulong vaddr,
                                            int mmu_idx)
{
    large_page_t *lp;
    target_ulong hash = large_page_hash_func(vaddr);
    large_page_t **p1= &l->allocated[mmu_idx][hash];
    large_page_t **p= p1;

    while ((lp = *p)) {
        if (lp->vaddr == (vaddr & lp->mask))
            break;
        p = &lp->next;
    }
    /* move lp to the head of list */
    if (lp && lp != *p1) {
        *p = lp->next;
        lp->next = *p1;
        *p1 = lp;
    }
    return lp;
}

#endif /* CONFIG_SOFTMMU */
#endif /* CPUTLB_LARGE_PAGE_H */
