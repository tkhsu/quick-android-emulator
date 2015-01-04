#ifndef IBTC_H
#define IBTC_H

#define IBTC_ENABLE 1
#define IBTC_PROFILE 0

#if IBTC_ENABLE == 1 && !defined(ITLB_ENABLE)
#define ITLB_ENABLE
#endif

typedef struct IBTCEntry {
    uintptr_t g, h;
#ifdef CONFIG_SOFTMMU
    uintptr_t flags;
    uintptr_t paddr;
#endif
} IBTCEntry;

#define IBTC_CACHE_BITS (16)
#define IBTC_CACHE_SIZE (1 << IBTC_CACHE_BITS)
#define IBTC_CACHE_MASK (IBTC_CACHE_SIZE-1)

static inline IBTCEntry *ibtc_get_entry(IBTCEntry *Cache, uintptr_t g)
{
#if defined(TARGET_ARM)
    int index = g >> 2;
#else
    int index = g;
#endif
    return &Cache[index & IBTC_CACHE_MASK];
}

static inline void ibtc_update(IBTCEntry *entry,
                               target_ulong g,
                               uint8_t *h
#ifdef CONFIG_SOFTMMU
                               , uintptr_t flags
                               , uintptr_t paddr
#endif
                               )
{
    IBTCEntry tmp = {.g = g, .h = (uintptr_t)h};
#ifdef CONFIG_SOFTMMU
    tmp.flags = flags;
    tmp.paddr = paddr;
#endif
    *entry = tmp;
}

#if IBTC_ENABLE
#define IBTC_ELEMENT                 \
    IBTCEntry *ibtc_missed_entry;    \
    IBTCEntry ibtc[IBTC_CACHE_SIZE];
#else
#define IBTC_ELEMENT
#endif

typedef struct ibtc_data_t {
    uint8_t *tb_ret_addr;
    int enabled;
#if IBTC_PROFILE
    int64_t total;
    int64_t miss;
    int64_t cold_miss;
    int64_t miss_flags;
    int64_t miss_phy;
    int64_t count_clean;
#endif
} ibtc_data_t;
extern ibtc_data_t ibtc;

static inline void ibtc_init(void)
{
    char *v = getenv("IBTC");
    ibtc.enabled = (v ? atoi(v) : 1);
#if IBTC_PROFILE
    ibtc.total = 0;
    ibtc.miss = 0;
    ibtc.cold_miss = 0;
    ibtc.miss_flags = 0;
    ibtc.miss_phy = 0;
    ibtc.count_clean = 0;
#endif
}

static inline void ibtc_clean(IBTCEntry *C)
{
    memset(C, 0xff, IBTC_CACHE_SIZE * sizeof(IBTCEntry));
#if IBTC_PROFILE
    ibtc.count_clean++;
#endif
}

#if IBTC_PROFILE
static inline void ibtc_profile_print(void)
{
    int64_t ibtc_total = ibtc.total;
    int64_t ibtc_miss = ibtc.miss;
    int64_t ibtc_cold_miss = ibtc.cold_miss;

    printf("ibtc hit rate: %.3lf%% (%"PRId64"/%"PRId64")\n",
            100.0-(ibtc_miss/(double)ibtc_total*100),
            ibtc_miss, ibtc_total);
    printf("ibtc cold miss rate: %.3lf%% (%"PRId64"/%"PRId64")\n",
            (ibtc_cold_miss/(double)ibtc_miss*100),
            ibtc_cold_miss, ibtc_miss);
    printf("ibtc flags miss rate: %.3lf%% (%"PRId64"/%"PRId64")\n",
            (ibtc.miss_flags/(double)ibtc_miss*100),
            ibtc.miss_flags, ibtc_miss);
    printf("ibtc paddr miss rate: %.3lf%% (%"PRId64"/%"PRId64")\n",
            (ibtc.miss_phy/(double)ibtc_miss*100),
            ibtc.miss_phy, ibtc_miss);
    printf("ibtc clean count: %"PRId64"\n", ibtc.count_clean);
}

static inline void ibtc_profile_total(void)
{
    ibtc.total++;
}

static inline void ibtc_profile_miss(target_ulong g)
{
    if (g == -1)
        ibtc.cold_miss++;
    ibtc.miss++;
}

static inline void ibtc_profile_miss_flags(void)
{
    ibtc.miss_flags++;
}

static inline void ibtc_profile_miss_phy(void)
{
    ibtc.miss_phy++;
}
#else /* ! IBTC_PROFILE */
static inline void ibtc_profile_total(void)
{
}

static inline void ibtc_profile_miss(target_ulong g)
{
}

static inline void ibtc_profile_miss_flags(void)
{
}

static inline void ibtc_profile_miss_phy(void)
{
}
#endif /* IBTC_PROFILE */

#endif
