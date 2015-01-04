#include "config.h"
#include "cpu.h"
#include "exec/exec-all.h" /* for tcg.h */
#include "tcg/tcg.h" /* TCG_TARGET_* */
#include "opt/optimizations.h"

#if defined(TCG_TARGET_I386)
#if defined(__i386__)
#define AREG0 "ebp"
#elif defined(__x86_64__)
#define AREG0 "r14"
#endif
#elif defined(TCG_TARGET_PPC) || defined(TCG_TARGET_PPC64)
#define AREG0 "r27"
#elif defined(TCG_TARGET_ARM)
#define AREG0 "r7"
#else
#error "unsupported processor type"
#endif

register CPUArchState * const exec_env asm(AREG0);

#if IBTC_ENABLE
ibtc_data_t ibtc;

void *helper_ibtc_lookup(target_ulong g);
void *helper_ibtc_lookup(target_ulong g)
{
    IBTCEntry *entry;

    if (unlikely(ENV_GET_CPU(exec_env)->exit_request)) {
        return ibtc.tb_ret_addr;
    }

    ibtc_profile_total();

    entry = ibtc_get_entry(exec_env->ibtc, g);
    if (unlikely(entry->g != g)) {
        goto miss;
    } else {
#ifdef CONFIG_SOFTMMU
        if (unlikely(!ibtc_check_flags(exec_env, entry->flags))) {
            ibtc_profile_miss_flags();
            goto miss;
        }
        if (unlikely(!itlb_check_phy_addr(exec_env, g, entry->paddr))) {
            ibtc_profile_miss_phy();
            goto miss;
        }
#endif
        return (void*)entry->h;
    }

miss:
    ibtc_profile_miss(entry->g);

    exec_env->ibtc_missed_entry = entry;
    return ibtc.tb_ret_addr;
}
#endif
