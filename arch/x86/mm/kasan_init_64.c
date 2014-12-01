#include <linux/bootmem.h>
#include <linux/kasan.h>
#include <linux/kdebug.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/vmalloc.h>

#include <asm/tlbflush.h>
#include <asm/sections.h>

extern pgd_t early_level4_pgt[PTRS_PER_PGD];
extern struct range pfn_mapped[E820_X_MAX];

extern unsigned char poisoned_page[PAGE_SIZE];

struct vm_struct kasan_vm __initdata = {
	.addr = (void *)KASAN_SHADOW_START,
	.size = (16UL << 40),
};


static int __init map_range(struct range *range)
{
	unsigned long start = kasan_mem_to_shadow(
		(unsigned long)pfn_to_kaddr(range->start));
	unsigned long end = kasan_mem_to_shadow(
		(unsigned long)pfn_to_kaddr(range->end));

	/*
	 * end + 1 here is intentional. We check several shadow bytes in advance
	 * to slightly speed up fastpath. In some rare cases we could cross
	 * boundary of mapped shadow, so we just map some more here.
	 */
	return vmemmap_populate(start, end + 1, NUMA_NO_NODE);
}

static void __init clear_zero_shadow_mapping(unsigned long start,
					unsigned long end)
{
	for (; start < end; start += PGDIR_SIZE)
		pgd_clear(pgd_offset_k(start));
}

void __init kasan_map_zero_shadow(pgd_t *pgd)
{
	int i;
	unsigned long start = KASAN_SHADOW_START;
	unsigned long end = KASAN_SHADOW_END;

	for (i = pgd_index(start); start < end; i++) {
		pgd[i] = __pgd(__pa_nodebug(poisoned_pud) | _KERNPG_TABLE);
		start += PGDIR_SIZE;
	}
}

static pgd_t *kasan_pgd_populate(unsigned long addr, unsigned long end)
{
	pgd_t *pgd = pgd_offset_k(addr);

	if (pgd_none(*pgd) && addr + PGDIR_SIZE < end) {
		set_pgd(pgd, __pgd(__pa_nodebug(zero_pud) | __PAGE_KERNEL_RO));
	} else if (pgd_none(*pgd)) {
		void *p = vmemmap_alloc_block(PAGE_SIZE, NUMA_NO_NODE);
		if (!p)
			return NULL;
		set_pgd(pgd, __pgd(__pa_nodebug(p) | __PAGE_KERNEL_RO));
	}
	return pgd;
}

static pud_t *kasan_pud_populate(pgd_t *pgd, unsigned long addr,
				unsigned long end)
{
	pud_t *pud = pud_offset(pgd, addr);

	if (pud_none(*pud) && addr + PUD_SIZE < end) {
		set_pud(pud, __pud(__pa_nodebug(zero_pmd) | __PAGE_KERNEL_RO));
	} else if (pud_none(*pud)) {
		void *p = vmemmap_alloc_block(PAGE_SIZE, NUMA_NO_NODE);
		if (!p)
			return NULL;
		set_pud(pud, __pud(__pa_nodebug(p) | __PAGE_KERNEL_RO));
	}
	return pud;
}

static pmd_t *kasan_pmd_populate(pud_t *pud, unsigned long addr,
				unsigned long end)
{
	pmd_t *pmd = pmd_offset(pud, addr);

	if (pmd_none(*pmd) && addr + PMD_SIZE < end) {
		set_pmd(pmd, __pmd(__pa_nodebug(zero_pte) | __PAGE_KERNEL_RO));
	} else if (pmd_none(*pmd)) {
		void *p = vmemmap_alloc_block(PAGE_SIZE, NUMA_NO_NODE);
		if (!p)
			return NULL;
		set_pmd(pmd, __pmd(__pa_nodebug(p) | __PAGE_KERNEL_RO));
	}
	return pmd;
}

static pte_t *kasan_pte_populate(pmd_t *pmd, unsigned long addr,
				unsigned long end)
{
	pte_t *pte = pte_offset_kernel(pmd, addr);

	if (pte_none(*pte))
		set_pte(pte,
			__pte(__pa_nodebug(empty_zero_page) | __PAGE_KERNEL_RO));
	return pte;
}

int map_zeroes(unsigned long start, unsigned long end)
{
	unsigned long addr;
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;

	for (addr = start; addr < end;) {

		pgd = kasan_pgd_populate(addr, end);
		if (!pgd)
			return -ENOMEM;

		pud = kasan_pud_populate(pgd, addr, end);
		if (!pud)
			return -ENOMEM;

		pmd = kasan_pmd_populate(pud, addr, end);
		if (!pmd)
			return -ENOMEM;

		pte = kasan_pte_populate(pmd, addr, end);
		if (!pte)
			return -ENOMEM;

		addr += PAGE_SIZE;
	}
	return 0;
}


#ifdef CONFIG_KASAN_INLINE
static int kasan_die_handler(struct notifier_block *self,
			unsigned long val,
			void *data)
{
	if (val == DIE_GPF) {
		pr_emerg("CONFIG_KASAN_INLINE enabled\n");
		pr_emerg("GPF could be caused by NULL-ptr deref or user memory access\n");
	}
	return NOTIFY_OK;
}

static struct notifier_block kasan_die_notifier = {
	.notifier_call = kasan_die_handler,
};
#endif

void __init kasan_init(void)
{
	int i;

#ifdef CONFIG_KASAN_INLINE
	register_die_notifier(&kasan_die_notifier);
#endif
	vm_area_add_early(&kasan_vm);

	memcpy(early_level4_pgt, init_level4_pgt, sizeof(early_level4_pgt));
	load_cr3(early_level4_pgt);

	clear_zero_shadow_mapping(kasan_mem_to_shadow(PAGE_OFFSET),
				kasan_mem_to_shadow(PAGE_OFFSET + MAXMEM));

	for (i = 0; i < E820_X_MAX; i++) {
		if (pfn_mapped[i].end == 0)
			break;

		if (map_range(&pfn_mapped[i]))
			panic("kasan: unable to allocate shadow!");
	}

	clear_zero_shadow_mapping(kasan_mem_to_shadow(__START_KERNEL_map),
				kasan_mem_to_shadow(~0ULL));
	vmemmap_populate(kasan_mem_to_shadow(__START_KERNEL_map),
			kasan_mem_to_shadow((unsigned long)_end),
			NUMA_NO_NODE);

	map_zeroes(kasan_mem_to_shadow(MODULES_VADDR), kasan_mem_to_shadow(~0ULL));

	memset(poisoned_page, 0, PAGE_SIZE);

	load_cr3(init_level4_pgt);
	init_task.kasan_depth = 0;
}
