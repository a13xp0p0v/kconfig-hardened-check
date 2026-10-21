#!/usr/bin/env python3

"""
This tool is for checking the security hardening options of the Linux kernel.

SPDX-FileCopyrightText: Alexander Popov <alex.popov@linux.com>
SPDX-License-Identifier: GPL-3.0-only

This module contains knowledge for checks.
"""

# pylint: disable=missing-function-docstring,too-many-lines,too-many-branches,too-many-statements,too-many-locals

from .engine import (
    AND,
    OR,
    ChecklistObjType,
    CmdlineCheck,
    KconfigCheck,
    StrOrNone,
    SysctlCheck,
    VersionCheck,
)


def add_kconfig_checks(l: list[ChecklistObjType], arch: str) -> None:
    assert (arch), 'empty arch'

    # Calling the KconfigCheck class constructor:
    #     KconfigCheck(reason, decision, name, expected)
    #
    # [!] Don't add CmdlineChecks in add_kconfig_checks() to avoid wrong results
    #     when the tool doesn't check the cmdline.

    efi_not_set = KconfigCheck('-', '-', 'EFI', 'is not set')
    cc_is_gcc = KconfigCheck('-', '-', 'CC_IS_GCC', 'y')  # exists since v4.18
    cc_is_clang = KconfigCheck('-', '-', 'CC_IS_CLANG', 'y')  # exists since v4.18
    if arch in {'X86_64', 'X86_32'}:
        cpu_sup_amd_not_set = KconfigCheck('-', '-', 'CPU_SUP_AMD', 'is not set')
        cpu_sup_intel_not_set = KconfigCheck('-', '-', 'CPU_SUP_INTEL', 'is not set')

    modules_not_set = KconfigCheck('cut_attack_surface', 'kspp', 'MODULES', 'is not set')
                      # see the README.md: How can I disable loading of vulnerable Linux kernel modules?
    devmem_not_set = KconfigCheck('cut_attack_surface', 'kspp', 'DEVMEM', 'is not set')  # refers to LOCKDOWN
    bpf_syscall_not_set = KconfigCheck('cut_attack_surface', 'lockdown', 'BPF_SYSCALL', 'is not set')
                          # refers to LOCKDOWN
    selinux_not_set = KconfigCheck('-', '-', 'SECURITY_SELINUX', 'is not set')

    # 'self_protection', 'defconfig'
    l += [KconfigCheck('self_protection', 'defconfig', 'BUG', 'y')]
    l += [KconfigCheck('self_protection', 'defconfig', 'SLUB_DEBUG', 'y')]
    l += [KconfigCheck('self_protection', 'defconfig', 'THREAD_INFO_IN_TASK', 'y')]
    l += [KconfigCheck('self_protection', 'defconfig', 'IOMMU_DEFAULT_PASSTHROUGH', 'is not set')]
          # mutually exclusive with IOMMU_DEFAULT_DMA_STRICT
    iommu_support_is_set = KconfigCheck('self_protection', 'defconfig', 'IOMMU_SUPPORT', 'y')
    l += [iommu_support_is_set]  # is needed for mitigating DMA attacks
    l += [OR(KconfigCheck('self_protection', 'defconfig', 'STACKPROTECTOR', 'y'),
             KconfigCheck('self_protection', 'defconfig', 'CC_STACKPROTECTOR', 'y'),
             KconfigCheck('self_protection', 'defconfig', 'CC_STACKPROTECTOR_REGULAR', 'y'),
             KconfigCheck('self_protection', 'defconfig', 'CC_STACKPROTECTOR_AUTO', 'y'),
             KconfigCheck('self_protection', 'defconfig', 'CC_STACKPROTECTOR_STRONG', 'y'))]
    l += [OR(KconfigCheck('self_protection', 'defconfig', 'STACKPROTECTOR_STRONG', 'y'),
             KconfigCheck('self_protection', 'defconfig', 'CC_STACKPROTECTOR_STRONG', 'y'))]
    l += [OR(KconfigCheck('self_protection', 'defconfig', 'STRICT_KERNEL_RWX', 'y'),
             KconfigCheck('self_protection', 'defconfig', 'DEBUG_RODATA', 'y'))]  # before v4.11
    l += [OR(KconfigCheck('self_protection', 'defconfig', 'STRICT_MODULE_RWX', 'y'),
             KconfigCheck('self_protection', 'defconfig', 'DEBUG_SET_MODULE_RONX', 'y'),
             modules_not_set)]  # DEBUG_SET_MODULE_RONX existed before v4.11
    l += [OR(KconfigCheck('self_protection', 'defconfig', 'REFCOUNT_FULL', 'y'),
             VersionCheck((5, 4, 208)))]
             # REFCOUNT_FULL is enabled by default since v5.5 and backported to v5.4.208
    l += [OR(KconfigCheck('self_protection', 'defconfig', 'INIT_STACK_ALL_ZERO', 'y'),
             AND(KconfigCheck('self_protection', 'kspp', 'GCC_PLUGIN_STRUCTLEAK', 'y'),
                 KconfigCheck('self_protection', 'kspp', 'GCC_PLUGIN_STRUCTLEAK_BYREF_ALL', 'y')))]
    l += [OR(KconfigCheck('self_protection', 'defconfig', 'CPU_MITIGATIONS', 'y'),
             KconfigCheck('self_protection', 'defconfig', 'SPECULATION_MITIGATIONS', 'y'))]
    if arch in {'X86_64', 'ARM64', 'X86_32'}:
        l += [KconfigCheck('self_protection', 'defconfig', 'RANDOMIZE_BASE', 'y')]
    vmap_stack_is_set = KconfigCheck('self_protection', 'defconfig', 'VMAP_STACK', 'y')
    if arch in {'X86_64', 'ARM64', 'ARM', 'RISCV'}:
        l += [vmap_stack_is_set]
    if arch in {'X86_64', 'X86_32', 'RISCV'}:
        l += [OR(KconfigCheck('self_protection', 'defconfig', 'LSM_MMAP_MIN_ADDR', '65536'),
                 selinux_not_set)]
    if arch in {'X86_64', 'X86_32'}:
        l += [KconfigCheck('self_protection', 'defconfig', 'DEBUG_WX', 'y')]
        l += [KconfigCheck('self_protection', 'defconfig', 'WERROR', 'y')]
        l += [KconfigCheck('self_protection', 'defconfig', 'X86_MCE', 'y')]
        l += [KconfigCheck('self_protection', 'defconfig', 'MITIGATION_SPECTRE_V1', 'y')]
        l += [KconfigCheck('self_protection', 'defconfig', 'MITIGATION_SPECTRE_V2', 'y')]
        l += [KconfigCheck('self_protection', 'defconfig', 'MITIGATION_SSB', 'y')]
        microcode_is_set = KconfigCheck('self_protection', 'defconfig', 'MICROCODE', 'y')
        l += [microcode_is_set]  # is needed for mitigating CPU bugs
        l += [OR(KconfigCheck('self_protection', 'defconfig', 'MICROCODE_INTEL', 'y'),
                 cpu_sup_intel_not_set,
                 AND(microcode_is_set,
                     VersionCheck((6, 6, 0))))]  # MICROCODE_INTEL was included in MICROCODE since v6.6
        l += [OR(KconfigCheck('self_protection', 'defconfig', 'MICROCODE_AMD', 'y'),
                 cpu_sup_amd_not_set,
                 AND(microcode_is_set,
                     VersionCheck((6, 6, 0))))]  # MICROCODE_AMD was included in MICROCODE since v6.6
        l += [OR(KconfigCheck('self_protection', 'defconfig', 'X86_SMAP', 'y'),
                 VersionCheck((5, 19, 0)))]  # X86_SMAP is enabled by default since v5.19
        l += [OR(KconfigCheck('self_protection', 'defconfig', 'X86_UMIP', 'y'),
                 KconfigCheck('self_protection', 'defconfig', 'X86_INTEL_UMIP', 'y'))]
        l += [OR(KconfigCheck('self_protection', 'defconfig', 'X86_MCE_INTEL', 'y'),
                 cpu_sup_intel_not_set)]
        l += [OR(KconfigCheck('self_protection', 'defconfig', 'X86_MCE_AMD', 'y'),
                 cpu_sup_amd_not_set)]
        l += [OR(KconfigCheck('self_protection', 'defconfig', 'MITIGATION_RETPOLINE', 'y'),
                 KconfigCheck('self_protection', 'defconfig', 'RETPOLINE', 'y'))]
        l += [OR(KconfigCheck('self_protection', 'defconfig', 'MITIGATION_GDS', 'y'),
                 cpu_sup_intel_not_set)]
        l += [OR(KconfigCheck('self_protection', 'defconfig', 'MITIGATION_RFDS', 'y'),
                 cpu_sup_intel_not_set)]
        l += [OR(KconfigCheck('self_protection', 'defconfig', 'MITIGATION_SPECTRE_BHI', 'y'),
                 cpu_sup_intel_not_set)]
        l += [OR(KconfigCheck('self_protection', 'defconfig', 'MITIGATION_MDS', 'y'),
                 cpu_sup_intel_not_set)]
        l += [OR(KconfigCheck('self_protection', 'defconfig', 'MITIGATION_TAA', 'y'),
                 cpu_sup_intel_not_set)]
        l += [OR(KconfigCheck('self_protection', 'defconfig', 'MITIGATION_MMIO_STALE_DATA', 'y'),
                 cpu_sup_intel_not_set)]
        l += [OR(KconfigCheck('self_protection', 'defconfig', 'MITIGATION_L1TF', 'y'),
                 cpu_sup_intel_not_set)]
        l += [OR(KconfigCheck('self_protection', 'defconfig', 'MITIGATION_RETBLEED', 'y'),
                 cpu_sup_intel_not_set)]
        l += [OR(KconfigCheck('self_protection', 'defconfig', 'MITIGATION_SRBDS', 'y'),
                 cpu_sup_intel_not_set)]
        l += [OR(KconfigCheck('self_protection', 'defconfig', 'MITIGATION_TSA', 'y'),
                 cpu_sup_amd_not_set)]
        l += [OR(KconfigCheck('self_protection', 'defconfig', 'MITIGATION_VMSCAPE', 'y'),
                 KconfigCheck('-', '-', 'KVM', 'is not set'))]
    if arch in {'ARM64', 'ARM', 'RISCV'}:
        l += [KconfigCheck('self_protection', 'defconfig', 'IOMMU_DEFAULT_DMA_STRICT', 'y')]
        l += [KconfigCheck('self_protection', 'defconfig', 'IOMMU_DEFAULT_DMA_LAZY', 'is not set')]
              # mutually exclusive with IOMMU_DEFAULT_DMA_STRICT
        l += [KconfigCheck('self_protection', 'defconfig', 'STACKPROTECTOR_PER_TASK', 'y')]
    if arch in {'ARM64', 'ARM'}:
        l += [KconfigCheck('self_protection', 'defconfig', 'HW_RANDOM_TPM', 'y')]
    if arch == 'X86_64':
        l += [KconfigCheck('self_protection', 'defconfig', 'RANDOMIZE_MEMORY', 'y')]
        l += [KconfigCheck('self_protection', 'defconfig', 'X86_KERNEL_IBT', 'y')]
        l += [KconfigCheck('self_protection', 'defconfig', 'MITIGATION_RETHUNK', 'y')]
        l += [OR(KconfigCheck('self_protection', 'defconfig', 'MITIGATION_PAGE_TABLE_ISOLATION', 'y'),
                 KconfigCheck('self_protection', 'defconfig', 'PAGE_TABLE_ISOLATION', 'y'))]
        l += [OR(KconfigCheck('self_protection', 'defconfig', 'MITIGATION_UNRET_ENTRY', 'y'),
                 cpu_sup_amd_not_set)]
        l += [OR(KconfigCheck('self_protection', 'defconfig', 'MITIGATION_CALL_DEPTH_TRACKING', 'y'),
                 cpu_sup_intel_not_set)]
        l += [OR(KconfigCheck('self_protection', 'defconfig', 'MITIGATION_IBPB_ENTRY', 'y'),
                 cpu_sup_amd_not_set)]
        l += [OR(KconfigCheck('self_protection', 'defconfig', 'MITIGATION_IBRS_ENTRY', 'y'),
                 cpu_sup_intel_not_set)]
        l += [OR(KconfigCheck('self_protection', 'defconfig', 'MITIGATION_SRSO', 'y'),
                 KconfigCheck('self_protection', 'defconfig', 'CPU_SRSO', 'y'),
                 cpu_sup_amd_not_set)]
        l += [OR(KconfigCheck('self_protection', 'defconfig', 'MITIGATION_ITS', 'y'),
                 cpu_sup_intel_not_set)]
        l += [AND(KconfigCheck('self_protection', 'defconfig', 'INTEL_IOMMU', 'y'),
                  iommu_support_is_set)]
        l += [AND(KconfigCheck('self_protection', 'defconfig', 'AMD_IOMMU', 'y'),
                  iommu_support_is_set)]
    if arch == 'ARM64':
        l += [KconfigCheck('self_protection', 'defconfig', 'ARM64_PAN', 'y')]
        l += [KconfigCheck('self_protection', 'defconfig', 'ARM64_EPAN', 'y')]
        l += [KconfigCheck('self_protection', 'defconfig', 'UNMAP_KERNEL_AT_EL0', 'y')]
        l += [KconfigCheck('self_protection', 'defconfig', 'ARM64_E0PD', 'y')]
        l += [OR(KconfigCheck('self_protection', 'defconfig', 'RODATA_FULL_DEFAULT_ENABLED', 'y'),
                 VersionCheck((6, 18, 0)))]  # removed in v6.18; full rodata protection is now the default
        l += [KconfigCheck('self_protection', 'defconfig', 'ARM64_PTR_AUTH_KERNEL', 'y')]
        l += [KconfigCheck('self_protection', 'defconfig', 'ARM64_BTI_KERNEL', 'y')]
        l += [KconfigCheck('self_protection', 'defconfig', 'ARM_SMMU', 'y')]
        l += [KconfigCheck('self_protection', 'defconfig', 'ARM_SMMU_DISABLE_BYPASS_BY_DEFAULT', 'y')]
        l += [KconfigCheck('self_protection', 'defconfig', 'ARM_SMMU_V3', 'y')]
        l += [KconfigCheck('self_protection', 'defconfig', 'MITIGATE_SPECTRE_BRANCH_HISTORY', 'y')]
        l += [KconfigCheck('self_protection', 'defconfig', 'ARM64_MTE', 'y')]
        l += [KconfigCheck('self_protection', 'defconfig', 'RANDOMIZE_MODULE_REGION_FULL', 'y')]
        l += [OR(KconfigCheck('self_protection', 'defconfig', 'HARDEN_EL2_VECTORS', 'y'),
                 AND(KconfigCheck('self_protection', 'defconfig', 'RANDOMIZE_BASE', 'y'),
                     VersionCheck((5, 9, 0))))]  # HARDEN_EL2_VECTORS was included in RANDOMIZE_BASE in v5.9
        l += [OR(KconfigCheck('self_protection', 'defconfig', 'HARDEN_BRANCH_PREDICTOR', 'y'),
                 VersionCheck((5, 10, 0)))]  # HARDEN_BRANCH_PREDICTOR is enabled by default since v5.10
    if arch == 'ARM':
        l += [KconfigCheck('self_protection', 'defconfig', 'ARM_PAN', 'y')]
        l += [KconfigCheck('self_protection', 'defconfig', 'CPU_SW_DOMAIN_PAN', 'y')]
        l += [KconfigCheck('self_protection', 'defconfig', 'HARDEN_BRANCH_PREDICTOR', 'y')]
        l += [KconfigCheck('self_protection', 'defconfig', 'HARDEN_BRANCH_HISTORY', 'y')]
        l += [KconfigCheck('self_protection', 'defconfig', 'DEBUG_ALIGN_RODATA', 'y')]
    if arch == 'RISCV':
        l += [OR(KconfigCheck('self_protection', 'defconfig', 'ERRATA_THEAD_GHOSTWRITE', 'y'),
                 KconfigCheck('self_protection', 'defconfig', 'RISCV_ISA_XTHEADVECTOR', 'is not set'))]
        l += [OR(KconfigCheck('self_protection', 'defconfig', 'LIST_HARDENED', 'y'),
                 KconfigCheck('self_protection', 'defconfig', 'DEBUG_LIST', 'y'))]

    # 'self_protection', 'kspp'
    l += [OR(KconfigCheck('self_protection', 'kspp', 'KMALLOC_PARTITION_CACHES', 'y'),
             KconfigCheck('self_protection', 'kspp', 'RANDOM_KMALLOC_CACHES', 'y'))]
             # KMALLOC_PARTITION_CACHES replaces the transitional RANDOM_KMALLOC_CACHES in Linux v7.2
    l += [KconfigCheck('self_protection', 'kspp', 'SLAB_BUCKETS', 'y')]
    l += [KconfigCheck('self_protection', 'kspp', 'SLAB_MERGE_DEFAULT', 'is not set')]
    l += [KconfigCheck('self_protection', 'kspp', 'BUG_ON_DATA_CORRUPTION', 'y')]
    l += [KconfigCheck('self_protection', 'kspp', 'SLAB_FREELIST_HARDENED', 'y')]
    l += [KconfigCheck('self_protection', 'kspp', 'SLAB_FREELIST_RANDOM', 'y')]
    l += [KconfigCheck('self_protection', 'kspp', 'SHUFFLE_PAGE_ALLOCATOR', 'y')]  # requires page_alloc.shuffle=1
    l += [KconfigCheck('self_protection', 'kspp', 'FORTIFY_SOURCE', 'y')]
    l += [KconfigCheck('self_protection', 'kspp', 'DEBUG_VIRTUAL', 'y')]
    l += [KconfigCheck('self_protection', 'kspp', 'INIT_ON_ALLOC_DEFAULT_ON', 'y')]
    l += [KconfigCheck('self_protection', 'kspp', 'STATIC_USERMODEHELPER', 'y')]  # needs userspace support
    l += [KconfigCheck('self_protection', 'kspp', 'SECURITY_LOCKDOWN_LSM', 'y')]
    l += [KconfigCheck('self_protection', 'kspp', 'LSM', '*lockdown*')]
    l += [KconfigCheck('self_protection', 'kspp', 'SECURITY_LOCKDOWN_LSM_EARLY', 'y')]
    l += [KconfigCheck('self_protection', 'kspp', 'LOCK_DOWN_KERNEL_FORCE_CONFIDENTIALITY', 'y')]
    l += [KconfigCheck('self_protection', 'kspp', 'DEBUG_SG', 'y')]
    l += [KconfigCheck('self_protection', 'kspp', 'ZERO_CALL_USED_REGS', 'y')]
          # ZERO_CALL_USED_REGS is useless against ROP, however AMD claims that it makes
          # the BTC-RET attack harder (Branch Type Confusion for RET instructions, CVE-2022-29900)
    cfi_clang_is_set = KconfigCheck('self_protection', 'kspp', 'CFI_CLANG', 'y')
    cfi_clang_permissive_not_set = KconfigCheck('self_protection', 'kspp', 'CFI_PERMISSIVE', 'is not set')
    cfi_is_set = KconfigCheck('self_protection', 'kspp', 'CFI', 'y')
    cfi_permissive_not_set = KconfigCheck('self_protection', 'kspp', 'CFI_PERMISSIVE', 'is not set')
    l += [OR(KconfigCheck('self_protection', 'kspp', 'DEBUG_CREDENTIALS', 'y'),
             VersionCheck((6, 6, 8)))]  # DEBUG_CREDENTIALS was dropped in v6.6.8
    l += [OR(KconfigCheck('self_protection', 'kspp', 'DEBUG_NOTIFIERS', 'y'),
             AND(cfi_clang_is_set,
                 cfi_clang_permissive_not_set,
                 cc_is_clang),
             AND(cfi_is_set,
                 cfi_permissive_not_set))]
    kfence_is_set = KconfigCheck('self_protection', 'kspp', 'KFENCE', 'y')
    l += [kfence_is_set]
    l += [AND(KconfigCheck('self_protection', 'kspp', 'KFENCE_SAMPLE_INTERVAL', '100'),
              kfence_is_set)]
    randstruct_is_set = OR(KconfigCheck('self_protection', 'kspp', 'RANDSTRUCT_FULL', 'y'),
                           KconfigCheck('self_protection', 'kspp', 'GCC_PLUGIN_RANDSTRUCT', 'y'))
    l += [randstruct_is_set]
#   l += [AND(KconfigCheck('self_protection', 'kspp', 'RANDSTRUCT_PERFORMANCE', 'is not set'),
#             KconfigCheck('self_protection', 'kspp', 'GCC_PLUGIN_RANDSTRUCT_PERFORMANCE', 'is not set'),
#             randstruct_is_set)] # comment this out for now: KSPP has revoked this recommendation
    hardened_usercopy_is_set = KconfigCheck('self_protection', 'kspp', 'HARDENED_USERCOPY', 'y')
    l += [hardened_usercopy_is_set]
    l += [AND(KconfigCheck('self_protection', 'kspp', 'HARDENED_USERCOPY_DEFAULT_ON', 'y'),
              hardened_usercopy_is_set)]
    l += [AND(KconfigCheck('self_protection', 'kspp', 'HARDENED_USERCOPY_FALLBACK', 'is not set'),
              hardened_usercopy_is_set)]  # usercopy whitelist violations should be prohibited
    l += [AND(KconfigCheck('self_protection', 'kspp', 'HARDENED_USERCOPY_PAGESPAN', 'is not set'),
              hardened_usercopy_is_set)]  # this debugging for HARDENED_USERCOPY is not needed for security
    l += [AND(KconfigCheck('self_protection', 'kspp', 'GCC_PLUGIN_LATENT_ENTROPY', 'y'),
              cc_is_gcc)]
    l += [OR(KconfigCheck('self_protection', 'kspp', 'MODULE_SIG', 'y'),
             modules_not_set)]
    l += [OR(KconfigCheck('self_protection', 'kspp', 'MODULE_SIG_ALL', 'y'),
             modules_not_set)]
    l += [OR(KconfigCheck('self_protection', 'kspp', 'MODULE_SIG_SHA512', 'y'),
             KconfigCheck('self_protection', 'a13xp0p0v', 'MODULE_SIG_SHA3_512', 'y'),
             modules_not_set)]
    l += [OR(KconfigCheck('self_protection', 'kspp', 'MODULE_SIG_FORCE', 'y'),
             modules_not_set)]  # refers to LOCKDOWN
    l += [OR(KconfigCheck('self_protection', 'kspp', 'INIT_ON_FREE_DEFAULT_ON', 'y'),
             KconfigCheck('self_protection', 'kspp', 'PAGE_POISONING_ZERO', 'y'))]
             # INIT_ON_FREE_DEFAULT_ON was added in v5.3.
             # PAGE_POISONING_ZERO was removed in v5.11.
             # Starting from v5.11 PAGE_POISONING unconditionally checks
             # the 0xAA poison pattern on allocation.
             # That brings higher performance penalty.
    l += [OR(KconfigCheck('self_protection', 'kspp', 'EFI_DISABLE_PCI_DMA', 'y'),
             efi_not_set)]
    l += [OR(KconfigCheck('self_protection', 'kspp', 'RESET_ATTACK_MITIGATION', 'y'),
             efi_not_set)]  # needs userspace support (systemd)
    ubsan_bounds_is_set = KconfigCheck('self_protection', 'kspp', 'UBSAN_BOUNDS', 'y')
    l += [ubsan_bounds_is_set]
    l += [OR(KconfigCheck('self_protection', 'kspp', 'UBSAN_LOCAL_BOUNDS', 'y'),
             AND(ubsan_bounds_is_set,
                 cc_is_gcc))]
    l += [AND(KconfigCheck('self_protection', 'kspp', 'UBSAN_TRAP', 'y'),
              ubsan_bounds_is_set,
              KconfigCheck('self_protection', 'kspp', 'UBSAN_SHIFT', 'is not set'),
              KconfigCheck('self_protection', 'kspp', 'UBSAN_DIV_ZERO', 'is not set'),
              KconfigCheck('self_protection', 'kspp', 'UBSAN_UNREACHABLE', 'is not set'),
              KconfigCheck('self_protection', 'kspp', 'UBSAN_SIGNED_WRAP', 'is not set'),
              KconfigCheck('self_protection', 'kspp', 'UBSAN_INTEGER_WRAP', 'is not set'),
              KconfigCheck('self_protection', 'kspp', 'UBSAN_BOOL', 'is not set'),
              KconfigCheck('self_protection', 'kspp', 'UBSAN_ENUM', 'is not set'),
              KconfigCheck('self_protection', 'kspp', 'UBSAN_ALIGNMENT', 'is not set'))]
              # only array index bounds checking with traps
    l += [OR(KconfigCheck('self_protection', 'kspp', 'UBSAN_SANITIZE_ALL', 'y'),
             AND(ubsan_bounds_is_set,
                 VersionCheck((6, 9, 0))))]
             # UBSAN_SANITIZE_ALL was enabled by default in UBSAN in v6.9
    l += [OR(KconfigCheck('self_protection', 'kspp', 'SCHED_STACK_END_CHECK', 'y'),
             vmap_stack_is_set)]
    stackleak_is_set = OR(KconfigCheck('self_protection', 'kspp', 'KSTACK_ERASE', 'y'),
                          KconfigCheck('self_protection', 'kspp', 'GCC_PLUGIN_STACKLEAK', 'y'))
    l += [stackleak_is_set]
    l += [AND(KconfigCheck('self_protection', 'kspp', 'KSTACK_ERASE_METRICS', 'is not set'),
              KconfigCheck('self_protection', 'kspp', 'STACKLEAK_METRICS', 'is not set'),
              stackleak_is_set)]
    l += [AND(KconfigCheck('self_protection', 'kspp', 'KSTACK_ERASE_RUNTIME_DISABLE', 'is not set'),
              KconfigCheck('self_protection', 'kspp', 'STACKLEAK_RUNTIME_DISABLE', 'is not set'),
              stackleak_is_set)]
    if arch in {'X86_64', 'ARM64', 'X86_32', 'ARM'}:
        l += [KconfigCheck('self_protection', 'kspp', 'SCHED_CORE', 'y')]
        l += [OR(KconfigCheck('self_protection', 'kspp', 'LIST_HARDENED', 'y'),
                 KconfigCheck('self_protection', 'kspp', 'DEBUG_LIST', 'y'))]
    if arch in {'X86_64', 'ARM64', 'X86_32', 'RISCV'}:
        l += [KconfigCheck('self_protection', 'kspp', 'RANDOMIZE_KSTACK_OFFSET_DEFAULT', 'y')]
    if arch in {'X86_64', 'ARM64', 'RISCV'}:
        l += [KconfigCheck('self_protection', 'kspp', 'PAGE_TABLE_CHECK', 'y')]
        l += [KconfigCheck('self_protection', 'kspp', 'PAGE_TABLE_CHECK_ENFORCED', 'y')]
    if arch in {'X86_64', 'X86_32', 'RISCV'}:
        l += [KconfigCheck('self_protection', 'kspp', 'DEFAULT_MMAP_MIN_ADDR', '65536')]
        l += [KconfigCheck('self_protection', 'kspp', 'HW_RANDOM_TPM', 'y')]
    if arch in {'ARM64', 'ARM', 'RISCV'}:
        l += [KconfigCheck('self_protection', 'kspp', 'WERROR', 'y')]
    if arch in {'X86_64', 'ARM64'}:
        l += [AND(cfi_clang_is_set,
                  cc_is_clang)]
        l += [AND(cfi_clang_permissive_not_set,
                  cfi_clang_is_set,
                  cc_is_clang)]
    if arch in {'X86_64', 'X86_32'}:
        l += [KconfigCheck('self_protection', 'kspp', 'IOMMU_DEFAULT_DMA_STRICT', 'y')]
        l += [KconfigCheck('self_protection', 'kspp', 'IOMMU_DEFAULT_DMA_LAZY', 'is not set')]
              # mutually exclusive with IOMMU_DEFAULT_DMA_STRICT
        l += [AND(KconfigCheck('self_protection', 'kspp', 'INTEL_IOMMU_DEFAULT_ON', 'y'),
                  iommu_support_is_set)]
    if arch in {'ARM64', 'RISCV'}:
        l += [KconfigCheck('self_protection', 'kspp', 'DEBUG_WX', 'y')]
    if arch == 'X86_64':
        l += [AND(KconfigCheck('self_protection', 'kspp', 'CFI_AUTO_DEFAULT', 'is not set'),
                  KconfigCheck('self_protection', 'kspp', 'CFI_AUTO_DEFAULT', 'is present'))]
        l += [OR(KconfigCheck('self_protection', 'kspp', 'MITIGATION_SLS', 'y'),
                 KconfigCheck('self_protection', 'kspp', 'SLS', 'y'))]
                 # this feature protects against CVE-2021-26341 in Straight-Line-Speculation
        l += [AND(KconfigCheck('self_protection', 'kspp', 'INTEL_IOMMU_SVM', 'y'),
                  iommu_support_is_set)]
        l += [OR(KconfigCheck('self_protection', 'kspp', 'AMD_IOMMU_V2', 'y'),
                 VersionCheck((6, 7, 0)))]  # AMD_IOMMU_V2 was dropped in v6.7
    if arch == 'ARM64':
        l += [KconfigCheck('self_protection', 'kspp', 'ARM64_SW_TTBR0_PAN', 'y')]
        l += [KconfigCheck('self_protection', 'kspp', 'SHADOW_CALL_STACK', 'y')]
        l += [KconfigCheck('self_protection', 'kspp', 'KASAN_HW_TAGS', 'y')]
              # see also: kasan=on, kasan.stacktrace=off, kasan.fault=panic
        l += [AND(KconfigCheck('self_protection', 'kspp', 'DEFAULT_MMAP_MIN_ADDR', '65536'),
                  KconfigCheck('cut_attack_surface', 'kspp', 'COMPAT', 'is not set'))]
                  # LSM_MMAP_MIN_ADDR in security/Kconfig has the default value
                  # 32768 if ARM || (ARM64 && COMPAT). That's why we require
                  # COMPAT disabled for setting DEFAULT_MMAP_MIN_ADDR=65536 on ARM64.
    if arch == 'X86_32':
        l += [KconfigCheck('self_protection', 'kspp', 'X86_PAE', 'y')]
        l += [OR(KconfigCheck('self_protection', 'kspp', 'MITIGATION_PAGE_TABLE_ISOLATION', 'y'),
                 KconfigCheck('self_protection', 'kspp', 'PAGE_TABLE_ISOLATION', 'y'))]
        l += [AND(KconfigCheck('self_protection', 'kspp', 'INTEL_IOMMU', 'y'),
                  iommu_support_is_set)]
        l += [OR(KconfigCheck('self_protection', 'kspp', 'HIGHMEM64G', 'y'),
                 AND(KconfigCheck('self_protection', 'kspp', 'HIGHMEM4G', 'y'),
                     VersionCheck((6, 15, 0))))]
                 # The commit bbeb69ce301323e84f1677484eb8e4cd8fb1f9f8 in Linux v6.15
                 # removed HIGHMEM64G support
    if arch == 'ARM':
        l += [KconfigCheck('self_protection', 'kspp', 'DEFAULT_MMAP_MIN_ADDR', '32768')]
        l += [OR(KconfigCheck('self_protection', 'kspp', 'ARM_DEBUG_WX', 'y'),
                 KconfigCheck('self_protection', 'kspp', 'DEBUG_WX', 'y'))]
                 # DEBUG_WX has been renamed to ARM_DEBUG_WX on ARM
    if arch == 'RISCV':
        l += [KconfigCheck('self_protection', 'kspp', 'RANDOMIZE_BASE', 'y')]

    # 'self_protection', 'a13xp0p0v'
    if arch == 'ARM64':
        l += [OR(selinux_not_set,
                 AND(KconfigCheck('self_protection', 'a13xp0p0v', 'LSM_MMAP_MIN_ADDR', '65536'),
                     KconfigCheck('cut_attack_surface', 'kspp', 'COMPAT', 'is not set')))]
                 # LSM_MMAP_MIN_ADDR applies only with SELinux; ARM64 also needs COMPAT disabled for 65536.
    if arch == 'ARM':
        l += [KconfigCheck('self_protection', 'a13xp0p0v', 'ARM_SMMU', 'y')]
        l += [KconfigCheck('self_protection', 'a13xp0p0v', 'ARM_SMMU_DISABLE_BYPASS_BY_DEFAULT', 'y')]
        l += [OR(KconfigCheck('self_protection', 'a13xp0p0v', 'LSM_MMAP_MIN_ADDR', '32768'),
                 selinux_not_set)]
              # LSM_MMAP_MIN_ADDR is SELinux-dependent and may be absent from defconfig.

    # 'security_policy'
    if arch in {'X86_64', 'ARM64', 'X86_32', 'RISCV'}:
        l += [KconfigCheck('security_policy', 'defconfig', 'SECURITY', 'y')]
    if arch == 'ARM':
        l += [KconfigCheck('security_policy', 'kspp', 'SECURITY', 'y')]
    l += [KconfigCheck('security_policy', 'kspp', 'SECURITY_YAMA', 'y')]
    l += [KconfigCheck('security_policy', 'kspp', 'LSM', '*yama*')]
    l += [KconfigCheck('security_policy', 'kspp', 'SECURITY_LANDLOCK', 'y')]
    l += [KconfigCheck('security_policy', 'kspp', 'LSM', '*landlock*')]
    l += [KconfigCheck('security_policy', 'kspp', 'SECURITY_SELINUX_DISABLE', 'is not set')]
    l += [KconfigCheck('security_policy', 'kspp', 'SECURITY_SELINUX_BOOTPARAM', 'is not set')]
    l += [KconfigCheck('security_policy', 'kspp', 'SECURITY_SELINUX_DEVELOP', 'is not set')]
    l += [KconfigCheck('security_policy', 'kspp', 'SECURITY_WRITABLE_HOOKS', 'is not set')]
          # refers to SECURITY_SELINUX_DISABLE
    l += [KconfigCheck('security_policy', 'kspp', 'SECURITY_SELINUX_DEBUG', 'is not set')]
    l += [OR(KconfigCheck('security_policy', 'a13xp0p0v', 'SECURITY_SELINUX', 'y'),
             KconfigCheck('security_policy', 'a13xp0p0v', 'SECURITY_APPARMOR', 'y'),
             KconfigCheck('security_policy', 'a13xp0p0v', 'SECURITY_SMACK', 'y'),
             KconfigCheck('security_policy', 'a13xp0p0v', 'SECURITY_TOMOYO', 'y'))]
             # one of major LSMs implementing MAC
    l += [OR(KconfigCheck('security_policy', 'a13xp0p0v', 'LSM', '*selinux*'),
             KconfigCheck('security_policy', 'a13xp0p0v', 'LSM', '*apparmor*'),
             KconfigCheck('security_policy', 'a13xp0p0v', 'LSM', '*smack*'),
             KconfigCheck('security_policy', 'a13xp0p0v', 'LSM', '*tomoyo*'))]
             # N.B. Here we check that one of major LSMs implementing MAC is in the LSM list,
             # but we can't be sure that it's the same module that was detected in the check above

    # N.B. We don't use 'if arch' for the 'cut_attack_surface' checks that require 'is not set'.
    # It makes the maintainance easier. These kernel options should be disabled anyway.
    # 'cut_attack_surface', 'defconfig'
    l += [KconfigCheck('cut_attack_surface', 'defconfig', 'SECCOMP', 'y')]
    l += [KconfigCheck('cut_attack_surface', 'defconfig', 'SECCOMP_FILTER', 'y')]
    l += [OR(KconfigCheck('cut_attack_surface', 'defconfig', 'BPF_UNPRIV_DEFAULT_OFF', 'y'),
             bpf_syscall_not_set)]  # see unprivileged_bpf_disabled
    if arch in {'X86_64', 'ARM64', 'X86_32'}:
        l += [OR(KconfigCheck('cut_attack_surface', 'defconfig', 'STRICT_DEVMEM', 'y'),
                 devmem_not_set)]  # refers to LOCKDOWN
    if arch in {'X86_64', 'X86_32'}:
        l += [OR(KconfigCheck('cut_attack_surface', 'defconfig', 'X86_INTEL_TSX_MODE_OFF', 'y'),
                 cpu_sup_intel_not_set)]  # tsx=off

    # 'cut_attack_surface', 'kspp'
    l += [KconfigCheck('cut_attack_surface', 'kspp', 'SECURITY_DMESG_RESTRICT', 'y')]
    l += [KconfigCheck('cut_attack_surface', 'kspp', 'ACPI_CUSTOM_METHOD', 'is not set')]  # refers to LOCKDOWN
    l += [KconfigCheck('cut_attack_surface', 'kspp', 'COMPAT_BRK', 'is not set')]
    l += [KconfigCheck('cut_attack_surface', 'kspp', 'DEVKMEM', 'is not set')]  # refers to LOCKDOWN
    l += [KconfigCheck('cut_attack_surface', 'kspp', 'BINFMT_MISC', 'is not set')]
    l += [KconfigCheck('cut_attack_surface', 'kspp', 'INET_DIAG', 'is not set')]
    l += [KconfigCheck('cut_attack_surface', 'kspp', 'KEXEC', 'is not set')]  # refers to LOCKDOWN
    l += [KconfigCheck('cut_attack_surface', 'kspp', 'PROC_KCORE', 'is not set')]  # refers to LOCKDOWN
    l += [KconfigCheck('cut_attack_surface', 'kspp', 'LEGACY_PTYS', 'is not set')]
    l += [KconfigCheck('cut_attack_surface', 'kspp', 'HIBERNATION', 'is not set')]  # refers to LOCKDOWN
    l += [KconfigCheck('cut_attack_surface', 'kspp', 'COMPAT', 'is not set')]
    l += [KconfigCheck('cut_attack_surface', 'kspp', 'IA32_EMULATION', 'is not set')]
    l += [KconfigCheck('cut_attack_surface', 'kspp', 'X86_X32', 'is not set')]
    l += [KconfigCheck('cut_attack_surface', 'kspp', 'X86_X32_ABI', 'is not set')]
    l += [KconfigCheck('cut_attack_surface', 'kspp', 'MODIFY_LDT_SYSCALL', 'is not set')]
    l += [KconfigCheck('cut_attack_surface', 'kspp', 'OABI_COMPAT', 'is not set')]
    l += [KconfigCheck('cut_attack_surface', 'kspp', 'X86_MSR', 'is not set')]  # refers to LOCKDOWN
    l += [KconfigCheck('cut_attack_surface', 'kspp', 'LEGACY_TIOCSTI', 'is not set')]
    l += [KconfigCheck('cut_attack_surface', 'kspp', 'MODULE_FORCE_LOAD', 'is not set')]
    l += [KconfigCheck('cut_attack_surface', 'kspp', 'M486', 'is not set')]  # M486 support is incompatible with X86_PAE
    l += [modules_not_set]
    l += [devmem_not_set]
    l += [OR(KconfigCheck('cut_attack_surface', 'kspp', 'IO_STRICT_DEVMEM', 'y'),
             devmem_not_set)]  # refers to LOCKDOWN
    l += [AND(KconfigCheck('cut_attack_surface', 'kspp', 'LDISC_AUTOLOAD', 'is not set'),
              KconfigCheck('cut_attack_surface', 'kspp', 'LDISC_AUTOLOAD', 'is present'))]
    l += [OR(KconfigCheck('cut_attack_surface', 'kspp', 'X86_VSYSCALL_EMULATION', 'is not set'),
             KconfigCheck('cut_attack_surface', 'kspp', 'LEGACY_VSYSCALL_NONE', 'y'))]
             # disabling X86_VSYSCALL_EMULATION turns vsyscall off completely,
             # and LEGACY_VSYSCALL_NONE can be changed at boot time via the cmdline parameter
    if arch in {'X86_64', 'X86_32'}:
        l += [KconfigCheck('cut_attack_surface', 'kspp', 'COMPAT_VDSO', 'is not set')]
              # COMPAT_VDSO disabled ASLR of vDSO only on X86_64 and X86_32;
              # on ARM64 this option has different meaning
    if arch in {'ARM', 'RISCV'}:
        l += [OR(KconfigCheck('cut_attack_surface', 'kspp', 'STRICT_DEVMEM', 'y'),
                 devmem_not_set)]  # refers to LOCKDOWN

    # 'cut_attack_surface', 'maintainer'
    l += [KconfigCheck('cut_attack_surface', 'maintainer', 'DRM_LEGACY', 'is not set')]
          # recommended by Daniel Vetter in /issues/38
    l += [KconfigCheck('cut_attack_surface', 'maintainer', 'FB', 'is not set')]
          # recommended by Daniel Vetter in /issues/38
    l += [KconfigCheck('cut_attack_surface', 'maintainer', 'VT', 'is not set')]
          # recommended by Daniel Vetter in /issues/38, requires the adaptation in the userspace (getty)
    l += [KconfigCheck('cut_attack_surface', 'maintainer', 'BLK_DEV_FD', 'is not set')]
          # recommended by Denis Efremov in /pull/54
    l += [KconfigCheck('cut_attack_surface', 'maintainer', 'BLK_DEV_FD_RAWCMD', 'is not set')]
          # recommended by Denis Efremov in /pull/62
    l += [KconfigCheck('cut_attack_surface', 'maintainer', 'NOUVEAU_LEGACY_CTX_SUPPORT', 'is not set')]
          # recommended by Dave Airlie in kernel commit b30a43ac7132cdda
    l += [KconfigCheck('cut_attack_surface', 'maintainer', 'N_GSM', 'is not set')]
          # recommended by Greg KH at https://www.openwall.com/lists/oss-security/2024/04/17/1
    l += [KconfigCheck('cut_attack_surface', 'maintainer', 'CRYPTO_USER_API', 'is not set')]
    l += [KconfigCheck('cut_attack_surface', 'maintainer', 'CRYPTO_USER_API_ENABLE_OBSOLETE', 'is not set')]
    l += [KconfigCheck('cut_attack_surface', 'maintainer', 'CRYPTO_USER_API_AEAD', 'is not set')]
    l += [KconfigCheck('cut_attack_surface', 'maintainer', 'CRYPTO_USER_API_HASH', 'is not set')]
    l += [KconfigCheck('cut_attack_surface', 'maintainer', 'CRYPTO_USER_API_RNG', 'is not set')]
    l += [KconfigCheck('cut_attack_surface', 'maintainer', 'CRYPTO_USER_API_RNG_CAVP', 'is not set')]
    l += [KconfigCheck('cut_attack_surface', 'maintainer', 'CRYPTO_USER_API_SKCIPHER', 'is not set')]
          # all recommended by Eric Biggers at https://news.ycombinator.com/item?id=47956312,
          # related to CVE-2026-31431 (Copy Fail)

    # 'cut_attack_surface', 'grsec'
    l += [KconfigCheck('cut_attack_surface', 'grsec', 'ZSMALLOC_STAT', 'is not set')]
    l += [KconfigCheck('cut_attack_surface', 'grsec', 'DEBUG_KMEMLEAK', 'is not set')]
    l += [KconfigCheck('cut_attack_surface', 'grsec', 'BINFMT_AOUT', 'is not set')]
    l += [KconfigCheck('cut_attack_surface', 'grsec', 'KPROBE_EVENTS', 'is not set')]
    l += [KconfigCheck('cut_attack_surface', 'grsec', 'UPROBE_EVENTS', 'is not set')]
    l += [KconfigCheck('cut_attack_surface', 'grsec', 'GENERIC_TRACER', 'is not set')]  # refers to LOCKDOWN
    l += [KconfigCheck('cut_attack_surface', 'grsec', 'FUNCTION_TRACER', 'is not set')]
    l += [KconfigCheck('cut_attack_surface', 'grsec', 'STACK_TRACER', 'is not set')]
    l += [KconfigCheck('cut_attack_surface', 'grsec', 'HIST_TRIGGERS', 'is not set')]
    l += [KconfigCheck('cut_attack_surface', 'grsec', 'BLK_DEV_IO_TRACE', 'is not set')]
    l += [KconfigCheck('cut_attack_surface', 'grsec', 'PROC_VMCORE', 'is not set')]
    l += [KconfigCheck('cut_attack_surface', 'grsec', 'PROC_PAGE_MONITOR', 'is not set')]
    l += [KconfigCheck('cut_attack_surface', 'grsec', 'USELIB', 'is not set')]
    l += [KconfigCheck('cut_attack_surface', 'grsec', 'CHECKPOINT_RESTORE', 'is not set')]
    l += [KconfigCheck('cut_attack_surface', 'grsec', 'USERFAULTFD', 'is not set')]
    l += [KconfigCheck('cut_attack_surface', 'grsec', 'HWPOISON_INJECT', 'is not set')]
    l += [KconfigCheck('cut_attack_surface', 'grsec', 'MEM_SOFT_DIRTY', 'is not set')]
    l += [KconfigCheck('cut_attack_surface', 'grsec', 'DEVPORT', 'is not set')]  # refers to LOCKDOWN
    l += [KconfigCheck('cut_attack_surface', 'grsec', 'DEBUG_FS', 'is not set')]  # refers to LOCKDOWN
    l += [KconfigCheck('cut_attack_surface', 'grsec', 'NOTIFIER_ERROR_INJECTION', 'is not set')]
    l += [KconfigCheck('cut_attack_surface', 'grsec', 'FAIL_FUTEX', 'is not set')]
    l += [KconfigCheck('cut_attack_surface', 'grsec', 'PUNIT_ATOM_DEBUG', 'is not set')]
    l += [KconfigCheck('cut_attack_surface', 'grsec', 'ACPI_CONFIGFS', 'is not set')]
    l += [KconfigCheck('cut_attack_surface', 'grsec', 'EDAC_DEBUG', 'is not set')]
    l += [KconfigCheck('cut_attack_surface', 'grsec', 'DRM_I915_DEBUG', 'is not set')]
    l += [KconfigCheck('cut_attack_surface', 'grsec', 'DVB_C8SECTPFE', 'is not set')]
    l += [KconfigCheck('cut_attack_surface', 'grsec', 'MTD_SLRAM', 'is not set')]
    l += [KconfigCheck('cut_attack_surface', 'grsec', 'MTD_PHRAM', 'is not set')]
    l += [KconfigCheck('cut_attack_surface', 'grsec', 'IO_URING', 'is not set')]
    l += [KconfigCheck('cut_attack_surface', 'grsec', 'KCMP', 'is not set')]
    l += [KconfigCheck('cut_attack_surface', 'grsec', 'RSEQ', 'is not set')]
    l += [KconfigCheck('cut_attack_surface', 'grsec', 'LATENCYTOP', 'is not set')]
    l += [KconfigCheck('cut_attack_surface', 'grsec', 'KCOV', 'is not set')]
    l += [KconfigCheck('cut_attack_surface', 'grsec', 'PROVIDE_OHCI1394_DMA_INIT', 'is not set')]
    l += [KconfigCheck('cut_attack_surface', 'grsec', 'SUNRPC_DEBUG', 'is not set')]
    l += [KconfigCheck('cut_attack_surface', 'grsec', 'X86_16BIT', 'is not set')]
    l += [KconfigCheck('cut_attack_surface', 'grsec', 'BLK_DEV_UBLK', 'is not set')]
    l += [KconfigCheck('cut_attack_surface', 'grsec', 'SMB_SERVER', 'is not set')]
    l += [KconfigCheck('cut_attack_surface', 'grsec', 'XFS_ONLINE_SCRUB_STATS', 'is not set')]
    l += [KconfigCheck('cut_attack_surface', 'grsec', 'CACHESTAT_SYSCALL', 'is not set')]
    l += [KconfigCheck('cut_attack_surface', 'grsec', 'PREEMPTIRQ_TRACEPOINTS', 'is not set')]
    l += [KconfigCheck('cut_attack_surface', 'grsec', 'ENABLE_DEFAULT_TRACERS', 'is not set')]
    l += [KconfigCheck('cut_attack_surface', 'grsec', 'PROVE_LOCKING', 'is not set')]
    l += [KconfigCheck('cut_attack_surface', 'grsec', 'TEST_DEBUG_VIRTUAL', 'is not set')]
    l += [KconfigCheck('cut_attack_surface', 'grsec', 'MPTCP', 'is not set')]
    l += [KconfigCheck('cut_attack_surface', 'grsec', 'TLS', 'is not set')]
    l += [KconfigCheck('cut_attack_surface', 'grsec', 'TIPC', 'is not set')]
    l += [KconfigCheck('cut_attack_surface', 'grsec', 'IP_SCTP', 'is not set')]
    l += [KconfigCheck('cut_attack_surface', 'grsec', 'KGDB', 'is not set')]
    l += [KconfigCheck('cut_attack_surface', 'grsec', 'PTDUMP_DEBUGFS', 'is not set')]
    l += [KconfigCheck('cut_attack_surface', 'grsec', 'X86_PTDUMP', 'is not set')]  # the old name of PTDUMP_DEBUGFS
    l += [KconfigCheck('cut_attack_surface', 'grsec', 'DEBUG_CLOSURES', 'is not set')]
    l += [KconfigCheck('cut_attack_surface', 'grsec', 'BCACHE_CLOSURES_DEBUG', 'is not set')]
          # the old name of DEBUG_CLOSURES

    # 'cut_attack_surface', 'clipos'
    l += [KconfigCheck('cut_attack_surface', 'clipos', 'STAGING', 'is not set')]
    l += [KconfigCheck('cut_attack_surface', 'clipos', 'KSM', 'is not set')]  # to prevent FLUSH+RELOAD attack
    l += [KconfigCheck('cut_attack_surface', 'clipos', 'KALLSYMS', 'is not set')]
    l += [KconfigCheck('cut_attack_surface', 'clipos', 'KEXEC_FILE', 'is not set')]  # refers to LOCKDOWN (permissive)
    l += [KconfigCheck('cut_attack_surface', 'clipos', 'CRASH_DUMP', 'is not set')]
    l += [KconfigCheck('cut_attack_surface', 'clipos', 'USER_NS', 'is not set')]  # user.max_user_namespaces=0
    l += [KconfigCheck('cut_attack_surface', 'clipos', 'X86_CPUID', 'is not set')]
    l += [KconfigCheck('cut_attack_surface', 'clipos', 'X86_IOPL_IOPERM', 'is not set')]  # refers to LOCKDOWN
    l += [KconfigCheck('cut_attack_surface', 'clipos', 'ACPI_TABLE_UPGRADE', 'is not set')]  # refers to LOCKDOWN
    l += [KconfigCheck('cut_attack_surface', 'clipos', 'EFI_CUSTOM_SSDT_OVERLAYS', 'is not set')]
    l += [KconfigCheck('cut_attack_surface', 'clipos', 'AIO', 'is not set')]
#   l += [KconfigCheck('cut_attack_surface', 'clipos', 'IKCONFIG', 'is not set')]
          # no, IKCONFIG is needed for this check :)
    l += [OR(KconfigCheck('cut_attack_surface', 'clipos', 'BPF_JIT_ALWAYS_ON', 'y'),
             bpf_syscall_not_set)]
    l += [OR(KconfigCheck('cut_attack_surface', 'clipos', 'MAGIC_SYSRQ', 'is not set'),
             KconfigCheck('cut_attack_surface', 'grapheneos', 'MAGIC_SYSRQ_DEFAULT_ENABLE', '0x0'))]

    # 'cut_attack_surface', 'grapheneos'
    l += [OR(KconfigCheck('cut_attack_surface', 'grapheneos', 'MAGIC_SYSRQ_SERIAL', 'is not set'),
             KconfigCheck('cut_attack_surface', 'grapheneos', 'MAGIC_SYSRQ_DEFAULT_ENABLE', '0x0'))]

    # 'cut_attack_surface', 'lockdown'
    l += [KconfigCheck('cut_attack_surface', 'lockdown', 'EFI_TEST', 'is not set')]  # refers to LOCKDOWN
    l += [KconfigCheck('cut_attack_surface', 'lockdown', 'MMIOTRACE_TEST', 'is not set')]  # refers to LOCKDOWN
    l += [KconfigCheck('cut_attack_surface', 'lockdown', 'KPROBES', 'is not set')]  # refers to LOCKDOWN
    l += [bpf_syscall_not_set]  # refers to LOCKDOWN

    # 'cut_attack_surface', 'a13xp0p0v'
    l += [KconfigCheck('cut_attack_surface', 'a13xp0p0v', 'MMIOTRACE', 'is not set')]  # refers to LOCKDOWN (permissive)
    l += [KconfigCheck('cut_attack_surface', 'a13xp0p0v', 'LIVEPATCH', 'is not set')]
    l += [KconfigCheck('cut_attack_surface', 'a13xp0p0v', 'IP_DCCP', 'is not set')]
    l += [KconfigCheck('cut_attack_surface', 'a13xp0p0v', 'FTRACE', 'is not set')]  # refers to LOCKDOWN
    l += [KconfigCheck('cut_attack_surface', 'a13xp0p0v', 'VIDEO_VIVID', 'is not set')]
    l += [KconfigCheck('cut_attack_surface', 'a13xp0p0v', 'INPUT_EVBUG', 'is not set')]  # can be used as a keylogger
    l += [KconfigCheck('cut_attack_surface', 'a13xp0p0v', 'CORESIGHT', 'is not set')]
    l += [KconfigCheck('cut_attack_surface', 'a13xp0p0v', 'XFS_SUPPORT_V4', 'is not set')]
    l += [KconfigCheck('cut_attack_surface', 'a13xp0p0v', 'BLK_DEV_WRITE_MOUNTED', 'is not set')]
          # see the comment about bdev_allow_write_mounted below
    l += [KconfigCheck('cut_attack_surface', 'a13xp0p0v', 'FAULT_INJECTION', 'is not set')]
    l += [KconfigCheck('cut_attack_surface', 'a13xp0p0v', 'ARM_PTDUMP_DEBUGFS', 'is not set')]
    l += [KconfigCheck('cut_attack_surface', 'a13xp0p0v', 'ARM_PTDUMP', 'is not set')]
          # the old name of ARM_PTDUMP_DEBUGFS
    l += [KconfigCheck('cut_attack_surface', 'a13xp0p0v', 'SECCOMP_CACHE_DEBUG', 'is not set')]
    l += [KconfigCheck('cut_attack_surface', 'a13xp0p0v', 'CRASH_DM_CRYPT', 'is not set')]
    l += [KconfigCheck('cut_attack_surface', 'a13xp0p0v', 'LKDTM', 'is not set')]
          # dangerous, only for debugging the kernel hardening features!
    l += [OR(KconfigCheck('cut_attack_surface', 'a13xp0p0v', 'TRIM_UNUSED_KSYMS', 'y'),
             modules_not_set)]

    # 'network_security'
    if arch in {'X86_64', 'X86_32'}:
        l += [KconfigCheck('network_security', 'defconfig', 'SYN_COOKIES', 'y')]
    if arch in {'ARM64', 'ARM', 'RISCV'}:
        l += [KconfigCheck('network_security', 'kspp', 'SYN_COOKIES', 'y')]

    # 'harden_userspace'
    if arch == 'ARM64':
        l += [KconfigCheck('harden_userspace', 'defconfig', 'ARM64_PTR_AUTH', 'y')]
        l += [KconfigCheck('harden_userspace', 'defconfig', 'ARM64_BTI', 'y')]
        l += [KconfigCheck('harden_userspace', 'defconfig', 'ARM64_GCS', 'y')]
    if arch in {'ARM', 'X86_32'}:
        l += [KconfigCheck('harden_userspace', 'defconfig', 'VMSPLIT_3G', 'y')]
    l += [KconfigCheck('harden_userspace', 'kspp', 'PROC_MEM_NO_FORCE', 'y')]
    l += [KconfigCheck('harden_userspace', 'clipos', 'COREDUMP', 'is not set')]
    l += [KconfigCheck('harden_userspace', 'a13xp0p0v', 'ARCH_MMAP_RND_BITS', 'MAX')]
          # 'MAX' value is refined using ARCH_MMAP_RND_BITS_MAX
    l += [OR(KconfigCheck('harden_userspace', 'a13xp0p0v', 'ARCH_MMAP_RND_COMPAT_BITS', 'MAX'),
             KconfigCheck('cut_attack_surface', 'kspp', 'COMPAT', 'is not set'))]
             # 'MAX' value is refined using ARCH_MMAP_RND_COMPAT_BITS_MAX,
             # however ARCH_MMAP_RND_COMPAT_BITS disappears if COMPAT is disabled.
    if arch == 'X86_64':
        l += [KconfigCheck('harden_userspace', 'kspp', 'X86_USER_SHADOW_STACK', 'y')]


def add_cmdline_checks(l: list[ChecklistObjType], arch: str) -> None:
    assert (arch), 'empty arch'

    # Calling the CmdlineCheck class constructor:
    #     CmdlineCheck(reason, decision, name, expected)
    #
    # [!] Don't add CmdlineChecks in add_kconfig_checks() to avoid wrong results
    #     when the tool doesn't check the cmdline.
    #
    # [!] Make sure that values of the options in CmdlineChecks need normalization.
    #     For more info see normalize_cmdline_options().
    #
    # A common pattern for checking the 'param_x' cmdline parameter
    # that __overrides__ the 'PARAM_X_DEFAULT' kconfig option:
    #   l += [OR(CmdlineCheck(reason, decision, 'param_x', '1'),
    #            AND(KconfigCheck(reason, decision, 'PARAM_X_DEFAULT_ON', 'y'),
    #                CmdlineCheck('-', '-', 'param_x, 'is not set')))]
    #
    # Here we don't check the kconfig options or minimal kernel version
    # required for the cmdline parameters. That would make the checks
    # very complex and not give a 100% guarantee anyway.

    # 'self_protection', 'defconfig'
    l += [CmdlineCheck('self_protection', 'defconfig', 'nokaslr', 'is not set')]  # [KNL]
    l += [CmdlineCheck('self_protection', 'defconfig', 'no_hash_pointers', 'is not set')]  # [KNL]
    l += [CmdlineCheck('self_protection', 'defconfig', 'nosmep', 'is not set')]  # [X86]
    l += [CmdlineCheck('self_protection', 'defconfig', 'nosmap', 'is not set')]  # [X86]
    l += [CmdlineCheck('self_protection', 'defconfig', 'dis_ucode_ldr', 'is not set')]  # [X86]
    l += [CmdlineCheck('self_protection', 'defconfig', 'setcpuid', 'is not set')]  # [X86]
    l += [CmdlineCheck('self_protection', 'defconfig', 'clearcpuid', 'is not set')]  # [X86]
    l += [CmdlineCheck('self_protection', 'defconfig', 'nopti', 'is not set')]  # [X86]
    l += [CmdlineCheck('self_protection', 'defconfig', 'nospec_store_bypass_disable', 'is not set')]  # [X86]
    l += [CmdlineCheck('self_protection', 'defconfig', 'nospectre_v1', 'is not set')]  # [X86]
    l += [CmdlineCheck('self_protection', 'defconfig', 'nospectre_v2', 'is not set')]  # [X86, ARM64]
    l += [CmdlineCheck('self_protection', 'defconfig', 'nospectre_bhb', 'is not set')]  # [ARM64]
    l += [CmdlineCheck('self_protection', 'defconfig', 'arm64.nobti', 'is not set')]  # [ARM64]
    l += [CmdlineCheck('self_protection', 'defconfig', 'arm64.nopauth', 'is not set')]  # [ARM64]
    l += [CmdlineCheck('self_protection', 'defconfig', 'arm64.nomte', 'is not set')]  # [ARM64]
    l += [CmdlineCheck('self_protection', 'defconfig', 'arm64.nogcs', 'is not set')]  # [ARM64]
    l += [OR(CmdlineCheck('self_protection', 'defconfig', 'iommu.passthrough', '0'),
             AND(KconfigCheck('self_protection', 'defconfig', 'IOMMU_DEFAULT_PASSTHROUGH', 'is not set'),
                 CmdlineCheck('-', '-', 'iommu.passthrough', 'is not set')))]
    if arch in {'X86_64', 'X86_32', 'ARM', 'RISCV'}:
        l += [OR(CmdlineCheck('self_protection', 'defconfig', 'rodata', 'on'),
                 CmdlineCheck('self_protection', 'defconfig', 'rodata', 'is not set'))]
    if arch in {'ARM64', 'ARM', 'RISCV'}:
        l += [OR(CmdlineCheck('self_protection', 'defconfig', 'iommu.strict', '1'),
                 AND(KconfigCheck('self_protection', 'defconfig', 'IOMMU_DEFAULT_DMA_STRICT', 'y'),
                     CmdlineCheck('-', '-', 'iommu.strict', 'is not set')))]
        l += [OR(CmdlineCheck('self_protection', 'defconfig', 'mitigations', 'auto'),
                 CmdlineCheck('self_protection', 'defconfig', 'mitigations', 'is not set'))]  # same as 'auto'
    if arch in {'X86_64', 'X86_32'}:
        l += [OR(CmdlineCheck('self_protection', 'defconfig', 'spectre_v2', 'is not off'),
                 AND(CmdlineCheck('self_protection', 'kspp', 'mitigations', 'auto,nosmt'),
                     CmdlineCheck('-', '-', 'spectre_v2', 'is not set')))]
        l += [OR(CmdlineCheck('self_protection', 'defconfig', 'spectre_v2_user', 'is not off'),
                 AND(CmdlineCheck('self_protection', 'kspp', 'mitigations', 'auto,nosmt'),
                     CmdlineCheck('-', '-', 'spectre_v2_user', 'is not set')))]
        l += [OR(CmdlineCheck('self_protection', 'defconfig', 'spectre_bhi', 'is not off'),
                 AND(CmdlineCheck('self_protection', 'kspp', 'mitigations', 'auto,nosmt'),
                     CmdlineCheck('-', '-', 'spectre_bhi', 'is not set')))]
        l += [OR(CmdlineCheck('self_protection', 'defconfig', 'spec_store_bypass_disable', 'is not off'),
                 AND(CmdlineCheck('self_protection', 'kspp', 'mitigations', 'auto,nosmt'),
                     CmdlineCheck('-', '-', 'spec_store_bypass_disable', 'is not set')))]
        l += [OR(CmdlineCheck('self_protection', 'defconfig', 'l1tf', 'is not off'),
                 AND(CmdlineCheck('self_protection', 'kspp', 'mitigations', 'auto,nosmt'),
                     CmdlineCheck('-', '-', 'l1tf', 'is not set')))]
        l += [OR(CmdlineCheck('self_protection', 'defconfig', 'mds', 'is not off'),
                 AND(CmdlineCheck('self_protection', 'kspp', 'mitigations', 'auto,nosmt'),
                     CmdlineCheck('-', '-', 'mds', 'is not set')))]
        l += [OR(CmdlineCheck('self_protection', 'defconfig', 'tsx_async_abort', 'is not off'),
                 AND(CmdlineCheck('self_protection', 'kspp', 'mitigations', 'auto,nosmt'),
                     CmdlineCheck('-', '-', 'tsx_async_abort', 'is not set')))]
        l += [OR(CmdlineCheck('self_protection', 'defconfig', 'srbds', 'is not off'),
                 AND(CmdlineCheck('self_protection', 'kspp', 'mitigations', 'auto,nosmt'),
                     CmdlineCheck('-', '-', 'srbds', 'is not set')))]
        l += [OR(CmdlineCheck('self_protection', 'defconfig', 'mmio_stale_data', 'is not off'),
                 AND(CmdlineCheck('self_protection', 'kspp', 'mitigations', 'auto,nosmt'),
                     CmdlineCheck('-', '-', 'mmio_stale_data', 'is not set')))]
        l += [OR(CmdlineCheck('self_protection', 'defconfig', 'retbleed', 'is not off'),
                 AND(CmdlineCheck('self_protection', 'kspp', 'mitigations', 'auto,nosmt'),
                     CmdlineCheck('-', '-', 'retbleed', 'is not set')))]
        l += [OR(CmdlineCheck('self_protection', 'defconfig', 'spec_rstack_overflow', 'is not off'),
                 AND(CmdlineCheck('self_protection', 'kspp', 'mitigations', 'auto,nosmt'),
                     CmdlineCheck('-', '-', 'spec_rstack_overflow', 'is not set')))]
        l += [OR(CmdlineCheck('self_protection', 'defconfig', 'gather_data_sampling', 'is not off'),
                 AND(CmdlineCheck('self_protection', 'kspp', 'mitigations', 'auto,nosmt'),
                     CmdlineCheck('-', '-', 'gather_data_sampling', 'is not set')))]
        l += [OR(CmdlineCheck('self_protection', 'defconfig', 'reg_file_data_sampling', 'is not off'),
                 AND(CmdlineCheck('self_protection', 'kspp', 'mitigations', 'auto,nosmt'),
                     CmdlineCheck('-', '-', 'reg_file_data_sampling', 'is not set')))]
        l += [OR(CmdlineCheck('self_protection', 'defconfig', 'tsa', 'is not off'),
                 AND(CmdlineCheck('self_protection', 'kspp', 'mitigations', 'auto,nosmt'),
                     CmdlineCheck('-', '-', 'tsa', 'is not set')))]
        l += [OR(CmdlineCheck('self_protection', 'defconfig', 'indirect_target_selection', 'is not off'),
                 AND(CmdlineCheck('self_protection', 'kspp', 'mitigations', 'auto,nosmt'),
                     CmdlineCheck('-', '-', 'indirect_target_selection', 'is not set')))]
        l += [OR(CmdlineCheck('self_protection', 'defconfig', 'vmscape', 'is not off'),
                 AND(CmdlineCheck('self_protection', 'kspp', 'mitigations', 'auto,nosmt'),
                     CmdlineCheck('-', '-', 'vmscape', 'is not set')))]
    if arch == 'X86_64':
        l += [OR(CmdlineCheck('self_protection', 'defconfig', 'amd_iommu', 'is not off'),
                 CmdlineCheck('self_protection', 'defconfig', 'amd_iommu', 'is not set'))]
    if arch == 'ARM64':
        l += [OR(CmdlineCheck('self_protection', 'defconfig', 'kpti', 'is not off'),
                 AND(CmdlineCheck('self_protection', 'defconfig', 'mitigations', 'auto'),
                     CmdlineCheck('-', '-', 'kpti', 'is not set')),
                 AND(CmdlineCheck('self_protection', 'defconfig', 'mitigations', 'is not set'),
                     CmdlineCheck('-', '-', 'kpti', 'is not set')))]
        l += [OR(CmdlineCheck('self_protection', 'defconfig', 'ssbd', 'kernel'),
                 CmdlineCheck('self_protection', 'a13xp0p0v', 'ssbd', 'force-on'),
                 AND(CmdlineCheck('self_protection', 'defconfig', 'mitigations', 'auto'),
                     CmdlineCheck('-', '-', 'ssbd', 'is not set')),
                 AND(CmdlineCheck('self_protection', 'defconfig', 'mitigations', 'is not set'),
                     CmdlineCheck('-', '-', 'ssbd', 'is not set')))]
        l += [OR(CmdlineCheck('self_protection', 'defconfig', 'rodata', 'full'),
                 AND(CmdlineCheck('self_protection', 'defconfig', 'rodata', 'on'),
                     VersionCheck((6, 18, 0))),
                 AND(KconfigCheck('self_protection', 'defconfig', 'RODATA_FULL_DEFAULT_ENABLED', 'y'),
                     CmdlineCheck('-', '-', 'rodata', 'is not set')),
                 AND(CmdlineCheck('-', '-', 'rodata', 'is not set'),
                     VersionCheck((6, 18, 0))))]

    # 'self_protection', 'kspp'
    l += [CmdlineCheck('self_protection', 'kspp', 'slab_merge', 'is not set')]  # consequence of 'slab_nomerge' by kspp
    l += [CmdlineCheck('self_protection', 'kspp', 'slub_merge', 'is not set')]  # consequence of 'slab_nomerge' by kspp
    l += [CmdlineCheck('self_protection', 'kspp', 'page_alloc.shuffle', '1')]
    l += [CmdlineCheck('self_protection', 'kspp', 'hash_pointers', 'always')]
    l += [OR(CmdlineCheck('self_protection', 'kspp', 'slab_nomerge', 'is present'),
             AND(KconfigCheck('self_protection', 'kspp', 'SLAB_MERGE_DEFAULT', 'is not set'),
                 CmdlineCheck('self_protection', 'kspp', 'slab_merge', 'is not set'),
                 CmdlineCheck('self_protection', 'kspp', 'slub_merge', 'is not set')))]
    l += [OR(CmdlineCheck('self_protection', 'kspp', 'init_on_alloc', '1'),
             AND(KconfigCheck('self_protection', 'kspp', 'INIT_ON_ALLOC_DEFAULT_ON', 'y'),
                 CmdlineCheck('-', '-', 'init_on_alloc', 'is not set')))]
    l += [OR(CmdlineCheck('self_protection', 'kspp', 'init_on_free', '1'),
             AND(KconfigCheck('self_protection', 'kspp', 'INIT_ON_FREE_DEFAULT_ON', 'y'),
                 CmdlineCheck('-', '-', 'init_on_free', 'is not set')),
             AND(CmdlineCheck('self_protection', 'kspp', 'page_poison', '1'),
                 KconfigCheck('self_protection', 'kspp', 'PAGE_POISONING_ZERO', 'y'),
                 CmdlineCheck('self_protection', 'kspp', 'slub_debug', 'P')))]
    l += [OR(CmdlineCheck('self_protection', 'kspp', 'hardened_usercopy', '1'),
             AND(KconfigCheck('self_protection', 'kspp', 'HARDENED_USERCOPY_DEFAULT_ON', 'y'),
                 CmdlineCheck('-', '-', 'hardened_usercopy', 'is not set')))]
    l += [AND(CmdlineCheck('self_protection', 'kspp', 'slab_common.usercopy_fallback', 'is not set'),
              KconfigCheck('self_protection', 'kspp', 'HARDENED_USERCOPY_FALLBACK', 'is not set'))]
              # consequence of the HARDENED_USERCOPY_FALLBACK check by kspp;
              # but we don't require slab_common.usercopy_fallback=0,
              # since HARDENED_USERCOPY_FALLBACK was removed in Linux v5.16.
    l += [OR(CmdlineCheck('self_protection', 'kspp', 'kfence.sample_interval', '100'),
             AND(KconfigCheck('self_protection', 'kspp', 'KFENCE_SAMPLE_INTERVAL', '100'),
                 CmdlineCheck('-', '-', 'kfence.sample_interval', 'is not set')))]
    l += [OR(CmdlineCheck('self_protection', 'kspp', 'lockdown', 'confidentiality'),
             AND(KconfigCheck('self_protection', 'kspp', 'LOCK_DOWN_KERNEL_FORCE_CONFIDENTIALITY', 'y'),
                 CmdlineCheck('-', '-', 'lockdown', 'is not set')))]
             # consequence of the LOCK_DOWN_KERNEL_FORCE_CONFIDENTIALITY check by kspp
    l += [OR(CmdlineCheck('self_protection', 'kspp', 'module.sig_enforce', '1'),
             KconfigCheck('self_protection', 'kspp', 'MODULE_SIG_FORCE', 'y'),
             KconfigCheck('cut_attack_surface', 'kspp', 'MODULES', 'is not set'))]
             # consequence of the MODULE_SIG_FORCE check by kspp
    l += [OR(CmdlineCheck('self_protection', 'kspp', 'efi', '*disable_early_pci_dma*'),
             KconfigCheck('-', '-', 'EFI', 'is not set'),
             AND(KconfigCheck('self_protection', 'kspp', 'EFI_DISABLE_PCI_DMA', 'y'),
                 CmdlineCheck('-', '-', 'efi', 'is not set')))]
             # consequence of the EFI_DISABLE_PCI_DMA check by kspp;
             # it's better to check in the last line that the efi parameter
             # doesn't contain no_disable_early_pci_dma (this feature should be added in engine.py)
    if arch in {'X86_64', 'ARM64', 'X86_32', 'RISCV'}:
        l += [OR(CmdlineCheck('self_protection', 'kspp', 'randomize_kstack_offset', '1'),
                 AND(KconfigCheck('self_protection', 'kspp', 'RANDOMIZE_KSTACK_OFFSET_DEFAULT', 'y'),
                     CmdlineCheck('-', '-', 'randomize_kstack_offset', 'is not set')))]
    if arch in {'X86_64', 'X86_32'}:
        l += [CmdlineCheck('self_protection', 'kspp', 'mitigations', 'auto,nosmt')]
        l += [OR(CmdlineCheck('self_protection', 'kspp', 'intel_iommu', 'on'),
                 AND(KconfigCheck('self_protection', 'kspp', 'INTEL_IOMMU_DEFAULT_ON', 'y'),
                     CmdlineCheck('-', '-', 'intel_iommu', 'is not set')))]
                 # consequence of the INTEL_IOMMU_DEFAULT_ON check by kspp
        l += [OR(CmdlineCheck('self_protection', 'kspp', 'iommu.strict', '1'),
                 AND(KconfigCheck('self_protection', 'kspp', 'IOMMU_DEFAULT_DMA_STRICT', 'y'),
                     CmdlineCheck('-', '-', 'iommu.strict', 'is not set')))]
        l += [AND(CmdlineCheck('self_protection', 'kspp', 'pti', 'on'),
                  CmdlineCheck('self_protection', 'defconfig', 'nopti', 'is not set'))]
    if arch == 'X86_64':
        l += [OR(CmdlineCheck('self_protection', 'kspp', 'cfi', 'kcfi'),
                 AND(KconfigCheck('self_protection', 'kspp', 'CFI_AUTO_DEFAULT', 'is not set'),
                     KconfigCheck('self_protection', 'kspp', 'CFI_AUTO_DEFAULT', 'is present'),
                     CmdlineCheck('-', '-', 'cfi', 'is not set')))]

    # 'self_protection', 'clipos'
    if arch in {'X86_64', 'X86_32'}:
        l += [CmdlineCheck('self_protection', 'clipos', 'iommu', 'force')]

    # 'cut_attack_surface', 'defconfig'
    if arch in {'X86_64', 'X86_32'}:
        tsx_not_set = CmdlineCheck('cut_attack_surface', 'defconfig', 'tsx', 'is not set')
        l += [OR(CmdlineCheck('cut_attack_surface', 'defconfig', 'tsx', 'off'),
                 AND(KconfigCheck('cut_attack_surface', 'defconfig', 'X86_INTEL_TSX_MODE_OFF', 'y'),
                     tsx_not_set),
                 AND(KconfigCheck('-', '-', 'CPU_SUP_INTEL', 'is not set'),
                     tsx_not_set))]

    # 'cut_attack_surface', 'kspp'
    l += [CmdlineCheck('cut_attack_surface', 'kspp', 'nosmt', 'is present')]  # slow (high performance penalty)
    if arch == 'X86_64':
        l += [OR(CmdlineCheck('cut_attack_surface', 'kspp', 'vsyscall', 'none'),
                 KconfigCheck('cut_attack_surface', 'kspp', 'X86_VSYSCALL_EMULATION', 'is not set'),
                 AND(KconfigCheck('cut_attack_surface', 'kspp', 'LEGACY_VSYSCALL_NONE', 'y'),
                     CmdlineCheck('-', '-', 'vsyscall', 'is not set')))]
        l += [OR(CmdlineCheck('cut_attack_surface', 'kspp', 'vdso32', '0'),
                 AND(KconfigCheck('cut_attack_surface', 'kspp', 'COMPAT_VDSO', 'is not set'),
                     CmdlineCheck('-', '-', 'vdso32', 'is not set')))]
                 # disable 32-bit VDSO entirely or at least ensure that COMPAT_VDSO is disabled
                 # (on old kernels, this kconfig option turned on dangerous vdso32=2)
        l += [OR(CmdlineCheck('cut_attack_surface', 'kspp', 'ia32_emulation', '0'),
                 KconfigCheck('cut_attack_surface', 'kspp', 'IA32_EMULATION', 'is not set'),
                 AND(KconfigCheck('cut_attack_surface', 'a13xp0p0v', 'IA32_EMULATION_DEFAULT_DISABLED', 'y'),
                     CmdlineCheck('-', '-', 'ia32_emulation', 'is not set')))]
                 # consequence of the IA32_EMULATION check by kspp
    if arch == 'X86_32':
        l += [OR(CmdlineCheck('cut_attack_surface', 'kspp', 'vdso32', '0'),
                 CmdlineCheck('cut_attack_surface', 'a13xp0p0v', 'vdso', '0'),
                 CmdlineCheck('cut_attack_surface', 'a13xp0p0v', 'vdso32', '1'),
                 CmdlineCheck('cut_attack_surface', 'a13xp0p0v', 'vdso', '1'),
                 AND(KconfigCheck('cut_attack_surface', 'kspp', 'COMPAT_VDSO', 'is not set'),
                     CmdlineCheck('-', '-', 'vdso32', 'is not set'),
                     CmdlineCheck('-', '-', 'vdso', 'is not set')))]
                 # the vdso and vdso32 parameters must not be 2

    # 'cut_attack_surface', 'grsec'
    l += [OR(CmdlineCheck('cut_attack_surface', 'grsec', 'debugfs', 'off'),
             KconfigCheck('cut_attack_surface', 'grsec', 'DEBUG_FS', 'is not set'))]
             # the cmdline check is compatible with the 'DEBUG_FS' kconfig check by grsecurity;
             # it may disturb the `powertop` utility

    # 'cut_attack_surface', 'grapheneos'
    l += [CmdlineCheck('cut_attack_surface', 'grapheneos', 'sysrq_always_enabled', 'is not set')]

    # 'cut_attack_surface', 'a13xp0p0v'
    l += [OR(CmdlineCheck('cut_attack_surface', 'a13xp0p0v', 'nomodule', 'is present'),
             KconfigCheck('cut_attack_surface', 'kspp', 'MODULES', 'is not set'))]
             # see the README.md: How can I disable loading of vulnerable Linux kernel modules?
    l += [OR(CmdlineCheck('cut_attack_surface', 'a13xp0p0v', 'bdev_allow_write_mounted', '0'),
             AND(KconfigCheck('cut_attack_surface', 'a13xp0p0v', 'BLK_DEV_WRITE_MOUNTED', 'is not set'),
                 CmdlineCheck('-', '-', 'bdev_allow_write_mounted', 'is not set')))]
                 # 1) bdev_allow_write_mounted=0 may break snap and its applications on Ubuntu,
                 # since snap uses the squashfs filesystem and creates loop devices.
                 # 2) On Gentoo with openrc-init, bdev_allow_write_mounted=0 makes fsck fail
                 # on boot during the root filesystem check.

    # 'harden_userspace'
    l += [CmdlineCheck('harden_userspace', 'defconfig', 'norandmaps', 'is not set')]
    l += [OR(CmdlineCheck('harden_userspace', 'kspp', 'proc_mem.force_override', 'never'),
             AND(KconfigCheck('harden_userspace', 'kspp', 'PROC_MEM_NO_FORCE', 'y'),
                 CmdlineCheck('-', '-', 'proc_mem.force_override', 'is not set')))]


no_kstrtobool_options = [
    'debugfs',  # see debugfs_kernel() in fs/debugfs/inode.c
    'mitigations',  # see mitigations_parse_cmdline() in kernel/cpu.c
    'pti',  # see pti_check_boottime_disable() in arch/x86/mm/pti.c
    'spectre_v2',  # see spectre_v2_parse_cmdline() in arch/x86/kernel/cpu/bugs.c
    'spectre_v2_user',  # see spectre_v2_parse_user_cmdline() in arch/x86/kernel/cpu/bugs.c
    'spectre_bhi',  # see spectre_bhi_parse_cmdline() in arch/x86/kernel/cpu/bugs.c
    'spec_store_bypass_disable',  # see ssb_parse_cmdline() in arch/x86/kernel/cpu/bugs.c
    'l1tf',  # see l1tf_cmdline() in arch/x86/kernel/cpu/bugs.c
    'mds',  # see mds_cmdline() in arch/x86/kernel/cpu/bugs.c
    'tsx_async_abort',  # see tsx_async_abort_parse_cmdline() in arch/x86/kernel/cpu/bugs.c
    'srbds',  # see srbds_parse_cmdline() in arch/x86/kernel/cpu/bugs.c
    'mmio_stale_data',  # see mmio_stale_data_parse_cmdline() in arch/x86/kernel/cpu/bugs.c
    'retbleed',  # see retbleed_parse_cmdline() in arch/x86/kernel/cpu/bugs.c
    'rodata',  # see set_debug_rodata() in init/main.c
    'ssbd',  # see parse_spectre_v4_param() in arch/arm64/kernel/proton-pack.c
    'spec_rstack_overflow',  # see srso_parse_cmdline() in arch/x86/kernel/cpu/bugs.c
    'gather_data_sampling',  # see gds_parse_cmdline() in arch/x86/kernel/cpu/bugs.c
    'reg_file_data_sampling',  # see rfds_parse_cmdline() in arch/x86/kernel/cpu/bugs.c
    'tsa',  # see tsa_parse_cmdline() in arch/x86/kernel/cpu/bugs.c
    'indirect_target_selection',  # see its_parse_cmdline() in arch/x86/kernel/cpu/bugs.c
    'vmscape',  # see vmscape_parse_cmdline() in arch/x86/kernel/cpu/bugs.c
    'slub_debug',  # see setup_slub_debug() in mm/slub.c
    'iommu',  # see iommu_setup() in arch/x86/kernel/pci-dma.c
    'vsyscall',  # see vsyscall_setup() in arch/x86/entry/vsyscall/vsyscall_64.c
    'vdso32',  # see vdso32_setup() in arch/x86/entry/vdso/vdso32-setup.c
    'vdso',  # see vdso32_setup() in arch/x86/entry/vdso/vdso32-setup.c
    'cfi',  # see cfi_parse_cmdline() in arch/x86/kernel/alternative.c
    'tsx',  # see tsx_init() in arch/x86/kernel/cpu/tsx.c
    'lockdown',  # see lockdown_param() in security/lockdown/lockdown.c
    'intel_iommu',  # see intel_iommu_setup() in drivers/iommu/intel/iommu.c
    'amd_iommu',  # see parse_amd_iommu_options() in drivers/iommu/amd/init.c
    'efi',  # see efi_parse_options() in drivers/firmware/efi/libstub/efi-stub-helper.c
    'hash_pointers',  # see hash_pointers_mode_parse() in lib/vsprintf.c
    'ipv6.disable',  # see the disable_ipv6_mod parameter in net/ipv6/af_inet6.c
    'proc_mem.force_override',  # see early_proc_mem_force_override() in fs/proc/base.c
]


def normalize_cmdline_options(option: str, value: str) -> str:
    # Don't normalize an option value if the Linux kernel doesn't use kstrtobool() for it:
    if option in no_kstrtobool_options:
        return value

    # Implement a limited part of the kstrtobool() logic:
    if value.lower() in {'1', 'on', 'y', 'yes', 't', 'true'}:
        return '1'
    if value.lower() in {'0', 'off', 'n', 'no', 'f', 'false'}:
        return '0'

    # Preserve unique values:
    return value


def add_sysctl_checks(l: list[ChecklistObjType], arch: StrOrNone) -> None:
    # Calling the SysctlCheck class constructor:
    #   SysctlCheck(reason, decision, name, expected)

    # Use an omnipresent kconfig symbol to see if we have a kconfig file for checking:
    have_kconfig = KconfigCheck('-', '-', 'LOCALVERSION', 'is present')

    # 'self_protection', 'kspp'
    l += [OR(SysctlCheck('self_protection', 'kspp', 'net.core.bpf_jit_harden', '2'),
             AND(KconfigCheck('-', '-', 'BPF_JIT', 'is not set'),
                 have_kconfig))]
    # Compatible with the 'DEFAULT_MMAP_MIN_ADDR' kconfig check by KSPP:
    if arch in {'X86_64', 'X86_32', 'RISCV'}:
        l += [SysctlCheck('self_protection', 'kspp', 'vm.mmap_min_addr', '65536')]
    if arch == 'ARM64':
        l += [AND(SysctlCheck('self_protection', 'kspp', 'vm.mmap_min_addr', '65536'),
                  KconfigCheck('cut_attack_surface', 'kspp', 'COMPAT', 'is not set'))]
                  # see the comment about DEFAULT_MMAP_MIN_ADDR for ARM64 above
    if arch == 'ARM':
        l += [SysctlCheck('self_protection', 'kspp', 'vm.mmap_min_addr', '32768')]

    # 'self_protection', 'a13xp0p0v'
    # Choosing a right value for 'kernel.oops_limit' and 'kernel.warn_limit' is not easy.
    # A small value (e.g. 1, which is recommended by KSPP) allows easy DoS.
    # A large value (e.g. 10000, which is default 'kernel.oops_limit') may miss the exploit attempt.
    # Let's choose 100 as a reasonable compromise.
    l += [SysctlCheck('self_protection', 'a13xp0p0v', 'kernel.oops_limit', '100')]
    l += [SysctlCheck('self_protection', 'a13xp0p0v', 'kernel.warn_limit', '100')]

    # 'security_policy'
    l += [OR(SysctlCheck('security_policy', 'ubuntu', 'kernel.apparmor_restrict_unprivileged_unconfined', '1'),
             SysctlCheck('-', '-', 'kernel.apparmor_restrict_unprivileged_unconfined', 'is not set'))]
             # Forbid unprivileged and unconfined processes to change their AppArmor profiles
             # https://discourse.ubuntu.com/t/understanding-apparmor-user-namespace-restriction/58007

    # 'cut_attack_surface', 'kspp'
    l += [SysctlCheck('cut_attack_surface', 'kspp', 'kernel.dmesg_restrict', '1')]
    l += [SysctlCheck('cut_attack_surface', 'kspp', 'kernel.perf_event_paranoid', '3')]
          # Without the custom patch that adds CONFIG_SECURITY_PERF_EVENTS_RESTRICT,
          # the value '3' has a similar effect to the value '2'. For more information, see:
          #  - https://lkml.org/lkml/2016/1/11/587
          #  - https://lwn.net/Articles/696216/
    l += [SysctlCheck('cut_attack_surface', 'kspp', 'dev.tty.ldisc_autoload', '0')]
    l += [SysctlCheck('cut_attack_surface', 'kspp', 'kernel.kptr_restrict', '2')]
    l += [SysctlCheck('cut_attack_surface', 'kspp', 'dev.tty.legacy_tiocsti', '0')]
    l += [OR(SysctlCheck('cut_attack_surface', 'kspp', 'user.max_user_namespaces', '0'),
             SysctlCheck('cut_attack_surface', 'debian', 'kernel.unprivileged_userns_clone', '0'))]
             # 1) Debian-specific sysctl kernel.unprivileged_userns_clone is deprecated
             # 2) user.max_user_namespaces=0 may break the upower daemon in Ubuntu
             # 3) AppArmor restriction of user namespaces in Ubuntu is vulnerable without setting
             #    kernel.apparmor_restrict_unprivileged_unconfined=1
    l += [OR(SysctlCheck('cut_attack_surface', 'kspp', 'kernel.kexec_load_disabled', '1'),
             AND(KconfigCheck('-', '-', 'KEXEC_CORE', 'is not set'),
                 have_kconfig))]
    l += [OR(SysctlCheck('cut_attack_surface', 'kspp', 'kernel.unprivileged_bpf_disabled', '1'),
             AND(KconfigCheck('cut_attack_surface', 'lockdown', 'BPF_SYSCALL', 'is not set'),
                 have_kconfig))]
    l += [OR(SysctlCheck('cut_attack_surface', 'kspp', 'vm.unprivileged_userfaultfd', '0'),
             AND(KconfigCheck('cut_attack_surface', 'grsec', 'USERFAULTFD', 'is not set'),
                 have_kconfig))]
             # at first, it disabled unprivileged userfaultfd,
             # and since v5.11 it enables unprivileged userfaultfd for user-mode only
    l += [OR(SysctlCheck('cut_attack_surface', 'kspp', 'kernel.modules_disabled', '1'),
             CmdlineCheck('cut_attack_surface', 'a13xp0p0v', 'nomodule', 'is present'),
             AND(KconfigCheck('cut_attack_surface', 'kspp', 'MODULES', 'is not set'),
                 have_kconfig))]
             # block loading kernel modules:
             #  - set kernel.modules_disabled=1 (e.g. with systemd) after
             #    the kernel startup, when the needed modules have been loaded;
             #  - or set the nomodule cmdline parameter (it uses the same
             #    modules_disabled flag).
             # See the README.md: How can I disable loading of vulnerable Linux kernel modules?
    l += [OR(SysctlCheck('cut_attack_surface', 'a13xp0p0v', 'kernel.modprobe', ''),
             SysctlCheck('cut_attack_surface', 'kspp', 'kernel.modules_disabled', '1'),
             CmdlineCheck('cut_attack_surface', 'a13xp0p0v', 'nomodule', 'is present'),
             AND(KconfigCheck('cut_attack_surface', 'kspp', 'MODULES', 'is not set'),
                 have_kconfig))]
             # disable kernel-requested module autoloading: an empty kernel.modprobe
             # makes __request_module() bail out before the usermode helper, but it
             # doesn't prevent explicit modprobe/insmod; the stronger
             # modules_disabled=1 / nomodule / MODULES=n disable all module loading.
             # See the README.md: How can I disable loading of vulnerable Linux kernel modules?

    # 'cut_attack_surface', 'grsec'
    l += [OR(SysctlCheck('cut_attack_surface', 'grsec', 'kernel.io_uring_disabled', '2'),
             AND(KconfigCheck('cut_attack_surface', 'grsec', 'IO_URING', 'is not set'),
                 have_kconfig))]  # compatible with the 'IO_URING' kconfig check by grsecurity

    # 'cut_attack_surface', 'a13xp0p0v'
    l += [OR(SysctlCheck('cut_attack_surface', 'a13xp0p0v', 'kernel.sysrq', '0'),
             AND(KconfigCheck('cut_attack_surface', 'clipos', 'MAGIC_SYSRQ', 'is not set'),
                 have_kconfig))]

    # 'network_security', 'cis'
    ipv6_not_set = CmdlineCheck('-', '-', 'ipv6.disable', '1')
    l += [SysctlCheck('network_security', 'cis', 'net.ipv4.icmp_ignore_bogus_error_responses', '1')]
    l += [SysctlCheck('network_security', 'cis', 'net.ipv4.icmp_echo_ignore_broadcasts', '1')]
    l += [SysctlCheck('network_security', 'cis', 'net.ipv4.conf.all.accept_redirects', '0')]
    l += [SysctlCheck('network_security', 'cis', 'net.ipv4.conf.default.accept_redirects', '0')]
    l += [OR(SysctlCheck('network_security', 'cis', 'net.ipv6.conf.all.accept_redirects', '0'),
             ipv6_not_set)]
    l += [OR(SysctlCheck('network_security', 'cis', 'net.ipv6.conf.default.accept_redirects', '0'),
             ipv6_not_set)]
    l += [SysctlCheck('network_security', 'cis', 'net.ipv4.conf.all.accept_source_route', '0')]
    l += [SysctlCheck('network_security', 'cis', 'net.ipv4.conf.default.accept_source_route', '0')]
    l += [OR(SysctlCheck('network_security', 'cis', 'net.ipv6.conf.all.accept_source_route', '0'),
             ipv6_not_set)]
    l += [OR(SysctlCheck('network_security', 'cis', 'net.ipv6.conf.default.accept_source_route', '0'),
             ipv6_not_set)]
    l += [SysctlCheck('network_security', 'cis', 'net.ipv4.tcp_syncookies', '1')]
    l += [OR(SysctlCheck('network_security', 'cis', 'net.ipv6.conf.all.accept_ra', '0'),
             ipv6_not_set)]
    l += [OR(SysctlCheck('network_security', 'cis', 'net.ipv6.conf.default.accept_ra', '0'),
             ipv6_not_set)]
    # The following recommendations from the CIS Benchmark may impact normal network functionality:
    #  CAUTION: without IP forwarding your system can not act as a router
    #   l += [SysctlCheck('network_security', 'cis', 'net.ipv4.ip_forward', '0')]
    #   l += [OR(SysctlCheck('network_security', 'cis', 'net.ipv6.conf.all.forwarding', '0'),
    #            ipv6_not_set)]
    #   l += [SysctlCheck('network_security', 'cis', 'net.ipv4.conf.all.send_redirects', '0')]
    #   l += [SysctlCheck('network_security', 'cis', 'net.ipv4.conf.default.send_redirects', '0')]
    #  CAUTION: it's strange to ignore ICMP redirects from your default gateway
    #   l += [SysctlCheck('network_security', 'cis', 'net.ipv4.conf.all.secure_redirects', '0')]
    #   l += [SysctlCheck('network_security', 'cis', 'net.ipv4.conf.default.secure_redirects', '0')]
    #  CAUTION: rp_filter for network packets breaks asymmetrical routing (BGP, OSPF, etc) and some VPNs
    #   l += [SysctlCheck('network_security', 'cis', 'net.ipv4.conf.all.rp_filter', '1')]
    #   l += [SysctlCheck('network_security', 'cis', 'net.ipv4.conf.default.rp_filter', '1')]
    #  CAUTION: messages about packets with un-routable source addresses may clog up the kernel log
    #   l += [SysctlCheck('network_security', 'cis', 'net.ipv4.conf.all.log_martians', '1')]
    #   l += [SysctlCheck('network_security', 'cis', 'net.ipv4.conf.default.log_martians', '1')]

    # 'harden_userspace', 'kspp'
    l += [SysctlCheck('harden_userspace', 'kspp', 'fs.protected_symlinks', '1')]
    l += [SysctlCheck('harden_userspace', 'kspp', 'fs.protected_hardlinks', '1')]
    l += [SysctlCheck('harden_userspace', 'kspp', 'fs.protected_fifos', '2')]
    l += [SysctlCheck('harden_userspace', 'kspp', 'fs.protected_regular', '2')]
    l += [SysctlCheck('harden_userspace', 'kspp', 'fs.suid_dumpable', '0')]
    l += [SysctlCheck('harden_userspace', 'kspp', 'kernel.randomize_va_space', '2')]
    l += [SysctlCheck('harden_userspace', 'kspp', 'kernel.yama.ptrace_scope', '3')]

    # 'harden_userspace', 'a13xp0p0v'
    l += [SysctlCheck('harden_userspace', 'a13xp0p0v', 'vm.mmap_rnd_bits', 'MAX')]
          # 'MAX' value is refined using ARCH_MMAP_RND_BITS_MAX
    l += [OR(SysctlCheck('harden_userspace', 'a13xp0p0v', 'vm.mmap_rnd_compat_bits', 'MAX'),
             KconfigCheck('cut_attack_surface', 'kspp', 'COMPAT', 'is not set'))]
             # 'MAX' value is refined using ARCH_MMAP_RND_COMPAT_BITS_MAX,
             # however vm.mmap_rnd_compat_bits disappears if COMPAT is disabled.
