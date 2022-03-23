{ lib, version}:
with lib;
with lib.kernel;
with (lib.kernel.whenHelpers version);

assert (versionAtLeast version "4.9");
{
  # Report BUG() conditions and kill the offending process.
  BUG = yes;

  # Safer page access permissions (wrt. code injection).  Default on >=4.11.
  DEBUG_RODATA          = whenOlder "4.11" yes;
  DEBUG_SET_MODULE_RONX = whenOlder "4.11" yes;

  # Mark LSM hooks read-only after init.  SECURITY_WRITABLE_HOOKS n
  # conflicts with SECURITY_SELINUX_DISABLE y; disabling the latter
  # implicitly marks LSM hooks read-only after init.
  #
  # SELinux can only be disabled at boot via selinux=0
  #
  # We set SECURITY_WRITABLE_HOOKS n primarily for documentation purposes; the
  # config builder fails to detect that it has indeed been unset.
  SECURITY_SELINUX_DISABLE = whenAtLeast "4.12" no;
  SECURITY_WRITABLE_HOOKS  = whenAtLeast "4.12" (option no);

  STRICT_KERNEL_RWX = whenAtLeast "4.11" yes;

  # Perform additional validation of commonly targeted structures.
  DEBUG_CREDENTIALS     = yes;
  DEBUG_NOTIFIERS       = yes;
  DEBUG_PI_LIST         = whenOlder "5.2" yes; # doesn't BUG()
  DEBUG_PLIST           = whenAtLeast "5.2" yes;
  DEBUG_SG              = yes;
  SCHED_STACK_END_CHECK = yes;

  REFCOUNT_FULL = whenBetween "4.13" "5.5" yes;

  # Randomize page allocator when page_alloc.shuffle=1
  SHUFFLE_PAGE_ALLOCATOR = whenAtLeast "5.2" yes;

  # Allow enabling slub/slab free poisoning with slub_debug=P
  SLUB_DEBUG = yes;

  # Wipe higher-level memory allocations on free() with page_poison=1
  PAGE_POISONING           = yes;
  PAGE_POISONING_NO_SANITY = whenOlder "5.11" yes;
  PAGE_POISONING_ZERO      = whenOlder "5.11" yes;

  # Enable the SafeSetId LSM
  SECURITY_SAFESETID = whenAtLeast "5.1" yes;

  # Reboot devices immediately if kernel experiences an Oops.
  PANIC_TIMEOUT = freeform "-1";

  GCC_PLUGINS = yes; # Enable gcc plugin options
  # Gather additional entropy at boot time for systems that may not have appropriate entropy sources.
  GCC_PLUGIN_LATENT_ENTROPY = yes;

  GCC_PLUGIN_STRUCTLEAK = whenAtLeast "4.11" yes; # A port of the PaX structleak plugin
  GCC_PLUGIN_STRUCTLEAK_BYREF_ALL = whenAtLeast "4.14" yes; # Also cover structs passed by address
  GCC_PLUGIN_STACKLEAK = whenAtLeast "4.20" yes; # A port of the PaX stackleak plugin
  GCC_PLUGIN_RANDSTRUCT = whenAtLeast "4.13" yes; # A port of the PaX randstruct plugin
  GCC_PLUGIN_RANDSTRUCT_PERFORMANCE = whenAtLeast "4.13" yes;

  # Disable various dangerous settings
  ACPI_CUSTOM_METHOD = no; # Allows writing directly to physical memory
  PROC_KCORE         = no; # Exposes kernel text image layout
  INET_DIAG          = no; # Has been used for heap based attacks in the past

  # INET_DIAG=n causes the following options to not exist anymore, but since they are defined in common-config.nix,
  # make them optional
  INET_DIAG_DESTROY = option no;
  INET_RAW_DIAG     = option no;
  INET_TCP_DIAG     = option no;
  INET_UDP_DIAG     = option no;
  INET_MPTCP_DIAG   = option no;

  # Use -fstack-protector-strong (gcc 4.9+) for best stack canary coverage.
  CC_STACKPROTECTOR_REGULAR = lib.mkForce (whenOlder "4.18" no);
  CC_STACKPROTECTOR_STRONG  = whenOlder "4.18" yes;

  # Detect out-of-bound reads/writes and use-after-free
  KFENCE = whenAtLeast "5.12" yes;

  # CONFIG_DEVMEM=n causes these to not exist anymore.
  STRICT_DEVMEM    = option no;
  IO_STRICT_DEVMEM = option no;


  # additional values:
  # DBG
  # TODO KMEMLEAK = yes;

  # layout rand
  # TODO RANDSTRUCT = yes;
  # TODO LATENT_ENTROPY = yes;
  RANDOMIZE_KSTACK_OFFSET_DEFAULT = yes;
  RANDOMIZE_BASE = yes;
  RANDOMIZE_MEMORY = yes;


  # __ro_after_init -> TODO

  
  # mem corruption detection (stack depth overflows and such):
  
  # >causes kernel stack overflows to be caught immediately rather than causing difficult-to-diagnose corruption.
  VMAP_STACK = yes;
  THREAD_INFO_IN_TASK = yes;


  # kernel space mirroring attacks:
  # TODO RDONLY swapper_pg_dir = yes

  # info exposure
  X86_UMIP = yes; #Intel User Mode Instruction Prevention (TODO will this fail if cpu doesn't support it?)
  # TODO kptr_restrict = yes
  # TODO SECURITY_DMESG_RESTRICT = yes   [well its a pain to debug without it]
  # TODO INIT_STACK_ALL_ZERO = yes;
  # TODO STRUCTLEAK_BYREF_ALL = yes;

  # use after free:
  # TODO init_on_free == yes
  # init_on_alloc = yes
  # double free:
  SLAB_FREELIST_HARDENED = yes;

  # out ouf bound access shit
  HARDENED_USERCOPY = yes;
  # TODO ifarm KASAN_HW_TAGS with ARM64_MTE
  FORTIFY_SOURCE = yes; #Harden common str/mem functions against buffer overflows
  # TODO UBSAN_BOUNDS = yes; #detection of directly indexed out of bounds array accesse

  # bpf (if present):
  #bpf_jit_harden = yes;

  # malicious module loading 
  #MODULE_SIG = yes;
  SECURITY_LOADPIN = yes; #only load modules from RDONLY filesystems such as a cdrom

  #Automatically load TTY Line Disciplines
  #CONFIG_LDISC_AUTOLOAD = no;

  # WX mem shit
  STRICT_MODULE_RWX = yes;
  DEBUG_WX = yes;
  # ifarm RODATA_FULL_DEFAULT_ENABLED


  # controll flow manipulation shit:
  # ifarm  CFI_CLANG
  # ifarm: SHADOW_CALL_STACK
  # ifarm: ARM64_PTR_AUTH_KERNEL
  # ifarm: RM64_BTI_KERNEL
  # TODO X86_SHADOW_STACK = yes;
  # TODO ZERO_CALL_USED_REGS = yes;
  STACKPROTECTOR = yes;
  # ifarm: CPU_SW_DOMAIN_PAN=yes
  # ifarm: ARM64_SW_TTBR0_PAN=yes

  # NULL ptr deref prot 
  #TODO V 
  #DEFAULT_MMAP_MIN_ADDR=65536; #might break qemu


  # spectre/meltdown/.. chache/prediction bullshitery
  PAGE_TABLE_ISOLATION=yes; #Spectre v3 
  #ifarm: UNMAP_KERNEL_AT_EL0=yes #spectre v3
  # ifarm: HARDEN_BRANCH_PREDICTOR=yes;
  # TODO spectre_v2=on
  # ifarm: MITIGATE_SPECTRE_BRANCH_HISTORY=yes
  # TODO mitigations=auto,nosmt
  # TODO MICROCODE
  # TODO Manual usage of nospec barriers

  # TODO spec_store_bypass_disable=on
  # ifarm:  ssbd=force-on

  # shoop
  # TODO l1d_flush=on 
  # TODO l1tf=full,force
  
  # Fallout
  # mds=full,nosmt 
  
  # straight line speculation
  #SLS=yes; #only in <= 5.17 releases

  # heap layout controll
  # TODO slab_nomerge
  # TODO unprivileged_userfaultfd=0


  # metadata manipulation:
  STATIC_USERMODEHELPER=yes;
  DEBUG_LIST=yes;
  DEBUG_VIRTUAL=yes;
  BUG_ON_DATA_CORRUPTION=yes;
  #kernel image manipulation
  # TODO LOCKDOWN_LSM=yes;


}
