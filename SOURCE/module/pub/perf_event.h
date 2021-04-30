#if defined(ALIOS_4000_009)

struct cpu_hw_events;

union perf_capabilities {
	struct {
		u64	lbr_format:6;
		u64	pebs_trap:1;
		u64	pebs_arch_reg:1;
		u64	pebs_format:4;
		u64	smm_freeze:1;
		/*
		 * PMU supports separate counter range for writing
		 * values > 32bit.
		 */
		u64	full_width_write:1;
		u64     pebs_baseline:1;
	};
	u64	capabilities;
};

enum {
	x86_lbr_exclusive_lbr,
	x86_lbr_exclusive_bts,
	x86_lbr_exclusive_pt,
	x86_lbr_exclusive_max,
};

/*
 * struct x86_pmu - generic x86 pmu
 */
struct x86_pmu {
  /*
   * Generic x86 PMC bits
   */
  const char  *name;
  int    version;
  int    (*handle_irq)(struct pt_regs *);
  void    (*disable_all)(void);
  void    (*enable_all)(int added);
  void    (*enable)(struct perf_event *);
  void    (*disable)(struct perf_event *);
  void    (*add)(struct perf_event *);
  void    (*del)(struct perf_event *);
  void    (*read)(struct perf_event *event);
  int    (*hw_config)(struct perf_event *event);
  int    (*schedule_events)(struct cpu_hw_events *cpuc, int n, int *assign);
  unsigned  eventsel;
  unsigned  perfctr;
  int    (*addr_offset)(int index, bool eventsel);
  int    (*rdpmc_index)(int index);
  u64    (*event_map)(int);
  int    max_events;
  int    num_counters;
  int    num_counters_fixed;
  int    cntval_bits;
  u64    cntval_mask;
  union {
      unsigned long events_maskl;
      unsigned long events_mask[BITS_TO_LONGS(ARCH_PERFMON_EVENTS_COUNT)];
  };
  int    events_mask_len;
  int    apic;
  u64    max_period;
  struct event_constraint *
      (*get_event_constraints)(struct cpu_hw_events *cpuc,
             int idx,
             struct perf_event *event);

  void    (*put_event_constraints)(struct cpu_hw_events *cpuc,
             struct perf_event *event);

  void    (*start_scheduling)(struct cpu_hw_events *cpuc);

  void    (*commit_scheduling)(struct cpu_hw_events *cpuc, int idx, int cntr);

  void    (*stop_scheduling)(struct cpu_hw_events *cpuc);

  struct event_constraint *event_constraints;
  struct x86_pmu_quirk *quirks;
  int    perfctr_second_write;
  bool    late_ack;
  u64    (*limit_period)(struct perf_event *event, u64 l);

  /*
   * sysfs attrs
   */
  int    attr_rdpmc_broken;
  int    attr_rdpmc;
  struct attribute **format_attrs;

  ssize_t    (*events_sysfs_show)(char *page, u64 config);
  const struct attribute_group **attr_update;

  unsigned long  attr_freeze_on_smi;

  /*
   * CPU Hotplug hooks
   */
  int    (*cpu_prepare)(int cpu);
  void    (*cpu_starting)(int cpu);
  void    (*cpu_dying)(int cpu);
  void    (*cpu_dead)(int cpu);

  void    (*check_microcode)(void);
  void    (*sched_task)(struct perf_event_context *ctx,
              bool sched_in);

  /*
   * Intel Arch Perfmon v2+
   */
  u64      intel_ctrl;
  union perf_capabilities intel_cap;

  /*
   * Intel DebugStore bits
   */
  unsigned int  bts      :1,
      bts_active    :1,
      pebs      :1,
      pebs_active    :1,
      pebs_broken    :1,
      pebs_prec_dist    :1,
      pebs_no_tlb    :1;
  int    pebs_record_size;
  int    pebs_buffer_size;
  int    max_pebs_events;
  void    (*drain_pebs)(struct pt_regs *regs);
  struct event_constraint *pebs_constraints;
  void    (*pebs_aliases)(struct perf_event *event);
  unsigned long  large_pebs_flags;
  u64    rtm_abort_event;

  /*
   * Intel LBR
   */
  unsigned int  lbr_tos, lbr_from, lbr_to,
      lbr_nr;         /* LBR base regs and size */
  u64    lbr_sel_mask;       /* LBR_SELECT valid bits */
  const int  *lbr_sel_map;       /* lbr_select mappings */
  bool    lbr_double_abort;     /* duplicated lbr aborts */
  bool    lbr_pt_coexist;       /* (LBR|BTS) may coexist with PT */

  /*
   * Intel PT/LBR/BTS are exclusive
   */
  atomic_t  lbr_exclusive[x86_lbr_exclusive_max];

  /*
   * Intel perf metrics
   */
  u64    (*update_topdown_event)(struct perf_event *event);
  int    (*set_topdown_event_period)(struct perf_event *event);

  /*
   * AMD bits
   */
  unsigned int  amd_nb_constraints : 1;
  u64    perf_ctr_pair_en;

  /*
   * Extra registers for events
   */
  struct extra_reg *extra_regs;
  unsigned int flags;

  /*
   * Intel host/guest support (KVM)
   */
  struct perf_guest_switch_msr *(*guest_get_msrs)(int *nr);

  /*
   * Check period value for PERF_EVENT_IOC_PERIOD ioctl.
   */
  int (*check_period) (struct perf_event *event, u64 period);
};
#elif defined(ALIOS_4000_007)
/*
crash> struct x86_pmu -o | grep lbr_nr
  [456] int lbr_nr;
*/
struct cpu_hw_events;

union perf_capabilities {
	struct {
		u64	lbr_format:6;
		u64	pebs_trap:1;
		u64	pebs_arch_reg:1;
		u64	pebs_format:4;
		u64	smm_freeze:1;
		/*
		 * PMU supports separate counter range for writing
		 * values > 32bit.
		 */
		u64	full_width_write:1;
		u64     pebs_baseline:1;
	};
	u64	capabilities;
};

enum {
	x86_lbr_exclusive_lbr,
	x86_lbr_exclusive_bts,
	x86_lbr_exclusive_pt,
	x86_lbr_exclusive_max,
};

/*
 * struct x86_pmu - generic x86 pmu
 */
struct x86_pmu {
  /*
   * Generic x86 PMC bits
   */
  const char  *name;
  int    version;
  int    (*handle_irq)(struct pt_regs *);
  void    (*disable_all)(void);
  void    (*enable_all)(int added);
  void    (*enable)(struct perf_event *);
  void    (*disable)(struct perf_event *);
  void    (*add)(struct perf_event *);
  void    (*del)(struct perf_event *);
  void    (*read)(struct perf_event *event);
  int    (*hw_config)(struct perf_event *event);
  int    (*schedule_events)(struct cpu_hw_events *cpuc, int n, int *assign);
  unsigned  eventsel;
  unsigned  perfctr;
  int    (*addr_offset)(int index, bool eventsel);
  int    (*rdpmc_index)(int index);
  u64    (*event_map)(int);
  int    max_events;
  int    num_counters;
  int    num_counters_fixed;
  int    cntval_bits;
  u64    cntval_mask;
  union {
      unsigned long events_maskl;
      unsigned long events_mask[BITS_TO_LONGS(ARCH_PERFMON_EVENTS_COUNT)];
  };
  int    events_mask_len;
  int    apic;
  u64    max_period;
  struct event_constraint *
      (*get_event_constraints)(struct cpu_hw_events *cpuc,
             int idx,
             struct perf_event *event);

  void    (*put_event_constraints)(struct cpu_hw_events *cpuc,
             struct perf_event *event);

  void    (*start_scheduling)(struct cpu_hw_events *cpuc);

  void    (*commit_scheduling)(struct cpu_hw_events *cpuc, int idx, int cntr);

  void    (*stop_scheduling)(struct cpu_hw_events *cpuc);

  struct event_constraint *event_constraints;
  struct x86_pmu_quirk *quirks;
  int    perfctr_second_write;
  bool    late_ack;
  u64    (*limit_period)(struct perf_event *event, u64 l);

  /*
   * sysfs attrs
   */
  int    attr_rdpmc_broken;
  int    attr_rdpmc;
  struct attribute **format_attrs;
  struct attribute **event_attrs;
  struct attribute **caps_attrs;

  ssize_t    (*events_sysfs_show)(char *page, u64 config);
  struct attribute **cpu_events;

  unsigned long  attr_freeze_on_smi;
  struct attribute **attrs;

  /*
   * CPU Hotplug hooks
   */
  int    (*cpu_prepare)(int cpu);
  void    (*cpu_starting)(int cpu);
  void    (*cpu_dying)(int cpu);
  void    (*cpu_dead)(int cpu);

  void    (*check_microcode)(void);
  void    (*sched_task)(struct perf_event_context *ctx,
              bool sched_in);

  /*
   * Intel Arch Perfmon v2+
   */
  u64      intel_ctrl;
  union perf_capabilities intel_cap;

  /*
   * Intel DebugStore bits
   */
  unsigned int  bts      :1,
      bts_active    :1,
      pebs      :1,
      pebs_active    :1,
      pebs_broken    :1,
      pebs_prec_dist    :1,
      pebs_no_tlb    :1;
  int    pebs_record_size;
  int    pebs_buffer_size;
  int    max_pebs_events;
  void    (*drain_pebs)(struct pt_regs *regs);
  struct event_constraint *pebs_constraints;
  void    (*pebs_aliases)(struct perf_event *event);
  unsigned long  large_pebs_flags;
  u64    rtm_abort_event;

  /*
   * Intel LBR
   */
  unsigned long  lbr_tos, lbr_from, lbr_to; /* MSR base regs       */
  int    lbr_nr;         /* hardware stack size */
  u64    lbr_sel_mask;       /* LBR_SELECT valid bits */
  const int  *lbr_sel_map;       /* lbr_select mappings */
  bool    lbr_double_abort;     /* duplicated lbr aborts */
  bool    lbr_pt_coexist;       /* (LBR|BTS) may coexist with PT */

  /*
   * Intel PT/LBR/BTS are exclusive
   */
  atomic_t  lbr_exclusive[x86_lbr_exclusive_max];

  /*
   * AMD bits
   */
  unsigned int  amd_nb_constraints : 1;

  /*
   * Extra registers for events
   */
  struct extra_reg *extra_regs;
  unsigned int flags;

  /*
   * Intel host/guest support (KVM)
   */
  struct perf_guest_switch_msr *(*guest_get_msrs)(int *nr);

  /*
   * Check period value for PERF_EVENT_IOC_PERIOD ioctl.
   */
  int (*check_period) (struct perf_event *event, u64 period);
};
#elif defined(ALIOS_3000_016) || defined(ALIOS_3000_015) \
	|| defined(ALIOS_3000_010) || defined(ALIOS_3000_009)
/*
crash> struct x86_pmu -o | grep lbr_nr
  [424] int lbr_nr;
*/
struct cpu_hw_events;

union perf_capabilities {
	struct {
		u64	lbr_format:6;
		u64	pebs_trap:1;
		u64	pebs_arch_reg:1;
		u64	pebs_format:4;
		u64	smm_freeze:1;
		/*
		 * PMU supports separate counter range for writing
		 * values > 32bit.
		 */
		u64	full_width_write:1;
	};
	u64	capabilities;
};

enum {
	x86_lbr_exclusive_lbr,
	x86_lbr_exclusive_bts,
	x86_lbr_exclusive_pt,
	x86_lbr_exclusive_max,
};

/*
 * struct x86_pmu - generic x86 pmu
 */
struct x86_pmu {
	/*
	 * Generic x86 PMC bits
	 */
	const char	*name;
	int		version;
	int		(*handle_irq)(struct pt_regs *);
	void		(*disable_all)(void);
	void		(*enable_all)(int added);
	void		(*enable)(struct perf_event *);
	void		(*disable)(struct perf_event *);
	void		(*add)(struct perf_event *);
	void		(*del)(struct perf_event *);
	int		(*hw_config)(struct perf_event *event);
	int		(*schedule_events)(struct cpu_hw_events *cpuc, int n, int *assign);
	unsigned	eventsel;
	unsigned	perfctr;
	int		(*addr_offset)(int index, bool eventsel);
	int		(*rdpmc_index)(int index);
	u64		(*event_map)(int);
	int		max_events;
	int		num_counters;
	int		num_counters_fixed;
	int		cntval_bits;
	u64		cntval_mask;
	union {
			unsigned long events_maskl;
			unsigned long events_mask[BITS_TO_LONGS(ARCH_PERFMON_EVENTS_COUNT)];
	};
	int		events_mask_len;
	int		apic;
	u64		max_period;
	struct event_constraint *
			(*get_event_constraints)(struct cpu_hw_events *cpuc,
						 int idx,
						 struct perf_event *event);

	void		(*put_event_constraints)(struct cpu_hw_events *cpuc,
						 struct perf_event *event);

	void		(*start_scheduling)(struct cpu_hw_events *cpuc);

	void		(*commit_scheduling)(struct cpu_hw_events *cpuc, int idx, int cntr);

	void		(*stop_scheduling)(struct cpu_hw_events *cpuc);

	struct event_constraint *event_constraints;
	struct x86_pmu_quirk *quirks;
	int		perfctr_second_write;
	bool		late_ack;
	unsigned	(*limit_period)(struct perf_event *event, unsigned l);

	/*
	 * sysfs attrs
	 */
	int		attr_rdpmc_broken;
	int		attr_rdpmc;
	struct attribute **format_attrs;
	struct attribute **event_attrs;

	ssize_t		(*events_sysfs_show)(char *page, u64 config);
	struct attribute **cpu_events;

	/*
	 * CPU Hotplug hooks
	 */
	int		(*cpu_prepare)(int cpu);
	void		(*cpu_starting)(int cpu);
	void		(*cpu_dying)(int cpu);
	void		(*cpu_dead)(int cpu);

	void		(*check_microcode)(void);
	void		(*sched_task)(struct perf_event_context *ctx,
				      bool sched_in);

	/*
	 * Intel Arch Perfmon v2+
	 */
	u64			intel_ctrl;
	union perf_capabilities intel_cap;

	/*
	 * Intel DebugStore bits
	 */
	unsigned int	bts		:1,
			bts_active	:1,
			pebs		:1,
			pebs_active	:1,
			pebs_broken	:1,
			pebs_prec_dist	:1;
	int		pebs_record_size;
	int		pebs_buffer_size;
	void		(*drain_pebs)(struct pt_regs *regs);
	struct event_constraint *pebs_constraints;
	void		(*pebs_aliases)(struct perf_event *event);
	int 		max_pebs_events;
	unsigned long	free_running_flags;

	/*
	 * Intel LBR
	 */
	unsigned long	lbr_tos, lbr_from, lbr_to; /* MSR base regs       */
	int		lbr_nr;			   /* hardware stack size */
	u64		lbr_sel_mask;		   /* LBR_SELECT valid bits */
	const int	*lbr_sel_map;		   /* lbr_select mappings */
	bool		lbr_double_abort;	   /* duplicated lbr aborts */
	bool		lbr_pt_coexist;		   /* (LBR|BTS) may coexist with PT */

	/*
	 * Intel PT/LBR/BTS are exclusive
	 */
	atomic_t	lbr_exclusive[x86_lbr_exclusive_max];

	/*
	 * AMD bits
	 */
	unsigned int	amd_nb_constraints : 1;

	/*
	 * Extra registers for events
	 */
	struct extra_reg *extra_regs;
	unsigned int flags;

	/*
	 * Intel host/guest support (KVM)
	 */
	struct perf_guest_switch_msr *(*guest_get_msrs)(int *nr);
};
#elif defined(ALIOS_2016)
struct cpu_hw_events;

union perf_capabilities {
	struct {
		u64	lbr_format:6;
		u64	pebs_trap:1;
		u64	pebs_arch_reg:1;
		u64	pebs_format:4;
		u64	smm_freeze:1;
		/*
		 * PMU supports separate counter range for writing
		 * values > 32bit.
		 */
		u64	full_width_write:1;
	};
	u64	capabilities;
};

/*
 * struct x86_pmu - generic x86 pmu
 */
struct x86_pmu {
	/*
	 * Generic x86 PMC bits
	 */
	const char	*name;
	int		version;
	int		(*handle_irq)(struct pt_regs *);
	void		(*disable_all)(void);
	void		(*enable_all)(int added);
	void		(*enable)(struct perf_event *);
	void		(*disable)(struct perf_event *);
	int		(*hw_config)(struct perf_event *event);
	int		(*schedule_events)(struct cpu_hw_events *cpuc, int n, int *assign);
	unsigned	eventsel;
	unsigned	perfctr;
	int		(*addr_offset)(int index, bool eventsel);
	int		(*rdpmc_index)(int index);
	u64		(*event_map)(int);
	int		max_events;
	int		num_counters;
	int		num_counters_fixed;
	int		cntval_bits;
	u64		cntval_mask;
	union {
			unsigned long events_maskl;
			unsigned long events_mask[BITS_TO_LONGS(ARCH_PERFMON_EVENTS_COUNT)];
	};
	int		events_mask_len;
	int		apic;
	u64		max_period;
	struct event_constraint *
			(*get_event_constraints)(struct cpu_hw_events *cpuc,
						 int idx,
						 struct perf_event *event);

	void		(*put_event_constraints)(struct cpu_hw_events *cpuc,
						 struct perf_event *event);

	void		(*commit_scheduling)(struct cpu_hw_events *cpuc, int idx, int cntr);

	void		(*start_scheduling)(struct cpu_hw_events *cpuc);

	void		(*stop_scheduling)(struct cpu_hw_events *cpuc);

	struct event_constraint *event_constraints;
	struct x86_pmu_quirk *quirks;
	int		perfctr_second_write;
	bool		late_ack;
	unsigned	(*limit_period)(struct perf_event *event, unsigned l);

	/*
	 * sysfs attrs
	 */
	int		attr_rdpmc_broken;
	int		attr_rdpmc;
	struct attribute **format_attrs;
	struct attribute **event_attrs;

	ssize_t		(*events_sysfs_show)(char *page, u64 config);
	struct attribute **cpu_events;

	/*
	 * CPU Hotplug hooks
	 */
	int		(*cpu_prepare)(int cpu);
	void		(*cpu_starting)(int cpu);
	void		(*cpu_dying)(int cpu);
	void		(*cpu_dead)(int cpu);

	void		(*check_microcode)(void);
	void		(*sched_task)(struct perf_event_context *ctx,
				      bool sched_in);

	/*
	 * Intel Arch Perfmon v2+
	 */
	u64			intel_ctrl;
	union perf_capabilities intel_cap;

	/*
	 * Intel DebugStore bits
	 */
	unsigned int	bts		:1,
			bts_active	:1,
			pebs		:1,
			pebs_active	:1,
			pebs_broken	:1,
			pebs_no_tlb	:1;
	int		pebs_record_size;
	int		pebs_buffer_size;
	void		(*drain_pebs)(struct pt_regs *regs);
	struct event_constraint *pebs_constraints;
	void		(*pebs_aliases)(struct perf_event *event);
	int 		max_pebs_events;

	/*
	 * Intel LBR
	 */
	unsigned long	lbr_tos, lbr_from, lbr_to; /* MSR base regs       */
	int		lbr_nr;			   /* hardware stack size */
	u64		lbr_sel_mask;		   /* LBR_SELECT valid bits */
	const int	*lbr_sel_map;		   /* lbr_select mappings */
	bool		lbr_double_abort;	   /* duplicated lbr aborts */

	/*
	 * Extra registers for events
	 */
	struct extra_reg *extra_regs;
	unsigned int flags;

	/*
	 * Intel host/guest support (KVM)
	 */
	struct perf_guest_switch_msr *(*guest_get_msrs)(int *nr);
};
#else
#define INGORE_LBR
#endif