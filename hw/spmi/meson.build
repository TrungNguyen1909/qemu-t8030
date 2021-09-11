specific_ss.add(when: ['CONFIG_SOFTMMU', 'TARGET_AARCH64'], if_true: files('apple_spmi.c', 'apple_spmi_pmu.c'))
spmi_ss = ss.source_set()
spmi_ss.add(when: 'CONFIG_SPMI', if_true: files('core.c'))
softmmu_ss.add_all(when: 'CONFIG_SPMI', if_true: spmi_ss)
