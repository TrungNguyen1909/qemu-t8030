spmi_ss = ss.source_set()
spmi_ss.add(when: 'CONFIG_SPMI', if_true: files('core.c'))
spmi_ss.add(when: 'CONFIG_APPLE_SPMI', if_true: files('apple_spmi.c'))
softmmu_ss.add_all(when: 'CONFIG_SPMI', if_true: spmi_ss)
