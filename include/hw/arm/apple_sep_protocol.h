#ifndef HW_MISC_APPLE_SEP_PROTOCOL_H
#define HW_MISC_APPLE_SEP_PROTOCOL_H

#include "qemu/osdep.h"

#define kEndpoint_CONTROL       (0)
#define kEndpoint_CREDENTIAL    (10)
#define kEndpoint_XART_SLAVE    (16)
#define kEndpoint_KEYSTORE      (18)
#define kEndpoint_XART_MASTER   (19)
#define kEndpoint_DISCOVERY     (253)
#define kEndpoint_L4INFO        (254)
#define kEndpoint_SEPROM	    (255)

/* SEPROM Opcodes */
enum seprom_opcodes {
	kOpCode_Ping = 1,
    kOpCode_GetStatus = 2,
	kOpCode_GenerateNonce = 3,
	kOpCode_GetNonceWord = 4,
    kOpCode_BootTz0 = 5,
    kOpCode_Start = 6,
    kOpCode_NotifyOSActiveAsync = 13,
	kOpCode_SendDpa = 15,
    kOpCode_NotifyOSActive = 21,
	kOpCode_Ack = 101,
	kOpCode_AckStatus = 102,
	kOpCode_ReportGeneratedNonce = 103,
	kOpCode_ReportNonceWord = 104,
    kOpCode_AcceptTz0 = 105,
    kOpCode_AcceptIMG4 = 106,
    kOpCode_AcceptSEPART = 107,
    kOpCode_ResumeRAM = 108,
	kOpCode_ReportSentDpa = 115,
	kOpCode_LogRaw = 201,
	kOpCode_LogPrintable = 202,
	kOpCode_AnnouceStatus = 210,
	kOpCode_ReportPanic = 255
};

/* SEP Cntl Opcodes */
enum sepcntl_opcodes {
    kOpCode_NOP = 0,
    kOpCode_SET_OOL_IN_ADDR = 2,
    kOpCode_SET_OOL_OUT_ADDR = 3,
    kOpCode_SET_OOL_IN_SIZE = 4,
    kOpCode_SET_OOL_OUT_SIZE = 5,
    kOpCode_TTYIN = 10,
    kOpCode_Sleep = 12,
    kOpCode_Nap = 19,
    kOpCode_SECMODE_REQUEST = 0x14,
    kOpCode_SELFTEST = 0x18,
    kOpCode_ERASE_INSTALL = 0x25,
    kOpCode_L4_PANIC = 0x26,
    kOpCode_SEPOSPANIC = 0x27,
};

/* SEP Discovery Opcodes */
enum sepdiscovery_opcodes {
    kOpCode_Advertise = 0,
    kOpCode_Expose = 1,
};

struct QEMU_PACKED ep_advertise_data {
    uint8_t id; /* param */
    uint32_t name; /*data */
};

struct QEMU_PACKED ep_expose_data {
    uint8_t id; /* param */
    char ool_in_min_pages;
    char ool_in_max_pages;
    char ool_out_min_pages;
    char ool_out_max_pages;
};

/* SEP mbox message format */
struct QEMU_PACKED sep_message {
    union {
        struct QEMU_PACKED {
            uint8_t		endpoint;
            uint8_t		tag;
            uint8_t		opcode;
            union {
                struct QEMU_PACKED {
                    uint8_t		param;
                    uint32_t	data;
                };
                struct ep_advertise_data ep_advertise_data;
                struct ep_expose_data ep_expose_data;
            };
        };
        uint64_t raw;
    };
};
#endif /* HW_MISC_APPLE_SEP_PROTOCOL_H */
