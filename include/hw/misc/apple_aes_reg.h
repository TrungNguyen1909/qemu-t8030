#ifndef HW_MISC_APPLE_AES_REG_H
#define HW_MISC_APPLE_AES_REG_H

#include "qemu/osdep.h"

#pragma pack(push, 1)

/* Register defintion for AES V2 */
#define rAES_VERSION                (0x0)
#define rAES_CONFIG                 (0x4)
#define rAES_CONTROL                (0x8)
#define  AES_BLK_CONTROL_START      (1 << 0)
#define  AES_BLK_CONTROL_STOP       (1 << 1)
#define  AES_BLK_CONTROL_RESET      (1 << 2)
#define  AES_BLK_CONTROL_RESET_AES  (1 << 3)

#define rAES_STATUS                                                      (0xc)
#define  AES_BLK_STATUS_DMA_READ_ACTIVE                                  (1 << 0)
#define  AES_BLK_STATUS_DMA_READ_INCOMPLETE                              (1 << 1)
#define  AES_BLK_STATUS_DMA_WRITE_ACTIVE                                 (1 << 2)
#define  AES_BLK_STATUS_DMA_WRITE_INCOMPLETE                             (1 << 3)
#define  AES_BLK_STATUS_ACTIVE                                           (1 << 4)
#define  AES_BLK_STATUS_COMMAND_FIFO_ACTIVE                              (1 << 5)
#define  AES_BLK_STATUS_COMMAND_FIFO_ENABLED                             (1 << 6)
#define  AES_BLK_STATUS_TEXT_DPA_RANDOM_SEEDED                           (1 << 7)
#define  AES_BLK_STATUS_KEY_UNWRAP_DPA_RANDOM_SEEDED                     (1 << 8)

#define rAES_KEY_ID                             (0x10)
#define  AES_BLK_KEY_ID_CONTEXT_0_SHIFT         (0)
#define  AES_BLK_KEY_ID_CONTEXT_0_WIDTH         (8)
#define  AES_BLK_KEY_ID_CONTEXT_0_UMASK         (0xff)
#define  AES_BLK_KEY_ID_CONTEXT_0_SMASK         (0xff)
#define  AES_BLK_KEY_ID_CONTEXT_0_XTRCT(r)      ((((uint32_t)r) >> 0) & 0xff)
#define  AES_BLK_KEY_ID_CONTEXT_0_INSRT(f)      ((((uint32_t)f) & 0xff) << 0)
#define  AES_BLK_KEY_ID_CONTEXT_1_SHIFT         (8)
#define  AES_BLK_KEY_ID_CONTEXT_1_WIDTH         (8)
#define  AES_BLK_KEY_ID_CONTEXT_1_UMASK         (0xff00)
#define  AES_BLK_KEY_ID_CONTEXT_1_SMASK         (0xff)
#define  AES_BLK_KEY_ID_CONTEXT_1_XTRCT(r)      ((((uint32_t)r) >> 8) & 0xff)
#define  AES_BLK_KEY_ID_CONTEXT_1_INSRT(f)      ((((uint32_t)f) & 0xff) << 8)

#define rAES_AXI_STATUS                         (0x14)

#define rAES_INT_STATUS                                              (0x18)
#define rAES_INT_ENABLE                                              (0x1c)
#define  AES_BLK_INT_COMMAND_FIFO_LOW                                (1 << 0)
#define  AES_BLK_INT_COMMAND_FIFO_OVERFLOW                           (1 << 1)
#define  AES_BLK_INT_INVALID_COMMAND                                 (1 << 2)
#define  AES_BLK_INT_AXI_READ_RESPONSE_NOT_OKAY                      (1 << 3)
#define  AES_BLK_INT_AXI_WRITE_RESPONSE_NOT_OKAY                     (1 << 4)
#define  AES_BLK_INT_FLAG_COMMAND                                    (1 << 5)
#define  AES_BLK_INT_INVALID_DATA_LENGTH                             (1 << 6)
#define  AES_BLK_INT_KEY_0_DISABLED                                  (1 << 7)
#define  AES_BLK_INT_KEY_0_CMAC_TAG_MISMATCH                         (1 << 8)
#define  AES_BLK_INT_KEY_0_POLICY_MISMATCH                           (1 << 9)
#define  AES_BLK_INT_KEY_0_INVALID_AT_USE_TIME                       (1 << 10)
#define  AES_BLK_INT_KEY_0_HDCP_ERR                                  (1 << 11)
#define  AES_BLK_INT_KEY_0_DPA_RANDOM_UNSEEDED                       (1 << 12)
#define  AES_BLK_INT_KEY_1_DISABLED                                  (1 << 13)
#define  AES_BLK_INT_KEY_1_CMAC_TAG_MISMATCH                         (1 << 14)
#define  AES_BLK_INT_KEY_1_POLICY_MISMATCH                           (1 << 15)
#define  AES_BLK_INT_KEY_1_INVALID_AT_USE_TIME                       (1 << 16)
#define  AES_BLK_INT_KEY_1_HDCP_ERR                                  (1 << 17)
#define  AES_BLK_INT_KEY_1_DPA_RANDOM_UNSEEDED                       (1 << 18)

#define rAES_WATERMARKS                                  (0x20)
#define  AES_BLK_WATERMARKS_COMMAND_FIFO_LOW_SHIFT       (0)
#define  AES_BLK_WATERMARKS_COMMAND_FIFO_LOW_WIDTH       (7)
#define  AES_BLK_WATERMARKS_COMMAND_FIFO_LOW_UMASK       (0x7f)
#define  AES_BLK_WATERMARKS_COMMAND_FIFO_LOW_SMASK       (0x7f)
#define  AES_BLK_WATERMARKS_COMMAND_FIFO_LOW_XTRCT(r)    ((((uint32_t)r) >> 0) & 0x7f)
#define  AES_BLK_WATERMARKS_COMMAND_FIFO_LOW_INSRT(f)    ((((uint32_t)f) & 0x7f) << 0)

#define rAES_COMMAND_FIFO_STATUS                            (0x24)
#define  AES_BLK_COMMAND_FIFO_STATUS_LOW                    (1 << 0)
#define  AES_BLK_COMMAND_FIFO_STATUS_EMPTY                  (1 << 1)
#define  AES_BLK_COMMAND_FIFO_STATUS_FULL                   (1 << 2)
#define  AES_BLK_COMMAND_FIFO_STATUS_OVERFLOW               (1 << 3)
#define  AES_BLK_COMMAND_FIFO_STATUS_LEVEL_SHIFT            (8)
#define  AES_BLK_COMMAND_FIFO_STATUS_LEVEL_WIDTH            (8)
#define  AES_BLK_COMMAND_FIFO_STATUS_LEVEL_UMASK            (0xff00)
#define  AES_BLK_COMMAND_FIFO_STATUS_LEVEL_SMASK            (0xff)
#define  AES_BLK_COMMAND_FIFO_STATUS_LEVEL_XTRCT(r)         ((((uint32_t)r) >> 8) & 0xff)
#define  AES_BLK_COMMAND_FIFO_STATUS_LEVEL_INSRT(f)         ((((uint32_t)f) & 0xff) << 8)
#define  AES_BLK_COMMAND_FIFO_STATUS_READ_POINTER_SHIFT     (16)
#define  AES_BLK_COMMAND_FIFO_STATUS_READ_POINTER_WIDTH     (7)
#define  AES_BLK_COMMAND_FIFO_STATUS_READ_POINTER_UMASK     (0x7f0000)
#define  AES_BLK_COMMAND_FIFO_STATUS_READ_POINTER_SMASK     (0x7f)
#define  AES_BLK_COMMAND_FIFO_STATUS_READ_POINTER_XTRCT(r)  ((((uint32_t)r) >> 16) & 0x7f)
#define  AES_BLK_COMMAND_FIFO_STATUS_READ_POINTER_INSRT(f)  ((((uint32_t)f) & 0x7f) << 16)
#define  AES_BLK_COMMAND_FIFO_STATUS_WRITE_POINTER_SHIFT    (24)
#define  AES_BLK_COMMAND_FIFO_STATUS_WRITE_POINTER_WIDTH    (7)
#define  AES_BLK_COMMAND_FIFO_STATUS_WRITE_POINTER_UMASK    (0x7f000000)
#define  AES_BLK_COMMAND_FIFO_STATUS_WRITE_POINTER_SMASK    (0x7f)
#define  AES_BLK_COMMAND_FIFO_STATUS_WRITE_POINTER_XTRCT(r) ((((uint32_t)r) >> 24) & 0x7f)
#define  AES_BLK_COMMAND_FIFO_STATUS_WRITE_POINTER_INSRT(f) ((((uint32_t)f) & 0x7f) << 24)

#define rAES_COMMAND_FIFO_COUNT                         (0x2c)
#define  AES_BLK_COMMAND_FIFO_COUNT_TOTAL_SHIFT         (0)
#define  AES_BLK_COMMAND_FIFO_COUNT_TOTAL_WIDTH         (32)
#define  AES_BLK_COMMAND_FIFO_COUNT_TOTAL_UMASK         (0xffffffff)
#define  AES_BLK_COMMAND_FIFO_COUNT_TOTAL_SMASK         (0xffffffff)
#define  AES_BLK_COMMAND_FIFO_COUNT_TOTAL_XTRCT(r)      ((((uint32_t)r) >> 0) & 0xffffffff)
#define  AES_BLK_COMMAND_FIFO_COUNT_TOTAL_INSRT(f)      ((((uint32_t)f) & 0xffffffff) << 0)

#define rAES_FLAG_COMMAND                       (0x30)
#define  AES_BLK_FLAG_COMMAND_CODE_SHIFT        (0)
#define  AES_BLK_FLAG_COMMAND_CODE_WIDTH        (16)
#define  AES_BLK_FLAG_COMMAND_CODE_UMASK        (0xffff)
#define  AES_BLK_FLAG_COMMAND_CODE_SMASK        (0xffff)
#define  AES_BLK_FLAG_COMMAND_CODE_XTRCT(r)     ((((uint32_t)r) >> 0) & 0xffff)
#define  AES_BLK_FLAG_COMMAND_CODE_INSRT(f)     ((((uint32_t)f) & 0xffff) << 0)

#define rAES_SKG_KEY                (0x34)

#define rAES_CLEAR_FIFO             (0x38)
#define rAES_CLEAR_FIFO_RESET       (1 << 0)

#define rAES_COMMAND_FIFO           (0x200)

#define rAES_HISTORY_FIFO           (0x400)

#define COMMAND_FIFO_SIZE 128

typedef enum {
	BLOCK_MODE_ECB = 0,
	BLOCK_MODE_CBC = 1,
	BLOCK_MODE_CTR = 2,
} block_mode_t;

typedef enum {
	KEY_LEN_128 = 0,
	KEY_LEN_192 = 1,
	KEY_LEN_256 = 2,
} key_len_t;

typedef enum {
	KEY_SELECT_SOFTWARE = 0,
	KEY_SELECT_UID1 = 1,
	KEY_SELECT_GID_AP_1 = 2,
	KEY_SELECT_GID_AP_2 = 3,
	KEY_SELECT_HDCP_0 = 4,
	KEY_SELECT_HDCP_1 = 5,
	KEY_SELECT_HDCP_2 = 6,
	KEY_SELECT_HDCP_3 = 7,
} key_select_t;

typedef enum {
	KEY_FUNC_NONE = 0,
	KEY_FUNC_LEGACY = 1,
	KEY_FUNC_FAIRPLAY_LEGACY = 2,
	KEY_FUNC_FAIRPLAY_H8F = 3,
} key_func_t;

typedef enum {
	OPCODE_KEY       = 0x01,
	OPCODE_IV        = 0x02,
	OPCODE_DSB       = 0x03,
	OPCODE_SKG       = 0x04,
	OPCODE_DATA      = 0x05,
	OPCODE_STORE_IV  = 0x06,
	OPCODE_WRITE_REG = 0x07,
	OPCODE_FLAG      = 0x08,
} command_opcodes_t;

#define COMMAND_OPCODE_SHIFT	 (28)
#define COMMAND_OPCODE_MASK      (0xF)
#define COMMAND_OPCODE(_x)       (((_x) >> COMMAND_OPCODE_SHIFT) & COMMAND_OPCODE_MASK)

typedef struct command_key {
	#define COMMAND_KEY_COMMAND_KEY_CONTEXT(_x)  ((_x >> 27) & 0x1)

	#define COMMAND_KEY_COMMAND_KEY_SELECT_SHIFT (24)
	#define COMMAND_KEY_COMMAND_KEY_SELECT_MASK  (0x7)
	#define COMMAND_KEY_COMMAND_KEY_SELECT(_x)   (((_x) >> COMMAND_KEY_COMMAND_KEY_SELECT_SHIFT) & COMMAND_KEY_COMMAND_KEY_SELECT_MASK)

	#define COMMAND_KEY_COMMAND_KEY_LENGTH_SHIFT (22)
	#define COMMAND_KEY_COMMAND_KEY_LENGTH_MASK  (0x3)
	#define COMMAND_KEY_COMMAND_KEY_LENGTH(_x)   (((_x) >> COMMAND_KEY_COMMAND_KEY_LENGTH_SHIFT) & COMMAND_KEY_COMMAND_KEY_LENGTH_MASK)

	#define COMMAND_KEY_COMMAND_WRAPPED          (1 << 21)

	#define COMMAND_KEY_COMMAND_ENCRYPT          (1 << 20)

	#define COMMAND_KEY_COMMAND_KEY_FUNC_SHIFT   (18)
	#define COMMAND_KEY_COMMAND_KEY_FUNC_MASK    (0x3)
	#define COMMAND_KEY_COMMAND_KEY_FUNC(_x)     (((_x) >> 18) & 0x3)

	#define COMMAND_KEY_COMMAND_BLOCK_MODE_SHIFT (16)
	#define COMMAND_KEY_COMMAND_BLOCK_MODE_MASK  (0x3)
	#define COMMAND_KEY_COMMAND_BLOCK_MODE(_x)  (((_x) >> 16) & 0x3)

	#define COMMAND_KEY_COMMAND_COMMAND_ID_SHIFT (0)
	#define COMMAND_KEY_COMMAND_COMMAND_ID_MASK  (0xFF)
	#define COMMAND_KEY_COMMAND_COMMAND_ID(_x)  (((_x) >> 0) & 0xFF)
	uint32_t command;
	uint32_t key[8];
} command_key_t;

typedef struct aes_command_iv {
	#define COMMAND_IV_COMMAND_IV_CONTEXT_SHIFT (26)
	#define COMMAND_IV_COMMAND_IV_CONTEXT_MASK (0x3)
	#define COMMAND_IV_COMMAND_IV_CONTEXT(_x) (((_x) >> 26) & 0x3)

	#define COMMAND_IV_COMMAND_HDCP_KEY_SHIFT (25)
	#define COMMAND_IV_COMMAND_HDCP_KEY_MASK (0x1)

	#define COMMAND_IV_COMMAND_IV_IN_HDCP_SHIFT (23)
	#define COMMAND_IV_COMMAND_IV_IN_HDCP_MASK (0x3)
	uint32_t command;
	uint32_t iv[4];
} command_iv_t;

typedef struct aes_command_data {
	#define COMMAND_DATA_COMMAND_KEY_CONTEXT_SHIFT (27)
	#define COMMAND_DATA_COMMAND_KEY_CONTEXT_MASK (0x1)
	#define COMMAND_DATA_COMMAND_KEY_CONTEXT(_x) (((_x) >> 27) & 0x1)

	#define COMMAND_DATA_COMMAND_IV_CONTEXT_SHIFT (25)
	#define COMMAND_DATA_COMMAND_IV_CONTEXT_MASK (0x3)
	#define COMMAND_DATA_COMMAND_IV_CONTEXT(_x)  (((_x) >> 25) & 0x3)

	#define COMMAND_DATA_COMMAND_LENGTH_SHIFT (0)
	#define COMMAND_DATA_COMMAND_LENGTH_MASK (0xFFFFFF)
	#define COMMAND_DATA_COMMAND_LENGTH(_x) (((_x) >> 0) & 0xFFFFFF)
	uint32_t command;
	#define COMMAND_DATA_UPPER_ADDR_SOURCE_SHIFT (16)
	#define COMMAND_DATA_UPPER_ADDR_SOURCE_MASK (0xFF)
	#define COMMAND_DATA_UPPER_ADDR_SOURCE(_x)  (((_x) >> 16) & 0xFF)

	#define COMMAND_DATA_UPPER_ADDR_DEST_SHIFT (0)
	#define COMMAND_DATA_UPPER_ADDR_DEST_MASK (0xFF)
	#define COMMAND_DATA_UPPER_ADDR_DEST(_x)  (((_x) >> 0) & 0xFF)
	uint32_t upper_addr;
	uint32_t source_addr;
	uint32_t dest_addr;
} command_data_t;

typedef struct aes_command_store_iv {
	#define COMMAND_STORE_IV_COMMAND_CONTEXT_SHIFT (26)
	#define COMMAND_STORE_IV_COMMAND_CONTEXT_MASK (0x3)
	#define COMMAND_STORE_IV_COMMAND_CONTEXT(_x) (((_x) >> 26) & 0x3)

	#define COMMAND_STORE_IV_COMMAND_UPPER_ADDR_DEST_SHIFT (0)
	#define COMMAND_STORE_IV_COMMAND_UPPER_ADDR_DEST_MASK (0xFF)
	#define COMMAND_STORE_IV_COMMAND_UPPER_ADDR_DEST(_x)  (((_x) >> 0) & 0xFF)
	uint32_t command;
	uint32_t dest_addr;
} command_store_iv_t;

#define COMMAND_FLAG_ID_CODE_SHIFT      (0)
#define COMMAND_FLAG_ID_CODE_MASK       (0xFF)
#define COMMAND_FLAG_ID_CODE(_x)        (((_x) >> COMMAND_FLAG_ID_CODE_SHIFT) & COMMAND_FLAG_ID_CODE_MASK)
#define COMMAND_FLAG_STOP_COMMANDS      (1 << 26)
#define COMMAND_FLAG_SEND_INTERRUPT     (1 << 27)

typedef union
{
    uint32_t      raw;
    struct
    {
        /*!
         *  Range = 7:0 | Width = 8 | Access = read-only | Default = 0x0 @n
         *  Minor Release Number
         */
        uint32_t  minor_release  : 8;

        /*!
         *  Range = 15:8 | Width = 8 | Access = read-only | Default = 0x0 @n
         *  Major Release Number
         */
        uint32_t  major_release  : 8;

        /*!
         *  Range = 23:16 | Width = 8 | Access = read-only | Default = 0x0 @n
         *  Version Number
         */
        uint32_t  fld            : 8;

        /*!
         *  Range = 31:24 | Width = 8 | Access = read-as-zero | Default = 0x0 @n
         *  Reserved
         */
        uint32_t  rsvd0          : 8;
    };
} aes_blk_version_t;

typedef union
{
    uint32_t      raw;
    struct
    {
        /*!
         *  Range = 3:0 | Width = 4 | Access = read-write | Default = 0x0 @n
         *  USER ID for AXI Address Read transactions
         */
        uint32_t  axi_aruser   : 4;

        /*!
         *  Range = 7:4 | Width = 4 | Access = read-write | Default = 0x0 @n
         *  ARCACHE for AXI Address Read transactions
         */
        uint32_t  axi_arcache  : 4;

        /*!
         *  Range = 11:8 | Width = 4 | Access = read-write | Default = 0x0 @n
         *  USER ID for AXI Address Write transactions
         */
        uint32_t  axi_awuser   : 4;

        /*!
         *  Range = 15:12 | Width = 4 | Access = read-write | Default = 0x0 @n
         *  AWCACHE for AXI Address Write transactions
         */
        uint32_t  axi_awcache  : 4;

        /*!
         *  Range = 17:16 | Width = 2 | Access = read-write | Default = 0x0 @n
         *  0 = Full Size (default) 64 bytes, 1 = Half Size 32 bytes, 2 =
         *  Quarter Size 16 bytes, 3 = N/A
         */
        uint32_t  burst_size   : 2;

        /*!
         *  Range = 31:18 | Width = 14 | Access = read-as-zero | Default = 0x0
         *  @n
         *  Reserved
         */
        uint32_t  rsvd0        : 14;
    };
} aes_blk_config_t;

typedef union
{
    uint32_t      raw;
    struct
    {
        /*!
         *  Range = 0 | Width = 1 | Access = write-auto-clear | Default = 0x0 @n
         *  Start executing commands in Command FIFO
         */
        uint32_t  start                : 1;

        /*!
         *  Range = 1 | Width = 1 | Access = write-auto-clear | Default = 0x0 @n
         *  Stop executing commands in Command FIFO
         */
        uint32_t  stop                 : 1;

        /*!
         *  Range = 2 | Width = 1 | Access = write-auto-clear | Default = 0x0 @n
         *  Empty Command FIFO
         */
        uint32_t  reset                : 1;

        /*!
         *  Range = 3 | Width = 1 | Access = write-auto-clear | Default = 0x0 @n
         *  Reset the AES Engine
         */
        uint32_t  reset_aes            : 1;

        /*!
         *  Range = 4 | Width = 1 | Access = write-auto-clear | Default = 0x0 @n
         *  Unused. May be used in future chips.
         */
        uint32_t  reset_read_channel   : 1;

        /*!
         *  Range = 5 | Width = 1 | Access = write-auto-clear | Default = 0x0 @n
         *  Unused. May be used in future chips.
         */
        uint32_t  reset_write_channel  : 1;

        /*!
         *  Range = 31:6 | Width = 26 | Access = read-as-zero | Default = 0x0 @n
         *  Reserved
         */
        uint32_t  rsvd0                : 26;
    };
} aes_blk_control_t;

typedef union
{
    uint32_t      raw;
    struct
    {
        /*!
         *  Range = 0 | Width = 1 | Access = read-only | Default = 0x0 @n
         *  The DMA is reading data from System Memory
         */
        uint32_t  dma_read_active               : 1;

        /*!
         *  Range = 1 | Width = 1 | Access = read-only | Default = 0x0 @n
         *  The DMA is done reading data from System Memory but not all data
         *  has been pushed into the AES engine
         */
        uint32_t  dma_read_incomplete           : 1;

        /*!
         *  Range = 2 | Width = 1 | Access = read-only | Default = 0x0 @n
         *  The DMA is writing data to System Memory
         */
        uint32_t  dma_write_active              : 1;

        /*!
         *  Range = 3 | Width = 1 | Access = read-only | Default = 0x0 @n
         *  The DMA is done writing data to System Memory but not all data has
         *  been written
         */
        uint32_t  dma_write_incomplete          : 1;

        /*!
         *  Range = 4 | Width = 1 | Access = read-only | Default = 0x0 @n
         *  AES module is busy
         */
        uint32_t  active                        : 1;

        /*!
         *  Range = 5 | Width = 1 | Access = read-only | Default = 0x0 @n
         *  A command is being executed from the Command FIFO
         */
        uint32_t  command_fifo_active           : 1;

        /*!
         *  Range = 6 | Width = 1 | Access = read-only | Default = 0x0 @n
         *  Indicates the Command FIFO has been enabled and ready to execute
         *  commands
         */
        uint32_t  command_fifo_enabled          : 1;

        /*!
         *  Range = 7 | Width = 1 | Access = read-only | Default = 0x0 @n
         *  The random number generator for text DPA has been seeded
         */
        uint32_t  text_dpa_random_seeded        : 1;

        /*!
         *  Range = 8 | Width = 1 | Access = read-only | Default = 0x0 @n
         *  The random number generator for key unwrap DPA has been seeded
         */
        uint32_t  key_unwrap_dpa_random_seeded  : 1;

        /*!
         *  Range = 31:9 | Width = 23 | Access = read-as-zero | Default = 0x0 @n
         *  Reserved
         */
        uint32_t  rsvd0                         : 23;
    };
} aes_blk_status_t;

typedef union
{
    uint32_t      raw;
    struct
    {
        /*!
         *  Range = 7:0 | Width = 8 | Access = read-only | Default = 0x0 @n
         *  ID for Key in context 0
         */
        uint32_t  context_0  : 8;

        /*!
         *  Range = 15:8 | Width = 8 | Access = read-only | Default = 0x0 @n
         *  ID for Key in context 1
         */
        uint32_t  context_1  : 8;

        /*!
         *  Range = 31:16 | Width = 16 | Access = read-as-zero | Default = 0x0
         *  @n
         *  Reserved
         */
        uint32_t  rsvd0      : 16;
    };
} aes_blk_key_id_t;

typedef union
{
    uint32_t      raw;
    struct
    {
        /*!
         *  Range = 1:0 | Width = 2 | Access = read-only | Default = 0x0 @n
         *  AXI response to read request
         */
        uint32_t  read_response   : 2;

        /*!
         *  Range = 3:2 | Width = 2 | Access = read-only | Default = 0x0 @n
         *  AXI response to write request
         */
        uint32_t  write_response  : 2;

        /*!
         *  Range = 31:4 | Width = 28 | Access = read-as-zero | Default = 0x0 @n
         *  Reserved
         */
        uint32_t  rsvd0           : 28;
    };
} aes_blk_axi_status_t;

typedef union
{
    uint32_t      raw;
    struct
    {
        /*!
         *  Range = 0 | Width = 1 | Access = read-only | Default = 0x0 @n
         *  The number of entries in the Command FIFO has gone below
         *  CHAN.DMA_WATERMARKS.COMMAND_FIFO_LOW (not sticky)
         */
        uint32_t  command_fifo_low             : 1;

        /*!
         *  Range = 1 | Width = 1 | Access = write-once-clear | Default = 0x0 @n
         *  SW pushed (wrote) too many entries into the Command FIFO
         */
        uint32_t  command_fifo_overflow        : 1;

        /*!
         *  Range = 2 | Width = 1 | Access = write-once-clear | Default = 0x0 @n
         *  An invalid opcode detected.
         */
        uint32_t  invalid_command              : 1;

        /*!
         *  Range = 3 | Width = 1 | Access = write-once-clear | Default = 0x0 @n
         *  AXI responded with an "error", "retry" or "split"
         */
        uint32_t  axi_read_response_not_okay   : 1;

        /*!
         *  Range = 4 | Width = 1 | Access = write-once-clear | Default = 0x0 @n
         *  AXI responded with an "error", "retry" or "split"
         */
        uint32_t  axi_write_response_not_okay  : 1;

        /*!
         *  Range = 5 | Width = 1 | Access = write-once-clear | Default = 0x0 @n
         *  A "flag" command has been executed.
         */
        uint32_t  flag_command                 : 1;

        /*!
         *  Range = 6 | Width = 1 | Access = write-once-clear | Default = 0x0 @n
         *  Non-multiple of 16B data length.
         */
        uint32_t  invalid_data_length          : 1;

        /*!
         *  Range = 7 | Width = 1 | Access = write-once-clear | Default = 0x0 @n
         *  Keys are disabled
         */
        uint32_t  key_0_disabled               : 1;

        /*!
         *  Range = 8 | Width = 1 | Access = write-once-clear | Default = 0x0 @n
         *  CMAC Tag mismatch detected
         */
        uint32_t  key_0_cmac_tag_mismatch      : 1;

        /*!
         *  Range = 9 | Width = 1 | Access = write-once-clear | Default = 0x0 @n
         *  Key policy mismatch at load time
         */
        uint32_t  key_0_policy_mismatch        : 1;

        /*!
         *  Range = 10 | Width = 1 | Access = write-once-clear | Default = 0x0
         *  @n
         *  Keys have expired
         */
        uint32_t  key_0_invalid_at_use_time    : 1;

        /*!
         *  Range = 11 | Width = 1 | Access = write-once-clear | Default = 0x0
         *  @n
         *  HDCP error detected
         */
        uint32_t  key_0_hdcp_err               : 1;

        /*!
         *  Range = 12 | Width = 1 | Access = write-once-clear | Default = 0x0
         *  @n
         *  DAP random number generator has not been seeded
         */
        uint32_t  key_0_dpa_random_unseeded    : 1;

        /*!
         *  Range = 13 | Width = 1 | Access = write-once-clear | Default = 0x0
         *  @n
         *  Keys are disabled
         */
        uint32_t  key_1_disabled               : 1;

        /*!
         *  Range = 14 | Width = 1 | Access = write-once-clear | Default = 0x0
         *  @n
         *  CMAC Tag mismatch detected
         */
        uint32_t  key_1_cmac_tag_mismatch      : 1;

        /*!
         *  Range = 15 | Width = 1 | Access = write-once-clear | Default = 0x0
         *  @n
         *  Key policy mismatch at load time
         */
        uint32_t  key_1_policy_mismatch        : 1;

        /*!
         *  Range = 16 | Width = 1 | Access = write-once-clear | Default = 0x0
         *  @n
         *  Keys have expired
         */
        uint32_t  key_1_invalid_at_use_time    : 1;

        /*!
         *  Range = 17 | Width = 1 | Access = write-once-clear | Default = 0x0
         *  @n
         *  HDCP error detected
         */
        uint32_t  key_1_hdcp_err               : 1;

        /*!
         *  Range = 18 | Width = 1 | Access = write-once-clear | Default = 0x0
         *  @n
         *  DAP random number generator has not been seeded
         */
        uint32_t  key_1_dpa_random_unseeded    : 1;

        /*!
         *  Range = 31:19 | Width = 13 | Access = read-as-zero | Default = 0x0
         *  @n
         *  Reserved
         */
        uint32_t  rsvd0                        : 13;
    };
} aes_blk_int_status_t;

typedef union
{
    uint32_t      raw;
    struct
    {
        /*!
         *  Range = 0 | Width = 1 | Access = read-write | Default = 0x0 @n
         *  Enable COMMAND_FIFO_LOW Interrupt.
         */
        uint32_t  command_fifo_low             : 1;

        /*!
         *  Range = 1 | Width = 1 | Access = read-write | Default = 0x0 @n
         *  Enable COMMAND_FIFO_OVERFLOW Interrupt.
         */
        uint32_t  command_fifo_overflow        : 1;

        /*!
         *  Range = 2 | Width = 1 | Access = read-write | Default = 0x0 @n
         *  Enable INVALID_COMMAND Interrupt.
         */
        uint32_t  invalid_command              : 1;

        /*!
         *  Range = 3 | Width = 1 | Access = read-write | Default = 0x0 @n
         *  Enable AXI_READ_RESPONSE_NOT_OKAY Interrupt.
         */
        uint32_t  axi_read_response_not_okay   : 1;

        /*!
         *  Range = 4 | Width = 1 | Access = read-write | Default = 0x0 @n
         *  Enable AXI_WRITE_RESPONSE_NOT_OKAY Interrupt.
         */
        uint32_t  axi_write_response_not_okay  : 1;

        /*!
         *  Range = 5 | Width = 1 | Access = read-write | Default = 0x0 @n
         *  Enable FLAG_COMMAND Interrupt.
         */
        uint32_t  flag_command                 : 1;

        /*!
         *  Range = 6 | Width = 1 | Access = read-write | Default = 0x0 @n
         *  Enable INVALID_DATA_LENGTH Interrupt.
         */
        uint32_t  invalid_data_length          : 1;

        /*!
         *  Range = 7 | Width = 1 | Access = read-write | Default = 0x0 @n
         *  Enable KEY_0_DISABLED Interrupt.
         */
        uint32_t  key_0_disabled               : 1;

        /*!
         *  Range = 8 | Width = 1 | Access = read-write | Default = 0x0 @n
         *  Enable KEY_0_CMAC_TAG_MISMATCH Interrupt.
         */
        uint32_t  key_0_cmac_tag_mismatch      : 1;

        /*!
         *  Range = 9 | Width = 1 | Access = read-write | Default = 0x0 @n
         *  Enable KEY_0_POLICY_MISMATCH Interrupt.
         */
        uint32_t  key_0_policy_mismatch        : 1;

        /*!
         *  Range = 10 | Width = 1 | Access = read-write | Default = 0x0 @n
         *  Enable KEY_0_INVALID_AT_USE_TIME Interrupt.
         */
        uint32_t  key_0_invalid_at_use_time    : 1;

        /*!
         *  Range = 11 | Width = 1 | Access = read-write | Default = 0x0 @n
         *  Enable KEY_0_HDCP_ERR Interrupt.
         */
        uint32_t  key_0_hdcp_err               : 1;

        /*!
         *  Range = 12 | Width = 1 | Access = read-write | Default = 0x0 @n
         *  Enable KEY_0_DPA_RANDOM_UNSEEDED Interrupt.
         */
        uint32_t  key_0_dpa_random_unseeded    : 1;

        /*!
         *  Range = 13 | Width = 1 | Access = read-write | Default = 0x0 @n
         *  Enable KEY_1_DISABLED Interrupt.
         */
        uint32_t  key_1_disabled               : 1;

        /*!
         *  Range = 14 | Width = 1 | Access = read-write | Default = 0x0 @n
         *  Enable KEY_1_CMAC_TAG_MISMATCH Interrupt.
         */
        uint32_t  key_1_cmac_tag_mismatch      : 1;

        /*!
         *  Range = 15 | Width = 1 | Access = read-write | Default = 0x0 @n
         *  Enable KEY_1_POLICY_MISMATCH Interrupt.
         */
        uint32_t  key_1_policy_mismatch        : 1;

        /*!
         *  Range = 16 | Width = 1 | Access = read-write | Default = 0x0 @n
         *  Enable KEY_1_INVALID_AT_USE_TIME Interrupt.
         */
        uint32_t  key_1_invalid_at_use_time    : 1;

        /*!
         *  Range = 17 | Width = 1 | Access = read-write | Default = 0x0 @n
         *  Enable KEY_1_HDCP_ERR Interrupt.
         */
        uint32_t  key_1_hdcp_err               : 1;

        /*!
         *  Range = 18 | Width = 1 | Access = read-write | Default = 0x0 @n
         *  Enable KEY_1_DPA_RANDOM_UNSEEDED Interrupt.
         */
        uint32_t  key_1_dpa_random_unseeded    : 1;

        /*!
         *  Range = 31:19 | Width = 13 | Access = read-as-zero | Default = 0x0
         *  @n
         *  Reserved
         */
        uint32_t  rsvd0                        : 13;
    };
} aes_blk_int_enable_t;

typedef union
{
    uint32_t      raw;
    struct
    {
        /*!
         *  Range = 6:0 | Width = 7 | Access = read-write | Default = 0x0 @n
         *  Command FIFO Level below which the COMMAND_FIFO_LOW interrupt will
         *  be asserted
         */
        uint32_t  command_fifo_low  : 7;

        /*!
         *  Range = 31:7 | Width = 25 | Access = read-as-zero | Default = 0x0 @n
         *  Reserved
         */
        uint32_t  rsvd0             : 25;
    };
} aes_blk_watermarks_t;

typedef union
{
    uint32_t      raw;
    struct
    {
        /*!
         *  Range = 0 | Width = 1 | Access = read-only | Default = 0x0 @n
         *  Command FIFO has gone below Low Watermark
         */
        uint32_t  low            : 1;

        /*!
         *  Range = 1 | Width = 1 | Access = read-only | Default = 0x1 @n
         *  Command FIFO is empty
         */
        uint32_t  empty          : 1;

        /*!
         *  Range = 2 | Width = 1 | Access = read-only | Default = 0x0 @n
         *  Command FIFO is full
         */
        uint32_t  full           : 1;

        /*!
         *  Range = 3 | Width = 1 | Access = read-only | Default = 0x0 @n
         *  Software overflowed Command FIFO. This bit is not sticky
         */
        uint32_t  overflow       : 1;

        /*!
         *  Range = 7:4 | Width = 4 | Access = read-as-zero | Default = 0x0 @n
         *  Reserved
         */
        uint32_t  rsvd0          : 4;

        /*!
         *  Range = 15:8 | Width = 8 | Access = read-only | Default = 0x0 @n
         *  Number of 4 byte words in the Command FIFO
         */
        uint32_t  level          : 8;

        /*!
         *  Range = 22:16 | Width = 7 | Access = read-only | Default = 0x0 @n
         *  Pointer to next command
         */
        uint32_t  read_pointer   : 7;

        /*!
         *  Range = 23 | Width = 1 | Access = read-as-zero | Default = 0x0 @n
         *  Reserved
         */
        uint32_t  rsvd1          : 1;

        /*!
         *  Range = 30:24 | Width = 7 | Access = read-only | Default = 0x0 @n
         *  Pointer to next empty location
         */
        uint32_t  write_pointer  : 7;

        /*!
         *  Range = 31 | Width = 1 | Access = read-as-zero | Default = 0x0 @n
         *  Reserved
         */
        uint32_t  rsvd2          : 1;
    };
} aes_blk_command_fifo_status_t;

typedef union
{
    uint32_t      raw;
    struct
    {
        /*!
         *  Range = 31:0 | Width = 32 | Access = read-only | Default = 0x0 @n
         *  Number of commands popped from the Command FIFO since it was last
         *  turned on. (saturates at max)
         */
        uint32_t  total  : 32;
    };
} aes_blk_command_fifo_count_t;

typedef union
{
    uint32_t      raw;
    struct
    {
        /*!
         *  Range = 15:0 | Width = 16 | Access = read-only | Default = 0x0 @n
         *  Interrupt code from the last flag command executed in the Command
         *  FIFO
         */
        uint16_t  code;

        /*!
         *  Range = 31:16 | Width = 16 | Access = read-as-zero | Default = 0x0
         *  @n
         *  Reserved
         */
        uint16_t  rsvd0;
    };
} aes_blk_flag_command_t;

typedef union
{
    uint32_t      raw;
    struct
    {
        /*!
         *  Range = 31:0 | Width = 32 | Access = read-only | Default = 0x0 @n
         *  Count
         */
        uint32_t  count  : 32;
    };
} aes_blk_skg_key_t;

typedef union {
    #define AES_BLK_REG_SIZE (0x204)
    uint32_t raw[AES_BLK_REG_SIZE / sizeof(uint32_t)];
    struct {
        /*!
         *  Offset = 0x0 @n
         *  IP Implementation Version
         */
        aes_blk_version_t version;

        /*!
         *  Offset = 0x4 @n
         *  Configuration register
         */
        aes_blk_config_t config;

        /*!
         *  Offset = 0x8 @n
         *  Control Register
         */
        aes_blk_control_t control;

        /*!
         *  Offset = 0xc @n
         *  Channel status register
         */
        aes_blk_status_t status;

        /*!
         *  Offset = 0x10 @n
         *  Current Key IDs
         */
        aes_blk_key_id_t key_id;

        /*!
         *  Offset = 0x14 @n
         *  AXI status register
         */
        aes_blk_axi_status_t axi_status;

        /*!
         *  Offset = 0x18 @n
         *  Channel interrupt status register
         */
        aes_blk_int_status_t int_status;

        /*!
         *  Offset = 0x1c @n
         *  Channel interrupt enable register
         */
        aes_blk_int_enable_t int_enable;

        /*!
         *  Offset = 0x20 @n
         *  Watermarks for FIFO interrupts.
         */
        aes_blk_watermarks_t  watermarks;

        /*!
         *  Offset = 0x24 @n
         *  Status information for the Command Queue
         */
        aes_blk_command_fifo_status_t command_fifo_status;

        /*!
         *  Offset = 0x28 @n
         *  Status information for the DMA Debug FIFO
         */
        uint32_t history_fifo_status;

        /*!
         *  Offset = 0x2c @n
         *  Total count of commands since the Command FIFO was last enabled
         */
        aes_blk_command_fifo_count_t command_fifo_count;

        /*!
         *  Offset = 0x30 @n
         *  Interrupt code that provides information about the flag interrupt that
         *  occurred.
         */
        aes_blk_flag_command_t flag_command;

        /*!
         *  Offset = 0x34 @n
         *  Secure Key Generation Key
         */
        aes_blk_skg_key_t skg_key;

        /*!
         *  Offset = 0x38 @n
         *  Clear COMMAND and HISTORY FIFOs
         */
        uint32_t clear_fifos;
        uint8_t rsvd0[452];

        /*!
         *  Offset = 0x200 @n
         *  Command FIFO. FIFO Depth is (128) Words
         */
        uint32_t command_fifo;
    };
} aes_reg_t;

#pragma pack(pop)

#endif //HW_MISC_APPLE_AES_REG_H

