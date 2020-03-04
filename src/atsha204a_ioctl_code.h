#ifndef __ATSHA204A_IOCTL_CODE_H__
#define __ATSHA204A_IOCTL_CODE_H__


#include "atsha204a_api.h"




#define ATSHA204A_CMD_SN                   (0x10)       //读sn
#define ATSHA204A_CMD_OTP                  (0x11)       //读otp
#define ATSHA204A_CMD_NONCE                (0x12)       //nonce命令
#define ATSHA204A_CMD_MAC                  (0x13)       //mac命令

#define ATSHA204A_CMD_BURN_CONFIG          (0x30)       //写入并锁定config区
#define ATSHA204A_CMD_BURN_DEFCONFIG       (0x31)       //写入默认值并锁定config区
#define ATSHA204A_CMD_WRITE_KEY            (0x32)       //写入秘钥
#define ATSHA204A_CMD_WRITE_OTP            (0x33)       //写入OTP
#define ATSHA204A_CMD_LOCK_VALUE           (0x34)       //锁定data和otp
#define ATSHA204A_CMD_GENDIG               (0x35)       //生成摘要
#define ATSHA204A_CMD_WRITE_ENCRYPTED_KEY  (0x36)       //用加密写的方式写一个密钥







typedef struct {
    u8 sn[SHA204_SN_SIZE];
}atsha204a_cmd_sn_t;

typedef struct {
    u8 otp[SHA204_OTP_SIZE];
}atsha204a_cmd_otp_t;

typedef struct {
    u8 in_zone;
    u8 in_word_addr;
    u8 out_response[4];
}atsha204a_cmd_read_t;

typedef struct {
    u8 in_mode;
    u8 in_numin[NONCE_NUMIN_SIZE];
    u8 out_response[32];
}atsha204a_cmd_nonce_t;

typedef struct {
    u8 in_mode;
    u8 in_slot;
    u8 in_challenge_len;
    u8 in_challenge[MAC_CHALLENGE_SIZE];
    u8 out_response[32];
}atsha204a_cmd_mac_t;




typedef struct {
    u8 config[SHA204_WRITABLE_CONFIG_SIZE];
}atsha204a_cmd_burn_config_t;

typedef struct {
    u8 slot;
    u8 key[SHA204_KEY_SIZE];
    u8 digest[32];
}atsha204a_cmd_write_key_t;

typedef struct {
    u8  zone;
    u16 slot;
    u8  data_len;
    u8  data[SHA204_OTP_SIZE];
}atsha204a_cmd_gendig_t;



#endif
