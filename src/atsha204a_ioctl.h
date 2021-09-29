#ifndef __ATSHA204A_IOCTL_H__
#define __ATSHA204A_IOCTL_H__


#include <linux/types.h>
#include "sha204.h"




#define ATSHA204A_CMD_READ_SN              (0x10)       //读sn
#define ATSHA204A_CMD_READ_OTP             (0x11)       //读otp
#define ATSHA204A_CMD_NONCE                (0x12)       //NONCE命令
#define ATSHA204A_CMD_MAC                  (0x13)       //MAC命令

#define ATSHA204A_CMD_BURN_CONFIG          (0x30)       //写入并锁定config区
#define ATSHA204A_CMD_BURN_DEFCONFIG       (0x31)       //写入默认值并锁定config区
#define ATSHA204A_CMD_WRITE_KEY            (0x32)       //写入秘钥
#define ATSHA204A_CMD_WRITE_OTP            (0x33)       //写入otp
#define ATSHA204A_CMD_LOCK_VALUE           (0x34)       //锁定data和otp
#define ATSHA204A_CMD_GENDIG               (0x35)       //生成摘要
#define ATSHA204A_CMD_WRITE_ENCRYPTED_KEY  (0x36)       //用加密写的方式写一个密钥

#define ATSHA204A_CMD_VERIFY_KEY           (0x50)       //验证秘钥是否烧录成功





/* 读sn */
typedef struct {
    uint8_t sn[SHA204_SN_SIZE];
}atsha204a_cmd_sn_t;

/* 读写otp */
typedef struct {
    uint8_t otp[SHA204_OTP_SIZE];
}atsha204a_cmd_otp_t;

typedef struct {
    uint8_t in_mode;
    uint8_t in_numin[NONCE_NUMIN_SIZE];
    uint8_t out_randout[NONCE_RANDOUT_SIZE];
}atsha204a_cmd_nonce_t;

typedef struct {
    uint8_t in_mode;
    uint8_t in_slot;
    uint8_t in_challenge_len;
    uint8_t in_challenge[MAC_CHALLENGE_SIZE];
    uint8_t out_digest[MAC_DIGEST_SIZE];
}atsha204a_cmd_mac_t;




typedef struct {
    uint8_t config[SHA204_WRITABLE_CONFIG_SIZE];
}atsha204a_cmd_burn_config_t;

typedef struct {
    uint8_t slot;
    uint8_t key[SHA204_KEY_SIZE];
    uint8_t digest[WRITE_MAC_SIZE];
}atsha204a_cmd_write_key_t;

typedef struct {
    uint8_t  zone;
    uint16_t slot;
    uint8_t  data_len;
    uint8_t  data[GENDIG_OTHER_DATA_SIZE];
}atsha204a_cmd_gendig_t;




typedef struct {
    uint8_t slot;
    uint8_t key[SHA204_KEY_SIZE];
}atsha204a_cmd_verify_key_t;


#endif
