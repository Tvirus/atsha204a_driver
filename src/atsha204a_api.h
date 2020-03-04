#ifndef __ATSHA204A_API_H__
#define __ATSHA204A_API_H__


#include <linux/i2c.h>
#include "atsha204a_i2c.h"




/* Definitions of Data and Packet Sizes */
#define SHA204_RSP_SIZE_VAL             ((uint8_t) 7)          //!< size of response packet containing four bytes of data
#define SHA204_KEY_SIZE                 (32)                   //!< size of key
#define SHA204_KEY_COUNT                (16)                   //!< number of keys
#define SHA204_CONFIG_SIZE              (88)                   //!< size of configuration zone
#define SHA204_OTP_SIZE                 (64)                   //!< size of OTP zone
#define SHA204_DATA_SIZE                (SHA204_KEY_COUNT * SHA204_KEY_SIZE) //!< size of data zone
#define SHA204_SN_SIZE                  (9) //!< size of data zone

#define NONCE_NUMIN_SIZE                (20)                   //!< Nonce data length
#define NONCE_NUMIN_SIZE_PASSTHROUGH    (32)                   //!< Nonce data length in pass-through mode (mode = 3)

#define MAC_CHALLENGE_SIZE              (32)                   //!< MAC size of challenge

#define SHA204_WRITABLE_CONFIG_SIZE     (68)                   //可写的config区大小


extern int hex_dump_str(char *str, int str_len, u8 *buf, int buf_len, u8 col);
extern int atsha204a_read_sn(const struct i2c_client *i2c, u8 *sn);
extern int atsha204a_read_otp(const struct i2c_client *i2c, u8 *otp);
extern int atsha204a_read_config(const struct i2c_client *i2c, u8 *config);
extern int atsha204a_parse_config(const struct i2c_client *i2c, u8 *str, int len);
extern int atsha204a_read_key(const struct i2c_client *i2c, u8 *key, u8 slot);
extern int atsha204a_write_key(const struct i2c_client *i2c, const u8 *key, u8 slot);
extern int atsha204a_write_encrypted_key(const struct i2c_client *i2c, const u8 *key, u8 slot, u8 *digest);
extern int atsha204a_write_config(const struct i2c_client *i2c, const u8 *config);
extern int atsha204a_write_defconfig(const struct i2c_client *i2c);
extern int atsha204a_write_otp(const struct i2c_client *i2c, const u8 *otp);
extern int atsha204a_lock_config(const struct i2c_client *i2c);
extern int atsha204a_lock_value(const struct i2c_client *i2c);
extern int atsha204a_nonce(const struct i2c_client *i2c, u8 mode, const u8 *in, u8 *out);
extern int atsha204a_mac(const struct i2c_client *i2c, u8 mode, u8 slot, const u8 *challenge, u8 len, u8 *mac);
extern int atsha204a_gendig(const struct i2c_client *i2c, u8 zone, u16 slot, const u8 *data, u8 len);




#endif
