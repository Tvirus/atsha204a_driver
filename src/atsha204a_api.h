#ifndef __ATSHA204A_API_H__
#define __ATSHA204A_API_H__


#include <linux/i2c.h>
#include "sha204.h"





extern int hex_dump_str(char *str, int str_len, const u8 *buf, int buf_len, u8 col);
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
extern int atsha204a_nonce(const struct i2c_client *i2c, u8 mode, const u8 *num_in, u8 *rand_out);
extern int atsha204a_mac(const struct i2c_client *i2c, u8 mode, u8 slot, const u8 *challenge, u8 len, u8 *mac);
extern int atsha204a_gendig(const struct i2c_client *i2c, u8 zone, u16 slot, const u8 *data, u8 len);
extern int atsha204a_verify_key(const struct i2c_client *i2c, const u8 *key, u8 slot);



#endif
