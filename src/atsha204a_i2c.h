#ifndef __ATSHA204A_I2C_H__
#define __ATSHA204A_I2C_H__


#include <linux/i2c.h>





extern int atsha204a_i2c_read( const struct i2c_client *i2c, u8 *buf, u8 len);
extern int atsha204a_i2c_write(const struct i2c_client *i2c, const u8 *buf, u8 len);




#endif
