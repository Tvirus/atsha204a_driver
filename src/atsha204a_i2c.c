#include "atsha204a_i2c.h"
#include <linux/i2c.h>
#include <linux/delay.h>



extern u8 atsha204a_debug;




/* i2c速度配置为100k时可以发送一个0字节来唤醒 */
void atsha204a_wakeup(const struct i2c_client *i2c)
{
    struct i2c_msg msg;

    msg.addr  = 0;
    msg.flags = i2c->flags;
    msg.buf   = NULL;
    msg.len   = 0;
    i2c_transfer(i2c->adapter, &msg, 1);

    mdelay(3);
}

int atsha204a_i2c_write(const struct i2c_client *i2c, const u8 *buf, u8 len)
{
    struct i2c_msg msg;
    int i;


    if(NULL == buf)
        return -EFAULT;

    if (atsha204a_debug)
    {
        printk("atsha204a i2c write data(%u):\n", len);
        for(i = 0; i < len; i++)
            printk("%02x  ", buf[i]);
        printk("\n");
    }

    msg.addr  = i2c->addr;
    msg.flags = i2c->flags;
    msg.len   = len;
    msg.buf   = (char *)buf;
    return i2c_transfer(i2c->adapter, &msg, 1);
}

int atsha204a_i2c_read(const struct i2c_client *i2c, u8 *buf, u8 len)
{
    char cmd = 0;
    int i;
    struct i2c_msg msg[2];


    msg[0].addr  = i2c->addr;
    msg[0].flags = i2c->flags;
    msg[0].len = 1;
    msg[0].buf = &cmd;

    msg[1].addr  = i2c->addr;
    msg[1].flags = i2c->flags | I2C_M_RD;
    msg[1].len = len;
    msg[1].buf = (char *)buf;
    if (2 != i2c_transfer(i2c->adapter, msg, sizeof(msg) / sizeof(struct i2c_msg)))
        return -1;

    if (atsha204a_debug)
    {
        printk("atsha204a i2c read data(%u):\n", len);
        for(i = 0; i < len; i++){
            printk("%02x  ", buf[i]);
        }
        printk("\n");
    }

    return 0; 
}
