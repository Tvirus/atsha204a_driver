#include "atsha204a_api.h"
#include <linux/delay.h>
#include <linux/slab.h>
#include <linux/random.h>

#include "atsha204a_i2c.h"
#include "sha204_helper.h"




#define ERROR(fmt, arg...)  printk(KERN_ERR "--atsha204a-- " fmt "\n", ##arg)


typedef struct
{
    u8 addr;   /* 字地址值,command对应0x03 */
    u8 count;
    u8 opcode;
    u8 param1;
    u8 param2[2];
    u8 data[0];
}atsha204a_cmd_t;




u8 defconfig[SHA204_WRITABLE_CONFIG_SIZE] =
{
    0xc9, 0x00, 0xaa, 0x00,  //I2C_Addr  CheckMacConfig  OTP_Mode  SelectorMode

    0x80, 0x00, 0x80, 0x00,  //SlotConfig  0  1
    0x80, 0x00, 0x80, 0x00,  //SlotConfig  2  3
    0x80, 0x00, 0x80, 0x00,  //SlotConfig  4  5
    0x80, 0x00, 0x80, 0x00,  //SlotConfig  6  7
    0x80, 0x00, 0x80, 0x00,  //SlotConfig  8  9
    0x80, 0x00, 0x80, 0x00,  //SlotConfig 10 11
    0x80, 0x00, 0x80, 0x00,  //SlotConfig 12 13
    0x80, 0x00, 0x80, 0x00,  //SlotConfig 14 15

    0xff, 0x00, 0xff, 0x00,  //UseFlag UpdateCount 0 1
    0xff, 0x00, 0xff, 0x00,  //UseFlag UpdateCount 2 3
    0xff, 0x00, 0xff, 0x00,  //UseFlag UpdateCount 4 5
    0xff, 0x00, 0xff, 0x00,  //UseFlag UpdateCount 6 7

    0xff, 0xff, 0xff, 0xff,  //LastKeyUse  0 - 3
    0xff, 0xff, 0xff, 0xff,  //LastKeyUse  4 - 7
    0xff, 0xff, 0xff, 0xff,  //LastKeyUse  8 -11
    0xff, 0xff, 0xff, 0xff   //LastKeyUse 12 -15
};




/* 返回成功写入的长度，包括最后的'\0' */
int hex_dump_str(char *str, int str_len, const u8 *buf, int buf_len, u8 col)
{
    u32 i;
    int ret;
    int index = 0;


    if ((NULL == str) || (NULL == buf) || (0 >= str_len) || (0 >= buf_len))
        return -1;

    for (i = 0; i < buf_len; i++)
    {
        if (col && (0 == ((i + 1) % col)))
            ret = snprintf(str + index, str_len, "%02x\n", buf[i]);
        else
            ret = snprintf(str + index, str_len, "%02x ", buf[i]);

        if ((0 > ret) || (ret >= str_len))
            return -1;
        str_len -= ret;
        index += ret;
    }

    if (' ' == (*(str + index - 1)))
        *(str + index - 1) = '\n';
    return index + 1;
}







/** \brief Calculates CRC over the given raw data and returns the CRC in
 *         little-endian byte order.
 *
 * \param[in]  length  Size of data not including the CRC byte positions
 * \param[in]  data    Pointer to the data over which to compute the CRC
 * \param[out] crc_le  Pointer to the place where the two-bytes of CRC will be
 *                     returned in little-endian byte order.
 */
void atsha204a_crc(size_t length, const u8 *data, u8 *crc_le)
{
    size_t counter;
    u16 crc_register = 0;
    u16 polynom = 0x8005;
    u8 shift_register;
    u8 data_bit, crc_bit;

    for (counter = 0; counter < length; counter++)
    {
        for (shift_register = 0x01; shift_register > 0x00; shift_register <<= 1)
        {
            data_bit = (data[counter] & shift_register) ? 1 : 0;
            crc_bit = crc_register >> 15;
            crc_register <<= 1;
            if (data_bit != crc_bit)
            {
                crc_register ^= polynom;
            }
        }
    }
    crc_le[0] = (u8)(crc_register & 0x00FF);
    crc_le[1] = (u8)(crc_register >> 8);
}
/** \brief This function calculates CRC and adds it to the correct offset in the packet data
 * \param[in] packet Packet to calculate CRC data for
 */
/* block结构：count(1),data(n),CRC(2) */
static int atsha204a_calc_block_crc(u8 *block)
{
    if (4 > block[SHA204_BUFFER_POS_COUNT])
        return -1;

    atsha204a_crc(block[SHA204_BUFFER_POS_COUNT] - SHA204_CRC_SIZE, block,
                    block + block[SHA204_BUFFER_POS_COUNT] - SHA204_CRC_SIZE);
    return 0;
}
/** \brief This function checks the consistency of a response.
 * \param[in] response pointer to response
 * \return ATCA_SUCCESS on success, otherwise ATCA_RX_CRC_ERROR
 */
int atsha204a_check_block_crc(const u8 *response, u32 len)
{
    u8 crc[SHA204_CRC_SIZE];

    if ((len != response[SHA204_BUFFER_POS_COUNT]) || (SHA204_RSP_SIZE_MIN > len))
        return -1;

    atsha204a_crc(len - SHA204_CRC_SIZE, response, crc);

    if (memcmp(crc, &response[len - SHA204_CRC_SIZE], SHA204_CRC_SIZE))
        return -1;
    else
        return 0;
}




void atsha204a_reset(const struct i2c_client *i2c)
{
    u8 v = SHA204_PACKET_FUNC_RESET;
    atsha204a_i2c_write(i2c, &v, 1);
}
void atsha204a_go_sleep(const struct i2c_client *i2c)
{
    u8 v = SHA204_PACKET_FUNC_SLEEP;
    atsha204a_i2c_write(i2c, &v, 1);
}
void atsha204a_rewakeup(const struct i2c_client *i2c)
{
    atsha204a_go_sleep(i2c);
    atsha204a_wakeup(i2c);
}
void atsha204a_set_idle(const struct i2c_client *i2c)
{
    u8 v = SHA204_PACKET_FUNC_IDLE;
    atsha204a_i2c_write(i2c, &v, 1);
}

static int atsha204a_send_command(const struct i2c_client *i2c, u8 opcode, u8 param1, const u8 *param2, const u8 *data, u8 data_len)
{
    u8 buf[100];
    atsha204a_cmd_t *cmd = (atsha204a_cmd_t *)buf;


    if (sizeof(buf) < (sizeof(atsha204a_cmd_t) + data_len + SHA204_CRC_SIZE))
        return -1;

    cmd->addr      = SHA204_PACKET_FUNC_CMD;
    cmd->count     = sizeof(atsha204a_cmd_t) + data_len + SHA204_CRC_SIZE - 1;
    cmd->opcode    = opcode;
    cmd->param1    = param1;
    cmd->param2[0] = param2[0];
    cmd->param2[1] = param2[1];
    memcpy(cmd->data, data, data_len);
    atsha204a_calc_block_crc(((u8 *)cmd) + 1);
    if (0 > atsha204a_i2c_write(i2c, (u8 *)cmd, sizeof(atsha204a_cmd_t) + data_len + SHA204_CRC_SIZE))
        return -1;

    return 0;
}
static int atsha204a_read_response(const struct i2c_client *i2c, u8 *res, u8 len)
{
    if (0 > atsha204a_i2c_read(i2c, res, len))
        return -1;
    if (atsha204a_check_block_crc(res, len))
        return -1;
    return (int)res[0];
}



int atsha204a_pause(const struct i2c_client *i2c, u8 selector)
{
    u8 param2[2];

    param2[0] = param2[1] = 0;
    atsha204a_send_command(i2c, SHA204_PAUSE, selector, param2, NULL, 0);
    msleep(PAUSE_EXEC_MAX);

    return 0;
}

int atsha204a_read_sn(const struct i2c_client *i2c, u8 *sn)
{
    u8 param2[2];
    u8 res[READ_32_RSP_SIZE] = {0};


    atsha204a_rewakeup(i2c);

    param2[0] = param2[1] = 0;
    atsha204a_send_command(i2c, SHA204_READ, SHA204_ZONE_COUNT_FLAG | SHA204_ZONE_CONFIG, param2, NULL, 0);
    msleep(READ_EXEC_MAX);
    if (   (0 > atsha204a_read_response(i2c, res, READ_32_RSP_SIZE))
        || (READ_32_RSP_SIZE != res[SHA204_BUFFER_POS_COUNT]))
    {
        ERROR("read sn failed !");
        return -1;
    }
    memcpy(sn,     res + 1, 4);
    memcpy(sn + 4, res + 9, 5);

    atsha204a_go_sleep(i2c);

    return 0;
}

int atsha204a_read_devrev(const struct i2c_client *i2c, u8 *rev)
{
    u8 param2[2];
    u8 res[DEVREV_RSP_SIZE] = {0};


    atsha204a_rewakeup(i2c);

    param2[0] = param2[1] = 0;
    atsha204a_send_command(i2c, SHA204_DEVREV, 0, param2, NULL, 0);
    msleep(DEVREV_EXEC_MAX);
    if (   (0 > atsha204a_read_response(i2c, res, DEVREV_RSP_SIZE))
        || (DEVREV_RSP_SIZE != res[SHA204_BUFFER_POS_COUNT]))
    {
        ERROR("read device revision number failed !");
        return -1;
    }
    memcpy(rev, &res[SHA204_BUFFER_POS_DATA], SHA204_DEVREV_SIZE);

    atsha204a_go_sleep(i2c);

    return 0;
}

int atsha204a_read_otp(const struct i2c_client *i2c, u8 *otp)
{
    u8 param2[2];
    u8 res[READ_32_RSP_SIZE] = {0};
    int i;


    atsha204a_rewakeup(i2c);

    param2[0] = param2[1] = 0;
    for (i = 0; i < 2; i++)
    {
        atsha204a_send_command(i2c, SHA204_READ, SHA204_ZONE_COUNT_FLAG | SHA204_ZONE_OTP, param2, NULL, 0);
        msleep(READ_EXEC_MAX);
        if (   (0 > atsha204a_read_response(i2c, res, READ_32_RSP_SIZE))
            || (READ_32_RSP_SIZE != res[SHA204_BUFFER_POS_COUNT]))
        {
            ERROR("read otp failed !");
            return -1;
        }
        memcpy(otp, &res[SHA204_BUFFER_POS_DATA], 32);
        otp += 32;
        param2[0] = 0x08;
        res[SHA204_BUFFER_POS_COUNT] = 0;
    }

    atsha204a_go_sleep(i2c);

    return 0;
}

int atsha204a_read_config(const struct i2c_client *i2c, u8 *config)
{
    u8 param2[2];
    u8 res[READ_32_RSP_SIZE] = {0};
    int i;


    atsha204a_rewakeup(i2c);

    /* 读两个32字节 */
    param2[0] = param2[1] = 0;
    for (i = 0; i < 2; i++)
    {
        atsha204a_send_command(i2c, SHA204_READ, SHA204_ZONE_COUNT_FLAG | SHA204_ZONE_CONFIG, param2, NULL, 0);
        msleep(READ_EXEC_MAX);
        if (   (0 > atsha204a_read_response(i2c, res, READ_32_RSP_SIZE))
            || (READ_32_RSP_SIZE != res[SHA204_BUFFER_POS_COUNT]))
        {
            ERROR("read config failed !");
            return -1;
        }
        memcpy(config, &res[SHA204_BUFFER_POS_DATA], 32);
        config += 32;
        param2[0] = 0x08;
        res[SHA204_BUFFER_POS_COUNT] = 0;
    }

    /* 读6个4字节 */
    param2[0] = 0x10;
    param2[1] = 0;
    for (i = 0; i < 6; i++)
    {
        atsha204a_send_command(i2c, SHA204_READ, SHA204_ZONE_CONFIG, param2, NULL, 0);
        msleep(READ_EXEC_MAX);
        if (   (0 > atsha204a_read_response(i2c, res, READ_4_RSP_SIZE))
            || (READ_4_RSP_SIZE != res[SHA204_BUFFER_POS_COUNT]))
        {
            ERROR("read config failed !");
            return -1;
        }
        memcpy(config, &res[SHA204_BUFFER_POS_DATA], 4);
        config += 4;
        param2[0] += 1;
        res[SHA204_BUFFER_POS_COUNT] = 0;
    }

    atsha204a_go_sleep(i2c);

    return 0;
}

/* 读数据区中的一个key(32字节) */
int atsha204a_read_key(const struct i2c_client *i2c, u8 *key, u8 slot)
{
    u8 param2[2];
    u8 res[READ_32_RSP_SIZE] = {0};


    if (SHA204_KEY_COUNT <= slot)
        return -1;

    atsha204a_rewakeup(i2c);

    param2[0] = 0x08 * slot;
    param2[1] = 0;
    atsha204a_send_command(i2c, SHA204_READ, SHA204_ZONE_COUNT_FLAG | SHA204_ZONE_DATA, param2, NULL, 0);
    msleep(READ_EXEC_MAX);
    if (   (0 > atsha204a_read_response(i2c, res, READ_32_RSP_SIZE))
        || (READ_32_RSP_SIZE != res[SHA204_BUFFER_POS_COUNT]))
    {
        ERROR("read key(%u) failed !", slot);
        return -1;
    }
    memcpy(key, &res[SHA204_BUFFER_POS_DATA], SHA204_KEY_SIZE);

    atsha204a_go_sleep(i2c);

    return 0;
}
/* 写数据区中的一个key(32字节) */
int atsha204a_write_key(const struct i2c_client *i2c, const u8 *key, u8 slot)
{
    u8 param2[2];
    u8 res[WRITE_RSP_SIZE] = {0};


    if (SHA204_KEY_COUNT <= slot)
        return -1;

    atsha204a_rewakeup(i2c);

    param2[0] = 0x08 * slot;
    param2[1] = 0;
    atsha204a_send_command(i2c, SHA204_WRITE, SHA204_ZONE_COUNT_FLAG | SHA204_ZONE_DATA, param2, key, SHA204_KEY_SIZE);
    msleep(WRITE_EXEC_MAX);
    if (   (0 > atsha204a_read_response(i2c, res, WRITE_RSP_SIZE))
        || (WRITE_RSP_SIZE != res[SHA204_BUFFER_POS_COUNT]))
    {
        ERROR("write key(%u) failed !", slot);
        return -1;
    }
    if (0 != res[SHA204_BUFFER_POS_DATA])
    {
        ERROR("write key(%u) failed(0x%02x) !", slot, res[SHA204_BUFFER_POS_DATA]);
        return -1;
    }

    atsha204a_go_sleep(i2c);

    return 0;
}
/* 用加密写的方式写一个密钥 */
int atsha204a_write_encrypted_key(const struct i2c_client *i2c, const u8 *key, u8 slot, u8 *digest)
{
    u8 param2[2];
    u8 res[WRITE_RSP_SIZE] = {0};
    u8 data[SHA204_KEY_SIZE + WRITE_MAC_SIZE] = {0};


    if (SHA204_KEY_COUNT <= slot)
        return -1;

    /* 仅唤醒，恢复上一步nonce中的TempKey等相关值 */
    atsha204a_wakeup(i2c);

    param2[0] = 0x08 * slot;
    param2[1] = 0;
    memcpy(data, key, SHA204_KEY_SIZE);
    memcpy(data + SHA204_KEY_SIZE, digest, WRITE_MAC_SIZE);
    atsha204a_send_command(i2c, SHA204_WRITE, SHA204_ZONE_COUNT_FLAG | SHA204_ZONE_DATA, param2, data, sizeof(data));
    msleep(WRITE_EXEC_MAX);
    if (   (0 > atsha204a_read_response(i2c, res, WRITE_RSP_SIZE))
        || (WRITE_RSP_SIZE != res[SHA204_BUFFER_POS_COUNT]))
    {
        ERROR("write encrypted key(%u) failed !", slot);
        return -1;
    }
    if (0 != res[SHA204_BUFFER_POS_DATA])
    {
        ERROR("write encrypted key(%u) failed(0x%02x) !", slot, res[SHA204_BUFFER_POS_DATA]);
        return -1;
    }

    atsha204a_go_sleep(i2c);

    return 0;
}

/* 输出带注解的config区数据 */
int atsha204a_parse_config(const struct i2c_client *i2c, u8 *str, int len)
{
    u8 config[SHA204_CONFIG_SIZE];
    int index = 0;
    int ret;


    if (0 > atsha204a_read_config(i2c, config))
        return -1;

    ret = snprintf(str, len, "SN:\n");
    if ((0 > ret) || (len <= ret))
        return -1;
    index += ret;
    len -= ret;

    ret = hex_dump_str(str + index, len, config, 20, 4);
    if ((0 > ret) || (len < ret))
        return -1;
    index += ret - 1;
    len -= ret - 1;


    ret = snprintf(str + index, len, "\nSlotConfig:\n");
    if ((0 > ret) || (len <= ret))
        return -1;
    index += ret;
    len -= ret;

    ret = hex_dump_str(str + index, len, config + 20, 32, 4);
    if ((0 > ret) || (len < ret))
        return -1;
    index += ret - 1;
    len -= ret - 1;


    ret = snprintf(str + index, len, "\nUseFlag:\n");
    if ((0 > ret) || (len <= ret))
        return -1;
    index += ret;
    len -= ret;

    ret = hex_dump_str(str + index, len, config + 52, 16, 4);
    if ((0 > ret) || (len < ret))
        return -1;
    index += ret - 1;
    len -= ret - 1;


    ret = snprintf(str + index, len, "\nLastKeyUse:\n");
    if ((0 > ret) || (len <= ret))
        return -1;
    index += ret;
    len -= ret;

    ret = hex_dump_str(str + index, len, config + 68, 16, 4);
    if ((0 > ret) || (len < ret))
        return -1;
    index += ret - 1;
    len -= ret - 1;


    ret = snprintf(str + index, len, "\nLock:\n");
    if ((0 > ret) || (len <= ret))
        return -1;
    index += ret;
    len -= ret;

    ret = hex_dump_str(str + index, len, config + 84, 4, 4);
    if ((0 > ret) || (len < ret))
        return -1;
    index += ret - 1;
    len -= ret - 1;

    return index + 1;
}


/* 输入的config参数是要写入的从I2C_Addr(字0x04)开始的68字节配置 */
int atsha204a_write_config(const struct i2c_client *i2c, const u8 *config)
{
    u8 param2[2];
    u8 res[WRITE_RSP_SIZE] = {0};
    int i;


    atsha204a_rewakeup(i2c);

    /* 4字节写，写17次 */
    param2[0] = 4; /* 从第4字(偏移16字节)开始写 */
    param2[1] = 0;
    for (i = 0; i < 17; i++)
    {
        atsha204a_send_command(i2c, SHA204_WRITE, SHA204_ZONE_CONFIG, param2, config, 4);
        msleep(WRITE_EXEC_MAX);
        if (   (0 > atsha204a_read_response(i2c, res, WRITE_RSP_SIZE))
            || (WRITE_RSP_SIZE != res[SHA204_BUFFER_POS_COUNT]))
        {
            ERROR("write config failed !");
            return -1;
        }
        if (0 != res[SHA204_BUFFER_POS_DATA])
        {
            ERROR("write config failed(0x%02x) !", res[SHA204_BUFFER_POS_DATA]);
            return -1;
        }
        config += 4;
        param2[0]++;
        res[SHA204_BUFFER_POS_COUNT] = 0;

        if (8 == i)
            atsha204a_rewakeup(i2c);
    }

    atsha204a_go_sleep(i2c);

    return 0;
}
/* 写入默认的68字节配置 */
int atsha204a_write_defconfig(const struct i2c_client *i2c)
{
    return atsha204a_write_config(i2c, defconfig);
}

int atsha204a_write_otp(const struct i2c_client *i2c, const u8 *otp)
{
    u8 param2[2];
    u8 res[WRITE_RSP_SIZE] = {0};
    int i;


    atsha204a_rewakeup(i2c);

    param2[0] = param2[1] = 0;
    for (i = 0; i < 2; i++)
    {
        atsha204a_send_command(i2c, SHA204_WRITE, SHA204_ZONE_COUNT_FLAG | SHA204_ZONE_OTP, param2, otp, 32);
        msleep(WRITE_EXEC_MAX);
        if (   (0 > atsha204a_read_response(i2c, res, WRITE_RSP_SIZE))
            || (WRITE_RSP_SIZE != res[SHA204_BUFFER_POS_COUNT]))
        {
            ERROR("write otp failed !");
            return -1;
        }
        if (0 != res[SHA204_BUFFER_POS_DATA])
        {
            ERROR("write otp failed(0x%02x) !",res[SHA204_BUFFER_POS_DATA]);
            return -1;
        }
        otp += 32;
        param2[0] = 0x08;
        res[SHA204_BUFFER_POS_COUNT] = 0;
    }

    atsha204a_go_sleep(i2c);

    return 0;
}


int atsha204a_lock_config(const struct i2c_client *i2c)
{
    u8 param2[2];
    u8 res[LOCK_RSP_SIZE] = {0};


    atsha204a_rewakeup(i2c);

    param2[0] = param2[1] = 0;
    atsha204a_send_command(i2c, SHA204_LOCK, LOCK_ZONE_NO_CRC, param2, NULL, 0);
    msleep(LOCK_EXEC_MAX);
    if (   (0 > atsha204a_read_response(i2c, res, LOCK_RSP_SIZE))
        || (LOCK_RSP_SIZE != res[SHA204_BUFFER_POS_COUNT]))
    {
        ERROR("lock config failed !");
        return -1;
    }
    if (0 != res[SHA204_BUFFER_POS_DATA])
    {
        ERROR("lock config failed(0x%02x) !", res[SHA204_BUFFER_POS_DATA]);
        return -1;
    }

    atsha204a_go_sleep(i2c);

    return 0;
}
int atsha204a_lock_value(const struct i2c_client *i2c)
{
    u8 param2[2];
    u8 res[LOCK_RSP_SIZE] = {0};


    atsha204a_rewakeup(i2c);

    param2[0] = param2[1] = 0;
    atsha204a_send_command(i2c, SHA204_LOCK, LOCK_ZONE_NO_CRC | LOCK_ZONE_NO_CONFIG, param2, NULL, 0);
    msleep(LOCK_EXEC_MAX);
    if (   (0 > atsha204a_read_response(i2c, res, LOCK_RSP_SIZE))
        || (LOCK_RSP_SIZE != res[SHA204_BUFFER_POS_COUNT]))
    {
        ERROR("lock value failed !");
        return -1;
    }
    if (0 != res[SHA204_BUFFER_POS_DATA])
    {
        ERROR("lock value failed(0x%02x) !", res[SHA204_BUFFER_POS_DATA]);
        return -1;
    }

    atsha204a_go_sleep(i2c);

    return 0;
}

/* 输入20/32字节，输出32字节随机数 */
int atsha204a_nonce(const struct i2c_client *i2c, u8 mode, const u8 *num_in, u8 *rand_out)
{
    u8 param2[2];
    u8 res[NONCE_RSP_SIZE_LONG] = {0};


    atsha204a_rewakeup(i2c);

    if ((NONCE_MODE_SEED_UPDATE == mode) || (NONCE_MODE_NO_SEED_UPDATE == mode))
    {
        param2[0] = param2[1] = 0;
        atsha204a_send_command(i2c, SHA204_NONCE, mode, param2, num_in, NONCE_NUMIN_SIZE);
        msleep(NONCE_EXEC_MAX);
        if (   (0 > atsha204a_read_response(i2c, res, NONCE_RSP_SIZE_LONG))
            || (NONCE_RSP_SIZE_LONG != res[SHA204_BUFFER_POS_COUNT]))
        {
            ERROR("execute nonce cmd failed !");
            return -1;
        }
        memcpy(rand_out, &res[SHA204_BUFFER_POS_DATA], NONCE_RANDOUT_SIZE);
    }
    else
    {
        param2[0] = param2[1] = 0;
        atsha204a_send_command(i2c, SHA204_NONCE, mode, param2, num_in, NONCE_NUMIN_SIZE_PASSTHROUGH);
        msleep(NONCE_EXEC_MAX);
        if (   (0 > atsha204a_read_response(i2c, res, NONCE_RSP_SIZE_SHORT))
            || (NONCE_RSP_SIZE_SHORT != res[SHA204_BUFFER_POS_COUNT]))
        {
            ERROR("execute passthrough nonce cmd failed !");
            return -1;
        }
        if (0 != res[SHA204_BUFFER_POS_DATA])
        {
            ERROR("execute passthrough nonce cmd failed(0x%02x) !", res[SHA204_BUFFER_POS_DATA]);
            return -1;
        }
    }

    /* 这里必须idle，保留TempKey和RNG Seed寄存器的值，让接下来的mac等指令正确执行 */
    atsha204a_set_idle(i2c);

    return 0;
}

/* 芯片计算mac时需要用到mode和slot */
int atsha204a_mac(const struct i2c_client *i2c, u8 mode, u8 slot, const u8 *challenge, u8 len, u8 *mac)
{
    u8 param2[2];
    u8 res[MAC_RSP_SIZE] = {0};


    if (SHA204_KEY_COUNT <= slot)
        return -1;
    if ((0 != len) && (MAC_CHALLENGE_SIZE != len))
        return -1;

    /* 仅唤醒，恢复上一步nonce中的TempKey等相关值 */
    atsha204a_wakeup(i2c);

    param2[0] = slot;
    param2[1] = 0;
    atsha204a_send_command(i2c, SHA204_MAC, mode, param2, challenge, len);
    msleep(MAC_EXEC_MAX);
    if (   (0 > atsha204a_read_response(i2c, res, MAC_RSP_SIZE))
        || (MAC_RSP_SIZE != res[SHA204_BUFFER_POS_COUNT]))
    {
        ERROR("execute mac cmd failed !");
        return -1;
    }
    memcpy(mac, &res[SHA204_BUFFER_POS_DATA], MAC_DIGEST_SIZE);

    atsha204a_go_sleep(i2c);

    return 0;
}

/* 仅针对用data区密钥产生摘要的情况 */
int atsha204a_gendig(const struct i2c_client *i2c, u8 zone, u16 slot, const u8 *data, u8 len)
{
    u8 param2[2];
    u8 res[GENDIG_RSP_SIZE] = {0};


    if ((SHA204_ZONE_CONFIG != zone) && (SHA204_ZONE_OTP != zone) && (SHA204_ZONE_DATA != zone))
        return -1;
    if ((0 != len) && (GENDIG_OTHER_DATA_SIZE != len))
        return -1;

    /* 仅唤醒，恢复上一步nonce中的TempKey等相关值 */
    atsha204a_wakeup(i2c);

    param2[0] =  slot & 0xff;
    param2[1] = (slot & 0xff00) >> 8;
    atsha204a_send_command(i2c, SHA204_GENDIG, zone, param2, data, len);
    msleep(GENDIG_EXEC_MAX);
    if (   (0 > atsha204a_read_response(i2c, res, GENDIG_RSP_SIZE))
        || (GENDIG_RSP_SIZE != res[SHA204_BUFFER_POS_COUNT]))
    {
        ERROR("execute gendig cmd failed !");
        return -1;
    }
    if (0 != res[SHA204_BUFFER_POS_DATA])
    {
        ERROR("execute gendig cmd failed(0x%02x) !", res[SHA204_BUFFER_POS_DATA]);
        return -1;
    }

    /* 这里必须idle，保留TempKey和RNG Seed寄存器的值，让接下来的加密写等指令正确执行 */
    atsha204a_set_idle(i2c);

    return 0;
}



/* 验证芯片内的秘钥是否烧录成功,  -1:错误  0:秘钥验证一致  1:秘钥验证不一致 */
int atsha204a_verify_key(const struct i2c_client *i2c, const u8 *key, u8 slot)
{
    u8 num_in[NONCE_NUMIN_SIZE];
    u8 rand_out[NONCE_RANDOUT_SIZE];
    struct sha204h_nonce_in_out nonce_param;
    struct sha204h_temp_key tempkey;
    u8 mac_hw[MAC_DIGEST_SIZE];
    u8 mac_sw[MAC_DIGEST_SIZE];
    struct sha204h_mac_in_out mac_param;


    get_random_bytes(num_in, sizeof(num_in));

    // 1.加密芯片运行 NONCE 命令, 在芯片内部生成 tempkey, 并返回32字节随机数
    if (0 != atsha204a_nonce(i2c, NONCE_MODE_NO_SEED_UPDATE, num_in, rand_out))
        return -1;

    // 2.软件模拟运行 NONCE 命令, 生成 tempkey
    nonce_param.mode = NONCE_MODE_NO_SEED_UPDATE;
    nonce_param.num_in = num_in;
    nonce_param.rand_out = rand_out;
    nonce_param.temp_key = &tempkey;
    if (SHA204_SUCCESS != sha204h_nonce(&nonce_param))
        return -1;

    // 3.加密芯片运行 MAC 命令
    if (0 != atsha204a_mac(i2c, MAC_MODE_BLOCK2_TEMPKEY, slot, NULL, 0, mac_hw))
        return -1;

    // 4.软件模拟运行 MAC 命令
    mac_param.mode = MAC_MODE_BLOCK2_TEMPKEY;
    mac_param.key_id = slot;
    mac_param.challenge = NULL;
    mac_param.key = key;
    mac_param.otp = NULL;
    mac_param.sn = NULL;
    mac_param.response = mac_sw;
    mac_param.temp_key = &tempkey;
    if (SHA204_SUCCESS != sha204h_mac(&mac_param))
        return -1;

    // 5.加密芯片和软件生成的摘要进行对比，如果相等，则验证成功
    if (0 == memcmp(mac_hw, mac_sw, MAC_DIGEST_SIZE))
        return 0;
    else
        return 1;
}
