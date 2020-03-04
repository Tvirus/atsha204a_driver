#include "atsha204a_api.h"
#include <linux/delay.h>
#include <linux/slab.h>





#define ERROR(fmt, arg...)  printk(KERN_ERR "--atsha204a-- " fmt "\n", ##arg)


/* opcodes for ATSHA204 Commands */
#define SHA204_CHECKMAC                 ((uint8_t) 0x28)       //!< CheckMac command op-code
#define SHA204_DERIVE_KEY               ((uint8_t) 0x1C)       //!< DeriveKey command op-code
#define SHA204_DEVREV                   ((uint8_t) 0x30)       //!< DevRev command op-code
#define SHA204_GENDIG                   ((uint8_t) 0x15)       //!< GenDig command op-code
#define SHA204_HMAC                     ((uint8_t) 0x11)       //!< HMAC command op-code
#define SHA204_LOCK                     ((uint8_t) 0x17)       //!< Lock command op-code
#define SHA204_MAC                      ((uint8_t) 0x08)       //!< MAC command op-code
#define SHA204_NONCE                    ((uint8_t) 0x16)       //!< Nonce command op-code
#define SHA204_PAUSE                    ((uint8_t) 0x01)       //!< Pause command op-code
#define SHA204_RANDOM                   ((uint8_t) 0x1B)       //!< Random command op-code
#define SHA204_READ                     ((uint8_t) 0x02)       //!< Read command op-code
#define SHA204_UPDATE_EXTRA             ((uint8_t) 0x20)       //!< UpdateExtra command op-code
#define SHA204_WRITE                    ((uint8_t) 0x12)       //!< Write command op-code

/* Definitions for Zone and Address Parameters */
#define SHA204_ZONE_CONFIG              ((uint8_t) 0x00)       //!< Configuration zone
#define SHA204_ZONE_OTP                 ((uint8_t) 0x01)       //!< OTP (One Time Programming) zone
#define SHA204_ZONE_DATA                ((uint8_t) 0x02)       //!< Data zone
#define SHA204_ZONE_MASK                ((uint8_t) 0x03)       //!< Zone mask
#define SHA204_ZONE_COUNT_FLAG          ((uint8_t) 0x80)       //!< Zone bit 7 set: Access 32 bytes, otherwise 4 bytes.
#define SHA204_ZONE_ACCESS_4            ((uint8_t)    4)       //!< Read or write 4 bytes.
#define SHA204_ZONE_ACCESS_32           ((uint8_t)   32)       //!< Read or write 32 bytes.

/* Word Address Values */
#define SHA204_PACKET_FUNC_RESET        ((uint8_t) 0x00)
#define SHA204_PACKET_FUNC_SLEEP        ((uint8_t) 0x01)
#define SHA204_PACKET_FUNC_IDLE         ((uint8_t) 0x02)
#define SHA204_PACKET_FUNC_CMD          ((uint8_t) 0x03)

/* Definitions for the Lock Command */
#define LOCK_ZONE_IDX                   SHA204_PARAM1_IDX      //!< Lock command index for zone
#define LOCK_SUMMARY_IDX                SHA204_PARAM2_IDX      //!< Lock command index for summary
#define LOCK_COUNT                      SHA204_CMD_SIZE_MIN    //!< Lock command packet size
#define LOCK_ZONE_NO_CONFIG             ((uint8_t) 0x01)       //!< Lock zone is OTP or Data
#define LOCK_ZONE_NO_CRC                ((uint8_t) 0x80)       //!< Lock command: Ignore summary.
#define LOCK_ZONE_MASK                  (0x81)                 //!< Lock parameter 1 bits 2 to 6 are 0.

/*name Definitions for the Nonce Command */
#define NONCE_MODE_IDX                  SHA204_PARAM1_IDX      //!< Nonce command index for mode
#define NONCE_PARAM2_IDX                SHA204_PARAM2_IDX      //!< Nonce command index for 2. parameter
#define NONCE_INPUT_IDX                 SHA204_DATA_IDX        //!< Nonce command index for input data
#define NONCE_COUNT_SHORT               (27)                   //!< Nonce command packet size for 20 bytes of data
#define NONCE_COUNT_LONG                (39)                   //!< Nonce command packet size for 32 bytes of data
#define NONCE_MODE_MASK                 ((uint8_t) 3)          //!< Nonce mode bits 2 to 7 are 0.
#define NONCE_MODE_SEED_UPDATE          ((uint8_t) 0x00)       //!< Nonce mode: update seed
#define NONCE_MODE_NO_SEED_UPDATE       ((uint8_t) 0x01)       //!< Nonce mode: do not update seed
#define NONCE_MODE_INVALID              ((uint8_t) 0x02)       //!< Nonce mode 2 is invalid.
#define NONCE_MODE_PASSTHROUGH          ((uint8_t) 0x03)       //!< Nonce mode: pass-through

/* Definitions for the MAC Command */
#define MAC_MODE_IDX                    SHA204_PARAM1_IDX      //!< MAC command index for mode
#define MAC_KEYID_IDX                   SHA204_PARAM2_IDX      //!< MAC command index for key id
#define MAC_CHALLENGE_IDX               SHA204_DATA_IDX        //!< MAC command index for optional challenge
#define MAC_COUNT_SHORT                 SHA204_CMD_SIZE_MIN    //!< MAC command packet size without challenge
#define MAC_COUNT_LONG                  (39)                   //!< MAC command packet size with challenge
#define MAC_MODE_CHALLENGE              ((uint8_t) 0x00)       //!< MAC mode       0: first SHA block from data slot
#define MAC_MODE_BLOCK2_TEMPKEY         ((uint8_t) 0x01)       //!< MAC mode bit   0: second SHA block from TempKey
#define MAC_MODE_BLOCK1_TEMPKEY         ((uint8_t) 0x02)       //!< MAC mode bit   1: first SHA block from TempKey
#define MAC_MODE_SOURCE_FLAG_MATCH      ((uint8_t) 0x04)       //!< MAC mode bit   2: match TempKey.SourceFlag
#define MAC_MODE_PASSTHROUGH            ((uint8_t) 0x07)       //!< MAC mode bit 0-2: pass-through mode
#define MAC_MODE_INCLUDE_OTP_88         ((uint8_t) 0x10)       //!< MAC mode bit   4: include first 88 OTP bits
#define MAC_MODE_INCLUDE_OTP_64         ((uint8_t) 0x20)       //!< MAC mode bit   5: include first 64 OTP bits
#define MAC_MODE_INCLUDE_SN             ((uint8_t) 0x40)       //!< MAC mode bit   6: include serial number
#define MAC_MODE_MASK                   ((uint8_t) 0x77)       //!< MAC mode bits 3 and 7 are 0.

/* Definitions for the GenDig Command */
#define GENDIG_ZONE_IDX                 SHA204_PARAM1_IDX      //!< GenDig command index for zone
#define GENDIG_KEYID_IDX                SHA204_PARAM2_IDX      //!< GenDig command index for key id
#define GENDIG_DATA_IDX                 SHA204_DATA_IDX        //!< GenDig command index for optional data
#define GENDIG_COUNT                    SHA204_CMD_SIZE_MIN    //!< GenDig command packet size without "other data"
#define GENDIG_COUNT_DATA               (11)                   //!< GenDig command packet size with "other data"
#define GENDIG_OTHER_DATA_SIZE          (4)                    //!< GenDig size of "other data"
#define GENDIG_ZONE_CONFIG              ((uint8_t) 0)          //!< GenDig zone id config
#define GENDIG_ZONE_OTP                 ((uint8_t) 1)          //!< GenDig zone id OTP
#define GENDIG_ZONE_DATA                ((uint8_t) 2)          //!< GenDig zone id data




/* 各个命令的最大执行时间(ms) */
#define CMD_MAX_TIME_DERIVE_KEY         (62)
#define CMD_MAX_TIME_DEVREV             (2)
#define CMD_MAX_TIME_GENDIG             (43)
#define CMD_MAX_TIME_HMAC               (69)
#define CMD_MAX_TIME_CHECKMAC           (38)
#define CMD_MAX_TIME_LOCK               (24)
#define CMD_MAX_TIME_MAC                (35)
#define CMD_MAX_TIME_NONCE              (60)
#define CMD_MAX_TIME_PAUSE              (2)
#define CMD_MAX_TIME_RANDOM             (50)
#define CMD_MAX_TIME_READ               (4)
#define CMD_MAX_TIME_SHA                (22)
#define CMD_MAX_TIME_UPDATE_EXTRA       (12)
#define CMD_MAX_TIME_WRITE              (42)





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

    0x00, 0x80, 0x00, 0x80,  //SlotConfig  0  1
    0x00, 0x80, 0x00, 0x80,  //SlotConfig  2  3
    0x00, 0x80, 0x00, 0x80,  //SlotConfig  4  5
    0x00, 0x80, 0x00, 0x80,  //SlotConfig  6  7
    0x00, 0x80, 0x00, 0x80,  //SlotConfig  8  9
    0x00, 0x80, 0x00, 0x80,  //SlotConfig 10 11
    0x00, 0x80, 0x00, 0x80,  //SlotConfig 12 13
    0x00, 0x80, 0x00, 0x80,  //SlotConfig 14 15

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
int hex_dump_str(char *str, int str_len, u8 *buf, int buf_len, u8 col)
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
int atsha204a_calc_block_crc(u8 *block)
{
    if (4 > block[0])
        return -1;

    atsha204a_crc(block[0] - 2, block, block + block[0] - 2);
    return 0;
}
/** \brief This function checks the consistency of a response.
 * \param[in] response pointer to response
 * \return ATCA_SUCCESS on success, otherwise ATCA_RX_CRC_ERROR
 */
int atsha204a_check_block_crc(const u8 *response, u32 len)
{
    u8 crc[2];

    if (len != response[0] || 4 > len)
        return -1;

    atsha204a_crc(len - 2, response, crc);

    return (crc[0] == response[len - 2] && crc[1] == response[len - 1]) ? 0 : -1;
}



/* i2c速度配置为100k时可以发送一个0字节来唤醒 */
void atsha204a_wakeup(const struct i2c_client *i2c)
{
    u8 v = 0;
    atsha204a_i2c_write(i2c, &v, 1);
    msleep(2);
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

static int atsha204a_send_command(const struct i2c_client *i2c, u8 opcode, u8 param1, const u8 *param2, const u8 *data, u8 len)
{
    u8 buf[100];
    atsha204a_cmd_t *cmd = (atsha204a_cmd_t *)buf;


    if (sizeof(buf) < (sizeof(atsha204a_cmd_t) + len + 2))
        return -1;

    cmd->addr      = SHA204_PACKET_FUNC_CMD;
    cmd->count     = sizeof(atsha204a_cmd_t) + len + 1;
    cmd->opcode    = opcode;
    cmd->param1    = param1;
    cmd->param2[0] = param2[0];
    cmd->param2[1] = param2[1];
    memcpy(cmd->data, data, len);
    atsha204a_calc_block_crc(((u8 *)cmd) + 1);
    if (0 > atsha204a_i2c_write(i2c, (u8 *)cmd, sizeof(atsha204a_cmd_t) + len + 2))
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
    msleep(CMD_MAX_TIME_PAUSE);

    return 0;
}

int atsha204a_read_sn(const struct i2c_client *i2c, u8 *sn)
{
    u8 param2[2];
    u8 res[SHA204_ZONE_ACCESS_32 + 3] = {0}; /* 32字节读，加上count和CRC共35字节 */


    atsha204a_rewakeup(i2c);

    param2[0] = param2[1] = 0;
    atsha204a_send_command(i2c, SHA204_READ, SHA204_ZONE_COUNT_FLAG | SHA204_ZONE_CONFIG, param2, NULL, 0);
    msleep(CMD_MAX_TIME_READ);
    if ((0 > atsha204a_read_response(i2c, res, sizeof(res))) || (sizeof(res) != res[0]))
    {
        ERROR("read sn failed !");
        return -1;
    }
    memcpy(sn,     res + 1, 4);
    memcpy(sn + 4, res + 9, 5);

    atsha204a_go_sleep(i2c);

    return 0;
}

int atsha204a_read_otp(const struct i2c_client *i2c, u8 *otp)
{
    u8 param2[2];
    u8 res[SHA204_ZONE_ACCESS_32 + 3] = {0}; /* 32字节读，加上count和CRC共35字节 */
    int i;


    atsha204a_rewakeup(i2c);

    param2[0] = param2[1] = 0;
    for (i = 0; i < 2; i++)
    {
        atsha204a_send_command(i2c, SHA204_READ, SHA204_ZONE_COUNT_FLAG | SHA204_ZONE_OTP, param2, NULL, 0);
        msleep(CMD_MAX_TIME_READ);
        if ((0 > atsha204a_read_response(i2c, res, sizeof(res))) || (sizeof(res) != res[0]))
        {
            ERROR("read otp failed !");
            return -1;
        }
        memcpy(otp, res + 1, 32);
        otp += 32;
        param2[0] = 0x08;
        res[0] = 0;
    }

    atsha204a_go_sleep(i2c);

    return 0;
}

int atsha204a_read_config(const struct i2c_client *i2c, u8 *config)
{
    u8 param2[2];
    u8 res[SHA204_ZONE_ACCESS_32 + 3] = {0}; /* 32字节读，加上count和CRC共35字节 */
    int i;


    atsha204a_rewakeup(i2c);

    /* 读两个32字节 */
    param2[0] = param2[1] = 0;
    for (i = 0; i < 2; i++)
    {
        atsha204a_send_command(i2c, SHA204_READ, SHA204_ZONE_COUNT_FLAG | SHA204_ZONE_CONFIG, param2, NULL, 0);
        msleep(CMD_MAX_TIME_READ);
        if ((0 > atsha204a_read_response(i2c, res, sizeof(res))) || (sizeof(res) != res[0]))
        {
            ERROR("read config failed !");
            return -1;
        }
        memcpy(config, res + 1, 32);
        config += 32;
        param2[0] = 0x08;
        res[0] = 0;
    }

    /* 读6个4字节 */
    param2[0] = 0x10;
    param2[1] = 0;
    for (i = 0; i < 6; i++)
    {
        atsha204a_send_command(i2c, SHA204_READ, SHA204_ZONE_CONFIG, param2, NULL, 0);
        msleep(CMD_MAX_TIME_READ);
        if ((0 > atsha204a_read_response(i2c, res, 7)) || (7 != res[0]))
        {
            ERROR("read config failed !");
            return -1;
        }
        memcpy(config, res + 1, 4);
        config += 4;
        param2[0] += 1;
        res[0] = 0;
    }

    atsha204a_go_sleep(i2c);

    return 0;
}

/* 读数据区中的一个key(32字节) */
int atsha204a_read_key(const struct i2c_client *i2c, u8 *key, u8 slot)
{
    u8 param2[2];
    u8 res[SHA204_ZONE_ACCESS_32 + 3] = {0}; /* 32字节读，加上count和CRC共35字节 */


    if (SHA204_KEY_COUNT <= slot)
        return -1;

    atsha204a_rewakeup(i2c);

    param2[0] = 0x08 * slot;
    param2[1] = 0;
    atsha204a_send_command(i2c, SHA204_READ, SHA204_ZONE_COUNT_FLAG | SHA204_ZONE_DATA, param2, NULL, 0);
    msleep(CMD_MAX_TIME_READ);
    if ((0 > atsha204a_read_response(i2c, res, sizeof(res))) || (sizeof(res) != res[0]))
    {
        ERROR("read key(%u) failed !", slot);
        return -1;
    }
    memcpy(key, res + 1, 32);

    atsha204a_go_sleep(i2c);

    return (int)32;
}
/* 写数据区中的一个key(32字节) */
int atsha204a_write_key(const struct i2c_client *i2c, const u8 *key, u8 slot)
{
    u8 param2[2];
    u8 res[4] = {0};


    if (SHA204_KEY_COUNT <= slot)
        return -1;

    atsha204a_rewakeup(i2c);

    param2[0] = 0x08 * slot;
    param2[1] = 0;
    atsha204a_send_command(i2c, SHA204_WRITE, SHA204_ZONE_COUNT_FLAG | SHA204_ZONE_DATA, param2, key, SHA204_KEY_SIZE);
    msleep(CMD_MAX_TIME_WRITE);
    if ((0 > atsha204a_read_response(i2c, res, sizeof(res))) || (sizeof(res) != res[0]))
    {
        ERROR("write key(%u) failed !", slot);
        return -1;
    }
    if (0 != res[1])
    {
        ERROR("write key(%u) failed(0x%02x) !", slot, res[1]);
        return -1;
    }

    atsha204a_go_sleep(i2c);

    return 0;
}
/* 用加密写的方式写一个密钥 */
int atsha204a_write_encrypted_key(const struct i2c_client *i2c, const u8 *key, u8 slot, u8 *digest)
{
    u8 param2[2];
    u8 res[4] = {0};
    u8 data[64] = {0};


    if (SHA204_KEY_COUNT <= slot)
        return -1;

    /* 仅唤醒，恢复上一步nonce中的TempKey等相关值 */
    atsha204a_wakeup(i2c);

    param2[0] = 0x08 * slot;
    param2[1] = 0;
    memcpy(data,      key,    32);
    memcpy(data + 32, digest, 32);
    atsha204a_send_command(i2c, SHA204_WRITE, SHA204_ZONE_COUNT_FLAG | SHA204_ZONE_DATA, param2, data, 64);
    msleep(CMD_MAX_TIME_WRITE);
    if ((0 > atsha204a_read_response(i2c, res, sizeof(res))) || (sizeof(res) != res[0]))
    {
        ERROR("write encrypted key(%u) failed !", slot);
        return -1;
    }
    if (0 != res[1])
    {
        ERROR("write encrypted key(%u) failed(0x%02x) !", slot, res[1]);
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
    u8 res[4] = {0};
    int i;


    atsha204a_rewakeup(i2c);

    /* 4字节写，写17次 */
    param2[0] = 4; /* 从第4字(偏移16字节)开始写 */
    param2[1] = 0;
    for (i = 0; i < 17; i++)
    {
        atsha204a_send_command(i2c, SHA204_WRITE, SHA204_ZONE_CONFIG, param2, config, 4);
        msleep(CMD_MAX_TIME_WRITE);
        if ((0 > atsha204a_read_response(i2c, res, sizeof(res))) || (sizeof(res) != res[0]))
        {
            ERROR("write config failed !");
            return -1;
        }
        if (0 != res[1])
        {
            ERROR("write config failed(0x%02x) !", res[1]);
            return -1;
        }
        config += 4;
        param2[0]++;
        res[0] = 0;

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
    u8 res[4] = {0};
    int i;


    atsha204a_rewakeup(i2c);

    param2[0] = param2[1] = 0;
    for (i = 0; i < 2; i++)
    {
        atsha204a_send_command(i2c, SHA204_WRITE, SHA204_ZONE_COUNT_FLAG | SHA204_ZONE_OTP, param2, otp, 32);
        msleep(CMD_MAX_TIME_WRITE);
        if ((0 > atsha204a_read_response(i2c, res, sizeof(res))) || (sizeof(res) != res[0]))
        {
            ERROR("write otp failed !");
            return -1;
        }
        if (0 != res[1])
        {
            ERROR("write otp failed(0x%02x) !",res[1]);
            return -1;
        }
        otp += 32;
        param2[0] = 0x08;
        res[0] = 0;
    }

    atsha204a_go_sleep(i2c);

    return 0;
}


int atsha204a_lock_config(const struct i2c_client *i2c)
{
    u8 param2[2];
    u8 res[4] = {0};


    atsha204a_rewakeup(i2c);

    param2[0] = param2[1] = 0;
    atsha204a_send_command(i2c, SHA204_LOCK, LOCK_ZONE_NO_CRC, param2, NULL, 0);
    msleep(CMD_MAX_TIME_LOCK);
    if ((0 > atsha204a_read_response(i2c, res, sizeof(res))) || (sizeof(res) != res[0]))
    {
        ERROR("lock config failed !");
        return -1;
    }
    if (0 != res[1])
    {
        ERROR("lock config failed(0x%02x) !", res[1]);
        return -1;
    }

    atsha204a_go_sleep(i2c);

    return 0;
}
int atsha204a_lock_value(const struct i2c_client *i2c)
{
    u8 param2[2];
    u8 res[4] = {0};


    atsha204a_rewakeup(i2c);

    param2[0] = param2[1] = 0;
    atsha204a_send_command(i2c, SHA204_LOCK, LOCK_ZONE_NO_CRC | LOCK_ZONE_NO_CONFIG, param2, NULL, 0);
    msleep(CMD_MAX_TIME_LOCK);
    if ((0 > atsha204a_read_response(i2c, res, sizeof(res))) || (sizeof(res) != res[0]))
    {
        ERROR("lock value failed !");
        return -1;
    }
    if (0 != res[1])
    {
        ERROR("lock value failed(0x%02x) !", res[1]);
        return -1;
    }

    atsha204a_go_sleep(i2c);

    return 0;
}

/* 输入20字节，输出32字节随机数 */
int atsha204a_nonce(const struct i2c_client *i2c, u8 mode, const u8 *in, u8 *out)
{
    u8 param2[2];
    u8 res[32 + 3] = {0}; /* 32字节读，加上count和CRC共35字节 */


    atsha204a_rewakeup(i2c);

    param2[0] = param2[1] = 0;
    atsha204a_send_command(i2c, SHA204_NONCE, mode, param2, in, NONCE_NUMIN_SIZE);
    msleep(CMD_MAX_TIME_NONCE);
    if ((0 > atsha204a_read_response(i2c, res, sizeof(res))) || (sizeof(res) != res[0]))
    {
        ERROR("execute nonce cmd failed !");
        return -1;
    }
    memcpy(out, res + 1, 32);

    /* 这里必须idle，保留TempKey和RNG Seed寄存器的值，让接下来的mac等指令正确执行 */
    atsha204a_set_idle(i2c);

    return 0;
}

/* 芯片计算mac时需要用到mode和slot */
int atsha204a_mac(const struct i2c_client *i2c, u8 mode, u8 slot, const u8 *challenge, u8 len, u8 *mac)
{
    u8 param2[2];
    u8 res[32 + 3] = {0}; /* 32字节读，加上count和CRC共35字节 */


    if (SHA204_KEY_COUNT <= slot)
        return -1;
    if ((0 != len) && (MAC_CHALLENGE_SIZE != len))
        return -1;

    /* 仅唤醒，恢复上一步nonce中的TempKey等相关值 */
    atsha204a_wakeup(i2c);

    param2[0] = 0;
    param2[1] = slot;
    atsha204a_send_command(i2c, SHA204_MAC, mode, param2, challenge, len);
    msleep(CMD_MAX_TIME_MAC);
    if ((0 > atsha204a_read_response(i2c, res, sizeof(res))) || (sizeof(res) != res[0]))
    {
        ERROR("execute mac cmd failed !");
        return -1;
    }
    memcpy(mac, res + 1, 32);

    atsha204a_go_sleep(i2c);

    return 0;
}

/* 仅针对用data区密钥产生摘要的情况 */
int atsha204a_gendig(const struct i2c_client *i2c, u8 zone, u16 slot, const u8 *data, u8 len)
{
    u8 param2[2];
    u8 res[4] = {0};


    if ((SHA204_ZONE_CONFIG != zone) && (SHA204_ZONE_OTP != zone) && (SHA204_ZONE_DATA != zone))
        return -1;
    if ((0 != len) && (GENDIG_OTHER_DATA_SIZE != len))
        return -1;

    /* 仅唤醒，恢复上一步nonce中的TempKey等相关值 */
    atsha204a_wakeup(i2c);

    param2[0] = (slot & 0xff00) >> 8;
    param2[1] =  slot & 0xff;
    atsha204a_send_command(i2c, SHA204_GENDIG, zone, param2, data, len);
    msleep(CMD_MAX_TIME_GENDIG);
    if ((0 > atsha204a_read_response(i2c, res, sizeof(res))) || (sizeof(res) != res[0]))
    {
        ERROR("execute gendig cmd failed !");
        return -1;
    }
    if (0 != res[1])
    {
        ERROR("execute gendig cmd failed(0x%02x) !", res[1]);
        return -1;
    }

    /* 这里必须idle，保留TempKey和RNG Seed寄存器的值，让接下来的加密写等指令正确执行 */
    atsha204a_set_idle(i2c);

    return 0;
}
