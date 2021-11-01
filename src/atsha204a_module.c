#include <linux/module.h>
#include <linux/i2c.h>
#include <linux/cdev.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include "atsha204a_ioctl.h"
#include "atsha204a_api.h"



#define VERSION "3.0"




#define DEBUG(fmt, arg...)  printk(KERN_NOTICE "--atsha204a-- " fmt "\n", ##arg);
#define ERROR(fmt, arg...)  printk(KERN_ERR    "--atsha204a-- " fmt "\n", ##arg)










typedef struct atsha204a_sysdata
{
    struct i2c_client *client;
    dev_t dev_num;
    struct cdev cdev;
    struct file_operations fops;
    struct class *class;
    struct device *class_device;
    u8 tmp_slot;
}atsha204a_sysdata_t;



u8 atsha204a_debug = 0;




static int atsha204a_open(struct inode* inode, struct file* filp)
{
    filp->private_data = container_of(inode->i_cdev, struct atsha204a_sysdata, cdev);
    return 0;
}

static int atsha204a_release(struct inode* inode, struct file* filp)
{
    return 0;
}

static ssize_t atsha204a_read(struct file *filp, char __user *buf, size_t count, loff_t *off)
{
    return 0;
}

static ssize_t atsha204a_write(struct file* filp, const char __user *buf, size_t count, loff_t* f_pos)
{
    return count;
}

static long atsha204a_ioctl(struct file* filp, unsigned int cmd, unsigned long data)
{
    atsha204a_sysdata_t *sha204_sysdata = filp->private_data;
    atsha204a_cmd_sn_t          sn;
    atsha204a_cmd_devrev_t      devrev;
    atsha204a_cmd_otp_t         otp;
    atsha204a_cmd_nonce_t       nonce;
    atsha204a_cmd_mac_t         mac;
    atsha204a_cmd_burn_config_t config;
    atsha204a_cmd_write_key_t   key;
    atsha204a_cmd_gendig_t      gendig;
    atsha204a_cmd_verify_key_t  verify_key;


    switch (cmd)
    {
        case ATSHA204A_CMD_READ_SN:
        {
            if (0 > atsha204a_read_sn(sha204_sysdata->client, sn.sn))
                return -1;
            if (0 != copy_to_user((u8 *)data, &sn, sizeof(sn)))
                return -1;
            return 0;
        }
        case ATSHA204A_CMD_READ_DEVREV:
        {
            if (0 > atsha204a_read_devrev(sha204_sysdata->client, devrev.rev))
                return -1;
            if (0 != copy_to_user((u8 *)data, &devrev, sizeof(devrev)))
                return -1;
            return 0;
        }
        case ATSHA204A_CMD_READ_OTP:
        {
            if (0 > atsha204a_read_otp(sha204_sysdata->client, otp.otp))
                return -1;
            if (0 != copy_to_user((u8 *)data, &otp, sizeof(otp)))
                return -1;
            return 0;
        }
        case ATSHA204A_CMD_NONCE:
        {
            if (0 != copy_from_user(&nonce, (u8 *)data, sizeof(nonce)))
                return -1;
            if (0 > atsha204a_nonce(sha204_sysdata->client, nonce.in_mode, nonce.in_numin, nonce.out_randout))
                return -1;
            if (0 != copy_to_user((u8 *)data, &nonce, sizeof(nonce)))
                return -1;
            return 0;
        }
        case ATSHA204A_CMD_MAC:
        {
            if (0 != copy_from_user(&mac, (u8 *)data, sizeof(mac)))
                return -1;
            if (0 > atsha204a_mac(sha204_sysdata->client, mac.in_mode, mac.in_slot,
                                  mac.in_challenge, mac.in_challenge_len, mac.out_digest))
                return -1;
            if (0 != copy_to_user((u8 *)data, &mac, sizeof(mac)))
                return -1;
            return 0;
        }
        case ATSHA204A_CMD_BURN_CONFIG:
        {
            if (0 != copy_from_user(&config, (u8 *)data, sizeof(config)))
                return -1;
            if (0 > atsha204a_write_config(sha204_sysdata->client, config.config))
                return -1;
            if (0 > atsha204a_lock_config(sha204_sysdata->client))
                return -1;
            return 0;
        }
        case ATSHA204A_CMD_BURN_DEFCONFIG:
        {
            if (0 > atsha204a_write_defconfig(sha204_sysdata->client))
                return -1;
            if (0 > atsha204a_lock_config(sha204_sysdata->client))
                return -1;
            return 0;
        }
        case ATSHA204A_CMD_WRITE_KEY:
        {
            if (0 != copy_from_user(&key, (u8 *)data, sizeof(key)))
                return -1;
            if (0 > atsha204a_write_key(sha204_sysdata->client, key.key, key.slot))
                return -1;
            return 0;
        }
        case ATSHA204A_CMD_WRITE_OTP:
        {
            if (0 != copy_from_user(&otp, (u8 *)data, sizeof(otp)))
                return -1;
            if (0 > atsha204a_write_otp(sha204_sysdata->client, otp.otp))
                return -1;
            return 0;
        }
        case ATSHA204A_CMD_LOCK_VALUE:
        {
            if (0 > atsha204a_lock_value(sha204_sysdata->client))
                return -1;
            return 0;
        }
        case ATSHA204A_CMD_GENDIG:
        {
            if (0 != copy_from_user(&gendig, (u8 *)data, sizeof(gendig)))
                return -1;
            if (0 > atsha204a_gendig(sha204_sysdata->client, gendig.zone, gendig.slot, gendig.data, gendig.data_len))
                return -1;
            return 0;
        }
        case ATSHA204A_CMD_WRITE_ENCRYPTED_KEY:
        {
            if (0 != copy_from_user(&key, (u8 *)data, sizeof(key)))
                return -1;
            if (0 > atsha204a_write_encrypted_key(sha204_sysdata->client, key.key, key.slot, key.digest))
                return -1;
            return 0;
        }
        case ATSHA204A_CMD_VERIFY_KEY:
        {
            if (0 != copy_from_user(&verify_key, (u8 *)data, sizeof(verify_key)))
                return -1;
            if (0 == atsha204a_verify_key(sha204_sysdata->client, verify_key.key, verify_key.slot))
            {
                DEBUG("Key(%u) verify OK", verify_key.slot);
                return 0;
            }
            else
            {
                DEBUG("Key(%u) verify failed", verify_key.slot);
                return -1;
            }
        }
        default:
            return -1;
    }

    return -1;
}


static ssize_t sn_show(struct device *dev, struct device_attribute *attr, char *buf)
{
    atsha204a_sysdata_t *sha204_sysdata = NULL;
    u8 sn[SHA204_SN_SIZE];

    sha204_sysdata = (atsha204a_sysdata_t *)dev_get_drvdata(dev);
    if (0 > atsha204a_read_sn(sha204_sysdata->client, sn))
        return -EIO;

    return snprintf(buf, PAGE_SIZE, "%02x %02x %02x %02x %02x %02x %02x %02x %02x\n", \
                                     sn[0],sn[1],sn[2],sn[3],sn[4],sn[5],sn[6],sn[7],sn[8]);
}
static ssize_t sn_store(struct device *dev, struct device_attribute *attr, const char *buf, size_t size)
{
    return -EPERM;
}

static ssize_t config_show(struct device *dev, struct device_attribute *attr, char *buf)
{
    atsha204a_sysdata_t *sha204_sysdata = NULL;

    sha204_sysdata = (atsha204a_sysdata_t *)dev_get_drvdata(dev);
    return atsha204a_parse_config(sha204_sysdata->client, buf, PAGE_SIZE);
}
static ssize_t config_store(struct device *dev, struct device_attribute *attr, const char *buf, size_t size)
{
    return -EPERM;
}

static ssize_t otp_show(struct device *dev, struct device_attribute *attr, char *buf)
{
    atsha204a_sysdata_t *sha204_sysdata = NULL;
    u8 otp[SHA204_OTP_SIZE + 1];
    int ret;

    sha204_sysdata = (atsha204a_sysdata_t *)dev_get_drvdata(dev);
    if (0 > atsha204a_read_otp(sha204_sysdata->client, otp))
        return -EIO;

    otp[SHA204_OTP_SIZE] = '\0';
    if ((' ' <= otp[0]) && ('~' >= otp[0]))
        ret = sprintf(buf, "%s\n", otp);
    else
        ret = sprintf(buf, "\n");
    if (0 > ret)
        return ret;

    return ret + hex_dump_str(buf + ret, PAGE_SIZE - ret, otp, SHA204_OTP_SIZE, 8);

}
static ssize_t otp_store(struct device *dev, struct device_attribute *attr, const char *buf, size_t size)
{
    return -EPERM;
}

static ssize_t debug_show(struct device *dev, struct device_attribute *attr, char *buf)
{
    return snprintf(buf, PAGE_SIZE, "%u\n", atsha204a_debug);
}
static ssize_t debug_store(struct device *dev, struct device_attribute *attr, const char *buf, size_t size)
{
    unsigned long debug;

    if (kstrtoul(buf, 0, &debug))
        return -EINVAL;

    atsha204a_debug = !!debug;
    return size;
}

static ssize_t key_show(struct device *dev, struct device_attribute *attr, char *buf)
{
    atsha204a_sysdata_t *sha204_sysdata = NULL;
    u8 key[SHA204_KEY_SIZE] = {0};

    sha204_sysdata = (atsha204a_sysdata_t *)dev_get_drvdata(dev);
    if (0 > atsha204a_read_key(sha204_sysdata->client, key, sha204_sysdata->tmp_slot))
        return -EPERM;
    return hex_dump_str(buf, PAGE_SIZE, key, SHA204_KEY_SIZE, 8);
}
static ssize_t key_store(struct device *dev, struct device_attribute *attr, const char *buf, size_t size)
{
    atsha204a_sysdata_t *sha204_sysdata = NULL;
    unsigned long slot;

    sha204_sysdata = (atsha204a_sysdata_t *)dev_get_drvdata(dev);
    if (kstrtoul(buf, 0, &slot))
        return -EINVAL;
    if ((0 > slot) || (SHA204_KEY_COUNT <= slot))
        return -EINVAL;

    sha204_sysdata->tmp_slot = slot;
    DEBUG("key(%u) will be read", sha204_sysdata->tmp_slot);
    return size;
}

static ssize_t lock_defconfig_show(struct device *dev, struct device_attribute *attr, char *buf)
{
    return -EPERM;
}
static ssize_t lock_defconfig_store(struct device *dev, struct device_attribute *attr, const char *buf, size_t size)
{
    atsha204a_sysdata_t *sha204_sysdata = NULL;

    sha204_sysdata = (atsha204a_sysdata_t *)dev_get_drvdata(dev);
    if (0 > atsha204a_write_defconfig(sha204_sysdata->client))
    {
        ERROR("lock defconfig failed !");
        return -EIO;;
    }
    if (0 > atsha204a_lock_config(sha204_sysdata->client))
    {
        ERROR("lock defconfig failed !");
        return -EIO;;
    }
    DEBUG("locked defconfig");
    return size;
}


struct device_attribute atsha204a_attrs[] =
{
    __ATTR(sn,             0660, sn_show,             sn_store),
    __ATTR(config,         0660, config_show,         config_store),
    __ATTR(otp,            0660, otp_show,            otp_store),
    __ATTR(debug,          0660, debug_show,          debug_store),
    __ATTR(key,            0660, key_show,            key_store),
    __ATTR(lock_defconfig, 0660, lock_defconfig_show, lock_defconfig_store)
};
int atsha204a_attrs_size = sizeof(atsha204a_attrs)/sizeof(atsha204a_attrs[0]);

static int atsha204a_add_sysfs_interfaces(struct device *dev, struct device_attribute *a, int size)
{
    int i;

    for (i = 0; i < size; i++)
        if (device_create_file(dev, a + i))
            goto undo;
    return 0;

undo:
    for (i--; i >= 0; i--)
        device_remove_file(dev, a + i);
    return -EPERM;
}
static void atsha204a_del_sysfs_interfaces(struct device *dev, struct device_attribute *a, int size)
{
    int i;

    for (i = 0; i < size; i++)
        device_remove_file(dev, a + i);
}


static int atsha204a_probe(struct i2c_client *client, const struct i2c_device_id *id)
{
    atsha204a_sysdata_t *sha204_sysdata = NULL;
    int ret = 0;


    DEBUG("I2C address: 0x%02x", client->addr);

    sha204_sysdata = kzalloc(sizeof(atsha204a_sysdata_t), GFP_KERNEL);
    if (IS_ERR_OR_NULL(sha204_sysdata))
    {
        ERROR("cannot allocate memory, size: %lu !", sizeof(atsha204a_sysdata_t));
        return -ENOMEM;
    }
    sha204_sysdata->client = client;
    i2c_set_clientdata(client, sha204_sysdata);

    /* 创建字符设备 */
    ret = alloc_chrdev_region(&sha204_sysdata->dev_num, 0, 1, "atsha204a");
    if (ret)
    {
        ERROR("alloc chrdev region failed !");
        goto ERR_1;
    }
    sha204_sysdata->fops.owner   = THIS_MODULE,
    sha204_sysdata->fops.open    = atsha204a_open,
    sha204_sysdata->fops.release = atsha204a_release,
    sha204_sysdata->fops.read    = atsha204a_read,
    sha204_sysdata->fops.write   = atsha204a_write,
    sha204_sysdata->fops.unlocked_ioctl = atsha204a_ioctl,
    cdev_init(&sha204_sysdata->cdev, &sha204_sysdata->fops);
    ret = cdev_add(&sha204_sysdata->cdev, sha204_sysdata->dev_num, 1);
    if (ret)
    {
        ERROR("failed to add char dev !");
        goto ERR_2;
    }

    /* 创建字符设备节点 */
    sha204_sysdata->class = class_create(THIS_MODULE, "crypto");
    if (IS_ERR_OR_NULL(sha204_sysdata->class))
    {
        ERROR("failed to create class \"atsha204a\" !");
        ret = PTR_ERR(sha204_sysdata->class);
        goto ERR_3;
    }
    sha204_sysdata->class_device = device_create(sha204_sysdata->class, NULL, sha204_sysdata->dev_num, sha204_sysdata, "atsha204a");
    if (IS_ERR_OR_NULL(sha204_sysdata->class_device))
    {
        ERROR("failed to create class device !");
        ret = PTR_ERR(sha204_sysdata->class_device);
        goto ERR_4;
    }
    dev_set_drvdata(sha204_sysdata->class_device, sha204_sysdata);

    /* 增加配置接口 */
    ret = atsha204a_add_sysfs_interfaces(sha204_sysdata->class_device, atsha204a_attrs, atsha204a_attrs_size);
    if (ret)
    {
        ERROR("create sysfs interface failed !");
        goto ERR_5;
    }

    return 0;



ERR_5:
    dev_set_drvdata(sha204_sysdata->class_device, NULL);
    device_destroy(sha204_sysdata->class, sha204_sysdata->dev_num);
ERR_4:
    class_destroy(sha204_sysdata->class);
ERR_3:
    cdev_del(&sha204_sysdata->cdev);
ERR_2:
    unregister_chrdev_region(sha204_sysdata->dev_num, 1);
ERR_1:
    i2c_set_clientdata(client, NULL);
    kfree(sha204_sysdata);
    return ret;
}
static int atsha204a_remove(struct i2c_client *client)
{
    atsha204a_sysdata_t *sha204_sysdata = NULL;

    sha204_sysdata = i2c_get_clientdata(client);
    if (IS_ERR_OR_NULL(sha204_sysdata))
        return 0;

    atsha204a_del_sysfs_interfaces(sha204_sysdata->class_device, atsha204a_attrs, atsha204a_attrs_size);
    dev_set_drvdata(sha204_sysdata->class_device, NULL);
    device_destroy(sha204_sysdata->class, sha204_sysdata->dev_num);
    class_destroy(sha204_sysdata->class);
    cdev_del(&sha204_sysdata->cdev);
    unregister_chrdev_region(sha204_sysdata->dev_num, 1);
    i2c_set_clientdata(client, NULL);
    kfree(sha204_sysdata);

    return 0;
}



static const struct of_device_id atsha204a_match_table[] = {
    { .compatible = "atmel,atsha204a", },
    { /* end */ },
};
static const struct i2c_device_id atsha204a_id[] = {
    { "atsha204a", 0 },
    { /* end */ }
};
static struct i2c_driver atsha204a_driver =
{
    .probe    = atsha204a_probe,
    .remove   = atsha204a_remove,
    .id_table = atsha204a_id,
    .driver = {
        .name  = "atsha204a",
        .owner = THIS_MODULE,
        .of_match_table = atsha204a_match_table,
    },
};


static int __init atsha204a_init(void)
{
    DEBUG("Driver Version: %s", VERSION);
    return i2c_add_driver(&atsha204a_driver);
}
static void __exit atsha204a_exit(void)
{
    DEBUG("exit");
    i2c_del_driver(&atsha204a_driver);
}


late_initcall(atsha204a_init);
module_exit(atsha204a_exit);


MODULE_AUTHOR("LLL");
MODULE_DESCRIPTION("atsha204a driver");
MODULE_LICENSE("GPL");
