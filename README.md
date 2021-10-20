* 为了方便唤醒，i2c波特率需要设置为100K
* 驱动可以添加在:  drivers\crypto\atsha204a
* menuconfig:  Cryptographic API --> Hardware crypto devices


**命令读取sn：**  
cat /sys/class/crypto/atsha204a/sn

**命令读取配置：**  
cat /sys/class/crypto/atsha204a/config

**ioctl节点：**  
/dev/atsha204a
