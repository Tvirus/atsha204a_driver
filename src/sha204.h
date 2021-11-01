#ifdef __cplusplus
extern "C" {
#endif
/** \file
 *  \brief  Definitions and Prototypes for Command Marshaling Layer of ATSHA204 Library
 *  \author Atmel Crypto Products
 *  \date   January 9, 2013
 *
 * \copyright Copyright (c) 2013 Atmel Corporation. All rights reserved.
 *
 * \atsha204_library_license_start
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * 3. The name of Atmel may not be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * 4. This software may only be redistributed and used in connection with an
 *    Atmel integrated circuit.
 *
 * THIS SOFTWARE IS PROVIDED BY ATMEL "AS IS" AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT ARE
 * EXPRESSLY AND SPECIFICALLY DISCLAIMED. IN NO EVENT SHALL ATMEL BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * \atsha204_library_license_stop

   <table>
     <caption align="top">Command Packet Structure</caption>
     <tr>
       <th width=25%>Byte #</th> <th width=25%>Name</th> <th>Meaning</th>
     </tr>
     <tr>
       <td>0</td>
       <td>Count</td>
       <td>Number of bytes in the packet, includes the count byte, body and the checksum</td>
     </tr>
     <tr>
       <td>1</td>
       <td>Op-Code</td>
       <td>Indicates type of command</td>
     </tr>
     <tr>
       <td>2</td>
       <td>Parameter 1</td>
       <td>mode, zone, etc.</td>
     </tr>
     <tr>
       <td>3 and 4</td>
       <td>Parameter 2</td>
       <td>key id, address, etc.</td>
     </tr>
     <tr>
       <td>5 to n</td>
       <td>data (not for every command)</td>
       <td>challenge, pass-through, etc.</td>
     </tr>
     <tr>
       <td>n+1 to n+2</td>
       <td>Checksum</td>
       <td>Checksum of the command packet</td>
     </tr>
   </table>

   <table>
     <caption align="top">Response Packet Structure</caption>
     <tr>
       <th width=25%>Byte #</th> <th width=25%>Name</th> <th>Meaning</th>
     </tr>
     <tr>
       <td>0</td>
       <td>Count</td>
       <td>Number of bytes in the packet, includes the count byte, body and the checksum</td>
     </tr>
     <tr>
       <td>1</td>
       <td>Status / Data</td>
       <td>Status or first data byte</td>
     </tr>
     <tr>
       <td>2 to n</td>
       <td>More data bytes</td>
       <td>random, challenge response, read data, etc.</td>
     </tr>
     <tr>
       <td>n+1 to n+2</td>
       <td>Checksum</td>
       <td>Checksum of the command packet</td>
     </tr>
   </table>
 */

#ifndef SHA204_H
#   define SHA204_H


/* Word Address Values */
#define SHA204_PACKET_FUNC_RESET     ((uint8_t) 0x00)
#define SHA204_PACKET_FUNC_SLEEP     ((uint8_t) 0x01)
#define SHA204_PACKET_FUNC_IDLE      ((uint8_t) 0x02)
#define SHA204_PACKET_FUNC_CMD       ((uint8_t) 0x03)



#define SHA204_RSP_SIZE_MIN          ((uint8_t)  4)  //!< minimum number of bytes in response
#define SHA204_RSP_SIZE_MAX          ((uint8_t) 35)  //!< maximum size of response packet

#define SHA204_BUFFER_POS_COUNT      (0)             //!< buffer index of count byte in command or response
#define SHA204_BUFFER_POS_DATA       (1)             //!< buffer index of data in response

//! width of Wakeup pulse in 10 us units
#define SHA204_WAKEUP_PULSE_WIDTH    (uint8_t) (6)

//! delay between Wakeup pulse and communication in ms
#define SHA204_WAKEUP_DELAY          (uint8_t) (3)



/** \defgroup atsha204_communication Module 02: Communication
 *
 * This module implements communication with the device. It does not depend on the interface
 * (SWI or I<SUP>2</SUP>C).
 *
 * Basic communication flow:
 * - Calculate CRC of command packet and append.
 * - Send command and repeat if it failed.
 * - Delay for minimum command execution time.
 * - Poll for response until maximum execution time. Repeat if communication failed.
 *
 * Retries are implemented including sending the command again depending on the type
 * of failure. A retry might include waking up the device which will be indicated by
 * an appropriate return status. The number of retries is defined with a macro and
 * can be set to 0 at compile time.
@{ */

//! maximum command delay
#define SHA204_COMMAND_EXEC_MAX      (69)

//! minimum number of bytes in command (from count byte to second CRC byte)
#define SHA204_CMD_SIZE_MIN          ((uint8_t)  7)

//! maximum size of command packet (CheckMac)
#define SHA204_CMD_SIZE_MAX          ((uint8_t) 84)

//! number of CRC bytes
#define SHA204_CRC_SIZE              ((uint8_t)  2)

//! buffer index of status byte in status response
#define SHA204_BUFFER_POS_STATUS     (1)

//! buffer index of first data byte in data response
#define SHA204_BUFFER_POS_DATA       (1)

//! status byte after wake-up
#define SHA204_STATUS_BYTE_WAKEUP    ((uint8_t) 0x11)

//! command parse error
#define SHA204_STATUS_BYTE_PARSE     ((uint8_t) 0x03)

//! command execution error
#define SHA204_STATUS_BYTE_EXEC      ((uint8_t) 0x0F)

//! communication error
#define SHA204_STATUS_BYTE_COMM      ((uint8_t) 0xFF)

/** \defgroup atsha204_command_marshaling Module 01: Command Marshaling
 \brief
 * A function is provided for every ATSHA204 command. These functions check the parameters,
 * assemble a command packet, send it, receive its response, and return the status of the operation
 * and the response.
 *
 * If available code space in your system is tight, you can use instead the sha204m_execute function
 * for any command. It is more complex to use, though. Modern compilers can garbage-collect unused
 * functions. If your compiler does not support this feature and you want to use only the
 * sha204m_execute function, you can just delete the command wrapper functions. If
 * you do use the command wrapper functions, you can respectively delete the sha204m_execute function.
@{ */

/** \name Codes for ATSHA204 Commands
@{ */
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
/** @} */


/** \name Definitions of Data and Packet Sizes
@{ */
#define SHA204_RSP_SIZE_VAL             ((uint8_t)  7)         //!< size of response packet containing four bytes of data
#define SHA204_KEY_SIZE                 (32)                   //!< size of key
#define SHA204_KEY_COUNT                (16)                   //!< number of keys
#define SHA204_CONFIG_SIZE              (88)                   //!< size of configuration zone
#define SHA204_WRITABLE_CONFIG_SIZE     (68)                   //!< 可写的config区大小
#define SHA204_OTP_SIZE                 (64)                   //!< size of OTP zone
#define SHA204_SN_SIZE                  (9)                    //!< SN长度
#define SHA204_DEVREV_SIZE              (4)                    //!< 芯片版本号长度
#define SHA204_DATA_SIZE                (SHA204_KEY_COUNT * SHA204_KEY_SIZE) //!< size of data zone
/** @} */

/** \name Definitions for Command Parameter Ranges
@{ */
#define SHA204_KEY_ID_MAX               (SHA204_KEY_COUNT - 1) //!< maximum value for key id
#define SHA204_OTP_BLOCK_MAX            ( 1)                   //!< maximum value for OTP block
/** @} */

/** \name Definitions for Indexes Common to All Commands
@{ */
#define SHA204_COUNT_IDX                ( 0)                   //!< command packet index for count
#define SHA204_OPCODE_IDX               ( 1)                   //!< command packet index for op-code
#define SHA204_PARAM1_IDX               ( 2)                   //!< command packet index for first parameter
#define SHA204_PARAM2_IDX               ( 3)                   //!< command packet index for second parameter
#define SHA204_DATA_IDX                 ( 5)                   //!< command packet index for data load
/** @} */

/** \name Definitions for Zone and Address Parameters
@{ */
#define SHA204_ZONE_CONFIG              ((uint8_t)  0x00)      //!< Configuration zone
#define SHA204_ZONE_OTP                 ((uint8_t)  0x01)      //!< OTP (One Time Programming) zone
#define SHA204_ZONE_DATA                ((uint8_t)  0x02)      //!< Data zone
#define SHA204_ZONE_MASK                ((uint8_t)  0x03)      //!< Zone mask
#define SHA204_ZONE_COUNT_FLAG          ((uint8_t)  0x80)      //!< Zone bit 7 set: Access 32 bytes, otherwise 4 bytes.
#define SHA204_ZONE_ACCESS_4            ((uint8_t)     4)      //!< Read or write 4 bytes.
#define SHA204_ZONE_ACCESS_32           ((uint8_t)    32)      //!< Read or write 32 bytes.
#define SHA204_ADDRESS_MASK_CONFIG      (         0x001F)      //!< Address bits 5 to 7 are 0 for Configuration zone.
#define SHA204_ADDRESS_MASK_OTP         (         0x000F)      //!< Address bits 4 to 7 are 0 for OTP zone.
#define SHA204_ADDRESS_MASK             (         0x007F)      //!< Address bit 7 to 15 are always 0.
/** @} */

/** \name Definitions for the CheckMac Command
@{ */
#define CHECKMAC_MODE_IDX               SHA204_PARAM1_IDX      //!< CheckMAC command index for mode
#define CHECKMAC_KEYID_IDX              SHA204_PARAM2_IDX      //!< CheckMAC command index for key identifier
#define CHECKMAC_CLIENT_CHALLENGE_IDX   SHA204_DATA_IDX        //!< CheckMAC command index for client challenge
#define CHECKMAC_CLIENT_RESPONSE_IDX    (37)                   //!< CheckMAC command index for client response
#define CHECKMAC_DATA_IDX               (69)                   //!< CheckMAC command index for other data
#define CHECKMAC_COUNT                  (84)                   //!< CheckMAC command packet size
#define CHECKMAC_MODE_CHALLENGE         ((uint8_t) 0x00)       //!< CheckMAC mode       0: first SHA block from key id
#define CHECKMAC_MODE_BLOCK2_TEMPKEY    ((uint8_t) 0x01)       //!< CheckMAC mode bit   0: second SHA block from TempKey
#define CHECKMAC_MODE_BLOCK1_TEMPKEY    ((uint8_t) 0x02)       //!< CheckMAC mode bit   1: first SHA block from TempKey
#define CHECKMAC_MODE_SOURCE_FLAG_MATCH ((uint8_t) 0x04)       //!< CheckMAC mode bit   2: match TempKey.SourceFlag
#define CHECKMAC_MODE_INCLUDE_OTP_64    ((uint8_t) 0x20)       //!< CheckMAC mode bit   5: include first 64 OTP bits
#define CHECKMAC_MODE_MASK              ((uint8_t) 0x27)       //!< CheckMAC mode bits 3, 4, 6, and 7 are 0.
#define CHECKMAC_CLIENT_CHALLENGE_SIZE  (32)                   //!< CheckMAC size of client challenge
#define CHECKMAC_CLIENT_RESPONSE_SIZE   (32)                   //!< CheckMAC size of client response
#define CHECKMAC_OTHER_DATA_SIZE        (13)                   //!< CheckMAC size of "other data"
#define CHECKMAC_CLIENT_COMMAND_SIZE    ( 4)                   //!< CheckMAC size of client command header size inside "other data"
/** @} */

/** \name Definitions for the DeriveKey Command
@{ */
#define DERIVE_KEY_RANDOM_IDX           SHA204_PARAM1_IDX      //!< DeriveKey command index for random bit
#define DERIVE_KEY_TARGETKEY_IDX        SHA204_PARAM2_IDX      //!< DeriveKey command index for target slot
#define DERIVE_KEY_MAC_IDX              SHA204_DATA_IDX        //!< DeriveKey command index for optional MAC
#define DERIVE_KEY_COUNT_SMALL          SHA204_CMD_SIZE_MIN    //!< DeriveKey command packet size without MAC
#define DERIVE_KEY_COUNT_LARGE          (39)                   //!< DeriveKey command packet size with MAC
#define DERIVE_KEY_RANDOM_FLAG          ((uint8_t) 4)          //!< DeriveKey 1. parameter; has to match TempKey.SourceFlag
#define DERIVE_KEY_MAC_SIZE             (32)                   //!< DeriveKey MAC size
/** @} */

/** \name Definitions for the DevRev Command
@{ */
#define DEVREV_PARAM1_IDX               SHA204_PARAM1_IDX      //!< DevRev command index for 1. parameter (ignored)
#define DEVREV_PARAM2_IDX               SHA204_PARAM2_IDX      //!< DevRev command index for 2. parameter (ignored)
#define DEVREV_COUNT                    SHA204_CMD_SIZE_MIN    //!< DevRev command packet size
/** @} */

/** \name Definitions for the GenDig Command
@{ */
#define GENDIG_ZONE_IDX                 SHA204_PARAM1_IDX      //!< GenDig command index for zone
#define GENDIG_KEYID_IDX                SHA204_PARAM2_IDX      //!< GenDig command index for key id
#define GENDIG_DATA_IDX                 SHA204_DATA_IDX        //!< GenDig command index for optional data
#define GENDIG_COUNT                    SHA204_CMD_SIZE_MIN    //!< GenDig command packet size without "other data"
#define GENDIG_COUNT_DATA               (11)                   //!< GenDig command packet size with "other data"
#define GENDIG_OTHER_DATA_SIZE          (4)                    //!< GenDig size of "other data"
#define GENDIG_ZONE_CONFIG              ((uint8_t) 0)          //!< GenDig zone id config
#define GENDIG_ZONE_OTP                 ((uint8_t) 1)          //!< GenDig zone id OTP
#define GENDIG_ZONE_DATA                ((uint8_t) 2)          //!< GenDig zone id data
/** @} */

/** \name Definitions for the HMAC Command
@{ */
#define HMAC_MODE_IDX                   SHA204_PARAM1_IDX      //!< HMAC command index for mode
#define HMAC_KEYID_IDX                  SHA204_PARAM2_IDX      //!< HMAC command index for key id
#define HMAC_COUNT                      SHA204_CMD_SIZE_MIN    //!< HMAC command packet size
#define HMAC_MODE_MASK                  ((uint8_t) 0x74)       //!< HMAC mode bits 0, 1, 3, and 7 are 0.
/** @} */

/** \name Definitions for the Lock Command
@{ */
#define LOCK_ZONE_IDX                   SHA204_PARAM1_IDX      //!< Lock command index for zone
#define LOCK_SUMMARY_IDX                SHA204_PARAM2_IDX      //!< Lock command index for summary
#define LOCK_COUNT                      SHA204_CMD_SIZE_MIN    //!< Lock command packet size
#define LOCK_ZONE_NO_CONFIG             ((uint8_t) 0x01)       //!< Lock zone is OTP or Data
#define LOCK_ZONE_NO_CRC                ((uint8_t) 0x80)       //!< Lock command: Ignore summary.
#define LOCK_ZONE_MASK                  (0x81)                 //!< Lock parameter 1 bits 2 to 6 are 0.
/** @} */

/** \name Definitions for the MAC Command
@{ */
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
#define MAC_CHALLENGE_SIZE              (32)                   //!< MAC size of challenge
#define MAC_DIGEST_SIZE                 (32)                   //!< MAC返回的摘要长度
#define MAC_MODE_MASK                   ((uint8_t) 0x77)       //!< MAC mode bits 3 and 7 are 0.
/** @} */

/** \name Definitions for the Nonce Command
@{ */
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
#define NONCE_NUMIN_SIZE                (20)                   //!< Nonce data length
#define NONCE_RANDOUT_SIZE              (32)                   //!< Nonce 命令返回的随机数长度
#define NONCE_NUMIN_SIZE_PASSTHROUGH    (32)                   //!< Nonce data length in pass-through mode (mode = 3)
/** @} */

/** \name Definitions for the Pause Command
@{ */
#define PAUSE_SELECT_IDX                SHA204_PARAM1_IDX      //!< Pause command index for Selector
#define PAUSE_PARAM2_IDX                SHA204_PARAM2_IDX      //!< Pause command index for 2. parameter
#define PAUSE_COUNT                     SHA204_CMD_SIZE_MIN    //!< Pause command packet size
/** @} */

/** \name Definitions for the Random Command
@{ */
#define RANDOM_MODE_IDX                 SHA204_PARAM1_IDX      //!< Random command index for mode
#define RANDOM_PARAM2_IDX               SHA204_PARAM2_IDX      //!< Random command index for 2. parameter
#define RANDOM_COUNT                    SHA204_CMD_SIZE_MIN    //!< Random command packet size
#define RANDOM_SEED_UPDATE              ((uint8_t) 0x00)       //!< Random mode for automatic seed update
#define RANDOM_NO_SEED_UPDATE           ((uint8_t) 0x01)       //!< Random mode for no seed update
/** @} */

/** \name Definitions for the Read Command
@{ */
#define READ_ZONE_IDX                   SHA204_PARAM1_IDX      //!< Read command index for zone
#define READ_ADDR_IDX                   SHA204_PARAM2_IDX      //!< Read command index for address
#define READ_COUNT                      SHA204_CMD_SIZE_MIN    //!< Read command packet size
#define READ_ZONE_MASK                  ((uint8_t) 0x83)       //!< Read zone bits 2 to 6 are 0.
#define READ_ZONE_MODE_32_BYTES         ((uint8_t) 0x80)       //!< Read mode: 32 bytes
/** @} */

/** \name Definitions for the UpdateExtra Command
@{ */
#define UPDATE_MODE_IDX                  SHA204_PARAM1_IDX     //!< UpdateExtra command index for mode
#define UPDATE_VALUE_IDX                 SHA204_PARAM2_IDX     //!< UpdateExtra command index for new value
#define UPDATE_COUNT                     SHA204_CMD_SIZE_MIN   //!< UpdateExtra command packet size
#define UPDATE_CONFIG_BYTE_86            ((uint8_t) 0x01)      //!< UpdateExtra mode: update Config byte 86
/** @} */

/** \name Definitions for the Write Command
@{ */
#define WRITE_ZONE_IDX                  SHA204_PARAM1_IDX      //!< Write command index for zone
#define WRITE_ADDR_IDX                  SHA204_PARAM2_IDX      //!< Write command index for address
#define WRITE_VALUE_IDX                 SHA204_DATA_IDX        //!< Write command index for data
#define WRITE_MAC_VS_IDX                ( 9)                   //!< Write command index for MAC following short data
#define WRITE_MAC_VL_IDX                (37)                   //!< Write command index for MAC following long data
#define WRITE_COUNT_SHORT               (11)                   //!< Write command packet size with short data and no MAC
#define WRITE_COUNT_LONG                (39)                   //!< Write command packet size with long data and no MAC
#define WRITE_COUNT_SHORT_MAC           (43)                   //!< Write command packet size with short data and MAC
#define WRITE_COUNT_LONG_MAC            (71)                   //!< Write command packet size with long data and MAC
#define WRITE_MAC_SIZE                  (32)                   //!< Write MAC size
#define WRITE_ZONE_MASK                 ((uint8_t) 0xC3)       //!< Write zone bits 2 to 5 are 0.
#define WRITE_ZONE_WITH_MAC             ((uint8_t) 0x40)       //!< Write zone bit 6: write encrypted with MAC
/** @} */

/** \name Response Size Definitions
@{ */
#define CHECKMAC_RSP_SIZE               SHA204_RSP_SIZE_MIN    //!< response size of DeriveKey command
#define DERIVE_KEY_RSP_SIZE             SHA204_RSP_SIZE_MIN    //!< response size of DeriveKey command
#define DEVREV_RSP_SIZE                 SHA204_RSP_SIZE_VAL    //!< response size of DevRev command returns 4 bytes
#define GENDIG_RSP_SIZE                 SHA204_RSP_SIZE_MIN    //!< response size of GenDig command
#define HMAC_RSP_SIZE                   SHA204_RSP_SIZE_MAX    //!< response size of HMAC command
#define LOCK_RSP_SIZE                   SHA204_RSP_SIZE_MIN    //!< response size of Lock command
#define MAC_RSP_SIZE                    SHA204_RSP_SIZE_MAX    //!< response size of MAC command
#define NONCE_RSP_SIZE_SHORT            SHA204_RSP_SIZE_MIN    //!< response size of Nonce command with mode[0:1] = 3
#define NONCE_RSP_SIZE_LONG             SHA204_RSP_SIZE_MAX    //!< response size of Nonce command
#define PAUSE_RSP_SIZE                  SHA204_RSP_SIZE_MIN    //!< response size of Pause command
#define RANDOM_RSP_SIZE                 SHA204_RSP_SIZE_MAX    //!< response size of Random command
#define READ_4_RSP_SIZE                 SHA204_RSP_SIZE_VAL    //!< response size of Read command when reading 4 bytes
#define READ_32_RSP_SIZE                SHA204_RSP_SIZE_MAX    //!< response size of Read command when reading 32 bytes
#define UPDATE_RSP_SIZE                 SHA204_RSP_SIZE_MIN    //!< response size of UpdateExtra command
#define WRITE_RSP_SIZE                  SHA204_RSP_SIZE_MIN    //!< response size of Write command
/** @} */


/** \name Definitions of Typical Command Execution Times
 * The library starts polling the device for a response after these delays.
@{ */
//! CheckMac command typical execution time
#define CHECKMAC_DELAY                  (12)

//! DeriveKey command typical execution time
#define DERIVE_KEY_DELAY                (14)

//! DevRev command typical execution time
// We set the delay value to 1.0 instead of 0.4 because we have to make sure that we don't poll immediately.
#define DEVREV_DELAY                    (1))

//! GenDig command typical execution time
#define GENDIG_DELAY                    (11)

//! HMAC command typical execution time
#define HMAC_DELAY                      (27)

//! Lock command typical execution time
#define LOCK_DELAY                      (5)

//! MAC command typical execution time
#define MAC_DELAY                       (12)

//! Nonce command typical execution time
#define NONCE_DELAY                     (22)

//! Pause command typical execution time
// We set the delay value to 1.0 instead of 0.4 because we have to make sure that we don't poll immediately.
#define PAUSE_DELAY                     (1))

//! Random command typical execution time
#define RANDOM_DELAY                    (11)

//! Read command typical execution time
// We set the delay value to 1.0 instead of 0.4 because we have to make sure that we don't poll immediately.
#define READ_DELAY                      (1))

//! UpdateExtra command typical execution time
#define UPDATE_DELAY                    (8)

//! Write command typical execution time
#define WRITE_DELAY                     (4)
/** @} */


/** \name Definitions of Maximum Command Execution Times
@{ */
//! CheckMAC maximum execution time
#define CHECKMAC_EXEC_MAX                (38)

//! DeriveKey maximum execution time
#define DERIVE_KEY_EXEC_MAX              (62)

//! DevRev maximum execution time
#define DEVREV_EXEC_MAX                  (2)

//! GenDig maximum execution time
#define GENDIG_EXEC_MAX                  (43)

//! HMAC maximum execution time
#define HMAC_EXEC_MAX                    (69)

//! Lock maximum execution time
#define LOCK_EXEC_MAX                    (24)

//! MAC maximum execution time
#define MAC_EXEC_MAX                     (35)

//! Nonce maximum execution time
#define NONCE_EXEC_MAX                   (60)

//! Pause maximum execution time
#define PAUSE_EXEC_MAX                   (2)

//! Random maximum execution time
#define RANDOM_EXEC_MAX                  (50)

//! Read maximum execution time
#define READ_EXEC_MAX                    (4)

//! UpdateExtra maximum execution time
#define UPDATE_EXEC_MAX                  (12)

//! Write maximum execution time
#define WRITE_EXEC_MAX                   (42)
/** @} */


#endif
#ifdef __cplusplus
}
#endif
