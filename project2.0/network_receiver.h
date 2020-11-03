/**
 * Name         : newtwork_receiver.h 
 * Author       : Qu Xiangjun
 * Version      : 2.0
 * Date         : 2020-11-1
 * Description  : network datagram receiver function, and analysis datagram.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "crc16.h"

unsigned char my_address[4] =  {0x00,0x00,0x00,0x02};

unsigned char Source_address[4],Destination_address[4]; // 来源地址和目的地址
// unsigned char datagram[65535];
unsigned char Version;
unsigned char IHL;
unsigned char Differentialted_Services; 
unsigned short Total_length;
unsigned short Identification; 
unsigned char DF; 
unsigned char MF; 
unsigned short Fragment_offset; 
unsigned char TTL; 
unsigned char Protocol; 
unsigned short Header_checksum;
unsigned char Source_address[4];
unsigned char Destination_address[4];
unsigned char *Option; 
unsigned int Option_len;
unsigned char *payload; 
unsigned short payload_len;

/**
 * print octal number 
 * @x octal array
 * @len octal array's length
 **/
int output_octal(unsigned char *x, unsigned int len){
    unsigned int i;
    for (i = 0; i < len; i++)
    {
        printf("%02x", x[i]);
        if (i != len - 1)
            printf(" ");
        if (i % 9 == 0 && i != 0)
            printf("\n");
    }
    printf("\n");
    return 0;
}

/**
 * check address (char array, length = 6 Bytes)
 * @des_addr received frame's destination address
 * @return flag: the resul of check (boolean) 
 **/
int addr_check(unsigned char des_addr[4], unsigned char my_addr[4]){
    int flag = 1;
    int i = 0;
    for (i = 0; i < 4; i++){
        if (des_addr[i] != my_addr[i])
            flag = 0;
    }
    if (flag){
        printf("[INFO] Address check success!\n");
    } else{
        printf("[Error] Address check error!\n");
        printf("[Error] Destination address : ");
        output_octal(des_addr, 4);
    }
    return flag;
}

int analyse_datagram(unsigned char * datagram,unsigned int datagram_len){
    /* 取Version 和 IHL */
    unsigned char temp;
    memcpy(&temp, datagram[0],1);
    Version = temp & 0xF0;
    Version = Version >> 4;
    IHL = temp & 0x0F;

    memcpy(&Differentialted_Services,&datagram[1],1);
    memcpy(&Total_length,&datagram[2],2);
    memcpy(&Identification,&datagram[4],2);
    
    /* 取DF、MF、Fragment Offset */
    memcpy(&Fragment_offset,&datagram[6],2);
    DF = Fragment_offset & 0x4000;
    DF = DF >> 14;
    MF = Fragment_offset & 0x2000;
    MF = MF >> 13;
    Fragment_offset  = Fragment_offset & 0x1fff;

    memcpy(&TTL,&datagram[8],1);
    memcpy(&Protocol,&datagram[9],1);
    memcpy(&Header_checksum,&datagram[10],2);
    memcpy(&Source_address,&datagram[12],4);
    memcpy(&Destination_address,&datagram[16],4);
    
    /* 取Option */
    Option_len = IHL;
    Option_len -= 5; // 比header少五行
    memcpy(&Option,&datagram[20],Option_len * 4);

    /* 取payload */
    payload_len = Total_length - (Option_len + 5) * 4;
    memcpy(&payload,&datagram[20+Option_len*4],payload_len);

    /* 地址验证 */
    if (!addr_check(des_addr, my_addr))
        exit(1);

    /* 校验crc16 */
    unsigned char Header[IHL * 4 - 2];
    memcpy(&Header[0],&datagram[0],10);
	memcpy(&Header[10],&datagram[12],8 + Option_len * 4);
    unsigned short crc16_result = CRC16(Header,IHL * 4 - 2);
    if(Header_checksum != crc16_result){  // crc16 校验失败
        printf("[Error] CRC16 check error!\n");
        printf("[Error] datagram's CRC16 : ");
        printf("%02x%02x\n", datagram[10], datagram[11]);
        printf("[Error] calculated CRC16 : ");
        printf("%04x\n",crc16_result);
        exit(1);
    }

    /* print frame information */ 
    printf("******receive datagrame information******\n");
    printf("Source address: ");
    output_octal(Source_address,4);
    printf("Destination address  : ");
    output_octal(Destination_address,4);
    printf("payload      : %s\n",payload);
    printf("CRC16        : ");
    printf("%04x\n",crc16_result); 
    printf("payload length  : %d\n", payload_len);
    printf("Header length   : %d(row*4bytes)\n", IHL);
    printf("datagram length : %d\n", Total_length);
    printf("**************************************\n");
    printf("[INFO] datagram received success!\n");

    /**/
}