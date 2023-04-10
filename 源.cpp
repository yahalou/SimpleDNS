#define _CRT_SECURE_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define CACHENUM 300
#include<stdio.h>
#include<string.h>
#include<malloc.h>
#include<Windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdlib.h>
#include<time.h>
// Need to link with Ws2_32.lib
#pragma comment (lib, "Ws2_32.lib")

#define DEFAULT_BUFLEN 1000	
#define DEFAULT_PORT 53

//微软提供的解决10054错误方法
#define IOC_VENDOR 0x18000000
#define _WSAIOW(x,y) (IOC_IN|(x)|(y))
#define SIO_UDP_CONNRESET _WSAIOW(IOC_VENDOR,12)
DWORD  dwByteReturned = 0;
BOOL bNewBehavior = FALSE;
DWORD status;
//

char* cacheIP[CACHENUM];//IP缓存
char* cacheName[CACHENUM];//域名缓存
char dns_server[16];//上级dns
char path[200];
int debugLevel;
clock_t start;
//dns报文首部，用位域，注意小端转大端
struct DNS_HEADER {
    unsigned short id;      //会话标识
    unsigned char rd : 1;   // 表示期望递归
    unsigned char tc : 1;   // 表示可截断的
    unsigned char aa : 1;   //  表示授权回答
    unsigned char opcode : 4;   //响应码，0无错误，3不存在域名
    unsigned char qr : 1; //  查询/响应标志，0为查询，1为响应
    unsigned char rcode : 4; //应答码
    unsigned char cd : 1;
    unsigned char ad : 1;
    unsigned char z : 1;    //保留值
    unsigned char ra : 1;   // 表示可用递归
    unsigned short q_count; // 表示查询问题区域节的数量
    unsigned short ans_count; // 表示回答区域的数量
    unsigned short auth_count; // 表示授权区域的数量
    unsigned short add_count; // 表示附加区域的数量
};

//dns报文中查询问题区域
struct QUESTION {   
    unsigned short qtype;   //查询类型
    unsigned short qclass;  //查询类
};
typedef struct {
    unsigned char* name;    //域名
    struct QUESTION* ques;
} QUERY;

#pragma pack(push, 1)//保存对齐状态，设定为1字节对齐
//回答区域报文的常量字段
struct R_DATA {
    unsigned short type;        //表示资源记录的类型
    unsigned short _class;      //类
    unsigned int ttl;           //表示资源记录可以缓存的时间
    unsigned short data_len;    //数据长度
};
#pragma pack(pop) //恢复对齐状态

//DNS报文中回答区域字段
struct RES_RECORD {
    unsigned char* name;    //资源记录包含的域名，压缩标签
    struct R_DATA* resource;//资源数据
    unsigned char* rdata;   //ip地址
};

//读取本地文件
void LoadCache(char* path)
{
    int i, j;
    for (i = 0; i < CACHENUM; i++)
    {
        cacheIP[i] = NULL;
        cacheName[i] = NULL;
    }
    FILE* fp = 0;
    char strbuf[300];//读取文件缓存
    if ((fp = fopen(path, "r")) == 0)
    {
        printf("打开文件失败\n");
        return;
    }
    i = 0;
    while (1)
    {
        //清空读取缓存
        memset(strbuf, 0, sizeof(strbuf));
        //读取
        if (fgets(strbuf, 300, fp) == 0) break;
        
        char* tempIP = (char*)malloc(sizeof(char) * 20);
        char* tempName = (char*)malloc(sizeof(char) * 100);

        int x = 0;
        //读ip地址
        for (j = 0; strbuf[j] != ' '; j++)
        {
            tempIP[x] = strbuf[j];
            x++;
        }
        tempIP[x] = 0;
        //读域名
        x = 0;
        for (j = j + 1; strbuf[j] != '\n'; j++)
        {
            tempName[x] = strbuf[j];
            x++;
        }
        tempName[x] = 0;
        //ip和域名后面都有'\0'
        cacheIP[i] = (char*)malloc(sizeof(char) * strlen(tempIP)+1);
        cacheName[i] = (char*)malloc(sizeof(char) * strlen(tempName)+1);
        for (j = 0; j < strlen(tempIP); j++)
        {
            cacheIP[i][j] = tempIP[j];
        }
        cacheIP[i][j] = 0;
        for (j = 0; j < strlen(tempName); j++)
        {
            cacheName[i][j] = tempName[j];
        }
        cacheName[i][j] = 0;

        free(tempIP);
        free(tempName);
        i++;
    }
    fclose(fp);
    printf("读取本地文件完成\n");
}

//在本地查找ip，1表示在本地有效，2表示本地无效，3表示向上查找，找到了就传给第二个参数
int searchInCache(char* name,char** ip)
{
    int i;
    for (i = 0; cacheName[i] != NULL; i++)
    {
        if (strcmp(name, cacheName[i]) == 0)
        { 
            if (strcmp(cacheIP[i], "0.0.0.0") == 0)
            {
                if(debugLevel==1||debugLevel==2)
                printf("0.0.0.0\n");
                return 2;
            }
            else {
                *ip = cacheIP[i];
                if (debugLevel == 1||debugLevel==2)
                printf("%s\n", *ip);
                return 1;
            }
        }
    }
    if (cacheName[i] == NULL)
    {
        if (debugLevel == 1)
        printf("未找到，向上级查询\n");
        return 3;
    }
}

//解析接收的查询报文，获取域名
char* queryNameByRecieve(unsigned char* recvbuf)
{
    unsigned char* answer;
    unsigned char * reader;//光标
    struct DNS_HEADER* dns = NULL;
    dns = (struct DNS_HEADER*)recvbuf;
    reader = &recvbuf[sizeof(struct DNS_HEADER)];
    char* queryName = (char*)malloc(sizeof(char) * 100);
    char* temp = queryName;
    reader++;//跳过开头的数字
    while (*reader)
    {
        if (*reader >= 0 && *reader <= 32)//把数字都变成.
        {
            *queryName = '.';
        }
        else *queryName = *reader;
        queryName++;
        reader++;
    }
    *queryName = 0;//变成字符串
    if (debugLevel == 1||debugLevel==2)
    {
        clock_t end=(clock() - start) / CLOCKS_PER_SEC;
        printf("%d ", end);
        printf("%s ", temp);
    }
    
    return temp;
}

//在本地中找到且是普通IP地址
void SendBackGoodResult(struct sockaddr_in* SenderAddr, SOCKET* RecvSocket, unsigned char* recvbuf,char* ip)
{
    int iResult;
    //填充要发送的内容
    unsigned char sendbuf[DEFAULT_BUFLEN], * write;
    memset(sendbuf, 0, sizeof(sendbuf));
    struct DNS_HEADER* dns = NULL;
    struct DNS_HEADER* recvHeader = NULL;
    struct RES_RECORD* rinfo = NULL;
    recvHeader = (struct DNS_HEADER*)recvbuf;//查询报文的编号
    dns = (struct DNS_HEADER*)&sendbuf;
    /*设置DNS报文首部*/
    dns->id = recvHeader->id;
    dns->qr = 1; //响应
    dns->opcode = 0; //标准查询
    dns->aa = 1; //权威回答
    dns->tc = 0; //不可截断
    dns->rd = 1; //期望递归
    dns->ra = 0; //不可用递归
    dns->z = 0; //必须为0
    dns->ad = 0;
    dns->cd = 0;
    dns->rcode = 0;//没有差错
    dns->q_count = htons(1); //1个问题
    dns->ans_count = htons(1);//1个answer
    dns->auth_count = 0;
    dns->add_count = 0;

    unsigned char* sendQuery = &recvbuf[sizeof(struct DNS_HEADER)];//dns首部后，查询部分的开头
    //填充queries，跟查询报文的查询部分一样
    write = (unsigned char*)&sendbuf[sizeof(struct DNS_HEADER)];
    while (*sendQuery != 0)
    {
        *write = *sendQuery;
        write++;
        sendQuery++;
    }
    *write = *sendQuery;
    write++;
    sendQuery++;

    int i;
    for (i = 0; i < sizeof(struct QUESTION); i++)
    {
        *write = *sendQuery;
        write++;
        sendQuery++;
    }

    //填充响应报文
    UINT16 offset = htons(0xc00c);//压缩标签
    struct R_DATA rresource;
    rresource.type = htons(1);
    rresource.ttl = htonl(600);
    rresource.data_len = htons(4);
    rresource._class = htons(1);
    //rinfo包括name,resource,rdata
    rinfo = (struct RES_RECORD*)&sendbuf[sizeof(struct DNS_HEADER) + strlen((char*)&sendbuf[sizeof(struct DNS_HEADER)]) + 1 + i];
    rinfo->name = (unsigned char*)&offset;

    unsigned int addr = inet_addr(ip);//地址4个字节，inet_addr自动转为大端
    rinfo->resource = &rresource;
    rinfo->rdata = (unsigned char*)&addr;
    memcpy(write, &offset, sizeof(offset));
    write += sizeof(offset);
    memcpy(write, &rresource, sizeof(struct R_DATA));
    write += sizeof(struct R_DATA);
    memcpy(write, (char*)&addr, sizeof(addr));
    write += sizeof(addr);

    iResult = sendto(*RecvSocket, (char*)sendbuf, write - sendbuf, 0, (SOCKADDR*)SenderAddr, sizeof(SOCKADDR));
    if (iResult == SOCKET_ERROR) {
        printf("send failed with error: %d\n", WSAGetLastError());
        WSACleanup();
        return;
    }
    if (debugLevel == 2) printf("向%s发送回答报文成功\n", inet_ntoa(SenderAddr->sin_addr));
}

//在本地中找到且是不存在的域名
void SendBackBadResult(struct sockaddr_in* SenderAddr, SOCKET* RecvSocket, unsigned char* recvbuf)
{
    int iResult;
    //填充要发送的内容
    unsigned char sendbuf[DEFAULT_BUFLEN], * write;
    struct DNS_HEADER* dns = NULL;
    struct DNS_HEADER* sendDns = NULL;
    struct RES_RECORD* rinfo = NULL;
    sendDns = (struct DNS_HEADER*)recvbuf;
    dns = (struct DNS_HEADER*)&sendbuf;
    /*设置DNS报文首部*/
    dns->id = sendDns->id;
    dns->qr = 1; //响应
    dns->opcode = 0; //标准查询
    dns->aa = 1; //权威回答
    dns->tc = 0; //不可截断
    dns->rd = 1; //期望递归
    dns->ra = 0; //不可用递归
    dns->z = 0; //必须为0
    dns->ad = 0;
    dns->cd = 0;
    dns->rcode = 3;//no such name
    dns->q_count = htons(1); //1个问题
    dns->ans_count = htons(0);//0个answer
    dns->auth_count = 0;
    dns->add_count = 0;

    unsigned char* sendQuery = &recvbuf[sizeof(struct DNS_HEADER)];
    //填充QUERY
    write = (unsigned char*)&sendbuf[sizeof(struct DNS_HEADER)];
    while (*sendQuery != 0)
    {
        *write = *sendQuery;
        write++;
        sendQuery++;
    }
    *write = *sendQuery;
    write++;
    sendQuery++;
    int i;
    for (i = 0; i < sizeof(struct QUESTION); i++)
    {
        *write = *sendQuery;
        write++;
        sendQuery++;
    }

    iResult = sendto(*RecvSocket, (char*)sendbuf, write - sendbuf, 0, (SOCKADDR*)SenderAddr, sizeof(SOCKADDR));
    if (iResult == SOCKET_ERROR) {
        printf("send failed with error: %d\n", WSAGetLastError());
        WSACleanup();
        return;
    }
    if (debugLevel == 2) printf("向%s发送回答报文成功\n", inet_ntoa(SenderAddr->sin_addr));
}

//向上级dns查找
void LookUp(SOCKET* RecvSocket, struct sockaddr_in* SenderAddr, unsigned char* recvbuf, int length)
{
    int iResult;
    struct sockaddr_in SendAddr;//调整端口参数

    SendAddr.sin_family = AF_INET;
    SendAddr.sin_port = htons(GetCurrentProcessId());//以当前进程为端口号
    SendAddr.sin_addr.S_un.S_addr = htonl(INADDR_ANY);//接收上级dns发回的报文时使用
    SOCKET SendSocket = INVALID_SOCKET;//建立连接的socket
    SendSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (SendSocket == INVALID_SOCKET) {
        wprintf(L"socket failed with error %d\n", WSAGetLastError());
        return;
    }
    iResult = bind(SendSocket, (SOCKADDR*)&SendAddr, sizeof(SendAddr));
    if (iResult != 0) {
        printf("here\n");
        wprintf(L"bind failed with error %d\n", WSAGetLastError());
        return;
    }

    unsigned char buf[DEFAULT_BUFLEN];

    struct sockaddr_in fromAddr;
    //调整发送端口参数
    SendAddr.sin_family = AF_INET;//目标端口
    SendAddr.sin_port = htons(53);
    SendAddr.sin_addr.S_un.S_addr = inet_addr(dns_server);
    iResult = sendto(SendSocket, (char*)recvbuf, length, 0, (SOCKADDR*)&SendAddr, sizeof(SOCKADDR));
    if (iResult == SOCKET_ERROR) {
        printf("send failed with error: %d\n", WSAGetLastError());
        WSACleanup();
        return;
    }
    if (debugLevel == 2) printf("转发给dns %s 成功\n",inet_ntoa(SendAddr.sin_addr));
    //接收dns发回的信息
    int len = sizeof(fromAddr);
    int nNetTimeout = 2000;//2000ms
    if (SOCKET_ERROR == setsockopt(SendSocket, SOL_SOCKET, SO_RCVTIMEO, (char*)&nNetTimeout, sizeof(int)))
    {
        printf("Set Ser_RecTIMEO error !\r\n");
    }
    iResult = recvfrom(SendSocket, (char*)buf, DEFAULT_BUFLEN, 0, (SOCKADDR*)&fromAddr, &len);
    if (iResult == SOCKET_ERROR) {
        printf("recieve failed with error: %d\n", WSAGetLastError());
        WSACleanup();
        return;
    }
    if (iResult < 0)
    {
        printf("recv timeout! %d\n", iResult);
        return;
    }
    if (debugLevel == 2) printf("收到来自dns的回答\n");
    //转发给主机
    iResult = sendto(*RecvSocket, (char*)buf, iResult, 0, (SOCKADDR*)SenderAddr, sizeof(SOCKADDR));
    if (iResult == SOCKET_ERROR) {
        printf("send failed with error: %d\n", WSAGetLastError());
        WSACleanup();
        return;
    }
    if (debugLevel == 2) printf("转发回主机成功\n");
    closesocket(SendSocket);
}

//检查输入
int checkInput(int argc, char* argv[])
{
    memset(dns_server, 0, sizeof(dns_server));
    memset(path, 0, sizeof(path));
    if (argc == 1)
    {
        strcpy(dns_server, "192.168.5.1");
        strcpy(path, "dnsrelay.txt");
        debugLevel = 0;
    }
    else if (argc == 2)
    {
        if (strcmp(argv[1], "-d") == 0)
        {
            strcpy(dns_server, "192.168.5.1");
            strcpy(path, "dnsrelay.txt");
            debugLevel = 1;
        }
        else if (strcmp(argv[1], "-dd") == 0)
        {
            strcpy(dns_server, "192.168.5.1");
            strcpy(path, "dnsrelay.txt");
            debugLevel = 2;
        }
        else {
            printf("Usage: SimpleDNS [-d | -dd] [dns-server-ipaddr] [filename] \n");
            return 0;
        }
    }
    else if (argc == 3)
    {
        if (strcmp(argv[1], "-d") == 0)
        {
            strcpy(dns_server, argv[2]);
            strcpy(path, "dnsrelay.txt");
            debugLevel = 1;
        }
        else if (strcmp(argv[1], "-dd") == 0)
        {
            strcpy(dns_server, argv[2]);
            strcpy(path, "dnsrelay.txt");
            debugLevel = 2;
        }
        else {
            printf("Usage: SimpleDNS [-d | -dd] [dns-server-ipaddr] [filename] \n");
            return 0;
        }
    }
    else if (argc == 4)
    {
        if (strcmp(argv[1], "-d") == 0)
        {
            strcpy(dns_server, argv[2]);
            strcpy(path, argv[3]);
            debugLevel = 1;
        }
        if (strcmp(argv[1], "-dd") == 0)
        {
            strcpy(dns_server, argv[2]);
            strcpy(path, argv[3]);
            debugLevel = 2;
        }
        else {
            printf("Usage: SimpleDNS [-d | -dd] [dns-server-ipaddr] [filename] \n");
            return 0;
        }
    }
    else
    {
        printf("Usage: SimpleDNS [-d | -dd] [dns-server-ipaddr] [filename] \n");
        return 0;
    }
    return 1;
}

int main(int argc, char* argv[])
{
    start = clock();
    if (!checkInput(argc, argv)) return 0;
    LoadCache(path);

    //初始化wsa
    WSADATA wsaData;
    int iResult;
    
    //建立连接的socket
    SOCKET RecvSocket = INVALID_SOCKET;
    struct sockaddr_in RecvAddr;//发送方的信息
    struct addrinfo* result = NULL;

    unsigned char recvbuf[DEFAULT_BUFLEN];
    int recvbuflen = DEFAULT_BUFLEN;

    struct sockaddr_in SenderAddr;
    int SenderAddrSize = sizeof(SenderAddr);

    // Initialize Winsock
    iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (iResult != 0) {
        printf("WSAStartup failed with error: %d\n", iResult);
        return 1;
    }
    // Create a receiver socket to receive datagrams
    RecvSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (RecvSocket == INVALID_SOCKET) {
        wprintf(L"socket failed with error %d\n", WSAGetLastError());
        return 1;
    }
    // Bind the socket to any address and the specified port.
    RecvAddr.sin_family = AF_INET;
    RecvAddr.sin_port = htons(DEFAULT_PORT);
    RecvAddr.sin_addr.s_addr = htonl(INADDR_ANY);

    iResult = bind(RecvSocket, (SOCKADDR*)&RecvAddr, sizeof(RecvAddr));
    if (iResult != 0) {
        printf("there\n");
        wprintf(L"bind failed with error %d\n", WSAGetLastError());
        return 1;
    }

    //忽略10045错误
    BOOL bEnalbeConnRestError = FALSE;
    DWORD dwBytesReturned = 0;
    WSAIoctl(RecvSocket, SIO_UDP_CONNRESET, &bEnalbeConnRestError, sizeof(bEnalbeConnRestError), NULL, 0, &dwBytesReturned, NULL, NULL);
    //
    
    //循环接收报文
    while (1)
    {
        iResult = recvfrom(RecvSocket, (char*)recvbuf, DEFAULT_BUFLEN, 0, (SOCKADDR*)&SenderAddr, &SenderAddrSize);
        if (iResult < 0 && iResult == 0)
        {
            wprintf(L"recvfrom failed with error %d\n", WSAGetLastError());
            break;
        }
        if (iResult == SOCKET_ERROR) {
            wprintf(L"recvfrom failed with error %d\n", WSAGetLastError());
            break;
        }
        char* senderIP = inet_ntoa(SenderAddr.sin_addr);//记录发送主机的ip

        if(debugLevel==2) printf("收到来自%s的询问报文\n",senderIP);

        //解析出要的地址
        char* queryName = queryNameByRecieve(recvbuf);
        //在本地查找
        char* ip = (char*)malloc(20);
        int result = searchInCache(queryName,&ip);
        switch (result)
        {
        case 1://本地有效
            SendBackGoodResult(&SenderAddr, &RecvSocket, recvbuf, ip);
            break;
        case 2://本地无效
            SendBackBadResult(&SenderAddr, &RecvSocket, recvbuf);
            break;
        case 3://向上查找
            LookUp(&RecvSocket, &SenderAddr, recvbuf, iResult);
            break;
        }
    }

    // shutdown the connection since we're done
    iResult = shutdown(RecvSocket, SD_SEND);
    if (iResult == SOCKET_ERROR) {
        printf("shutdown failed with error: %d\n", WSAGetLastError());
        closesocket(RecvSocket);
        WSACleanup();
        return 1;
    }

    // cleanup
    closesocket(RecvSocket);
    WSACleanup();
}