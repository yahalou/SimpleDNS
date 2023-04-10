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

//΢���ṩ�Ľ��10054���󷽷�
#define IOC_VENDOR 0x18000000
#define _WSAIOW(x,y) (IOC_IN|(x)|(y))
#define SIO_UDP_CONNRESET _WSAIOW(IOC_VENDOR,12)
DWORD  dwByteReturned = 0;
BOOL bNewBehavior = FALSE;
DWORD status;
//

char* cacheIP[CACHENUM];//IP����
char* cacheName[CACHENUM];//��������
char dns_server[16];//�ϼ�dns
char path[200];
int debugLevel;
clock_t start;
//dns�����ײ�����λ��ע��С��ת���
struct DNS_HEADER {
    unsigned short id;      //�Ự��ʶ
    unsigned char rd : 1;   // ��ʾ�����ݹ�
    unsigned char tc : 1;   // ��ʾ�ɽضϵ�
    unsigned char aa : 1;   //  ��ʾ��Ȩ�ش�
    unsigned char opcode : 4;   //��Ӧ�룬0�޴���3����������
    unsigned char qr : 1; //  ��ѯ/��Ӧ��־��0Ϊ��ѯ��1Ϊ��Ӧ
    unsigned char rcode : 4; //Ӧ����
    unsigned char cd : 1;
    unsigned char ad : 1;
    unsigned char z : 1;    //����ֵ
    unsigned char ra : 1;   // ��ʾ���õݹ�
    unsigned short q_count; // ��ʾ��ѯ��������ڵ�����
    unsigned short ans_count; // ��ʾ�ش����������
    unsigned short auth_count; // ��ʾ��Ȩ���������
    unsigned short add_count; // ��ʾ�������������
};

//dns�����в�ѯ��������
struct QUESTION {   
    unsigned short qtype;   //��ѯ����
    unsigned short qclass;  //��ѯ��
};
typedef struct {
    unsigned char* name;    //����
    struct QUESTION* ques;
} QUERY;

#pragma pack(push, 1)//�������״̬���趨Ϊ1�ֽڶ���
//�ش������ĵĳ����ֶ�
struct R_DATA {
    unsigned short type;        //��ʾ��Դ��¼������
    unsigned short _class;      //��
    unsigned int ttl;           //��ʾ��Դ��¼���Ի����ʱ��
    unsigned short data_len;    //���ݳ���
};
#pragma pack(pop) //�ָ�����״̬

//DNS�����лش������ֶ�
struct RES_RECORD {
    unsigned char* name;    //��Դ��¼������������ѹ����ǩ
    struct R_DATA* resource;//��Դ����
    unsigned char* rdata;   //ip��ַ
};

//��ȡ�����ļ�
void LoadCache(char* path)
{
    int i, j;
    for (i = 0; i < CACHENUM; i++)
    {
        cacheIP[i] = NULL;
        cacheName[i] = NULL;
    }
    FILE* fp = 0;
    char strbuf[300];//��ȡ�ļ�����
    if ((fp = fopen(path, "r")) == 0)
    {
        printf("���ļ�ʧ��\n");
        return;
    }
    i = 0;
    while (1)
    {
        //��ն�ȡ����
        memset(strbuf, 0, sizeof(strbuf));
        //��ȡ
        if (fgets(strbuf, 300, fp) == 0) break;
        
        char* tempIP = (char*)malloc(sizeof(char) * 20);
        char* tempName = (char*)malloc(sizeof(char) * 100);

        int x = 0;
        //��ip��ַ
        for (j = 0; strbuf[j] != ' '; j++)
        {
            tempIP[x] = strbuf[j];
            x++;
        }
        tempIP[x] = 0;
        //������
        x = 0;
        for (j = j + 1; strbuf[j] != '\n'; j++)
        {
            tempName[x] = strbuf[j];
            x++;
        }
        tempName[x] = 0;
        //ip���������涼��'\0'
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
    printf("��ȡ�����ļ����\n");
}

//�ڱ��ز���ip��1��ʾ�ڱ�����Ч��2��ʾ������Ч��3��ʾ���ϲ��ң��ҵ��˾ʹ����ڶ�������
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
        printf("δ�ҵ������ϼ���ѯ\n");
        return 3;
    }
}

//�������յĲ�ѯ���ģ���ȡ����
char* queryNameByRecieve(unsigned char* recvbuf)
{
    unsigned char* answer;
    unsigned char * reader;//���
    struct DNS_HEADER* dns = NULL;
    dns = (struct DNS_HEADER*)recvbuf;
    reader = &recvbuf[sizeof(struct DNS_HEADER)];
    char* queryName = (char*)malloc(sizeof(char) * 100);
    char* temp = queryName;
    reader++;//������ͷ������
    while (*reader)
    {
        if (*reader >= 0 && *reader <= 32)//�����ֶ����.
        {
            *queryName = '.';
        }
        else *queryName = *reader;
        queryName++;
        reader++;
    }
    *queryName = 0;//����ַ���
    if (debugLevel == 1||debugLevel==2)
    {
        clock_t end=(clock() - start) / CLOCKS_PER_SEC;
        printf("%d ", end);
        printf("%s ", temp);
    }
    
    return temp;
}

//�ڱ������ҵ�������ͨIP��ַ
void SendBackGoodResult(struct sockaddr_in* SenderAddr, SOCKET* RecvSocket, unsigned char* recvbuf,char* ip)
{
    int iResult;
    //���Ҫ���͵�����
    unsigned char sendbuf[DEFAULT_BUFLEN], * write;
    memset(sendbuf, 0, sizeof(sendbuf));
    struct DNS_HEADER* dns = NULL;
    struct DNS_HEADER* recvHeader = NULL;
    struct RES_RECORD* rinfo = NULL;
    recvHeader = (struct DNS_HEADER*)recvbuf;//��ѯ���ĵı��
    dns = (struct DNS_HEADER*)&sendbuf;
    /*����DNS�����ײ�*/
    dns->id = recvHeader->id;
    dns->qr = 1; //��Ӧ
    dns->opcode = 0; //��׼��ѯ
    dns->aa = 1; //Ȩ���ش�
    dns->tc = 0; //���ɽض�
    dns->rd = 1; //�����ݹ�
    dns->ra = 0; //�����õݹ�
    dns->z = 0; //����Ϊ0
    dns->ad = 0;
    dns->cd = 0;
    dns->rcode = 0;//û�в��
    dns->q_count = htons(1); //1������
    dns->ans_count = htons(1);//1��answer
    dns->auth_count = 0;
    dns->add_count = 0;

    unsigned char* sendQuery = &recvbuf[sizeof(struct DNS_HEADER)];//dns�ײ��󣬲�ѯ���ֵĿ�ͷ
    //���queries������ѯ���ĵĲ�ѯ����һ��
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

    //�����Ӧ����
    UINT16 offset = htons(0xc00c);//ѹ����ǩ
    struct R_DATA rresource;
    rresource.type = htons(1);
    rresource.ttl = htonl(600);
    rresource.data_len = htons(4);
    rresource._class = htons(1);
    //rinfo����name,resource,rdata
    rinfo = (struct RES_RECORD*)&sendbuf[sizeof(struct DNS_HEADER) + strlen((char*)&sendbuf[sizeof(struct DNS_HEADER)]) + 1 + i];
    rinfo->name = (unsigned char*)&offset;

    unsigned int addr = inet_addr(ip);//��ַ4���ֽڣ�inet_addr�Զ�תΪ���
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
    if (debugLevel == 2) printf("��%s���ͻش��ĳɹ�\n", inet_ntoa(SenderAddr->sin_addr));
}

//�ڱ������ҵ����ǲ����ڵ�����
void SendBackBadResult(struct sockaddr_in* SenderAddr, SOCKET* RecvSocket, unsigned char* recvbuf)
{
    int iResult;
    //���Ҫ���͵�����
    unsigned char sendbuf[DEFAULT_BUFLEN], * write;
    struct DNS_HEADER* dns = NULL;
    struct DNS_HEADER* sendDns = NULL;
    struct RES_RECORD* rinfo = NULL;
    sendDns = (struct DNS_HEADER*)recvbuf;
    dns = (struct DNS_HEADER*)&sendbuf;
    /*����DNS�����ײ�*/
    dns->id = sendDns->id;
    dns->qr = 1; //��Ӧ
    dns->opcode = 0; //��׼��ѯ
    dns->aa = 1; //Ȩ���ش�
    dns->tc = 0; //���ɽض�
    dns->rd = 1; //�����ݹ�
    dns->ra = 0; //�����õݹ�
    dns->z = 0; //����Ϊ0
    dns->ad = 0;
    dns->cd = 0;
    dns->rcode = 3;//no such name
    dns->q_count = htons(1); //1������
    dns->ans_count = htons(0);//0��answer
    dns->auth_count = 0;
    dns->add_count = 0;

    unsigned char* sendQuery = &recvbuf[sizeof(struct DNS_HEADER)];
    //���QUERY
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
    if (debugLevel == 2) printf("��%s���ͻش��ĳɹ�\n", inet_ntoa(SenderAddr->sin_addr));
}

//���ϼ�dns����
void LookUp(SOCKET* RecvSocket, struct sockaddr_in* SenderAddr, unsigned char* recvbuf, int length)
{
    int iResult;
    struct sockaddr_in SendAddr;//�����˿ڲ���

    SendAddr.sin_family = AF_INET;
    SendAddr.sin_port = htons(GetCurrentProcessId());//�Ե�ǰ����Ϊ�˿ں�
    SendAddr.sin_addr.S_un.S_addr = htonl(INADDR_ANY);//�����ϼ�dns���صı���ʱʹ��
    SOCKET SendSocket = INVALID_SOCKET;//�������ӵ�socket
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
    //�������Ͷ˿ڲ���
    SendAddr.sin_family = AF_INET;//Ŀ��˿�
    SendAddr.sin_port = htons(53);
    SendAddr.sin_addr.S_un.S_addr = inet_addr(dns_server);
    iResult = sendto(SendSocket, (char*)recvbuf, length, 0, (SOCKADDR*)&SendAddr, sizeof(SOCKADDR));
    if (iResult == SOCKET_ERROR) {
        printf("send failed with error: %d\n", WSAGetLastError());
        WSACleanup();
        return;
    }
    if (debugLevel == 2) printf("ת����dns %s �ɹ�\n",inet_ntoa(SendAddr.sin_addr));
    //����dns���ص���Ϣ
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
    if (debugLevel == 2) printf("�յ�����dns�Ļش�\n");
    //ת��������
    iResult = sendto(*RecvSocket, (char*)buf, iResult, 0, (SOCKADDR*)SenderAddr, sizeof(SOCKADDR));
    if (iResult == SOCKET_ERROR) {
        printf("send failed with error: %d\n", WSAGetLastError());
        WSACleanup();
        return;
    }
    if (debugLevel == 2) printf("ת���������ɹ�\n");
    closesocket(SendSocket);
}

//�������
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

    //��ʼ��wsa
    WSADATA wsaData;
    int iResult;
    
    //�������ӵ�socket
    SOCKET RecvSocket = INVALID_SOCKET;
    struct sockaddr_in RecvAddr;//���ͷ�����Ϣ
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

    //����10045����
    BOOL bEnalbeConnRestError = FALSE;
    DWORD dwBytesReturned = 0;
    WSAIoctl(RecvSocket, SIO_UDP_CONNRESET, &bEnalbeConnRestError, sizeof(bEnalbeConnRestError), NULL, 0, &dwBytesReturned, NULL, NULL);
    //
    
    //ѭ�����ձ���
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
        char* senderIP = inet_ntoa(SenderAddr.sin_addr);//��¼����������ip

        if(debugLevel==2) printf("�յ�����%s��ѯ�ʱ���\n",senderIP);

        //������Ҫ�ĵ�ַ
        char* queryName = queryNameByRecieve(recvbuf);
        //�ڱ��ز���
        char* ip = (char*)malloc(20);
        int result = searchInCache(queryName,&ip);
        switch (result)
        {
        case 1://������Ч
            SendBackGoodResult(&SenderAddr, &RecvSocket, recvbuf, ip);
            break;
        case 2://������Ч
            SendBackBadResult(&SenderAddr, &RecvSocket, recvbuf);
            break;
        case 3://���ϲ���
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