#pragma comment(lib, "ws2_32.lib")
#define s(A) string(A)
#pragma warning(disable:4786)
#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <map>
using namespace std;

typedef map<int, string> m_str;

class outstack
{
private:
	m_str m_stack;
	ostream* out;

	int m_last;
public:
	outstack(ostream*);
	int add(string&, int);
};

typedef struct
{
	unsigned char verlen;	// версия и длина заголовка
	unsigned char tos;		// тип сервиса 
	unsigned short length;	// длина всего пакета 
	unsigned short id;		// Id 
	unsigned short offset;	// флаги и смещения 
	unsigned char ttl;		// время жизни 
	unsigned char protocol; // протокол 
	unsigned short xsum;	// контрольная сумма 
	unsigned long src;		// IP-адрес отправителя 
	unsigned long dest;		// IP-адрес назначения 
}IPHeader;

typedef struct
{
	unsigned short port_src;
	unsigned short port_dest;
	unsigned short length;
	unsigned short checksum;
}UDPHeader;

typedef struct
{
	unsigned short port_src;
	unsigned short port_dest;
	unsigned long sequence;
	unsigned long ack;
	unsigned short offctrl;
	unsigned short window;
	unsigned short checksum;
	unsigned short urgent;
}TCPHeader;

typedef struct
{
	char* ip_packet;
	int size;
	int datamode;
	unsigned long host;
	int packet;
}ThreadData;

class Packet
{
private:
	m_str protocols;
	char str_ip_dest[256];
	char str_ip_src[256];

	void init_tcp(IPHeader* iph);
	void init_udp(IPHeader* iph);
public:
	unsigned char version;
	unsigned char length_header;
	unsigned short length_packet;
	unsigned short length_data;

	struct
	{
		unsigned char precedence;
		bool delay;
		bool throughput;
		bool reliability;
		unsigned char raw_tos;
	}tos;
	
	bool fragmented;
	bool fraggable;
	unsigned short offset;
	unsigned char protocol;
	unsigned short xsum;
	unsigned char ttl;
	unsigned long ip_src;
	unsigned long ip_dest;
	unsigned short port_src;
	unsigned short port_dest;
	char* data;

	bool is_data;
public:
	bool IsIPv4();
	const char* GetProtocolAbbr();
	char* GetSourceIpStr();
	char* GetDestinationIpStr();
public:
	Packet(IPHeader* iph);
	~Packet();
};

#define SIO_RCVALL 0x98000001

#define MAX_PACKET_SIZE 0x10000	//максимальный размер пакета

#define MODE_HEADER	0x01
#define MODE_DATA	0x02

typedef struct
{
	bool resolve;
	string condition;
	string action_header;
	string action_data;
}action;

typedef vector<action> v_act;
typedef vector<string> v_str;