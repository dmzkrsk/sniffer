#include <windows.h>
#include "sniffer.h"

using namespace std;

DWORD WINAPI ProcessPacket(LPVOID ptd);
#define num(A) itoa(A, tmp_num, 10);

CRITICAL_SECTION g_cs;
outstack g_stack(&cout);
HANDLE g_copyevent;
int LoadScript();

int find_ips(string &str);
int find_hosts(string &str);
v_act g_actlist;

string& str_replace(const char* what, const char* with, string& where)
{
	int len=lstrlen(what);
	int first=-len;
	while((first=where.find(what, first+len))!=string::npos)
		where.replace(first, len, with);

	return where;
}

int str_split(string& str, const char* del, v_str &arr)
{
	int parts=0;
	int len=lstrlen(del);
	int first=-len, last=0;
	while((first=str.find(del, first+len))!=string::npos)
	{
		arr.push_back(str.substr(last, first-last));
		last=first+len;
		parts++;
	}
	arr.push_back(str.substr(last));
	parts++;

	return parts;
}

void main(int argc, char** argv)
{
	WSADATA wsadata;		// Инициализация WinSock.
	SOCKET s;				// Cлущающий сокет.
	char name[128];			// Имя хоста (компьютера).
	HOSTENT* phe;			// Информация о хосте.
	SOCKADDR_IN sa;			// Адрес хоста
	unsigned long flag=1; // Флаг PROMISC Вкл/выкл.
	static char Buffer[MAX_PACKET_SIZE]; // // Буфер для приёма данных 64 Kb

	int packet_counter=0;
	g_copyevent=CreateEvent(NULL,TRUE, FALSE, NULL);

	int datamode=MODE_HEADER;
	if(argc==2)
	{
		if(!strcmp(argv[1], "data")) datamode=MODE_HEADER|MODE_DATA;
		if(!strcmp(argv[1], "dataonly")) datamode=MODE_DATA;
	}

// инициализация
	WSAStartup(MAKEWORD(2,2), &wsadata);
	s=socket(AF_INET, SOCK_RAW, IPPROTO_IP);
	gethostname(name, sizeof(name));
	phe=gethostbyname(name);
	ZeroMemory(&sa, sizeof(sa));
	sa.sin_family=AF_INET;
	sa.sin_addr.s_addr=((struct in_addr *)phe->h_addr_list[0])->s_addr;
	bind(s,(SOCKADDR*)&sa, sizeof(SOCKADDR));
	LoadScript();
	cerr<<"sniffing started for "<<name<<"("<<inet_ntoa(sa.sin_addr)<<")"<<endl;
	cerr<<"source           destination         protocol ttl"<<endl;

// Включение promiscuous mode.
	ioctlsocket(s, SIO_RCVALL, &flag);
	DWORD dwThread;
	HANDLE hThread;

// Приём IP-пакетов.
	ThreadData td;
	InitializeCriticalSection(&g_cs);

	while(1)
	{
		int count;
		count = recv(s, Buffer, sizeof(Buffer), 0);
// обработка IP-пакета
		if(count >= sizeof(IPHeader))
		{
			ResetEvent(g_copyevent);
			td.ip_packet=Buffer;
			td.datamode=datamode;
			td.host=sa.sin_addr.s_addr;
			td.packet=packet_counter++;
			td.size=count;
			hThread=CreateThread(NULL, NULL, ProcessPacket, (void*)&td, NULL, &dwThread);
			WaitForSingleObject(g_copyevent, INFINITE);
			CloseHandle(hThread);
		}
	}
// Конец работы.
	CloseHandle(g_copyevent);
	DeleteCriticalSection(&g_cs);
	closesocket(s);
	WSACleanup();
}

DWORD WINAPI ProcessPacket(LPVOID ptd)
{
	ThreadData *td=(ThreadData*)ptd;
	Packet pack((IPHeader*)td->ip_packet);
	int datamode=td->datamode;
	int packet=td->packet;
	unsigned long host=td->host;
	SetEvent(g_copyevent);

	char tmp_num[16];
	string obuff="";

	if(!pack.IsIPv4())
	{
		EnterCriticalSection(&g_cs);
		g_stack.add(obuff, packet);
		LeaveCriticalSection(&g_cs);
		cerr<<"unknown packet recieved\n";
		return 1;
	}

	if(datamode&MODE_HEADER)
	{
		obuff+="\n";

		obuff+=pack.GetProtocolAbbr();
		obuff+=" ";
		obuff+=pack.GetSourceIpStr();
		if(pack.is_data) obuff+=s(":")+num(pack.port_src);
		obuff+=" ";
		obuff+=pack.GetDestinationIpStr();
		if(pack.is_data) obuff+=s(":")+num(pack.port_dest);
		obuff+=" ";
		obuff+=num(pack.length_data);
//		obuff+=num(pack.ttl);
//		obuff+="\n";
	}

	if(datamode&MODE_DATA && pack.is_data)
		obuff+=pack.data;

	EnterCriticalSection(&g_cs);
	g_stack.add(obuff, packet);
	LeaveCriticalSection(&g_cs);
	return 0;
}

int LoadScript()
{
	ifstream file;
	string line;
	file.open("settings.snf", ios::in);
	v_str parts;
	
	action act;
	while(getline(file, line, '\n'))
	{
		parts.erase(parts.begin(), parts.end());
		if(str_split(line, ";", parts)!=4) continue;
		act.resolve=!parts[0].compare("name");
		act.condition=parts[1];

		str_replace("#tcp", "6", act.condition);
		str_replace("#udp", "17", act.condition);
		find_ips(act.condition);
		find_hosts(act.condition);

		act.action_header=parts[2];
		act.action_data=parts[3];

		g_actlist.push_back(act);
	}

	return g_actlist.size();
}

int find_ips(string &str)
{
	int nIn=0;
	string tmp="";
	string replace;
	v_str parts;
	char tmp_num[16];
	for(int a=0;a<str.length();a++)
	{
		if(str[a]=='#' && nIn==0) {nIn=1;continue;}
		if(str[a]=='i' && nIn==1) {nIn=2;continue;}
		if(str[a]=='p' && nIn==2) {nIn=3;continue;}
		if(str[a]==':' && nIn==3) {nIn=4;continue;}

		if(((str[a]>='0' && str[a]<='9') || str[a]=='.' || str[a]==':') && nIn==4)
			tmp+=str[a];

		if(nIn==4 && (!((str[a]>='0' && str[a]<='9') || str[a]=='.' || str[a]==':')||a==str.length()-1))
		{
			parts.erase(parts.begin(), parts.end());
			switch(str_split(tmp, ":", parts))
			{
			case 1:
				replace=num(inet_addr(tmp.data()));
				tmp="#ip:"+tmp;
				str_replace(tmp.data(), replace.data(), str);
				a+=(replace.length()-tmp.length());
				break;
			case 2:
				replace=num(inet_addr(parts[0].data()));
				replace+=s(" and $port=")+parts[1];
				tmp="#ip:"+tmp;
				str_replace(tmp.data(), replace.data(), str);
				a+=(replace.length()-tmp.length());
				break;
			}
			tmp="";
			nIn=0;
		}
	}

	return 0;
}

bool host_digit(char a)
{
	if(a>='0' && a<='9') return true;
	if(a>='a' && a<='z') return true;
	if(a>='A' && a<='Z') return true;
	if(a=='-' || a=='+' || a=='.' || a=='_' || a==':') return true;

	return false;
}

int find_hosts(string &str)
{
	int nIn=0;
	string tmp="";
	string replace;
	v_str parts;
	char tmp_num[16];
	hostent *he;

	for(int a=0;a<str.length();a++)
	{
		if(str[a]=='#' && nIn==0) {nIn=1;continue;}
		if(str[a]=='h' && nIn==1) {nIn=2;continue;}
		if(str[a]=='o' && nIn==2) {nIn=3;continue;}
		if(str[a]=='s' && nIn==3) {nIn=4;continue;}
		if(str[a]=='t' && nIn==4) {nIn=5;continue;}
		if(str[a]==':' && nIn==5) {nIn=6;continue;}

		if(host_digit(str[a]) && nIn==6)
			tmp+=str[a];

		if(nIn==6 && (!host_digit(str[a]) || a==str.length()-1))
		{
			parts.erase(parts.begin(), parts.end());
			switch(str_split(tmp, ":", parts))
			{
			case 1:
				he=gethostbyname(tmp.data());
				if(he) replace=num(*(int*)he->h_addr)
				else replace="0";
				tmp="#host:"+tmp;
				str_replace(tmp.data(), replace.data(), str);
				a+=(replace.length()-tmp.length());
				break;
			case 2:
				he=gethostbyname(parts[0].data());
				if(he) replace=num(*(int*)he->h_addr)
				else replace="0";
				replace+=s(" and $port=")+parts[1];
				tmp="#host:"+tmp;
				str_replace(tmp.data(), replace.data(), str);
				a+=(replace.length()-tmp.length());
				break;
			}
			tmp="";
			nIn=0;
		}
	}

	return 0;
}
