
#include <arpa/inet.h>
#include <getopt.h>
#include "xtool.h"
#include "CDDoSParams.h"
#include "CDDoSParser.h"
#include "CAttack.h"
#include "rapidjson/document.h"
#include "rapidjson/writer.h"
#include "rapidjson/stringbuffer.h"
#include <iostream>
#include <fstream>
#include <string>
#include <cassert>
#include "rapidjson/filereadstream.h"
#include "stdio.h"
#include "ipparser.h"


using namespace rapidjson;
using namespace std;

/*xtool --attack [syn|ack|udp|http|https|dns] --speed 1000 --duration 60 --count 250 --thread 3
--sip x.x.x.x/x --dip x.x.x.x/x --sport xx --dport xx 
--tcpflag xx 
--domain xxxxxx.com 
--path xxxxx
--method GET|POST
--paylen 250
--vlan 250
--ttl 63
--fw
--conn 250
--browser
--bot
--cnc x.x.x.x*/
static struct option g_ddos_long_options[] =
{
		{"help",  no_argument,       NULL, 'h'},
		{"attack",  required_argument,       NULL, 'a'},
		{"speed",  required_argument,       NULL, 's'},
		{"duration", required_argument, NULL, 'd'},
		{"count", required_argument, NULL, 'c'},
		{"thread", required_argument, NULL, 't'},
		{"sip", required_argument, NULL, 'S'},
		{"dip", required_argument, NULL, 'D'},
		{"sport", required_argument, NULL, 'P'},
		{"dport", required_argument, NULL, 'Q'},
		//{"tcpflag", required_argument, NULL, 'T'},
		{"host", required_argument, NULL, 'H'},
		{"url", required_argument, NULL, 'A'},
		//{"vlan", required_argument, NULL, 'V'},
		{"paylen", required_argument, NULL, 'O'},
		{"payload-data", required_argument, NULL, 'M'}, //payload�����ַ���
		{"payload-type", required_argument, NULL, 'N'},// hex ascii ����ú�����������Ĭ��Ϊhex����
		{"ttl", required_argument, NULL, 'L'},
		//{"ack-fw", no_argument, NULL, 'R'},
		// {"ack-sock", no_argument, NULL, 'Z'},
		//{"method", required_argument, NULL, 'U'},
		// {"conn", required_argument, NULL, 'W'},
		{"browser", no_argument, NULL, 'X'},
		//{"ack-bot", no_argument, NULL, 'Y'},
		{"cnc", required_argument, NULL, 'z'},
		//{"cnc-port", required_argument, NULL, 'y'},
		// {"monlist", no_argument, NULL, 'x'},
		{ "http", required_argument, NULL, 'B' },   //����http���ֶΣ�
		{ "https", required_argument, NULL, 'G' },   //����http���ֶΣ�
		{ "sip_attack", required_argument, NULL, 'E' },   //����sip���ֶΣ�sip=0 ��ʾINVITE sip=1��ʾREGISTER
		//{ "icmp-type", required_argument, NULL, 'F' },   //����icmp_type���ֶΣ�icmp_type=0 ��ʾreply, icmp_type=8 ��ʾrequest
		{ "relay_ip", required_argument, NULL, 'f' },
		{ "options", required_argument, NULL, 'j' },
		{ "client_mac", required_argument, NULL, 'I' },
		{ "msg_type", required_argument, NULL, 'R' },
		{ "ipv6_address", required_argument, NULL, 'F' },
		{ "ipv4_address", required_argument, NULL, 'T' },
		{ "json", required_argument, NULL, 'J' }, 
		{ "ipv6", no_argument, NULL, 'i' }, //open ipv6 flag
		{"server_duid", required_argument, NULL, 'U'},
		{"client_duid", required_argument, NULL, 'W'},
		{"PD", no_argument, NULL, 'Y'},
		{"TA", no_argument, NULL, 'y'},
		{"mac_start", required_argument, NULL, 'V'},
		{"iaid", required_argument, NULL, 'Z'},
		{"bootp", no_argument, NULL, 'x'},

		{"syn64", no_argument, NULL, 0},
		{"random-domain", no_argument, NULL, 0},
		{0, 0, 0, 0}
};

const static char *g_ddos_short_opts = "ha:s:d:c:t:S:D:P:Q:T:H:A:V:O:L:R:U:W:XYZz:y:x:B:E:F:M:N:G:J:i:f:j:I";

CDDoSParser::CDDoSParser() {
	// TODO Auto-generated constructor stub

}

CDDoSParser::~CDDoSParser() {
	// TODO Auto-generated destructor stub
}

int CDDoSParser::parse_json(CDDoSParam * param){
     if(param == NULL)
		return RC_ERROR;
	using rapidjson::Document;
	using std::string;
    using std::ifstream;
	
	
	std::string stringFromStream;
	std::ifstream in;
	in.open(JSON_CONF_FILE, ifstream::in);
	if (!in.is_open()){
		RC_LOG_ERROR("json: cannot open json file.");
		return RC_ERROR;
	}
        
	
	string line;
	 while (getline(in, line)) {
		 stringFromStream.append(line + "\n");
	 }
	 in.close();
	 
	 RC_LOG_INFO("\n\n %s\n\n",stringFromStream.c_str());

	rapidjson::Document doc;
    doc.Parse(stringFromStream.c_str());
    if (doc.HasParseError()) {
        rapidjson::ParseErrorCode code = doc.GetParseError();
        //psln(code);
        printf("json file format is utf-8(unuse bom)? please check!");
        RC_LOG_ERROR("json file format is utf-8(unuse bom)? please check!\nerrorcode:%d %d",code,doc.GetErrorOffset());
        return RC_ERROR;
    }   
	
	

    char buff[1500];
    // use values in parse result.
    using rapidjson::Value;
	 Value & contents = doc["attack_list"];
	RC_LOG_INFO("start parse json\n");
    if (contents.IsArray()) {
        for (size_t i = 0; i < contents.Size(); ++i) {
          Value & v = contents[i];
            assert(v.IsObject());
		    
		    string s ;

            if (v.HasMember("name") && v["name"].IsString()) {
				s = v["name"].GetString();
				if(strcmp(s.c_str(), param->m_json_name)!=0){
					continue;//如果name不相等直接跳到下个循�?
				}
			 }
             //查找到了对应的json_name
			
			if (param->m_payload_data == NULL&&v.HasMember("payload-data") && v["payload-data"].IsString()) {
                s = v["payload-data"].GetString();
				if(hex2str(buff, s.c_str(), s.length())==-1){
					RC_LOG_ERROR("json: json parse [payload-data] error.");
                    return RC_ERROR;  
				}
				
				param->set_payload_data(buff, s.length()/2);
			}


			int type=ATK_VEC_MAX;
			if (v.HasMember("attack-type") && v["attack-type"].IsString()) {
                s = v["attack-type"].GetString();
				type = parse_type(s.c_str());	
			}
            /*
			if(type == ATK_VEC_ACK){
				if (v.HasMember("tcp-options") && v["tcp-options"].IsString()){
					s = v["tcp-options"].GetString();
					if(hex2str(buff, s.c_str(), s.length())==-1){
						return RC_ERROR;  
					}
					int buf_len = s.length()/2;
					if( (buf_len/4) ==0  && buf_len<=40){
						util_strncpy(param->m_tcp_options,buff,buf_len);
						param->m_tcpoptionflag = buf_len;
					}else{
						return RC_ERROR;  
					}
			
				}					
			}*/

			
			return RC_OK;
           
        }
    }
	
    return RC_OK;//not find json_name
}



ATTACK_VECTOR CDDoSParser::parse_type(const char* typeStr)
{
	if (strcmp(typeStr, "syn") == 0)
	{
		return ATK_VEC_SYN;
	}   
	else if (strcmp(typeStr, "ack") == 0)
	{
		return ATK_VEC_ACK;
	}
	else if (strcmp(typeStr, "udp") == 0)
	{
		return ATK_VEC_UDP;
	}
	else if (strcmp(typeStr, "icmp") == 0)
	{
		return ATK_VEC_ICMP;
	}
	else if (strcmp(typeStr, "dns") == 0)
	{
		return ATK_VEC_DNS;
	}
	else if (strcmp(typeStr, "http") == 0)
	{
		return ATK_VEC_HTTP;
	}
	else if (strcmp(typeStr, "https") == 0)
	{
		return ATK_VEC_HTTPS;
	}
	else if (strcmp(typeStr, "ntp") == 0)
	{
		return ATK_VEC_NTP;
	}

	return ATK_VEC_INVALID;
}	



void CDDoSParser::Usage(const char *pragram)
{
	printf("Usage: \n");
	//printf("%-8s --attack [syn|ack|udp|http|https|dns|ntp|icmp ] \n", pragram);
	printf("%-8s --speed xxx (pps, not precise, just for control speed in this version)\n", "");
	printf("%-8s --count xxx (packet count to continous)\n", "");
	printf("%-8s --thread xxx \n", "");
	printf("%-8s --sip x.x.x.x\n", "");
	printf("%-8s --dip x.x.x.x\n", "");
	printf("%-8s --sport xxx\n", "");
	printf("%-8s --dport xxx\n", "");
	printf("%-8s --ipv4 or --ipv6, default ipv4\n", "");
	printf("%-8s --msg_type 13(12+1):relay_solicit, 16:relay_confirm, 17:relay_renew, 18:relay_rebind, 20:relay_release, 21:relay_decline when dhcpv6 \n", "");
	printf("%-8s --msg_type 1:relay_discover, 3:relay_renew, 4:relay_decline, 7:relay_release when dhcpv4 \n", "");
	printf("%-8s --ipv6_address 2001::1 or 2001::/64 or 2002::2e#2002::3e(only support solicit)\n", "" );
	printf("%-8s --ipv4_address 10.1.1.109\n", "");
	printf("%-8s --bootp send the bootp resquest when msg_type=3, only for ipv4\n", "");
	printf("%-8s --client_mac ababab121212(ab:ab:ab:12:12:12)\n", "");
	printf("%-8s --PD send the prefix packet\n", "");
	printf("%-8s --TA send the IATA packet(only support solicit)\n", "");
	printf("%-8s --client_duid(only support dhcpv6)\n", "");
	printf("%-8s --server_duid include dhcpv6 server duid and dhcpv4 server id\n", "");
	printf("%-8s --option 3d1b00636973636f2d636330322e326233302e303030302d4661302f30(only support dhcpv4)\n", "");
	printf("%-8s --mac_start mac address strart\n", "");
	printf("%-8s --iaid simulate the window system dhcpv6 request(the normal length is 8bit, only for ipv6)\n", "");

	printf("DHCPv4 parameter declaration:\n");
	printf("%-2s if client_mac is  lost, the default mac address start 00:00:00:00:00:01. \n", "");
	printf("%-2s the client_mac and option is the optional parameter. \n", "");

	printf("%s \n", "For Example:");
	printf("DHCPv4 discover:\n");
	printf("%-2s --attack udp --dip 10.10.10.40 --dport 67 --sport 67 --sip 10.10.10.45  --speed 1 --count 1 --msg_type 1\n", "");	
	printf("%-2s --attack udp --dip 10.10.10.40 --dport 67 --sport 67 --sip 10.10.10.45  --speed 1 --count 1 --msg_type 1 --client_mac ababab121212\n", "");
	printf("%-2s --attack udp --dip 10.10.10.40 --dport 67 --sport 67 --sip 10.10.10.45  --speed 1 --count 1 --msg_type 1 --option 39020480\n", "");
	printf("%-2s ***\n", "");	
	printf("%-2s the default option include option 53 and 55. \n", "");	
	printf("%-2s ***\n", "");
	printf("\n");

	printf("DHCPv4 renew:\n");
	printf("%-2s --attack udp --dip 10.10.10.40 --dport 67 --sport 67 --sip 10.10.10.45  --speed 1 --count 1 --msg_type 3 --ipv4_address 10.1.109.220\n", "");	
	printf("%-2s --attack udp --dip 10.10.10.40 --dport 67 --sport 67 --sip 10.10.10.45  --speed 1 --count 1 --msg_type 3 --ipv4_address 10.1.109.220 --client_mac ababab121212 \n", "");	
	printf("%-2s --attack udp --dip 10.10.10.40 --dport 67 --sport 67 --sip 10.10.10.45  --speed 1 --count 1 --msg_type 3 --ipv4_address 10.1.109.220 --option 39020480\n", "");	
	printf("%-2s --attack udp --dip 10.10.10.40 --dport 67 --sport 67 --sip 10.10.10.45  --speed 1 --count 1 --msg_type 3 --bootp \n", "");
	printf("%-2s ***\n", "");
	printf("%-2s the default option include option 53 and 55. \n", "");
	printf("%-2s the ipv4_address is indispensable. \n", "");
	printf("%-2s ***\n", "");
	printf("\n");

	printf("DHCPv4 release:\n");
	printf("%-2s --attack udp --dip 10.10.10.40 --dport 67 --sport 67 --sip 10.10.10.45  --speed 1 --count 1 --msg_type 7 --server_duid 36040a016d29 --ipv4_address 10.1.109.220\n", "");	
	printf("%-2s --attack udp --dip 10.10.10.40 --dport 67 --sport 67 --sip 10.10.10.45  --speed 1 --count 1 --msg_type 7 --server_duid 36040a016d29 --ipv4_address 10.1.109.220 --client_mac ababab121212 \n", "");	
	printf("%-2s --attack udp --dip 10.10.10.40 --dport 67 --sport 67 --sip 10.10.10.45  --speed 1 --count 1 --msg_type 7 --server_duid 36040a016d29 --ipv4_address 10.1.109.220 --option 39020480\n", "");	
	printf("%-2s ***\n", "");
	printf("%-2s the default option include option 53 and 54. \n", "");
	printf("%-2s the server_duid and ipv4_address is indispensable. \n", "");
	printf("%-2s ***\n", "");
	printf("\n");	

	printf("DHCPv4 decline:\n");
	printf("%-2s --attack udp --dip 10.10.10.40 --dport 67 --sport 67 --sip 10.10.10.45  --speed 1 --count 1 --msg_type 4 --ipv4_address 10.1.109.230\n", "");	
	printf("%-2s --attack udp --dip 10.10.10.40 --dport 67 --sport 67 --sip 10.10.10.45  --speed 1 --count 1 --msg_type 4 --ipv4_address 10.1.109.230 --client_mac ababab121212 \n", "");	
	printf("%-2s --attack udp --dip 10.10.10.40 --dport 67 --sport 67 --sip 10.10.10.45  --speed 1 --count 1 --msg_type 4 --ipv4_address 10.1.109.230 --option 39020480\n", "");	
	printf("%-2s ***\n", "");
	printf("%-2s the default option include option 53 and 50. \n", "");
	printf("%-2s the server_duid and ipv4_address is indispensable. \n", "");
	printf("%-2s ***\n", "");
	printf("\n");

	printf("DHCPv4 inform:\n");
	printf("%-2s --attack udp --dip 10.10.10.40 --dport 67 --sport 67 --sip 10.10.10.45  --speed 1 --count 1 --msg_type 8\n", "");	
	printf("%-2s --attack udp --dip 10.10.10.40 --dport 67 --sport 67 --sip 10.10.10.45  --speed 1 --count 1 --msg_type 8 --client_mac ababab121212\n", "");
	printf("%-2s --attack udp --dip 10.10.10.40 --dport 67 --sport 67 --sip 10.10.10.45  --speed 1 --count 1 --msg_type 8 --option 39020480\n", "");
	printf("%-2s ***\n", "");	
	printf("%-2s the default option include option 53 and 55. \n", "");	
	printf("%-2s ***\n", "");
	printf("\n");

	printf("\n");
	printf("DHCPv6 relay_solicit:\n");
	printf("%-2s  --attack udp --dip 2001::40 --dport 547 --sport 547 --sip 2001::46 --msg_type 13 --speed 1  --ipv6\n", "");
	printf("%-2s  --attack udp --dip 2001::40 --dport 547 --sport 547 --sip 2001::46 --msg_type 13 --speed 1  --iaid aabbccdd --client_duid 00010001234ecc25005056b17032 --ipv6\n", "");
	printf("%-2s  --attack udp --dip 2001::40 --dport 547 --sport 547 --sip 2001::46 --msg_type 13 --speed 1  --ipv6 --ipv6_address 2002::2e#2002::3e\n", "");
	printf("%-2s  --attack udp --dip 2001::40 --dport 547 --sport 547 --sip 2001::46 --msg_type 13 --speed 1  --ipv6 --client_duid 00010001234ecc25005056b17032 --ipv6_address 2002::2e\n", "");
	printf("%-2s  ***options client_duid and ipv6_address is the optional parameter***\n", "");
	//printf("%-4s dip address must be the link_local address when ipv6\n", "");

	printf("\n");
	printf("DHCPv6 relay_request:\n");
	printf("%-2s  --attack udp --dip 2001::40 --dport 547 --sport 547 --sip 2001::45 --speed 1  --ipv6 --msg_type 15 --ipv6_address 2002::2e --server_duid 000100012350193e005056b15054\n", "");
	printf("%-2s  --attack udp --dip 2001::43 --dport 547 --sport 547 --sip 2001::45 --speed 1  --ipv6 --msg_type 15 --ipv6_address 2002::2e --server_duid 000100012350193e005056b15054 --client_duid 00010001234ecc25005056b17032\n", "");
	printf("%-2s  ***options client_duid is the optional parameter***\n", "");
	
	printf("\n");
	printf("DHCPv6 relay_renew:\n");
	printf("%-2s  --attack udp --dip 2001::40 --dport 547 --sport 547 --sip 2001::45 --speed 1  --ipv6 --msg_type 17 --ipv6_address 2002::2e --server_duid 000100012350193e005056b15054\n", "");
	printf("%-2s  --attack udp --dip 2001::40 --dport 547 --sport 547 --sip 2001::45 --speed 1  --ipv6 --msg_type 17 --ipv6_address 2002::2e --server_duid 000100012350193e005056b15054 --client_duid 00010001234ecc25005056b17032\n", "");
	printf("%-2s  ***options client_duid is the optional parameter***\n", "");
	
	printf("\n");
	printf("DHCPv6 relay_rebind:\n");
	printf("%-2s --attack udp --dip 2001::40 --dport 547 --sport 547 --sip 2001::45 --speed 1  --ipv6 --msg_type 18 --ipv6_address 2002::2e\n", "");
	printf("%-2s --attack udp --dip 2001::40 --dport 547 --sport 547 --sip 2001::45 --speed 1  --ipv6 --msg_type 18 --ipv6_address 2002::2e --client_duid 00010001234ecc25005056b17032\n", "");
	printf("%-2s ***options client_duid is the optional parameter***\n", "");
	printf("\n");
	printf("DHCPv6 relay_confirm:\n");
	printf("%-2s --attack udp --dip 2001::40 --dport 547 --sport 547 --sip 2001::45 --speed 1  --ipv6 --msg_type 16 --ipv6_address 2002::2e\n", "");
	printf("%-2s --attack udp --dip 2001::40 --dport 547 --sport 547 --sip 2001::45 --speed 1  --ipv6 --msg_type 16 --ipv6_address 2002::2e --client_duid 00010001234ecc25005056b17032\n", "");
	printf("%-2s ***options client_duid is the optional parameter***\n", "");
	
	printf("\n");
	printf("DHCPv6 relay_release:\n");
	printf("%-2s --attack udp --dip 2001::40 --dport 547 --sport 547 --sip 2001::45 --speed 1  --ipv6 --msg_type 20 --ipv6_address 2002::2e --server_duid 000100012350193e005056b15054 \n", "");
	printf("%-2s --attack udp --dip 2001::40 --dport 547 --sport 547 --sip 2001::45 --speed 1  --ipv6 --msg_type 20 --ipv6_address 2002::2e --server_duid 000100012350193e005056b15054  --client_duid 00010001234ecc25005056b17032\n", "");
	printf("%-2s ***options client_duid is the optional parameter***\n", "");
	
	printf("\n");
	printf("DHCPv6 relay_decline:\n");
	printf("%-2s --attack udp --2001::40 --dport 547 --sport 547 --sip 2001::45 --speed 1  --ipv6 --msg_type 21 --ipv6_address 2002::2e --server_duid 000100012350193e005056b15054 \n", "");
	printf("%-2s --attack udp --dip 2001::40 --dport 547 --sport 547 --sip 2001::45 --speed 1  --ipv6 --msg_type 21 --ipv6_address 2002::2e --server_duid 000100012350193e005056b15054  --client_duid 00010001234ecc25005056b17032\n", "");
	printf("%-2s ***options client_duid is the optional parameter***\n", "");

	printf("\n");
	printf("DHCPv6 relay information-request:\n");
	printf("%-2s --attack udp --dip 2002::41 --dport 547 --sport 547 --sip 2001::45 --speed 1  --ipv6 --msg_type 23 \n", "");
	printf("%-2s --attack udp --dip fe80::250:56ff:feb1:5054 --dport 547 --sport 547 --sip 2001::45 --speed 1  --ipv6 --msg_type 23 --client_duid 00010001234ecc25005056b17032\n", "");

	printf("\n");
	printf("DHCPv6 relay prefix delegation:\n");
	printf("%-2s  --attack udp --dip 2001::40 --dport 547 --sport 547 --sip 2001::/64 --msg_type 13 --speed 1  --ipv6 --PD\n", "");
	printf("%-2s  --attack udp --dip fe80::250:56ff:feb1:5054 --dport 547 --sport 547 --sip 2001::45 --speed 1  --ipv6 --msg_type 17 --ipv6_address 2002::/64 --server_duid 000100012350193e005056b15054 --PD\n", "");

}

int CDDoSParser::cmd_parser(int argc, char *argv[], CDDoSParam *params)
{
	int c;
	int tmp = 0;
	char ports[256] = {0};
	char hosts[256] = {0};
	uint32_t ipaddr = 0;
	int option_index = 0;
	char * payload_data = NULL;
	int flag = 0;
	uint32_t	pay_len =0;  
	int tmp_ip_type_flag=-1;

	opterr = 0;
	optind = 1;
	while ( (c = getopt_long(argc, argv, g_ddos_short_opts, g_ddos_long_options, &option_index)) != -1 )
	{
	   // RC_LOG_INFO("test ****************************** %s \n", optarg);
		switch ( c )
		{
			case 0:
				if (strcmp(g_ddos_long_options[option_index].name, "syn64") == 0) 
				{
					params->m_issyn64 = true;
				}
				else if (strcmp(g_ddos_long_options[option_index].name, "random-domain") == 0) 
				{
					params->m_is_random_domain = true;
				}
				break;
			case 'a' :
				params->m_type = parse_type(optarg);

				if (ATK_VEC_INVALID == params->m_type)
				{
					RC_LOG_INFO("test ****************************** %s \n", optarg);    // ��ӡ��Ϣ����־�����/tmp/xddos.log����
					printf("invalid attack type %s\n", optarg);
					Usage(argv[0]);
					return RC_ERROR;
				}
				break;
			case 's' :
				params->m_speed = atoi(optarg);
				break;
			case 'd' :
				params->m_duration = atoi(optarg);
				break;
			case 'c':
				params->m_total_cnt = atol(optarg);
				break;
			case 't':
				g_thrd_cnt = atoi(optarg);
				break;
			case 'S':
				strncpy(hosts, optarg, sizeof(hosts));
				hosts[255] = 0;
         
			    if(strchr(optarg, ':')){		 
                     params->m_ip_type=IP_V6;
					 if(tmp_ip_type_flag==-1)
					 {
					    tmp_ip_type_flag=IP_V6;
					 }
					 if (RC_OK != get_ip6_scope(hosts, &params->m_srcnet6))
					 {
						 printf("invalid src addr range %s\n", optarg);
						 Usage(argv[0]);
						 return RC_ERROR;
					 }

				}else{
					 params->m_ip_type=IP_V4;
					 if(tmp_ip_type_flag==-1)
					 {
					    tmp_ip_type_flag=IP_V4;
					 }
					if (RC_OK != get_ip_scope(hosts, &params->m_srcnet))
					{
						printf("invalid src addr range %s\n", optarg);
						Usage(argv[0]);
						return RC_ERROR;
					}

				}
				if(tmp_ip_type_flag!=params->m_ip_type){
					printf("it must be the same type of src_ip and dst_ip ");
					Usage(argv[0]);
					return RC_ERROR;
				}

				break;
			case 'D':			
				strncpy(hosts, optarg, sizeof(hosts));
				hosts[255] = 0;
			    if(strchr(optarg, ':')){
                     params->m_ip_type=IP_V6;
					 if(tmp_ip_type_flag==-1)
					 {
					    tmp_ip_type_flag=IP_V6;
					 }
					  //printf("---\n");
					 if (RC_OK != get_ip6_scope(hosts, &params->m_dstnet6))
					 {
						 printf("invalid dst addr range %s\n", optarg);
						 Usage(argv[0]);
						 return RC_ERROR;
					 }
					 char tmp[255];
					 libnet_addr2name6_r(params->m_dstnet6.begin_addr6,1,tmp,255);
					 //printf("---\n%s\n\n",tmp);
					 libnet_addr2name6_r(params->m_dstnet6.end_addr6,1,tmp,255);
					 //printf("---\n%s\n\n",tmp);


				}else{
					params->m_ip_type=IP_V4;
					if(tmp_ip_type_flag==-1)
					 {
					    tmp_ip_type_flag=IP_V4;
					 }
					if (RC_OK != get_ip_scope(hosts, &params->m_dstnet))
					{
						printf("invalid dst addr range %s\n", optarg);
						Usage(argv[0]);
						return RC_ERROR;
					}

				}
				
				if(tmp_ip_type_flag!=params->m_ip_type){
					printf("it must be the same type of src_ip and dst_ip ");
					Usage(argv[0]);
					return RC_ERROR;
				}			    

				break;
			case 'P':
				strncpy(ports, optarg, sizeof(ports));
				ports[255] = 0;

				if (RC_OK != get_port_scope(ports, &params->m_srcport))
				{
					printf("invalid src port range %s\n", optarg);
					Usage(argv[0]);
					return RC_ERROR;
				}
				break;
			case 'Q':
				//char dstport[4] = "547";
				strncpy(ports, optarg, sizeof(ports));
				ports[255] = 0;

				if (RC_OK != get_port_scope(ports, &params->m_dstport))
				{
					printf("invalid dst port range %s\n", optarg);
					Usage(argv[0]);
					return RC_ERROR;
				}
				break;
			// case 'T':
			// 	if (optarg[0] != '0' && optarg[1] != 'x')
			// 	{
			// 		printf("tcpflag must begin with 0x, like 0x1a\n");
			// 		Usage(argv[0]);
			// 		return RC_ERROR;
			// 	}
			// 	if (strlen(optarg) != 4)
			// 	{
			// 		printf("tcpflag must 4 bytes length, like 0x1a\n");
			// 		Usage(argv[0]);
			// 		return RC_ERROR;
			// 	}

			// 	sscanf(&optarg[2],"%x",&tmp);
			// 	params->m_tcpflag = (uint8_t)tmp;
			// 	break;
			case 'H':
				util_strncpy(params->m_domain, optarg, 255);
				break;
				
			case 'f':
				util_strncpy(params->m_relay_ip, optarg, 15);
				break; 
			case 'j':
				util_strncpy(params->m_options, optarg, 512); //{ "options", required_argument, NULL, 'j' },
				//printf("params->m_options:%s\n", params->m_options);
				break;
			case 'I':
				util_strncpy(params->m_client_ip_mac, optarg, 12);  //{ "client_mac", required_argument, NULL, 'I' },
				//printf("params->m_client_ip_mac:%s\n", params->m_client_ip_mac);
				break;			
			
			case 'A':
				util_strncpy(params->m_http_path, optarg, 255);
				break;
			// case 'V':
			// 	params->m_vlan_id = atoi(optarg);
			// 	break;
			case 'V':
				params->m_mac_start = atoi(optarg);
				break;
			case 'O':
				params->m_payload_len = atoi(optarg);
				break;
			case 'i':
				params->m_ip_type = IP_V6;
				break;

			case 'M':
				pay_len = strlen(optarg);
			    if(pay_len>0){
					payload_data = (char*)malloc(sizeof(char) * (pay_len/2 + 1) );
					params->m_payload_len = pay_len/2 + 1;
					printf("optarg:%s\n", optarg);
	
					flag= hex2str(payload_data, optarg, pay_len);
					
					/* for (int i = 0; i < 1 + pay_len/2; i++){
						printf("%c", payload_data[i]);
					}
					printf("\n"); */
					if(flag == -1){ //�������hex�ַ������ɹ����ͷŷ���Ŀռ�
					
						if(payload_data!=NULL){
							free(payload_data);
						}
						printf("payload-data format invalid:%s\n", optarg);
						Usage(argv[0]);
						return RC_ERROR;

					}else{
						params->set_payload_data(payload_data, pay_len/2 );
						if(payload_data != NULL){
							
							free(payload_data);
						}
					}
				}else{
					Usage(argv[0]);
					printf("payload-data lenght invalid:%d\n", pay_len);
					return RC_ERROR;
				}
				RC_LOG_INFO("end payload-data  \n");  
				break;
			case 'B': 
				params->m_http_action = atoi(optarg);//��ȡ��--http�ֶβ�������ת��
				break;
			case 'G': 
				params->m_https_action = atoi(optarg);//��ȡ��--http�ֶβ�������ת��
				break;
			case 'E':
				params->m_sip_action = atoi(optarg);//��ȡ��--sip�ֶβ�������ת��
				break;

			case 'L':
				params->m_ttl = atoi(optarg);
				break;
			case 'R':
				params->m_msg_type = atoi(optarg);
				printf("params->m_msg_type is %d\n", params->m_msg_type);
				break;
			case 'U':
				util_strncpy(params->m_server_id_duid, optarg, 36);
				break;
			case 'W':
				util_strncpy(params->m_client_id_duid, optarg, 36);
				break;
			case 'X':
				params->m_is_browser = true;
				break;
			case 'Y':
				params->m_prefix_delegetion = true;
				break;
			case 'Z':
				util_strncpy(params->m_iaid, optarg, 8);
				break;
			case 'z':
				if(RC_OK != str_to_ip(optarg, &ipaddr))
				{
					printf("cnc %s not valid.\n", optarg);
					return RC_ERROR;
				}
				g_cnc_addr = ntohl(ipaddr);
				break;
			case 'y':
				//g_cnc_port = atoi(optarg);
				params->m_ia_ta = true;
				break;
			case 'x':
				params->m_bootp = true;
				break;
			case 'h':
				Usage(argv[0]);
				return RC_OK;
				break;
			case 'T':
				util_strncpy(params->m_ipv4_address, optarg, 15);
				break;
			case 'F':
				util_strncpy(params->m_ipv6_address, optarg, 512);
				break;
			case 'J':
				util_strncpy(params->m_json_name, optarg, 255);
				if(parse_json(params)==RC_ERROR){
					printf("invalid json format \n");
				}
				
				break;

			default:
				printf("invalid cmd key %c\n", c);
				Usage(argv[0]);
				return RC_ERROR;
				break;
		}
	}

	if (g_cnc_addr != 0)
	{
		printf("run as a client, cnc server %s\n", ip_to_str(htonl(g_cnc_addr)));
		return RC_OK;
	}

	if (params->params_check() == RC_ERROR)
	{
		Usage(argv[0]);
		return RC_ERROR;
	}	


	return RC_OK;
}

int CDDoSParser::buf_parser(char *buffer, int *cmd_type, CDDoSParam *params)
{
	/*len(2bytes) + cmd(2bytes)*/
	/*len(2bytes) + 2(2bytes)*/
	/*len(2bytes) + 1(2bytes) + atktype(2bytes) + tlv*/
	int tmp = 0;
	uint16_t length = buffer[0] << 16 | buffer[1];
	if (length < 4)
	{
		RC_LOG_ERROR("invalid length %d", length);
		return RC_ERROR;
	}

	*cmd_type = buffer[2] << 16 | buffer[3];
	if (*cmd_type == CNC_CMD_STOP)
	{
		/*recv stop cmd, not parese other params*/
		return RC_OK;
	}
	else if (*cmd_type != CNC_CMD_START)
	{
		RC_LOG_ERROR("invalid cmd type %d", *cmd_type);
		return RC_ERROR;
	}

	if (length < 8)
	{
		RC_LOG_ERROR("invalid length %d", length);
		return RC_ERROR;
	}
	params->m_type = buffer[4] << 16 | buffer[5];

	uint16_t sparelen = length - 6;
	char *pos = &buffer[6];
	while(sparelen > 4)
	{
		uint16_t type = pos[0] << 16 | pos[1];
		uint16_t len = pos[2] << 16 | pos[3];

		if (len > sparelen)
		{
			RC_LOG_ERROR("invalid length %d, cur len %d, spare %d", length, len, sparelen);
			return RC_ERROR;
		}

		char *tmpbuf = (char*)calloc(1, len-4 + 1);
		memcpy(tmpbuf, &pos[4], len-4);

		sparelen -= len;
		pos = &pos[len];
		
		switch(type)
		{
		case P_SPEED:
			params->m_speed = util_atoi(tmpbuf, 10);
			break;
		case P_DURATION:
			params->m_duration = util_atoi(tmpbuf, 10);
			break;
		case P_COUNT:
			params->m_total_cnt = util_atoi(tmpbuf, 10);
			break;
		case P_THREAD:
			g_thrd_cnt = util_atoi(tmpbuf, 10);
			break;
		case P_SIP:
			if (RC_OK != get_ip_scope(tmpbuf, &params->m_srcnet))
			{
				RC_LOG_ERROR("invalid src addr range %s", tmpbuf);
				return RC_ERROR;
			}
			break;
		case P_DIP:
			if (RC_OK != get_ip_scope(tmpbuf, &params->m_dstnet))
			{
				RC_LOG_ERROR("invalid dst addr range %s", tmpbuf);
				return RC_ERROR;
			}
			break;

		case P_SPORT:			
			if (RC_OK != get_port_scope(tmpbuf, &params->m_srcport))
			{
				printf("invalid src port range %s\n", tmpbuf);
				return RC_ERROR;
			}
			break;
		case P_DPORT:
			if (RC_OK != get_port_scope(tmpbuf, &params->m_dstport))
			{
				printf("invalid dst port range %s\n", tmpbuf);
				return RC_ERROR;
			}
			break;
		case P_TCPFLAG:
			if (tmpbuf[0] != '0' && tmpbuf[1] != 'x')
			{
				printf("tcpflag must begin with 0x, like 0x1a\n");
				return RC_ERROR;
			}
			if (strlen(tmpbuf) != 4)
			{
				printf("tcpflag must 4 bytes length, like 0x1a\n");
				return RC_ERROR;
			}

			sscanf(&tmpbuf[2],"%x",&tmp);
			params->m_tcpflag = (uint8_t)tmp;
			break;
		case P_DOMAIN:
			util_strncpy(params->m_domain, tmpbuf, 255);
			break;
		case P_PATH:
			util_strncpy(params->m_http_path, tmpbuf, 255);
			break;
		case P_VLAN:
			params->m_vlan_id = util_atoi(tmpbuf, 10);
			break;
		case P_PAYLEN:
			params->m_payload_len = util_atoi(tmpbuf, 10);
			break;

		case P_HTTP_ACTION:
			params->m_http_action = util_atoi(tmpbuf, 10);  //
			break;
		case P_SIP_ACTION:
			params->m_sip_action = util_atoi(tmpbuf, 10);  //
			break;
		case P_ICMP_TYPE:   //
			params->m_icmp_type = util_atoi(tmpbuf, 10);
			break;

		case P_TTL:
			params->m_ttl = util_atoi(tmpbuf, 10);
			break;
		case P_ACK_FW:
			params->m_is_passfw = true;
			break;
		case P_METHOD:
			util_strncpy(params->m_http_method, tmpbuf, 31);
			break;
		case P_CONN:
			params->m_concurrent_cnt = util_atoi(tmpbuf, 10);
			break;
		case P_BROWSER:
			params->m_is_browser = true;
			break;
		case P_ACK_BOT:
			params->m_is_bot = true;
			break;
		case P_ACK_SOCK:
			params->m_is_sockstress = true;
			break;
		case P_NTP_MONLIST:
			params->m_ntp_monlist = true;
			break;
		default:
			RC_LOG_ERROR("invalid param key %d", type);
			return RC_ERROR;
			break;
		}
	}

	if (params->params_check() == RC_ERROR)
	{
		return RC_ERROR;
	}

	return RC_OK;
}
