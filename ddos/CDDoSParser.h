#ifndef _DDOS_PARSER_H
#define _DDOS_PARSER_H

class CDDoSParser {
public:
	CDDoSParser();
	virtual ~CDDoSParser();
	int parse_json(CDDoSParam * param);

	void Usage(const char *pragram);
	int cmd_parser(int argc, char *argv[], CDDoSParam *params);
	int buf_parser(char *buffer, int *cmd_type, CDDoSParam *params);

	
private:
	ATTACK_VECTOR parse_type(const char* typeStr);

};		

#endif
