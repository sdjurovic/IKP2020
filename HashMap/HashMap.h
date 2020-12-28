#pragma once
#define MAXSIZE 10
#define MAXLEN 256

struct ClientData {
	unsigned char name[MAXLEN];
	unsigned char address[MAXLEN];
	unsigned int port;
};

struct ClientData *HashMap[MAXSIZE];

unsigned long GenerateHashValue(unsigned char *str);
void InitializeHashMap();
void ShowHashMap();
bool AddValueToHashMap(ClientData *clientData);
ClientData* FindValueInHashMap(unsigned char *clientName);
bool RemoveValueFromHashMap(unsigned char *clientName);