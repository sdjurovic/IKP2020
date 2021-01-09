#pragma once
#ifndef HASHMAP_CLIENT_H
#define HASHMAP_CLIENT_H

#define MAXSIZE 10
#define MAX_USERNAME 30
#define MAXLEN 256

typedef struct ClientData {
	unsigned char name[MAXLEN];
	unsigned char address[MAXLEN];
	unsigned int port;
	unsigned char flag[2];  // 0 ako je u connected, a 1 ako je u accepted socketima 
} ClientData;

struct Element
{
	ClientData *clientData;
	struct Element *nextElement;
};

unsigned long GenerateHashMapKey(unsigned char *str);
void InitializeHashMap(Element** HashMap);
void ShowHashMap(Element** HashMap);
bool AddValueToHashMap(Element** HashMap, ClientData *clientData);
ClientData* FindValueInHashMap(Element** HashMap, unsigned char *clientName);
bool RemoveValueFromHashMap(Element** HashMap, unsigned char *clientName);
bool ClientExistsInHashMap(Element** HashMap, unsigned char *name);

#endif