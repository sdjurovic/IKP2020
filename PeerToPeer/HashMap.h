#ifndef HASHMAP_H
#define HASHMAP_H

#define MAXSIZE 10
#define MAXLEN 256


typedef struct ClientData {
	unsigned char name[MAXLEN];
	unsigned char address[MAXLEN];
	unsigned int port;
} ClientData;

struct Element
{
	ClientData *clientData;
	struct Element *nextElement;
};

static Element *HashMap[MAXSIZE];

unsigned long GenerateHashValue(unsigned char *str);
void InitializeHashMap();
void ShowHashMap();
bool AddValueToHashMap(ClientData *clientData);
ClientData* FindValueInHashMap(unsigned char *clientName);
bool RemoveValueFromHashMap(unsigned char *clientName);
bool ClientExistsInHashMap(unsigned char *name);

#endif