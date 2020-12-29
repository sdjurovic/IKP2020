#include "pch.h"
#include "HashMap.h"
#include <stdio.h>

unsigned long GenerateHashValue(unsigned char *str)
{
	unsigned long hash = 5381;
	int c;

	while (c = *str++)
		hash = ((hash << 5) + hash) + c; /* hash * 33 + c */
	return hash;
}

void InitializeHashMap()
{
	for (int i = 0; i < MAXSIZE; i++)
	{
		HashMap[i] = NULL;
	}
}

void ShowHashMap()
{
	printf("\n---- START ----\n");
	for (int i = 0; i < MAXSIZE; i++)
	{
		if (HashMap[i] != NULL)
			printf("\t(%s,%s,%d)\n", HashMap[i]->name, HashMap[i]->address, HashMap[i]->port);
		else
			printf("\t~\n");
	}
	printf("---- END ----\n");
}

bool AddValueToHashMap(ClientData *clientData)
{
	unsigned int key = GenerateHashValue(clientData->name) % MAXSIZE;
	if (clientData == NULL)
		return false;
	if (HashMap[key] != NULL)
		return false;
	HashMap[key] = clientData;
	return true;
}

ClientData* FindValueInHashMap(unsigned char *clientName)
{
	unsigned long key = GenerateHashValue(clientName) % MAXSIZE;
	return HashMap[key];
}

bool RemoveValueFromHashMap(unsigned char *clientName)
{
	unsigned long key = GenerateHashValue(clientName) % MAXSIZE;
	if (HashMap[key] != NULL)
	{
		HashMap[key] = NULL;
		return true;
	}
	return false;
}