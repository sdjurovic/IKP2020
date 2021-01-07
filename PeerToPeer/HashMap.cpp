#include "pch.h"
#include "HashMap.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

bool AddValueToHashMap(ClientData* clientData)
{
	struct Element *newElement = (struct Element*)malloc(sizeof(struct Element));
	newElement->clientData = clientData;
	newElement->nextElement = NULL;

	unsigned int key = GenerateHashValue(clientData->name) % MAXSIZE;

	if (HashMap[key] == NULL)
	{
		HashMap[key] = newElement;
		return true;
	}
	else
	{
		struct Element *tempElement = HashMap[key];
		while (tempElement->nextElement)
		{
			tempElement = tempElement->nextElement;
		}
		tempElement->nextElement = newElement;
		return true;
	}
	return false;
}

void ShowHashMap()
{
	printf("\n---- START ----\n");
	for (int i = 0; i < MAXSIZE; i++)
	{
		struct Element *tempElement = HashMap[i];
		printf("[%d] --->", i);
		while (tempElement)
		{
			printf(" %s, %s, %d |", tempElement->clientData->name, tempElement->clientData->address, tempElement->clientData->port);
			tempElement = tempElement->nextElement;
		}
		printf(" NULL\n");
	}
	printf("---- END ----\n");
}

ClientData* FindValueInHashMap(unsigned char *clientName)
{
	for (int i = 0; i < MAXSIZE; i++)
	{
		struct Element *tempElement = HashMap[i];
		while (tempElement)
		{
			if (strcmp((const char*)clientName, (const char*)tempElement->clientData->name) == 0)
			{
				return tempElement->clientData;
			}
			tempElement = tempElement->nextElement;
		}
	}
}

bool RemoveValueFromHashMap(unsigned char *clientName)
{
	unsigned int key = GenerateHashValue(clientName) % MAXSIZE;
	struct Element *tempElement = HashMap[key];
	if (tempElement != NULL)
	{
		if (strcmp((const char*)clientName, (const char*)tempElement->clientData->name) == 0)
		{
			HashMap[key] = NULL;
			return true;
		}
		else
		{
			while (tempElement->nextElement)
			{
				if (strcmp((const char*)clientName, (const char*)tempElement->nextElement->clientData->name) == 0)
				{
					HashMap[key]->nextElement = tempElement->nextElement->nextElement;
					return true;
				}
				tempElement = tempElement->nextElement;
			}
		}
	}
	return false;
}

bool ClientExistsInHashMap(unsigned char *clientName)
{
	for (int i = 0; i < MAXSIZE; i++)
	{
		struct Element *tempElement = HashMap[i];
		while (tempElement)
		{
			if (strcmp((const char*)clientName, (const char*)tempElement->clientData->name) == 0)
			{
				return true;
			}
			tempElement = tempElement->nextElement;
		}
	}
	return false;
}
