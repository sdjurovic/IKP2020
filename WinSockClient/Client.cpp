#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdlib.h>
#include <stdio.h>
#include <conio.h>
#include <ctype.h>
#include <cstdio>
#include <iostream>

#define DEFAULT_BUFLEN 512
#define DEFAULT_PORT 27016
#define MAX_USERNAME 30
#define MAX_MESSAGE 450

#define SERVER_IP_ADDRESS "127.0.0.1"  // DODALA

// Initializes WinSock2 library
// Returns true if succeeded, false otherwise.
bool InitializeWindowsSockets();

int main()
{
	// socket used to communicate with server
	SOCKET connectSocket = INVALID_SOCKET;
	// variable used to store function return value
	int iResult;

	struct Message_For_Client  // ovo ide u .h
	{
		unsigned char sender[MAX_USERNAME];
		unsigned char receiver[MAX_USERNAME];
		unsigned char message[MAX_MESSAGE];
		unsigned char flag[2];  // vrednosti: "1"(registracija) / "2"(prosledjivanje) / "3"(direktno) + null terminator
	};


	if (InitializeWindowsSockets() == false)
	{
		// we won't log anything since it will be logged
		// by InitializeWindowsSockets() function
		return 1;
	}

	// create a socket
	connectSocket = socket(AF_INET,
		SOCK_STREAM,
		IPPROTO_TCP);

	if (connectSocket == INVALID_SOCKET)
	{
		printf("socket failed with error: %ld\n", WSAGetLastError());
		WSACleanup();
		return 1;
	}

	// create and initialize address structure
	sockaddr_in serverAddress;
	serverAddress.sin_family = AF_INET;								// IPv4
	serverAddress.sin_addr.s_addr = inet_addr(SERVER_IP_ADDRESS);   // serverska adresa
	serverAddress.sin_port = htons(DEFAULT_PORT);					// port

	// connect to server specified in serverAddress and socket connectSocket
	if (connect(connectSocket, (SOCKADDR*)&serverAddress, sizeof(serverAddress)) == SOCKET_ERROR)
	{
		printf("Unable to connect to server.\n");
		closesocket(connectSocket);
		WSACleanup();
	}




	unsigned char sender[MAX_USERNAME];
	unsigned char receiver[MAX_USERNAME];
	char *message = (char*)malloc(MAX_MESSAGE);

	Message_For_Client packet;
	bool directly_communication = false;
	strcpy((char*)packet.flag, "1\0");  // registracija

	unsigned char communication_type[MAX_USERNAME];  // unos kakvu komunikaciju zeli (da/ne)

	char recvbuf[DEFAULT_BUFLEN];


	printf("Zdravo! Da biste ostvarili komunikaciju sa ostalim klijntima morate da se registrujete.\n");
	while (true) {

		printf("Unesite Vase korisnicko ime:\n");
		scanf("%s", &sender);
		strcpy((char*)packet.sender, (char*)sender);
		strcpy((char*)packet.receiver, "*\0");
		strcpy((char*)packet.message, "*\0");
		iResult = send(connectSocket, (char*)&packet, sizeof(packet), 0);
		if (iResult == SOCKET_ERROR)
		{
			printf("send failed with error: %d\n", WSAGetLastError());
			closesocket(connectSocket);
			WSACleanup();
			return 1;
		}
		
		// primanje odgovora od servera
		// Receive data until the client shuts down the connection
		iResult = recv(connectSocket, recvbuf, DEFAULT_BUFLEN, 0);
		if (iResult > 0)
		{
			recvbuf[iResult] = '\0';
			//printf("Message received from server: %s\n", recvbuf);
			if (strcmp(&recvbuf[0], "1") == 0) {
				//strcpy((char*)packet.sender, (char*)sender);  // mislim da vise ne treba
				printf("\nUspesno ste se registrovali!\n");
				break;
			}
			else if (strcmp(&recvbuf[0], "0") == 0) {
				printf("\nVec postoji klijent sa username-om koji ste uneli. Pokusajte opet:\n");
			}
			else {
				printf("\nPokusajte ponovo:\n");
			}

		}
		else if (iResult == 0)  // ako je primljena komanda za iskljucivanje (shutdown signal) ili je pozvan closeSocket na serverskoj strani
		{
			//connection was closed gracefully
			//printf("Connection with server closed.\n");
			printf("Server vise nije dostupan!\n");
			// Shutdown the connection since we're done
			iResult = shutdown(connectSocket, SD_BOTH);  // na dalje se sprecava i slanje i primanje
			// Check if connection is succesfully shut down.
			if (iResult == SOCKET_ERROR)
			{
				printf("Shutdown failed with error: %d\n", WSAGetLastError());
				closesocket(connectSocket);
				WSACleanup();
				return 1;
			}

			printf("\nPress any key to exit: ");
			_getch(); // da bi sacekao nas znak da zatvori socket

			closesocket(connectSocket);  // zatvara se konekcija sa tim serverom
			WSACleanup();
			
			return 0;

		}
		else  // ako je server nasilno zatvoren
		{
			// there was an error during recv
			//printf("recv failed with error: %d\n", WSAGetLastError());
			//closesocket(connectSocket);  // zatvara se konekcija sa tim serverom
			printf("Server vise nije dostupan!\n");
			// Shutdown the connection since we're done
			iResult = shutdown(connectSocket, SD_BOTH);  // na dalje se sprecava i slanje i primanje
			// Check if connection is succesfully shut down.
			if (iResult == SOCKET_ERROR)
			{
				printf("Shutdown failed with error: %d\n", WSAGetLastError());
				closesocket(connectSocket);
				WSACleanup();
				return 1;
			}

			printf("\nPress any key to exit: ");
			_getch(); // da bi sacekao nas znak da zatvori socket

			closesocket(connectSocket);  // zatvara se konekcija sa tim serverom
			WSACleanup();

			return 0;
			
		}
		
	}

	strcpy((char*)packet.flag, "2\0");  // prosledjivanje

	// odavde bi trebalo da se ukljuci i druga nit koja ce primati poruke od klijenta (za oba tipa komunikacije)

	while (true) {

		do {
			printf("Trenutan nacin komunikacije sa klijentima je preko servera.\nDa li zelite direktno da komunicirate sa klijentima? (da/ne)\n");
			scanf("%s", &communication_type);

			for (int i = 0; communication_type[i]; i++) {
				communication_type[i] = tolower(communication_type[i]);
			}

			if (strcmp((const char*)communication_type, "da") == 0) {
				directly_communication = true;
				strcpy((char*)packet.flag, "3\0");  // direktno
			}

		} while (strcmp((const char*)communication_type, "da") != 0 && strcmp((const char*)communication_type, "ne") != 0);

		if (directly_communication == false) {

			printf("Unesite naziv klijenta kome zelite da posaljete poruku:\n");
			scanf("%s", &receiver);
			getchar();
			strcpy((char*)packet.receiver, (char*)receiver);
			//printf("%s\n", packet.username);
			printf("Unesite poruku:\n");
			fgets(message, MAX_MESSAGE, stdin);
			//printf("Poruka: %s\nbroj bajta: %d\n", message, strlen((char*)message));
			message[strlen(message) - 1] = message[strlen(message)];  // skidam novi red
			strcpy((char*)packet.message, (char*)message);
			iResult = send(connectSocket, (char*)&packet, sizeof(packet), 0);  // sizeof(Message_For_Client)
			if (iResult == SOCKET_ERROR)
			{
				printf("send failed with error: %d\n", WSAGetLastError());
				closesocket(connectSocket);
				WSACleanup();
				return 1;
			}
			// primanje odgovora od servera
			// Receive data until the client shuts down the connection
			iResult = recv(connectSocket, recvbuf, DEFAULT_BUFLEN, 0);  // sta god da dobije od servera treba da ispise i da zavrti petlju opet...
			if (iResult > 0)  
			{
				//recvbuf[iResult] = '\0';
				//printf("Message received from server: %s\n", recvbuf);
				printf("%s\n\n", recvbuf);

			}
			else if (iResult == 0)  // ako je primljena komanda za iskljucivanje (shutdown signal) ili je pozvan closeSocket na serverskoj strani
			{
				//connection was closed gracefully
				//printf("Connection with server closed.\n");
				printf("Server vise nije dostupan!\n");
				// Shutdown the connection since we're done
				iResult = shutdown(connectSocket, SD_BOTH);  // na dalje se sprecava i slanje i primanje
				// Check if connection is succesfully shut down.
				if (iResult == SOCKET_ERROR)
				{
					printf("Shutdown failed with error: %d\n", WSAGetLastError());
					closesocket(connectSocket);
					WSACleanup();
					return 1;
				}

				printf("\nPress any key to exit: ");
				_getch(); // da bi sacekao nas znak da zatvori socket

				free(message);

				closesocket(connectSocket);  // zatvara se konekcija sa tim serverom
				WSACleanup();

				return 0;

			}
			else  // ako je server nasilno zatvoren
			{
				// there was an error during recv
				//printf("recv failed with error: %d\n", WSAGetLastError());
				//closesocket(connectSocket);  // zatvara se konekcija sa tim serverom
				printf("Server vise nije dostupan!\n");
				// Shutdown the connection since we're done
				iResult = shutdown(connectSocket, SD_BOTH);  // na dalje se sprecava i slanje i primanje
				// Check if connection is succesfully shut down.
				if (iResult == SOCKET_ERROR)
				{
					printf("Shutdown failed with error: %d\n", WSAGetLastError());
					closesocket(connectSocket);
					WSACleanup();
					return 1;
				}

				printf("\nPress any key to exit: ");
				_getch(); // da bi sacekao nas znak da zatvori socket

				free(message);

				closesocket(connectSocket);  // zatvara se konekcija sa tim serverom
				WSACleanup();

				return 0;

			}



		}
		
	}

	
	/*--------------------------------------------------------------------------------------------------*/
	// Shutdown the connection since we're done
	iResult = shutdown(connectSocket, SD_BOTH);  // na dalje se sprecava i slanje i primanje
	// Check if connection is succesfully shut down.
	if (iResult == SOCKET_ERROR)
	{
		printf("Shutdown failed with error: %d\n", WSAGetLastError());
		closesocket(connectSocket);
		WSACleanup();
		return 1;
	}
	/*--------------------------------------------------------------------------------------------------*/

	// DODALA:
	printf("\nPress any key to exit: ");
	_getch(); // da bi sacekao nas znak da zatvori socket

	free(message);

	// cleanup
	closesocket(connectSocket);
	WSACleanup();

	return 0;

	
}

bool InitializeWindowsSockets()
{
	WSADATA wsaData;
	// Initialize windows sockets library for this process
	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
	{
		printf("WSAStartup failed with error: %d\n", WSAGetLastError());
		return false;
	}
	return true;
}