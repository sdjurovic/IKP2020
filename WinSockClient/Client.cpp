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
#include "../PeerToPeer/HashMap_Client.cpp"

#define DEFAULT_BUFLEN 512
#define DEFAULT_PORT 27016
#define MAX_USERNAME 25
#define MAX_MESSAGE 400
#define MAX_ADDRESS 50
#define MAX_DIRECTLY_MESSAGE 510
#define MAX_MESSAGE_DIRECTLY 484

#define MAX_DIRECTLY_CONNECTIONS 10

#define SERVER_IP_ADDRESS "127.0.0.1"

/* Makro za bezbedno brisanje handle-ova.*/
#define SAFE_DELETE_HANDLE(a) if(a){CloseHandle(a);}

// Initializes WinSock2 library
// Returns true if succeeded, false otherwise.
bool InitializeWindowsSockets();
void KrajPrograma();

HANDLE FinishSignal;
HANDLE FinishThreadSignal;
CRITICAL_SECTION critical_section_server;

SOCKET connectSocket;  // socket used to communicate with server
SOCKET coonectSockets_directly[MAX_DIRECTLY_CONNECTIONS];  // sockets used to communicate with other clients
int count_connect_sockets;
SOCKET listenSocket;  // Socket used for listening for other clients 
SOCKET acceptedSockets[MAX_CLIENTS];  // Socket used for communication with other client
int counter_accepted_clients;


HANDLE StartMainSignal;
HANDLE StartSendMessageSignal;
HANDLE FinishSignal_Directly;
CRITICAL_SECTION critical_section_directly;

CRITICAL_SECTION critical_section_hash_map;


struct Client_Information_Directly  // dobijam od servera informacije o klijentu sa kojim treba da se povezem
{
	unsigned char my_username[MAX_USERNAME];
	unsigned char client_username[MAX_USERNAME];  // dodala...da bih znala kod dodavanja u hash sa kim sam ostvarila konekciju...
	unsigned char message[MAX_MESSAGE];
	unsigned char listen_address[MAX_ADDRESS];
	unsigned int listen_port;
};

struct Directly_Message {
	unsigned char message[MAX_DIRECTLY_MESSAGE];
	unsigned char flag[2];  // "0" username klijenta koji se konektovao - ja, "1" poruka od klijenta koji se konektovao - od mene
};

struct Element* HashMap[MAX_CLIENTS];

DWORD WINAPI thread_function(LPVOID parametri) {

	int iResult;
	char recvbuf[DEFAULT_BUFLEN];

	while (WaitForSingleObject(FinishThreadSignal, 1) == WAIT_TIMEOUT) {

		iResult = recv(connectSocket, recvbuf, DEFAULT_BUFLEN, 0);  // sta god da dobije od servera treba da ispise i da zavrti petlju opet...
		if (iResult > 0)
		{
			//recvbuf[iResult] = '\0';
			//printf("Message received from server: %s\n", recvbuf);
			EnterCriticalSection(&critical_section_server);
			printf("%s\n", recvbuf);
			LeaveCriticalSection(&critical_section_server);

		}
		else if (iResult == 0)  // ako je primljena komanda za iskljucivanje (shutdown signal) ili je pozvan closeSocket na serverskoj strani
		{
			//connection was closed gracefully
			//printf("Connection with server closed.\n");
			printf("\nIzgubljena je konekcija sa serverom...\n");
			ReleaseSemaphore(FinishSignal, 2, NULL);  // obavestava main() i thread_for_accepted_clients
			break;  // return 0;
			/*
			iResult = shutdown(connectSocket, SD_BOTH);
			if (iResult == SOCKET_ERROR)
			{
				printf("Shutdown failed with error: %d\n", WSAGetLastError());
				closesocket(connectSocket);
				WSACleanup();
				ReleaseSemaphore(FinishSignal, 1, NULL);
				return 1;
			}

			ReleaseSemaphore(FinishSignal, 1, NULL);

			//printf("\nPress any key to exit: ");
			//_getch();

			//free(message);

			//closesocket(connectSocket);
			//WSACleanup();


			return 0;
			*/

		}
		else  // ako je server nasilno zatvoren
		{
			if (WSAGetLastError() == WSAEWOULDBLOCK) {

				//printf("Operacija zahteva blokiranje.");   // nastavlja se dalje....
				//Sleep(1000);
				continue;
			}
			else {

				// there was an error during recv
				//printf("recv failed with error: %d\n", WSAGetLastError());
				//closesocket(connectSocket);
				printf("\nIzgubljena je konekcija sa serverom...\n");
				ReleaseSemaphore(FinishSignal, 2, NULL);  // obavestava main() i thread_for_accepted_clients
				break;  // return 0;
				/*
				iResult = shutdown(connectSocket, SD_BOTH);
				if (iResult == SOCKET_ERROR)
				{
					printf("Shutdown failed with error: %d\n", WSAGetLastError());
					closesocket(connectSocket);
					WSACleanup();
					ReleaseSemaphore(FinishSignal, 1, NULL);
					return 1;
				}

				ReleaseSemaphore(FinishSignal, 1, NULL);

				//printf("\nPress any key to exit: ");
				//_getch();

				//free(message);

				//closesocket(connectSocket);
				//WSACleanup();

				return 0;
				*/

			}
		}


	}

	return 0;
}

DWORD WINAPI function_recv_directly(LPVOID parametri) {

	int iResult;
	char recvbuf[DEFAULT_BUFLEN];
	Client_Information_Directly *client_informations;
	//int count_connect_sockets = 0;

	while (true) {

		iResult = recv(connectSocket, recvbuf, DEFAULT_BUFLEN, 0);  // sta god da dobije od servera treba da ispise i da zavrti petlju opet...
		if (iResult > 0)
		{
			//recvbuf[iResult] = '\0';
			//printf("Message received from server: %s\n", recvbuf);
			client_informations = (Client_Information_Directly*)recvbuf;

			// samo za testiranje:
			EnterCriticalSection(&critical_section_directly);
			printf("My username: %s\n", client_informations->my_username);
			printf("Client username: %s\n", client_informations->client_username);
			printf("Message: %s\n", client_informations->message);
			printf("Ip address: %s\n", client_informations->listen_address);
			printf("Port: %d\n", client_informations->listen_port);
			LeaveCriticalSection(&critical_section_directly);


			if (strcmp((char*)client_informations->listen_address, "*\0") == 0) {  // prosledjena poruka

				EnterCriticalSection(&critical_section_directly);
				printf("%s\n", client_informations->message);
				LeaveCriticalSection(&critical_section_directly);

			}
			else if (strcmp((char*)client_informations->listen_address, "/\0") == 0) {  // klijent ne postoji ili smo uneli nase ime

				EnterCriticalSection(&critical_section_directly);
				printf("%s\n", client_informations->message);
				LeaveCriticalSection(&critical_section_directly);

				ReleaseSemaphore(StartMainSignal, 1, NULL);  // javljamo mainu da opet zavrti unos klijenta

			}
			else {  // klijent za kog smo trazili podatke postoji i dobili smo podatke o njemu, treba da se povezemo na njega:

				if (count_connect_sockets >= MAX_DIRECTLY_CONNECTIONS) {

					EnterCriticalSection(&critical_section_directly);
					printf("Nema mesta za nove klijente!\n");
					LeaveCriticalSection(&critical_section_directly);

				}
				else {

					EnterCriticalSection(&critical_section_directly);
					printf("Povezivanje sa zeljenim klijentom...");
					LeaveCriticalSection(&critical_section_directly);

					Client_Information_Directly *client_informations_1 = (Client_Information_Directly*)parametri;
					strcpy((char*)client_informations_1->my_username, (char*)client_informations->my_username);
					strcpy((char*)client_informations_1->client_username, (char*)client_informations->client_username);
					strcpy((char*)client_informations_1->message, (char*)client_informations->message);
					strcpy((char*)client_informations_1->listen_address, (char*)client_informations->listen_address);
					client_informations_1->listen_port = client_informations->listen_port;

					//printf("jnds");
				}

				ReleaseSemaphore(StartSendMessageSignal, 1, NULL);
				// otvaranje connectSocket-a za povezivanje sa njim
				// kada uspe dodati klijenta u Hash tabelu i reci da se nalazi u connectSocket-ima
				// omoguciti unos poruke

			}

		}
		else if (iResult == 0)  // ako je primljena komanda za iskljucivanje (shutdown signal) ili je pozvan closeSocket na serverskoj strani
		{
			//connection was closed gracefully
			//printf("Connection with server closed.\n");
			printf("\nIzgubljena je konekcija sa serverom...\n");
			ReleaseSemaphore(FinishSignal_Directly, 3, NULL);
			ReleaseSemaphore(FinishSignal, 1, NULL);
			break;  // return 0;
			/*
			iResult = shutdown(connectSocket, SD_BOTH);
			if (iResult == SOCKET_ERROR)
			{
				printf("Shutdown failed with error: %d\n", WSAGetLastError());
				closesocket(connectSocket);
				WSACleanup();
				return 1;
			}
			*/


			//printf("\nPress any key to exit: ");
			//_getch();

			//free(message);

			//closesocket(connectSocket);
			//WSACleanup();


			return 0;

		}
		else  // ako je server nasilno zatvoren
		{
			if (WSAGetLastError() == WSAEWOULDBLOCK) {

				//printf("Operacija zahteva blokiranje.");   // nastavlja se dalje....
				//ReleaseSemaphore(StartSignal, 1, NULL);  // promeniti na semafor direktne...
				//Sleep(1000);
				continue;
			}
			else {

				// there was an error during recv
				//printf("recv failed with error: %d\n", WSAGetLastError());
				//closesocket(connectSocket);
				printf("\nIzgubljena je konekcija sa serverom...\n");
				ReleaseSemaphore(FinishSignal_Directly, 3, NULL);
				ReleaseSemaphore(FinishSignal, 1, NULL);
				break;  // return 0;
				/*
				iResult = shutdown(connectSocket, SD_BOTH);
				if (iResult == SOCKET_ERROR)
				{
					printf("Shutdown failed with error: %d\n", WSAGetLastError());
					closesocket(connectSocket);
					WSACleanup();
					return 1;
				}
				*/


				//printf("\nPress any key to exit: ");
				//_getch();

				//free(message);

				//closesocket(connectSocket);
				//WSACleanup();

				return 0;
			}
		}

	}

	return 0;
}

DWORD WINAPI function_send_message_directly(LPVOID parametri) {

	Client_Information_Directly *information = (Client_Information_Directly*)parametri;  // da li ce uvek biti osvezeno???? //HOCE
	char *directly_message = (char*)malloc(MAX_MESSAGE_DIRECTLY);
	//Directly_Message *directly_message_packet = (Directly_Message*)malloc(sizeof(Directly_Message));
	Directly_Message directly_message_packet;
	int iResult;
	unsigned long mode = 1;

	HANDLE semaphores[2] = { FinishSignal_Directly, StartSendMessageSignal };
	while (WaitForMultipleObjects((DWORD)2, semaphores, FALSE, INFINITE) == WAIT_OBJECT_0 + 1) {

		// samo za testiranje:
		EnterCriticalSection(&critical_section_directly);
		printf("My username: %s\n", information->my_username);
		printf("Client username: %s\n", information->client_username);
		printf("Message: %s\n", information->message);
		printf("Ip address: %s\n", information->listen_address);
		printf("Port: %d\n", information->listen_port);    // ispise host zapis
		LeaveCriticalSection(&critical_section_directly);

		// create a socket
		coonectSockets_directly[count_connect_sockets] = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		if (coonectSockets_directly[count_connect_sockets] == INVALID_SOCKET)
		{
			printf("socket failed with error: %ld\n", WSAGetLastError());
			ReleaseSemaphore(StartMainSignal, 1, NULL);  // znak da main() zavrti petlju za unos novog klijenta
			continue;
			//WSACleanup();
			//return 1;
		}

		// create and initialize address structure
		sockaddr_in serverAddress;
		serverAddress.sin_family = AF_INET;								// IPv4
		serverAddress.sin_addr.s_addr = inet_addr((char*)information->listen_address);   // serverska adresa
		serverAddress.sin_port = htons(information->listen_port);					// port   

		//printf("*************************\n");
		//printf("%d\n", serverAddress.sin_port);  // ispise mrezni zapis


		// connect to server specified in serverAddress and socket connectSocket
		if (connect(coonectSockets_directly[count_connect_sockets], (SOCKADDR*)&serverAddress, sizeof(serverAddress)) == SOCKET_ERROR)
		{
			printf("Unable to connect to client.\n");
			// poravnavanje socket-a nije potrebno jer j euvek u pitanju poslednji
			closesocket(coonectSockets_directly[count_connect_sockets]);
			coonectSockets_directly[count_connect_sockets] = INVALID_SOCKET;
			//WSACleanup();
			ReleaseSemaphore(StartMainSignal, 1, NULL);  // znak da main() zavrti petlju za unos novog klijenta
			continue;
			// dopuniti...

		}
		else {

			count_connect_sockets++;
			printf("POVEZAO SAM SE NA KLIJENTA!!! \t Njegova adresa i port: %s : %d \n", inet_ntoa(serverAddress.sin_addr), ntohs(serverAddress.sin_port));
			// dodavanje klijnta sa kojim smo se povezali u Hash Map:
			ClientData *newClient = (ClientData*)malloc(sizeof(ClientData));
			strcpy((char*)newClient->name, (char*)information->client_username);
			strcpy((char*)newClient->address, (char*)information->listen_address);
			newClient->port = information->listen_port;
			strcpy((char*)newClient->socket_type, "0\0");
			EnterCriticalSection(&critical_section_hash_map);
			AddValueToHashMap(HashMap, newClient);
			ShowHashMap(HashMap);
			LeaveCriticalSection(&critical_section_hash_map);

			// slanje mog imena klijentu da bi me upisao u Hash Mapu:
			strcpy((char*)directly_message_packet.flag, "0\0");
			strcpy((char*)directly_message_packet.message, (char*)information->my_username);
			iResult = send(coonectSockets_directly[count_connect_sockets - 1], (char*)&directly_message_packet, sizeof(directly_message_packet), 0);
			if (iResult == SOCKET_ERROR)
			{
				//printf("send failed with error: %d\n", WSAGetLastError());
				printf("Klijent vise nije dostupan!\n");
				// poravnavanje socket-a nije potrebno jer j euvek u pitanju poslednji
				closesocket(coonectSockets_directly[count_connect_sockets - 1]);
				coonectSockets_directly[count_connect_sockets - 1] = INVALID_SOCKET;
				count_connect_sockets--;
				EnterCriticalSection(&critical_section_hash_map);
				RemoveValueFromHashMap(HashMap, newClient->name);
				ShowHashMap(HashMap);
				LeaveCriticalSection(&critical_section_hash_map);
				//WSACleanup();
				ReleaseSemaphore(StartMainSignal, 1, NULL);  // znak da main() zavrti petlju za unos novog klijenta
				continue;
				//return 1;
			}

			getchar();
			EnterCriticalSection(&critical_section_directly);
			printf("Unesite poruku:\n");
			fgets(directly_message, MAX_MESSAGE_DIRECTLY, stdin);
			LeaveCriticalSection(&critical_section_directly);
			//printf("Poruka: %s\nbroj bajta: %d\n", message, strlen((char*)message));
			directly_message[strlen(directly_message) - 1] = directly_message[strlen(directly_message)];  // skidam novi red
			strcpy((char*)directly_message_packet.flag, "1\0");
			sprintf((char*)directly_message_packet.message, "[%s]:%s", information->my_username, directly_message);
			//printf("Poruka direktna za klijenta: %s\n", directly_message_packet.message);
			iResult = send(coonectSockets_directly[count_connect_sockets - 1], (char*)&directly_message_packet, sizeof(directly_message_packet), 0);
			if (iResult == SOCKET_ERROR)
			{
				//printf("send failed with error: %d\n", WSAGetLastError());
				printf("Poruka nije poslata, jer klijent vise nije dostupan!\n");
				// poravnavanje socket-a nije potrebno jer j euvek u pitanju poslednji
				closesocket(coonectSockets_directly[count_connect_sockets - 1]);
				coonectSockets_directly[count_connect_sockets - 1] = INVALID_SOCKET;
				count_connect_sockets--;
				EnterCriticalSection(&critical_section_hash_map);
				RemoveValueFromHashMap(HashMap, newClient->name);
				ShowHashMap(HashMap);
				LeaveCriticalSection(&critical_section_hash_map);
				//WSACleanup();
				ReleaseSemaphore(StartMainSignal, 1, NULL);  // znak da main() zavrti petlju za unos novog klijenta
				continue;
				//return 1;
			}
			else {

				EnterCriticalSection(&critical_section_directly);
				printf("Poruka je uspesno poslata zeljenom klijentu!\n");
				LeaveCriticalSection(&critical_section_directly);

			}

			
			iResult = ioctlsocket(coonectSockets_directly[count_connect_sockets - 1], FIONBIO, &mode);
			if (iResult != NO_ERROR) {
				//printf("ioctlsocket failed with error: %ld\n", iResult);
				printf("Poruka nije poslata, jer klijent vise nije dostupan!\n");
				// poravnavanje socket-a nije potrebno jer je uvek u pitanju poslednji
				closesocket(coonectSockets_directly[count_connect_sockets - 1]);
				coonectSockets_directly[count_connect_sockets - 1] = INVALID_SOCKET;
				count_connect_sockets--;
				EnterCriticalSection(&critical_section_hash_map);
				RemoveValueFromHashMap(HashMap, newClient->name);
				ShowHashMap(HashMap);
				LeaveCriticalSection(&critical_section_hash_map);
				ReleaseSemaphore(StartMainSignal, 1, NULL);  // znak da main() zavrti petlju za unos novog klijenta
				continue;
			}


		}

		ReleaseSemaphore(StartMainSignal, 1, NULL);  // znak da main() zavrti petlju za unos novog klijenta
	}

	free(directly_message);

	return 0;

}

DWORD WINAPI function_accept_clients(LPVOID parametri) {

	// ova nit treba da radi dok server ne padne
	// radi i tokom prvog i tokom drugog tipa komunikacije

	Directly_Message *directly_message;
	char recvbuf[DEFAULT_BUFLEN];
	int iResult = 0;

	// Set listenSocket in listening mode
	iResult = listen(listenSocket, SOMAXCONN);
	if (iResult == SOCKET_ERROR)
	{
		printf("listen failed with error: %d\n", WSAGetLastError());
		closesocket(listenSocket);
		//WSACleanup();
		//return 1;
	}
	printf("Server socket is set to listening mode. Waiting for new connection requests.\n");

	unsigned long mode = 1;
	iResult = ioctlsocket(listenSocket, FIONBIO, &mode);
	if (iResult != NO_ERROR) {
		printf("ioctlsocket failed with error: %ld\n", iResult);
	}

	fd_set readfds;
	FD_ZERO(&readfds);

	timeval timeVal;
	timeVal.tv_sec = 1;
	timeVal.tv_usec = 0;


	while (WaitForSingleObject(FinishSignal, 1) == WAIT_TIMEOUT) {

		if (counter_accepted_clients < MAX_CLIENTS) {  
			FD_SET(listenSocket, &readfds);
		}

		for (int a = 0; a < counter_accepted_clients; a++) {
			FD_SET(acceptedSockets[a], &readfds);
		}

		iResult = select(0, &readfds, NULL, NULL, &timeVal);
		if (iResult == 0) {

			continue;					 
		}
		else if (iResult == SOCKET_ERROR) {

			printf("select failed with error: %ld\n", WSAGetLastError());
			break;                         // ugasiti server

		}
		else {  // desio se neki dogadjaj

			if (FD_ISSET(listenSocket, &readfds) && counter_accepted_clients < MAX_CLIENTS) {

				// Struct for information about connected client
				sockaddr_in clientAddr;
				int clientAddrSize = sizeof(struct sockaddr_in);

				FD_CLR(listenSocket, &readfds);

				// New connection request is received. Add new socket in array on first free position.
				acceptedSockets[counter_accepted_clients] = accept(listenSocket, (struct sockaddr *)&clientAddr, &clientAddrSize);
				if (acceptedSockets[counter_accepted_clients] == INVALID_SOCKET)
				{
					printf("accept failed with error: %d\n", WSAGetLastError());
					closesocket(listenSocket);
					//WSACleanup();
					//return 1;
					break;

				}
				printf("\nNew client[%d] request accepted. Client address: %s : %d\n", counter_accepted_clients, inet_ntoa(clientAddr.sin_addr), ntohs(clientAddr.sin_port));

				FD_CLR(listenSocket, &readfds);	 // ciscenje set-a za sledecu iteraciju

				iResult = ioctlsocket(acceptedSockets[counter_accepted_clients], FIONBIO, &mode);
				if (iResult != NO_ERROR) {
					printf("ioctlsocket failed with error: %ld\n", iResult);
				}

				counter_accepted_clients++;

			}


			for (int i = 0; i < counter_accepted_clients; i++) {
				if ((FD_ISSET(acceptedSockets[i], &readfds)) == 1) {   // ako se desio dogadjaj recv:

					FD_CLR(acceptedSockets[i], &readfds);

					int iResult = recv(acceptedSockets[i], recvbuf, DEFAULT_BUFLEN, 0);
					if (iResult > 0)
					{
						directly_message = (Directly_Message*)recvbuf;
						/*
						// samo za testiranje:
						EnterCriticalSection(&critical_section_directly);
						printf("Message: %s\n", directly_message->message);
						printf("Flag: %s\n", directly_message->flag);
						LeaveCriticalSection(&critical_section_directly);
						*/

						if (strcmp((char*)directly_message->flag, "0\0") == 0) {  // klijent se konektovao na mene, ubacujemo ga u Has Map-u

							struct sockaddr_in socketAddress;  // struktura za smestanje adrese i porta iz socket-a iz connectSocket_directly niza
							int socketAddress_len = sizeof(socketAddress);

							if (getpeername(acceptedSockets[i], (sockaddr *)&socketAddress, &socketAddress_len) == -1)
							{
								//printf("getsockname() failed.\n");
								//return -1;
								// doraditi...
								//printf("Pokusajte ponovo!\n");
								break;
							}

							char client_address[MAX_ADDRESS];  // klijentska listen address-a, samo pretvorena u ascii
							inet_ntop(AF_INET, &socketAddress.sin_addr, client_address, INET_ADDRSTRLEN);

							ClientData *newClient = (ClientData*)malloc(sizeof(ClientData));
							unsigned char name[MAX_USERNAME];
							strcpy((char*)name, (char*)directly_message->message);
							strcpy((char*)newClient->name, (char*)name);
							strcpy((char*)newClient->address, (char*)client_address);
							newClient->port = (unsigned int)ntohs(socketAddress.sin_port);
							strcpy((char*)newClient->socket_type, "1\0");
							EnterCriticalSection(&critical_section_hash_map);
							AddValueToHashMap(HashMap, newClient);
							ShowHashMap(HashMap);
							LeaveCriticalSection(&critical_section_hash_map);

						}
						else if(strcmp((char*)directly_message->flag, "1\0") == 0){

							printf("%s\n", directly_message->message);

						} 
						else {

							continue;
						}
						

					}
					else if (iResult == 0)	// Check if shutdown command is received   // ako je client poslao shutdown signal, hoce da se iskljuci iz komunikacije:
					{
						for (int j = 0; j < MAX_CLIENTS; j++)
						{
							EnterCriticalSection(&critical_section_hash_map);
							struct Element *tempClientElement = HashMap[j];
							LeaveCriticalSection(&critical_section_hash_map);
							while (tempClientElement)
							{
								sockaddr_in socketAddress;
								int socketAddress_len = sizeof(struct sockaddr_in);
								if (getpeername(acceptedSockets[i], (sockaddr *)&socketAddress, &socketAddress_len) == -1)
								{
									break;
								}
								char tempClientAddress[MAX_ADDRESS];
								inet_ntop(AF_INET, &socketAddress.sin_addr, tempClientAddress, INET_ADDRSTRLEN);

								if ((strcmp(tempClientAddress, (const char*)tempClientElement->clientData->address) == 0) && ((unsigned int)ntohs(socketAddress.sin_port) == tempClientElement->clientData->port))
								{
									EnterCriticalSection(&critical_section_hash_map);
									RemoveValueFromHashMap(HashMap, tempClientElement->clientData->name);
									//printf("Klijent %s, je uklonjen iz HashMape", tempClientElement->clientData->name);
									ShowHashMap(HashMap);
									LeaveCriticalSection(&critical_section_hash_map);
									break;
								}
								tempClientElement = tempClientElement->nextElement;
							}
						}

						closesocket(acceptedSockets[i]);
						for (int j = i; j < counter_accepted_clients - 1; j++)
						{
							acceptedSockets[j] = acceptedSockets[j + 1];
						}
						acceptedSockets[counter_accepted_clients - 1] = INVALID_SOCKET;
						counter_accepted_clients--;
						i--;  // DA NE BI PRESKOCILI JEDNOG U PETLJI !!!


					}
					else  // desila se greska u recv:
					{
						if (WSAGetLastError() == WSAEWOULDBLOCK) {

							continue;
						}
						else {

							for (int j = 0; j < MAX_CLIENTS; j++)
							{
								EnterCriticalSection(&critical_section_hash_map);
								struct Element *tempClientElement = HashMap[j];
								LeaveCriticalSection(&critical_section_hash_map);
								while (tempClientElement)
								{
									sockaddr_in socketAddress;
									int socketAddress_len = sizeof(struct sockaddr_in);
									if (getpeername(acceptedSockets[i], (sockaddr *)&socketAddress, &socketAddress_len) == -1)
									{
										break;
									}
									char tempClientAddress[MAX_ADDRESS];
									inet_ntop(AF_INET, &socketAddress.sin_addr, tempClientAddress, INET_ADDRSTRLEN);

									if ((strcmp(tempClientAddress, (const char*)tempClientElement->clientData->address) == 0) && ((unsigned int)ntohs(socketAddress.sin_port) == tempClientElement->clientData->port))
									{
										EnterCriticalSection(&critical_section_hash_map);
										RemoveValueFromHashMap(HashMap, tempClientElement->clientData->name);
										//printf("Klijent %s, je uklonjen iz HashMape", tempClientElement->clientData->name);
										ShowHashMap(HashMap);
										LeaveCriticalSection(&critical_section_hash_map);
										break;
									}
									tempClientElement = tempClientElement->nextElement;
								}
							}

							closesocket(acceptedSockets[i]);
							for (int j = i; j < counter_accepted_clients - 1; j++)
							{
								acceptedSockets[j] = acceptedSockets[j + 1];
							}
							acceptedSockets[counter_accepted_clients - 1] = INVALID_SOCKET;
							counter_accepted_clients--;
							i--;  // DA NE BI PRESKOCILI JEDNOG U PETLJI !!!


						}


					}





				}

			}






		}





	}












	

	return 0;
}

DWORD WINAPI function_recv_coonectSockets_directly(LPVOID parametri) {

	int iResult = 0;
	char recvbuf[DEFAULT_BUFLEN];

	fd_set readfds;
	FD_ZERO(&readfds);

	timeval timeVal;
	timeVal.tv_sec = 1;
	timeVal.tv_usec = 0;


	while (WaitForSingleObject(FinishSignal_Directly, 1) == WAIT_TIMEOUT) {

		if (count_connect_sockets == 0) {
			continue;
		}

		for (int a = 0; a < count_connect_sockets; a++) {
			FD_SET(coonectSockets_directly[a], &readfds);
		}

		iResult = select(0, &readfds, NULL, NULL, &timeVal);
		if (iResult == 0) {

			continue;
		}
		else if (iResult == SOCKET_ERROR) {

			printf("********select failed with error: %ld\n", WSAGetLastError());
			break;                         // ugasiti server

		}
		else {  // desio se neki dogadjaj

			for (int i = 0; i < count_connect_sockets; i++) {
				if ((FD_ISSET(coonectSockets_directly[i], &readfds)) == 1) {   // ako se desio dogadjaj recv:

					FD_CLR(coonectSockets_directly[i], &readfds);

					int iResult = recv(coonectSockets_directly[i], recvbuf, DEFAULT_BUFLEN, 0);
					if (iResult > 0)
					{
						printf("%s\n", recvbuf);

					}
					else if (iResult == 0)	// Check if shutdown command is received   // ako je client poslao shutdown signal, hoce da se iskljuci iz komunikacije:
					{
						for (int j = 0; j < MAX_CLIENTS; j++)
						{
							EnterCriticalSection(&critical_section_hash_map);
							struct Element *tempClientElement = HashMap[j];
							LeaveCriticalSection(&critical_section_hash_map);
							while (tempClientElement)
							{
								sockaddr_in socketAddress;
								int socketAddress_len = sizeof(struct sockaddr_in);
								if (getpeername(coonectSockets_directly[i], (sockaddr *)&socketAddress, &socketAddress_len) == -1)
								{
									break;
								}
								char tempClientAddress[MAX_ADDRESS];
								inet_ntop(AF_INET, &socketAddress.sin_addr, tempClientAddress, INET_ADDRSTRLEN);

								if ((strcmp(tempClientAddress, (const char*)tempClientElement->clientData->address) == 0) && ((unsigned int)ntohs(socketAddress.sin_port) == tempClientElement->clientData->port))
								{
									EnterCriticalSection(&critical_section_hash_map);
									RemoveValueFromHashMap(HashMap, tempClientElement->clientData->name);
									printf("Klijent %s, je uklonjen iz HashMape", tempClientElement->clientData->name);
									ShowHashMap(HashMap);
									LeaveCriticalSection(&critical_section_hash_map);
									break;
								}
								tempClientElement = tempClientElement->nextElement;
							}
						}

						closesocket(coonectSockets_directly[i]);
						for (int j = i; j < count_connect_sockets - 1; j++)
						{
							coonectSockets_directly[j] = coonectSockets_directly[j + 1];
						}
						coonectSockets_directly[count_connect_sockets - 1] = INVALID_SOCKET;
						count_connect_sockets--;
						i--;  // DA NE BI PRESKOCILI JEDNOG U PETLJI !!!


					}
					else  // desila se greska u recv:
					{
						if (WSAGetLastError() == WSAEWOULDBLOCK) {

							continue;
						}
						else {

							for (int j = 0; j < MAX_CLIENTS; j++)
							{
								EnterCriticalSection(&critical_section_hash_map);
								struct Element *tempClientElement = HashMap[j];
								LeaveCriticalSection(&critical_section_hash_map);
								while (tempClientElement)
								{
									sockaddr_in socketAddress;
									int socketAddress_len = sizeof(struct sockaddr_in);
									if (getpeername(coonectSockets_directly[i], (sockaddr *)&socketAddress, &socketAddress_len) == -1)
									{
										break;
									}
									char tempClientAddress[MAX_ADDRESS];
									inet_ntop(AF_INET, &socketAddress.sin_addr, tempClientAddress, INET_ADDRSTRLEN);

									if ((strcmp(tempClientAddress, (const char*)tempClientElement->clientData->address) == 0) && ((unsigned int)ntohs(socketAddress.sin_port) == tempClientElement->clientData->port))
									{
										EnterCriticalSection(&critical_section_hash_map);
										RemoveValueFromHashMap(HashMap, tempClientElement->clientData->name);
										printf("Klijent %s, je uklonjen iz HashMape", tempClientElement->clientData->name);
										ShowHashMap(HashMap);
										LeaveCriticalSection(&critical_section_hash_map);
										break;
									}
									tempClientElement = tempClientElement->nextElement;
								}
							}

							closesocket(coonectSockets_directly[i]);
							for (int j = i; j < count_connect_sockets - 1; j++)
							{
								coonectSockets_directly[j] = coonectSockets_directly[j + 1];
							}
							coonectSockets_directly[count_connect_sockets - 1] = INVALID_SOCKET;
							count_connect_sockets--;
							i--;  // DA NE BI PRESKOCILI JEDNOG U PETLJI !!!


						}


					}





				}

			}






		}





	}



	return 0;
}


int main()
{

	Client_Information_Directly *client_information_for_thread = (Client_Information_Directly*)malloc(sizeof(Client_Information_Directly));
	//Client_Information_Directly client_information_for_thread;

	HANDLE thread;
	DWORD thread_id;

	HANDLE thread_directly_recv;
	DWORD thread_directly_recv_id;

	HANDLE thread_send_message_directly;
	DWORD thread_send_message_directly_id;

	HANDLE thread_for_accept_clients;
	DWORD thread_for_accept_clients_id;

	HANDLE thread_recv_on_connectSockets;
	DWORD thread_recv_on_connectSockets_id;

	FinishSignal = CreateSemaphore(NULL, 0, 2, NULL);  // nit thread obavestava main()-SAMO U PROSLEDJIVANJU i thread_for_accept_clients-UVEK
	FinishThreadSignal = CreateSemaphore(NULL, 0, 1, NULL);  // kada se prebacimo na direktnu komunikaciju main() obavestava nit thread da prestane sa radom
	FinishSignal_Directly = CreateSemaphore(NULL, 0, 3, NULL);  // nit thread_directly_recv obavestava main()-SAMO U DIREKTNOJ i thread_send_message_directly-U DIREKTNOJ
																					// i thread_recv_on_connectSockets-U DIREKTNOJ
	StartMainSignal = CreateSemaphore(NULL, 1, 1, NULL);
	StartSendMessageSignal = CreateSemaphore(NULL, 0, 1, NULL);
	

	if (FinishThreadSignal && FinishSignal && StartSendMessageSignal && FinishSignal_Directly && StartMainSignal) {

		InitializeCriticalSection(&critical_section_server);
		InitializeCriticalSection(&critical_section_directly);
		InitializeCriticalSection(&critical_section_hash_map);
		thread = CreateThread(NULL, 0, &thread_function, NULL, CREATE_SUSPENDED, &thread_id);
		thread_directly_recv = CreateThread(NULL, 0, &function_recv_directly, client_information_for_thread, CREATE_SUSPENDED, &thread_directly_recv_id);
		thread_send_message_directly = CreateThread(NULL, 0, &function_send_message_directly, client_information_for_thread, CREATE_SUSPENDED, &thread_send_message_directly_id);
		thread_for_accept_clients = CreateThread(NULL, 0, &function_accept_clients, NULL, CREATE_SUSPENDED, &thread_for_accept_clients_id);
		thread_recv_on_connectSockets = CreateThread(NULL, 0, &function_recv_coonectSockets_directly, NULL, CREATE_SUSPENDED, &thread_recv_on_connectSockets_id);

	}
	else {

		SAFE_DELETE_HANDLE(FinishSignal);
		SAFE_DELETE_HANDLE(StartSendMessageSignal);
		SAFE_DELETE_HANDLE(FinishThreadSignal);
		SAFE_DELETE_HANDLE(FinishSignal_Directly);
		SAFE_DELETE_HANDLE(StartMainSignal);

		SAFE_DELETE_HANDLE(thread);
		SAFE_DELETE_HANDLE(thread_directly_recv);
		SAFE_DELETE_HANDLE(thread_send_message_directly);
		SAFE_DELETE_HANDLE(thread_for_accept_clients);
		SAFE_DELETE_HANDLE(thread_recv_on_connectSockets);

		DeleteCriticalSection(&critical_section_server);
		DeleteCriticalSection(&critical_section_directly);
		DeleteCriticalSection(&critical_section_hash_map);

		return 1;

	}

	

	struct Message_For_Client  // saljem serveru
	{
		unsigned char sender[MAX_USERNAME];
		unsigned char receiver[MAX_USERNAME];
		unsigned char message[MAX_MESSAGE];
		unsigned char listen_address[MAX_ADDRESS];
		unsigned int listen_port;
		unsigned char flag[2];  // vrednosti: "1"(registracija) / "2"(prosledjivanje) / "3"(direktno) / "4"(presao sam na direktnu) + null terminator
	};



	connectSocket = INVALID_SOCKET;  // za konekciju sa serverom

	for (int i = 0; i < MAX_CLIENTS; i++) {  // za slanje zahteva za konekciju sa klijentima
		coonectSockets_directly[i] = INVALID_SOCKET;
	}
	count_connect_sockets = 0;

	listenSocket = INVALID_SOCKET;
	for (int i = 0; i < MAX_CLIENTS; i++) {
		acceptedSockets[i] = INVALID_SOCKET;
	}
	counter_accepted_clients = 0;



	// variable used to store function return value
	int iResult;

	if (InitializeWindowsSockets() == false)
	{
		// we won't log anything since it will be logged
		// by InitializeWindowsSockets() function
		return 1;
	}

	// Prepare address information structures
	addrinfo *resultingAddress = NULL;
	addrinfo hints;

	memset(&hints, 0, sizeof(hints));  // inicijalizuje memoriju za hints i popunjava je nulama
	hints.ai_family = AF_INET;       // IPv4 address
	hints.ai_socktype = SOCK_STREAM; // Provide reliable data streaming
	hints.ai_protocol = IPPROTO_TCP; // Use TCP protocol
	hints.ai_flags = AI_PASSIVE;     // 

	// Resolve the server address and port
	iResult = getaddrinfo(NULL, "0", &hints, &resultingAddress);
	if (iResult != 0)
	{
		printf("getaddrinfo failed with error: %d\n", iResult);
		WSACleanup();
		return 1;
	}

	listenSocket = socket(AF_INET,      // IPv4 address famly
		SOCK_STREAM,  // stream socket (TCP)
		IPPROTO_TCP); // TCP

	if (listenSocket == INVALID_SOCKET)
	{
		printf("socket failed with error: %ld\n", WSAGetLastError());
		freeaddrinfo(resultingAddress);
		WSACleanup();
		return 1;
	}

	// Setup the TCP listening socket - bind port number and local address to socket
	iResult = bind(listenSocket, resultingAddress->ai_addr, (int)resultingAddress->ai_addrlen);
	if (iResult == SOCKET_ERROR)
	{
		printf("bind failed with error: %d\n", WSAGetLastError());
		freeaddrinfo(resultingAddress);
		closesocket(listenSocket);
		WSACleanup();
		return 1;
	}

	// Since we don't need resultingAddress any more, free it
	freeaddrinfo(resultingAddress);

	// SAMO DA BIH IZVUKLA IZ listenSocket-A ADERSU I PORT:
	struct sockaddr_in socketAddress;
	int socketAddress_len = sizeof(socketAddress);
	// Ask getsockname to fill in this socket's local adress
	if (getsockname(listenSocket, (sockaddr *)&socketAddress, &socketAddress_len) == -1)
	{
		printf("getsockname() failed.\n");
		return -1;
	}
	InetPton(AF_INET, TEXT(SERVER_IP_ADDRESS), &socketAddress.sin_addr.s_addr);
	// Print the IP address and local port
	printf("Local(listen) IP address is: %s\n", inet_ntoa(socketAddress.sin_addr));
	printf("Local(listen) port is: %d\n", (int)ntohs(socketAddress.sin_port));

	Message_For_Client packet;
	strcpy((char*)packet.listen_address, inet_ntoa(socketAddress.sin_addr));
	packet.listen_port = (int)ntohs(socketAddress.sin_port);


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
			//printf("send failed with error: %d\n", WSAGetLastError());
			printf("Server vise nije dostupan!");
			iResult = shutdown(connectSocket, SD_BOTH);
			if (iResult == SOCKET_ERROR)
			{
				printf("Shutdown failed with error: %d\n", WSAGetLastError());
				free(message);
				closesocket(connectSocket);
				WSACleanup();
				return 1;
			}

			printf("\nPress any key to exit: ");
			_getch();

			free(message);
			closesocket(connectSocket);
			WSACleanup();
			return 0;
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
			iResult = shutdown(connectSocket, SD_BOTH);
			if (iResult == SOCKET_ERROR)
			{
				printf("Shutdown failed with error: %d\n", WSAGetLastError());
				free(message);
				closesocket(connectSocket);
				WSACleanup();
				return 1;
			}
			

			printf("\nPress any key to exit: ");
			_getch();

			free(message);
			closesocket(connectSocket);
			WSACleanup();

			return 0;
			

		}
		else  // ako je server nasilno zatvoren
		{
			// there was an error during recv
			//printf("recv failed with error: %d\n", WSAGetLastError());
			//closesocket(connectSocket);
			printf("Server vise nije dostupan!\n");
			iResult = shutdown(connectSocket, SD_BOTH);
			if (iResult == SOCKET_ERROR)
			{
				printf("Shutdown failed with error: %d\n", WSAGetLastError());
				free(message);
				closesocket(connectSocket);
				WSACleanup();
				return 1;
			}

			printf("\nPress any key to exit: ");
			_getch();

			free(message);
			closesocket(connectSocket);
			WSACleanup();

			return 0;

		}

	}

	strcpy((char*)packet.flag, "2\0");  // prosledjivanje

	unsigned long mode = 1;
	iResult = ioctlsocket(connectSocket, FIONBIO, &mode);
	if (iResult != NO_ERROR) {
		printf("ioctlsocket failed with error: %ld\n", iResult);
		iResult = shutdown(connectSocket, SD_BOTH);
		if (iResult == SOCKET_ERROR)
		{
			printf("Shutdown failed with error: %d\n", WSAGetLastError());
			free(message);
			closesocket(connectSocket);
			WSACleanup();
			return 1;
		}

		printf("\nPress any key to exit: ");
		_getch();

		free(message);
		closesocket(connectSocket);
		WSACleanup();

		return 0;
	}


	EnterCriticalSection(&critical_section_hash_map);
	InitializeHashMap(HashMap);
	LeaveCriticalSection(&critical_section_hash_map);

	ResumeThread(thread);  // nit koja ce primati sve poruke od servera za prvi tip komunikacije
	ResumeThread(thread_for_accept_clients);  // nit koja ce osluskivati i accept-ovati ostale klijente


	printf("Trenutan nacin komunikacije sa klijentima je preko servera.\n");
	while (WaitForSingleObject(FinishSignal, 110) == WAIT_TIMEOUT) {

		//Sleep(110);

		do {

			if (WaitForSingleObject(FinishSignal, 1) != WAIT_TIMEOUT) {
				break;
			}

			EnterCriticalSection(&critical_section_server);
			printf("Da li zelite direktno da komunicirate sa klijentima? (da/ne)\n");
			scanf("%s", &communication_type);
			LeaveCriticalSection(&critical_section_server);

			for (int i = 0; communication_type[i]; i++) {
				communication_type[i] = tolower(communication_type[i]);
			}

			if (strcmp((const char*)communication_type, "da") == 0) {
				directly_communication = true;
				strcpy((char*)packet.flag, "3\0");  // direktno
			}

		} while (strcmp((const char*)communication_type, "da") != 0 && strcmp((const char*)communication_type, "ne") != 0);

		//Sleep(60);
		if (WaitForSingleObject(FinishSignal, 60) != WAIT_TIMEOUT || (strcmp((const char*)communication_type, "da") != 0 && strcmp((const char*)communication_type, "ne") != 0)) {
			break;
		}

		if (directly_communication == false) {

			EnterCriticalSection(&critical_section_server);
			printf("Unesite naziv klijenta kome zelite da posaljete poruku:\n");
			scanf("%s", &receiver);
			LeaveCriticalSection(&critical_section_server);
			getchar();
			strcpy((char*)packet.receiver, (char*)receiver);
			//printf("%s\n", packet.username);

			if (WaitForSingleObject(FinishSignal, 1) != WAIT_TIMEOUT) {
				break;
			}

			EnterCriticalSection(&critical_section_server);
			printf("Unesite poruku:\n");
			fgets(message, MAX_MESSAGE, stdin);
			LeaveCriticalSection(&critical_section_server);
			//printf("Poruka: %s\nbroj bajta: %d\n", message, strlen((char*)message));
			message[strlen(message) - 1] = message[strlen(message)];  // skidam novi red
			strcpy((char*)packet.message, (char*)message);
			iResult = send(connectSocket, (char*)&packet, sizeof(packet), 0);  // sizeof(Message_For_Client)
			if (iResult == SOCKET_ERROR)
			{
				//printf("send failed with error: %d\n", WSAGetLastError());
				break;
			}

			//Sleep(110); prebacila sam ga gore

		}
		else {  // direktan komunikacija

			break;
		}

	}

	if (directly_communication != true) {  // nije u pitanju break zbog prealaza na direktnu, vec zbog gasenja servera...
		// kopiranooooooooooooooooooooooooooooooo
		printf("Server vise nije dostupan!");
		ReleaseSemaphore(FinishThreadSignal, 1, NULL);
		ReleaseSemaphore(FinishSignal, 1, NULL);
		if (thread != NULL) {
			WaitForSingleObject(thread, INFINITE);
		}
		if (thread_for_accept_clients != NULL) {
			WaitForSingleObject(thread_for_accept_clients, INFINITE);
		}
		
		// obrisane sve niti - ok
		SAFE_DELETE_HANDLE(thread_directly_recv);
		SAFE_DELETE_HANDLE(thread_send_message_directly);
		SAFE_DELETE_HANDLE(thread_for_accept_clients);
		SAFE_DELETE_HANDLE(thread_recv_on_connectSockets);

		//// k.s. doraditi...
		//DeleteCriticalSection(&critical_section_directly);
		//DeleteCriticalSection(&critical_section_hash_map);

		KrajPrograma();

		free(message);

		return 0;
		// dovdeeeeeeeeeeeeeeeeeeeeeeeeeeeee
	}

	/*-------------------------------------------------------------DIREKTNA KOMUNIKACIJA----------------------------------------------------------------------------------------*/
	free(message);

	// serveru prebaci me na direktno
	strcpy((char*)packet.flag, "4\0");
	iResult = send(connectSocket, (char*)&packet, sizeof(packet), 0);  // sizeof(Message_For_Client)
	if (iResult == SOCKET_ERROR)
	{
		//printf("send failed with error: %d\n", WSAGetLastError());
		printf("Server vise nije dostupan!");
		ReleaseSemaphore(FinishThreadSignal, 1, NULL);
		ReleaseSemaphore(FinishSignal, 1, NULL);
		if (thread != NULL) {
			WaitForSingleObject(thread, INFINITE);
		}
		if (thread_for_accept_clients != NULL) {
			WaitForSingleObject(thread_for_accept_clients, INFINITE);
		}
		
		SAFE_DELETE_HANDLE(thread_directly_recv);
		SAFE_DELETE_HANDLE(thread_send_message_directly);
		SAFE_DELETE_HANDLE(thread_for_accept_clients);
		SAFE_DELETE_HANDLE(thread_recv_on_connectSockets);

		//// k.s. doraditi...
		//DeleteCriticalSection(&critical_section_directly);
		//DeleteCriticalSection(&critical_section_hash_map);

		KrajPrograma();

		free(message);

		return 0;

	}

	// gasimo nit koja je do sada primala poruke od servera i oslobadjamo resurse...
	ReleaseSemaphore(FinishThreadSignal, 1, NULL);
	if (thread != NULL) {

		WaitForSingleObject(thread, INFINITE);  // sacekati da se zavrsi nit
	}
	SAFE_DELETE_HANDLE(FinishThreadSignal);  // ok
	SAFE_DELETE_HANDLE(thread);  // ok
	/*-------------------------------------------------------------------------------------------------------------------------------*/
	ResumeThread(thread_directly_recv);  // primace poruke od servera
	ResumeThread(thread_send_message_directly);  // pravice konekciju sa ostalim klijentima
	ResumeThread(thread_recv_on_connectSockets);  // nit koja ce primati poruke na connectSockets_directly soketima

	strcpy((char*)packet.flag, "3\0");  // direktno
	printf("Presli ste na direktan nacin komunikacije sa klijentima!\n");

	char *directly_message = (char*)malloc(MAX_MESSAGE_DIRECTLY);
	Directly_Message directly_message_packet;

	HANDLE semaphores[2] = { FinishSignal_Directly, StartMainSignal };
	while (WaitForMultipleObjects((DWORD)2, semaphores, FALSE, INFINITE) == WAIT_OBJECT_0 + 1) {

		Sleep(110);
		bool break_all = false;

		EnterCriticalSection(&critical_section_directly);
		printf("Unesite naziv klijenta sa kojim zelite da komunicirate:\n");
		scanf("%s", &receiver);
		LeaveCriticalSection(&critical_section_directly);
		//getchar();

		if (WaitForSingleObject(FinishSignal_Directly, 1) != WAIT_TIMEOUT) {
			break;
		}
		 
		bool postoji = false;

		EnterCriticalSection(&critical_section_hash_map);
		postoji = ClientExistsInHashMap(HashMap, receiver);
		LeaveCriticalSection(&critical_section_hash_map);

		if (!postoji) {  // nismo direktno povezani sa zeljenim klijentom, trazimo njegove podatke od servera:

			strcpy((char*)packet.receiver, (char*)receiver);
			iResult = send(connectSocket, (char*)&packet, sizeof(packet), 0);
			if (iResult == SOCKET_ERROR)
			{
				printf("Server vise nije dostupan!\n");
				break;
			}


		}
		else {  // vec smo direktno povezani sa zeljenim klijentom, vadimo njegove podatke iz Hash mape:

			printf("VEC SAM POVEZAN NA TOG KLIJENTA!!! \t Njegovi podaci:\n");

			EnterCriticalSection(&critical_section_hash_map);
			ClientData *client_from_HashMap = FindValueInHashMap(HashMap, receiver);
			LeaveCriticalSection(&critical_section_hash_map);
			printf("Client Name: %s\n", client_from_HashMap->name);
			printf("Client Listen IP address is: %s\n", client_from_HashMap->address);
			printf("Client Listen Port is: %d\n", client_from_HashMap->port);
			printf("Client Socket Type: %s\n", client_from_HashMap->socket_type);

			if (strcmp((char*)client_from_HashMap->socket_type, "1\0") == 0) {

				// pretraziti acceptedSocket-e

				bool nasao_a = false;

				struct sockaddr_in socketAddress;  // struktura za smestanje adrese i porta iz socket-a iz connectSocket_directly niza
				int socketAddress_len = sizeof(socketAddress);

				for (int k = 0; k < counter_accepted_clients; k++)
				{
					// Ask getsockname to fill in this socket's local adress
					if (getpeername(acceptedSockets[k], (sockaddr *)&socketAddress, &socketAddress_len) == -1)
					{
						//printf("getsockname() failed.\n");
						//return -1;
						// doraditi...
						//printf("Pokusajte ponovo!\n");
						break;
					}

					char client_address[MAX_ADDRESS];  // klijentska listen address-a, samo pretvorena u ascii
					//strcpy(client_address, inet_ntoa(socketAddress.sin_addr));
					inet_ntop(AF_INET, &socketAddress.sin_addr, client_address, INET_ADDRSTRLEN);
					//printf("%d\n", (int)ntohs(socketAddress.sin_port));
					//printf("%d\n", (int)htons(socketAddress.sin_port));
					//printf("%d\n", ntohs(socketAddress.sin_port));


					if ((strcmp(client_address, (char*)client_from_HashMap->address) == 0) && ((unsigned int)ntohs(socketAddress.sin_port) == client_from_HashMap->port))
					{
						nasao_a = true;

						getchar();
						EnterCriticalSection(&critical_section_directly);
						printf("Unesite poruku:\n");
						fgets(directly_message, MAX_MESSAGE_DIRECTLY, stdin);
						LeaveCriticalSection(&critical_section_directly);

						if (WaitForSingleObject(FinishSignal_Directly, 1) != WAIT_TIMEOUT) {
							break_all = true;
							break;
						}

						//printf("Poruka: %s\nbroj bajta: %d\n", message, strlen((char*)message));
						directly_message[strlen(directly_message) - 1] = directly_message[strlen(directly_message)];  // skidam novi red
						strcpy((char*)directly_message_packet.flag, "1\0");
						sprintf((char*)directly_message_packet.message, "[%s]:%s", (char*)sender, directly_message);
						//printf("Poruka direktna za klijenta: %s\n", directly_message_packet.message);
						iResult = send(acceptedSockets[k], (char*)&directly_message_packet, sizeof(directly_message_packet), 0);
						if (iResult == SOCKET_ERROR)
						{
							//printf("send failed with error: %d\n", WSAGetLastError());
							printf("Poruka nije poslata, jer klijent vise nije dostupan!\n");
							closesocket(acceptedSockets[k]);
							for (int j = k; j < counter_accepted_clients - 1; j++)
							{
								acceptedSockets[j] = acceptedSockets[j + 1];
							}
							acceptedSockets[counter_accepted_clients - 1] = INVALID_SOCKET;
							counter_accepted_clients--;

							EnterCriticalSection(&critical_section_hash_map);
							RemoveValueFromHashMap(HashMap, client_from_HashMap->name);
							ShowHashMap(HashMap);
							LeaveCriticalSection(&critical_section_hash_map);
							//WSACleanup();
							//return 1;
						}
						else {
							printf("Poruka je uspesno poslata zeljenom klijentu!\n");
						}

						break;
					}

				}

				if (break_all == true) {
					break;
				}

				if (nasao_a == false) {  // ako se desi greska na getsockname() ili ako ne postoji socket u nizu acceptSocket sa adresom i portom trazenog klijenta

					printf("Pokusajte ponovo!\n");
				}





			}
			else {

				// pretraziti connectSocket-e

				bool nasao = false;

				struct sockaddr_in socketAddress;  // struktura za smestanje adrese i porta iz socket-a iz connectSocket_directly niza
				int socketAddress_len = sizeof(socketAddress);

				for (int k = 0; k < count_connect_sockets; k++)
				{
					// Ask getsockname to fill in this socket's local adress
					if (getpeername(coonectSockets_directly[k], (sockaddr *)&socketAddress, &socketAddress_len) == -1)
					{
						//printf("getsockname() failed.\n");
						//return -1;
						// doraditi...
						//printf("Pokusajte ponovo!\n");
						break;
					}

					char client_address[MAX_ADDRESS];  // klijentska listen address-a, samo pretvorena u ascii
					//strcpy(client_address, inet_ntoa(socketAddress.sin_addr));
					inet_ntop(AF_INET, &socketAddress.sin_addr, client_address, INET_ADDRSTRLEN);
					//printf("%d\n", (int)ntohs(socketAddress.sin_port));
					//printf("%d\n", (int)htons(socketAddress.sin_port));
					//printf("%d\n", ntohs(socketAddress.sin_port));


					if ((strcmp(client_address, (char*)client_from_HashMap->address) == 0) && ((unsigned int)ntohs(socketAddress.sin_port) == client_from_HashMap->port))
					{
						nasao = true;

						getchar();
						EnterCriticalSection(&critical_section_directly);
						printf("Unesite poruku:\n");
						fgets(directly_message, MAX_MESSAGE_DIRECTLY, stdin);
						LeaveCriticalSection(&critical_section_directly);

						if (WaitForSingleObject(FinishSignal_Directly, 1) != WAIT_TIMEOUT) {
							break_all = true;
							break;
						}

						//printf("Poruka: %s\nbroj bajta: %d\n", message, strlen((char*)message));
						directly_message[strlen(directly_message) - 1] = directly_message[strlen(directly_message)];  // skidam novi red
						strcpy((char*)directly_message_packet.flag, "1\0");
						sprintf((char*)directly_message_packet.message, "[%s]:%s", (char*)sender, directly_message);
						//printf("Poruka direktna za klijenta: %s\n", directly_message_packet.message);
						iResult = send(coonectSockets_directly[k], (char*)&directly_message_packet, sizeof(directly_message_packet), 0);
						if (iResult == SOCKET_ERROR)
						{
							//printf("send failed with error: %d\n", WSAGetLastError());
							printf("Poruka nije poslata, jer klijent vise nije dostupan!\n");
							closesocket(coonectSockets_directly[k]);
							for (int j = k; j < count_connect_sockets - 1; j++)
							{
								coonectSockets_directly[j] = coonectSockets_directly[j + 1];
							}
							coonectSockets_directly[count_connect_sockets - 1] = INVALID_SOCKET;
							count_connect_sockets--;

							EnterCriticalSection(&critical_section_hash_map);
							RemoveValueFromHashMap(HashMap, client_from_HashMap->name);
							ShowHashMap(HashMap);
							LeaveCriticalSection(&critical_section_hash_map);
							//WSACleanup();
							//return 1;
						}
						else {
							printf("Poruka je uspesno poslata zeljenom klijentu!\n");
						}
						
						break;
					}

				}

				if (break_all == true) {
					break;
				}

				if (nasao == false) {  // ako se desi greska na getsockname() ili ako ne postoji socket u nizu connectSocket_directly sa adresom i portom trazenog klijenta

					printf("Pokusajte ponovo!\n");
				}

			}

			ReleaseSemaphore(StartMainSignal, 1, NULL);  // znak da main() zavrti petlju za unos novog klijenta

		}



	}

	// OVDE IDE KOD KADA SERVER PADNE:
	if (thread_directly_recv != NULL) {

		WaitForSingleObject(thread_directly_recv, INFINITE);  // sacekati da se zavrsi nit
	}
	if (thread_send_message_directly != NULL) {

		WaitForSingleObject(thread_send_message_directly, INFINITE);  // sacekati da se zavrsi nit
	}
	if (thread_recv_on_connectSockets != NULL) {

		WaitForSingleObject(thread_recv_on_connectSockets, INFINITE);  // sacekati da se zavrsi nit
	}
	if (thread_for_accept_clients != NULL) {

		WaitForSingleObject(thread_for_accept_clients, INFINITE);  // sacekati da se zavrsi nit
	}

	 // obrisane sve niti - ok
	SAFE_DELETE_HANDLE(thread_directly_recv);
	SAFE_DELETE_HANDLE(thread_send_message_directly);
	SAFE_DELETE_HANDLE(thread_for_accept_clients);
	SAFE_DELETE_HANDLE(thread_recv_on_connectSockets);

	//// k.s. doraditi...
	//DeleteCriticalSection(&critical_section_directly);
	//DeleteCriticalSection(&critical_section_hash_map);

	KrajPrograma();

	free(directly_message);

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

void KrajPrograma() {

	int iResult = 0;

	// svi semafori su obrisani - ok
	SAFE_DELETE_HANDLE(FinishSignal_Directly);
	SAFE_DELETE_HANDLE(StartMainSignal);
	SAFE_DELETE_HANDLE(StartSendMessageSignal);
	SAFE_DELETE_HANDLE(FinishSignal);
	
	// k.s. doraditi...
	DeleteCriticalSection(&critical_section_directly);
	DeleteCriticalSection(&critical_section_hash_map);

	printf("\nPress any key to exit: ");
	_getch();

	// zatvoriti sve ostale sokete....................
	// soket sa serverom:
	iResult = shutdown(connectSocket, SD_BOTH);
	if (iResult == SOCKET_ERROR)
	{
		printf("Shutdown failed with error: %d\n", WSAGetLastError());
	}
	closesocket(connectSocket);

	// soketi sa klijentima:
	for (int i = 0; i < counter_accepted_clients; i++) {
		iResult = shutdown(acceptedSockets[i], SD_BOTH);
		if (iResult == SOCKET_ERROR)
		{
			printf("Shutdown failed with error: %d\n", WSAGetLastError());
		}
		closesocket(acceptedSockets[i]);
	}

	for (int i = 0; i < count_connect_sockets; i++) {
		iResult = shutdown(coonectSockets_directly[i], SD_BOTH);
		if (iResult == SOCKET_ERROR)
		{
			printf("Shutdown failed with error: %d\n", WSAGetLastError());
		}
		closesocket(coonectSockets_directly[i]);
	}

	WSACleanup();

	return;
}
