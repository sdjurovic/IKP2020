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

#define MAX_DIRECTLY_CONNECTIONS 10

#define SERVER_IP_ADDRESS "127.0.0.1"

/* Makro za bezbedno brisanje handle-ova.*/
#define SAFE_DELETE_HANDLE(a) if(a){CloseHandle(a);}

// Initializes WinSock2 library
// Returns true if succeeded, false otherwise.
bool InitializeWindowsSockets();

HANDLE StartSignal;
HANDLE FinishSignal;
CRITICAL_SECTION critical_section_server;

SOCKET connectSocket;  // socket used to communicate with server
SOCKET coonectSockets_directly[MAX_DIRECTLY_CONNECTIONS];  // sockets used to communicate with other clients
int count_connect_sockets;

HANDLE StartMainSignal;
HANDLE StartSendMessageSignal;
HANDLE FinishSignal_Directly;
CRITICAL_SECTION critical_section_directly;

struct Client_Information_Directly  // dobijam od servera informacije o klijentu sa kojim treba da se povezem
{
	unsigned char my_username[MAX_USERNAME];
	unsigned char client_username[MAX_USERNAME];  // dodala...da bih znala kod dodavanja u hash sa kim sam ostvarila konekciju...
	unsigned char message[MAX_MESSAGE];
	unsigned char listen_address[MAX_ADDRESS];
	unsigned int listen_port;
};

struct Element* HashMap[MAX_CLIENTS];

DWORD WINAPI thread_function(LPVOID parametri) {

	HANDLE semaphores[2] = { FinishSignal, StartSignal };
	while (WaitForMultipleObjects((DWORD)2, semaphores, FALSE, INFINITE) == WAIT_OBJECT_0 + 1) {

		int iResult;
		char recvbuf[DEFAULT_BUFLEN];

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
			iResult = shutdown(connectSocket, SD_BOTH);
			if (iResult == SOCKET_ERROR)
			{
				printf("Shutdown failed with error: %d\n", WSAGetLastError());
				closesocket(connectSocket);
				WSACleanup();
				return 1;
			}

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
				ReleaseSemaphore(StartSignal, 1, NULL);
				//Sleep(1000);
				continue;
			}
			else {

				// there was an error during recv
				//printf("recv failed with error: %d\n", WSAGetLastError());
				//closesocket(connectSocket);
				printf("\nIzgubljena je konekcija sa serverom...\n");
				iResult = shutdown(connectSocket, SD_BOTH);
				if (iResult == SOCKET_ERROR)
				{
					printf("Shutdown failed with error: %d\n", WSAGetLastError());
					closesocket(connectSocket);
					WSACleanup();
					return 1;
				}

				//printf("\nPress any key to exit: ");
				//_getch();

				//free(message);

				//closesocket(connectSocket);
				//WSACleanup();

				return 0;
			}
		}

		ReleaseSemaphore(StartSignal, 1, NULL);

	}

	return 0;
}

DWORD WINAPI function_recv_directly(LPVOID parametri) {

	int iResult;
	char recvbuf[DEFAULT_BUFLEN];
	//int count_connect_sockets = 0;

	while (true) {


		iResult = recv(connectSocket, recvbuf, DEFAULT_BUFLEN, 0);  // sta god da dobije od servera treba da ispise i da zavrti petlju opet...
		if (iResult > 0)
		{
			//recvbuf[iResult] = '\0';
			//printf("Message received from server: %s\n", recvbuf);
			Client_Information_Directly *client_informations = (Client_Information_Directly*)recvbuf;
			/*
			// samo za testiranje:
			EnterCriticalSection(&critical_section_directly);
			printf("My username: %s\n", client_informations->my_username);
			printf("Client username: %s\n", client_informations->client_username);
			printf("Message: %s\n", client_informations->message);
			printf("Ip address: %s\n", client_informations->listen_address);
			printf("Port: %d\n", client_informations->listen_port);
			LeaveCriticalSection(&critical_section_directly);
			*/

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

					continue;
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
			iResult = shutdown(connectSocket, SD_BOTH);
			if (iResult == SOCKET_ERROR)
			{
				printf("Shutdown failed with error: %d\n", WSAGetLastError());
				closesocket(connectSocket);
				WSACleanup();
				return 1;
			}


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
				iResult = shutdown(connectSocket, SD_BOTH);
				if (iResult == SOCKET_ERROR)
				{
					printf("Shutdown failed with error: %d\n", WSAGetLastError());
					closesocket(connectSocket);
					WSACleanup();
					return 1;
				}


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
	char *directly_message = (char*)malloc(DEFAULT_BUFLEN);
	int iResult;

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
			/*
			// za testiranje dok nema accept-a:
			ClientData *newClient = (ClientData*)malloc(sizeof(ClientData));
			strcpy((char*)newClient->name, (char*)information->client_username);
			strcpy((char*)newClient->address, (char*)information->listen_address);
			newClient->port = information->listen_port;  // host zapis
			strcpy((char*)newClient->socket_type, "0\0");
			AddValueToHashMap(HashMap, newClient);
			ShowHashMap(HashMap);
			count_connect_sockets++;
			*/
			
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
			ClientData *newClient = (ClientData*)malloc(sizeof(ClientData));
			strcpy((char*)newClient->name, (char*)information->client_username);
			strcpy((char*)newClient->address, (char*)information->listen_address);
			newClient->port = information->listen_port;
			strcpy((char*)newClient->socket_type, "0\0");
			AddValueToHashMap(HashMap, newClient);
			ShowHashMap(HashMap);

			EnterCriticalSection(&critical_section_server);
			printf("Unesite poruku:\n");
			fgets(directly_message, MAX_MESSAGE, stdin);
			LeaveCriticalSection(&critical_section_server);
			//printf("Poruka: %s\nbroj bajta: %d\n", message, strlen((char*)message));
			directly_message[strlen(directly_message) - 1] = directly_message[strlen(directly_message)];  // skidam novi red
			char final_message[DEFAULT_BUFLEN];
			sprintf((char*)final_message, "[%s]:%s", information->my_username, directly_message);
			iResult = send(coonectSockets_directly[count_connect_sockets - 1], directly_message, (int)strlen(directly_message) + 1, 0);  // +1 zbog null karaktera kojeg cemo dodati na serveru
			if (iResult == SOCKET_ERROR)
			{
				//printf("send failed with error: %d\n", WSAGetLastError());
				printf("Poruka nije poslata, jer klijent vise nije dostupan!\n");
				// poravnavanje socket-a nije potrebno jer j euvek u pitanju poslednji
				closesocket(coonectSockets_directly[count_connect_sockets - 1]);
				coonectSockets_directly[count_connect_sockets - 1] = INVALID_SOCKET;
				count_connect_sockets--;
				//WSACleanup();
				ReleaseSemaphore(StartMainSignal, 1, NULL);  // znak da main() zavrti petlju za unos novog klijenta
				continue;
				//return 1;
			}

			EnterCriticalSection(&critical_section_server);
			printf("Poruka je uspesno poslata zeljenom klijentu!\n");
			LeaveCriticalSection(&critical_section_server);

		}

		ReleaseSemaphore(StartMainSignal, 1, NULL);  // znak da main() zavrti petlju za unos novog klijenta
	}

	free(directly_message);

	return 0;

}




int main()
{

	Client_Information_Directly *client_information_for_thread = (Client_Information_Directly*)malloc(sizeof(Client_Information_Directly));
	//Client_Information_Directly *client_information_for_thread;

	HANDLE thread;
	DWORD thread_id;

	HANDLE thread_directly_recv;
	DWORD thread_directly_recv_id;

	HANDLE thread_send_message_directly;
	DWORD thread_send_message_directly_id;

	StartSignal = CreateSemaphore(NULL, 0, 1, NULL);
	FinishSignal = CreateSemaphore(NULL, 0, 1, NULL);

	StartMainSignal = CreateSemaphore(NULL, 1, 1, NULL);
	StartSendMessageSignal = CreateSemaphore(NULL, 0, 1, NULL);
	FinishSignal_Directly = CreateSemaphore(NULL, 0, 2, NULL);

	if (StartSignal && FinishSignal && StartSendMessageSignal && FinishSignal_Directly && StartMainSignal) {

		InitializeCriticalSection(&critical_section_server);
		InitializeCriticalSection(&critical_section_directly);
		thread = CreateThread(NULL, 0, &thread_function, NULL, 0, &thread_id);
		thread_directly_recv = CreateThread(NULL, 0, &function_recv_directly, &client_information_for_thread, CREATE_SUSPENDED, &thread_directly_recv_id);
		thread_send_message_directly = CreateThread(NULL, 0, &function_send_message_directly, &client_information_for_thread, CREATE_SUSPENDED, &thread_send_message_directly_id);

	}
	else {

		SAFE_DELETE_HANDLE(FinishSignal);
		SAFE_DELETE_HANDLE(StartSendMessageSignal);
		SAFE_DELETE_HANDLE(StartSignal);
		SAFE_DELETE_HANDLE(FinishSignal_Directly);
		SAFE_DELETE_HANDLE(StartMainSignal);
		SAFE_DELETE_HANDLE(thread);
		SAFE_DELETE_HANDLE(thread_directly_recv);
		SAFE_DELETE_HANDLE(thread_send_message_directly);
		DeleteCriticalSection(&critical_section_server);
		DeleteCriticalSection(&critical_section_directly);

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

	

	connectSocket = INVALID_SOCKET;

	for (int i = 0; i < MAX_CLIENTS; i++) {
		coonectSockets_directly[i] = INVALID_SOCKET;
	}
	count_connect_sockets = 0;

	// Socket used for listening for new clients 
	SOCKET listenSocket = INVALID_SOCKET;
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

			free(message);
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
	}

	// odavde bi trebalo da se ukljuci i druga nit koja ce primati sve poruke od servera za prvi tip komunikacije
	ReleaseSemaphore(StartSignal, 1, NULL);

	printf("Trenutan nacin komunikacije sa klijentima je preko servera.\n");
	while (true) {

		Sleep(110);

		do {
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

		Sleep(60);

		if (directly_communication == false) {

			EnterCriticalSection(&critical_section_server);
			printf("Unesite naziv klijenta kome zelite da posaljete poruku:\n");
			scanf("%s", &receiver);
			LeaveCriticalSection(&critical_section_server);
			getchar();
			strcpy((char*)packet.receiver, (char*)receiver);
			//printf("%s\n", packet.username);
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
				printf("Server vise nije dostupan!");

				ReleaseSemaphore(FinishSignal_Directly, 1, NULL);
				if (thread != NULL) {

					WaitForSingleObject(thread, INFINITE);  // sacekati da se zavrsi nit
				}

				SAFE_DELETE_HANDLE(FinishSignal_Directly);
				SAFE_DELETE_HANDLE(StartSignal);
				SAFE_DELETE_HANDLE(thread);
				DeleteCriticalSection(&critical_section_server);

				free(message);

				printf("\nPress any key to exit: ");
				_getch();

				iResult = shutdown(connectSocket, SD_BOTH);
				if (iResult == SOCKET_ERROR)
				{
					printf("Shutdown failed with error: %d\n", WSAGetLastError());
					closesocket(connectSocket);
					WSACleanup();
					return 1;
				}
				
				closesocket(connectSocket);
				WSACleanup();

				return 1;
			}

			//Sleep(110); prebacila sam ga gore

		}
		else {  // direktan komunikacija

			break;
		}

	}

	/*-------------------------------------------------------------DIREKTNA KOMUNIKACIJA----------------------------------------------------------------------------------------*/
	free(message);

	InitializeHashMap(HashMap);

	// serveru prebaci me na direktno
	strcpy((char*)packet.flag, "4\0");  
	iResult = send(connectSocket, (char*)&packet, sizeof(packet), 0);  // sizeof(Message_For_Client)
	if (iResult == SOCKET_ERROR)
	{
		//printf("send failed with error: %d\n", WSAGetLastError());
		printf("Server vise nije dostupan!");

		ReleaseSemaphore(FinishSignal, 1, NULL);
		if (thread != NULL) {

			WaitForSingleObject(thread, INFINITE);  // sacekati da se zavrsi nit
		}

		SAFE_DELETE_HANDLE(FinishSignal);
		SAFE_DELETE_HANDLE(StartSignal);
		SAFE_DELETE_HANDLE(thread);
		DeleteCriticalSection(&critical_section_server);

		printf("\nPress any key to exit: ");
		_getch();

		iResult = shutdown(connectSocket, SD_BOTH);
		if (iResult == SOCKET_ERROR)
		{
			printf("Shutdown failed with error: %d\n", WSAGetLastError());
			closesocket(connectSocket);
			WSACleanup();
			return 1;
		}

		closesocket(connectSocket);
		WSACleanup();

		return 1;
	}

	// gasimo nit koja je do sada primala poruke od servera i oslobadjamo resurse...
	ReleaseSemaphore(FinishSignal, 1, NULL);
	if (thread != NULL) {

		WaitForSingleObject(thread, INFINITE);  // sacekati da se zavrsi nit
	}
	SAFE_DELETE_HANDLE(FinishSignal);
	SAFE_DELETE_HANDLE(StartSignal);
	SAFE_DELETE_HANDLE(thread);
	DeleteCriticalSection(&critical_section_server);

	/*---------------------------------------------------------------------------------------------*/

	ResumeThread(thread_directly_recv);  // aktiviram nit
	ResumeThread(thread_send_message_directly);  // aktiviram nit

	strcpy((char*)packet.flag, "3\0");  // direktno
	printf("Presli ste na direktan nacin komunikacije sa klijentima!\n");

	char *directly_message = (char*)malloc(DEFAULT_BUFLEN);

	HANDLE semaphores[2] = { FinishSignal_Directly, StartMainSignal };
	while (WaitForMultipleObjects((DWORD)2, semaphores, FALSE, INFINITE) == WAIT_OBJECT_0 + 1) {

		Sleep(110);

		EnterCriticalSection(&critical_section_directly);
		printf("Unesite naziv klijenta sa kojim zelite da komunicirate:\n");
		scanf("%s", &receiver);
		LeaveCriticalSection(&critical_section_directly);
		//getchar();

		if (!ClientExistsInHashMap(HashMap, receiver)) {  // nismo direktno povezani sa zeljenim klijentom, trazimo njegove podatke od servera:

			strcpy((char*)packet.receiver, (char*)receiver);
			iResult = send(connectSocket, (char*)&packet, sizeof(packet), 0);
			if (iResult == SOCKET_ERROR)
			{
				printf("Server vise nije dostupan!");
				ReleaseSemaphore(FinishSignal_Directly, 2, NULL);
				if (thread_directly_recv != NULL) {

					WaitForSingleObject(thread_directly_recv, INFINITE);  // sacekati da se zavrsi nit
				}
				if (thread_send_message_directly != NULL) {

					WaitForSingleObject(thread_send_message_directly, INFINITE);  // sacekati da se zavrsi nit
				}

				SAFE_DELETE_HANDLE(FinishSignal_Directly);
				SAFE_DELETE_HANDLE(StartMainSignal);
				SAFE_DELETE_HANDLE(StartSendMessageSignal);
				SAFE_DELETE_HANDLE(thread_directly_recv);
				SAFE_DELETE_HANDLE(thread_send_message_directly);
				DeleteCriticalSection(&critical_section_directly);

				printf("\nPress any key to exit: ");
				_getch();

				iResult = shutdown(connectSocket, SD_BOTH);
				if (iResult == SOCKET_ERROR)
				{
					printf("Shutdown failed with error: %d\n", WSAGetLastError());
					closesocket(connectSocket);
					WSACleanup();
					return 1;
				}

				closesocket(connectSocket);
				WSACleanup();

				return 1;
			}


		}
		else {  // vec smo direktno povezani sa zeljenim klijentom, vadimo njegove podatke iz Hash mape:

			printf("VEC SAM POVEZAN NA TOG KLIJENTA!!! \t Njegovi podaci:\n");

			ClientData *client_from_HashMap = FindValueInHashMap(HashMap, receiver);
			printf("Client Name: %s\n", client_from_HashMap->name);
			printf("Client Listen IP address is: %s\n", client_from_HashMap->address);
			printf("Client Listen Port is: %d\n", client_from_HashMap->port);
			printf("Client Socket Type: %s\n", client_from_HashMap->socket_type);
			
			if (strcmp((char*)client_from_HashMap->socket_type, "1\0") == 0) {

				// pretraziti acceptedSocket-e





				
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
						//break;
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

						EnterCriticalSection(&critical_section_server);
						printf("Unesite poruku:\n");
						fgets(directly_message, MAX_MESSAGE, stdin);
						LeaveCriticalSection(&critical_section_server);
						//printf("Poruka: %s\nbroj bajta: %d\n", message, strlen((char*)message));
						directly_message[strlen(directly_message) - 1] = directly_message[strlen(directly_message)];  // skidam novi red
						char final_message[DEFAULT_BUFLEN];
						sprintf((char*)final_message, "[%s]:%s", (char*)sender, directly_message);
						iResult = send(coonectSockets_directly[k], directly_message, (int)strlen(directly_message) + 1, 0);  // +1 zbog null karaktera kojeg cemo dodati na serveru
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

							RemoveValueFromHashMap(HashMap, client_from_HashMap->name);
							ShowHashMap(HashMap);
							//WSACleanup();
							//return 1;
						}

						printf("Poruka je uspesno poslata zeljenom klijentu!\n");
						break;
					}

				}

				if (nasao == false) {  // ako se desi greska na getsockname() ili ako ne postoji socket u nizu connectSocket_directly sa adresom i portom trazenog klijenta

					printf("Pokusajte ponovo!\n");
					printf("NESTO TI JE PROMAKLO JELENA...\n");
				}

			}

			ReleaseSemaphore(StartMainSignal, 1, NULL);  // znak da main() zavrti petlju za unos novog klijenta

		}


		


	}










	// obrisati ovo ispod ako ne bude trebalo...
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
