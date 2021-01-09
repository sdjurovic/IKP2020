#include <ws2tcpip.h>
#include <stdlib.h>
#include <stdio.h>
#include "../PeerToPeer/HashMap.cpp"

#define DEFAULT_BUFLEN 512
#define DEFAULT_PORT "27016"
#define MAX_CLIENTS 10
#define DEFAULT_ADDRESS "127.0.0.1"
#define MAX_USERNAME 25
#define MAX_MESSAGE 400
#define MAX_ADDRESS 50

bool InitializeWindowsSockets();
bool CheckIfSocketIsConnected(SOCKET socket);

// have function for handling accepts and reading the reacieved data
//void ReadFromSockets(SOCKET sockets[], int *socketsCount, fd_set* readfds);
//void AcceptIncoming(SOCKET acceptedSockets[], int *freeIndex, SOCKET listenSocket, fd_set* readfds);

int  main(void)
{
	struct Message_For_Client  // ovo ide u .h
	{
		unsigned char sender[MAX_USERNAME];
		unsigned char receiver[MAX_USERNAME];
		unsigned char message[MAX_MESSAGE];
		unsigned char listen_address[MAX_ADDRESS];
		unsigned int listen_port;
		unsigned char flag[2];  // vrednosti: "1"(registracija) / "2"(prosledjivanje) / "3"(direktno) / "4"(presao sam na direktnu)+ null terminator
	};

	struct Client_Information_Directly  // ovo ide u .h
	{
		unsigned char message[MAX_MESSAGE];
		unsigned char listen_address[MAX_ADDRESS];
		unsigned int listen_port;
	};


	// Socket used for listening for new clients 
	SOCKET listenSocket = INVALID_SOCKET;
	//array of sockets
	SOCKET acceptedSockets[MAX_CLIENTS];
	for (int i = 0; i < MAX_CLIENTS; i++) {
		acceptedSockets[i] = INVALID_SOCKET;
	}

	//current number of sockets server is listening to
	int connectedSockets = 0;
	// Socket used for communication with client
	SOCKET acceptedSocket = INVALID_SOCKET;
	fd_set readfds;
	// non-blocking listening mode
	unsigned long mode = 1;
	// variable used to store function return value
	int iResult;

	// initiallization of the hashmap
	InitializeHashMap();

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
	iResult = getaddrinfo(NULL, DEFAULT_PORT, &hints, &resultingAddress);
	if (iResult != 0)
	{
		printf("getaddrinfo failed with error: %d\n", iResult);
		WSACleanup();
		return 1;
	}

	// Create a SOCKET for connecting to server
	listenSocket = socket(AF_INET,      // IPv4 address famly
		SOCK_STREAM,  // stream socket (TCP)
		IPPROTO_TCP); // TCP

	if (listenSocket == INVALID_SOCKET)
	{
		printf("socket failed with error: %ld\n", WSAGetLastError());
		//freeaddrinfo(resultingAddress);
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

	// Set listenSocket to non-blocking listening mode
	iResult = ioctlsocket(listenSocket, FIONBIO, &mode);
	if (iResult != NO_ERROR)
	{
		printf("ioctlsocket failed with error: %ld\n", iResult);
		return 0;
	}


	// Set listenSocket in listening mode
	iResult = listen(listenSocket, SOMAXCONN);  // drugi parametar = max broj klijentskih zahteva koji mogu stici istovremeno i koji ce biti stavljeni u red za opsluzivanje
	if (iResult == SOCKET_ERROR)
	{
		printf("listen failed with error: %d\n", WSAGetLastError());
		closesocket(listenSocket);
		WSACleanup();
		return 1;
	}

	//printf("Server initialized, waiting for clients.\n");
	printf("Server socket is set to listening mode. Waiting for new connection requests.\n");

	char recvbuf[DEFAULT_BUFLEN];

	FD_ZERO(&readfds);

	timeval timeVal;
	timeVal.tv_sec = 1;
	timeVal.tv_usec = 0;

	do
	{
		if (connectedSockets < MAX_CLIENTS) {
			FD_SET(listenSocket, &readfds);
		}

		for (int i = 0; i < connectedSockets; i++)
		{
			FD_SET(acceptedSockets[i], &readfds);
		}

		int result = select(0, &readfds, NULL, NULL, &timeVal);

		if (result == 0)
		{
			// timeout has expired, continue
			continue;
		}
		else if (result == SOCKET_ERROR)
		{
			// error has occurd while calling a function
			for (int i = 0; i < connectedSockets; i++)
			{
				char temp_buffer;
				if (recv(acceptedSockets[i], &temp_buffer, 1, MSG_PEEK) == SOCKET_ERROR && WSAGetLastError() != WSAEWOULDBLOCK)
				{
					closesocket(acceptedSockets[i]);
					connectedSockets--;
				}
			}
			printf("error has occurd while calling a function: %d\n", WSAGetLastError());
			closesocket(listenSocket);
			WSACleanup();
			return 1;

			//printf("select failed with error: %ld\n", WSAGetLastError());
			//break;

		}
		else
		{
			if (FD_ISSET(listenSocket, &readfds) && connectedSockets < MAX_CLIENTS)
			{
				// Struct for information about connected client
				sockaddr_in clientAddr;
				int clientAddrSize = sizeof(struct sockaddr_in);

				FD_CLR(listenSocket, &readfds);

				// New connection request is received. Add new socket in array on first free position.
				acceptedSockets[connectedSockets] = accept(listenSocket, (struct sockaddr *)&clientAddr, &clientAddrSize);
				if (acceptedSockets[connectedSockets] == INVALID_SOCKET)
				{
					if (WSAGetLastError() == WSAECONNRESET)
					{
						printf("accept failed, because timeout for client request has expired.\n");
					}
					else
					{
						printf("accept failed with error: %d\n", WSAGetLastError());
					}

					closesocket(listenSocket);
					WSACleanup();
					return 1;

				}
				else
				{
					if (ioctlsocket(acceptedSockets[connectedSockets], FIONBIO, &mode) != 0)
					{
						printf("ioctlsocket failed with error.");
						continue;
					}
					connectedSockets++;
					printf("New client request accepted (%d). Client address: %s : %d\n", connectedSockets, inet_ntoa(clientAddr.sin_addr), ntohs(clientAddr.sin_port));

				}
			}


			for (int i = 0; i < connectedSockets; i++)
			{
				if (FD_ISSET(acceptedSockets[i], &readfds))
				{
					FD_CLR(acceptedSockets[i], &readfds);

					int iResult = recv(acceptedSockets[i], recvbuf, DEFAULT_BUFLEN, 0);
					if (iResult > 0)
					{
						Message_For_Client* clientMessage = (Message_For_Client*)recvbuf;
						printf("Sender: %s\n", clientMessage->sender);
						printf("Receiver: %s\n", clientMessage->receiver);
						printf("Message: %s\n", clientMessage->message);
						printf("ListenIP: %s\n", clientMessage->listen_address);
						printf("ListenPort: %d\n", clientMessage->listen_port);
						printf("Message: %s\n", clientMessage->message);

						printf("Flag: %s\n", clientMessage->flag);

						if (strcmp((char*)clientMessage->flag, "1") == 0) {  // REGISTRACIJA:

							printf("REGISTRACIJA\n");

							if (!ClientExistsInHashMap(clientMessage->sender))  // username ne postoji
							{
								printf("Registracija novog klijenta!\n");

								// name doesn't exists within the hashmap, register the name
								ClientData *newClient = (ClientData*)malloc(sizeof(ClientData));

								sockaddr_in socketAddress;
								int socketAddress_len = sizeof(struct sockaddr_in);

								// Ask getsockname to fill in this socket's local adress
								if (getpeername(acceptedSockets[i], (sockaddr *)&socketAddress, &socketAddress_len) == -1)
								{
									printf("getsockname() failed.\n"); return -1;
								}

								char clientAddress[MAX_ADDRESS];
								inet_ntop(AF_INET, &socketAddress.sin_addr, clientAddress, INET_ADDRSTRLEN);

								//memcpy(newClient->name, recvbuf, sizeof(recvbuf));
								//memcpy(newClient->address, clientAddress, sizeof(clientAddress));
								strcpy((char*)newClient->name, (char*)clientMessage->sender);
								strcpy((char*)newClient->address, (char*)clientAddress);
								strcpy((char*)newClient->listen_address, (char*)clientMessage->listen_address);
								newClient->port = (int)ntohs(socketAddress.sin_port);
								newClient->listen_port = clientMessage->listen_port;
								

								printf("Client Name: %s\n", newClient->name);
								printf("Client IP address is: %s\n", newClient->address);
								printf("Client Port is: %d\n", newClient->port);

								AddValueToHashMap(newClient);
								ShowHashMap();

								char returnValue = '1';
								iResult = send(acceptedSockets[i], (char*)&returnValue, sizeof(returnValue), 0);  // sizeof(Message_For_Client)
								if (iResult == SOCKET_ERROR)
								{
									printf("send failed with error: %d\n", WSAGetLastError());
									closesocket(acceptedSockets[i]);
									for (int j = i; j < connectedSockets - 1; j++)
									{
										acceptedSockets[j] = acceptedSockets[j + 1];
									}
									acceptedSockets[connectedSockets - 1] = INVALID_SOCKET;
									connectedSockets--;
									i--;  // DA NE BI PRESKOCILI JEDNOG U PETLJI !!!

									RemoveValueFromHashMap(clientMessage->sender);

								}
							}
							else  // username vec postoji
							{
								printf("Klijent je pokusao da se registruje sa vec zauzetim imenom!\n");
								char returnValue = '0';
								iResult = send(acceptedSockets[i], (char*)&returnValue, sizeof(returnValue), 0);  // sizeof(Message_For_Client)
								if (iResult == SOCKET_ERROR)
								{
									printf("send failed with error: %d\n", WSAGetLastError());
									closesocket(acceptedSockets[i]);
									for (int j = i; j < connectedSockets - 1; j++)
									{
										acceptedSockets[j] = acceptedSockets[j + 1];
									}
									acceptedSockets[connectedSockets - 1] = INVALID_SOCKET;
									connectedSockets--;
									i--;  // DA NE BI PRESKOCILI JEDNOG U PETLJI !!!

									RemoveValueFromHashMap(clientMessage->sender);
								}
							}
						}
						else if (strcmp((char*)clientMessage->flag, "2") == 0) {  // PROSLEDJIVANJE PORUKE:

							printf("KOMUNIKACIJA PROSLEDJIVANJEM PORUKE\n");

							if (!ClientExistsInHashMap((unsigned char*)clientMessage->receiver))  // ukoliko primalac ne postoji
							{
								printf("Klijent pokusao da prosledi poruku nepostojecom klijentu!\n");
								char errorMsg[256];
								sprintf(errorMsg, "Klijent kome zelite da posaljete poruku ne postoji!");
								iResult = send(acceptedSockets[i], errorMsg, sizeof(errorMsg), 0);  // sizeof(Message_For_Client)
								if (iResult == SOCKET_ERROR)
								{
									printf("send failed with error: %d\n", WSAGetLastError());
									closesocket(acceptedSockets[i]);
									for (int j = i; j < connectedSockets - 1; j++)
									{
										acceptedSockets[j] = acceptedSockets[j + 1];
									}
									acceptedSockets[connectedSockets - 1] = INVALID_SOCKET;
									connectedSockets--;
									i--;  // DA NE BI PRESKOCILI JEDNOG U PETLJI !!!
									RemoveValueFromHashMap(clientMessage->sender);
								}
							}
							else  // ukoliko primalac postoji
							{
								if (strcmp((const char*)clientMessage->receiver, (const char*)clientMessage->sender) == 0)
								{
									printf("Klijent je pokusao da prosledi poruku samom sebi!\n");
									char errorMsg[256];
									sprintf(errorMsg, "Ne mozete proslediti poruku samom sebi!");
									iResult = send(acceptedSockets[i], errorMsg, sizeof(errorMsg), 0);  // sizeof(Message_For_Client)
									if (iResult == SOCKET_ERROR)
									{
										printf("send failed with error: %d\n", WSAGetLastError());
										closesocket(acceptedSockets[i]);
										for (int j = i; j < connectedSockets - 1; j++)
										{
											acceptedSockets[j] = acceptedSockets[j + 1];
										}
										acceptedSockets[connectedSockets - 1] = INVALID_SOCKET;
										connectedSockets--;
										i--;  // DA NE BI PRESKOCILI JEDNOG U PETLJI !!!

										RemoveValueFromHashMap(clientMessage->sender);

									}
								}
								else  // ukoliko primalac nije i posiljaoc => sve je dobro, poruka se prosledjuje
								{
									ClientData *recievingClient = FindValueInHashMap((unsigned char*)clientMessage->receiver);  // klijent kome treba da se posalje

									struct sockaddr_in socketAddress;
									int socketAddress_len = sizeof(socketAddress);

									char clientAddress[MAXLEN];

									char msg[256];
									bool nasao = false;

									for (int k = 0; k < connectedSockets; k++)
									{
										// Ask getsockname to fill in this socket's local adress
										if (getpeername(acceptedSockets[k], (sockaddr *)&socketAddress, &socketAddress_len) == -1)
										{
											printf("getsockname() failed.\n"); return -1;
										}

										inet_ntop(AF_INET, &socketAddress.sin_addr, clientAddress, INET_ADDRSTRLEN);


										if ((strcmp(clientAddress, (const char*)recievingClient->address) == 0) && ((unsigned int)ntohs(socketAddress.sin_port) == recievingClient->port))
										{
											nasao = true;

											// TO DO: ako je recievingClient->flag postavljen na 1 onda mu posalji strukturu, 
											// gde ce message biti poruka, a port i ip adresa ce biti *
											// u suprotnom saljes kao i do sada

											if (strcmp((const char*)recievingClient->flag, "1") == 0)
											{
												Client_Information_Directly directMessage;
												strcpy((char*)directMessage.listen_address, "*\0");
												strcpy((char*)directMessage.listen_port, "*\0");
												sprintf((char*)directMessage.message, "[%s]:%s", clientMessage->sender, clientMessage->message);
												iResult = send(acceptedSockets[k], (char*)&directMessage, sizeof(Client_Information_Directly), 0);
											}
											else
											{
												char clientMessageString[512];
												sprintf(clientMessageString, "[%s]:%s", clientMessage->sender, clientMessage->message);
												iResult = send(acceptedSockets[k], (char*)&clientMessageString, sizeof(clientMessageString), 0);
											}
											if (iResult == SOCKET_ERROR)
											{
												printf("send failed with error: %d\n", WSAGetLastError());
												closesocket(acceptedSockets[k]);
												for (int j = k; j < connectedSockets - 1; j++)
												{
													acceptedSockets[j] = acceptedSockets[j + 1];
												}
												acceptedSockets[connectedSockets - 1] = INVALID_SOCKET;
												connectedSockets--;
												i--;  // DA NE BI PRESKOCILI JEDNOG U PETLJI !!!

												RemoveValueFromHashMap(clientMessage->receiver);


												printf("[Neuspesno]: Prosledjivanje poruke. Posiljalac: %s, Primalac: %s.\n", clientMessage->sender, clientMessage->receiver);
												sprintf(msg, "Poruka je neuspesno prosledjena zeljenom klijentu, jer on vise nije dostupan!");
												break;

											}
											else {

												printf("[Uspesno]: Prosledjivanje poruke. Posiljalac: %s, Primalac: %s.\n", clientMessage->sender, clientMessage->receiver);
												sprintf(msg, "Poruka je uspesno prosledjena zeljenom klijentu!");
												break;

											}
										}
									}
									if (nasao == false) {

										RemoveValueFromHashMap(clientMessage->receiver);
										printf("[Neuspesno]: Prosledjivanje poruke. Posiljalac: %s, Primalac: %s.\n", clientMessage->sender, clientMessage->receiver);
										sprintf(msg, "Poruka je neuspesno prosledjena zeljenom klijentu, jer on vise nije dostupan!");
									}

									iResult = send(acceptedSockets[i], msg, sizeof(msg), 0);  // sizeof(Message_For_Client)
									if (iResult == SOCKET_ERROR)
									{
										printf("send failed with error: %d\n", WSAGetLastError());
										closesocket(acceptedSockets[i]);
										for (int j = i; j < connectedSockets - 1; j++)
										{
											acceptedSockets[j] = acceptedSockets[j + 1];
										}
										acceptedSockets[connectedSockets - 1] = INVALID_SOCKET;
										connectedSockets--;
										i--;  // DA NE BI PRESKOCILI JEDNOG U PETLJI !!!

										RemoveValueFromHashMap(clientMessage->sender);
									}
								}
							}
						}
						else if (strcmp((char*)clientMessage->flag, "3") == 0) {  // DIREKTNA KOMUNIKACIJA:

							printf("DIREKTNA KOMUNIKACIJA\n");

							// TO DO: da li clientMessage->receiver postoji u Hash-u, ako postoji posalji mi strukturu Client_Information_Directly,
							// gde ce message biti / + null terminator
							// a ako ne postoji message ce biti poruka o tome da ne postoji ili da je sam sebi pokusao da posalje, a ip adresa i port ce biti / + null terminator
							
							Client_Information_Directly returnMessage;
							if (ClientExistsInHashMap(clientMessage->receiver) == true)
							{
								if (strcmp((const char*)clientMessage->receiver, (const char*)clientMessage->sender) == 0)
								{
									printf("[Direktna]: Klijent je pokusao da komunicira sa samim sobom\n");
									char errorMsg[256];
									sprintf(errorMsg, "Klijent je pokusao da komunicira sa samim sobom!");
									strcpy((char*)returnMessage.message, errorMsg);
									strcpy((char*)returnMessage.listen_address, "/\0");
									returnMessage.listen_port = 0;
								}
								else
								{
									ClientData *receivingClient = FindValueInHashMap(clientMessage->receiver);
									strcpy((char*)returnMessage.message, "/\0");
									strcpy((char*)returnMessage.listen_address, (const char*)receivingClient->listen_address);
									returnMessage.listen_port = receivingClient->listen_port;
								}
							}
							else
							{
								printf("[Direktna]: Trazeni klijent ne postoji!\n");
								char errorMsg[256];
								sprintf(errorMsg, "Trazeni klijent ne postoji!");
								strcpy((char*)returnMessage.message, errorMsg);
								strcpy((char*)returnMessage.listen_address, "/\0");
								returnMessage.listen_port = 0;
							}

							iResult = send(acceptedSockets[i], (char*)&returnMessage, sizeof(Client_Information_Directly), 0);  // sizeof(Message_For_Client)
							if (iResult == SOCKET_ERROR)
							{
								printf("send failed with error: %d\n", WSAGetLastError());
								closesocket(acceptedSockets[i]);
								for (int j = i; j < connectedSockets - 1; j++)
								{
									acceptedSockets[j] = acceptedSockets[j + 1];
								}
								acceptedSockets[connectedSockets - 1] = INVALID_SOCKET;
								connectedSockets--;
								i--;  // DA NE BI PRESKOCILI JEDNOG U PETLJI !!!
								RemoveValueFromHashMap(clientMessage->sender);
							}
						}
						else {  // POSTAVI ME DA SAM PRESAO NA DIREKTNU KOMUNIKACIJU:

							// TO DO: nadji clientMessage->sender u hash tabeli i izmeni mu flag direktne komunikacije na 1 (moras dodati fju koja ce raditi izmenu postojeceg)
							// default-no taj flag je 0
							if (ClientExistsInHashMap(clientMessage->sender) == true)
							{
								UpdateClientInHashMap(clientMessage->sender);
							}
						}
					}
					else if (iResult == 0 || WSAGetLastError() == WSAECONNRESET)  // klijent poslao shutdown signal ili je nasilno zatvoren
					{
						// connection was closed gracefully
						printf("Connection with client closed.\n");

						for (int j = 0; j < MAXSIZE; j++)
						{
							struct Element *tempClientElement = HashMap[j];
							while (tempClientElement)
							{
								sockaddr_in socketAddress;
								int socketAddress_len = sizeof(struct sockaddr_in);
								if (getpeername(acceptedSockets[i], (sockaddr *)&socketAddress, &socketAddress_len) == -1)
								{
									printf("getsockname() failed.\n"); return -1;
								}
								char tempClientAddress[MAXLEN];
								inet_ntop(AF_INET, &socketAddress.sin_addr, tempClientAddress, INET_ADDRSTRLEN);

								if ((strcmp(tempClientAddress, (const char*)tempClientElement->clientData->address) == 0) && ((unsigned int)ntohs(socketAddress.sin_port) == tempClientElement->clientData->port))
								{
									RemoveValueFromHashMap(tempClientElement->clientData->name);
									printf("Klijent %s, je uklonjen iz HashMape", tempClientElement->clientData->name);
									ShowHashMap();
									break;
								}
								tempClientElement = tempClientElement->nextElement;
							}
						}

						closesocket(acceptedSockets[i]);
						for (int j = i; j < connectedSockets - 1; j++)
						{
							acceptedSockets[j] = acceptedSockets[j + 1];
						}
						acceptedSockets[connectedSockets - 1] = INVALID_SOCKET;
						connectedSockets--;
						i--;  // DA NE BI PRESKOCILI JEDNOG U PETLJI !!!
					}
					else
					{
						if (WSAGetLastError() == WSAEWOULDBLOCK) {

							continue;
						}
						else {

							// there was an error during recv
							printf("recv failed with error: %d\n", WSAGetLastError());

							// TO DO: Naci klijenta u Hash mapi koji ima adresu i port isto kao i acceptedSocket[i] i obrisati ga iz Hash mape.
							for (int j = 0; j < MAXSIZE; j++)
							{

								struct Element *tempClientElement = HashMap[j];
								while (tempClientElement)
								{
									sockaddr_in socketAddress;
									int socketAddress_len = sizeof(struct sockaddr_in);
									if (getpeername(acceptedSockets[i], (sockaddr *)&socketAddress, &socketAddress_len) == -1)
									{
										printf("getsockname() failed.\n"); return -1;
									}
									char tempClientAddress[MAXLEN];
									inet_ntop(AF_INET, &socketAddress.sin_addr, tempClientAddress, INET_ADDRSTRLEN);

									if ((strcmp(tempClientAddress, (const char*)tempClientElement->clientData->address) == 0) && ((unsigned int)ntohs(socketAddress.sin_port) == tempClientElement->clientData->port))
									{
										printf("Klijent %s, je uklonjen iz HashMape", tempClientElement->clientData->name);
										RemoveValueFromHashMap(tempClientElement->clientData->name);
										ShowHashMap();
										break;
									}
									tempClientElement = tempClientElement->nextElement;
								}
							}
							closesocket(acceptedSockets[i]);
							for (int j = i; j < connectedSockets - 1; j++)
							{
								acceptedSockets[j] = acceptedSockets[j + 1];
							}
							acceptedSockets[connectedSockets - 1] = INVALID_SOCKET;
							connectedSockets--;
							i--;  // DA NE BI PRESKOCILI JEDNOG U PETLJI !!!
						}
					}
				}
			}


		}


	} while (1);  // trajanje konekcije

	// shutdown the connection since we're done
	for (int i = 0; i < connectedSockets; i++)
	{
		// shutdown the connection since we're done
		iResult = shutdown(acceptedSockets[i], SD_SEND);
		if (iResult == SOCKET_ERROR)
		{
			printf("shutdown failed with error: %d\n", WSAGetLastError());
			closesocket(acceptedSockets[i]);
			WSACleanup();
			return 1;
		}

	}

	closesocket(listenSocket);
	for (int i = 0; i < connectedSockets; i++) {
		closesocket(acceptedSockets[i]);
	}
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