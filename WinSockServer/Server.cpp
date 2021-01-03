#include <ws2tcpip.h>
#include <stdlib.h>
#include <stdio.h>
#include "../PeerToPeer/HashMap.cpp"

#define DEFAULT_BUFLEN 512
#define DEFAULT_PORT "27016"
#define MAX_CLIENTS 10
#define DEFAULT_ADDRESS "127.0.0.1"
#define MAX_USERNAME 30

bool InitializeWindowsSockets();
bool CheckIfSocketIsConnected(SOCKET socket);

// have function for handling accepts and reading the reacieved data
//void ReadFromSockets(SOCKET sockets[], int *socketsCount, fd_set* readfds);
//void AcceptIncoming(SOCKET acceptedSockets[], int *freeIndex, SOCKET listenSocket, fd_set* readfds);

struct Message_For_Client  // ovo ide u .h
{
	unsigned char sender[MAX_USERNAME];
	unsigned char receiver[MAX_USERNAME];
	unsigned char message[DEFAULT_BUFLEN];
};
int  main(void)
{
	// Socket used for listening for new clients 
	SOCKET listenSocket = INVALID_SOCKET;
	//array of sockets
	SOCKET acceptedSockets[MAX_CLIENTS];
	//current number of sockets server is listening to
	int connectedSockets = 0;
	// Socket used for communication with client
	SOCKET acceptedSocket = INVALID_SOCKET;
	fd_set readfds;
	// non-blocking listening mode
	unsigned long mode = 1;
	// variable used to store function return value
	int iResult;
	// Buffer used for storing incoming data
	char recvbuf[DEFAULT_BUFLEN];
	

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

	do
	{
		FD_ZERO(&readfds);
		FD_SET(listenSocket, &readfds);
		for (int i = 0; i < connectedSockets; i++)
		{
			FD_SET(acceptedSockets[i], &readfds);
		}

		timeval timeVal;
		timeVal.tv_sec = 1;
		timeVal.tv_usec = 0;

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
		}
		else 
		{
			if (FD_ISSET(listenSocket, &readfds) && connectedSockets < MAX_CLIENTS)
			{
				acceptedSockets[connectedSockets] = accept(listenSocket, NULL, NULL);

				if (acceptedSockets[connectedSockets] == INVALID_SOCKET)
				{
					printf("accept failed with error: %d\n", WSAGetLastError());
					closesocket(listenSocket);
					WSACleanup();
					return 0;
				}

				unsigned long mode = 1; //non-blocking mode
				int iResult = ioctlsocket(acceptedSockets[connectedSockets], FIONBIO, &mode);
				if (iResult != NO_ERROR)
					printf("ioctlsocket failed with error: %ld\n", iResult);
				FD_SET(acceptedSockets[connectedSockets], &readfds);
				connectedSockets++;
			}

			char recvbuf[DEFAULT_BUFLEN];
			for (int i = 0; i < connectedSockets; i++)
			{
				
				//char recvbuf[512];

				for (int i = 0; i < connectedSockets; i++)
				{
					if (FD_ISSET(acceptedSockets[i], &readfds))
					{
						int iResult = recv(acceptedSockets[i], recvbuf, DEFAULT_BUFLEN, 0);
						//memcpy(checkStruct, recvbuf, sizeof(recvbuf));

						if (iResult > 0)
						{
							//recvbuf[MAX_USERNAME] = '\0';

							//check if client is register
							if (!ClientExistsInHashMap((unsigned char*)recvbuf))
							{
								printf("klijent ne postoji...\n");

								// name doesn't exists within the hashmap, register the name
								ClientData *newClient = (ClientData*)malloc(sizeof(ClientData));

								struct sockaddr_in socketAddress; 
								int socketAddress_len = sizeof(socketAddress);
								
								// Ask getsockname to fill in this socket's local adress
								if (getsockname(acceptedSockets[i], (sockaddr *)&socketAddress, &socketAddress_len) == -1)
								{
									printf("getsockname() failed.\n"); return -1;
								}

								char clientAddress[MAXLEN];
								inet_ntop(AF_INET, &socketAddress.sin_addr, clientAddress, INET_ADDRSTRLEN);

								printf("%s\n", clientAddress);
								
								memcpy(newClient->name, recvbuf, sizeof(recvbuf));
								memcpy(newClient->address, clientAddress, sizeof(clientAddress));
								newClient->port = (int)ntohs(socketAddress.sin_port);

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
									acceptedSockets[connectedSockets] = INVALID_SOCKET;
									for (int i = 0; i < connectedSockets; i++)
									{
										acceptedSockets[i] = acceptedSockets[i + 1];
									}
									connectedSockets--;
									FD_CLR(acceptedSockets[i], &readfds);
								}
							}
							else
							{
								Message_For_Client* clientMessage = (Message_For_Client*)recvbuf;
								if ((ClientExistsInHashMap((unsigned char*)clientMessage->sender)) && (ClientExistsInHashMap((unsigned char*)clientMessage->receiver)))
								{
									if (strcmp((const char*)clientMessage->receiver, (const char*)clientMessage->sender) == 0)
									{
										printf("klijent ne moze proslediti poruku samom sebi!\n");
										
										char returnValue = '0';
										iResult = send(acceptedSockets[i], (char*)&returnValue, sizeof(returnValue), 0);  // sizeof(Message_For_Client)
										if (iResult == SOCKET_ERROR)
										{
											printf("send failed with error: %d\n", WSAGetLastError());
											closesocket(acceptedSockets[i]);
											acceptedSockets[connectedSockets] = INVALID_SOCKET;
											for (int i = 0; i < connectedSockets; i++)
											{
												acceptedSockets[i] = acceptedSockets[i + 1];
											}
											connectedSockets--;
											FD_CLR(acceptedSockets[i], &readfds);
										}
									}
									else 
									{
										//printf("klijent zeli da prosledi poruku...\n");
										//printf("%s\n", clientMessage->sender);
										//printf("%s\n", clientMessage->receiver);
										//printf("%s\n", clientMessage->message);
										printf("Prosledjivanje poruke. Posiljalac: %s, Primalac: %s.\n", clientMessage->sender, clientMessage->receiver);
										ClientData *recievingClient = FindValueInHashMap((unsigned char*)clientMessage->receiver);

										iResult = send(acceptedSockets[i], (char*)&(clientMessage->message), sizeof(clientMessage->message), 0);  // sizeof(Message_For_Client)

										// slanje poruke klijentu
										sockaddr_in receivingClientAddress;
										receivingClientAddress.sin_family = AF_INET;								// IPv4
										receivingClientAddress.sin_addr.s_addr = inet_addr((const char*)recievingClient->address);   // serverska adresa
										receivingClientAddress.sin_port = htons(recievingClient->port);					// port

										SOCKET connectSocket = INVALID_SOCKET;

										connectSocket = socket(AF_INET,
											SOCK_STREAM,
											IPPROTO_TCP);

										if (connectSocket == INVALID_SOCKET)
										{
											printf("socket failed with error: %ld\n", WSAGetLastError());
											WSACleanup();
											return 1;
										}

										// connect to client
										if (connect(connectSocket, (SOCKADDR*)&receivingClientAddress, sizeof(receivingClientAddress)) == SOCKET_ERROR)
										{
											printf("Unable to connect to server.\n");
											closesocket(connectSocket);
											WSACleanup();
										}

										iResult = send(connectSocket, (char*)&(clientMessage->message), sizeof(clientMessage->message), 0);  // sizeof(Message_For_Client)
										if (iResult == SOCKET_ERROR)
										{
											printf("slanje poruke klijentu nije uspelo: %d\n", WSAGetLastError());
											closesocket(connectSocket);

											char returnValue = '0';
											iResult = send(acceptedSockets[i], (char*)&returnValue, sizeof(returnValue), 0);  // sizeof(Message_For_Client)
											if (iResult == SOCKET_ERROR)
											{
												printf("send failed with error: %d\n", WSAGetLastError());
												closesocket(acceptedSockets[i]);
												acceptedSockets[connectedSockets] = INVALID_SOCKET;
												for (int i = 0; i < connectedSockets; i++)
												{
													acceptedSockets[i] = acceptedSockets[i + 1];
												}
												connectedSockets--;
												FD_CLR(acceptedSockets[i], &readfds);
											}
										}
										closesocket(connectSocket);

										char returnValue = '1';
										iResult = send(acceptedSockets[i], (char*)&returnValue, sizeof(returnValue), 0);  // sizeof(Message_For_Client)
										if (iResult == SOCKET_ERROR)
										{
											printf("send failed with error: %d\n", WSAGetLastError());
											closesocket(acceptedSockets[i]);
											acceptedSockets[connectedSockets] = INVALID_SOCKET;
											for (int i = 0; i < connectedSockets; i++)
											{
												acceptedSockets[i] = acceptedSockets[i + 1];
											}
											connectedSockets--;
											FD_CLR(acceptedSockets[i], &readfds);
										}
									}
								}
								else
								{
									printf("ime je vec registrovano...\n");
									char returnValue = '0';
									iResult = send(acceptedSockets[i], (char*)&returnValue, sizeof(returnValue), 0);  // sizeof(Message_For_Client)
									if (iResult == SOCKET_ERROR)
									{
										printf("send failed with error: %d\n", WSAGetLastError());
										closesocket(acceptedSockets[i]);
										acceptedSockets[connectedSockets] = INVALID_SOCKET;
										for (int i = 0; i < connectedSockets; i++)
										{
											acceptedSockets[i] = acceptedSockets[i + 1];
										}
										connectedSockets--;
										FD_CLR(acceptedSockets[i], &readfds);
									}
								}
							}
						}
						else if (iResult == 0 || WSAGetLastError() == WSAECONNRESET)
						{
							// connection was closed gracefully
							printf("Connection with client closed.\n");
							closesocket(acceptedSockets[i]);
							acceptedSockets[connectedSockets] = INVALID_SOCKET;
							for (int i = 0; i < connectedSockets; i++)
							{
								acceptedSockets[i] = acceptedSockets[i + 1];
							}
							connectedSockets--;
							FD_CLR(acceptedSockets[i], &readfds);
						}
						else if (WSAGetLastError() != WSAEWOULDBLOCK)
						{
							// there was an error during recv
							printf("recv failed with error: %d\n", WSAGetLastError());
							closesocket(acceptedSockets[i]);
							connectedSockets--;
						}
					}
				}

			}
		}
		/*
		{
			printf("accept failed with error: %d\n", WSAGetLastError());
			closesocket(listenSocket);
			WSACleanup();
			return 1;
		}
		*/

		//printf("\nNew client request accepted. Client address: %s : %d\n", inet_ntoa(clientAddr.sin_addr), ntohs(clientAddr.sin_port));
		// here is where server shutdown loguc could be placed

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
		closesocket(acceptedSockets[i]);
	}

	// cleanup
	closesocket(listenSocket);
	closesocket(acceptedSocket);
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