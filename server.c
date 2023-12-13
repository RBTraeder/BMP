/****************************************************
*
*    Basic minimal socket server program for use
*    in CSc 487 final projects.  You will have to
*    enhance this for your projects!!
*
*                                  RSF    11/14/20
*
****************************************************/
#include<stdio.h>
#include<string.h>	//strlen
#include<sys/socket.h>
#include<arpa/inet.h>	//inet_addr
#include<unistd.h>	//write
#include<stdlib.h>	// for system & others
#include"Project3AB.h"

char *LOCAL_FILEPATH = "/Users/user/Desktop/Project3/";
char *LOCAL_FILEPATH_CRL = "/Users/user/Desktop/Project3/CRL.txt";
char *LOCAL_FILEPATH_CC = "/Users/user/Desktop/Project3/certchain.txt";

int menu_6(int new_socket, int read_size)
{
	printf("Waiting for client...\n");
	char filename[320]; // receuve filename
	while( (read_size = recv(new_socket, filename, 320, 0)) > 0 )
	{
		printf(" > Received Filename [%2i byte]: \"%.*s\"\n", read_size, read_size, filename);
		
		char filepath[128];
		strcpy(filepath, LOCAL_FILEPATH);
		strcat(filepath, filename);
		strcpy(filename, filepath);

		char hashfile[128];
		strcpy(hashfile, filepath);
		strcat(hashfile, "_hash.txt");
		strcat(filename, ".txt");

		char recString[320], hashStr[320];
		while( (read_size = recv(new_socket, recString, 320, 0)) > 0 )
		{
			printf(" > Cert Received [%2i byte]\n", read_size);
			Cert cert;
			stringToCert(recString, &cert);
			writeCertToFile(filename, &cert);
			while( (read_size = recv(new_socket, hashStr, 320, 0)) > 0 )
			{
				printf(" > Hash Received [%2i byte]\n", read_size);
				writeHashFile(hashfile, hashStr[0]);
				break;
			}
			break;
		}
		printf(" > Cert File: \"%s\"\n", filename);
		break;
	}
	return 6;
}

int menu_7(int new_socket, int read_size)
{
	printf("Waiting for client...\n");
	char crl_string[2048];
	while( (read_size = recv(new_socket, crl_string, 2048, 0)) > 0 )
	{
		printf(" > Received CRL [%2i byte]\n", read_size);
		CRL crl;
		stringToCRL(crl_string, &crl);
		writeCRL(LOCAL_FILEPATH_CRL, &crl);
		printf(" > \"%s\" created/updated\n", LOCAL_FILEPATH_CRL);
		break;
	}
	printf(" > \"%s\" saved\n", LOCAL_FILEPATH_CRL);
	return 7;
}

int menu_11(int new_socket, int read_size)
{
	printf("Waiting for client...\n");
	char ccStr[2048];
	while( (read_size = recv(new_socket, ccStr, 2048, 0)) > 0 )
	{
		printf(" > Received Cert Chain [%2i byte]\n", read_size);
		Chain chain;
		stringToChain(ccStr, &chain);
		writeChain(LOCAL_FILEPATH_CC, &chain);
		printf(" > \"%s\" created/updated\n", LOCAL_FILEPATH_CC);
		break;
	}
	printf(" > \"%s\" saved\n", LOCAL_FILEPATH_CC);
	return 7;
}

int main(int argc , char *argv[])
{
	set_FILEPATH(LOCAL_FILEPATH);
	set_CRL_FILEPATH(LOCAL_FILEPATH_CRL);
	set_CHAIN_FILEPATH(LOCAL_FILEPATH_CC);
	
	int socket_desc , new_socket , c, read_size, i;
	struct sockaddr_in server , client;
	char *message, client_message[256], server_reply[256];

	char *list;	
	list = "ls -l\n";

	//Create socket
	socket_desc = socket(AF_INET , SOCK_STREAM , 0);
	printf("Trying to create socket\n");
	if (socket_desc == -1)
		printf("Could not create socket");
	server.sin_family = AF_INET;
	server.sin_addr.s_addr = INADDR_ANY;
	server.sin_port = htons( 8421 );  // Random high (assumed unused) port

	//Bind
	while( bind(socket_desc,(struct sockaddr *)&server , sizeof(server)) < 0)
	{;
		//printf(" unable to bind\n"); //return 1;
	}
	printf(" socket bound, ready for and waiting on a client\n");
	listen(socket_desc , 3);
	printf(" Waiting for incoming connections... \n");//Accept incoming connection
	c = sizeof(struct sockaddr_in);
	new_socket = accept(socket_desc, (struct sockaddr *)&client, (socklen_t*)&c);
	if (new_socket<0)
	{
		perror("accept failed");
		return 1;
	}
	printf("Connection accepted\n");

	int menu_choice = 1;
	while (menu_choice != 0)
	{
		menu_choice = menu();

		if(menu_choice == 4 || menu_choice == 5)
			printf(" > Send Only on Client\n");
		else if(menu_choice == 6)		// receive cert & hash
			menu_choice = menu_6(new_socket, read_size);
		else if(menu_choice == 7)
			menu_choice = menu_7(new_socket, read_size);
		else if(menu_choice == 11)
			menu_choice = menu_11(new_socket, read_size);
	}
	// char CRL_str[2048] = "";
	// while( (read_size = recv(new_socket , CRL_str, 2048, 0)) > 0 )
	// {
	// 	printf("Client sent %2i byte message:\n%.*s\n", read_size, read_size, CRL_str);

	// 	stringToFile_CRL(CRLfile, CRL_str);
	// }

	if(read_size == 0)
	{
		printf("client disconnected\n");
		fflush(stdout);
	}
	else if(read_size == -1)
		perror("receive failed");
	close(socket_desc);
	return 0;
}
