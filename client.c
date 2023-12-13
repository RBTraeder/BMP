/****************************************************
*
*    Basic minimal socket client program for use
*    in CSc 487 final projects.  You will have to
*    enhance this for your projects!!
*
*                                  RSF    11/14/20
*
****************************************************/
#include<stdio.h>      // used printf/scanf for demo (puts/getchar would be leaner)
#include<string.h>	
#include<sys/socket.h>
#include<arpa/inet.h>  // for inet_addr and sockaddr_in structs
#include<unistd.h>
#include"Project3AB.h"

int sendString(int socket_desc, const char* input)
{
    printf(" > Sending String ( Size: [%lu] ): %s\n", strlen(input), input);
    if (send(socket_desc, input, strlen(input), 0) < 0)
	{
        printf("> Send failed\n");
        return -1; // Indicate failure by returning NULL
    }
    sleep(1);
    printf("Sent\n");
    return 0;
}

char *LOCAL_FILEPATH = "/Users/user/Desktop/Sockets/";
char *LOCAL_FILEPATH_CRL = "/Users/user/Desktop/Sockets/CRL.txt";
char *LOCAL_FILEPATH_CC = "/Users/user/Desktop/Sockets/certchain.txt";

int send_cert(int socket_desc)
{
    char *certStr, filename[128];
    printf("Enter Existing File Name: ");
    scanf(" %[^\n]", filename);
    sendString(socket_desc, filename);

    char filepath[128];
    strcpy(filepath, LOCAL_FILEPATH);
    strcat(filepath, filename);
    strcpy(filename, filepath);

    // Allocate memory for hashfile and hashStr
    char hashFile[128];
    char *hashStr = (char *)malloc(320);

    strcpy(hashFile, filepath);
    strcat(hashFile, "_hash.txt");
    strcat(filename, ".txt");

    (filename, &certStr);

    // send Certificate
    sendString(socket_desc, certStr);      

    FILE *readFile = fopen(hashFile, "r");
    size_t bytesRead = fread(hashStr, 1, sizeof(hashStr) - 1, readFile);
    hashStr[bytesRead] = '\0'; // Null-terminate the string
    fclose(readFile);

    // Send Hash
    sendString(socket_desc, hashStr);
    return 4;
}

int send_cert_chain(int socket_desc)
{
    char *ccStr = (char *)malloc(2048);;
    chainfiletostring(LOCAL_FILEPATH_CC, &ccStr);
    // Send CRL
    sendString(socket_desc, ccStr);
    return 10;
}

int send_crl(int socket_desc)
{
    char *crl_string = (char *)malloc(2048);;
    CRL_FileToString(LOCAL_FILEPATH_CRL, &crl_string);
    // Send CRL
    sendString(socket_desc, crl_string);
    return 4;
}



int main(int argc , char *argv[])
{
    set_FILEPATH(LOCAL_FILEPATH);
	set_CRL_FILEPATH(LOCAL_FILEPATH_CRL);
    set_CHAIN_FILEPATH(LOCAL_FILEPATH_CC);

	int socket_desc, read_size;
	struct sockaddr_in server;    // in arpa/inet.h
	char  server_reply[256];//, client_message[256];   // will need to be bigger and possibly changed from char arrays to ints

	//Create socket
	socket_desc = socket(AF_INET , SOCK_STREAM , 0);
    printf("Trying to create socket\n");
	if (socket_desc == -1)
		printf("Unable to create socket\n");
	server.sin_addr.s_addr = inet_addr("169.254.132.101");  // doesn't like localhost?
	server.sin_family = AF_INET;
	server.sin_port = htons( 8421 );    // random "high"  port number
    printf(" > Socket Created\n");

	//Connect to remote server
	if (connect(socket_desc , (struct sockaddr *)&server , sizeof(server)) < 0)
	{
		printf(" connect error");
		return 1;
	}
	    printf(" > Successful connection\n");

    int menu_choice = 1;
	while (menu_choice != 0)
	{
		menu_choice = menu();

		if(menu_choice == 4)
            menu_choice = send_cert(socket_desc);
        else if(menu_choice == 5)
            menu_choice = send_crl(socket_desc);
        else if(menu_choice == 10)
            menu_choice = send_cert_chain(socket_desc);
        else if (menu_choice == 6 || menu_choice == 7)
            printf(" > Only Receive on Server\n");
	}

    // while (choice != 0)
    // {

    //     else if (choice == 5)
    //     {

    //         char *crlFile = "CRL.txt";

    //         char *CRL_str = NULL;
    //         CRL_FileToString(crlFile, &CRL_str);

    //         printf("Sending contents of [%s] [Size: %lu]\n", crlFile, strlen(CRL_str));

    //         // Send CRL string
    //         if( send(socket_desc, CRL_str, strlen(CRL_str), 0) < 0 )
    //         {
    //             printf("send failed");
    //             return 1;
    //         }
    //     }

    //     choice = menu();
    // }


    // if( (read_size = recv(socket_desc, charpuB, 5, 0)) < 0)
    // {
    //     printf("recieve failed");
    //     return 1;
    // }
 
    char *client_message = NULL;
    size_t len = 0;
  
	return 0;
}
