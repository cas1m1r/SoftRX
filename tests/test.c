#include <stdio.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>

#define WEBSITE "example.com"
#define PORT 80
#define REQUEST "GET / HTTP/1.1\r\nHost: " WEBSITE "\r\nConnection: close\r\n\r\n"
#define BUFFER_SIZE 4096

int makeWebRequest() {
    int sockfd;
    struct sockaddr_in server_addr;
    struct hostent *server;
    char buffer[BUFFER_SIZE];
    int bytes_received;

    // 1. Create a socket
    // AF_INET for IPv4, SOCK_STREAM for TCP (handled by OS)
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("socket creation failed");
        exit(EXIT_FAILURE);
    }

    // 2. Get server details
    server = gethostbyname(WEBSITE);
    if (server == NULL) {
        fprintf(stderr,"ERROR, no such host\n");
        exit(EXIT_FAILURE);
    }
    
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    // Copy the server's IP address from the hostent structure
    memcpy(&server_addr.sin_addr.s_addr, server->h_addr, server->h_length);
    server_addr.sin_port = htons(PORT);

    // 3. Connect to the server
    if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("connection failed");
        exit(EXIT_FAILURE);
    }

    // 4. Send the HTTP GET request
    // The request string must end with a blank line (\r\n\r\n)
    if (write(sockfd, REQUEST, strlen(REQUEST)) < 0) {
        perror("request send failed");
        exit(EXIT_FAILURE);
    }

    // 5. Receive the response
    printf("--- Response ---\n");
    while ((bytes_received = read(sockfd, buffer, BUFFER_SIZE - 1)) > 0) {
        buffer[bytes_received] = '\0'; // Null-terminate the received data
        printf("%s", buffer);
    }

    if (bytes_received < 0) {
        perror("response read failed");
    }

    // 6. Close the socket
    close(sockfd);
    
    return 0;
}




void testWrites(){
	printf("Testing File Writes\n");
	
	FILE * fd = fopen("test.txt","w+");
	if (fd != NULL){
		fputs("WROTE TO DISK\n",fd);
		printf("[+] Succeeded file write\n");
	}
	fclose(fd);
}


void testFileDelete(){
	printf("Testing File Deletion\n");
	remove("test.txt");	
}


void sensitiveRead(){
	// try a sensitive write that should be illegal	
	FILE* fd = fopen("~/.ssh/id_rsa","r");
	if (fd != NULL){ printf("*** ABLE TO READ SSH KEYS ***\n"); }
	fclose(fd);
}

void testExec(){
	printf("Attempting to use execve('id');\n");
	execve("/usr/bin/id",NULL,NULL);
}


int main(int argc, char*argv[]){

	const char* selfName = argv[0];

	// try to write to disk
	testWrites();
			
	// test file deletion
	testFileDelete();
	
	// test if execve passes 
	//testExec();
	
	// try to make a web request 
	int res;
	printf("Making a web request\n");
	res = makeWebRequest();

	// delete self
	remove(selfName);
	
	return res;
}
