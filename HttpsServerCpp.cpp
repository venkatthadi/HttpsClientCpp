#include <iostream>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

using namespace std;

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "libssl.lib")
#pragma comment(lib, "libcrypto.lib")

#define HOSTNAME "www.google.com"
#define PORT "443"
#define BUFFER_SIZE 4096

void initialize_openssl() {
    SSL_load_error_strings(); // load error strings for corresponding error codes
    OpenSSL_add_ssl_algorithms(); // load encryption and hash algorithms
}

void cleanup_openssl() {
    EVP_cleanup(); // free up memory taken by cryptographic algorithms.
}

SSL_CTX* create_context() {
    const SSL_METHOD* method;
    SSL_CTX* ctx;

    method = SSLv23_client_method(); // version flexible SSL_METHOD

    ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    return ctx;
}

int main() {
    WSADATA wsaData;
    int wsaResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (wsaResult != 0) {
        cerr << "WSAStartup failed: " << wsaResult << endl;
        return EXIT_FAILURE;
    }

    initialize_openssl();
    SSL_CTX* ctx = create_context();

    struct addrinfo hints, * result, * ptr;
    int res;
    SOCKET server_sock;

    // ZeroMemory(&hints, sizeof(hints));
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    res = getaddrinfo(HOSTNAME, PORT, &hints, &result);
    if (res != 0) {
        cerr << "getaddrinfo failed: " << gai_strerror(res) << endl;
        WSACleanup();
        return EXIT_FAILURE;
    }

    for (ptr = result; ptr != NULL; ptr = ptr->ai_next) {
        server_sock = socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);
        if (server_sock == INVALID_SOCKET) {
            cerr << "Error at socket(): " << WSAGetLastError() << endl;
            continue;
        }

        if (connect(server_sock, ptr->ai_addr, (int)ptr->ai_addrlen) == SOCKET_ERROR) {
            closesocket(server_sock);
            server_sock = INVALID_SOCKET;
            continue;
        }
        break;
    }

    freeaddrinfo(result);

    if (server_sock == INVALID_SOCKET) {
        cerr << "Unable to connect to server!" << endl;
        WSACleanup();
        return EXIT_FAILURE;
    }

    SSL* ssl = SSL_new(ctx);
    SSL_set_fd(ssl, server_sock);

    if (SSL_connect(ssl) <= 0) { // SSL handshake
        ERR_print_errors_fp(stderr);
    }
    else {
        cout << "Connected with " << SSL_get_cipher(ssl) << " encryption" << endl;
        SSL_write(ssl, "GET / HTTP/1.1\r\nHost: " HOSTNAME "\r\nConnection: close\r\n\r\n",
            strlen("GET / HTTP/1.1\r\nHost: " HOSTNAME "\r\nConnection: close\r\n\r\n"));

        char buffer[BUFFER_SIZE];
        int bytes;
        while ((bytes = SSL_read(ssl, buffer, sizeof(buffer) - 1)) > 0) {
            buffer[bytes] = 0;
            cout << buffer;
        }
    }

    SSL_free(ssl);
    closesocket(server_sock);
    SSL_CTX_free(ctx);
    cleanup_openssl();
    WSACleanup();

    return 0;
}