#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <map>
#include <string>
#include <algorithm>
#include <cctype>
#include <cstring>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <cstring>
#include <thread>
#include <errno.h>
#include <signal.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include "sp_socket.h"

http_socket WX(80, 1);
sp_websocket WS(8443, 0);
sp_websocket &obj = WS;

std::string urlDecode(const std::string &src);
void WX_GET(int client_sock);
void WX_POST(int client_sock);
static size_t callback(void *ptr, size_t size, size_t nmemb, void *stream);
inline size_t onWriteData(void *buffer, size_t size, size_t nmemb, void *userp);

int main()
{
    WX.GET_p = WX_GET;
    WX.POST_p = WX_POST;
    WS.message_p = sp_WS_message;
    std::thread WX_thread(&http_socket::on_accept, &WX);
    WX_thread.detach();
    std::thread WS_thread(&sp_websocket::on_accept, &WS);
    WS_thread.detach();
    while (1)
        ;

    return 0;
}

void WX_GET(int client_sock)
{
    char response[256];
    memset(response, 0, sizeof(response));
    sprintf(response, "{\"lat\":%s,\"lng\":%s,\"heart_rate\":%lf,\"oxy\":%d,\"isDanger\":%s}", lat.c_str(), lng.c_str(), heart_rate, oxy, isDanger.c_str());
    send(client_sock, response, strlen(response), 0);
}

void WX_POST(int client_sock)
{
    char *url = WX.getURL();
    if (url[1] == 'c' && url[2] == 'm' && url[3] == 'd')
    {
        std::cout << "开始播报" << std::endl;
        std::string cmd = url + 4;
        cmd = urlDecode(cmd);
        WS.on_send(cmd, false);
    }
}
