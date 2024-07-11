#ifndef __SP_SOCKET_H
#define __SP_SOCKET_H

#include <iostream>
#include <string>
#include <map>
#include <vector>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>

typedef struct requestHttp_structure
{
    std::string Method;                       // 请求方法get、post等等
    std::string URL;                          // 请求路径
    std::string version;                      // 协议版本
    std::string Host;                         // 主机
    std::string Connection;                   // 链接后续状态，是否升级协议
    std::string Upgrade;                      // 需要升级为什么协议
    std::string cookie;                       // cookie
    std::map<std::string, std::string> param; // get请求的参数
    std::string SecWebSocketKey;              // 用于建立websocket协议
    std::string content;                      // 主体内容
} Httpture;

typedef struct wsProtocol_structure
{
    uint8_t FIN; // 数据帧状态：0b0数据帧结束，0b1数据帧继续
    uint8_t RSV;
    uint8_t opcode;     // 控制码：0x0继续、0x1文本、0x2二进制，0x8关闭，0x9ping，0xApong
    uint8_t Mask;       // 是否掩码
    uint8_t PayloadLen; // 数据长度
    uint64_t ExtendPayloadLen;
    char Maskingkey[4] = {0}; // 掩码,若Mask为1则该字段存在，若为0则该字段缺失
    std::string Payload;      // 数据载荷
} Dataframe;

bool split(std::string str, std::string splitStr, std::vector<std::string> &buffer);

class simple_socket
{
private:
    int server_sock;

public:
    bool isActive;
    simple_socket(int port, int opt);
    inline int getServersock()
    {
        return this->server_sock;
    }
};

class http_socket : simple_socket
{
private:
    int client_sock;
    char method[128], url[128], recv_buff[1024];
    std::string headers;
    sockaddr_in client_addr;
    socklen_t addrlen;

public:
    http_socket(int port, int opt) : simple_socket(port, opt){}; // 实例化
    inline int getClientsock()                                   // 返回客户端套接字标识符
    {
        return this->client_sock;
    }
    inline char *getURL()
    {
        return url;
    }
    int get_line();   // 获取接收到的http请求中的i一行
    void on_accept(); // http请求监视函数
    bool on_header(); // 发送响应头
    void (*GET_p)(int sock) = nullptr;
    void (*POST_p)(int sock) = nullptr;
    virtual void on_GET()
    {
        std::cout << "GET_mehtod" << std::endl;
    }
    virtual void on_POST()
    {
        std::cout << "POST_mehtod" << std::endl;
    }
    void on_message(); // http请求数据流监视函数
};

class sp_websocket : simple_socket
{
private:
    int client_sock;
    char recv_buff[4096];
    Httpture http_req_ture;
    Dataframe ws_data_frame;
    sockaddr_in client_addr;
    socklen_t addrlen;

public:
    bool isActive;
    sp_websocket(int port, int opt) : simple_socket(port, opt) {} // 实例化
    inline int getClientsock()
    {
        return client_sock;
    }
    inline int getOpcode()
    {
        return ws_data_frame.opcode;
    }
    inline int getPayloadLen()
    {
        return ws_data_frame.ExtendPayloadLen;
    }
    inline std::string getPayload()
    {
        return ws_data_frame.Payload;
    }
    void on_accept();
    bool http_anaysis();
    bool frame_analysis(int len);
    void payload_analysis(int len);
    bool base64Encode(const unsigned char *data, int len, std::string &buffer);
    std::string getSec_WS_Acc(std::string &Sec_WS_Key);
    int on_recv();
    void on_send(std::string sendData, bool isMask);
    void upgrade_check();
    void (*message_p)() = nullptr;
};

void sp_WS_message();

#endif
