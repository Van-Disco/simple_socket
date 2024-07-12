#include "sp_socket.h"
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <netinet/in.h>
#include <algorithm>
#include <cstring>
#include <thread>
#include <string>
#include <cctype>
#include <vector>
#include <cstdlib>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>

extern sp_websocket &ws_obj;

bool split(std::string str, std::string splitStr, std::vector<std::string> &buffer)
{
    int index1 = 0;
    int index2 = 0;
    int size = splitStr.length();
    if (str.length() <= 0)
        return false;
    while (true)
    {
        index2 = str.find(splitStr, index1);

        if (index2 != std::string::npos)
        {
            std::string temp = str.substr(index1, index2 - index1);
            buffer.push_back(temp);
        }
        else
        {
            std::string temp = str.substr(index1, str.length() - index1);
            buffer.push_back(temp);
            break;
        }

        index1 = index2 + size;
    }
    return true;
}

simple_socket::simple_socket(int port, int opt)
{
    isActive = false;
    this->server_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (opt == 1 && setsockopt(this->server_sock, SOL_SOCKET, SO_REUSEADDR, (void *)&opt, sizeof(opt)) == -1)
    {
        printf("[%s]Failed to set port overcommitment\n", __FUNCTION__);
        printf("-------------------------------------------------------------\n\n\n");
    }
    else
    {
        if (this->server_sock != -1)
        {
            struct sockaddr_in server_addr;
            memset(&server_addr, 0, sizeof(server_addr));
            server_addr.sin_family = AF_INET;
            server_addr.sin_port = htons(port);
            server_addr.sin_addr.s_addr = htonl(INADDR_ANY);

            if (bind(this->server_sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1)
            {
                printf("[%s]Failed to bind the socket\n", __FUNCTION__);
                printf("-------------------------------------------------------------\n\n\n");
            }
            else
            {
                if (listen(this->server_sock, 5) == -1)
                {
                    printf("[%s]Failed to enter the listening state\n", __FUNCTION__);
                    printf("-------------------------------------------------------------\n\n\n");
                }
                else
                    printf("Initialized successfully(port:%d)\n", port);
            }
        }
        else
        {
            printf("[%s]The network communication endpoint failed to be created\n", __FUNCTION__);
            printf("-------------------------------------------------------------\n\n\n");
        }
    }
}

int http_socket::get_line()
{
    int i = 0, size = sizeof(this->recv_buff);
    char c = '\0';
    int n;
    while ((i < size - 1) && (c != '\n'))
    {
        n = recv(this->client_sock, &c, 1, 0);
        if (n > 0)
        {
            if (c == '\r')
            {
                // 偷窥一个字节，如果是\n就读走
                n = recv(this->client_sock, &c, 1, MSG_PEEK);
                if ((n > 0) && (c == '\n'))
                    recv(this->client_sock, &c, 1, 0);
                else
                    // 不是\n（读到下一行的字符）或者没读到，置c为\n 跳出循环,完成一行读取
                    c = '\n';
            }
            this->recv_buff[i] = c;
            i++;
        }
        else
            c = '\n';
    }
    this->recv_buff[i] = '\0';
    return (i);
}

void http_socket::on_accept()
{
    while (true)
    {
        this->client_sock = accept(getServersock(), (struct sockaddr *)&(this->client_addr), &(this->addrlen));
        if (this->client_sock == -1)
        {
            printf("[%s]Failed to accept\n", __FUNCTION__);
            printf("-------------------------------------------------------------\n\n\n");
            continue;
        }
        isActive = true;
        // std::thread http_recv_requst(&http_socket::on_message, this);
        // http_recv_requst.detach();
        on_message();
    }
}

bool http_socket::on_header()
{
    this->headers = "";
    this->headers += "HTTP/1.0 200 OK\r\n";
    this->headers += "Content-Type: application/json\r\n";
    this->headers += "\r\n";
    if (send(this->client_sock, this->headers.c_str(), this->headers.size(), 0) == -1)
    {
        printf("[%s]Failed to send headers\n", __FUNCTION__);
        printf("-------------------------------------------------------------\n\n\n");
        return false;
    }
    return true;
}

void http_socket::on_message()
{
    int numchars, i, j;
    numchars = get_line();
    i = j = 0;
    // printf("%s\n", recv_buff);
    while (!isspace((unsigned char)recv_buff[i]) && i < numchars && j < sizeof(method) - 1)
    {
        method[j++] = recv_buff[i++];
    }
    method[j] = '\0';

    while (isspace((unsigned char)recv_buff[i]) && i < numchars)
        i++;

    j = 0;
    while (!isspace((unsigned char)recv_buff[i]) && i < numchars && j < sizeof(url) - 1)
        url[j++] = recv_buff[i++];
    url[j] = '\0';

    while ((numchars > 0) && strcmp("\n", recv_buff)) /* read & discard headers */
        numchars = get_line();                        //, printf("%s\n", recv_buff);

    on_header();
    if (strcmp("GET", method) == 0)
    {
        if (GET_p == nullptr)
        {
            std::cout << "GET" << std::endl;
        }
        else
        {
            GET_p(this->client_sock);
        }
    }
    else if (strcmp("POST", method) == 0)
    {
        if (POST_p == nullptr)
        {
            std::cout << "POST" << std::endl;
        }
        else
        {
            POST_p(this->client_sock);
        }
    }
    close(this->client_sock);
}

void sp_websocket::on_accept()
{
    while (true)
    {
        this->client_sock = accept(getServersock(), (sockaddr *)&(this->client_addr), &(this->addrlen));
        if (this->client_sock == -1)
        {
            printf("[%s]Failed to accept\n", __FUNCTION__);
            printf("-------------------------------------------------------------\n\n\n");
            continue;
        }
        upgrade_check();
    }
}

bool sp_websocket::http_anaysis()
{
    if (sizeof(this->recv_buff) <= 2)
        return false;
    std::vector<std::string> httpStrs;
    split(this->recv_buff, "\r\n", httpStrs);
    int size = httpStrs.size();
    for (int i = 0; i < size; i++)
    {
        if (i == 0)
        {
            std::vector<std::string> httpMsgs;
            split(httpStrs[0], " ", httpMsgs);

            this->http_req_ture.Method = httpMsgs.at(0);
            std::transform(this->http_req_ture.Method.begin(), this->http_req_ture.Method.end(), this->http_req_ture.Method.begin(), toupper); // 转为大写

            this->http_req_ture.URL = httpMsgs.at(1);
            this->http_req_ture.version = httpMsgs.at(2);
            if (httpMsgs.at(1).find('?') != std::string::npos)
            {

                std::vector<std::string> tem;
                split(this->http_req_ture.URL, "?", tem);
                std::string content = tem.at(1);
                std::vector<std::string> paramStrs;
                split(content, "&", paramStrs);
                for (std::vector<std::string>::iterator iter = paramStrs.begin(); iter != paramStrs.end(); iter++)
                {
                    std::vector<std::string> paramStr;
                    split(*iter, "=", paramStr);
                    this->http_req_ture.param.insert(std::pair<std::string, std::string>(paramStr.at(0), paramStr.at(1)));
                }
            }
        }
        else if (i > 0 && i < size - 1)
        {
            // 头部内容
            std::vector<std::string> requestHead;
            split(httpStrs.at(i), ": ", requestHead);
            if (httpStrs.at(i).find("Host") != std::string::npos)
            {
                this->http_req_ture.Host = requestHead.at(1);
            }
            else if (httpStrs.at(i).find("Connection") != std::string::npos)
            {
                this->http_req_ture.Connection = requestHead.at(1);
            }
            else if (httpStrs.at(i).find("Upgrade") != std::string::npos)
            {
                this->http_req_ture.Upgrade = requestHead.at(1);
            }
            else if (httpStrs.at(i).find("Sec-WebSocket-Key") != std::string::npos)
            {
                this->http_req_ture.SecWebSocketKey = requestHead.at(1);
            }
        }
        else if (i == size - 1)
        {
            this->http_req_ture.content = httpStrs.at(i);
        }
    }
    return true;
}

bool sp_websocket::base64Encode(const unsigned char *data, int len, std::string &buffer)
{
    if (data == NULL)
        return false;
    BIO *bio, *b64;
    BUF_MEM *bufferPtr;

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);

    BIO_write(bio, data, len);
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &bufferPtr);

    char *base64Data = new char[bufferPtr->length + 1];
    memcpy(base64Data, bufferPtr->data, bufferPtr->length);
    base64Data[bufferPtr->length] = '\0';

    BIO_free_all(bio);

    buffer = base64Data;
    delete[] base64Data;
    return true;
}

std::string sp_websocket::getSec_WS_Acc(std::string &Sec_WS_Key)
{
    std::string guid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    std::string combined = Sec_WS_Key + guid;

    unsigned char hash[SHA_DIGEST_LENGTH];
    SHA1((const unsigned char *)combined.c_str(), combined.size(), hash);

    std::string _accept;
    base64Encode(hash, SHA_DIGEST_LENGTH, _accept);
    return _accept;
}

bool sp_websocket::frame_analysis(int len)
{
    int pos = 0;
    this->ws_data_frame.FIN = (uint8_t)((this->recv_buff[pos] >> 7) & 0x1);
    this->ws_data_frame.RSV = (uint8_t)((this->recv_buff[pos] >> 4) & 0x7);
    this->ws_data_frame.opcode = (uint8_t)(this->recv_buff[pos] & 0xf);
    pos++;
    this->ws_data_frame.Mask = (uint8_t)((this->recv_buff[pos] >> 7) & 0x1);
    this->ws_data_frame.PayloadLen = (uint8_t)(this->recv_buff[pos] & 0x7f);
    pos++;

    uint64_t extended_payload_len = this->ws_data_frame.PayloadLen;
    if (this->ws_data_frame.PayloadLen == 126)
    {
        extended_payload_len = ntohs(*((uint16_t *)(this->recv_buff + pos)));
        pos += 2;
    }
    else if (this->ws_data_frame.PayloadLen == 127)
    {
        extended_payload_len = ntohl(*((uint32_t *)(this->recv_buff + pos)));
        pos += 4;
    }
    this->ws_data_frame.ExtendPayloadLen = extended_payload_len;
    this->ws_data_frame.Payload = new char[extended_payload_len + 1];

    if (this->ws_data_frame.Mask == 1)
    {
        memcpy(this->ws_data_frame.Maskingkey, this->recv_buff + pos, 4);
        pos += 4;
    }

    if (len - pos < extended_payload_len && this->ws_data_frame.opcode == 0x1)
    {
        printf("[%s]The data frame is incomplete\n", __FUNCTION__);
        return false;
    }
    if (this->ws_data_frame.Mask == 1)
    {
        for (int i = 0; i < (this->ws_data_frame.PayloadLen < 126 ? this->ws_data_frame.PayloadLen : this->ws_data_frame.ExtendPayloadLen); i++)
        {
            int j = i % 4;
            this->ws_data_frame.Payload += (char)(this->recv_buff[pos++] ^ this->ws_data_frame.Maskingkey[j]);
        }
    }
    else
    {
        this->ws_data_frame.Payload = (const char *)this->recv_buff;
        this->ws_data_frame.Payload += '\0';
    }

    this->ws_data_frame.Payload[this->ws_data_frame.PayloadLen] = '\0';
    return true;
}

void sp_websocket::payload_analysis(int len)
{
    if (this->ws_data_frame.Mask == 1)
    {
        for (int i = 0; i < (this->ws_data_frame.PayloadLen < 126 ? this->ws_data_frame.PayloadLen : this->ws_data_frame.ExtendPayloadLen); i++)
        {
            int j = i % 4;
            this->ws_data_frame.Payload[i] = (char)(this->recv_buff[i] ^ this->ws_data_frame.Maskingkey[j]);
        }
    }
    else
    {
        this->ws_data_frame.Payload = (const char *)this->recv_buff;
        this->ws_data_frame.Payload += '\0';
    }
}

int sp_websocket::on_recv()
{
    int ret = recv(this->client_sock, this->recv_buff, sizeof(this->recv_buff), 0);
    if (ret < 0)
    {
        printf("[%s]Failed to recv wsframe\n", __FUNCTION__);
        printf("-------------------------------------------------------------\n\n\n");
        this->isActive = false;
        return 0;
    }
    else if (ret == 0)
    {
        printf("[%s]Socket has been closed\n", __FUNCTION__);
        printf("-------------------------------------------------------------\n\n\n");
        this->isActive = false;
        return 0;
    }
    this->recv_buff[ret] = '\0';
    return ret;
}

void sp_websocket::on_send(std::string sendData, bool isMask)
{
    size_t Payloadlen = sendData.length();
    std::string msg = "";
    char FIN_RSV_opcode = ((uint8_t)1 << 7 | 0x1);
    char MASK_Payloadlen = 0;
    char Extended_payload_length[9];
    char MaskingKey[4];

    if (isMask == true)
    {
        MASK_Payloadlen = (uint8_t)1 << 7;
    }
    if (Payloadlen <= 125)
    {
        MASK_Payloadlen += Payloadlen;
    }
    else if (Payloadlen <= UINT16_MAX)
    {
        MASK_Payloadlen += 126;
        union
        {
            char tem_str[2];
            uint16_t tem16;
        } transfer;
        transfer.tem16 = htons((uint16_t)Payloadlen);
        strcpy(Extended_payload_length, transfer.tem_str);
        Extended_payload_length[2] = '\0';
    }
    else
    {
        MASK_Payloadlen += 127;
        union
        {
            char tem_str[8];
            uint64_t tem64[2];
        } transfer;
        transfer.tem64[0] = htonl((uint64_t)Payloadlen & UINT32_MAX);
        transfer.tem64[1] = htonl((uint64_t)Payloadlen >> 8 & UINT32_MAX);
        strcpy(Extended_payload_length, transfer.tem_str);
        Extended_payload_length[8] = '\0';
    }

    if (isMask == true)
    {
        for (int i = 0; i < 4; i++)
        {
            MaskingKey[i] = rand() % UINT8_MAX;
        }
        for (int i = 0; i < sendData.length(); i++)
        {
            sendData[i] ^= MaskingKey[i % 4];
        }
    }
    msg += FIN_RSV_opcode;
    msg += MASK_Payloadlen;
    if (Payloadlen <= 125)
    {
        msg += Extended_payload_length;
    }
    if (isMask == true)
    {
        msg += MaskingKey;
    }
    msg += sendData;

    int ret = send(this->client_sock, msg.c_str(), msg.length(), 0);
    if (ret <= 0)
    {
        printf("[%s]Failed to send frame\n", __FUNCTION__);
    }
    else
    {
        printf("[%s]Succeeded to send frame\n", __FUNCTION__);
    }
}

void sp_websocket::upgrade_check()
{
    this->isActive = true;
    memset(this->recv_buff, 0, sizeof(this->recv_buff));
    int ret = recv(this->client_sock, this->recv_buff, sizeof(this->recv_buff), 0);
    if (ret < 0)
    {
        printf("[%s]Failed to recv http_Upgrade\n", __FUNCTION__);
        this->isActive = false;
        close(this->client_sock);
        return;
    }
    if (http_anaysis() == true && this->http_req_ture.version.compare("HTTP/1.1") == 0 && this->http_req_ture.Connection.find("Upgrade") != std::string::npos && this->http_req_ture.Upgrade.find("websocket") != std::string::npos)
    {
        std::string response = "HTTP/1.1 101 Switching Protocols\r\n";
        response += "Upgrade: websocket\r\n";
        response += "Connection: Upgrade\r\n";
        response += "Sec-WebSocket-Accept: " + getSec_WS_Acc(this->http_req_ture.SecWebSocketKey) + "\r\n";
        // response += "\r\n";
        int send_tag = send(this->client_sock, response.c_str(), response.length(), 0);
        if (send_tag <= 0)
        {
            printf("[%s]Failed to send Upgrade response\n", __FUNCTION__);
            printf("-------------------------------------------------------------\n\n\n");
            this->isActive = false;
            close(this->client_sock);
        }
        else
        {
            printf("[%s]Websocket handshake succeeded\n", __FUNCTION__);
            std::thread on_message(message_p);
            on_message.detach();
        }
    }
    else
    {
        printf("[%s]Not WS_req\n", __FUNCTION__);
        printf("-------------------------------------------------------------\n\n\n");
        this->isActive = false;
        close(this->client_sock);
    }
}

void sp_WS_message()
{
    int len = 0;
    while (ws_obj.isActive)
    {
        len = ws_obj.on_recv();
        if (ws_obj.frame_analysis(len) == false)
        {
            len = ws_obj.on_recv();
            ws_obj.payload_analysis(len);
        }

        if (ws_obj.getOpcode() == 0x1)
        {
            std::cout << ws_obj.getPayload() << std::endl;
        }
        else if (ws_obj.getOpcode() == 0x9)
        {
            printf("[%s]]Received ping\n", __FUNCTION__);
            uint8_t pong[2] = {0x8A, 0}; // 报文头
            int sendStatus = send(ws_obj.getClientsock(), pong, 2, 0);
        }
        else if (ws_obj.getOpcode() == 0x8)
        {
            ws_obj.isActive = false;
            printf("[%s]Close socket\n", __FUNCTION__);
            printf("-------------------------------------------------------------\n\n\n");
            break;
        }
    }
    close(ws_obj.getClientsock());
}
