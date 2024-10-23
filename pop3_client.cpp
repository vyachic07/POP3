#include <iostream>
#include <string>
#include <winsock2.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <sstream>

using namespace std;

void print_command_info() {
    cout << "Доступные команды:\n";
    cout << "STAT - Показать состояние почтового ящика\n";
    cout << "LIST - Показать список сообщений\n";
    cout << "RETR <номер> - Получить сообщение\n";
    cout << "DELE <номер> - Пометить сообщение как удаленное\n";
    cout << "NOOP - Проверить состояние сервера\n";
    cout << "RSET - Снять пометки об удалении\n";
    cout << "QUIT - Завершить сессию\n";
}

void handle_error(const string &message) {
    cerr << message << endl;
    exit(EXIT_FAILURE);
}

void send_command(SSL *ssl, const string &command) {
    cout << "Отправка команды: " << command << endl;
    SSL_write(ssl, command.c_str(), command.length());
}

string receive_response(SSL *ssl) {
    char buffer[4096] = {0};
    SSL_read(ssl, buffer, sizeof(buffer) - 1);
    return string(buffer);
}

string receive_full_message(SSL *ssl) {
    string message;
    char buffer[4096];
    while (true) {
        int bytes_read = SSL_read(ssl, buffer, sizeof(buffer) - 1);
        if (bytes_read <= 0) break;
        buffer[bytes_read] = '\0'; 
        message += buffer;
        if (message.find("\r\n.\r\n") != string::npos) break;
    }
    return message;
}

string base64_decode(const string &encoded) {
    BIO *bio, *b64;
    char buffer[4096];
    string decoded;

    bio = BIO_new_mem_buf(encoded.data(), encoded.size());
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_push(b64, bio);

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);

    int length;
    while ((length = BIO_read(bio, buffer, sizeof(buffer))) > 0) {
        decoded.append(buffer, length);
    }

    BIO_free_all(bio);
    return decoded;
}

string decode_header(const string &header) {
    if (header.find("=?UTF-8?B?") != string::npos) {
        size_t start = header.find("=?UTF-8?B?") + 10;
        size_t end = header.find("?=", start);
        string encoded = header.substr(start, end - start);
        return base64_decode(encoded);
    }
    return header;
}

void extract_message_details(const string &response) {
    size_t pos;
    if ((pos = response.find("From: ")) != string::npos) {
        size_t end = response.find("\n", pos + 6);
        cout << "Отправитель: " << decode_header(response.substr(pos + 6, end - (pos + 6))) << endl;
    }
    if ((pos = response.find("Date: ")) != string::npos) {
        size_t end = response.find("\n", pos + 6);
        cout << "Дата: " << response.substr(pos + 6, end - (pos + 6)) << endl;
    }
    if ((pos = response.find("Subject: ")) != string::npos) {
        size_t end = response.find("\n", pos + 9);
        cout << "Тема: " << decode_header(response.substr(pos + 9, end - (pos + 9))) << endl;
    }
}

void extract_message_body(const string &message) {
    istringstream message_stream(message);
    string line;
    bool is_base64 = false;
    string encoded_content;

    while (getline(message_stream, line)) {
        if (line.find("Content-Transfer-Encoding: base64") != string::npos) {
            is_base64 = true;
        } else if (is_base64) {
            if (line.empty() || line == "\r") continue;
            if (line.find("--") == 0) break;
            encoded_content += line;
        }
    }

    if (!encoded_content.empty()) {
        string decoded_message = base64_decode(encoded_content);
        cout << "Декодированное сообщение:\n" << decoded_message << endl;
    } else {
        cout << "Не удалось найти base64 содержимое в сообщении." << endl;
    }
}

int main() {
    string email, password;

    cout << "Введите вашу почту: ";
    getline(cin, email);
    cout << "Введите ваш пароль: ";
    getline(cin, password);

    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) handle_error("Ошибка инициализации WinSock");

    SOCKET sock = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in server_addr = {};
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(995);
    server_addr.sin_addr.s_addr = inet_addr("94.100.180.74"); 
    if (sock == INVALID_SOCKET || connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) != 0)
        handle_error("Ошибка подключения к серверу");

    
    SSL_CTX *ctx = SSL_CTX_new(SSLv23_client_method());
    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sock);
    if (SSL_connect(ssl) <= 0) handle_error("Ошибка SSL подключения");

    cout << "Сервер: " << receive_response(ssl) << endl;

    send_command(ssl, "USER " + email + "\r\n");
    receive_response(ssl);
    send_command(ssl, "PASS " + password + "\r\n");
    receive_response(ssl);

    print_command_info();

    string command;
    while (true) {
        cout << "Введите команду: ";
        getline(cin, command);
        if (command == "QUIT") {
            send_command(ssl, "QUIT\r\n");
            cout << "Сервер: " << receive_response(ssl) << endl;
            break;
        }

        if (command == "STAT") {
            send_command(ssl, "STAT\r\n");
            string response = receive_response(ssl);
            cout << "Сервер: " << response << endl;
        } else if (command == "LIST") {
            send_command(ssl, "LIST\r\n");
            string response = receive_response(ssl);
            cout << "Сервер: " << response << endl;

            if (response.substr(0, 3) == "+OK") {
                string full_list = receive_full_message(ssl); 
                cout << "Список сообщений:\n" << full_list << endl;
            }
        } else {
            send_command(ssl, command + "\r\n");
            cout << "Клиент: " << command << endl;
            string response = receive_response(ssl);
            cout << "Сервер: " << response << endl;

            if (command.substr(0, 5) == "RETR ") {
                if (response.substr(0, 3) == "+OK") {
                    string full_message = receive_full_message(ssl);
                    extract_message_details(full_message);
                    extract_message_body(full_message); 
                } else {
                    cout << "Ошибка: " << response << endl;
                }
            }

            if (command.substr(0, 5) == "DELE ") {
                if (response.substr(0, 3) == "+OK") {
                    cout << "Сообщение помечено как удаленное." << endl;
                } else {
                    cout << "Ошибка при пометке сообщения на удаление: " << response << endl;
                }
            }
        }
    }

    SSL_free(ssl);
    closesocket(sock);
    SSL_CTX_free(ctx);
    WSACleanup();

    return 0;
}
