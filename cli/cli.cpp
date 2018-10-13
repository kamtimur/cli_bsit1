
//#include "stdafx.h"
#define _WINSOCK_DEPRECATED_NO_WARNINGS

#include "winsock2.h"
#include <windows.h>

#include <mswsock.h>
#include <stdio.h>
#include <iostream>
#include <dos.h>
#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "mswsock.lib")
#define MAX_SERV (100)
using namespace std;
HANDLE g_io_port;
DWORD transferred;
ULONG_PTR key;
OVERLAPPED* lp_overlap;
//int socket;
int g_accepted_socket;
struct serv_ctx
{
	int socket;
	CHAR buf_recv[512]; // Буфер приема
	CHAR buf_send[512]; // Буфер отправки
	unsigned int sz_recv; // Принято данных
	unsigned int sz_send_total; // Данных в буфере отправки
	unsigned int sz_send; // Данных отправлено
						  // Структуры OVERLAPPED для уведомлений о
	OVERLAPPED overlap_recv;
	OVERLAPPED overlap_send;
	OVERLAPPED overlap_cancel;
	DWORD flags_recv; // Флаги для WSARecv
};
struct serv_ctx serv;
void schedule_read()
{
	WSABUF buf;
	buf.buf = serv.buf_recv + serv.sz_recv;
	buf.len = sizeof(serv.buf_recv) - serv.sz_recv;
	memset(&serv.overlap_recv, 0, sizeof(OVERLAPPED));
	serv.flags_recv = 0;
	WSARecv(serv.socket, &buf, 1, NULL, &serv.flags_recv, &serv.overlap_recv, NULL);
}
void schedule_write()
{
	WSABUF buf;
	buf.buf = serv.buf_send + serv.sz_send;
	//buf.buf = b;
	buf.len = serv.sz_send_total - serv.sz_send;//strlen(buf.buf); 
	memset(&serv.overlap_send, 0, sizeof(OVERLAPPED));
	WSASend(serv.socket, &buf, 1, NULL, 0, &serv.overlap_send, NULL);
}
void schedule_accept()
{
	g_accepted_socket = WSASocket(AF_INET, SOCK_STREAM, 0, NULL, 0, WSA_FLAG_OVERLAPPED); // Создание сокета для принятия подключения (AcceptEx не создает сокетов)

	memset(&serv.overlap_recv, 0, sizeof(OVERLAPPED));
	AcceptEx(serv.socket, g_accepted_socket, serv.buf_recv, 0, sizeof(struct sockaddr_in) + 16, sizeof(struct sockaddr_in) + 16, NULL, &serv.overlap_recv);
	// Принятие подключения.
	// Как только операция будет завершена - порт завершения пришлет уведомление. // Размеры буферов должны быть на 16 байт больше размера адреса согласно документации разработчика ОС
}
int is_string_received(DWORD idx, int* len)
{
	DWORD i;
	for (i = 0; i < serv.sz_recv; i++)
	{
		cout << serv.buf_recv[i];
		if (serv.buf_recv[i] == '\n')
		{
			*len = (int)(i + 1);
			return 1;
		}
	}
	cout  << endl;
	if (serv.sz_recv == sizeof(serv.buf_recv))
	{
		*len = sizeof(serv.buf_recv);
		return 1;
	}
	return 0;
}
int main()
{
	//int error(0);

	WSADATA wsa_data;
	if (WSAStartup(MAKEWORD(2, 2), &wsa_data) == 0)
	{
		printf("WSAStartup ok\n");
	}
	else
	{
		printf("WSAStartup error\n");
	}

	SOCKET s = WSASocket(AF_INET, SOCK_STREAM, 0, NULL, 0, WSA_FLAG_OVERLAPPED);

	g_io_port = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
	if (NULL == g_io_port)
	{
		printf("CreateIoCompletionPort error: %x\n", GetLastError());
		return 0;
	}

	if (NULL == CreateIoCompletionPort((HANDLE)s, g_io_port, 0, 0))
	{
		printf("CreateIoCompletionPort error: %x\n", GetLastError());
		return 0;
	}

	struct sockaddr_in smtp_addr; //структура адрес
	//memset(g_ctxs, 0, sizeof(g_ctxs));// Обнуление структуры данных для хранения входящих соединений

	memset(&smtp_addr, 0, sizeof(struct sockaddr_in));//устанавливает в 0 все байты структуры

	smtp_addr.sin_family = AF_INET;//протокол ipv4
	smtp_addr.sin_addr.s_addr = inet_addr("127.0.0.1");//Устанавливаем адрес сервера
	smtp_addr.sin_port = htons(9000);//smtp порт для сервера обязательно 25 (80-http,23-fttp и т.д. мы должны знать на какой порт передавать данные иначе не будет соединения
	if (SOCKET_ERROR == connect(s, (struct sockaddr*)&smtp_addr, sizeof(smtp_addr)))
	{
		printf("Connect to server error: %x\n", GetLastError());
	}
	serv.socket = s;
	while (1) // Бесконечный цикл принятия событий о завершенных операциях
	{

		BOOL b = GetQueuedCompletionStatus(g_io_port, &transferred, &key, &lp_overlap, 10);// Ожидание событий в течение 1 секунды
		if (b)
		{
			serv.sz_recv += transferred;
				// Иначе поступило событие по завершению операции от клиента. // Ключ key - индекс в массиве g_ctxs
				if (&serv.overlap_recv == lp_overlap)
				{
					int len;
					/*serv.sz_recv += transferred;*/
					if (is_string_received(key, &len))
					{
						cout <<serv.buf_recv << endl;
						// Если строка полностью пришла, то сформировать ответ и начать его отправлять
						//sprintf_s(serv.buf_send, "You string length: %d\0", len);
						//serv.sz_send_total = strlen(serv.buf_send);
						//serv.sz_send = 0; schedule_write(key);

						//sprintf_s(serv.buf_send, "You string length: 45454\0", len);
						//serv.sz_send_total = strlen(serv.buf_send);
						//serv.sz_send = 0; schedule_write(key);
					}
					else
					{
						// Иначе - ждем данные дальше
						/*schedule_read();*/
						serv.sz_recv = recv(serv.socket, serv.buf_recv, 512, 0);
						cout << serv.buf_recv << endl;
					}
				}
				else if (&serv.overlap_send == lp_overlap)
				{
					// Данные отправлены

					/*serv.sz_send += transferred;*/
					if (serv.sz_send < serv.sz_send_total && transferred > 0)
					{
						// Если данные отправлены не полностью - продолжить отправлять
						schedule_write();
					}
				}
				else if (&serv.overlap_cancel == lp_overlap)
				{
					// Все коммуникации завершены, сокет может быть закрыт
					closesocket(serv.socket); memset(&serv, 0, sizeof(serv));
					printf(" connection %u closed\n", key);
				}
		}
		else
		{
			// Ни одной операции не было завершено в течение заданного времени, программа может
			// выполнить какие-либо другие действия
			// ...
			sprintf_s(serv.buf_send, "Test\0");
			//serv.sz_send_total = strlen(serv.buf_send);
			serv.sz_send = 0;
			//schedule_write();
			serv.sz_send_total = send(serv.socket, serv.buf_send, strlen(serv.buf_send), 0);
			//serv.sz_recv = recv(serv.socket, serv.buf_recv, 512, 0);
			//cout << serv.buf_recv << endl;
			//schedule_read();
			//sprintf_s(serv.buf_send, "You string length: 45454\0", len);
			//serv.sz_send_total = strlen(serv.buf_send);
			//serv.sz_send = 0; schedule_write(key);
			//schedule_write(0, "4588646464\n");
		}
	}
	//serv.socket = s;
	//schedule_write(0, "4588646464\n");

	//schedule_accept();
	//schedule_read(0, 21);
	//schedule_read(0, 23);

	return 0;
}