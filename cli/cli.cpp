
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
#define BUFSIZE 2048
using namespace std;
HANDLE g_io_port;
DWORD transferred;
ULONG_PTR key;
OVERLAPPED* lp_overlap;
int g_accepted_socket;

HCRYPTPROV ClientRSAProv;

HCRYPTKEY ClientRSAKeys;
HCRYPTKEY ServerRSAKeys;

HCRYPTKEY hSessionKey_AES;
DWORD ServerPublicKeyBlobLength;
BYTE *ServerPublicKeyBlob = NULL;

DWORD ClientPublicKeyBlobLength;
BYTE *ClientPublicKeyBlob = NULL;

BYTE *SessionKeyBlob = NULL;
DWORD SessionKeyBlobLength = 0;
bool sessionkeyenum = false;
enum CMD
{
	CMD_PUBKEY = 1,
	CMD_SESSIONKEY,
	CMD_VERIFY,
	CMD_TEST,
	CMD_VERSION,
	CMD_CURRENT_TIME,
	CMD_LAUNCH_TIME,
	CMD_MEMORY_USED,
	CMD_MEMORY_FREE,
	CMD_RIGHTS,
	CMD_OWNER
};
struct serv_ctx
{
	int socket;
	CHAR buf_recv[BUFSIZE]; // Буфер приема
	CHAR buf_send[BUFSIZE]; // Буфер отправки
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
	buf.buf = serv.buf_recv;
	buf.len = serv.sz_recv;
	memset(&serv.overlap_recv, 0, sizeof(OVERLAPPED));
	serv.flags_recv = 0;
	WSARecv(serv.socket, &buf, 1, NULL, &serv.flags_recv, &serv.overlap_recv, NULL);
}
// Функция стартует операцию отправки подготовленных данных в сокет
void schedule_write()
{
	WSABUF buf; buf.buf = serv.buf_send + serv.sz_send;
	buf.len = serv.sz_send_total - serv.sz_send;
	memset(&serv.overlap_send, 0, sizeof(OVERLAPPED));
	WSASend(serv.socket, &buf, 1, NULL, 0, &serv.overlap_send, NULL);
}
//void schedule_accept()
//{
//	g_accepted_socket = WSASocket(AF_INET, SOCK_STREAM, 0, NULL, 0, WSA_FLAG_OVERLAPPED); // Создание сокета для принятия подключения (AcceptEx не создает сокетов)
//
//	memset(&serv.overlap_recv, 0, sizeof(OVERLAPPED));
//	AcceptEx(serv.socket, g_accepted_socket, serv.buf_recv, 0, sizeof(struct sockaddr_in) + 16, sizeof(struct sockaddr_in) + 16, NULL, &serv.overlap_recv);
//	// Принятие подключения.
//	// Как только операция будет завершена - порт завершения пришлет уведомление. // Размеры буферов должны быть на 16 байт больше размера адреса согласно документации разработчика ОС
//}
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
void encrypt_buf(CHAR* buf, unsigned int *len)
{
	DWORD length = BUFSIZE;
	if (!CryptEncrypt(hSessionKey_AES, NULL, TRUE, 0, (BYTE*)buf, (DWORD*)len, length))
	{
		printf("Error during CryptEncrypt(). 0x%08x\n", GetLastError());
	}
}
void decrypt_buf( CHAR* buf, unsigned int *len)
{
	DWORD length = *len;
	CryptDecrypt(hSessionKey_AES, NULL, TRUE, 0, (BYTE*)buf, (DWORD*)len);

}
void process_transmit(CMD cmd,CHAR* buf,unsigned int len)
{
	unsigned int payloadlen=0;
	serv.buf_send[0] = cmd;
	payloadlen++;
	serv.buf_send[1] = len << 0;
	payloadlen++;
	serv.buf_send[2] = len << 8;
	payloadlen++;
	serv.buf_send[3] = len << 16;
	payloadlen++;
	serv.buf_send[4] = len << 24;
	payloadlen++;
	memcpy(serv.buf_send+ payloadlen, buf, len);
	payloadlen = payloadlen + len;

	//зашифровываем буфер для отправки
	if (sessionkeyenum == true)
	{
		encrypt_buf(serv.buf_send, &payloadlen);
	}

	WSABUF buffer;
	buffer.buf = serv.buf_send;
	buffer.len = payloadlen;
	memset(&serv.overlap_send, 0, sizeof(OVERLAPPED));
	WSASend(serv.socket, &buffer, 1, NULL, 0, &serv.overlap_send, NULL);

}
void genkeys()
{
	//инициализация
	wchar_t info[] = L"Microsoft Enhanced RSA and AES Cryptographic Provider";
	if (!CryptAcquireContext(&ClientRSAProv, NULL, info, PROV_RSA_AES, 0))
	{
		if (NTE_BAD_KEYSET == GetLastError())
		{
			if (!CryptAcquireContext(&ClientRSAProv, NULL, info, PROV_RSA_AES, CRYPT_NEWKEYSET))
			{
				printf("Error in AcquireContext() 0x%08x\n", GetLastError());
			}
		}
		else
		{
			printf("Error in AcquireContext() 0x%08x\n", GetLastError());
		}
	}
	//генерация ключей
	if (!CryptGenKey(ClientRSAProv, CALG_RSA_KEYX, RSA1024BIT_KEY | CRYPT_EXPORTABLE, &ClientRSAKeys))
	{
		printf("Error during CryptGenKey(). \n");
	}
	//экспорт публичного ключа в массив
	if (!CryptExportKey(ClientRSAKeys, 0, PUBLICKEYBLOB, 0, NULL, &ClientPublicKeyBlobLength))
	{
		printf("Error during CryptExportKey(). \n");
	}
	if (!(ClientPublicKeyBlob = (BYTE *)malloc(ClientPublicKeyBlobLength)))
	{
		printf("Out of memory. \n");
	}
	if (!CryptExportKey(ClientRSAKeys, NULL, PUBLICKEYBLOB, NULL, ClientPublicKeyBlob, &ClientPublicKeyBlobLength))
	{
		printf("Error during CryptExportKey(). \n");
	}

}
void process_recieve(int* len)
{
	unsigned int tmplength = *len;
	//расшифровываем буфер для отправки
	if (sessionkeyenum == true)
	{
		decrypt_buf(serv.buf_recv, &tmplength);
	}
	CMD cmd = (CMD)serv.buf_recv[0];
	uint32_t u0 = serv.buf_recv[1], u1 = serv.buf_recv[2], u2 = serv.buf_recv[3], u3 = serv.buf_recv[4];
	uint32_t length = (u0&(0xff)) | (u1&(0xff)) | (u2&(0xff)) | (u3&(0xff));
	switch (cmd)
	{
		case CMD_PUBKEY:
		{
			//serv.ClientPublicKeyBlobLength = length;
			//if (!(serv.ClientPublicKeyBlob = (BYTE *)malloc(serv.ClientPublicKeyBlobLength)))
			//{
			//	printf("Out of memory. \n");
			//}
			//memcpy(serv.ClientPublicKeyBlob, serv.buf_recv + 5, length);
			//if (!CryptImportKey(ServerRSAProv, serv.ClientPublicKeyBlob, serv.ClientPublicKeyBlobLength, 0, CRYPT_EXPORTABLE, &serv.ClientRSAKeys))
			//{
			//	printf("\nError during CryptImportKey(). \n");
			//}
			break;
		}
		case CMD_SESSIONKEY:
		{
			SessionKeyBlobLength = length;
			if ((SessionKeyBlob = (BYTE *)malloc(SessionKeyBlobLength)))
			{
				memcpy(SessionKeyBlob,serv.buf_recv + 5, SessionKeyBlobLength);
				if (CryptImportKey(ClientRSAProv, SessionKeyBlob, SessionKeyBlobLength, ClientRSAKeys, CRYPT_EXPORTABLE, &hSessionKey_AES))
				{
					BYTE encryptedMessage[256];
					const char * message = "Decryption Works -- using multiple blocks";
					string str = string(message);
					BYTE messageLen = (BYTE)strlen(message);
					memcpy(encryptedMessage, message, messageLen);
					DWORD encryptedMessageLen = messageLen;
					CryptEncrypt(hSessionKey_AES, NULL, TRUE, 0, encryptedMessage, &encryptedMessageLen, sizeof(encryptedMessage));
					process_transmit(CMD_VERIFY, (CHAR*)encryptedMessage, encryptedMessageLen);
					sessionkeyenum = true;
					break;
				}
				else
				{
					printf("\nError during CryptImportKey(). \n");
					break;
				}
			}
			else
			{
				printf("Out of memory. \n");
				break;
			}
			break;
		}
		case CMD_TEST:
		{
			/*sessionkeyenum = true;*/
			printf("Test success \n");
			break;
		}
	}
}
void schedule_accept()
{
	g_accepted_socket = WSASocket(AF_INET, SOCK_STREAM, 0, NULL, 0, WSA_FLAG_OVERLAPPED); // Создание сокета для принятия подключения (AcceptEx не создает сокетов)

	memset(&serv.overlap_recv, 0, sizeof(OVERLAPPED));
	AcceptEx(serv.socket, g_accepted_socket, serv.buf_recv, 0, sizeof(struct sockaddr_in) + 16, sizeof(struct sockaddr_in) + 16, NULL, &serv.overlap_recv);
	// Принятие подключения.
	// Как только операция будет завершена - порт завершения пришлет уведомление. // Размеры буферов должны быть на 16 байт больше размера адреса согласно документации разработчика ОС
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
	//schedule_accept();
	//генерация ключей
	genkeys();
	process_transmit(CMD_PUBKEY, (CHAR*)ClientPublicKeyBlob, ClientPublicKeyBlobLength);
	//schedule_read();
	//process_recieve(&len);
	while (1) // Бесконечный цикл принятия событий о завершенных операциях
	{
		int len = recv(serv.socket, serv.buf_recv, 512, 0);
		process_recieve(&len);
	}


	return 0;
}