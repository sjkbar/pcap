#include <stdio.h>
#include <jni.h>
#include <string.h>
//#include "test_DatagramSocket2.h"
#define HAVE_REMOTE
#define WPCAP
#include <pcap.h>
#include "org_araqne_pcap_live_PcapDevice.h"

extern pcap_t *pcds[];

#ifdef _WIN32
#include <WinSock2.h>
#include <process.h>
#ifdef Yield()
#undef Yield()
#define Yield() Sleep(0)
#endif
BOOL WINAPI DllMain(HINSTANCE module_handle, DWORD reason_for_call, LPVOID reserved)
{
	if (reason_for_call == DLL_PROCESS_ATTACH)
	{
		WSADATA wd;
		WSAStartup( 0x202, &wd );
	}
	if (reason_for_call == DLL_PROCESS_DETACH)
	{
		WSACleanup();
	}
	return TRUE;
}
#else
#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <sched.h>
#include <fcntl.h>
#define SOCKET int
#define DWORD unsigned int
#define WSADATA int
#define WSAStartup(a,b)
#define FALSE 0
pthread_t pth;
#define _beginthread(a,b,c) pthread_create(&pth,NULL,(void *(*)(void *))a,c)
typedef struct wsaevent_t {
	pthread_mutex_t mutex;
	pthread_cond_t cond;
	volatile int wait;
	volatile int signal;
} *WSAEVENT;

WSAEVENT WSACreateEvent()
{
	WSAEVENT event = (WSAEVENT)malloc( sizeof(struct wsaevent_t) );

	event->wait = 0;
	event->signal = 0;
	pthread_mutex_init( &event->mutex, NULL );
	pthread_cond_init( &event->cond, NULL );

	return event;
}

void WSACloseEvent( WSAEVENT event )
{
	free( event );
}

void WSASetEvent( WSAEVENT event )
{
	pthread_mutex_lock( &event->mutex );
	event->signal = 1;
	if ( event->wait )
		pthread_cond_signal( &event->cond );
	pthread_mutex_unlock( &event->mutex );
}

void WSAResetEvent( WSAEVENT event )
{
	event->signal = 0;
}

#define WSAGetLastError() errno
#define closesocket(a) close(a)
#define Yield() sched_yield()
#define InterlockedIncrement(a) __sync_add_and_fetch(a, 1)
#define InterlockedDecrement(a) __sync_sub_and_fetch(a, 1)

#define WSA_WAIT_TIMEOUT -1

int WSAWaitForMultipleEvents( int count, WSAEVENT *events, int a, int timeout, int b )
{
	struct timespec ts;
	int ret;

	WSAEVENT event = events[0];
	if ( event->signal )
		return 0;
	clock_gettime( CLOCK_REALTIME, &ts );
	ts.tv_sec += timeout / 1000;
	ts.tv_nsec += ( timeout % 1000 ) * 1000000;
	pthread_mutex_lock( &event->mutex );
	event->wait = 1;
	ret = pthread_cond_timedwait( &event->cond, &event->mutex, &ts );
	event->wait = 0;
	pthread_mutex_unlock( &event->mutex );
	if ( ret )
		return -1;
	return 0;
}

#endif

//buffer = 160bytes x 500000packet x 2sec = 160MB 
#define thread_max 1
#define buffer_max ((40/thread_max) << 20)
#define packet_max 65536
#define waiter_max 1000
#define sendqueue_buffer_max 10485760

struct socket_t;

struct thread_buffer_t {
	char buffer[buffer_max];
	volatile int apos;
	volatile int fpos;
	volatile int lastpos;
	int lastsize;
	struct buffer_header_t *last;
	struct socket_t *socket;
};

struct socket_t {
	struct thread_buffer_t gtbuf[thread_max];
//	SOCKET s;
	pcap_t *pcd;
#ifdef _WIN32
	pcap_send_queue *squeue;
#endif
	int id;
	volatile unsigned int order;
	volatile unsigned int readorder;
	volatile int terminate;
	WSAEVENT waiter;
	volatile int waiting;
	int epfd;
};

struct buffer_header_t {
	volatile int next;
	unsigned int order;
	int len;
	char data[0];
};

static int buffer_alloc( struct thread_buffer_t *tbuf, int lastsize )
{
	if ( tbuf->fpos > tbuf->apos )
	{
		if ( tbuf->apos + lastsize + packet_max < tbuf->fpos )
		{
			tbuf->apos += lastsize;
			return tbuf->apos;
		}
	}
	else
	{
		if ( tbuf->apos + lastsize + packet_max < buffer_max )
		{
			tbuf->apos += lastsize;
			return tbuf->apos;
		}
		else if ( tbuf->fpos >= packet_max )
		{
			tbuf->apos = 0;
			return tbuf->apos;
		}
	}
	return -1;
}

static void buffer_free( struct thread_buffer_t *tbuf, int pos )
{
	tbuf->fpos = pos;	
}

static void buffer_txthread( void *p )
{
	struct thread_buffer_t *tbuf = (struct thread_buffer_t *)p;
	struct socket_t *buffer = tbuf->socket;
	int len, pkt = 0;
	int offset = 0;
	int timeout = 1000;
	unsigned short port;
	unsigned int addr;
	struct pcap_pkthdr pktheader;
//	struct sockaddr_in inaddr;

//	memset( &inaddr, 0, sizeof(inaddr) );
//	inaddr.sin_family = AF_INET;
	pktheader.ts.tv_sec = 0;
	pktheader.ts.tv_usec = 0;
	pkt = 0;
	#ifdef _WIN32
	buffer->squeue = pcap_sendqueue_alloc( sendqueue_buffer_max );
	#endif

	for ( ;; )
	{
		char *buf = (char *)buffer;
		int ret = buffer_recvpacket( buffer, offset, timeout );
		if ( buffer->terminate )
		{
			#ifdef _WIN32
			pcap_sendqueue_destroy( buffer->squeue );
			#endif
			InterlockedDecrement( &buffer->terminate );
			return;
		}

		if ( ret >= 0 )
		{
			offset = ret;
			len = *(int *)( buf + offset );
/*			if ( *(short *)( buf + offset + 4 ) == 0x0600 )
			{
				port = *(unsigned short *)( buf + offset + 6 );
				addr = *(unsigned int *)( buf + offset + 8 );
			}
			len-=8;
			inaddr.sin_addr.s_addr = addr;
			inaddr.sin_port = port;
			sendto( buffer->s, buf + offset + 12, len, 0, (struct sockaddr *)&inaddr, sizeof(inaddr) );*/
			pktheader.caplen = len;
			pktheader.len = len;

			#ifdef _WIN32
			pcap_sendqueue_queue( buffer->squeue, &pktheader, buf + offset + 4 );
			#else
			pcap_sendpacket( buffer->pcd, buf + offset + 4, len );
			#endif

			pkt += len + sizeof(pktheader);
			if ( pkt + 65536 >= sendqueue_buffer_max )
			{
				//flush
				#ifdef _WIN32
//				printf( "tx:%d\n", pkt );
				pcap_sendqueue_transmit( buffer->pcd, buffer->squeue, FALSE );
				pcap_sendqueue_destroy( buffer->squeue );
				buffer->squeue = pcap_sendqueue_alloc( sendqueue_buffer_max );
				#endif
				pkt = 0;
			}
			timeout = 0;
/*			pkt++;
			if ( pkt >= 128 )
			{
				printf( "tx packet\n" );
				pkt = 0;
			}*/
		}
		else if ( timeout == 0 )
		{
			//flush
			#ifdef _WIN32
//			printf( "tx:%d\n", pkt );
			pcap_sendqueue_transmit( buffer->pcd, buffer->squeue, FALSE);
			pcap_sendqueue_destroy( buffer->squeue );
			buffer->squeue = pcap_sendqueue_alloc( sendqueue_buffer_max );
			#endif
			timeout = 1000;
			pkt = 0;
		}
//		else
//			printf( "no tx packet\n" );
	}
}

int buffer_sendpacket( struct socket_t *sock, char *buf, int len, unsigned int addr, unsigned short port )
{
	struct thread_buffer_t *tbuf = sock->gtbuf; 
	struct buffer_header_t *cur;
	int ret;

	ret = buffer_alloc( tbuf, tbuf->lastsize );
	if ( ret < 0 )
	{
		return -1;
	}

	cur = (struct buffer_header_t *)( tbuf->buffer + ret );
	cur->next = -1;
	cur->len = len;

	memcpy( cur->data/* + 8*/, buf, len );

	cur->order = InterlockedIncrement( &sock->order );
//	cur->data[0] = 0; //ipv4
//	cur->data[1] = 6; //len
//	*(unsigned short *)(cur->data + 2) = port; //port (little endian)
//	*(unsigned int *)(cur->data + 4) = addr; //address (network order)

//	cur->len+=8;
	tbuf->lastsize = sizeof(struct buffer_header_t) + ( ( cur->len + 3 ) & ~3 );

	tbuf->last->next = ret;
	tbuf->last = cur;
	if ( sock->waiting )
		WSASetEvent( sock->waiter );

	return 0;
}

static void buffer_thread( void *p )
{
	struct thread_buffer_t *tbuf = (struct thread_buffer_t *)p;
	struct socket_t *sock = tbuf->socket;
	struct buffer_header_t *last = (struct buffer_header_t *)tbuf->buffer, *cur;
	int lastsize = sizeof(struct buffer_header_t);
	int ret, newret;
	struct sockaddr_in inaddr;
	int addrlen;
	char *buf;
#ifndef _WIN32
/*NO				struct epoll_event ee;
				sock->epfd = epoll_create(1);
				memset( &ee, 0, sizeof(ee) );
				ee.events = EPOLLIN;
				epoll_ctl(sock->epfd, EPOLL_CTL_ADD, sock->s, &ee);NO*/
#endif
/*				fd_set rfds;

				FD_ZERO(&rfds);
				FD_SET(sock->s, &rfds);
*/
	ret = buffer_alloc( tbuf, lastsize );

	for ( ;; )
	{
		//WSABUF wb;
		DWORD flags = 0;
		int waiter = 0;
		struct pcap_pkthdr ph;
		if ( sock->terminate )
		{
			InterlockedDecrement( &sock->terminate );
			return;
		}

		cur = (struct buffer_header_t *)( tbuf->buffer + ret );
		cur->next = -1;
		addrlen = sizeof(inaddr);

		//wb.buf = cur->data + 8;
		//wb.len = packet_max;
		//while ( WSARecvFrom( sock->s, &wb, 1, &cur->len, &flags, (struct sockaddr *)&inaddr, &addrlen, NULL, NULL ) < 0 )
		//while ( ( cur->len = recvfrom( sock->s, cur->data + 8, packet_max, 0, (struct sockaddr *)&inaddr, &addrlen) ) < 0 )
		//printf( "packet\n" );
		while ( ( buf = pcap_next( sock->pcd, /*cur->data*/&ph ) ) == NULL )
		{
			if ( sock->terminate )
			{
				InterlockedDecrement( &sock->terminate );
				return;
			}
		}

		cur->len = ph.caplen;//((struct pcap_pkthdr *)cur->data)->caplen;
		memcpy( cur->data + 16/*sizeof(struct pcap_pkthdr)*/, buf, cur->len );
		*(unsigned int *)(cur->data + 0) = ph.ts.tv_sec;
		*(unsigned int *)(cur->data + 4) = ph.ts.tv_usec;
		*(unsigned int *)(cur->data + 8) = ph.caplen;
		*(unsigned int *)(cur->data + 12) = ph.len;

/*		{
			waiter++;
			if ( waiter >= waiter_max )
			{
//				struct timeval tv;
				int retval;

				tv.tv_sec = 1;
				tv.tv_usec = 0;

				select(1, &rfds, NULL, NULL, &tv);//
#ifndef _WIN32
				epoll_wait(sock->epfd, &ee, 1, 1000);
#endif
				waiter = 0;
			}
			else
				Yield();
			//printf( "thread: recvfrom() failed with error code %d\n", WSAGetLastError() );
			//return;
			if ( sock->terminate )
			{
				InterlockedDecrement( &sock->terminate );
				return;
			}
		}*/
		//cur->data[0] = 0; //ipv4
		//cur->data[1] = 6; //len
		//*(unsigned short *)(cur->data + 2) = htons(inaddr.sin_port); //port (little endian)
		//*(unsigned int *)(cur->data + 4) = inaddr.sin_addr.s_addr; //address (network order)
		cur->len+=16;//sizeof(struct pcap_pkthdr);
		lastsize = sizeof(struct buffer_header_t) + ( ( cur->len + 3 ) & ~3 );
		//lastsize = sizeof(struct buffer_header_t) + cur->len;

		newret = buffer_alloc( tbuf, lastsize );
		if ( newret < 0 )
		{
			//Yield();
			//printf("buffer overrun...\n");
			continue;
		}
		cur->order = InterlockedIncrement( &sock->order );

		last->next = ret;
		last = cur;
		ret = newret;

		if ( sock->waiting )
			WSASetEvent( sock->waiter );
	}
}

static void buffer_socket_init( struct socket_t *sock, int id )
{
	int i;

	sock->terminate = 0;
	sock->order = 0;
	sock->readorder = 1;
	sock->waiter = WSACreateEvent();
	sock->waiting = 0;
	sock->id = id;
	sock->pcd = pcds[id];

	for ( i = 0; i < thread_max; i++ )
	{
		struct thread_buffer_t *tbuf = sock->gtbuf + i;
		struct buffer_header_t *last = (struct buffer_header_t *)tbuf->buffer;

		tbuf->apos = 0;
		tbuf->fpos = 0;
		tbuf->lastpos = 0;
		tbuf->socket = sock;
		tbuf->last = last;
		tbuf->lastsize = sizeof(struct buffer_header_t);

		last->len = 0;
		last->next = -1;
		last->order = InterlockedIncrement( &sock->order );
	}
}


//JNIEXPORT jobject JNICALL Java_test_DatagramSocket2_bindsocket
//  (JNIEnv *env, jobject jobj, jint port)
JNIEXPORT jobject JNICALL Java_org_araqne_pcap_live_PcapDevice_openBuffer(JNIEnv *env, jobject obj, jint id, jstring name, jint snaplen, jboolean promisc, jint milliseconds)
{
	WSADATA wd;
	struct sockaddr_in inaddr;
	int i, size;
	jobject jbuf;
	struct socket_t *sock;
	int txon = 1;

//	WSAStartup( 0x202, &wd );

	Java_org_araqne_pcap_live_PcapDevice_open(env, obj, id, name, snaplen, promisc, milliseconds);
	if ( pcds[id] == NULL )
		return NULL;

	sock = (struct socket_t *)malloc(sizeof(struct socket_t) * ( txon ? 2:1 ) ); 
	jbuf = (*env)->NewDirectByteBuffer(env, sock, sizeof(struct socket_t) );

/*NO
	if ( ( sock->s = socket( AF_INET, SOCK_DGRAM, 0 ) ) == -1 )
	{
		printf( "bindsocket: socket() failed with error code %d\n", WSAGetLastError() );
		return NULL;
	}

	memset( &inaddr, 0, sizeof(inaddr) );
	inaddr.sin_family = AF_INET;
	inaddr.sin_addr.s_addr = INADDR_ANY;
	inaddr.sin_port = htons( (unsigned short)port );

	if ( bind( sock->s, (struct sockaddr *)&inaddr, sizeof(inaddr) ) == -1 )
	{
		printf( "bindsocket: bind() failed with error code %d\n", WSAGetLastError() );
		return NULL;
	}
	
	size = 1048576;
	setsockopt( sock->s, SOL_SOCKET, SO_RCVBUF, (char *)&size, sizeof(int) );
	size = 1;
#ifndef _WIN32
	fcntl( sock->s, F_SETFL, O_NONBLOCK );
#endif
//	ioctlsocket( sock->s, FIONBIO, &size );
	printf( "Listening to udp port %d\n", port );
NO*/
	buffer_socket_init( sock, id );
	if ( txon )
	{
		buffer_socket_init( sock + 1, id );
		for ( i = 0; i < thread_max; i++ )
			sock[1].gtbuf[i].lastsize = buffer_alloc( sock[1].gtbuf + i, sizeof(struct buffer_header_t) );
		#ifdef _WIN32
		//sock[1].squeue = pcap_sendqueue_alloc( sendqueue_buffer_max );
		#endif
	}

	for ( i = 0; i < thread_max; i++ )
		_beginthread( buffer_thread, 0, sock->gtbuf + i );
	if ( txon )
	{
		for ( i = 0; i < thread_max; i++ )
			_beginthread( buffer_txthread, 0, sock[1].gtbuf + i );
	}
	return jbuf;
}

JNIEXPORT jbyteArray JNICALL Java_test_DatagramSocket2_recvsocket
  (JNIEnv *env, jobject jobj)
/*{
	jbyteArray jarr;
	jbyte *pb;
	int freepos, i;
	struct buffer_header_t *last = NULL;
	struct thread_buffer_t *tbuf = NULL;

retry:;
	for ( i = 0; i < thread_max; i++ )
	{
		tbuf = gtbuf + i;

		last = (struct buffer_header_t *)( tbuf->buffer + tbuf->lastpos );
		if ( last->next == -1 )
			continue;
//		printf( "%d\n", last->order );
		if ( last->order != readorder )
			continue;

		freepos = tbuf->lastpos;
		tbuf->lastpos = last->next;
		last = (struct buffer_header_t *)( tbuf->buffer + tbuf->lastpos );
		break;
	}
	if ( i == thread_max )
	{
		Yield();
		goto retry;
	}

	readorder++;
	jarr = (*env)->NewByteArray( env, last->len );
	pb = (*env)->GetByteArrayElements( env, jarr, NULL );
	memcpy( pb, last->data, last->len );
	(*env)->ReleaseByteArrayElements( env, jarr, pb, 0 );
	
	buffer_free( tbuf, freepos );
	return jarr;
}*/
{
	jbyteArray jarr;
	jbyte *pb;

	jarr = (*env)->NewByteArray( env, 160 );
	pb = (*env)->GetByteArrayElements( env, jarr, NULL );
	(*env)->ReleaseByteArrayElements( env, jarr, pb, 0 );

	return jarr;
}

int buffer_recvpacket( struct socket_t *sock, int freepos, int timeout )
{
	int i, waiter = 0;
	struct buffer_header_t *last = NULL;
	struct thread_buffer_t *tbuf;
//	struct socket_t *sock = (struct socket_t *)(*env)->GetDirectBufferAddress(env, jbuf);
	
	freepos-=8;
	tbuf = &sock->gtbuf[freepos / sizeof(struct thread_buffer_t)];

	freepos %= sizeof(struct thread_buffer_t);
	buffer_free( tbuf, freepos );

retry:;
	if ( sock->terminate )
		return -1;
	for ( i = 0; i < thread_max; i++ )
	{
		tbuf = sock->gtbuf + i;

		last = (struct buffer_header_t *)( tbuf->buffer + tbuf->lastpos );
		if ( last->next == -1 )
			continue;
//		printf( "%d\n", last->order );
		if ( last->order != sock->readorder )
			continue;	

		//freepos = tbuf->lastpos;
		tbuf->lastpos = last->next;
		freepos = tbuf->lastpos + i * sizeof(struct thread_buffer_t) + 8;
		//last = (struct buffer_header_t *)( tbuf->buffer + tbuf->lastpos );
		break;
	}
	if ( i == thread_max )
	{
//		Yield();
//		goto retry;
//		return -1;
		if ( timeout == 0 )
			return -1;
		waiter++;
		if ( waiter < waiter_max )
		{
			Yield();
			goto retry;
		}
		waiter = 0;
		sock->waiting = 1;
		if ( WSAWaitForMultipleEvents( 1, &sock->waiter, FALSE, timeout, FALSE ) == WSA_WAIT_TIMEOUT )
			return -1;
		WSAResetEvent( sock->waiter );
		sock->waiting = 0;
		timeout = 0;
		goto retry;
	}

	sock->readorder++;
	
	return freepos;
}

JNIEXPORT jint JNICALL Java_org_araqne_pcap_live_PcapDevice_getPacketBuffered(JNIEnv *env, jobject jobj, jobject jbuf, jint freepos, jint timeout)
{
	struct socket_t *sock = (struct socket_t *)(*env)->GetDirectBufferAddress(env, jbuf);

	return buffer_recvpacket( sock, freepos, timeout );
}

JNIEXPORT void JNICALL Java_org_araqne_pcap_live_PcapDevice_closeBuffer(JNIEnv *env, jobject obj, jobject jbuf)
//JNIEXPORT void JNICALL Java_test_DatagramSocket2_closesocket
//  (JNIEnv *env, jobject jobj, jobject jbuf)
{
	struct socket_t *sock = (struct socket_t *)(*env)->GetDirectBufferAddress(env, jbuf);

	sock[0].terminate = thread_max;
	while ( sock[0].terminate )
		Yield();
	sock[1].terminate = thread_max;
	WSASetEvent( sock[1].waiter );
	while ( sock[1].terminate )
		Yield();

#ifndef _WIN32
//NO	epoll_ctl(sock->epfd, EPOLL_CTL_DEL, sock->s, NULL);
#endif
//	closesocket( sock->s );
	Java_org_araqne_pcap_live_PcapDevice_close(env, obj, sock->id);
	WSACloseEvent( sock[0].waiter );
	WSACloseEvent( sock[1].waiter );
	free( sock );
}

JNIEXPORT jobject JNICALL Java_org_araqne_pcap_live_PcapDevice_getTxBuffer
  (JNIEnv *env, jobject obj, jobject jbuf)
{
	struct socket_t *sock = (struct socket_t *)(*env)->GetDirectBufferAddress(env, jbuf);

	jbuf = (*env)->NewDirectByteBuffer(env, sock + 1, sizeof(struct socket_t) );
	
	return jbuf;
}

JNIEXPORT jint JNICALL Java_org_araqne_pcap_live_PcapDevice_writeBuffer
  (JNIEnv *env, jobject obj, jobject jbuf, jint len)
{
	struct socket_t *sock = (struct socket_t *)(*env)->GetDirectBufferAddress(env, jbuf);
	struct thread_buffer_t *tbuf = sock->gtbuf; 
	struct buffer_header_t *cur;
	int lastsize, ret;

	if ( len < 0 )
		return tbuf->lastsize;

	cur = (struct buffer_header_t *)( tbuf->buffer + tbuf->lastsize );
	cur->next = -1;
	cur->len = len;

//	memcpy( cur->data/* + 8*/, buf, len );

	cur->order = InterlockedIncrement( &sock->order );
//	cur->data[0] = 0; //ipv4
//	cur->data[1] = 6; //len
//	*(unsigned short *)(cur->data + 2) = port; //port (little endian)
//	*(unsigned int *)(cur->data + 4) = addr; //address (network order)

//	cur->len+=8;
	lastsize = sizeof(struct buffer_header_t) + ( ( cur->len + 3 ) & ~3 );

	tbuf->last->next = tbuf->lastsize;
	tbuf->last = cur;
	if ( sock->waiting )
		WSASetEvent( sock->waiter );

	while ( ( ret = buffer_alloc( tbuf, lastsize ) ) < 0 )
		Yield();

	tbuf->lastsize = ret;
	return ret;
}
