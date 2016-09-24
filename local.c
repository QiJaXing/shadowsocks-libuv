//
//  shadow.c
//  shadowsocks-libuv
//
//  Created by Cube on 14-9-14.
//  Copyright (c) 2014年 Cube. All rights reserved.
//
#include <getopt.h>
#include <shadow.h>

conf_t conf;

static void help(void) {
	printf(
			"Usage. ss-local\n"
					"  -s <server_host>           host name or ip address of your remote server\n"
					"  -p <server_port>           port number of your remote server\n"
					"  -b <local_host>            local address to bind\n"
					"  -l <local_port>            port number of your local server\n"
					"  -k <password>              password of your remote server\n"
					"  -m <encrypt_method>        encrypt method: table, rc4, rc4-md5,\n"
					"                             aes-128-cfb, aes-192-cfb, aes-256-cfb,\n"
					"                             bf-cfb, camellia-128-cfb, camellia-192-cfb,\n"
					"                             camellia-256-cfb, cast5-cfb, des-cfb,\n"
					"                             idea-cfb, rc2-cfb and seed-cfb\n"
//         "  [-t <timeout>]             socket timeout in seconds\n"
//         "  [-c <config_file>]         config file in json\n"
//         "  [-i <interface>]           network interface to bind,\n"
//         "                             not available in redir mode\n"
//         "  [-b <local_address>]       local address to bind,\n"
//         "                             not available in server mode\n"
			);
	exit(EXIT_FAILURE);
}

static void parse(int argc, char *argv[]) {
	memset(&conf, 0, sizeof(conf));

	char opt;
	while ((opt = getopt(argc, argv, "s:p:b:l:k:m:")) != -1)
		switch (opt) {
		case 's':
			conf.remote.ip = optarg;
			break;
		case 'p':
			conf.remote.port = optarg;
			break;
		case 'b':
			conf.local.ip = optarg;
			break;
		case 'l':
			conf.local.port = optarg;
			break;
		case 'k':
			conf.pass = optarg;
			break;
		case 'm':
			conf.method = optarg;
			break;
		default:
			break;
		}

	// check conf
	do {
		if (!conf.remote.ip)
			break;
		if (!conf.remote.port)
			break;
		if (!conf.local.ip)
			break;
		if (!conf.local.ip)
			break;
		if (!conf.remote.port)
			break;
		if (!conf.pass)
			break;
		if (!conf.method)
			break;
		return;
	} while (0);

	help();
}

int main(int argc, char *argv[]) {
	parse(argc, argv);
	signal(SIGPIPE, SIG_IGN);
	// set rand seed
	srand((unsigned int) time(NULL));

	uv_tcp_t * listener = malloc(sizeof(uv_tcp_t));
	uv_stream_t * stream = (uv_stream_t *) listener;
	uv_loop_t * loop = uv_default_loop();
	uv_loop_init(loop);
	struct sockaddr_in6 addr;
	int iret;
	iret = uv_ip6_addr(conf.local.ip, atoi(conf.local.port), &addr);
	if (iret < 0) {
		fprintf(stderr, "%s:\t%s\n", uv_err_name(iret), uv_strerror(iret));
		return iret;
	}
	do {
		if (uv_tcp_init(loop, listener))
			break;
		if (uv_tcp_bind(listener, (const struct sockaddr*) &addr, 0))
			break;
		if (uv_listen(stream, 128, client_connect_cb))
			break;
		return uv_run(loop, UV_RUN_DEFAULT);
	} while (0);
	return 0;
}

