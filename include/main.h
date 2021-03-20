//
// Created by imlk on 19-7-7.
//

#ifndef DNS_RELAY_MAIN_H
#define DNS_RELAY_MAIN_H

#include <uv.h>


void init_log();

void init_db();

int setup_loop();

void
on_recv_dns_query(uv_udp_t *handle, ssize_t nread, const uv_buf_t *buf, const struct sockaddr *addr, unsigned flags);

void on_recv_from_upstream(uv_udp_t *handle, ssize_t nread, const uv_buf_t *buf, const struct sockaddr *addr,
                           unsigned flags);

void send_reply_pkg(dns::dns_package &reply_pkg, const sockaddr &addr);

bool resolve_questions(dns::dns_package &pkg, dns::dns_package &reply_pkg);// 返回值标识是否能直接在本机解决

void forward_to_upstream(dns::dns_package &pkg, const sockaddr &addr, int try_times = 1);

void update_cache(const dns::dns_package &pkg);

bool search_and_add_answer(dns::addr_record_key k, dns::dns_package &reply_pkg);

void refresh_db(uv_timer_t *handle);

void init_listen_query();

void init_listen_upstream();

void init_refresh_cache_timer();

void init_args(int argc, char const *argv[]);

void dump_params();

void retry_forward_to_upstream(int upstream_id);

void init_signal();

#endif //DNS_RELAY_MAIN_H
