#define LOG_TAG "main"


#include <iostream>
#include <dns_helper.h>
#include <sstream>
#include <ctime>
#include "elog.h"
#include "dns_package.h"
#include "dns_db.h"
#include <algorithm>
#include <dns_proxy.h>
#include <cstring>
#include "main.h"

//#define DNS_SERVER_PORT 1068
#define DNS_SERVER_PORT 53
#define DNS_SERVER_ADDR "0.0.0.0"

#define DNS_RECU_ADDR "0.0.0.0"
#define DNS_RECU_PORT 0

#define DEFAULT_DNS_UPSTREAM_ADDR "10.3.9.4"
#define DNS_UPSTREAM_PORT 53

#define RETRY_UPSTREAM_TIME_SLOT 1000

#define REFRESH_DB_TIME_SLOT 5000

#define TTL_LARGER_THAN_UPSTREAM_S 10
#define MIN_ALLOW_TTL_S 5

#define DEFAULT_CONFIG_FILE_PATH "./dns-table.txt"


#define check_uv_status(status_expression) { \
    auto status = status_expression;\
    if (status < 0) {\
        log_e("bad status[%d]: %s %s", status, uv_err_name(status), uv_strerror(status));\
    }\
}


using namespace dns;

int log_level = 0;
std::string upstream_dns_server_ipaddr(DEFAULT_DNS_UPSTREAM_ADDR);
std::string config_file_path(DEFAULT_CONFIG_FILE_PATH);


uv_loop_t *loop;
uv_udp_t server_handle;

uv_udp_t recu_handle;

sockaddr_in server_addr;
sockaddr_in recu_addr;
sockaddr_in upstream_addr;

dns_db *db;

uv_timer_t refresh_cache_timer_handle;


int main(int argc, char const *argv[]) {
    init_args(argc, argv);
    init_signal();
    init_log();
    dump_params();
    init_db();
    return setup_loop();
}

void init_signal() {
    signal(SIGINT, [](int sig) {
        if (loop) {
            uv_loop_close(loop);
        }
        if (db) {
            delete db;
        }


        exit(0);
    });
}

void dump_params() {
    log_i("[params] upstream_dns_server_ipaddr: %s", upstream_dns_server_ipaddr.c_str());
    log_i("[params] config_file_path: %s", config_file_path.c_str());
}

void init_args(int argc, char const *argv[]) {
    int ind = 1;

    if (ind < argc) {
        if (!std::strcmp(argv[ind], "-d")) {
            log_level = 1;
        } else if (!std::strcmp(argv[ind], "-dd")) {
            log_level = 2;
        }
        ind++;
    }
    if (ind < argc) {
        upstream_dns_server_ipaddr = std::string(argv[ind]);
        ind++;
    }

    if (ind < argc) {
        config_file_path = std::string(argv[ind]);
        ind++;
    }

    if (ind < argc) {
        std::cout << "usage: " << argv[0] << " [-d | -dd] [dns-server-ipaddr] [filename]";

    }


}

void init_log() {
/* close printf buffer */
    setbuf(stdout, nullptr);
/* initialize EasyLogger */
    elog_init();

    if (log_level == 0) {
        elog_set_filter_lvl(ELOG_LVL_ASSERT);
    } else if (log_level == 1) {
        elog_set_filter_lvl(ELOG_LVL_INFO);
    } else {
        elog_set_filter_lvl(ELOG_LVL_VERBOSE);
    }

/* set EasyLogger log format */
    elog_set_fmt(ELOG_LVL_ASSERT, ELOG_FMT_ALL);
    elog_set_fmt(ELOG_LVL_ERROR, ELOG_FMT_LVL | ELOG_FMT_TAG | ELOG_FMT_TIME);
    elog_set_fmt(ELOG_LVL_WARN, ELOG_FMT_LVL | ELOG_FMT_TAG | ELOG_FMT_TIME);
    elog_set_fmt(ELOG_LVL_INFO, ELOG_FMT_LVL | ELOG_FMT_TAG | ELOG_FMT_TIME);
    elog_set_fmt(ELOG_LVL_DEBUG, ELOG_FMT_LVL | ELOG_FMT_TAG | ELOG_FMT_TIME);
    elog_set_fmt(ELOG_LVL_VERBOSE, ELOG_FMT_ALL & ~ELOG_FMT_FUNC);
/* start EasyLogger */
    elog_start();
}

void init_db() {
    db = dns_db::empty();
    db->load_config_file(config_file_path);

//    db->insert_cache(
//            addr_record_key(encode_name("gist.github.com."), parse_addr_type("A"), parse_addr_class("IN")),
//            addr_record_value(time(nullptr) + 100, encode_ipv4("192.30.253.119")));
//    db->insert_ban(encode_name("www.baidu.com"));
}

int setup_loop() {

    loop = uv_default_loop();

    init_listen_query();
    init_listen_upstream();
    init_refresh_cache_timer();

    check_uv_status(uv_run(loop, UV_RUN_DEFAULT));

    return 0;
}

void init_listen_query() {
    uv_udp_init(loop, &server_handle);
    uv_ip4_addr(DNS_SERVER_ADDR, DNS_SERVER_PORT, &server_addr);
    check_uv_status(uv_udp_bind(&server_handle, (const sockaddr *) (&server_addr), 0));

    check_uv_status(uv_udp_recv_start(&server_handle,
                                      [](uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf) {
                                          buf->base = new char[suggested_size];
                                          buf->len = suggested_size;
                                      }, on_recv_dns_query));
}

void init_listen_upstream() {
    uv_udp_init(loop, &recu_handle);
    uv_ip4_addr(DNS_RECU_ADDR, DNS_RECU_PORT, &recu_addr);
    check_uv_status(uv_udp_bind(&recu_handle, (const sockaddr *) (&recu_addr), 0));

    uv_ip4_addr(upstream_dns_server_ipaddr.c_str(), DNS_UPSTREAM_PORT, &upstream_addr);

    check_uv_status(uv_udp_recv_start(&recu_handle,
                                      [](uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf) {
                                          buf->base = new char[suggested_size];
                                          buf->len = suggested_size;
                                      }, on_recv_from_upstream));
}

void init_refresh_cache_timer() {
    uv_timer_init(loop, &refresh_cache_timer_handle);
    uv_timer_start(&refresh_cache_timer_handle, refresh_db, REFRESH_DB_TIME_SLOT, REFRESH_DB_TIME_SLOT);

}

void
on_recv_dns_query(uv_udp_t *handle, ssize_t nread, const uv_buf_t *buf, const struct sockaddr *addr, unsigned flags) {
    if (nread != 0) {

        // 检查pkg的合法性
        if (nread < sizeof(dns_head)) {
            log_w("invalid pkg from client(framily: %d ip: %s port: %d)", addr->sa_family,
                  inet_ntoa(((sockaddr_in *) addr)->sin_addr), ((sockaddr_in *) addr)->sin_port);

            delete[] buf->base;
            return;
        }

        dns_package pkg;
        pkg.decode(buf->base, nread);


        log_i("client(framily: %d ip: %s port: %d) => pkg(id: %d %s)", addr->sa_family,
              inet_ntoa(((sockaddr_in *) addr)->sin_addr), ((sockaddr_in *) addr)->sin_port, pkg.head.id,
              pkg.describe_questions().c_str());

        std::stringstream ss;
        ss << pkg;
        log_d("pkg(%s)", ss.str().c_str());

        if (pkg.head.code.qr == 0) {// 请求包

            dns_package reply_pkg;

            bool all_found = resolve_questions(pkg, reply_pkg);

            if (all_found) {
                send_reply_pkg(reply_pkg, *addr);
            } else {
                forward_to_upstream(pkg, *addr);
            }

        }
    }
    delete[] buf->base;

}

bool resolve_questions(dns_package &pkg, dns_package &reply_pkg) {// 返回值标识是否能直接在本机解决

    reply_pkg.reply(pkg);

    auto questions = pkg.questions;
    unsigned short qn = pkg.head.question_num;

    for (int i = 0; i < qn; ++i) {

        if (search_and_add_answer(
                addr_record_key(questions[i].name, questions[i].type, questions[i].clazz), reply_pkg)) {
            log_d("found cache_data of name: %s", decode_name(questions[i].name).c_str());
        } else {
            log_d("not found any cache_data of name: %s", decode_name(questions[i].name).c_str());
            return false;
        }
    }

    return true;
}

bool search_and_add_answer(addr_record_key k, dns_package &reply_pkg) {
    addr_type old_type = k.type;

    std::vector<addr_record_value> cache_datas;
    int c = db->search(k, cache_datas);

    if (c == 0 && k.type != addr_type::CNAME) {// try cname
        k.type = addr_type::CNAME;
        c = db->search(k, cache_datas);
    }
    if (c != 0) {

        auto cur_time = std::time(nullptr);

        bool found_by_cname = false;
        for (auto cache_data : cache_datas) {
            unsigned int ttl;
            if (cache_data.ddl - MIN_ALLOW_TTL_S > cur_time) {// 如果剩余时间少于5，就不返回该结果，待外层函数去上游服务器拿新数据
                ttl = cache_data.ddl - cur_time;
            } else {
                c--;
                continue;
            }

            answer_record ans;
            ans.name = k.name;
            ans.type = k.type;
            ans.clazz = k.clazz;
            ans.data = cache_data.data;
            ans.ttl = ttl;
            reply_pkg.add_answer(ans);

            if (k.type == CNAME) {// 递归cname
                if (search_and_add_answer(addr_record_key(ans.data, old_type, k.clazz), reply_pkg)) {
                    found_by_cname = true;
                }
            }
        }

        if (old_type != CNAME && k.type == CNAME && !found_by_cname) {
            // 不是问CNAME，而且cache里只存在CNAME而通过CNAME找不到对应的ip，则应当更新数据
            return false;
        }
    }

    if (c > 0) {
        return true;
    } else {
        return false;
    }

}

// 与上游通信出错时重传
void retry_forward_to_upstream(int upstream_id) {
    auto iter = proxy::clients.find(upstream_id);

    if (iter != proxy::clients.end()) {

        if (iter->second.try_times < MAX_TRY_TIMES) {
            log_i("retry_forward query_id: %d <==> upstream_id: %d try_times: %d", iter->second.pkg.head.id,
                  upstream_id, iter->second.try_times);
            forward_to_upstream(iter->second.pkg, iter->second.addr, iter->second.try_times + 1);

        } else {
            log_i("retry_forward query_id: %d <==> upstream_id: %d, but max try time exceed", iter->second.pkg.head.id,
                  upstream_id);
            dns_package reply_pkg;
            resolve_questions(iter->second.pkg, reply_pkg);
            send_reply_pkg(reply_pkg, iter->second.addr);
        }

        proxy::clients.erase(iter);
    } else {

        log_e("upstream_id: %d was not found in proxy::clients", upstream_id);

    }


}

void forward_to_upstream(dns_package &pkg, const sockaddr &addr, int try_times) {
    log_d("forward pkg(id: %d) to upstream(%s)", pkg.head.id, upstream_dns_server_ipaddr.c_str());
    // 任务发到上级dns

    dns_package to_upstream_pkg;
    to_upstream_pkg.head.id = proxy::upstream_id_next++;
    to_upstream_pkg.head.code.rd = 1;

    for (int i = 0; i < pkg.questions.size(); ++i) {
        to_upstream_pkg.add_question(pkg.questions[i]);
    }
    proxy::clients[to_upstream_pkg.head.id] = query_request(addr, pkg, try_times);
    log_i("add forward map: query_id: %d <==> upstream_id: %d", pkg.head.id, to_upstream_pkg.head.id);

    uv_buf_t to_upstream_msg;
    auto encode_result = to_upstream_pkg.encode();
    to_upstream_msg.len = encode_result.first;
    to_upstream_msg.base = encode_result.second;

    uv_udp_send_t *recu_send_req = new uv_udp_send_t();
    recu_send_req->data = to_upstream_msg.base;

    log_i("upstream(%s) <= pkg(id: %d)", upstream_dns_server_ipaddr.c_str(), to_upstream_pkg.head.id);

    uv_udp_send(recu_send_req, &recu_handle, &to_upstream_msg, 1, (sockaddr *) &upstream_addr,
                [](uv_udp_send_t *req, int status) {
                    log_d("upstsream send status: %d", status);
                    delete[] (char *) req->data;
                    delete req;
                });


    auto retry_handle = new uv_timer_t();
    proxy::clients[to_upstream_pkg.head.id].retry_handle = retry_handle;
    retry_handle->data = new int(to_upstream_pkg.head.id);
    uv_timer_init(loop, retry_handle);
    uv_timer_start(retry_handle, [](uv_timer_t *handle) {
                       retry_forward_to_upstream(*(int *) handle->data);

                       uv_timer_stop(handle);
//                       log_d("uv_close pkg_id: %d", *(int *) handle->data);
                       uv_close((uv_handle_t *) (handle), [](uv_handle_t *h) {
                           delete (int *) h->data;
                           delete (uv_timer_t *) h;
                       });
                   },
                   RETRY_UPSTREAM_TIME_SLOT, 0);

}

void on_recv_from_upstream(uv_udp_t *handle, ssize_t nread, const uv_buf_t *buf, const struct sockaddr *addr,
                           unsigned flags) {
    if (nread != 0) {

        // 检查pkg的合法性
        if (nread < sizeof(dns_head)) {
            log_w("invalid pkg from upstream(%s)", upstream_dns_server_ipaddr.c_str());
            delete[] buf->base;
            return;
        }

        dns_package pkg;
        pkg.decode(buf->base, nread);

        log_i("upstream(%s) => pkg(id: %d)", upstream_dns_server_ipaddr.c_str(), pkg.head.id);

        std::stringstream ss;
        ss << pkg;
        log_d("pkg(upstream %s)", ss.str().c_str());

        if (pkg.head.code.qr == 1) {// 响应包

            update_cache(pkg);

            auto iter = proxy::clients.find(pkg.head.id);
            if (iter != proxy::clients.end()) {
                log_i("found forward map: query_id: %d <==> upstream_id: %d", iter->second.pkg.head.id, pkg.head.id);
                dns_package reply_pkg;
                resolve_questions(iter->second.pkg, reply_pkg);
                send_reply_pkg(reply_pkg, iter->second.addr);

                auto handle = iter->second.retry_handle;
                uv_timer_stop(handle);
//                log_d("uv_close pkg_id: %d", *(int *) handle->data);
                uv_close((uv_handle_t *) (handle), [](uv_handle_t *h) {
                    delete (int *) h->data;
                    delete (uv_timer_t *) h;
                });
                proxy::clients.erase(iter);

            } else {
                log_w("can not found proxyed request upstream_id: %d", pkg.head.id);
            }

        }
    }
    delete[] buf->base;
}

void insert_answer_record_to_cache(const answer_record &r) {

    db->insert_cache(addr_record_key(r.name, r.type, r.clazz),
                     addr_record_value(r.ttl + time(nullptr) + TTL_LARGER_THAN_UPSTREAM_S, r.data));

}

void update_cache(const dns_package &pkg) {

    for (int i = 0; i < pkg.head.answer_num; ++i) {
        insert_answer_record_to_cache(pkg.answers[i]);
    }
    for (int i = 0; i < pkg.head.authority_num; ++i) {
        insert_answer_record_to_cache(pkg.authorities[i]);
    }
    // 不处理questions和additions

}

void send_reply_pkg(dns_package &reply_pkg, const sockaddr &addr) {
    uv_buf_t reply_msg;
    auto encode_result = reply_pkg.encode();
    reply_msg.len = encode_result.first;
    reply_msg.base = encode_result.second;

    uv_udp_send_t *server_send_req = new uv_udp_send_t();
    server_send_req->data = reply_msg.base;

    log_i("client(framily: %d ip: %s port: %d) <= pkg(id: %d ques:{%s} ans:{%s})", addr.sa_family,
          inet_ntoa(((sockaddr_in *) &addr)->sin_addr), ((sockaddr_in *) &addr)->sin_port, reply_pkg.head.id,
          reply_pkg.describe_questions().c_str(), reply_pkg.describe_answers().c_str());

    uv_udp_send(server_send_req, &server_handle, &reply_msg, 1, &addr,
                [](uv_udp_send_t *req, int status) {
                    log_d("reply status: %d", status);
                    delete[] (char *) req->data;
                    delete req;
                });

}

void refresh_db(uv_timer_t *handle) {
    db->remove_timeout_cache();
}

