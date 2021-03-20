//
// Created by imlk on 19-7-7.
//

#ifndef DNS_RELAY_UPSTREAM_SERVICE_H
#define DNS_RELAY_UPSTREAM_SERVICE_H

#include <map>
#include <sys/socket.h>
#include <uv.h>
#include "dns_package.h"

#define MAX_TRY_TIMES 3

namespace dns {

    struct query_request {
        sockaddr addr;// queryer's addr
        dns_package pkg;// queryer's pkg
        int try_times{1};
        uv_timer_t *retry_handle{nullptr};

        query_request(const sockaddr &addr, const dns_package &pkg, int tryTimes);

        query_request(const sockaddr &addr, const dns_package &pkg);

        query_request();
    };

    namespace proxy {
        extern int upstream_id_next;
        extern std::map<int, query_request> clients;

    }

}


#endif //DNS_RELAY_UPSTREAM_SERVICE_H
