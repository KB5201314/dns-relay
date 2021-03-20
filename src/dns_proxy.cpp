//
// Created by imlk on 19-7-7.
//

#include "dns_proxy.h"

namespace dns {
    namespace proxy {
        int upstream_id_next = 0;
        std::map<int, query_request> clients;
    }

    query_request::query_request(const sockaddr &addr, const dns_package &pkg) : addr(addr), pkg(pkg) {}

    query_request::query_request() {}

    query_request::query_request(const sockaddr &addr, const dns_package &pkg, int tryTimes) : addr(addr), pkg(pkg),
                                                                                               try_times(tryTimes) {}

}
