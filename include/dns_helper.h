//
// Created by imlk on 19-7-3.
//

#ifndef DNS_RELAY_DNS_HELPER_H
#define DNS_RELAY_DNS_HELPER_H

#include "dns_package.h"

namespace dns {
    addr_type parse_addr_type(const std::string &str);

    addr_class parse_addr_class(const std::string &str);

    std::vector<char> encode_name(const std::string &str);

    std::string decode_name(const std::vector<char> &name);

    std::vector<char> encode_ipv4(const std::string &str);

    std::string decode_ipv4(const std::vector<char> &data);

}


#endif //DNS_RELAY_DNS_HELPER_H
