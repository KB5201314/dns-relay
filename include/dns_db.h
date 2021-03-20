//
// Created by imlk on 19-7-3.
//

#ifndef DNS_RELAY_DNS_DB_H
#define DNS_RELAY_DNS_DB_H

#include <string>
#include <map>
#include <set>
#include <vector>
#include <ostream>
#include "dns_package.h"

namespace dns {

    typedef question_record addr_record_key;

    struct addr_record_value {
        unsigned long ddl{0};// 消亡的时间点

//        unsigned short data_len{0};// 数据资源长度
//        char *data{nullptr};// 数据资源
        std::vector<char> data;

        addr_record_value();

        addr_record_value(unsigned long ddl, const std::vector<char> &data);

        friend std::ostream &operator<<(std::ostream &os, const addr_record_value &value);
    };

    class dns_db {
        std::multimap<addr_record_key, addr_record_value> cache;
        std::multimap<addr_record_key, addr_record_value> fixed;

    private:
        dns_db();

    public:
        virtual ~dns_db();

    public:

        void insert_cache(const addr_record_key &key, const addr_record_value &addr);

        void insert_fixed(const addr_record_key &key, const addr_record_value &addr);

        int search(const addr_record_key &key, std::vector<addr_record_value> &values);

        void load_config_file(const std::string &path);

        static dns_db *empty();

        void remove_timeout_cache();
    };

    std::string describe_record_pair(const addr_record_key &key, const addr_record_value &value);
}

#endif //DNS_RELAY_DNS_DB_H
