//
// Created by imlk on 19-7-3.
//

#define LOG_TAG "dns_db"

#include "dns_db.h"
#include <fstream>
#include <dns_package.h>
#include <sstream>
#include <cstring>
#include <ctime>
#include <inc/elog.h>

#include "dns_helper.h"

namespace dns {

    void dns_db::load_config_file(const std::string &path) {
        std::ifstream f(path);
        std::string line;
        int c = 0;
        while (std::getline(f, line)) {
            std::string url;
            std::string ip;
            std::stringstream ss(line);
            ss >> ip >> url;

            if (ip != "" && url != "") {
                this->insert_fixed(
                        addr_record_key(encode_name(url), addr_type::A, addr_class::IN),
                        addr_record_value(0, encode_ipv4(ip)));

                c++;
            }

        }

        log_i("load config from %s , %d fixed record", path.c_str(), c);
    }

    dns_db *dns_db::empty() {
        return new dns_db();
    }

    dns_db::dns_db() {

    }

    void dns_db::insert_cache(const addr_record_key &key, const addr_record_value &addr) {


        log_i("insert cache record: %s", describe_record_pair(key, addr).c_str());

        int c = this->cache.count(key);
        auto iter = this->cache.find(key);

        for (int i = 0; i < c; ++i, ++iter) {
            if (iter->second.data == addr.data) {// 如果存在，只则刷新TTL
                iter->second.ddl = addr.ddl;
                return;
            }
        }

        this->cache.insert(std::pair<addr_record_key, addr_record_value>(key, addr));
    }

    void dns_db::insert_fixed(const addr_record_key &key, const addr_record_value &addr) {
        log_v("insert fixed record: %s", describe_record_pair(key, addr).c_str());
        this->fixed.insert(std::pair<addr_record_key, addr_record_value>(key, addr));
    }

    int dns_db::search(const addr_record_key &key, std::vector<addr_record_value> &values) {
        {
            int c = this->fixed.count(key);
            auto iter = this->fixed.find(key);
            for (int i = 0; i < c; ++i, iter++) {
                iter->second.ddl = time(nullptr) + 1000;
                values.push_back(iter->second);
            }
            if (c) {
                return c;
            }
        }
        {
            auto c = this->cache.count(key);
            auto iter = this->cache.find(key);
            for (int i = 0; i < c; ++i, iter++) {
                values.push_back(iter->second);
            }
            return c;

        }
    }

    void dns_db::remove_timeout_cache() {
        auto cur_time = std::time(nullptr);
        for (auto iter = this->cache.begin(); iter != this->cache.end();) {
            if (iter->second.ddl < cur_time) {
                log_i("remove cache record: %s", describe_record_pair(iter->first, iter->second).c_str());

                iter = this->cache.erase(iter);
            } else {
                ++iter;
            }
        }

    }

    dns_db::~dns_db() {
        cache.clear();
        fixed.clear();
    }

    std::ostream &operator<<(std::ostream &os, const addr_record_value &value) {
        os << "ddl: " << value.ddl << " data.size: " << value.data.size();
        return os;
    }

    std::string describe_record_pair(const addr_record_key &key, const addr_record_value &value) {
        std::stringstream ss;
        ss << "key(" << key << ") => addr(" << "ddl: " << value.ddl;
        ss << " ttl: ";
        auto cur_time = time(nullptr);
        if (value.ddl >= cur_time) {
            ss << value.ddl - cur_time;
        } else {
            ss << "< 0";
        }

        bool data_printable = false;
        if (key.clazz == addr_class::IN) {
            if (key.type == addr_type::A) {
                ss << " data: " << decode_ipv4(value.data);
                data_printable = true;
            } else if (key.type == addr_type::AAAA) {
                char s[INET6_ADDRSTRLEN];
                inet_ntop(AF_INET6, value.data.data(), s, INET6_ADDRSTRLEN);
                ss << " data: " << s;
                data_printable = true;
            } else if (key.type == addr_type::CNAME) {
                ss << " data: " << decode_name(value.data);
                data_printable = true;
            }
        }
        if (!data_printable) {
            ss << " data.size: " << value.data.size();
        }
        ss << ")";
        return ss.str();
    }

    addr_record_value::addr_record_value() {

    }

    addr_record_value::addr_record_value(unsigned long ddl, const std::vector<char> &data) : ddl(ddl), data(data) {}


}
