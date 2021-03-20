//
// Created by imlk on 19-7-3.
//

#include <string>
#include <cstring>
#include "dns_helper.h"
#include <vector>
#include <sstream>

#define LOG_TAG "dns_helper"

namespace dns {

    addr_type parse_addr_type(const std::string &str) {
        if (str == "A")return A;
        if (str == "NS")return NS;
        if (str == "MD")return MD;
        if (str == "MF")return MF;
        if (str == "CNAME")return CNAME;
        if (str == "SOA")return SOA;
        if (str == "MB")return MB;
        if (str == "MG")return MG;
        if (str == "MR")return MR;
        if (str == "NULL")return NULL_;
        if (str == "WKS")return WKS;
        if (str == "PTR")return PTR;
        if (str == "HINFO")return HINFO;
        if (str == "MINFO")return MINFO;
        if (str == "MX")return MX;
        if (str == "TXT")return TXT;
        if (str == "AAAA")return AAAA;
        if (str == "IXFR")return IXFR;
        if (str == "AXFR")return AXFR;
        if (str == "OPT")return OPT;
        if (str == "UNKNOWN_TYPE")return UNKNOWN_TYPE;
        return UNKNOWN_TYPE;
    }


    addr_class parse_addr_class(const std::string &str) {
        if (str == "IN") return IN;
        if (str == "CS") return CS;
        if (str == "CH") return CH;
        if (str == "HS") return HS;
        return UNKNOWN_CLASS;
    }

    std::vector<char> encode_name(const std::string &str) {//接受类似于gist.github.com.或者gist.github.com的输入
        std::vector<char> name;
        int t = 0;
        for (int i = 0; i <= str.length(); i++) {
            if (i != str.length() && str[i] != '.') {
                t++;
            } else {
                if (t != 0) {
                    name.push_back(t);
                    for (int j = i - t; j < i; ++j) {
                        name.push_back(str[j]);
                    }
                    t = 0;
                }
            }
        }
        name.push_back('\0');
        return name;
    }

    std::string decode_name(const std::vector<char> &name) {// 名字转换为输出gist.github.com.
        std::string str;
        if (name.empty()) {
            return str;
        }

        int i = 0;
        int t = name[0];
        i++;
        while (i < name.size()) {
            if (t && i != name.size()) {
                str += name[i];
                t--;
            } else {
                t = name[i];
                str += '.';
            }
            i++;
        }
        return str;
    }

    std::vector<char> encode_ipv4(const std::string &str) {
        std::vector<char> data;
        data.resize(4);
        int a, b, c, d;
        sscanf(str.c_str(), "%d.%d.%d.%d", &a, &b, &c, &d);
        data[0] = a;
        data[1] = b;
        data[2] = c;
        data[3] = d;
        return data;
    }

    std::string decode_ipv4(const std::vector<char> &data) {
        std::stringstream ss;
        ss << (int) (unsigned char) data[0];
        ss << '.';
        ss << (int) (unsigned char) data[1];
        ss << '.';
        ss << (int) (unsigned char) data[2];
        ss << '.';
        ss << (int) (unsigned char) data[3];
        return ss.str();
    }

}