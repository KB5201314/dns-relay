//
// Created by imlk on 19-7-3.
//

#ifndef DNS_RELAY_DNS_PACKAGE_H
#define DNS_RELAY_DNS_PACKAGE_H


#include <ostream>
#include <vector>
#include <uv/unix.h>

namespace dns {

    enum addr_type : unsigned short {
        A = 1,
        NS = 2,
        MD = 3,
        MF = 4,
        CNAME = 5,
        SOA = 6,
        MB = 7,
        MG = 8,
        MR = 9,
        NULL_ = 10,
        WKS = 11,
        PTR = 12,
        HINFO = 13,
        MINFO = 14,
        MX = 15,
        TXT = 16,
        AAAA = 28,
        IXFR = 251,
        AXFR = 252,
        OPT = 41,
        UNKNOWN_TYPE = 0,
    };

    std::ostream &operator<<(std::ostream &os, const addr_type &type);

    enum addr_class : unsigned short {
        IN = 1,
        CS = 2,
        CH = 3,
        HS = 4,
        UNKNOWN_CLASS = 0,
    };

    std::ostream &operator<<(std::ostream &os, const addr_class &clazz);

    struct code_section {
        unsigned short rd:1;      // 表示期望递归
        unsigned short tc:1;      // 表示可截断的
        unsigned short aa:1;      // 表示授权回答
        unsigned short opcode:4;  // 0表示标准查询，1表示反向查询，2表示服务器状态请求
        unsigned short qr:1;      // 查询/响应标志，0为查询，1为响应

        unsigned short rcode:4;   // 表示返回码，0表示没有差错，3表示名字差错，2表示服务器错误（Server Failure）
        unsigned short cd :1;
        unsigned short ad :1;
        unsigned short zero:1;
        unsigned short ra:1;      // 表示可用递归
        friend std::ostream &operator<<(std::ostream &os, const code_section &section);
    };

    struct question_record {
        std::vector<char> name;// name以\0结尾，非压缩形式
        addr_type type;
        addr_class clazz;

        question_record(const std::vector<char> &name, addr_type type, addr_class clazz);

        question_record();

        bool operator<(const question_record &rhs) const;

        bool operator>(const question_record &rhs) const;

        bool operator<=(const question_record &rhs) const;

        bool operator>=(const question_record &rhs) const;

        int deserialize(const char *src, int len, int offset);

        int serialize(char *buff);

        int serialized_size();

        friend std::ostream &operator<<(std::ostream &os, const question_record &record);
    };

    struct answer_record {
        std::vector<char> name;
        addr_type type;
        addr_class clazz;
        unsigned int ttl;
        std::vector<char> data;

        friend std::ostream &operator<<(std::ostream &os, const answer_record &record);

        int deserialize(const char *src, int len, int offset);

        int serialize(char *buff);

        int serialized_size();
    };

    void parse_question_record(const char *&src, question_record &r);

    void parse_answer_record(const char *&src, answer_record &r);

    struct dns_head {
        unsigned short id{0};
        code_section code{0};
        unsigned short question_num{0};
        unsigned short answer_num{0};
        unsigned short authority_num{0};
        unsigned short addition_num{0};
    };

    class dns_package {
    public:
        dns_head head;
        std::vector<question_record> questions;
        std::vector<answer_record> answers;
        std::vector<answer_record> authorities;
        std::vector<answer_record> additions;

    public:
        friend std::ostream &operator<<(std::ostream &os, const dns_package &aPackage);

    public:
        void decode(const char *src, int len);

        void reply(const dns_package &pkg);

        void add_question(const question_record &question);

        void add_answer(const answer_record &answer);

        void add_authority(const answer_record &authority);

        void add_addition(const answer_record &addition);

        std::pair<long, char *> encode();

        std::string describe_questions();

        std::string describe_answers();

    };

    int decompress_name(std::vector<char> &name, const char *src, int offset);

}
#endif //DNS_RELAY_DNS_PACKAGE_H
