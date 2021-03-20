//
// Created by imlk on 19-7-3.
//

#include <cstring>
#include <algorithm>
#include <dns_helper.h>
#include <sstream>
#include "dns_package.h"

#define LOG_TAG "dns_package"

namespace dns {

    void dns_package::decode(const char *src, int len) {
        memcpy(&this->head, src, sizeof(dns_head));
        this->head.question_num = ntohs(this->head.question_num);
        this->head.answer_num = ntohs(this->head.answer_num);
        this->head.authority_num = ntohs(this->head.authority_num);
        this->head.addition_num = ntohs(this->head.addition_num);


        const char *p = src + sizeof(dns_head);

        for (int i = 0; i < this->head.question_num; ++i) {
            question_record r;
            p += r.deserialize(src, len, p - src);
            this->questions.push_back(r);
        }
        for (int i = 0; i < this->head.answer_num; ++i) {
            answer_record r;
            p += r.deserialize(src, len, p - src);
            this->answers.push_back(r);
        }
        for (int i = 0; i < this->head.authority_num; ++i) {
            answer_record r;
            p += r.deserialize(src, len, p - src);
            this->authorities.push_back(r);
        }
        for (int i = 0; i < this->head.addition_num; ++i) {
            answer_record r;
            p += r.deserialize(src, len, p - src);
            this->additions.push_back(r);
        }

    }


    void dns_package::reply(const dns_package &pkg) {
        this->head.id = pkg.head.id;

        // TODO 回复的code
        this->head.code = pkg.head.code;
        this->head.code.qr = 1;
        this->head.code.ra = 1;

        this->head.question_num = pkg.head.question_num;
        for (auto question : pkg.questions) {
            this->questions.push_back(question);
        }

    }

    void dns_package::add_question(const question_record &question) {
        questions.push_back(question);
        head.question_num++;
    }

    void dns_package::add_answer(const answer_record &answer) {
        answers.push_back(answer);
        head.answer_num++;
    }

    void dns_package::add_authority(const answer_record &authority) {
        authorities.push_back(authority);
        head.authority_num++;
    }

    void dns_package::add_addition(const answer_record &addition) {
        additions.push_back(addition);
        head.addition_num++;
    }

    std::pair<long, char *> dns_package::encode() {
        int len = 0;// 计算长度
        len += sizeof(dns_head);

        for (int i = 0; i < this->head.question_num; ++i) {
            len += this->questions[i].serialized_size();
        }
        for (int i = 0; i < this->head.answer_num; ++i) {
            len += this->answers[i].serialized_size();
        }
        for (int i = 0; i < this->head.authority_num; ++i) {
            len += this->authorities[i].serialized_size();
        }
        for (int i = 0; i < this->head.addition_num; ++i) {
            len += this->additions[i].serialized_size();
        }

        // 填充
        char *data = new char[len];
        char *p = data;

        memcpy(data, &this->head, sizeof(dns_head));
        dns_head *p_dns_head = reinterpret_cast<dns_head *>(p);
        p_dns_head->question_num = htons(p_dns_head->question_num);
        p_dns_head->answer_num = htons(p_dns_head->answer_num);
        p_dns_head->authority_num = htons(p_dns_head->authority_num);
        p_dns_head->addition_num = htons(p_dns_head->addition_num);

        p += sizeof(dns_head);

        for (int i = 0; i < this->head.question_num; ++i) {
            p += this->questions[i].serialize(p);
        }
        for (int i = 0; i < this->head.answer_num; ++i) {
            p += this->answers[i].serialize(p);
        }
        for (int i = 0; i < this->head.authority_num; ++i) {
            p += this->authorities[i].serialize(p);
        }
        for (int i = 0; i < this->head.addition_num; ++i) {
            p += this->additions[i].serialize(p);
        }

        return std::pair<long, char *>(len, data);
    }


    question_record::question_record(const std::vector<char> &name, addr_type type, addr_class clazz) : name(name),
                                                                                                        type(type),
                                                                                                        clazz(clazz) {}

    question_record::question_record() {}

    int question_record::serialized_size() {
        int len = 0;
        len += this->name.size();

        len += sizeof(addr_type);
        len += sizeof(addr_class);
        return len;
    }

    int question_record::serialize(char *buff) {
        char *p = buff;
        std::copy(this->name.begin(), this->name.end(), p);
        p += this->name.size();

        *(addr_type *) p = static_cast<addr_type>(htons(this->type));
        p += sizeof(addr_type);
        *(addr_class *) p = static_cast<addr_class>(htons(this->clazz));
        p += sizeof(addr_class);

        return p - buff;
    }

    bool question_record::operator<(const question_record &rhs) const {
        if (name < rhs.name)
            return true;
        if (rhs.name < name)
            return false;
        if (type < rhs.type)
            return true;
        if (rhs.type < type)
            return false;
        return clazz < rhs.clazz;
    }

    bool question_record::operator>(const question_record &rhs) const {
        return rhs < *this;
    }

    bool question_record::operator<=(const question_record &rhs) const {
        return !(rhs < *this);
    }

    bool question_record::operator>=(const question_record &rhs) const {
        return !(*this < rhs);
    }

    int question_record::deserialize(const char *src, int len, int offset) {
        auto p = src + offset;
        auto const s = p;

        p += decompress_name(this->name, src, p - src);

        this->type = static_cast<addr_type>(ntohs(*(unsigned short *) p));
        p += sizeof(unsigned short);
        this->clazz = static_cast<addr_class>(ntohs(*(unsigned short *) p));
        p += sizeof(unsigned short);

        return p - s;
    }


    int answer_record::serialized_size() {
        int len = 0;
        len += this->name.size();

        len += sizeof(addr_type);
        len += sizeof(addr_class);

        len += sizeof(unsigned int);// ttl
        len += sizeof(unsigned short);// data_len
        len += this->data.size();
        return len;
    }

    int answer_record::serialize(char *buff) {
        char *p = buff;
        std::copy(this->name.begin(), this->name.end(), p);
        p += this->name.size();

        *(addr_type *) p = static_cast<addr_type>(htons(this->type));
        p += sizeof(addr_type);
        *(addr_class *) p = static_cast<addr_class>(htons(this->clazz));
        p += sizeof(addr_class);

        *(unsigned int *) p = htonl(this->ttl);
        p += sizeof(unsigned int);
        *(unsigned short *) p = htons(this->data.size());
        p += sizeof(unsigned short);
        std::copy(this->data.begin(), this->data.end(), p);
        p += this->data.size();

        return p - buff;
    }

    int answer_record::deserialize(const char *src, int len, int offset) {
        auto p = src + offset;
        auto const s = p;

        p += decompress_name(this->name, src, p - src);

        this->type = static_cast<addr_type>(ntohs(*(unsigned short *) p));
        p += sizeof(unsigned short);
        this->clazz = static_cast<addr_class>(ntohs(*(unsigned short *) p));
        p += sizeof(unsigned short);
        this->ttl = ntohl(*(unsigned int *) p);
        p += sizeof(unsigned int);
        unsigned short data_len = ntohs(*(unsigned short *) p);
        p += sizeof(unsigned short);

        if (this->type == addr_type::NS || this->type == addr_type::SOA || this->type == addr_type::CNAME ||
            this->type == addr_type::PTR) {
            decompress_name(this->data, src, p - src);
        } else {
            this->data.resize(data_len);
            std::copy(p, p + data_len, this->data.begin());
        }
        p += data_len;

        return p - s;
    }


    int decompress_name(std::vector<char> &name, const char *src, int offset) {
        auto p = src + offset;
        auto const s = p;

        if (((*p) & 0b11000000) == 0b11000000) {// 被压缩
            char b[2];
            b[0] = p[0];
            b[1] = p[1];
            b[0] &= 0b00111111;

            unsigned short off = ntohs(*(unsigned short *) b);
            decompress_name(name, src, off);

            return 2;
        } else {
            auto t = p;
            while (*t && ((*t) & 0b11000000) != 0b11000000) {
                t++;
            }
            int name_len = t - p;
            name.resize(name_len);
            std::copy(p, t, name.begin());

            if (*t) {// 遇到指针
                std::vector<char> name_1;
                decompress_name(name_1, src, t - src);
                name.insert(name.end(), name_1.begin(), name_1.end());
                p = t + 2;
            } else {// 以'\0'结尾
                name.push_back('\0');
                p = t + 1;// 跳过'\0'
            }

            return p - s;
        }
    }

    std::string dns_package::describe_questions() {
        std::stringstream ss;
        ss << "ques_num: " << this->head.question_num;
        if (this->head.question_num) {
            ss << " ques: {";
            for (int i = 0; i < this->head.question_num; ++i) {
                ss << "{" << this->questions[i] << "},";
            }
            ss << "}";
        }
        return ss.str();
    }

    std::string dns_package::describe_answers() {
        std::stringstream ss;
        ss << "ans_num: " << this->head.answer_num;
        if (this->head.answer_num) {
            ss << " anss: {";
            for (int i = 0; i < this->head.answer_num; ++i) {
                ss << "{" << this->answers[i] << "},";
            }
            ss << "}";
        }
        return ss.str();
    }


    std::ostream &operator<<(std::ostream &os, const dns_package &pkg) {
        os << "id: " << pkg.head.id << " code: " << pkg.head.code << " question_num: " << pkg.head.question_num
           << " answer_num: " << pkg.head.answer_num << " authority_num: " << pkg.head.authority_num
           << " addition_num: " << pkg.head.addition_num;
        return os;
    }

    std::ostream &operator<<(std::ostream &os, const addr_type &type) {
        switch (type) {
            case A:
                os << "A";
                return os;
            case NS:
                os << "NS";
                return os;
            case MD:
                os << "MD";
                return os;
            case MF:
                os << "MF";
                return os;
            case CNAME:
                os << "CNAME";
                return os;
            case SOA:
                os << "SOA";
                return os;
            case MB:
                os << "MB";
                return os;
            case MG:
                os << "MG";
                return os;
            case MR:
                os << "MR";
                return os;
            case NULL_:
                os << "NULL";
                return os;
            case WKS:
                os << "WKS";
                return os;
            case PTR:
                os << "PTR";
                return os;
            case HINFO:
                os << "HINFO";
                return os;
            case MINFO:
                os << "MINFO";
                return os;
            case MX:
                os << "MX";
                return os;
            case TXT:
                os << "TXT";
                return os;
            case AAAA:
                os << "AAAA";
                return os;
            case IXFR:
                os << "IXFR";
                return os;
            case AXFR:
                os << "AXFR";
                return os;
            case OPT:
                os << "OPT";
                return os;
            default:
                os << "UNKNOWN_TYPE(" << (unsigned short) type << ")";
                return os;
        }
    }

    std::ostream &operator<<(std::ostream &os, const addr_class &clazz) {
        switch (clazz) {
            case IN:
                os << "IN";
                return os;
            case CS:
                os << "CS";
                return os;
            case CH:
                os << "CH";
                return os;
            case HS:
                os << "HS";
                return os;
            default:
                os << "UNKNOWN_CLASS(" << (unsigned short) clazz << ")";
                return os;
        }
    }


    std::ostream &operator<<(std::ostream &os, const code_section &section) {
        os << "qr: " << section.qr << " opcode: " << section.opcode << " aa: " << section.aa << " tc: " << section.tc
           << " rd: " << section.rd << " ra: " << section.ra << " zero: " << section.zero << " ad: " << section.ad
           << " cd: " << section.cd << " rcode: " << section.rcode;
        return os;
    }


    std::ostream &operator<<(std::ostream &os, const question_record &record) {
        os << "name: " << decode_name(record.name) << " type: " << record.type << " clazz: " << record.clazz;
        return os;
    }


    std::ostream &operator<<(std::ostream &os, const answer_record &record) {
        os << "name: " << decode_name(record.name) << " type: " << record.type << " clazz: " << record.clazz
           << " ttl: "
           << record.ttl;
        if (record.clazz == addr_class::IN) {
            if (record.type == addr_type::A) {
                os << " data: " << decode_ipv4(record.data);
            } else if (record.type == addr_type::AAAA) {
                char s[INET6_ADDRSTRLEN];
                inet_ntop(AF_INET6, record.data.data(), s, INET6_ADDRSTRLEN);
                os << " data: " << s;
            } else if (record.type == addr_type::CNAME) {
                os << " data: " << decode_name(record.data);
            }
            return os;
        }
        os << " data.size: " << record.data.size();
        return os;
    }

}
