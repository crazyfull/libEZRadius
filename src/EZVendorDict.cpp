#include "EZVendorDict.h"
#include <algorithm>
#include <arpa/inet.h>
#include <cctype>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <sstream>

static std::string lower(const std::string &s)
{
    std::string r = s;
    std::transform(r.begin(), r.end(), r.begin(), [](unsigned char c){ return (char)std::tolower(c); });
    return r;
}

EZVendorRegistry::EZVendorRegistry() {}

EZVendorRegistry EZVendorRegistry::empty()
{
    return EZVendorRegistry();
}

EZVendorRegistry &EZVendorRegistry::instance()
{
    static EZVendorRegistry *reg = []{
        EZVendorRegistry *r = new EZVendorRegistry();       // lives until the process ends
        r->loadDictionary(EZVendorDictionaryMikroTik());
        r->loadDictionary(EZVendorDictionaryCisco());
        r->loadDictionary(EZVendorDictionaryJuniper());
        r->loadDictionary(EZVendorDictionaryHuawei());
        r->loadDictionary(EZVendorDictionaryMicrosoft());
        return r;
    }();
    return *reg;
}

bool EZVendorRegistry::registerVendor(const EZVendorDef &v)
{
    if(v.id == 0 || v.name.empty())
        return false;
    if(!(v.typeSize == 1 || v.typeSize == 2 || v.typeSize == 4) || v.lengthSize < 0 || v.lengthSize > 2)
        return false;
    auto it = m_vendors.find(v.id);
    if(it != m_vendors.end() && lower(it->second.name) != lower(v.name))
        return false;           // same id, different vendor
    auto byName = m_vendorByName.find(lower(v.name));
    if(byName != m_vendorByName.end() && byName->second != v.id)
        return false;
    m_vendors[v.id] = v;
    m_vendorByName[lower(v.name)] = v.id;
    return true;
}

bool EZVendorRegistry::registerAttribute(const EZVSADef &a)
{
    const EZVendorDef *v = findVendor(a.vendorId);
    if(!v || a.name.empty())
        return false;
    // the type must fit the vendor's type field
    if(v->typeSize < 4 && a.type >= (1u << (8 * v->typeSize)))
        return false;
    auto byName = m_attrByName.find(lower(a.name));
    if(byName != m_attrByName.end() && byName->second != std::make_pair(a.vendorId, a.type))
        return false;
    m_attrs[{a.vendorId, a.type}] = a;
    m_attrByName[lower(a.name)] = {a.vendorId, a.type};
    return true;
}

bool EZVendorRegistry::addValue(const std::string &attrName, const std::string &valueName, uint32_t value)
{
    auto it = m_attrByName.find(lower(attrName));
    if(it == m_attrByName.end())
        return false;
    m_attrs[it->second].values[valueName] = value;
    return true;
}

const EZVendorDef *EZVendorRegistry::findVendor(uint32_t id) const
{
    auto it = m_vendors.find(id);
    return it == m_vendors.end() ? nullptr : &it->second;
}

const EZVendorDef *EZVendorRegistry::findVendor(const std::string &name) const
{
    auto it = m_vendorByName.find(lower(name));
    return it == m_vendorByName.end() ? nullptr : findVendor(it->second);
}

const EZVSADef *EZVendorRegistry::findAttribute(uint32_t vendorId, uint32_t type) const
{
    auto it = m_attrs.find({vendorId, type});
    return it == m_attrs.end() ? nullptr : &it->second;
}

const EZVSADef *EZVendorRegistry::findAttribute(const std::string &name) const
{
    auto it = m_attrByName.find(lower(name));
    return it == m_attrByName.end() ? nullptr : findAttribute(it->second.first, it->second.second);
}

// ---------------------------------------------------------------------------------------------
// dictionary parser
static bool parseType(const std::string &t, EZVSAType &out)
{
    const std::string s = lower(t);
    if(s == "string" || s == "text")                    out = EZVSAType::String;
    else if(s == "octets" || s == "abinary")            out = EZVSAType::Octets;
    else if(s == "integer" || s == "uint32")            out = EZVSAType::Integer;
    else if(s == "short" || s == "uint16")              out = EZVSAType::Short;
    else if(s == "byte" || s == "uint8")                out = EZVSAType::Byte;
    else if(s == "ipaddr" || s == "ipv4addr")           out = EZVSAType::IPv4;
    else if(s == "ipv6addr")                            out = EZVSAType::IPv6;
    else if(s == "date")                                out = EZVSAType::Date;
    else return false;
    return true;
}

static bool parseNumber(const std::string &s, uint32_t &out)
{
    if(s.empty())
        return false;
    char *end = nullptr;
    unsigned long long v = strtoull(s.c_str(), &end, 0);
    if(*end != 0 || v > 0xffffffffULL)
        return false;
    out = (uint32_t)v;
    return true;
}

size_t EZVendorRegistry::loadDictionary(const std::string &text, std::string *error)
{
    size_t count = 0;
    uint32_t current = 0;           // vendor of the open BEGIN-VENDOR block
    std::istringstream in(text);
    std::string line;
    int lineNo = 0;

    auto fail = [&](const std::string &msg){
        if(error)
            *error = "line " + std::to_string(lineNo) + ": " + msg;
    };

    while(std::getline(in, line)){
        lineNo++;
        size_t hash = line.find('#');
        if(hash != std::string::npos)
            line.erase(hash);
        std::istringstream ls(line);
        std::vector<std::string> w;
        std::string tok;
        while(ls >> tok)
            w.push_back(tok);
        if(w.empty())
            continue;

        const std::string kw = w[0];
        if(kw == "VENDOR"){
            uint32_t id;
            if(w.size() < 3 || !parseNumber(w[2], id)){ fail("bad VENDOR"); return count; }
            EZVendorDef v;
            v.id = id; v.name = w[1];
            if(w.size() >= 4){
                // format=t,l
                size_t eq = w[3].find("format=");
                if(eq != 0){ fail("bad VENDOR format"); return count; }
                int t = 1, l = 1;
                if(sscanf(w[3].c_str() + 7, "%d,%d", &t, &l) < 1){ fail("bad VENDOR format"); return count; }
                v.typeSize = t; v.lengthSize = l;
            }
            if(!registerVendor(v)){ fail("cannot register vendor " + w[1]); return count; }
        }else if(kw == "BEGIN-VENDOR"){
            const EZVendorDef *v = w.size() >= 2 ? findVendor(w[1]) : nullptr;
            if(!v){ fail("unknown vendor in BEGIN-VENDOR"); return count; }
            current = v->id;
        }else if(kw == "END-VENDOR"){
            current = 0;
        }else if(kw == "ATTRIBUTE"){
            uint32_t type;
            EZVSAType vt;
            if(current == 0){ fail("ATTRIBUTE outside BEGIN-VENDOR"); return count; }
            if(w.size() < 4 || !parseNumber(w[2], type) || !parseType(w[3], vt)){ fail("bad ATTRIBUTE"); return count; }
            EZVSADef a;
            a.vendorId = current; a.type = type; a.name = w[1]; a.valueType = vt;
            if(!registerAttribute(a)){ fail("cannot register attribute " + w[1]); return count; }
            count++;
        }else if(kw == "VALUE"){
            uint32_t n;
            if(w.size() < 4 || !parseNumber(w[3], n) || !addValue(w[1], w[2], n)){ fail("bad VALUE"); return count; }
        }
        // anything else ($INCLUDE, ...) is ignored
    }
    return count;
}

size_t EZVendorRegistry::loadDictionaryFile(const std::string &path, std::string *error)
{
    std::ifstream f(path);
    if(!f){
        if(error)
            *error = "cannot open " + path;
        return 0;
    }
    std::stringstream ss;
    ss << f.rdbuf();
    return loadDictionary(ss.str(), error);
}

// ---------------------------------------------------------------------------------------------
// encoding
static void putBE(std::string &out, uint64_t v, int bytes)
{
    for(int i = bytes - 1; i >= 0; i--)
        out.push_back((char)((v >> (8 * i)) & 0xff));
}

bool EZVendorRegistry::buildValue(uint32_t vendorId, uint32_t type, const void *data, size_t len, std::string &value) const
{
    if(!data && len > 0)
        return false;
    const EZVendorDef *v = findVendor(vendorId);
    const int ts = v ? v->typeSize : 1;
    const int ls = v ? v->lengthSize : 1;

    if(ts < 4 && type >= (1u << (8 * ts)))
        return false;
    const size_t sub = (size_t)ts + (size_t)ls + len;
    if(ls == 1 && sub > 255)
        return false;
    if(ls == 2 && sub > 65535)
        return false;
    if(4 + sub > D_ATTR_MAX_VALUE_LENGTH)
        return false;

    value.clear();
    putBE(value, vendorId, 4);
    putBE(value, type, ts);
    if(ls > 0)
        putBE(value, sub, ls);
    value.append((const char*)data, len);
    return true;
}

static bool encodeText(const EZVSADef &a, const std::string &text, std::string &payload)
{
    payload.clear();
    switch(a.valueType){
    case EZVSAType::String:
        payload = text;
        return true;
    case EZVSAType::Octets: {
        if(text.size() >= 2 && text[0] == '0' && (text[1] == 'x' || text[1] == 'X')){
            if((text.size() - 2) % 2)
                return false;
            for(size_t i = 2; i < text.size(); i += 2){
                if(!isxdigit((unsigned char)text[i]) || !isxdigit((unsigned char)text[i + 1]))
                    return false;
                payload.push_back((char)strtoul(text.substr(i, 2).c_str(), nullptr, 16));
            }
        }else
            payload = text;
        return true; }
    case EZVSAType::IPv4: {
        struct in_addr ip;
        if(inet_pton(AF_INET, text.c_str(), &ip) != 1)
            return false;
        payload.assign((const char*)&ip, 4);
        return true; }
    case EZVSAType::IPv6: {
        struct in6_addr ip;
        if(inet_pton(AF_INET6, text.c_str(), &ip) != 1)
            return false;
        payload.assign((const char*)&ip, 16);
        return true; }
    case EZVSAType::Integer:
    case EZVSAType::Short:
    case EZVSAType::Byte:
    case EZVSAType::Date: {
        uint32_t n;
        auto sym = a.values.find(text);
        if(sym != a.values.end())
            n = sym->second;
        else if(!parseNumber(text, n))
            return false;
        const int size = a.valueType == EZVSAType::Short ? 2 : a.valueType == EZVSAType::Byte ? 1 : 4;
        if(size < 4 && n >= (1u << (8 * size)))
            return false;
        putBE(payload, n, size);
        return true; }
    }
    return false;
}

bool EZVendorRegistry::buildValue(const std::string &attrName, const std::string &text, std::string &value) const
{
    const EZVSADef *a = findAttribute(attrName);
    std::string payload;
    return a && encodeText(*a, text, payload) && buildValue(a->vendorId, a->type, payload.data(), payload.size(), value);
}

bool EZVendorRegistry::buildValue(const std::string &attrName, uint32_t number, std::string &value) const
{
    const EZVSADef *a = findAttribute(attrName);
    if(!a)
        return false;
    switch(a->valueType){
    case EZVSAType::Integer: case EZVSAType::Short: case EZVSAType::Byte: case EZVSAType::Date:
        return buildValue(attrName, std::to_string(number), value);
    default:
        return false;
    }
}

// ---------------------------------------------------------------------------------------------
// decoding
EZVSAValue EZVendorRegistry::describe(uint32_t vendorId, uint32_t type, const std::string &raw) const
{
    EZVSAValue v;
    v.vendorId = vendorId;
    v.type = type;
    v.raw = raw;
    if(const EZVendorDef *vd = findVendor(vendorId))
        v.vendorName = vd->name;

    const EZVSADef *a = findAttribute(vendorId, type);
    if(!a){
        v.text = "0x";
        static const char hex[] = "0123456789abcdef";
        for(unsigned char c : raw){ v.text.push_back(hex[c >> 4]); v.text.push_back(hex[c & 15]); }
        return v;
    }
    v.name = a->name;
    v.valueType = a->valueType;

    auto num = [&](size_t size){
        uint32_t n = 0;
        for(size_t i = 0; i < size; i++)
            n = (n << 8) | (unsigned char)raw[i];
        return n;
    };

    switch(a->valueType){
    case EZVSAType::String:
        v.text = raw;
        break;
    case EZVSAType::Octets: {
        v.text = "0x";
        static const char hex[] = "0123456789abcdef";
        for(unsigned char c : raw){ v.text.push_back(hex[c >> 4]); v.text.push_back(hex[c & 15]); }
        break; }
    case EZVSAType::IPv4:
        if(raw.size() == 4){
            char buf[INET_ADDRSTRLEN];
            if(inet_ntop(AF_INET, raw.data(), buf, sizeof(buf)))
                v.text = buf;
        }
        break;
    case EZVSAType::IPv6:
        if(raw.size() == 16){
            char buf[INET6_ADDRSTRLEN];
            if(inet_ntop(AF_INET6, raw.data(), buf, sizeof(buf)))
                v.text = buf;
        }
        break;
    case EZVSAType::Integer: case EZVSAType::Date:
        if(raw.size() == 4){ v.number = num(4); v.text = std::to_string(v.number); }
        break;
    case EZVSAType::Short:
        if(raw.size() == 2){ v.number = num(2); v.text = std::to_string(v.number); }
        break;
    case EZVSAType::Byte:
        if(raw.size() == 1){ v.number = num(1); v.text = std::to_string(v.number); }
        break;
    }
    // symbolic name of an integer value
    if(!a->values.empty() && !v.text.empty()){
        for(const auto &kv : a->values)
            if(kv.second == v.number){ v.text = kv.first; break; }
    }
    return v;
}

std::vector<EZVSAValue> EZVendorRegistry::decode(RadiusPacket &pck) const
{
    std::vector<EZVSAValue> out;
    for(const AttrValue &av : pck.getAttributes(VENDOR_SPECIFIC)){
        if(!av.valid)
            continue;
        const EZVendorDef *vd = findVendor(av.intValue);
        const size_t ts = vd ? (size_t)vd->typeSize : 1;
        const size_t ls = vd ? (size_t)vd->lengthSize : 1;
        const std::string &s = av.strValue;
        size_t pos = 0;
        while(pos + ts + ls <= s.size()){
            uint32_t type = 0;
            for(size_t i = 0; i < ts; i++)
                type = (type << 8) | (unsigned char)s[pos + i];
            size_t total;
            if(ls == 0)
                total = s.size() - pos;                 // no length field: one sub-attribute up to the end
            else{
                total = 0;
                for(size_t i = 0; i < ls; i++)
                    total = (total << 8) | (unsigned char)s[pos + ts + i];
            }
            if(total < ts + ls || pos + total > s.size())
                break;
            out.push_back(describe(av.intValue, type, s.substr(pos + ts + ls, total - ts - ls)));
            pos += total;
        }
    }
    return out;
}

bool EZVendorRegistry::find(RadiusPacket &pck, const std::string &attrName, EZVSAValue &out) const
{
    const EZVSADef *a = findAttribute(attrName);
    if(!a)
        return false;
    for(const EZVSAValue &v : decode(pck)){
        if(v.vendorId == a->vendorId && v.type == a->type){
            out = v;
            return true;
        }
    }
    return false;
}

bool EZVendorRegistry::findRaw(RadiusPacket &pck, uint32_t vendorId, uint32_t type, std::string &out) const
{
    for(const EZVSAValue &v : decode(pck)){
        if(v.vendorId == vendorId && v.type == type){
            out = v.raw;
            return true;
        }
    }
    return false;
}
