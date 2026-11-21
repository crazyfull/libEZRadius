/*
 * libEZRadius
 *
 * Copyright (c) 2023-2026 Mojtaba Kahvand.
 * All rights reserved.
 *
 * Licensed under the GNU Lesser General Public License v2.1.
 * See LICENSE for details.
 */

#ifndef EZVENDORDICT_H
#define EZVENDORDICT_H
// Vendor-Specific Attribute (VSA) dictionary: vendors and their attributes are data, not code.
//
// - Built-in vendor modules (src/vendors/): MikroTik, Cisco, Juniper, Huawei, Microsoft.
// - A new vendor needs no change in the library core: load a FreeRADIUS-style dictionary at run time
//   (loadDictionary / loadDictionaryFile) or register definitions from code.
// - Attributes are then used by name:   response.AddVendorAttribute("Mikrotik-Rate-Limit", "10M/10M");
//   and read by name:                   EZVendorRegistry::instance().find(request, "Mikrotik-Group", value);
//
// The registry is a process wide singleton. Fill it at start-up (before the reactors run); it is read only
// afterwards. It is not thread safe for concurrent modification.
#include "RadiusPacket.h"
#include <cstdint>
#include <map>
#include <string>
#include <vector>

enum class EZVSAType {
    String,         // text / binary string
    Octets,         // binary; text form is "0x<hex>"
    Integer,        // 32 bit unsigned
    Short,          // 16 bit unsigned
    Byte,           // 8 bit unsigned
    IPv4,           // dotted address
    IPv6,           // IPv6 address
    Date            // 32 bit unix time
};

struct EZVendorDef {
    uint32_t id = 0;
    std::string name;
    // sub-attribute header (FreeRADIUS "format=t,l"): type size 1/2/4 bytes, length size 0/1/2 bytes. Default 1,1.
    int typeSize = 1;
    int lengthSize = 1;
};

struct EZVSADef {
    uint32_t vendorId = 0;
    uint32_t type = 0;
    std::string name;
    EZVSAType valueType = EZVSAType::String;
    std::map<std::string, uint32_t> values;     // symbolic values of an integer attribute (VALUE lines)
};

// a decoded vendor attribute
struct EZVSAValue {
    uint32_t vendorId = 0;
    uint32_t type = 0;
    std::string vendorName;         // empty when the vendor is not in the dictionary
    std::string name;               // empty when the attribute is not in the dictionary
    EZVSAType valueType = EZVSAType::Octets;
    std::string raw;                // the value as sent
    std::string text;               // printable form (according to valueType)
    uint32_t number = 0;            // numeric value for Integer / Short / Byte / Date
};

class EZVendorRegistry
{
    std::map<uint32_t, EZVendorDef> m_vendors;
    std::map<std::string, uint32_t> m_vendorByName;                 // lower case name
    std::map<std::pair<uint32_t, uint32_t>, EZVSADef> m_attrs;      // (vendor, type)
    std::map<std::string, std::pair<uint32_t, uint32_t>> m_attrByName;

    EZVendorRegistry();

public:
    // registry with the built-in vendor modules loaded
    static EZVendorRegistry &instance();
    // empty registry (tests, isolated use)
    static EZVendorRegistry empty();

    bool registerVendor(const EZVendorDef &vendor);
    bool registerAttribute(const EZVSADef &attr);       // the vendor must be registered
    bool addValue(const std::string &attrName, const std::string &valueName, uint32_t value);

    // FreeRADIUS dictionary syntax (subset): VENDOR, BEGIN-VENDOR / END-VENDOR, ATTRIBUTE, VALUE, comments (#).
    //   VENDOR Mikrotik 14988 [format=1,1]
    //   BEGIN-VENDOR Mikrotik
    //   ATTRIBUTE Mikrotik-Rate-Limit 8 string
    //   END-VENDOR Mikrotik
    // Returns the number of attributes added; on a syntax error returns what was loaded and sets *error.
    size_t loadDictionary(const std::string &text, std::string *error = nullptr);
    size_t loadDictionaryFile(const std::string &path, std::string *error = nullptr);

    const EZVendorDef *findVendor(uint32_t id) const;
    const EZVendorDef *findVendor(const std::string &name) const;
    const EZVSADef *findAttribute(uint32_t vendorId, uint32_t type) const;
    const EZVSADef *findAttribute(const std::string &name) const;
    size_t vendorCount() const { return m_vendors.size(); }
    size_t attributeCount() const { return m_attrs.size(); }

    // ---- encoding ----
    // full value of a Vendor-Specific attribute (Vendor-Id + sub-attribute) using the vendor's header format
    bool buildValue(uint32_t vendorId, uint32_t type, const void *data, size_t len, std::string &value) const;
    // by dictionary name; text is converted according to the attribute type (numbers, addresses, "0x.." octets,
    // symbolic VALUE names for integers). false: unknown attribute or invalid text
    bool buildValue(const std::string &attrName, const std::string &text, std::string &value) const;
    bool buildValue(const std::string &attrName, uint32_t number, std::string &value) const;

    // ---- decoding ----
    // all vendor attributes of a packet (unknown vendors / attributes are returned raw)
    std::vector<EZVSAValue> decode(RadiusPacket &pck) const;
    // first attribute with that dictionary name
    bool find(RadiusPacket &pck, const std::string &attrName, EZVSAValue &out) const;
    // first attribute of (vendorId, type): raw bytes
    bool findRaw(RadiusPacket &pck, uint32_t vendorId, uint32_t type, std::string &out) const;
    EZVSAValue describe(uint32_t vendorId, uint32_t type, const std::string &raw) const;
};

// Built-in vendor dictionaries (src/vendors/*.cpp); each returns FreeRADIUS-style dictionary text.
const char *EZVendorDictionaryMikroTik();
const char *EZVendorDictionaryCisco();
const char *EZVendorDictionaryJuniper();
const char *EZVendorDictionaryHuawei();
const char *EZVendorDictionaryMicrosoft();

#endif // EZVENDORDICT_H
