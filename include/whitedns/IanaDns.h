#ifndef WHITEDNS_IANA_DNS_H
#define WHITEDNS_IANA_DNS_H

#include "whitedns/DnsTypes.h"

#include <string>

namespace whitedns {

// IANA DNS Parameters (https://www.iana.org/assignments/dns-parameters)
// plus RFC 1034/1035 architecture names used by WhiteDNS audit output.

inline const char* iana_class_name(uint16_t cls) {
    switch (cls) {
        case 1: return "IN";
        case 3: return "CH";
        case 4: return "HS";
        case 254: return "NONE";
        case 255: return "ANY";
        default: return "CLASS-UNASSIGNED";
    }
}

inline const char* iana_opcode_name(uint16_t opcode) {
    switch (opcode) {
        case 0: return "QUERY";
        case 1: return "IQUERY";
        case 2: return "STATUS";
        case 4: return "NOTIFY";
        case 5: return "UPDATE";
        case 6: return "DSO";
        default: return "OPCODE-UNASSIGNED";
    }
}

inline const char* iana_rcode_name(uint16_t rcode) {
    switch (rcode) {
        case 0: return "NOERROR";
        case 1: return "FORMERR";
        case 2: return "SERVFAIL";
        case 3: return "NXDOMAIN";
        case 4: return "NOTIMP";
        case 5: return "REFUSED";
        case 6: return "YXDOMAIN";
        case 7: return "YXRRSET";
        case 8: return "NXRRSET";
        case 9: return "NOTAUTH";
        case 10: return "NOTZONE";
        case 16: return "BADVERS";
        default: return "RCODE-OTHER";
    }
}

inline const char* rfc_for_rrtype(uint16_t type) {
    switch (type) {
        case DNS_TYPE_A: return "RFC1035";
        case DNS_TYPE_NS: return "RFC1035";
        case DNS_TYPE_CNAME: return "RFC1035";
        case DNS_TYPE_SOA: return "RFC1035";
        case DNS_TYPE_PTR: return "RFC1035";
        case DNS_TYPE_MX: return "RFC1035";
        case DNS_TYPE_TXT: return "RFC1035";
        case DNS_TYPE_AAAA: return "RFC3596";
        case DNS_TYPE_SRV: return "RFC2782";
        case DNS_TYPE_DS: return "RFC4034";
        case DNS_TYPE_RRSIG: return "RFC4034";
        case DNS_TYPE_DNSKEY: return "RFC4034";
        case DNS_TYPE_NSEC: return "RFC4034";
        case DNS_TYPE_NSEC3: return "RFC5155";
        case DNS_TYPE_TLSA: return "RFC6698";
        case DNS_TYPE_CAA: return "RFC8659";
        case DNS_TYPE_AXFR: return "RFC5936";
        case DNS_TYPE_ANY: return "RFC8482";
        case DNS_TYPE_SPF: return "RFC7208";
        default: return "IANA-dns-parameters";
    }
}

inline const char* architecture_role(uint16_t type) {
    switch (type) {
        case DNS_TYPE_SOA: return "zone-authority";
        case DNS_TYPE_NS: return "delegation";
        case DNS_TYPE_A:
        case DNS_TYPE_AAAA: return "addressing";
        case DNS_TYPE_CNAME:
        case DNS_TYPE_DNAME: return "alias";
        case DNS_TYPE_MX: return "mail-exchange";
        case DNS_TYPE_TXT: return "policy-or-payload";
        case DNS_TYPE_DNSKEY:
        case DNS_TYPE_DS:
        case DNS_TYPE_RRSIG:
        case DNS_TYPE_NSEC:
        case DNS_TYPE_NSEC3: return "dnssec-integrity";
        case DNS_TYPE_CAA:
        case DNS_TYPE_TLSA: return "certificate-binding";
        case DNS_TYPE_AXFR: return "zone-replication";
        default: return "other";
    }
}

} // namespace whitedns

#endif
