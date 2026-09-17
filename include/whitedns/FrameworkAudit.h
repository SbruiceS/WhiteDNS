#ifndef WHITEDNS_FRAMEWORK_AUDIT_H
#define WHITEDNS_FRAMEWORK_AUDIT_H

#include "whitedns/Analyzer.h"

#include <string>
#include <vector>

namespace whitedns {

struct FrameworkFinding {
    std::string finding_id;
    std::string title;
    std::string status;       // pass, warning, fail, info, error
    std::string severity;     // low, medium, high, critical, info
    std::string message;
    std::string sans_class;
    std::string mitre_id;
    std::string mitre_tactic;
    std::string rfc_ref;
    std::string iana_ref;
    std::string isaca_control;
    std::string change_required;
    Json::Value evidence;
};

struct FrameworkAuditReport {
    std::string domain;
    std::string schema = "whitedns.framework.v1";
    int fault_score = 0;
    std::string posture;      // resilient, degraded, exposed, unknown
    std::vector<FrameworkFinding> findings;
    std::vector<DnsResponse> queries;
};

FrameworkAuditReport run_framework_audit(const std::string& domain,
                                         const std::vector<std::string>& resolvers);

Json::Value framework_audit_to_json(const FrameworkAuditReport& report);
Json::Value framework_workpaper_to_json(const FrameworkAuditReport& report);
void print_framework_audit(const FrameworkAuditReport& report);

} // namespace whitedns

#endif
