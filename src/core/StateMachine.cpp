#include "whitedns/core/StateMachine.h"

namespace whitedns {
namespace core {

const char* finding_state_name(FindingState s) {
    switch (s) {
        case FindingState::New: return "NEW";
        case FindingState::Observing: return "OBSERVING";
        case FindingState::Suspected: return "SUSPECTED";
        case FindingState::Confirmed: return "CONFIRMED";
        case FindingState::Inconclusive: return "INCONCLUSIVE";
        case FindingState::Resolved: return "RESOLVED";
        case FindingState::Suppressed: return "SUPPRESSED";
    }
    return "UNKNOWN";
}

const char* exec_status_name(ExecStatus s) {
    switch (s) {
        case ExecStatus::Success: return "SUCCESS";
        case ExecStatus::Partial: return "PARTIAL";
        case ExecStatus::Timeout: return "TIMEOUT";
        case ExecStatus::NetworkError: return "NETWORK_ERROR";
        case ExecStatus::ParseError: return "PARSE_ERROR";
        case ExecStatus::ValidationError: return "VALIDATION_ERROR";
        case ExecStatus::Cancelled: return "CANCELLED";
        case ExecStatus::Unsupported: return "UNSUPPORTED";
    }
    return "UNKNOWN";
}

FindingState next_poison_state(FindingState current, bool gd, bool gr, bool ga) {
    if (current == FindingState::Suppressed || current == FindingState::Resolved) return current;
    if (gd && gr && ga) return FindingState::Confirmed;
    if (gd || gr || ga) return FindingState::Suspected;
    return FindingState::Inconclusive;
}

} // namespace core
} // namespace whitedns
