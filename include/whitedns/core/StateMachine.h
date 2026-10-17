#ifndef WHITEDNS_CORE_STATEMACHINE_H
#define WHITEDNS_CORE_STATEMACHINE_H

#include <string>

namespace whitedns {
namespace core {

// Finding state. Separate from execution status.
enum class FindingState { New, Observing, Suspected, Confirmed, Inconclusive, Resolved, Suppressed };

// Execution status. Not a finding.
enum class ExecStatus { Success, Partial, Timeout, NetworkError, ParseError, ValidationError, Cancelled, Unsupported };

const char* finding_state_name(FindingState s);
const char* exec_status_name(ExecStatus s);

// Promote only when all three poison gates are true. Otherwise stay Suspected or Inconclusive.
FindingState next_poison_state(FindingState current, bool gd, bool gr, bool ga);

} // namespace core
} // namespace whitedns

#endif
