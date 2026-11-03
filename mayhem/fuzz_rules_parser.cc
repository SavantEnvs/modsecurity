// Parses fuzzer bytes as a SecLang configuration (SecRule/SecAction/... directives).
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <strings.h>
#include <string>

#include "modsecurity/modsecurity.h"
#include "modsecurity/rules_set.h"

static modsecurity::ModSecurity *g_ms;

static void DiscardLog(void *, const void *) {}

extern "C" int LLVMFuzzerInitialize(int *, char ***) {
  g_ms = new modsecurity::ModSecurity();
  g_ms->setServerLogCb(DiscardLog, modsecurity::RuleMessageLogProperty);
  return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  std::string conf(reinterpret_cast<const char *>(data), size);
  // `Include` would read whatever path the input names (devices, FIFOs); that is a file-system
  // exercise, not parser coverage.
  for (size_t i = 0; i + 7 <= conf.size(); i++) {
    if (strncasecmp(conf.c_str() + i, "include", 7) == 0) return -1;
  }
  modsecurity::RulesSet rules;
  rules.load(conf.c_str());
  return 0;
}
