// Instantiates a SecLang operator (@rx, @pm, @detectSQLi, ...) with a fuzzer-chosen parameter and
// evaluates it against a fuzzer-chosen value, as the rule engine does.
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>

#include <fuzzer/FuzzedDataProvider.h>

#include "modsecurity/modsecurity.h"
#include "modsecurity/rule_message.h"
#include "modsecurity/rule_with_actions.h"
#include "modsecurity/rules_set.h"
#include "modsecurity/transaction.h"
#include "src/actions/capture.h"
#include "src/operators/operator.h"

using modsecurity::operators::Operator;

// File-reading, network and database operators are left out: they need external resources.
static const char *const kNames[] = {
    "beginsWith", "contains", "containsWord", "detectSQLi", "detectXSS",
    "endsWith", "eq", "ge", "gt", "le", "lt", "ipMatch", "noMatch", "pm",
    "rsub", "rx", "rxGlobal", "streq", "strmatch", "unconditionalMatch",
    "validateByteRange", "validateUrlEncoding", "validateUtf8Encoding",
    "verifyCC", "verifyCPF", "verifySSN", "verifySVNR", "within",
};
static const size_t kCount = sizeof(kNames) / sizeof(kNames[0]);

static modsecurity::ModSecurity *g_ms;
static modsecurity::RulesSet *g_rules;

static void DiscardLog(void *, const void *) {}

extern "C" int LLVMFuzzerInitialize(int *, char ***) {
  g_ms = new modsecurity::ModSecurity();
  g_ms->setServerLogCb(DiscardLog, modsecurity::RuleMessageLogProperty);
  g_rules = new modsecurity::RulesSet();
  return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 2) return -1;
  FuzzedDataProvider fdp(data, size);
  const std::string name = kNames[fdp.ConsumeIntegralInRange<size_t>(0, kCount - 1)];
  const bool capture = fdp.ConsumeBool();
  const std::string param = fdp.ConsumeRandomLengthString(256);
  const std::string value = fdp.ConsumeRemainingBytesAsString();

  std::unique_ptr<Operator> op(Operator::instantiate(name, param));
  std::string error;
  if (!op->init("", &error)) return -1;

  modsecurity::Transaction transaction(g_ms, g_rules, nullptr);
  std::unique_ptr<modsecurity::Actions> actions;
  if (capture) {
    actions = std::make_unique<modsecurity::Actions>();
    actions->push_back(new modsecurity::actions::Capture("capture"));
  }
  modsecurity::RuleWithActions rule{actions.release(), nullptr, "fuzz.conf", -1};
  modsecurity::RuleMessage ruleMessage{rule, transaction};
  op->evaluate(&transaction, &rule, value, ruleMessage);
  return 0;
}
