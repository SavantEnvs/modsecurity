// Drives a whole transaction (URI, headers, request body, response headers/body, logging) through
// a fixed rule set that enables every body processor plus several operators/transformations.
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <string>

#include <fuzzer/FuzzedDataProvider.h>

#include "modsecurity/modsecurity.h"
#include "modsecurity/rules_set.h"
#include "modsecurity/transaction.h"

static const char kRules[] = R"RULES(
SecRuleEngine On
SecRequestBodyAccess On
SecResponseBodyAccess On
SecResponseBodyMimeType text/plain text/html application/json
SecRequestBodyLimit 262144
SecRequestBodyNoFilesLimit 131072
SecResponseBodyLimit 262144
SecArgumentSeparator &
SecCookieFormat 0
SecRule REQUEST_HEADERS:Content-Type "^(?:application(?:/soap\+|/)|text/)xml" "id:1,phase:1,t:none,t:lowercase,pass,nolog,ctl:requestBodyProcessor=XML"
SecRule REQUEST_HEADERS:Content-Type "^application/json" "id:2,phase:1,t:none,t:lowercase,pass,nolog,ctl:requestBodyProcessor=JSON"
SecRule REQBODY_ERROR "!@eq 0" "id:3,phase:2,t:none,log,pass,msg:'Failed to parse request body'"
SecRule MULTIPART_STRICT_ERROR "!@eq 0" "id:4,phase:2,t:none,log,pass,msg:'Multipart error'"
SecRule MULTIPART_UNMATCHED_BOUNDARY "!@eq 0" "id:5,phase:2,t:none,log,pass"
SecRule REQUEST_HEADERS:Content-Length "!@rx ^\d+$" "id:6,phase:1,t:none,log,pass"
SecRule ARGS|ARGS_NAMES|REQUEST_COOKIES|REQUEST_COOKIES_NAMES|REQUEST_HEADERS|FILES|FILES_NAMES|XML:/*|XML://@* "@detectSQLi" "id:10,phase:2,t:none,t:urlDecodeUni,t:htmlEntityDecode,t:lowercase,log,pass,capture"
SecRule ARGS|REQUEST_COOKIES|REQUEST_HEADERS|XML:/* "@detectXSS" "id:11,phase:2,t:none,t:urlDecodeUni,t:htmlEntityDecode,t:jsDecode,t:cssDecode,t:removeNulls,log,pass,capture"
SecRule ARGS|XML:/* "@rx (?i:<script|javascript:|on[a-z]+\s*=)" "id:12,phase:2,t:none,t:base64DecodeExt,t:compressWhitespace,t:normalisePath,t:removeComments,log,pass,capture,setvar:tx.score=+1"
SecRule ARGS "@pm select union insert drop update delete" "id:13,phase:2,t:none,t:lowercase,t:replaceComments,log,pass"
SecRule ARGS|REQUEST_BODY "@validateUtf8Encoding" "id:14,phase:2,t:none,log,pass"
SecRule ARGS "@validateUrlEncoding" "id:15,phase:2,t:none,log,pass"
SecRule REQUEST_URI|REQUEST_FILENAME|QUERY_STRING "@rx (?i:\.\./|etc/passwd)" "id:16,phase:1,t:none,t:urlDecodeUni,t:normalisePath,log,pass"
SecRule TX:score "@ge 1" "id:17,phase:2,t:none,log,pass,msg:'score %{tx.score}'"
SecRule FILES_TMP_CONTENT|REQUEST_BODY "@contains attack" "id:18,phase:2,t:none,t:hexEncode,t:length,log,pass"
SecRule ARGS_COMBINED_SIZE "@gt 1000" "id:19,phase:2,t:none,log,pass"
SecRule RESPONSE_STATUS "@rx ^5" "id:30,phase:3,t:none,log,pass"
SecRule RESPONSE_HEADERS:Content-Type "@rx ." "id:31,phase:3,t:none,log,pass"
SecRule RESPONSE_BODY "@rx (?i:error|exception|stack trace)" "id:32,phase:4,t:none,log,pass,capture"
)RULES";

static modsecurity::ModSecurity *g_ms;
static modsecurity::RulesSet *g_rules;

static void DiscardLog(void *, const void *) {}

extern "C" int LLVMFuzzerInitialize(int *, char ***) {
  g_ms = new modsecurity::ModSecurity();
  g_ms->setServerLogCb(DiscardLog, modsecurity::RuleMessageLogProperty);
  g_rules = new modsecurity::RulesSet();
  if (g_rules->load(kRules) < 0) {
    std::cerr << "fuzz_transaction: rule set failed to load: " << g_rules->getParserError() << "\n";
    abort();
  }
  return 0;
}

static const char *const kContentTypes[] = {
    "application/x-www-form-urlencoded",
    "multipart/form-data; boundary=----fuzzboundary",
    "application/json",
    "text/xml",
    "application/soap+xml",
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider fdp(data, size);
  static const char *const kMethods[] = {"GET", "POST", "PUT", "DELETE", "HEAD"};
  const std::string method = kMethods[fdp.ConsumeIntegralInRange<int>(0, 4)];
  const std::string uri = "/" + fdp.ConsumeRandomLengthString(200);
  const int ct = fdp.ConsumeIntegralInRange<int>(0, 5);
  const std::string content_type =
      ct < 5 ? kContentTypes[ct] : fdp.ConsumeRandomLengthString(64);
  const int extra_headers = fdp.ConsumeIntegralInRange<int>(0, 3);

  modsecurity::Transaction t(g_ms, g_rules, nullptr);
  t.processConnection("127.0.0.1", 40000, "127.0.0.1", 80);
  t.processURI(uri.c_str(), method.c_str(), "1.1");
  t.addRequestHeader("Host", "localhost");
  t.addRequestHeader("Content-Type", content_type);
  for (int i = 0; i < extra_headers; i++) {
    const std::string name = fdp.ConsumeRandomLengthString(24);
    const std::string value = fdp.ConsumeRandomLengthString(96);
    t.addRequestHeader(name, value);
  }
  t.processRequestHeaders();

  const std::string response_body = fdp.ConsumeRandomLengthString(512);
  const std::string request_body = fdp.ConsumeRemainingBytesAsString();
  t.appendRequestBody(reinterpret_cast<const unsigned char *>(request_body.data()),
                      request_body.size());
  t.processRequestBody();

  t.addResponseHeader("Content-Type", "text/html");
  t.processResponseHeaders(response_body.size() % 3 == 0 ? 500 : 200, "HTTP/1.1");
  t.appendResponseBody(reinterpret_cast<const unsigned char *>(response_body.data()),
                       response_body.size());
  t.processResponseBody();
  t.processLogging();
  return 0;
}
