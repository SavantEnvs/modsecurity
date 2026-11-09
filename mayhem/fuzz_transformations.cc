// Runs every SecLang transformation (t:...) over fuzzer bytes; the first byte picks which one.
#include <cstddef>
#include <cstdint>
#include <string>

#include "src/actions/transformations/transformation.h"

using modsecurity::actions::transformations::Transformation;

static const char *const kNames[] = {
    "t:base64Decode", "t:base64DecodeExt", "t:base64Encode", "t:cmd_line",
    "t:compress_whitespace", "t:cssDecode", "t:escapeSeqDecode", "t:hexDecode",
    "t:hexEncode", "t:htmlEntityDecode", "t:jsDecode", "t:length",
    "t:lowercase", "t:md5", "t:none", "t:normalisePath",
    "t:normalisePathWin", "t:parityEven7bit", "t:parityOdd7bit",
    "t:parityZero7bit", "t:removeComments", "t:removeCommentsChar",
    "t:removeNulls", "t:removeWhitespace", "t:replaceComments",
    "t:replaceNulls", "t:sha1", "t:sqlHexDecode", "t:trim", "t:trimLeft",
    "t:trimRight", "t:uppercase", "t:urlDecode", "t:urlDecodeUni",
    "t:urlEncode", "t:utf8toUnicode",
};
static const size_t kCount = sizeof(kNames) / sizeof(kNames[0]);

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 1) return -1;
  Transformation *t = Transformation::instantiate(kNames[data[0] % kCount]);
  std::string value(reinterpret_cast<const char *>(data + 1), size - 1);
  t->transform(value, nullptr);
  delete t;
  return 0;
}
