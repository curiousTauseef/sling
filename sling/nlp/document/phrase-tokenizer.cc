// Copyright 2017 Google Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "sling/nlp/document/phrase-tokenizer.h"

#include <string>
#include <vector>

#include "sling/base/types.h"
#include "sling/nlp/document/fingerprinter.h"
#include "sling/nlp/document/text-tokenizer.h"
#include "sling/string/text.h"

namespace sling {
namespace nlp {

PhraseTokenizer::PhraseTokenizer() {
  tokenizer_.InitLDC();
}

void PhraseTokenizer::Tokenize(Text text, std::vector<string> *tokens) const {
  tokens->clear();
  tokenizer_.Tokenize(text,
    [tokens](const Tokenizer::Token &t) {
      tokens->push_back(t.text);
    }
  );
}

uint64 PhraseTokenizer::TokenFingerprints(Text text,
                                          std::vector<uint64> *tokens) const {
  tokens->clear();
  uint64 fp = 1;
  tokenizer_.Tokenize(text,
    [tokens, &fp](const Tokenizer::Token &t) {
      uint64 word_fp = Fingerprinter::Fingerprint(t.text);
      tokens->push_back(word_fp);
      if (word_fp != 1) fp = Fingerprinter::Mix(word_fp, fp);
    }
  );
  return fp;
}

uint64 PhraseTokenizer::Fingerprint(Text text) const {
  uint64 fp = 1;
  tokenizer_.Tokenize(text,
    [&fp](const Tokenizer::Token &t) {
      fp = Fingerprinter::Fingerprint(t.text, fp);
    }
  );
  return fp;
}

}  // namespace nlp
}  // namespace sling

