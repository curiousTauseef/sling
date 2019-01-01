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

// Generate template macro definition from infobox template.

#include <iostream>
#include <string>

#include "sling/base/flags.h"
#include "sling/base/init.h"
#include "sling/base/logging.h"
#include "sling/base/types.h"
#include "sling/file/file.h"
#include "sling/nlp/wiki/wiki-parser.h"
#include "sling/util/unicode.h"

DEFINE_string(input, "", "input file with wiki template");

using namespace sling;
using namespace sling::nlp;

int main(int argc, char *argv[]) {
  InitProgram(&argc, &argv);

  string wikitext;
  CHECK(File::ReadContents(FLAGS_input, &wikitext));

  WikiParser parser(wikitext.c_str());
  parser.Parse();

  for (const WikiParser::Node &templ : parser.nodes()) {
    if (templ.type != WikiParser::TEMPLATE) continue;
    std::cout << "\"" << templ.name() << "\": {\n";
    std::cout << "  type: \"infobox\"\n";
    std::cout << "  fields: {\n";

    int child = templ.first_child;
    while (child != -1) {
      const WikiParser::Node &n = parser.node(child);
      if (n.type == WikiParser::ARG) {
        std::cout << "    \"" << n.name();
        string id = UTF8::Lower(n.name().str());
        for (char &c : id) if (c == ' ') c = '_';
        std::cout << "\": /wp/info/" << id << "\n";
      }
      child = n.next_sibling;
    }

    std::cout << "  }\n";
    std::cout << "}\n";
  }

  return 0;
}

