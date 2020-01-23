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

#include "sling/file/textmap.h"
#include "sling/nlp/kb/facts.h"
#include "sling/nlp/parser/action-table.h"
#include "sling/nlp/parser/multiclass-learner.h"
#include "sling/nlp/parser/parser-trainer.h"
#include "sling/nlp/parser/transition-generator.h"

namespace sling {
namespace nlp {

using namespace task;
using namespace myelin;

// Main delegate for coarse-grained shift/mark/other classification.
class MainDelegateLearner : public MultiClassDelegateLearner {
 public:
  MainDelegateLearner(int other) : MultiClassDelegateLearner("main") {
    // Set up coarse actions.
    actions_.Add(ParserAction(ParserAction::SHIFT));
    actions_.Add(ParserAction(ParserAction::MARK));
    actions_.Add(ParserAction(ParserAction::CASCADE, other));
  }
};

// Delegate for evoking frames.
class EvokeDelegateLearner : public MultiClassDelegateLearner {
 public:
  EvokeDelegateLearner(const ActionTable &actions) 
      : MultiClassDelegateLearner("evoke") {
    for (const ParserAction &action : actions.list()) {
      actions_.Add(action);
    }
  }
};

// Parser trainer for knowledge extraction.
class KnolexTrainer : public ParserTrainer {
 public:
   // Set up KNOLEX parser model.
   void Setup(task::Task *task) override {
    // Reset parser state between sentences.
    sentence_reset_ = true;

    // Read word vocabulary.
    TextMapInput vocabulary(task->GetInputFile("vocabulary"));
    string word;
    int64 count;
    while (vocabulary.Read(nullptr, &word, &count)) words_[word] += count;

    // Set up evokes for all entity types.
    ActionTable evokes;
    FactCatalog catalog;
    catalog.Init(&commons_);
    Taxonomy *types = catalog.CreateEntityTaxonomy();
    evokes.Add(ParserAction::Evoke(0, Handle::nil()));
    evokes.Add(ParserAction::Evoke(1, Handle::nil()));
    for (auto &it : types->typemap()) {
      Handle type = it.first;
      evokes.Add(ParserAction::Evoke(0, type));
      evokes.Add(ParserAction::Evoke(1, type));
    }
    delete types;

    // Set up delegates.
    delegates_.push_back(new MainDelegateLearner(1));
    delegates_.push_back(new EvokeDelegateLearner(evokes));
  }

  // Transition generator.
  void GenerateTransitions(const Document &document, int begin, int end,
                           std::vector<ParserAction> *transitions) override {
    transitions->clear();
    Generate(document, begin, end, [&](const ParserAction &action) {
      if (action.type != ParserAction::SHIFT &&
          action.type != ParserAction::MARK) {
        transitions->emplace_back(ParserAction::CASCADE, 1);
      }
      transitions->push_back(action);
    });
  }
};

REGISTER_TASK_PROCESSOR("knolex-trainer", KnolexTrainer);

}  // namespace nlp
}  // namespace sling
