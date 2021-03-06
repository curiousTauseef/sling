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

#ifndef SLING_NLP_PARSER_PARSER_ACTION_H_
#define SLING_NLP_PARSER_PARSER_ACTION_H_

#include <string>

#include "sling/base/types.h"
#include "sling/frame/object.h"
#include "sling/frame/store.h"
#include "sling/util/fingerprint.h"

namespace sling {
namespace nlp {

// Parser action for transitioning from one parser state to another.
struct ParserAction {
  // Transition type.
  enum Type : uint8 {
    // Moves to the next input token. Only valid when not at the end of the
    // input buffer.
    SHIFT = 0,

    // Evokes frame of with type 'type' from the next 'length' tokens in the
    // input. The new frame will become the center of attention.
    EVOKE = 2,

    // Makes a new mention of an existing frame. This frame will become the new
    // center of attention.
    REFER = 3,

    // Adds slot to frame 'source' with name 'role' and value 'target'. The
    // source frame become the new center of attention.
    CONNECT = 4,

    // Adds slot to frame 'source' with name 'role' and value 'label' and moves
    // frame to the center of attention.
    ASSIGN = 5,

    // Delegate to another member (specified by 'delegate') of the cascade.
    CASCADE = 8,

    // Mark the current token as the beginning of a span.
    MARK = 9,
  };

  // Number of action types.
  static const int kNumActionTypes = MARK + 1;

  // Type of the action.
  Type type;

  // Transition parameters.
  // Length of the evoked frame for EVOKE and REFER.
  uint8 length;

  // Source frame index for CONNECT and ASSIGN.
  uint8 source;

  // Target frame index for CONNECT and REFER.
  uint8 target;

  // Role argument for CONNECT and ASSIGN.
  Handle role;

  // Frame type for EVOKE and value for ASSIGN.
  Handle label;

  // Index of the delegate for CASCADE actions.
  uint8 delegate;

  // Default constructor.
  ParserAction() { memset(this, 0, sizeof(struct ParserAction)); }

  // Copy constructor.
  ParserAction(const ParserAction &other) {
    memcpy(this, &other, sizeof(struct ParserAction));
  }

  // Other constructors.
  explicit ParserAction(Type t) : ParserAction() {
    type = t;
  }
  ParserAction(Type t, uint8 arg) : ParserAction() {
    type = t;
    if (t == CASCADE) {
      delegate = arg;
    } else {
      length = arg;
    }
  }

  // Check for equality with 'other'.
  inline bool operator ==(const ParserAction &other) const {
    return memcmp(this, &other, sizeof(struct ParserAction)) == 0;
  }

  // Check for inequality with 'other'.
  inline bool operator !=(const ParserAction &other) const {
    return !(*this == other);
  }

  // Return name of action type.
  static string TypeName(Type type);

  // Return the type name of the action.
  string TypeName() const {
    return TypeName(type);
  }

  // Return a human-readable representation of the action.
  string ToString(Store *store) const;

  // Return a MARK action.
  static ParserAction Mark() {
    return ParserAction(ParserAction::MARK);
  }

  // Return a SHIFT action.
  static ParserAction Shift() {
    return ParserAction(ParserAction::SHIFT);
  }

  // Return an EVOKE action.
  static ParserAction Evoke(uint8 length, Handle type) {
    ParserAction action(ParserAction::EVOKE, length);
    action.label = type;
    return action;
  }

  // Returns a REFER action.
  static ParserAction Refer(uint8 length, uint8 target) {
    ParserAction action(ParserAction::REFER, length);
    action.target = target;
    return action;
  }

  // Return a CONNECT action.
  static ParserAction Connect(int source, Handle role, int target) {
    ParserAction action(ParserAction::CONNECT);
    action.source = source;
    action.role = role;
    action.target = target;
    return action;
  }

  // Return an ASSIGN action.
  static ParserAction Assign(int frame, Handle role, Handle value) {
    ParserAction action(ParserAction::ASSIGN);
    action.source = frame;
    action.role = role;
    action.label = value;
    return action;
  }
} __attribute__ ((packed));

// Hasher for ParserAction.
struct ParserActionHash {
  size_t operator()(const ParserAction &action) const {
    return Fingerprint(
        reinterpret_cast<const char *>(&action),
        sizeof(struct ParserAction));
  }
};

}  // namespace nlp
}  // namespace sling

#endif  // SLING_NLP_PARSER_PARSER_ACTION_H_

