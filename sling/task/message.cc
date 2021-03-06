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

#include "sling/task/message.h"

#include <string.h>

namespace sling {
namespace task {

Message::Buffer::Buffer(size_t n) {
  data_ = n == 0 ? nullptr : static_cast<char *>(malloc(n));
  size_ = n;
}

Message::Buffer::Buffer(Slice source) {
  if (source.empty()) {
    data_ = nullptr;
    size_ = 0;
  } else {
    size_ = source.size();
    data_ = static_cast<char *>(malloc(size_));
    memcpy(data_, source.data(), size_);
  }
}

}  // namespace task
}  // namespace sling

