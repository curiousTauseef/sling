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

#include "sling/web/web-archive.h"

#include "sling/base/logging.h"
#include "sling/stream/bounded.h"
#include "sling/string/numbers.h"

namespace sling {

bool WARCInput::Next() {
  // Clear previous block.
  if (content_ != nullptr) {
    // Make sure that all the content has been processed.
    int read = content_->ByteCount();
    if (read < content_length_) content_->Skip(content_length_ - read);
    delete content_;
    content_ = nullptr;
  }

  // Read next WARC header.
  if (!ParseHeader()) return false;

  // Set up content stream for reading content of data block.
  content_ = new BoundedInputStream(stream_, content_length_);
  return true;
}

bool WARCInput::ParseHeader() {
  // Clear previous headers.
  headers_.Clear();

  // Read next WARC header.
  Input input(stream_);
  if (!headers_.Parse(&input)) return false;
  CHECK_EQ(headers_.from(), "WARC/1.0") << "Invalid WARC record";
  uri_ = headers_.Get("WARC-Target-URI");
  id_ = headers_.Get("WARC-Record-ID");
  type_ = headers_.Get("WARC-Type");
  date_ = headers_.Get("WARC-Date");
  content_type_ = headers_.Get("Content-Type");
  Text length = headers_.Get("Content-Length");
  CHECK(!length.empty()) << "Content-Length missing in WARC header";
  CHECK(safe_strto64(length.data(), length.size(), &content_length_));
  return true;
}

}  // namespace sling

