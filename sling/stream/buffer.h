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

#ifndef SLING_STREAM_BUFFER_H_
#define SLING_STREAM_BUFFER_H_

#include "sling/base/types.h"
#include "sling/stream/stream.h"

namespace sling {

// Memory buffer that owns a block of allocated memory. Data is consumed from
// the used portion of the buffer, and data is appended to the unused portion
// of the buffer.
//
//     +---------------------------------------------------------------+
//     |     consumed    |        used        |         unused         |
//     +---------------------------------------------------------------+
//     ^                 ^                     ^                        ^
//   floor             begin                  end                      ceil
//
//     <-- consumed() --><---- available() ---><----- remaining() ----->
//     <-------------------------- capacity() ------------------------->
//
class Buffer {
 public:
  ~Buffer() { free(floor_); }

  // Buffer capacity.
  size_t capacity() const { return ceil_ - floor_; }

  // Number of bytes consumed from buffer.
  size_t consumed() const { return begin_ - floor_; }

  // Number of bytes available in buffer.
  size_t available() const { return end_ - begin_; }

  // Number of bytes left in buffer.
  size_t remaining() const { return ceil_ - end_; }

  // Whether buffer is empty.
  bool empty() const { return begin_ == end_; }

  // Whether buffer is full.
  bool full() const { return end_ == ceil_; }

  // Clear buffer and allocate space.
  void Reset(size_t size);

  // Change buffer capacity keeping the used part.
  void Resize(size_t size);

  // Flush buffer by moving the used part to the beginning of the buffer.
  void Flush();

  // Make room in buffer.
  void Ensure(size_t size);

  // Clear buffer;
  void Clear();

  // Append data to buffer.
  char *Append(size_t size);
  void Append(const char *data, size_t size);
  void Append(const char *str) { if (str) Append(str, strlen(str)); }
  void Append(const string &str) { Append(str.data(), str.size()); }

  // Consume data from buffer.
  char *Consume(size_t size);

  // Buffer access.
  char *floor() const { return floor_; }
  char *ceil() const { return ceil_; }
  char *begin() const { return begin_; }
  char *end() const { return end_; }

 private:
  char *floor_ = nullptr;  // start of allocated memory
  char *ceil_ = nullptr;   // end of allocated memory
  char *begin_ = nullptr;  // beginning of used part of buffer
  char *end_ = nullptr;    // end of used part of buffer
};

// An InputStream for reading from a Buffer.
class BufferInputStream : public InputStream {
 public:
  BufferInputStream(Buffer *buffer);

  // InputStream interface.
  bool Next(const void **data, int *size) override;
  void BackUp(int count) override;
  bool Skip(int count) override;
  int64 ByteCount() const override;

 private:
  Buffer *buffer_;
};

// An OutputStream backed by a Buffer.
class BufferOutputStream : public OutputStream {
 public:
  BufferOutputStream(Buffer *buffer, int block_size = 4096);

  // OutputStream interface.
  bool Next(void **data, int *size) override;
  void BackUp(int count) override;
  int64 ByteCount() const override;

 private:
  Buffer *buffer_;
  int block_size_;
};

}  // namespace sling

#endif  // SLING_STREAM_BOUNDED_H_

