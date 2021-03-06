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

#ifndef SLING_UTIL_MUTEX_H_
#define SLING_UTIL_MUTEX_H_

#include <mutex>

namespace sling {

// Basic mutex wrapper around a std::mutex.
class Mutex : public std::mutex {
 public:
  // Wait for lock and acquire it.
  void Lock() { lock(); }

  // Release mutex.
  void Unlock() { unlock(); }

  // Try to acquire mutex.
  bool TryLock() { return try_lock(); }
};

// Lock guard.
class MutexLock {
 public:
  // Constructor that acquires mutex.
  explicit MutexLock(Mutex *lock) : lock_(lock) { lock_->Lock(); }

  // Destructor that releases mutex.
  ~MutexLock() { lock_->Unlock(); }

 private:
  // Lock for guard.
  Mutex *lock_;
};

}  // namespace sling

#endif  // SLING_UTIL_MUTEX_H_

