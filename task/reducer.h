#ifndef TASK_REDUCER_H_
#define TASK_REDUCER_H_

#include <vector>

#include "base/slice.h"
#include "task/message.h"
#include "task/task.h"
#include "util/mutex.h"

namespace sling {
namespace task {

// Input to reducer with a key and all messages with that key.
class ReduceInput {
 public:
  ReduceInput(int shard, Slice key, const std::vector<Message *> &messages)
      : shard_(shard), key_(key), messages_(messages) {}

  // Shard number for messages.
  int shard() const { return shard_; }

  // Key for messages.
  Slice key() const { return key_; }

  // Messages for key.
  const std::vector<Message *> &messages() const { return messages_; }

 private:
  int shard_;
  Slice key_;
  const std::vector<Message *> &messages_;
};

// A reducer groups all consecutive messages with the same key together and
// calls the Reduce() method for each key in the input.
class Reducer : public Processor {
 public:
  ~Reducer() override;

  void Start(Task *task) override;
  void Receive(Channel *channel, Message *message) override;
  void Done(Task *task) override;

  // The Reduce() method is called for each key in the input with all the
  // messages for that key.
  virtual void Reduce(const ReduceInput &input) = 0;

  // Output message to output shard.
  void Output(int shard, Message *message);

 private:
  // Reduce messages for a shard.
  void ReduceShard(int shard);

  // Each shard collects messages from a sorted input channel.
  struct Shard {
    Shard() {}
    ~Shard() { clear(); }

    // Clear shard information.
    void clear() {
      for (Message *m : messages) delete m;
      messages.clear();
      key.clear();
    }

    // Current key for input channel.
    Slice key;

    // All collected messages with the current key.
    std::vector<Message *> messages;

    // Mutex for serializing access to shard.
    Mutex mu;
  };
  std::vector<Shard *> shards_;

  // Output channels.
  std::vector<Channel *> outputs_;
};

}  // namespace task
}  // namespace sling

#endif  // TASK_REDUCER_H_

