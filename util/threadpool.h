#ifndef UTIL_THREADPOOL_H_
#define UTIL_THREADPOOL_H_

#include <condition_variable>
#include <functional>
#include <mutex>
#include <queue>
#include <vector>

#include "util/thread.h"

namespace sling {

// Thread pool for executing tasks using a pool of worker threads.
class ThreadPool {
 public:
  // Task that can be scheduled for execution.
  typedef std::function<void()> Task;

  // Initialize thread pool.
  ThreadPool(int num_workers, int queue_size);

  // Wait for all workers to complete.
  ~ThreadPool();

  // Start worker threads.
  void StartWorkers();

  // Schedule task to be executed by worker.
  void Schedule(Task &&task);

 private:
  // Fetch next task. Returns false when all tasks have been completed.
  bool FetchTask(Task *task);

  // Shut down workers. This waits until all tasks have been completed.
  void Shutdown();

  // Worker threads.
  int num_workers_;
  std::vector<ClosureThread> workers_;

  // Task queue.
  int queue_size_;
  std::queue<Task> tasks_;

  // Are we done with adding new tasks.
  bool done_ = false;

  // Mutex for serializing access to task queue.
  std::mutex mu_;

  // Signal to notify about new tasks in queue.
  std::condition_variable nonempty_;

  // Signal to notify about available space in queue.
  std::condition_variable nonfull_;
};

}  // namespace sling

#endif  // UTIL_THREADPOOL_H_

