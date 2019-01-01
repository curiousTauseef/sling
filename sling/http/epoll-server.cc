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

#include "sling/http/http-server.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>
#include <time.h>
#include <atomic>

#include "sling/string/numbers.h"
#include "sling/util/thread.h"

namespace sling {

class EPollHTTPServer;

// Return system error.
Status Error(const char *context) {
  return Status(errno, context, strerror(errno));
}

// HTTP connection for epoll-based HTTP server.
class EPollHTTPConnection : public HTTPConnection {
 public:
  // Initialize new HTTP connection on socket.
  EPollHTTPConnection(HTTPServer *server, int sock)
      : HTTPConnection(server), sock_(sock) {
    last_ = time(0);
  }

  ~EPollHTTPConnection() override {
    // Close client connection.
    close(sock_);
  }

 protected:
  // Receive data from socket.
  Status Recv(HTTPBuffer *buffer, bool *done) override {
    *done = false;
    int rc = recv(sock_, buffer->end, buffer->remaining(), 0);
    if (rc <= 0) {
      *done = true;
      if (rc == 0) {
        // Connection closed.
        state_ = HTTP_STATE_TERMINATE;
        return Status::OK;
      } else if (errno == EAGAIN) {
        // No more data available for now.
        VLOG(6) << "Recv " << sock_ << " again";
        return Status::OK;
      } else {
        // Receive error.
        VLOG(6) << "Recv " << sock_ << " error";
        return Error("recv");
      }
    }
    VLOG(6) << "Recv " << sock_ << ", " << rc << " bytes";
    buffer->end += rc;
    return Status::OK;
  }

  // Send data on socket.
  Status Send(HTTPBuffer *buffer, bool *done) override {
    *done = false;
    int rc  = send(sock_, buffer->start, buffer->size(), MSG_NOSIGNAL);
    if (rc <= 0) {
      *done = true;
      if (rc == 0) {
        // Connection closed.
        VLOG(6) << "Send " << sock_ << " closed";
        state_ = HTTP_STATE_TERMINATE;
        return Status::OK;
      } else if (errno == EAGAIN) {
        // Output queue full.
        VLOG(6) << "Send " << sock_ << " again";
        return Status::OK;
      } else {
        // Send error.
        VLOG(6) << "Send " << sock_ << " done";
        return Error("send");
      }
    }
    VLOG(6) << "Send " << sock_ << ", " << rc << " bytes";
    buffer->start += rc;
    return Status::OK;
  }

  // Shut down connection.
  void Shutdown() override {
    shutdown(sock_, SHUT_RDWR);
  }

 private:
  // Socket for connection.
  int sock_;

  // Last time event was received on connection.
  time_t last_;

  friend class EPollHTTPServer;
};

// HTTP server based on epoll.
class EPollHTTPServer : public HTTPServer {
 public:
  EPollHTTPServer() {
    sock_ = -1;
    pollfd_ = -1;
    stop_ = false;
    Register("/connz", this, &EPollHTTPServer::ConnectionHandler);
  }

  ~EPollHTTPServer() override {
    // Wait for workers to terminate.
    workers_.Join();

    // Close listening socket.
    if (sock_ != -1) close(sock_);

    // Close poll descriptor.
    if (pollfd_ != -1) close(pollfd_);
  }

  // Start HTTP server listening on the port.
  Status Start() {
    int rc;

    // Create poll file descriptor.
    pollfd_ = epoll_create(1);
    if (pollfd_ < 0) return Error("epoll_create");

    // Create listen socket.
    sock_ = socket(AF_INET, SOCK_STREAM, 0);
    if (sock_ < 0) return Error("socket");
    rc = fcntl(sock_, F_SETFL, O_NONBLOCK);
    if (rc < 0) return Error("fcntl");
    int on = 1;
    rc = setsockopt(sock_, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
    if (rc < 0) return Error("setsockopt");

    // Bind listen socket.
    struct sockaddr_in sin;
    sin.sin_addr.s_addr = htonl(INADDR_ANY);
    sin.sin_family = AF_INET;
    sin.sin_port = htons(options_.port);
    rc = bind(sock_, reinterpret_cast<struct sockaddr *>(&sin), sizeof(sin));
    if (rc < 0) return Error("bind");

    // Start listening on socket.
    rc = listen(sock_, SOMAXCONN);
    if (rc < 0) return Error("listen");

    // Add listening socket to poll descriptor.
    struct epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.ptr = nullptr;
    rc = epoll_ctl(pollfd_, EPOLL_CTL_ADD, sock_, &ev);
    if (rc < 0) return Error("epoll_ctl");

    // Start workers.
    workers_.Start(options_.num_workers, [this](int index) { this->Worker(); });

    return Status::OK;
  }

  // Wait for shutdown.
  void Wait() override {
    // Wait until all workers have terminated.
    workers_.Join();
  }

  // Shut down HTTP server.
  void Shutdown() override {
    // Set stop flag to terminate worker threads.
    stop_ = true;
  }

 private:
  // Worker handler.
  void Worker() {
    // Allocate event structure.
    int max_events = options_.max_events;
    struct epoll_event *events = new epoll_event[max_events];

    // Keep processing events until server is shut down.
    while (!stop_) {
      // Get new events.
      idle_++;
      int rc = epoll_wait(pollfd_, events, max_events, 2000);
      idle_--;
      if (stop_) break;
      if (rc < 0) {
        if (errno == EINTR) continue;
        LOG(ERROR) << Error("epoll_wait");
        break;
      }
      if (rc == 0) {
        ShutdownIdleConnections();
        continue;
      }

      // Start new worker if all workers are busy.
      if (++active_ == workers_.size()) {
        MutexLock lock(&mu_);
        if (workers_.size() < options_.max_workers) {
          VLOG(3) << "Starting new worker thread " << workers_.size();
          workers_.Start(1, [this](int index) { this->Worker(); });
        } else {
          LOG(WARNING) << "All HTTP worker threads are busy";
        }
      }

      // Process events.
      for (int i = 0; i < rc; ++i) {
        struct epoll_event *ev = &events[i];
        auto *conn = reinterpret_cast<EPollHTTPConnection *>(ev->data.ptr);
        if (conn == nullptr) {
          // New connection.
          AcceptConnection();
        } else {
          // Check if connection has been closed.
          if (ev->events & (EPOLLHUP | EPOLLERR)) {
            // Detach socket from poll descriptor.
            if (ev->events & EPOLLERR) {
              VLOG(5) << "Error polling socket " << conn->sock_;
            }
            rc = epoll_ctl(pollfd_, EPOLL_CTL_DEL, conn->sock_, ev);
            if (rc < 0) {
              VLOG(2) << Error("epoll_ctl");
            } else {
              // Delete client connection.
              VLOG(3) << "Close HTTP connection " << conn->sock_;
              RemoveConnection(conn);
              delete conn;
            }
          } else {
            // Process connection data.
            VLOG(5) << "Begin " << conn->sock_ << " in state " << conn->State();
            do {
              Status s = conn->Process();
              if (!s.ok()) {
                LOG(ERROR) << "HTTP error: " << s;
                conn->state_ = HTTP_STATE_TERMINATE;
              }
              if (conn->state_ == HTTP_STATE_IDLE) {
                VLOG(5) << "Process " << conn->sock_ << " again";
              }
            } while (conn->state_ == HTTP_STATE_IDLE);
            VLOG(5) << "End " << conn->sock_ << " in state " << conn->State();

            if (conn->state_ == HTTP_STATE_TERMINATE) {
              conn->Shutdown();
              VLOG(5) << "Shutdown HTTP connection";
            } else {
              conn->last_ = time(0);
            }
          }
        }
      }
      active_--;
    }

    // Free event structure.
    delete [] events;
  }

  // Accept new connection.
  void AcceptConnection() {
    int rc;

    // Accept new connection from listen socket.
    struct sockaddr_in addr;
    socklen_t len = sizeof(addr);
    int sock = accept(sock_, reinterpret_cast<struct sockaddr *>(&addr), &len);
    if (sock < 0) {
      if (errno != EAGAIN) LOG(WARNING) << Error("listen");
      return;
    }

    // Set non-blocking mode for socket.
    int flags = fcntl(sock, F_GETFL, 0);
    rc = fcntl(sock, F_SETFL, flags | O_NONBLOCK);
    if (rc < 0) LOG(WARNING) << Error("fcntl");

    // Create new connection.
    VLOG(3) << "New HTTP connection " << sock;
    EPollHTTPConnection *conn = new EPollHTTPConnection(this, sock);
    AddConnection(conn);

    // Add new connection to poll descriptor.
    struct epoll_event ev;
    ev.events = EPOLLIN | EPOLLOUT | EPOLLET;
    ev.data.ptr = conn;
    rc = epoll_ctl(pollfd_, EPOLL_CTL_ADD, sock, &ev);
    if (rc < 0) LOG(WARNING) << Error("epoll_ctl");
  }

  // Shut down idle connections.
  void ShutdownIdleConnections() {
    if (options_.max_idle <= 0) return;
    MutexLock lock(&mu_);
    time_t expire = time(0) - options_.max_idle;
    auto *conn = static_cast<EPollHTTPConnection *>(connections_);
    while (conn != nullptr) {
      if (conn->last_ < expire) {
        conn->Shutdown();
        VLOG(5) << "Shut down idle connection";
      }
      conn = static_cast<EPollHTTPConnection *>(conn->next_);
    }
  }

  // Handler for /connz.
  void ConnectionHandler(HTTPRequest *req, HTTPResponse *rsp) {
    static const char *header_state_name[] = {
      "FIRSTWORD", "FIRSTWS", "SECONDWORD", "SECONDWS", "THIRDWORD",
      "LINE", "LF", "CR", "CRLF", "CRLFCR", "DONE", "BOGUS",
    };

    MutexLock lock(&mu_);
    rsp->SetContentType("text/html");
    rsp->set_status(200);
    rsp->Append("<html><head><title>connz</title></head><body>\n");
    rsp->Append("<table border=\"1\"><tr>\n");
    rsp->Append("<td>Socket</td>");
    rsp->Append("<td>Client address</td>");
    rsp->Append("<td>Socket status</td>");
    rsp->Append("<td>State</td>");
    rsp->Append("<td>Header state</td>");
    rsp->Append("<td>Keep</td>");
    rsp->Append("<td>Idle</td>");
    rsp->Append("<td>URL</td>");
    rsp->Append("</tr>\n");
    auto *conn = static_cast<EPollHTTPConnection *>(connections_);
    time_t now = time(0);
    while (conn != nullptr) {
      rsp->Append("<tr>");

      // Socket.
      rsp->Append("<td>" + SimpleItoa(conn->sock_) + "</td>");

      // Client address.
      struct sockaddr_in peer;
      socklen_t plen = sizeof(peer);
      struct sockaddr *saddr = reinterpret_cast<sockaddr *>(&peer);
      if (getpeername(conn->sock_, saddr, &plen) == -1) {
        rsp->Append("<td>?</td>");
      } else {
        rsp->Append("<td>");
        rsp->Append(inet_ntoa(peer.sin_addr));
        rsp->Append(":");
        rsp->Append(SimpleItoa(ntohs(peer.sin_port)));
        rsp->Append("</td>");
      }

      // Socket state.
      int err = 0;
      socklen_t errlen = sizeof(err);
      int rc  = getsockopt(conn->sock_, SOL_SOCKET, SO_ERROR, &err, &errlen);
      const char *error = "OK";
      if (rc != 0) {
        error = strerror(rc);
      } else if (err != 0) {
        error = strerror(err);
      }
      rsp->Append("<td>");
      rsp->Append(error);
      rsp->Append("</td>");

      // Connection state.
      rsp->Append("<td>");
      rsp->Append(conn->State());
      rsp->Append("</td>");

      // Header parsing state.
      rsp->Append("<td>");
      rsp->Append(header_state_name[conn->header_state_]);
      rsp->Append("</td>");

      // Keep alive.
      rsp->Append(conn->keep_ ? "<td>Y</td>" : "<td>N</td>");

      // Idle time.
      rsp->Append("<td>" + SimpleItoa(now - conn->last_) + "</td>");

      // Request URL.
      rsp->Append("<td>");
      if (conn->request()) {
        if (conn->request()->full_path()) {
          rsp->Append(HTMLEscape(conn->request()->full_path()));
        }
        if (conn->request()->query()) {
          rsp->Append("?");
          rsp->Append(HTMLEscape(conn->request()->query()));
        }
      }
      rsp->Append("</td>");

      rsp->Append("</tr>\n");
      conn = static_cast<EPollHTTPConnection *>(conn->next_);
    }
    rsp->Append("</table>\n");
    rsp->Append("<p>" + std::to_string(workers_.size()) + " worker threads, " +
                std::to_string(active_) + " active, " +
                std::to_string(idle_) + " idle</p>\n");
    rsp->Append("</body></html>\n");
  }

  // Socket for accepting new connections.
  int sock_;

  // File descriptor for epoll.
  int pollfd_;

  // Worker threads.
  WorkerPool workers_;

  // Number of active worker threads.
  std::atomic<int> active_{0};

  // Number of idle worker threads.
  std::atomic<int> idle_{0};

  // Flag to determine if server is shutting down.
  bool stop_;
};

REGISTER_HTTP_SERVER("epoll", EPollHTTPServer);

}  // namespace sling

