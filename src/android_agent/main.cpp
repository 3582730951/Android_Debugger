#include <algorithm>
#include <arpa/inet.h>
#include <algorithm>
#include <cstdarg>
#include <cerrno>
#include <csignal>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <dirent.h>
#include <elf.h>
#include <fcntl.h>
#include <cstdlib>
#include <dlfcn.h>
#include <fstream>
#include <memory>
#include <netinet/in.h>
#include <sstream>
#include <string>
#include <limits>
#include <mutex>
#include <atomic>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>
#include <vector>

#include <linux/perf_event.h>
#include <linux/hw_breakpoint.h>

#if defined(__arm__) || defined(__aarch64__)
#include <asm/ptrace.h>
#endif
#if defined(__ANDROID__)
#include <android/log.h>
#endif
#include <zlib.h>

#ifndef __WALL
#define __WALL 0x40000000
#endif

#include "MemoryScanner.h"
#include "SafeMemoryReader.h"
#include "../protocol/Protocol.h"
#include "../protocol/Compression.h"

namespace {
constexpr int kListenPort = 12345;
constexpr uint32_t kMaxPayload = 16 * 1024 * 1024;
constexpr size_t kMaxScanReturn = 1024;
constexpr uint32_t kMaxReadSize = 1024 * 1024;
constexpr uint32_t kMaxWriteSize = 1024 * 1024;
constexpr uint32_t kMaxProcessEntries = 4096;
constexpr uint32_t kMaxModuleEntries = 8192;
constexpr uint32_t kMaxProcessIconBytes = 2 * 1024 * 1024;
constexpr size_t kMaxIndexReturn = 4096;
constexpr size_t kMaxIndexEntries = 20'000'000;
std::atomic<int> g_last_ptrace_errno{0};

void LogAgent(const char* fmt, ...) {
  char buf[512];
  va_list ap;
  va_start(ap, fmt);
  std::vsnprintf(buf, sizeof(buf), fmt, ap);
  va_end(ap);
  std::string line(buf);
  line.push_back('\n');
  write(STDERR_FILENO, line.data(), line.size());
#if defined(__ANDROID__)
  __android_log_print(ANDROID_LOG_WARN, "R3Agent", "%s", buf);
#endif
}

int32_t StatusCode(bool ok) { return ok ? 0 : -1; }

uint64_t StripTag64(uint64_t value) {
  return value & 0x00FFFFFFFFFFFFFFull;
}

std::string ReadCmdline(pid_t pid);
std::string ReadComm(pid_t pid);
bool ReadProcessUid(pid_t pid, uint32_t* out_uid);
bool IsLikelySystemUid(uint32_t uid);

int ReadTracerPid(pid_t target) {
  if (target <= 0) {
    return -1;
  }
  std::ifstream ifs(std::string("/proc/") + std::to_string(target) + "/status");
  if (!ifs.is_open()) {
    return -1;
  }
  std::string line;
  while (std::getline(ifs, line)) {
    if (line.rfind("TracerPid:", 0) == 0) {
      const char* p = line.c_str() + 10;
      while (*p == ' ' || *p == '\t') {
        ++p;
      }
      const int tracer = std::atoi(p);
      if (tracer > 0) {
        if (kill(tracer, 0) != 0 && errno == ESRCH) {
          return 0;
        }
      }
      return tracer;
    }
  }
  return -1;
}

bool IsSameProcess(pid_t pid) {
  if (pid <= 0) {
    return false;
  }
  const pid_t self = getpid();
  if (pid == self) {
    return true;
  }
  std::ifstream ifs(std::string("/proc/") + std::to_string(pid) + "/status");
  if (!ifs.is_open()) {
    return false;
  }
  std::string line;
  while (std::getline(ifs, line)) {
    if (line.rfind("Tgid:", 0) == 0) {
      const char* p = line.c_str() + 5;
      while (*p == ' ' || *p == '\t') {
        ++p;
      }
      const pid_t tgid = static_cast<pid_t>(std::atoi(p));
      return tgid == self;
    }
  }
  return false;
}

char ReadProcState(pid_t target) {
  if (target <= 0) {
    return '\0';
  }
  std::ifstream ifs(std::string("/proc/") + std::to_string(target) + "/status");
  if (!ifs.is_open()) {
    return '\0';
  }
  std::string line;
  while (std::getline(ifs, line)) {
    if (line.rfind("State:", 0) == 0) {
      for (size_t i = 6; i < line.size(); ++i) {
        const char c = line[i];
        if (c >= 'A' && c <= 'Z') {
          return c;
        }
        if (c >= 'a' && c <= 'z') {
          return c;
        }
      }
      break;
    }
  }
  return '\0';
}

bool ThreadExists(pid_t tid) {
  if (tid <= 0) {
    return false;
  }
  char path[64] = {0};
  std::snprintf(path, sizeof(path), "/proc/%d", tid);
  return access(path, F_OK) == 0;
}

std::vector<pid_t> ListThreads(pid_t pid);

bool StopProcess(pid_t pid) {
  if (pid <= 0) {
    return false;
  }
  std::vector<pid_t> tids = ListThreads(pid);
  if (tids.empty()) {
    return false;
  }
#if defined(__NR_tgkill)
  auto send_sigstop = [&](pid_t tid) -> int {
    return static_cast<int>(syscall(__NR_tgkill, pid, tid, SIGSTOP));
  };
#else
  auto send_sigstop = [&](pid_t tid) -> int {
    return kill(tid, SIGSTOP);
  };
#endif
  if (kill(pid, SIGSTOP) != 0 && errno != ESRCH) {
    LogAgent("[R3Agent] sigstop group failed pid=%d errno=%d", pid, errno);
  }
  for (pid_t tid : tids) {
    if (send_sigstop(tid) != 0) {
      const int err = errno;
      if (err != ESRCH) {
        LogAgent("[R3Agent] sigstop failed tid=%d errno=%d", tid, err);
      }
    }
  }
  constexpr int kWaitStepMs = 20;
  constexpr int kWaitMaxMs = 3000;
  int waited = 0;
  while (waited < kWaitMaxMs) {
    const char state = ReadProcState(pid);
    if (state == 'T' || state == 't') {
      return true;
    }
    usleep(kWaitStepMs * 1000);
    waited += kWaitStepMs;
  }
  LogAgent("[R3Agent] sigstop timeout pid=%d state=%c", pid, ReadProcState(pid));
  return false;
}

bool ResumeProcess(pid_t pid) {
  if (pid <= 0) {
    return false;
  }
  return kill(pid, SIGCONT) == 0;
}

std::vector<pid_t> ListThreads(pid_t pid) {
  std::vector<pid_t> tids;
  if (pid <= 0) {
    return tids;
  }
  std::string task_path = std::string("/proc/") + std::to_string(pid) + "/task";
  DIR* dir = opendir(task_path.c_str());
  if (!dir) {
    return tids;
  }
  struct dirent* ent = nullptr;
  while ((ent = readdir(dir)) != nullptr) {
    if (ent->d_name[0] < '0' || ent->d_name[0] > '9') {
      continue;
    }
    const pid_t tid = static_cast<pid_t>(std::atoi(ent->d_name));
    if (tid > 0) {
      tids.push_back(tid);
    }
  }
  closedir(dir);
  if (tids.empty()) {
    tids.push_back(pid);
  }
  return tids;
}

bool WaitForStop(pid_t tid, int timeout_ms) {
  constexpr int kWaitStepMs = 20;
  int waited = 0;
  int status = 0;
  int wait_flags = WNOHANG;
#ifdef __WALL
  wait_flags |= __WALL;
#endif
  while (waited < timeout_ms) {
    const pid_t rc = waitpid(tid, &status, wait_flags);
    if (rc == tid) {
      return WIFSTOPPED(status);
    }
    if (rc == 0) {
      usleep(kWaitStepMs * 1000);
      waited += kWaitStepMs;
      continue;
    }
    if (rc < 0 && errno == EINTR) {
      continue;
    }
    if (rc < 0 && (errno == ECHILD || errno == ESRCH)) {
      return false;
    }
    break;
  }
  return false;
}

bool EnsureTraceeStopped(pid_t tid, int timeout_ms, bool* interrupted) {
  if (interrupted) {
    *interrupted = false;
  }
  if (tid <= 0) {
    return false;
  }
  const char state = ReadProcState(tid);
  if (state == 'T' || state == 't') {
    return true;
  }
#if defined(PTRACE_INTERRUPT)
  if (ptrace(PTRACE_INTERRUPT, tid, nullptr, nullptr) != -1) {
    if (WaitForStop(tid, timeout_ms) || ReadProcState(tid) == 'T' || ReadProcState(tid) == 't') {
      if (interrupted) {
        *interrupted = true;
      }
      return true;
    }
  }
#endif
  if (kill(tid, SIGSTOP) == 0) {
    if (WaitForStop(tid, timeout_ms) || ReadProcState(tid) == 'T' || ReadProcState(tid) == 't') {
      if (interrupted) {
        *interrupted = true;
      }
      return true;
    }
  }
  return (ReadProcState(tid) == 'T' || ReadProcState(tid) == 't');
}

bool ReadAll(int fd, void* buffer, size_t size) {
  size_t offset = 0;
  while (offset < size) {
    ssize_t n = recv(fd, static_cast<char*>(buffer) + offset, size - offset, 0);
    if (n == 0) {
      return false;
    }
    if (n < 0) {
      if (errno == EINTR) {
        continue;
      }
      return false;
    }
    offset += static_cast<size_t>(n);
  }
  return true;
}

bool WriteAll(int fd, const void* buffer, size_t size) {
  size_t offset = 0;
  while (offset < size) {
    ssize_t n = send(fd, static_cast<const char*>(buffer) + offset, size - offset, 0);
    if (n <= 0) {
      if (n < 0 && errno == EINTR) {
        continue;
      }
      return false;
    }
    offset += static_cast<size_t>(n);
  }
  return true;
}

bool AttachDebugger(pid_t pid);
bool DetachDebugger(pid_t pid);
bool DebugStepIn(pid_t pid, std::string* err);
bool DebugStepOver(pid_t pid, std::string* err);
bool TrySetCon(const char* ctx);
std::string ReadCmdline(pid_t pid);
std::string ReadComm(pid_t pid);
ssize_t ProcessVmReadvCompat(pid_t pid,
                             const struct iovec* local_iov,
                             unsigned long liovcnt,
                             const struct iovec* remote_iov,
                             unsigned long riovcnt,
                             unsigned long flags);

int PerfEventOpen(struct perf_event_attr* attr,
                  pid_t pid,
                  int cpu,
                  int group_fd,
                  unsigned long flags) {
#if defined(__NR_perf_event_open)
  return static_cast<int>(syscall(__NR_perf_event_open, attr, pid, cpu, group_fd, flags));
#else
  errno = ENOSYS;
  return -1;
#endif
}

uint32_t ClampBreakpointSize(uint32_t size, uint8_t type, bool* ok) {
  if (ok) {
    *ok = true;
  }
  if (size == 1 || size == 2 || size == 4 || size == 8) {
    return size;
  }
  if (type == protocol::DEBUG_BP_EXEC) {
    return 4;
  }
  if (ok) {
    *ok = false;
  }
  return size;
}

uint32_t PerfBpTypeFromDebug(uint8_t type) {
  switch (type) {
    case protocol::DEBUG_BP_WRITE:
      return HW_BREAKPOINT_W;
    case protocol::DEBUG_BP_READ:
      return HW_BREAKPOINT_R;
    case protocol::DEBUG_BP_READWRITE:
      return HW_BREAKPOINT_RW;
    case protocol::DEBUG_BP_EXEC:
    default:
      return HW_BREAKPOINT_X;
  }
}

struct PerfBreakpoint {
  uint64_t address = 0;
  uint32_t type = 0;
  uint32_t size = 0;
  pid_t tid = 0;
  int fd = -1;
  uint64_t last_count = 0;
  void* mmap_base = MAP_FAILED;
  size_t mmap_len = 0;
  size_t data_size = 0;
  uint64_t data_tail = 0;
};

class PerfBreakpointManager {
 public:
  bool Set(pid_t pid, uint64_t addr, uint8_t type, uint8_t size, uint8_t flags, std::string* err) {
    if (err) {
      err->clear();
    }
    bool size_ok = true;
    const uint32_t len = ClampBreakpointSize(size, type, &size_ok);
    if (!size_ok) {
      if (err) *err = "invalid size";
      return false;
    }
    std::lock_guard<std::mutex> lock(mu_);
    if (pid_ != 0 && pid_ != pid) {
      ClearAllLocked();
    }
    const uint64_t clean_addr = StripTag64(addr);
    ClearLocked(pid, clean_addr, type, len);
    pid_ = pid;
    if (!watch_reader_ || watch_reader_->pid() != pid_) {
      watch_reader_ = std::make_unique<SafeMemoryReader>(pid_);
      // Prefer having maps; /proc/pid/mem may be restricted, but process_vm_readv can still work.
      if (!watch_reader_->RefreshMaps()) {
        watch_reader_.reset();
      } else {
        watch_reader_->Open();
      }
    }

    struct perf_event_attr attr {};
    attr.type = PERF_TYPE_BREAKPOINT;
    attr.size = sizeof(attr);
    attr.config = 0;
    attr.sample_period = 1;
    attr.sample_type = PERF_SAMPLE_TID | PERF_SAMPLE_TIME | PERF_SAMPLE_ADDR;
    attr.disabled = 1;
    attr.inherit = 1;
    attr.exclude_kernel = 0;
    attr.exclude_hv = 1;
    attr.bp_type = PerfBpTypeFromDebug(type);
    attr.bp_addr = clean_addr;
    attr.bp_len = len;
    attr.wakeup_events = 1;

    std::vector<pid_t> tids;
    {
      std::string task_path = std::string("/proc/") + std::to_string(pid) + "/task";
      DIR* dir = opendir(task_path.c_str());
      if (dir) {
        struct dirent* ent = nullptr;
        while ((ent = readdir(dir)) != nullptr) {
          if (ent->d_name[0] < '0' || ent->d_name[0] > '9') {
            continue;
          }
          const pid_t tid = static_cast<pid_t>(std::atoi(ent->d_name));
          if (tid > 0) {
            tids.push_back(tid);
          }
        }
        closedir(dir);
      }
    }
    if (tids.empty()) {
      tids.push_back(pid);
    }

    bool any = false;
    int last_errno = 0;
    size_t opened = 0;
    for (pid_t tid : tids) {
      const int fd = PerfEventOpen(&attr, tid, -1, -1, PERF_FLAG_FD_CLOEXEC);
      if (fd < 0) {
        last_errno = errno;
        if (perf_open_log_count_ < 5) {
          LogAgent("[R3Agent] perf_event_open failed tid=%d errno=%d", tid, last_errno);
          perf_open_log_count_++;
        }
        continue;
      }
      if (ioctl(fd, PERF_EVENT_IOC_RESET, 0) != 0) {
        last_errno = errno;
        if (perf_ioctl_log_count_ < 5) {
          LogAgent("[R3Agent] perf reset failed tid=%d errno=%d", tid, last_errno);
          perf_ioctl_log_count_++;
        }
        close(fd);
        continue;
      }
      if (ioctl(fd, PERF_EVENT_IOC_ENABLE, 0) != 0) {
        last_errno = errno;
        if (perf_ioctl_log_count_ < 5) {
          LogAgent("[R3Agent] perf enable failed tid=%d errno=%d", tid, last_errno);
          perf_ioctl_log_count_++;
        }
        close(fd);
        continue;
      }

      PerfBreakpoint bp{};
      bp.address = clean_addr;
      bp.type = type;
      bp.size = len;
      bp.tid = tid;
      bp.fd = fd;
      bp.last_count = 0;
      std::string ring_err;
      if (!SetupRingBuffer(fd, &bp, &ring_err) && !ring_err.empty()) {
        LogAgent("[R3Agent] perf ringbuffer %s", ring_err.c_str());
      }
      breakpoints_.push_back(bp);
      opened++;
      any = true;
    }
    LogAgent("[R3Agent] perf set addr=0x%llx threads=%zu opened=%zu",
             static_cast<unsigned long long>(addr),
             tids.size(),
             opened);
    if (!any) {
      if (err) {
        char buf[128] = {0};
        std::snprintf(buf, sizeof(buf), "perf_event_open failed errno=%d", last_errno);
        *err = buf;
      }
      return false;
    }
    if (type != protocol::DEBUG_BP_EXEC) {
      const WatchKey key{clean_addr, static_cast<uint8_t>(type), static_cast<uint8_t>(len)};
      if (watch_states_.find(key) == watch_states_.end()) {
        std::vector<uint8_t> current;
        if (ReadWatchValue(clean_addr, len, &current, watch_reader_.get())) {
          WatchState state{};
          state.last.swap(current);
          state.has_value = true;
          watch_states_[key] = std::move(state);
        }
      }
    }
    return true;
  }

  bool Clear(pid_t pid, uint64_t addr, uint8_t type, uint8_t size) {
    std::lock_guard<std::mutex> lock(mu_);
    if (pid_ != 0 && pid_ != pid) {
      return false;
    }
    const uint32_t len = ClampBreakpointSize(size, type, nullptr);
    return ClearLocked(pid, StripTag64(addr), type, len);
  }

  void ClearAll() {
    std::lock_guard<std::mutex> lock(mu_);
    ClearAllLocked();
  }

  bool Poll(uint32_t max_events,
            std::vector<protocol::DebugBreakpointEvent>* out,
            SafeMemoryReader* reader) {
    if (!out) {
      return false;
    }
    out->clear();
    std::lock_guard<std::mutex> lock(mu_);
    std::unordered_set<WatchKey, WatchKeyHash, WatchKeyEq> processed;
    for (auto& bp : breakpoints_) {
      uint64_t delta = 0;
      uint64_t ring_hits = 0;
      uint64_t count = 0;
      bool have_count = false;
      const ssize_t n = read(bp.fd, &count, sizeof(count));
      if (n != static_cast<ssize_t>(sizeof(count))) {
        if (perf_log_count_ < 5) {
          LogAgent("[R3Agent] perf read fd=%d n=%zd errno=%d", bp.fd, n, errno);
        }
        perf_log_count_++;
      }
      if (n == static_cast<ssize_t>(sizeof(count))) {
        have_count = true;
        if (count > bp.last_count) {
          delta = count - bp.last_count;
        }
        bp.last_count = count;
        if (perf_count_log_count_ < 5) {
          LogAgent("[R3Agent] perf count addr=0x%llx tid=%d count=%llu",
                   static_cast<unsigned long long>(bp.address),
                   bp.tid,
                   static_cast<unsigned long long>(count));
          perf_count_log_count_++;
        }
      }
      if (bp.mmap_base != MAP_FAILED) {
        ring_hits = PollRingBuffer(&bp);
      }
      if (ring_hits > 0 && (!have_count || delta == 0)) {
        if (perf_ring_log_count_ < 5) {
          LogAgent("[R3Agent] perf ring hits addr=0x%llx tid=%d hits=%llu count=%llu",
                   static_cast<unsigned long long>(bp.address),
                   bp.tid,
                   static_cast<unsigned long long>(ring_hits),
                   static_cast<unsigned long long>(count));
          perf_ring_log_count_++;
        }
      }
      if (!have_count || delta == 0) {
        if (ring_hits > 0) {
          delta = ring_hits;
        }
      } else if (ring_hits > delta) {
        delta = ring_hits;
      }
      if (delta == 0 && bp.type != protocol::DEBUG_BP_EXEC) {
        const WatchKey key{bp.address, static_cast<uint8_t>(bp.type), static_cast<uint8_t>(bp.size)};
        if (processed.insert(key).second) {
          auto& state = watch_states_[key];
          std::vector<uint8_t> current;
          if (ReadWatchValue(bp.address, bp.size, &current, reader)) {
            if (state.has_value &&
                state.last.size() == current.size() &&
                std::memcmp(state.last.data(), current.data(), current.size()) != 0) {
              delta = 1;
              if (watch_hit_log_count_ < 5) {
                LogAgent("[R3Agent] watch fallback hit addr=0x%llx size=%u",
                         static_cast<unsigned long long>(bp.address),
                         static_cast<unsigned>(bp.size));
                watch_hit_log_count_++;
              }
            }
            state.last.swap(current);
            state.has_value = true;
          } else if (watch_fail_log_count_ < 5) {
            LogAgent("[R3Agent] watch fallback read failed addr=0x%llx size=%u errno=%d",
                     static_cast<unsigned long long>(bp.address),
                     static_cast<unsigned>(bp.size),
                     watch_last_errno_);
            watch_fail_log_count_++;
          }
        }
      }
      if (delta == 0) {
        continue;
      }
      protocol::DebugBreakpointEvent ev{};
      ev.address = bp.address;
      ev.type = bp.type;
      ev.size = bp.size;
      ev.count = delta;
      out->push_back(ev);
      if (max_events && out->size() >= max_events) {
        break;
      }
    }
    return true;
  }

  bool IsActiveFor(pid_t pid) const {
    return pid_ == pid && !breakpoints_.empty();
  }

 private:
  struct WatchKey {
    uint64_t addr = 0;
    uint8_t type = 0;
    uint8_t size = 0;
  };

  struct WatchKeyHash {
    size_t operator()(const WatchKey& key) const {
      size_t h = std::hash<uint64_t>()(key.addr);
      h ^= static_cast<size_t>(key.type) << 1;
      h ^= static_cast<size_t>(key.size) << 8;
      return h;
    }
  };

  struct WatchKeyEq {
    bool operator()(const WatchKey& a, const WatchKey& b) const {
      return a.addr == b.addr && a.type == b.type && a.size == b.size;
    }
  };

  struct WatchState {
    std::vector<uint8_t> last;
    bool has_value = false;
  };

  static ssize_t PRead64Compat(int fd, void* buf, size_t len, uint64_t off) {
#if defined(__ANDROID__)
    return pread64(fd, buf, len, static_cast<off64_t>(off));
#else
    return pread(fd, buf, len, static_cast<off_t>(off));
#endif
  }

  bool EnsureMemFd() {
    if (mem_fd_ >= 0) {
      return true;
    }
    if (pid_ <= 0) {
      return false;
    }
    char path[64] = {0};
    std::snprintf(path, sizeof(path), "/proc/%d/mem", pid_);
    mem_fd_ = open(path, O_RDONLY | O_LARGEFILE | O_CLOEXEC);
    if (mem_fd_ < 0 && watch_open_log_count_ < 5) {
      LogAgent("[R3Agent] watch mem open failed pid=%d errno=%d", pid_, errno);
      watch_open_log_count_++;
    }
    return mem_fd_ >= 0;
  }

  void CloseMemFd() {
    if (mem_fd_ >= 0) {
      close(mem_fd_);
      mem_fd_ = -1;
    }
  }

  bool ReadWatchValue(uint64_t addr,
                      uint32_t size,
                      std::vector<uint8_t>* out,
                      SafeMemoryReader* reader) {
    if (!out || size == 0 || pid_ <= 0) {
      return false;
    }
    out->assign(size, 0);
    watch_last_errno_ = EIO;
    SafeMemoryReader* active_reader = nullptr;
    if (reader && reader->pid() == pid_) {
      active_reader = reader;
    } else if (watch_reader_ && watch_reader_->pid() == pid_) {
      active_reader = watch_reader_.get();
    } else if (!watch_reader_) {
      watch_reader_ = std::make_unique<SafeMemoryReader>(pid_);
      if (watch_reader_->RefreshMaps()) {
        watch_reader_->Open();
        active_reader = watch_reader_.get();
      } else {
        watch_reader_.reset();
      }
    }
    if (active_reader) {
      SafeMemoryReader::ReadStats stats{};
      if (active_reader->ValidateAndReadEx(addr,
                                           out->data(),
                                           size,
                                           &stats,
                                           true,
                                           true,
                                           true) &&
          stats.bytes_read >= size) {
        watch_last_errno_ = 0;
        return true;
      }
      active_reader->RefreshMaps();
      stats = SafeMemoryReader::ReadStats{};
      if (active_reader->ValidateAndReadEx(addr,
                                           out->data(),
                                           size,
                                           &stats,
                                           true,
                                           true,
                                           true) &&
          stats.bytes_read >= size) {
        watch_last_errno_ = 0;
        return true;
      }
      if (stats.last_errno != 0) {
        watch_last_errno_ = stats.last_errno;
      } else if (stats.bytes_read < size) {
        watch_last_errno_ = EIO;
      }
    }
    struct iovec local_iov;
    local_iov.iov_base = out->data();
    local_iov.iov_len = size;
    struct iovec remote_iov;
    remote_iov.iov_base = reinterpret_cast<void*>(addr);
    remote_iov.iov_len = size;
    const ssize_t n = ProcessVmReadvCompat(pid_, &local_iov, 1, &remote_iov, 1, 0);
    if (n != static_cast<ssize_t>(size)) {
      watch_last_errno_ = (n < 0) ? errno : EIO;
      if (EnsureMemFd()) {
        const ssize_t m = PRead64Compat(mem_fd_, out->data(), size, addr);
        if (m == static_cast<ssize_t>(size)) {
          watch_last_errno_ = 0;
          return true;
        }
        watch_last_errno_ = (m < 0) ? errno : EIO;
      }
      if (ReadWatchValuePtrace(addr, size, out)) {
        watch_last_errno_ = 0;
        return true;
      }
      out->clear();
      return false;
    }
    watch_last_errno_ = 0;
    return true;
  }

  bool ReadWatchValuePtrace(uint64_t addr, uint32_t size, std::vector<uint8_t>* out) {
    if (!out || size == 0 || pid_ <= 0) {
      return false;
    }
    if (!AttachDebugger(pid_)) {
      watch_last_errno_ = g_last_ptrace_errno.load();
      return false;
    }
    out->assign(size, 0);
    uint64_t cursor = addr & ~0x7ull;
    size_t offset = static_cast<size_t>(addr - cursor);
    size_t remaining = size;
    size_t out_index = 0;
    while (remaining > 0) {
      errno = 0;
      long data = ptrace(PTRACE_PEEKDATA, pid_, reinterpret_cast<void*>(cursor), nullptr);
      if (data == -1 && errno != 0) {
        watch_last_errno_ = errno;
        DetachDebugger(pid_);
        return false;
      }
      const uint8_t* bytes = reinterpret_cast<const uint8_t*>(&data);
      const size_t copy = std::min(remaining, static_cast<size_t>(8 - offset));
      std::memcpy(out->data() + out_index, bytes + offset, copy);
      remaining -= copy;
      out_index += copy;
      cursor += 8;
      offset = 0;
    }
    DetachDebugger(pid_);
    return true;
  }

  bool ClearLocked(pid_t pid, uint64_t addr, uint8_t type, uint32_t len) {
    if (pid_ != 0 && pid_ != pid) {
      return false;
    }
    bool removed = false;
    for (auto it = breakpoints_.begin(); it != breakpoints_.end();) {
      if (it->address == addr && it->type == type && it->size == len) {
        const WatchKey key{it->address, static_cast<uint8_t>(it->type), static_cast<uint8_t>(it->size)};
        watch_states_.erase(key);
        if (it->fd >= 0) {
          close(it->fd);
        }
        DestroyRingBuffer(&(*it));
        it = breakpoints_.erase(it);
        removed = true;
      } else {
        ++it;
      }
    }
    if (breakpoints_.empty()) {
      watch_states_.clear();
      CloseMemFd();
      watch_reader_.reset();
      pid_ = 0;
    }
    return removed;
  }

  void ClearAllLocked() {
    for (auto& bp : breakpoints_) {
      if (bp.fd >= 0) {
        close(bp.fd);
      }
      DestroyRingBuffer(&bp);
    }
    breakpoints_.clear();
    watch_states_.clear();
    CloseMemFd();
    watch_reader_.reset();
    pid_ = 0;
  }

  pid_t pid_ = 0;
  std::vector<PerfBreakpoint> breakpoints_;
  std::unordered_map<WatchKey, WatchState, WatchKeyHash, WatchKeyEq> watch_states_;
  std::unique_ptr<SafeMemoryReader> watch_reader_;
  int mem_fd_ = -1;
  int watch_last_errno_ = 0;
  uint32_t watch_open_log_count_ = 0;
  uint32_t watch_fail_log_count_ = 0;
  uint32_t watch_hit_log_count_ = 0;
  uint32_t perf_log_count_ = 0;
  uint32_t perf_count_log_count_ = 0;
  uint32_t perf_open_log_count_ = 0;
  uint32_t perf_ioctl_log_count_ = 0;
  uint32_t perf_ring_log_count_ = 0;
  mutable std::mutex mu_;

  static void ReadRingData(const uint8_t* base, size_t data_size, uint64_t offset, void* out, size_t size) {
    if (!base || data_size == 0 || !out || size == 0) {
      return;
    }
    const size_t pos = static_cast<size_t>(offset & (data_size - 1));
    if (pos + size <= data_size) {
      std::memcpy(out, base + pos, size);
    } else {
      const size_t first = data_size - pos;
      std::memcpy(out, base + pos, first);
      std::memcpy(static_cast<uint8_t*>(out) + first, base, size - first);
    }
  }

  static bool SetupRingBuffer(int fd, PerfBreakpoint* bp, std::string* err) {
    if (!bp) {
      return false;
    }
    const size_t page_size = static_cast<size_t>(sysconf(_SC_PAGESIZE));
    const size_t data_pages = 8;
    const size_t mmap_len = (data_pages + 1) * page_size;
    void* base = mmap(nullptr, mmap_len, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (base == MAP_FAILED) {
      if (err) {
        char buf[128] = {0};
        std::snprintf(buf, sizeof(buf), "perf mmap failed errno=%d", errno);
        *err = buf;
      }
      return false;
    }
    bp->mmap_base = base;
    bp->mmap_len = mmap_len;
    bp->data_size = data_pages * page_size;
    bp->data_tail = 0;
    return true;
  }

  static void DestroyRingBuffer(PerfBreakpoint* bp) {
    if (!bp) {
      return;
    }
    if (bp->mmap_base != MAP_FAILED) {
      munmap(bp->mmap_base, bp->mmap_len);
      bp->mmap_base = MAP_FAILED;
      bp->mmap_len = 0;
      bp->data_size = 0;
      bp->data_tail = 0;
    }
  }

  static uint64_t PollRingBuffer(PerfBreakpoint* bp) {
    if (!bp || bp->mmap_base == MAP_FAILED || bp->data_size == 0) {
      return 0;
    }
    auto* meta = reinterpret_cast<perf_event_mmap_page*>(bp->mmap_base);
    uint8_t* data = reinterpret_cast<uint8_t*>(bp->mmap_base) +
                    static_cast<size_t>(sysconf(_SC_PAGESIZE));
    const uint64_t head = meta->data_head;
    __sync_synchronize();
    uint64_t tail = bp->data_tail;
    uint64_t hits = 0;
    while (tail < head) {
      struct perf_event_header hdr {};
      ReadRingData(data, bp->data_size, tail, &hdr, sizeof(hdr));
      if (hdr.size < sizeof(hdr)) {
        break;
      }
      if (hdr.type == PERF_RECORD_SAMPLE) {
        hits++;
      }
      tail += hdr.size;
    }
    bp->data_tail = tail;
    meta->data_tail = tail;
    return hits;
  }
};

#if defined(__aarch64__)
constexpr uint32_t kAarch64BrkInsn = 0xD4200000u;

struct PtraceBreakpoint {
  uint64_t address = 0;
  uint32_t type = 0;
  uint32_t size = 0;
  uint32_t original_insn = 0;
  uint64_t hit_count = 0;
};

class PtraceBreakpointManager {
 public:
  ~PtraceBreakpointManager() { ClearAll(); }

  bool Set(pid_t pid, uint64_t addr, uint8_t type, uint8_t size, uint8_t flags, std::string* err) {
    if (err) {
      err->clear();
    }
    if (type != protocol::DEBUG_BP_EXEC) {
      if (err) *err = "ptrace supports exec only";
      return false;
    }
    const uint64_t clean_addr = StripTag64(addr);
    if ((clean_addr & 0x3) != 0) {
      if (err) *err = "unaligned exec addr";
      return false;
    }
    bool size_ok = true;
    const uint32_t len = ClampBreakpointSize(size, type, &size_ok);
    if (!size_ok) {
      if (err) *err = "invalid size";
      return false;
    }

    std::lock_guard<std::mutex> lock(mu_);
    if (pid_ != 0 && pid_ != pid) {
      ClearAllLocked();
    }
    pid_ = pid;
    for (const auto& bp : breakpoints_) {
      if (bp.address == clean_addr && bp.type == type && bp.size == len) {
        return true;
      }
    }

    if (!AttachAllThreadsLocked(err)) {
      return false;
    }

    errno = 0;
    const uint64_t word_addr = clean_addr & ~0x7ull;
    const bool upper = (clean_addr & 0x4u) != 0;
    long data = ptrace(PTRACE_PEEKTEXT, pid_, reinterpret_cast<void*>(word_addr), nullptr);
    if (data == -1 && errno != 0) {
      if (err) {
        char buf[96] = {0};
        std::snprintf(buf, sizeof(buf), "ptrace peek failed errno=%d", errno);
        *err = buf;
      }
      DetachNewlyAttachedLocked();
      return false;
    }
    const uint64_t word = static_cast<uint64_t>(data);
    const uint32_t original = upper ? static_cast<uint32_t>(word >> 32)
                                    : static_cast<uint32_t>(word & 0xFFFFFFFFu);
    uint64_t patched_word = word;
    if (upper) {
      patched_word = (word & 0x00000000FFFFFFFFull) |
                     (static_cast<uint64_t>(kAarch64BrkInsn) << 32);
    } else {
      patched_word = (word & 0xFFFFFFFF00000000ull) |
                     static_cast<uint64_t>(kAarch64BrkInsn);
    }
    if (ptrace(PTRACE_POKETEXT,
               pid_,
               reinterpret_cast<void*>(word_addr),
               reinterpret_cast<void*>(static_cast<long>(patched_word))) == -1) {
      if (err) {
        char buf[96] = {0};
        std::snprintf(buf, sizeof(buf), "ptrace poke failed errno=%d", errno);
        *err = buf;
      }
      DetachNewlyAttachedLocked();
      return false;
    }

    if (breakpoints_.empty()) {
      hit_log_count_ = 0;
      miss_log_count_ = 0;
      getreg_fail_log_count_ = 0;
    }
    PtraceBreakpoint bp{};
    bp.address = clean_addr;
    bp.type = type;
    bp.size = len;
    bp.original_insn = original;
    bp.hit_count = 0;
    breakpoints_.push_back(bp);
    ContinueNewlyAttachedLocked();

    return true;
  }

  bool Clear(pid_t pid, uint64_t addr, uint8_t type, uint8_t size) {
    std::lock_guard<std::mutex> lock(mu_);
    if (pid_ != 0 && pid_ != pid) {
      return false;
    }
    const uint32_t len = ClampBreakpointSize(size, type, nullptr);
    for (auto it = breakpoints_.begin(); it != breakpoints_.end(); ++it) {
      if (it->address == StripTag64(addr) && it->type == type && it->size == len) {
        const pid_t tid = PickThreadLocked();
        if (tid > 0) {
          RestoreInstruction(*it, tid);
        }
        breakpoints_.erase(it);
        if (breakpoints_.empty()) {
          DetachLocked();
        }
        return true;
      }
    }
    return false;
  }

  void ClearAll() {
    std::lock_guard<std::mutex> lock(mu_);
    ClearAllLocked();
  }

  bool Poll(uint32_t max_events, std::vector<protocol::DebugBreakpointEvent>* out) {
    if (!out) {
      return false;
    }
    out->clear();
    std::lock_guard<std::mutex> lock(mu_);
    const uint32_t pump_limit = max_events ? std::max<uint32_t>(max_events, 32u) : 32u;
    PumpEventsLocked(pump_limit);
    for (auto& bp : breakpoints_) {
      if (bp.hit_count == bp_last_report_[bp.address]) {
        continue;
      }
      const uint64_t delta = bp.hit_count - bp_last_report_[bp.address];
      protocol::DebugBreakpointEvent ev{};
      ev.address = bp.address;
      ev.type = bp.type;
      ev.size = bp.size;
      ev.count = delta;
      out->push_back(ev);
      bp_last_report_[bp.address] = bp.hit_count;
      if (max_events && out->size() >= max_events) {
        break;
      }
    }
    return true;
  }

 bool IsAttached(pid_t pid) const {
    return attached_ && pid_ == pid;
  }

 private:
  std::vector<pid_t> ListThreads(pid_t pid) const {
    std::vector<pid_t> tids;
    if (pid <= 0) {
      return tids;
    }
    std::string task_path = std::string("/proc/") + std::to_string(pid) + "/task";
    DIR* dir = opendir(task_path.c_str());
    if (!dir) {
      return tids;
    }
    struct dirent* ent = nullptr;
    while ((ent = readdir(dir)) != nullptr) {
      if (ent->d_name[0] < '0' || ent->d_name[0] > '9') {
        continue;
      }
      const pid_t tid = static_cast<pid_t>(std::atoi(ent->d_name));
      if (tid > 0) {
        tids.push_back(tid);
      }
    }
    closedir(dir);
    if (tids.empty()) {
      tids.push_back(pid);
    }
    return tids;
  }

  bool WaitForStop(pid_t tid, int timeout_ms) const {
    constexpr int kWaitStepMs = 20;
    int waited = 0;
    int status = 0;
    int wait_flags = WNOHANG;
#ifdef __WALL
    wait_flags |= __WALL;
#endif
    while (waited < timeout_ms) {
      const pid_t rc = waitpid(-1, &status, wait_flags);
      if (rc == tid) {
        return WIFSTOPPED(status);
      }
      if (rc > 0) {
        if (WIFSTOPPED(status)) {
          ptrace(PTRACE_CONT, rc, nullptr, nullptr);
        }
        continue;
      }
      if (rc == 0) {
        usleep(kWaitStepMs * 1000);
        waited += kWaitStepMs;
        continue;
      }
      if (rc < 0 && errno == EINTR) {
        continue;
      }
      break;
    }
    return false;
  }

  bool SetOptions(pid_t tid) const {
    long opts = 0;
#ifdef PTRACE_O_TRACECLONE
    opts |= PTRACE_O_TRACECLONE;
#endif
#ifdef PTRACE_O_TRACEEXIT
    opts |= PTRACE_O_TRACEEXIT;
#endif
#ifdef PTRACE_O_EXITKILL
    opts |= PTRACE_O_EXITKILL;
#endif
    if (opts == 0) {
      return true;
    }
    return ptrace(PTRACE_SETOPTIONS, tid, nullptr, reinterpret_cast<void*>(opts)) != -1;
  }

  bool AttachThreadLocked(pid_t tid, std::string* err, bool is_main) {
    if (tid <= 0) {
      return false;
    }
    if (attached_tids_.count(tid) != 0) {
      return true;
    }
    const int tracer = ReadTracerPid(tid);
    if (ptrace_log_count_ < 5) {
      LogAgent("[R3Agent] ptrace attach tid=%d tracer=%d is_main=%d", tid, tracer, is_main ? 1 : 0);
      ptrace_log_count_++;
    }
    if (IsSameProcess(tracer)) {
      attached_tids_.insert(tid);
      return true;
    }
    if (tracer > 0) {
#if defined(PTRACE_SEIZE) && defined(PTRACE_INTERRUPT)
      if (is_main) {
        if (ptrace(PTRACE_SEIZE, tid, nullptr, nullptr) != -1) {
          if (ptrace(PTRACE_INTERRUPT, tid, nullptr, nullptr) != -1) {
            goto wait_for_stop;
          }
          ptrace(PTRACE_DETACH, tid, nullptr, nullptr);
        }
      }
#endif
      if (tracer_log_count_ < 5) {
        const std::string comm = ReadComm(tracer);
        const std::string cmdline = ReadCmdline(tracer);
        LogAgent("[R3Agent] tracer pid=%d comm=%s cmd=%s",
                 tracer,
                 comm.empty() ? "?" : comm.c_str(),
                 cmdline.empty() ? "?" : cmdline.c_str());
        tracer_log_count_++;
      }
      if (is_main) {
        if (err) {
          char buf[64] = {0};
          std::snprintf(buf, sizeof(buf), "tracer pid=%d", tracer);
          *err = buf;
        }
        return false;
      }
      return true;
    }
#if defined(PTRACE_SEIZE) && defined(PTRACE_INTERRUPT)
    if (ptrace(PTRACE_SEIZE, tid, nullptr, nullptr) != -1) {
      if (ptrace(PTRACE_INTERRUPT, tid, nullptr, nullptr) != -1) {
        goto wait_for_stop;
      }
      ptrace(PTRACE_DETACH, tid, nullptr, nullptr);
    } else if (errno == EPERM && is_main) {
      const char* contexts[] = {
        "u:r:debuggerd:s0",
        "u:r:magisk:s0",
        "u:r:su:s0",
        "u:r:shell:s0"
      };
      for (const char* ctx : contexts) {
        if (TrySetCon(ctx)) {
          if (ptrace(PTRACE_SEIZE, tid, nullptr, nullptr) != -1) {
            if (ptrace(PTRACE_INTERRUPT, tid, nullptr, nullptr) != -1) {
              goto wait_for_stop;
            }
            ptrace(PTRACE_DETACH, tid, nullptr, nullptr);
          }
        }
      }
    }
#endif
    if (ptrace(PTRACE_ATTACH, tid, nullptr, nullptr) == -1) {
      const int perr = errno;
      if (perr == EPERM && is_main) {
        const char* contexts[] = {
          "u:r:debuggerd:s0",
          "u:r:magisk:s0",
          "u:r:su:s0",
          "u:r:shell:s0"
        };
        for (const char* ctx : contexts) {
          if (TrySetCon(ctx)) {
            if (ptrace(PTRACE_ATTACH, tid, nullptr, nullptr) != -1) {
              goto wait_for_stop;
            }
          }
        }
      }
#if defined(PTRACE_SEIZE) && defined(PTRACE_INTERRUPT)
      if (perr == EPERM || perr == EBUSY) {
        if (ptrace(PTRACE_SEIZE, tid, nullptr, nullptr) != -1) {
          if (ptrace(PTRACE_INTERRUPT, tid, nullptr, nullptr) != -1) {
            goto wait_for_stop;
          }
          ptrace(PTRACE_DETACH, tid, nullptr, nullptr);
        }
      }
#endif
      if (err) {
        char buf[64] = {0};
        std::snprintf(buf, sizeof(buf), "ptrace attach tid=%d errno=%d", tid, perr);
        *err = buf;
      }
      LogAgent("[R3Agent] ptrace attach failed tid=%d errno=%d", tid, perr);
      if (perr == ESRCH) {
        if (ThreadExists(tid)) {
          if (err && err->empty()) {
            *err = "ptrace attach ESRCH but thread exists";
          }
          return false;
        }
        return true;
      }
      if (!is_main) {
        return true;
      }
      return false;
    }
wait_for_stop:
    if (!WaitForStop(tid, is_main ? 5000 : 200)) {
      const char state = ReadProcState(tid);
      if (state == 'T' || state == 't') {
        SetOptions(tid);
        attached_tids_.insert(tid);
        newly_attached_tids_.push_back(tid);
        return true;
      }
      ptrace(PTRACE_DETACH, tid, nullptr, nullptr);
      if (!is_main) {
        return true;
      }
      if (err && err->empty()) {
        *err = "ptrace wait stop failed";
      }
      return false;
    }
    SetOptions(tid);
    attached_tids_.insert(tid);
    newly_attached_tids_.push_back(tid);
    return true;
  }

  bool AttachAllThreadsLocked(std::string* err) {
    if (pid_ <= 0) {
      if (err) *err = "invalid pid";
      return false;
    }
    std::vector<pid_t> tids = ListThreads(pid_);
    if (tids.empty()) {
      tids.push_back(pid_);
    }
    LogAgent("[R3Agent] ptrace attach threads=%zu", tids.size());
    for (pid_t tid : tids) {
      if (!AttachThreadLocked(tid, err, tid == pid_)) {
        for (pid_t ntid : newly_attached_tids_) {
          ptrace(PTRACE_DETACH, ntid, nullptr, nullptr);
          attached_tids_.erase(ntid);
        }
        newly_attached_tids_.clear();
        attached_ = !attached_tids_.empty();
        return false;
      }
    }
    attached_ = !attached_tids_.empty();
    if (!attached_) {
      if (err && err->empty()) {
        *err = "ptrace attach skipped";
      }
      LogAgent("[R3Agent] ptrace attach none (all threads skipped)");
    }
    return attached_;
  }

  pid_t PickThreadLocked() const {
    if (!attached_tids_.empty()) {
      return *attached_tids_.begin();
    }
    return pid_;
  }

  void ContinueNewlyAttachedLocked() {
    for (pid_t tid : newly_attached_tids_) {
      ptrace(PTRACE_CONT, tid, nullptr, nullptr);
    }
    newly_attached_tids_.clear();
  }

  void DetachNewlyAttachedLocked() {
    for (pid_t tid : newly_attached_tids_) {
      ptrace(PTRACE_DETACH, tid, nullptr, nullptr);
      attached_tids_.erase(tid);
    }
    newly_attached_tids_.clear();
    if (attached_tids_.empty()) {
      attached_ = false;
      pid_ = 0;
    }
  }

  void PumpEventsLocked(uint32_t max_steps) {
    if (!attached_ || pid_ <= 0 || max_steps == 0) {
      return;
    }
    uint32_t steps = 0;
    while (steps < max_steps) {
      int status = 0;
      int wait_flags = WNOHANG;
#ifdef __WALL
      wait_flags |= __WALL;
#endif
      const pid_t tid = waitpid(-1, &status, wait_flags);
      if (tid == 0) {
        break;
      }
      if (tid < 0) {
        if (errno == EINTR) {
          continue;
        }
        break;
      }
      HandleStopLocked(tid, status);
      steps++;
    }
  }

  void HandleStopLocked(pid_t tid, int status) {
    if (attached_tids_.count(tid) == 0) {
      attached_tids_.insert(tid);
      SetOptions(tid);
    }
    if (WIFEXITED(status) || WIFSIGNALED(status)) {
      attached_tids_.erase(tid);
      if (attached_tids_.empty()) {
        attached_ = false;
        pid_ = 0;
        breakpoints_.clear();
      }
      return;
    }
    if (!WIFSTOPPED(status)) {
      return;
    }
    const int sig = WSTOPSIG(status);
    if (sig == SIGTRAP) {
      const int event = status >> 16;
#ifdef PTRACE_EVENT_CLONE
      if (event == PTRACE_EVENT_CLONE) {
        unsigned long new_tid = 0;
        if (ptrace(PTRACE_GETEVENTMSG, tid, nullptr, &new_tid) != -1 && new_tid > 0) {
          if (attached_tids_.count(static_cast<pid_t>(new_tid)) == 0) {
            attached_tids_.insert(static_cast<pid_t>(new_tid));
            SetOptions(static_cast<pid_t>(new_tid));
          }
          ptrace(PTRACE_CONT, static_cast<pid_t>(new_tid), nullptr, nullptr);
        }
        ptrace(PTRACE_CONT, tid, nullptr, nullptr);
        return;
      }
#endif
#ifdef PTRACE_EVENT_EXIT
      if (event == PTRACE_EVENT_EXIT) {
        ptrace(PTRACE_CONT, tid, nullptr, nullptr);
        return;
      }
#endif
#ifdef PTRACE_EVENT_EXEC
      if (event == PTRACE_EVENT_EXEC) {
        ptrace(PTRACE_CONT, tid, nullptr, nullptr);
        return;
      }
#endif
#ifdef PTRACE_EVENT_FORK
      if (event == PTRACE_EVENT_FORK) {
        ptrace(PTRACE_CONT, tid, nullptr, nullptr);
        return;
      }
#endif
#ifdef PTRACE_EVENT_VFORK
      if (event == PTRACE_EVENT_VFORK) {
        ptrace(PTRACE_CONT, tid, nullptr, nullptr);
        return;
      }
#endif
#ifdef PTRACE_EVENT_VFORK_DONE
      if (event == PTRACE_EVENT_VFORK_DONE) {
        ptrace(PTRACE_CONT, tid, nullptr, nullptr);
        return;
      }
#endif
      if (event != 0) {
        ptrace(PTRACE_CONT, tid, nullptr, nullptr);
        return;
      }
    } else {
      ptrace(PTRACE_CONT,
             tid,
             nullptr,
             reinterpret_cast<void*>(static_cast<intptr_t>(sig)));
      return;
    }

    uint64_t hit_addr = 0;
    uint64_t alt_addr = 0;
    struct user_pt_regs regs {};
    struct iovec iov;
    iov.iov_base = &regs;
    iov.iov_len = sizeof(regs);
    bool have_regs = (ptrace(PTRACE_GETREGSET, tid, (void*)NT_PRSTATUS, &iov) != -1);
#ifdef PTRACE_GETREGS
    if (!have_regs) {
      if (ptrace(PTRACE_GETREGS, tid, nullptr, &regs) != -1) {
        have_regs = true;
      }
    }
#endif
    if (!have_regs) {
      if (getreg_fail_log_count_ < 5) {
        LogAgent("[R3Agent] ptrace getregset failed tid=%d errno=%d", tid, errno);
        getreg_fail_log_count_++;
      }
      siginfo_t info {};
      if (ptrace(PTRACE_GETSIGINFO, tid, nullptr, &info) != -1 && info.si_addr) {
        const uint64_t info_addr = StripTag64(reinterpret_cast<uint64_t>(info.si_addr));
        for (auto& bp : breakpoints_) {
          if (bp.address == info_addr) {
            bp.hit_count++;
            if (hit_log_count_ < 5) {
              LogAgent("[R3Agent] ptrace hit (siginfo) addr=0x%llx tid=%d count=%llu",
                       static_cast<unsigned long long>(bp.address),
                       tid,
                       static_cast<unsigned long long>(bp.hit_count));
              hit_log_count_++;
            }
            break;
          }
        }
      }
      ptrace(PTRACE_CONT, tid, nullptr, nullptr);
      return;
    }
    const uint64_t pc = StripTag64(regs.pc);
    hit_addr = pc;
    alt_addr = (pc >= 4) ? (pc - 4) : pc;

    PtraceBreakpoint* hit_bp = nullptr;
    for (auto& bp : breakpoints_) {
      if (bp.address == hit_addr) {
        hit_bp = &bp;
        break;
      }
    }
    if (!hit_bp && alt_addr != hit_addr) {
      for (auto& bp : breakpoints_) {
        if (bp.address == alt_addr) {
          hit_bp = &bp;
          hit_addr = alt_addr;
          break;
        }
      }
    }
    if (!hit_bp) {
      if (miss_log_count_ < 5) {
        LogAgent("[R3Agent] ptrace trap addr=0x%llx tid=%d (untracked)",
                 static_cast<unsigned long long>(hit_addr),
                 tid);
        miss_log_count_++;
      }
      ptrace(PTRACE_CONT, tid, nullptr, nullptr);
      return;
    }

    RestoreInstruction(*hit_bp, tid);
    hit_bp->hit_count++;
    if (hit_log_count_ < 5) {
      LogAgent("[R3Agent] ptrace hit addr=0x%llx tid=%d count=%llu",
               static_cast<unsigned long long>(hit_addr),
               tid,
               static_cast<unsigned long long>(hit_bp->hit_count));
      hit_log_count_++;
    }
    regs.pc = hit_addr;
    ptrace(PTRACE_SETREGSET, tid, (void*)NT_PRSTATUS, &iov);

    ptrace(PTRACE_SINGLESTEP, tid, nullptr, nullptr);
    int status2 = 0;
    int wait_flags = 0;
#ifdef __WALL
    wait_flags |= __WALL;
#endif
    waitpid(tid, &status2, wait_flags);

    InsertBreakpoint(*hit_bp, tid);
    ptrace(PTRACE_CONT, tid, nullptr, nullptr);
  }

  void RestoreInstruction(const PtraceBreakpoint& bp, pid_t tid) {
    errno = 0;
    const uint64_t word_addr = bp.address & ~0x7ull;
    const bool upper = (bp.address & 0x4u) != 0;
    long data = ptrace(PTRACE_PEEKTEXT, tid, reinterpret_cast<void*>(word_addr), nullptr);
    if (data == -1 && errno != 0) {
      return;
    }
    const uint64_t word = static_cast<uint64_t>(data);
    uint64_t restored_word = word;
    if (upper) {
      restored_word = (word & 0x00000000FFFFFFFFull) |
                      (static_cast<uint64_t>(bp.original_insn) << 32);
    } else {
      restored_word = (word & 0xFFFFFFFF00000000ull) |
                      static_cast<uint64_t>(bp.original_insn);
    }
    ptrace(PTRACE_POKETEXT,
           tid,
           reinterpret_cast<void*>(word_addr),
           reinterpret_cast<void*>(static_cast<long>(restored_word)));
  }

  void InsertBreakpoint(const PtraceBreakpoint& bp, pid_t tid) {
    errno = 0;
    const uint64_t word_addr = bp.address & ~0x7ull;
    const bool upper = (bp.address & 0x4u) != 0;
    long data = ptrace(PTRACE_PEEKTEXT, tid, reinterpret_cast<void*>(word_addr), nullptr);
    if (data == -1 && errno != 0) {
      return;
    }
    const uint64_t word = static_cast<uint64_t>(data);
    uint64_t patched_word = word;
    if (upper) {
      patched_word = (word & 0x00000000FFFFFFFFull) |
                     (static_cast<uint64_t>(kAarch64BrkInsn) << 32);
    } else {
      patched_word = (word & 0xFFFFFFFF00000000ull) |
                     static_cast<uint64_t>(kAarch64BrkInsn);
    }
    ptrace(PTRACE_POKETEXT,
           tid,
           reinterpret_cast<void*>(word_addr),
           reinterpret_cast<void*>(static_cast<long>(patched_word)));
  }

  void DetachLocked() {
    if (attached_) {
      for (pid_t tid : attached_tids_) {
        ptrace(PTRACE_DETACH, tid, nullptr, nullptr);
      }
    }
    attached_ = false;
    pid_ = 0;
    bp_last_report_.clear();
    attached_tids_.clear();
    newly_attached_tids_.clear();
  }

  void ClearAllLocked() {
    const pid_t tid = PickThreadLocked();
    if (tid > 0) {
      for (auto& bp : breakpoints_) {
        RestoreInstruction(bp, tid);
      }
    }
    breakpoints_.clear();
    DetachLocked();
    hit_log_count_ = 0;
    miss_log_count_ = 0;
  }

  pid_t pid_ = 0;
  bool attached_ = false;
  std::vector<PtraceBreakpoint> breakpoints_;
  std::unordered_map<uint64_t, uint64_t> bp_last_report_;
  std::unordered_set<pid_t> attached_tids_;
  std::vector<pid_t> newly_attached_tids_;
  uint32_t ptrace_log_count_ = 0;
  uint64_t hit_log_count_ = 0;
  uint64_t miss_log_count_ = 0;
  uint32_t getreg_fail_log_count_ = 0;
  uint32_t tracer_log_count_ = 0;
  std::mutex mu_;
};
#else
class PtraceBreakpointManager {
 public:
  bool Set(pid_t, uint64_t, uint8_t, uint8_t, uint8_t, std::string* err) {
    if (err) *err = "ptrace breakpoints unsupported";
    return false;
  }
  bool Clear(pid_t, uint64_t, uint8_t, uint8_t) { return false; }
  void ClearAll() {}
  bool Poll(uint32_t, std::vector<protocol::DebugBreakpointEvent>* out) {
    if (out) out->clear();
    return false;
  }
  bool IsAttached(pid_t) const { return false; }
};
#endif

bool GetProcArch(pid_t pid, protocol::RegsArch* out_arch, uint8_t* out_ptr_size) {
  if (out_arch) {
    *out_arch = protocol::RegsArch::UNKNOWN;
  }
  if (out_ptr_size) {
    *out_ptr_size = 0;
  }
  if (pid <= 0) {
    return false;
  }
  char path[64] = {0};
  std::snprintf(path, sizeof(path), "/proc/%d/exe", pid);
  std::ifstream file(path, std::ios::binary);
  if (!file.is_open()) {
    return false;
  }

  Elf64_Ehdr hdr{};
  file.read(reinterpret_cast<char*>(&hdr), sizeof(hdr));
  if (file.gcount() < static_cast<std::streamsize>(offsetof(Elf64_Ehdr, e_machine) + sizeof(hdr.e_machine))) {
    return false;
  }
  if (std::memcmp(hdr.e_ident, ELFMAG, SELFMAG) != 0) {
    return false;
  }

  uint8_t ptr_size = 0;
  if (hdr.e_ident[EI_CLASS] == ELFCLASS64) {
    ptr_size = 8;
  } else if (hdr.e_ident[EI_CLASS] == ELFCLASS32) {
    ptr_size = 4;
  }
  if (out_ptr_size) {
    *out_ptr_size = ptr_size;
  }

  protocol::RegsArch arch = protocol::RegsArch::UNKNOWN;
  if (hdr.e_machine == EM_AARCH64) {
    arch = protocol::RegsArch::ARM64;
  } else if (hdr.e_machine == EM_ARM) {
    arch = protocol::RegsArch::ARM32;
  }
  if (out_arch) {
    *out_arch = arch;
  }
  return arch != protocol::RegsArch::UNKNOWN && ptr_size != 0;
}

bool SendPacketEx(int fd, protocol::CommandType cmd, const void* payload, uint32_t size, bool allow_compress) {
  protocol::PacketHeader header{};
  header.magic = protocol::kMagic;
  header.command = static_cast<uint16_t>(cmd);
  header.reserved = 0;
  header.data_size = size;

  std::vector<uint8_t> compressed;
  protocol::CompressionType algo = protocol::COMPRESS_NONE;
  if (allow_compress &&
      size > 0 &&
      protocol::CompressPayloadIfUseful(static_cast<const uint8_t*>(payload),
                                        size,
                                        &compressed,
                                        &algo)) {
    const size_t comp_header = offsetof(protocol::CompressedPayloadHeader, data);
    const size_t total = comp_header + compressed.size();
    std::vector<uint8_t> out(total);
    auto* comp = reinterpret_cast<protocol::CompressedPayloadHeader*>(out.data());
    comp->raw_size = size;
    comp->algorithm = static_cast<uint16_t>(algo);
    comp->reserved = 0;
    std::memcpy(comp->data, compressed.data(), compressed.size());
    header.reserved = protocol::PACKET_FLAG_COMPRESSED;
    header.data_size = static_cast<uint32_t>(out.size());
    if (!WriteAll(fd, &header, sizeof(header))) {
      return false;
    }
    return WriteAll(fd, out.data(), out.size());
  }

  if (!WriteAll(fd, &header, sizeof(header))) {
    return false;
  }
  if (size == 0) {
    return true;
  }
  return WriteAll(fd, payload, size);
}

bool SendPacket(int fd, protocol::CommandType cmd, const void* payload, uint32_t size) {
  // Android-side override: disable response compression globally.
  return SendPacketEx(fd, cmd, payload, size, false);
}

bool SendPacketRaw(int fd, protocol::CommandType cmd, const void* payload, uint32_t size) {
  return SendPacketEx(fd, cmd, payload, size, false);
}

using ProcessVmReadvFn = ssize_t (*)(pid_t,
                                     const struct iovec*,
                                     unsigned long,
                                     const struct iovec*,
                                     unsigned long,
                                     unsigned long);

ProcessVmReadvFn ResolveProcessVmReadv() {
  static ProcessVmReadvFn fn = nullptr;
  static bool initialized = false;
  if (!initialized) {
    initialized = true;
    fn = reinterpret_cast<ProcessVmReadvFn>(dlsym(RTLD_DEFAULT, "process_vm_readv"));
  }
  return fn;
}

ssize_t ProcessVmReadvCompat(pid_t pid,
                             const struct iovec* local_iov,
                             unsigned long liovcnt,
                             const struct iovec* remote_iov,
                             unsigned long riovcnt,
                             unsigned long flags) {
  if (auto fn = ResolveProcessVmReadv()) {
    return fn(pid, local_iov, liovcnt, remote_iov, riovcnt, flags);
  }
#if defined(__NR_process_vm_readv)
  return syscall(__NR_process_vm_readv, pid, local_iov, liovcnt, remote_iov, riovcnt, flags);
#else
  errno = ENOSYS;
  return -1;
#endif
}

struct MapEntry {
  uint64_t start = 0;
  uint64_t end = 0;
  std::string perms;
  std::string path;
};
bool SendStatus(int fd, protocol::CommandType cmd, int32_t code);
size_t ValueSizeForType(protocol::ValueType type);
bool ReadViaProcessVm(pid_t pid,
                      uint64_t addr,
                      void* out,
                      size_t size,
                      SafeMemoryReader::ReadStats* stats);
bool IsDigits(const char* text);
std::string ReadCmdline(pid_t pid);
std::string ReadComm(pid_t pid);
void AppendBytes(std::vector<uint8_t>* out, const void* data, size_t size);
bool ParseMapsLineSimple(const std::string& line, MapEntry* out);
uint32_t PermsToFlags(const std::string& perms);
bool LoadProcessIconPng(pid_t pid, uint32_t desired_size, std::vector<uint8_t>* out_png);
bool AttachDebugger(pid_t pid);
bool DetachDebugger(pid_t pid);
bool GetArm64Regs(pid_t pid, protocol::Arm64Regs* out, bool already_attached, bool keep_stopped);
bool GetArm32Regs(pid_t pid, protocol::Arm32Regs* out, bool already_attached, bool keep_stopped);
#if defined(__aarch64__)
bool GetRegsAarch64(pid_t pid,
                    bool already_attached,
                    bool keep_stopped,
                    protocol::RegsArch* arch,
                    protocol::Arm64Regs* out64,
                    protocol::Arm32Regs* out32);
#endif

uint16_t ReadLe16(const uint8_t* p) {
  return static_cast<uint16_t>(p[0]) |
         static_cast<uint16_t>(static_cast<uint16_t>(p[1]) << 8);
}

uint32_t ReadLe32(const uint8_t* p) {
  return static_cast<uint32_t>(p[0]) |
         (static_cast<uint32_t>(p[1]) << 8) |
         (static_cast<uint32_t>(p[2]) << 16) |
         (static_cast<uint32_t>(p[3]) << 24);
}

bool ReadFileAt(std::ifstream* file, uint64_t offset, void* out, size_t size) {
  if (!file || !out || size == 0) {
    return false;
  }
  file->clear();
  file->seekg(static_cast<std::streamoff>(offset), std::ios::beg);
  if (!file->good()) {
    return false;
  }
  file->read(reinterpret_cast<char*>(out), static_cast<std::streamsize>(size));
  return file->gcount() == static_cast<std::streamsize>(size);
}

bool StartsWithAscii(const std::string& text, const char* prefix) {
  if (!prefix) {
    return false;
  }
  return text.rfind(prefix, 0) == 0;
}

std::string ToLowerAsciiLocal(std::string text) {
  std::transform(text.begin(), text.end(), text.begin(), [](unsigned char ch) {
    return static_cast<char>(std::tolower(ch));
  });
  return text;
}

bool EndsWithAsciiCi(const std::string& text, const char* suffix) {
  if (!suffix) {
    return false;
  }
  const std::string lower = ToLowerAsciiLocal(text);
  const std::string suf = ToLowerAsciiLocal(std::string(suffix));
  if (lower.size() < suf.size()) {
    return false;
  }
  return lower.compare(lower.size() - suf.size(), suf.size(), suf) == 0;
}

std::string TrimCopy(const std::string& text) {
  size_t begin = 0;
  while (begin < text.size() &&
         (text[begin] == ' ' || text[begin] == '\t' || text[begin] == '\r' || text[begin] == '\n')) {
    ++begin;
  }
  size_t end = text.size();
  while (end > begin &&
         (text[end - 1] == ' ' || text[end - 1] == '\t' || text[end - 1] == '\r' || text[end - 1] == '\n')) {
    --end;
  }
  return text.substr(begin, end - begin);
}

std::string NormalizeMappedApkPath(const std::string& raw_path) {
  std::string path = TrimCopy(raw_path);
  if (path.empty() || path[0] != '/') {
    return {};
  }
  static constexpr const char kDeletedSuffix[] = " (deleted)";
  if (EndsWithAsciiCi(path, kDeletedSuffix)) {
    path.resize(path.size() - (sizeof(kDeletedSuffix) - 1));
  }
  if (!EndsWithAsciiCi(path, ".apk")) {
    return {};
  }
  return path;
}

int ApkPathScore(const std::string& path) {
  if (path.empty()) {
    return -1;
  }
  const std::string lower = ToLowerAsciiLocal(path);
  int score = 0;
  if (EndsWithAsciiCi(lower, "/base.apk")) {
    score += 1000;
  }
  if (StartsWithAscii(lower, "/data/app/")) {
    score += 600;
  } else if (StartsWithAscii(lower, "/system_ext/")) {
    score += 420;
  } else if (StartsWithAscii(lower, "/product/")) {
    score += 400;
  } else if (StartsWithAscii(lower, "/system/")) {
    score += 380;
  } else if (StartsWithAscii(lower, "/vendor/")) {
    score += 360;
  }
  if (lower.find("/dalvik-cache/") != std::string::npos) {
    score -= 500;
  }
  if (lower.find("@classes.") != std::string::npos) {
    score -= 500;
  }
  return score;
}

bool IsPngBytes(const std::vector<uint8_t>& data) {
  static const uint8_t sig[8] = {0x89u, 0x50u, 0x4Eu, 0x47u, 0x0Du, 0x0Au, 0x1Au, 0x0Au};
  return data.size() >= 8 && std::memcmp(data.data(), sig, sizeof(sig)) == 0;
}

std::string PrimaryProcessNameFromCmdline(const std::string& cmdline) {
  std::string name = TrimCopy(cmdline);
  if (name.empty()) {
    return {};
  }
  const size_t space = name.find(' ');
  if (space != std::string::npos) {
    name.resize(space);
  }
  const size_t colon = name.find(':');
  if (colon != std::string::npos) {
    name.resize(colon);
  }
  return TrimCopy(name);
}

bool IsLikelyPackageName(const std::string& name) {
  if (name.size() < 3 || name.find('.') == std::string::npos) {
    return false;
  }
  for (char ch : name) {
    const bool ok = (ch >= 'a' && ch <= 'z') ||
                    (ch >= 'A' && ch <= 'Z') ||
                    (ch >= '0' && ch <= '9') ||
                    ch == '.' || ch == '_';
    if (!ok) {
      return false;
    }
  }
  return true;
}

std::unordered_map<std::string, std::string>& PackageApkPathCache() {
  static std::unordered_map<std::string, std::string> cache;
  return cache;
}

std::mutex& PackageApkPathCacheMutex() {
  static std::mutex mu;
  return mu;
}

std::string FindApkPathByPackageName(const std::string& package_name) {
  if (!IsLikelyPackageName(package_name)) {
    return {};
  }
  {
    std::lock_guard<std::mutex> lock(PackageApkPathCacheMutex());
    const auto it = PackageApkPathCache().find(package_name);
    if (it != PackageApkPathCache().end() && !it->second.empty() && access(it->second.c_str(), R_OK) == 0) {
      return it->second;
    }
  }

  std::string cmd = "cmd package path ";
  cmd.append(package_name);
  cmd.append(" 2>/dev/null");
  FILE* fp = popen(cmd.c_str(), "r");
  if (!fp) {
    return {};
  }
  std::string best_path;
  int best_score = -1;
  char buf[1024] = {0};
  while (std::fgets(buf, sizeof(buf), fp)) {
    std::string line = TrimCopy(buf);
    if (line.empty()) {
      continue;
    }
    if (StartsWithAscii(line, "package:")) {
      line = line.substr(8);
      line = TrimCopy(line);
    }
    const std::string normalized = NormalizeMappedApkPath(line);
    if (normalized.empty()) {
      continue;
    }
    const int score = ApkPathScore(normalized);
    if (score > best_score) {
      best_score = score;
      best_path = normalized;
    }
  }
  pclose(fp);
  if (!best_path.empty()) {
    std::lock_guard<std::mutex> lock(PackageApkPathCacheMutex());
    PackageApkPathCache()[package_name] = best_path;
  }
  return best_path;
}

std::string FindApkPathForPid(pid_t pid, std::string* out_package_name) {
  if (pid <= 0) {
    return {};
  }
  if (out_package_name) {
    out_package_name->clear();
  }
  const std::string cmdline = ReadCmdline(pid);
  const std::string package_name = PrimaryProcessNameFromCmdline(cmdline);
  if (out_package_name) {
    *out_package_name = package_name;
  }
  if (IsLikelyPackageName(package_name)) {
    const std::string pm_path = FindApkPathByPackageName(package_name);
    if (!pm_path.empty()) {
      return pm_path;
    }
  }
  char path[64] = {0};
  std::snprintf(path, sizeof(path), "/proc/%d/maps", pid);
  std::ifstream file(path);
  if (!file.is_open()) {
    return {};
  }
  std::string line;
  std::string best_path;
  int best_score = -1;
  while (std::getline(file, line)) {
    MapEntry entry{};
    if (!ParseMapsLineSimple(line, &entry)) {
      continue;
    }
    if (entry.path.empty() || entry.path.find(".apk") == std::string::npos) {
      continue;
    }
    const std::string candidate = NormalizeMappedApkPath(entry.path);
    if (candidate.empty()) {
      continue;
    }
    if (access(candidate.c_str(), R_OK) != 0) {
      continue;
    }
    const int score = ApkPathScore(candidate);
    if (score > best_score) {
      best_score = score;
      best_path = candidate;
    }
  }
  return best_path;
}

int ApkDensityBonus(const std::string& lower_name) {
  if (lower_name.find("xxxhdpi") != std::string::npos) return 80;
  if (lower_name.find("xxhdpi") != std::string::npos) return 70;
  if (lower_name.find("xhdpi") != std::string::npos) return 60;
  if (lower_name.find("hdpi") != std::string::npos) return 50;
  if (lower_name.find("mdpi") != std::string::npos) return 40;
  if (lower_name.find("ldpi") != std::string::npos) return 30;
  if (lower_name.find("nodpi") != std::string::npos) return 20;
  return 0;
}

int ApkIconEntryScore(const std::string& entry_name) {
  const std::string lower = ToLowerAsciiLocal(entry_name);
  if (!EndsWithAsciiCi(lower, ".png")) {
    return -1;
  }
  int score = 10;
  if (lower.find("res/mipmap") != std::string::npos) score += 180;
  if (lower.find("res/drawable") != std::string::npos) score += 120;
  if (lower.find("ic_launcher") != std::string::npos) score += 260;
  if (lower.find("launcher") != std::string::npos) score += 120;
  if (lower.find("app_icon") != std::string::npos) score += 100;
  score += ApkDensityBonus(lower);
  if (lower.find("foreground") != std::string::npos) score -= 180;
  if (lower.find("background") != std::string::npos) score -= 180;
  if (lower.find("monochrome") != std::string::npos) score -= 120;
  if (lower.find("notification") != std::string::npos) score -= 120;
  if (lower.find("round") != std::string::npos) score += 10;
  return score;
}

struct ApkZipEntry {
  std::string name;
  uint16_t method = 0;
  uint32_t comp_size = 0;
  uint32_t uncomp_size = 0;
  uint32_t local_offset = 0;
};

bool FindZipCentralDirectory(std::ifstream* file,
                             uint64_t file_size,
                             uint32_t* out_cd_offset,
                             uint32_t* out_cd_size) {
  if (!file || file_size < 22) {
    return false;
  }
  const size_t max_tail = 0x10000u + 22u;
  const size_t tail_size = static_cast<size_t>(std::min<uint64_t>(file_size, max_tail));
  std::vector<uint8_t> tail(tail_size);
  if (!ReadFileAt(file, file_size - tail_size, tail.data(), tail.size())) {
    return false;
  }
  static constexpr uint32_t kEocdSig = 0x06054B50u;
  for (size_t pos = tail_size - 22 + 1; pos-- > 0;) {
    if (ReadLe32(tail.data() + pos) != kEocdSig) {
      continue;
    }
    const uint32_t cd_size = ReadLe32(tail.data() + pos + 12);
    const uint32_t cd_offset = ReadLe32(tail.data() + pos + 16);
    if (static_cast<uint64_t>(cd_offset) + static_cast<uint64_t>(cd_size) > file_size) {
      continue;
    }
    if (out_cd_offset) {
      *out_cd_offset = cd_offset;
    }
    if (out_cd_size) {
      *out_cd_size = cd_size;
    }
    return true;
  }
  return false;
}

bool FindBestIconEntry(std::ifstream* file,
                       uint32_t cd_offset,
                       uint32_t cd_size,
                       ApkZipEntry* out_entry) {
  if (!file || !out_entry) {
    return false;
  }
  static constexpr uint32_t kCenSig = 0x02014B50u;
  const uint64_t cd_begin = cd_offset;
  const uint64_t cd_end = cd_begin + cd_size;
  uint64_t off = cd_begin;
  int best_score = -1;
  ApkZipEntry best{};

  while (off + 46 <= cd_end) {
    uint8_t hdr[46] = {0};
    if (!ReadFileAt(file, off, hdr, sizeof(hdr))) {
      break;
    }
    if (ReadLe32(hdr) != kCenSig) {
      break;
    }
    const uint16_t method = ReadLe16(hdr + 10);
    const uint32_t comp_size = ReadLe32(hdr + 20);
    const uint32_t uncomp_size = ReadLe32(hdr + 24);
    const uint16_t name_len = ReadLe16(hdr + 28);
    const uint16_t extra_len = ReadLe16(hdr + 30);
    const uint16_t comment_len = ReadLe16(hdr + 32);
    const uint32_t local_offset = ReadLe32(hdr + 42);
    const uint64_t item_size = 46ull + name_len + extra_len + comment_len;
    if (off + item_size > cd_end) {
      break;
    }
    std::string name(static_cast<size_t>(name_len), '\0');
    if (name_len > 0 && !ReadFileAt(file, off + 46, name.data(), name_len)) {
      break;
    }
    const int score = ApkIconEntryScore(name);
    if (score >= 0 &&
        (method == 0 || method == 8) &&
        comp_size > 0 &&
        comp_size <= kMaxProcessIconBytes &&
        uncomp_size <= (kMaxProcessIconBytes * 2u)) {
      if (score > best_score) {
        best_score = score;
        best.name = std::move(name);
        best.method = method;
        best.comp_size = comp_size;
        best.uncomp_size = uncomp_size;
        best.local_offset = local_offset;
      }
    }
    off += item_size;
  }

  if (best_score < 0) {
    return false;
  }
  *out_entry = std::move(best);
  return true;
}

bool InflateZipDeflate(const std::vector<uint8_t>& compressed,
                       uint32_t expected_size,
                       std::vector<uint8_t>* out_data) {
  if (!out_data) {
    return false;
  }
  out_data->clear();
  if (compressed.empty()) {
    return false;
  }
  size_t cap = expected_size > 0 ? expected_size : (compressed.size() * 4 + 4096);
  cap = std::min<size_t>(cap, kMaxProcessIconBytes);
  if (cap < 1024) {
    cap = 1024;
  }
  out_data->resize(cap);

  z_stream zs{};
  zs.next_in = const_cast<Bytef*>(reinterpret_cast<const Bytef*>(compressed.data()));
  zs.avail_in = static_cast<uInt>(compressed.size());
  if (inflateInit2(&zs, -MAX_WBITS) != Z_OK) {
    out_data->clear();
    return false;
  }

  int ret = Z_OK;
  while (ret == Z_OK) {
    if (zs.total_out >= out_data->size()) {
      size_t next_cap = out_data->size() * 2;
      if (next_cap <= out_data->size() || next_cap > kMaxProcessIconBytes) {
        inflateEnd(&zs);
        out_data->clear();
        return false;
      }
      out_data->resize(next_cap);
    }
    zs.next_out = reinterpret_cast<Bytef*>(out_data->data() + zs.total_out);
    zs.avail_out = static_cast<uInt>(out_data->size() - zs.total_out);
    ret = inflate(&zs, Z_NO_FLUSH);
  }
  if (ret != Z_STREAM_END) {
    inflateEnd(&zs);
    out_data->clear();
    return false;
  }
  out_data->resize(zs.total_out);
  inflateEnd(&zs);
  return !out_data->empty();
}

bool ReadZipEntryPayload(std::ifstream* file, const ApkZipEntry& entry, std::vector<uint8_t>* out_data) {
  if (!file || !out_data) {
    return false;
  }
  out_data->clear();
  if (entry.comp_size == 0 || entry.comp_size > kMaxProcessIconBytes) {
    return false;
  }
  uint8_t lfh[30] = {0};
  if (!ReadFileAt(file, entry.local_offset, lfh, sizeof(lfh))) {
    return false;
  }
  static constexpr uint32_t kLfhSig = 0x04034B50u;
  if (ReadLe32(lfh) != kLfhSig) {
    return false;
  }
  const uint16_t name_len = ReadLe16(lfh + 26);
  const uint16_t extra_len = ReadLe16(lfh + 28);
  const uint64_t data_off = static_cast<uint64_t>(entry.local_offset) + 30ull + name_len + extra_len;

  std::vector<uint8_t> compressed(entry.comp_size);
  if (!ReadFileAt(file, data_off, compressed.data(), compressed.size())) {
    return false;
  }
  if (entry.method == 0) {
    *out_data = std::move(compressed);
    return true;
  }
  if (entry.method == 8) {
    return InflateZipDeflate(compressed, entry.uncomp_size, out_data);
  }
  return false;
}

bool LoadProcessIconPng(pid_t pid, uint32_t desired_size, std::vector<uint8_t>* out_png) {
  (void)desired_size;
  if (!out_png) {
    return false;
  }
  out_png->clear();
  std::string package_name;
  const std::string apk_path = FindApkPathForPid(pid, &package_name);
  if (apk_path.empty()) {
    return false;
  }
  const std::string cache_key = !package_name.empty() ? package_name : apk_path;
  static std::unordered_map<std::string, std::vector<uint8_t>> icon_cache;
  static std::mutex icon_cache_mu;
  {
    std::lock_guard<std::mutex> lock(icon_cache_mu);
    const auto it = icon_cache.find(cache_key);
    if (it != icon_cache.end() && !it->second.empty()) {
      *out_png = it->second;
      return true;
    }
  }
  std::ifstream file(apk_path, std::ios::binary);
  if (!file.is_open()) {
    return false;
  }
  file.seekg(0, std::ios::end);
  const uint64_t file_size = static_cast<uint64_t>(file.tellg());
  if (file_size < 22) {
    return false;
  }

  uint32_t cd_offset = 0;
  uint32_t cd_size = 0;
  if (!FindZipCentralDirectory(&file, file_size, &cd_offset, &cd_size)) {
    return false;
  }

  ApkZipEntry icon_entry{};
  if (!FindBestIconEntry(&file, cd_offset, cd_size, &icon_entry)) {
    return false;
  }

  std::vector<uint8_t> payload;
  if (!ReadZipEntryPayload(&file, icon_entry, &payload)) {
    return false;
  }
  if (!IsPngBytes(payload) || payload.size() > kMaxProcessIconBytes) {
    return false;
  }
  {
    std::lock_guard<std::mutex> lock(icon_cache_mu);
    icon_cache[cache_key] = payload;
  }
  *out_png = std::move(payload);
  return true;
}

void HandleClient(int client_fd) {
  LogAgent("[R3Agent] client connected fd=%d", client_fd);
  std::unique_ptr<SafeMemoryReader> reader;
  MemoryScanner scanner(nullptr);
  PerfBreakpointManager perf_bp_mgr;
  PtraceBreakpointManager ptrace_bp_mgr;
  bool debug_attached = false;
  pid_t debug_pid = 0;
  bool debug_sigstop = false;
  bool debug_sigstop_sent = false;
  std::vector<protocol::PointerIndexEntry> pointer_index;
  uint16_t pointer_index_pointer_size = 0;
  uint32_t pointer_index_pid = 0;
  uint32_t readable_cache_pid = 0;
  std::vector<std::pair<uint64_t, uint64_t>> readable_ranges;

  auto InvalidateReadableCache = [&]() {
    readable_cache_pid = 0;
    readable_ranges.clear();
  };

  auto RefreshReadableCache = [&]() -> bool {
    if (!reader) {
      return false;
    }
    const uint32_t pid = static_cast<uint32_t>(reader->pid());
    if (readable_cache_pid == pid && !readable_ranges.empty()) {
      return true;
    }
    if (reader->regions().empty() && !reader->RefreshMaps()) {
      return false;
    }
    readable_ranges.clear();
    readable_ranges.reserve(reader->regions().size());
    for (const auto& region : reader->regions()) {
      if (!region.readable || region.end <= region.start) {
        continue;
      }
      readable_ranges.push_back({region.start, region.end});
    }
    if (!readable_ranges.empty()) {
      std::sort(readable_ranges.begin(), readable_ranges.end(),
                [](const std::pair<uint64_t, uint64_t>& a,
                   const std::pair<uint64_t, uint64_t>& b) {
                  return a.first < b.first;
                });
      size_t write = 0;
      for (size_t i = 0; i < readable_ranges.size(); ++i) {
        if (write == 0 || readable_ranges[i].first > readable_ranges[write - 1].second) {
          readable_ranges[write++] = readable_ranges[i];
        } else if (readable_ranges[i].second > readable_ranges[write - 1].second) {
          readable_ranges[write - 1].second = readable_ranges[i].second;
        }
      }
      readable_ranges.resize(write);
    }
    readable_cache_pid = pid;
    return true;
  };

  auto HasReadableOverlap = [&](uint64_t start, uint64_t end) -> bool {
    if (end <= start || readable_ranges.empty()) {
      return false;
    }
    auto it = std::lower_bound(readable_ranges.begin(),
                               readable_ranges.end(),
                               start,
                               [](const std::pair<uint64_t, uint64_t>& item, uint64_t value) {
                                 return item.second <= value;
                               });
    return it != readable_ranges.end() && it->first < end && it->second > start;
  };

  auto ReadMemoryCommon = [&](uint64_t address,
                              uint32_t size,
                              uint32_t flags,
                              uint8_t* out,
                              SafeMemoryReader::ReadStats* out_stats) -> bool {
    if (!reader || !out || !out_stats) {
      return false;
    }
    *out_stats = SafeMemoryReader::ReadStats{};
    out_stats->bytes_requested = size;
    if (size == 0) {
      return true;
    }
    if (address > UINT64_MAX - static_cast<uint64_t>(size)) {
      return false;
    }

    const bool allow_nonresident = (flags & protocol::READ_FLAG_ALLOW_NONRESIDENT) != 0;
    const bool ignore_perms = (flags & protocol::READ_FLAG_IGNORE_PERMS) != 0;
    const bool use_pvm = (flags & protocol::READ_FLAG_USE_PVM) != 0;

    if (use_pvm) {
      if (!ignore_perms) {
        if (!RefreshReadableCache()) {
          return false;
        }
        const uint64_t end = address + static_cast<uint64_t>(size);
        if (!HasReadableOverlap(address, end)) {
          out_stats->bytes_read = 0;
          out_stats->bytes_skipped = size;
          out_stats->pages_checked = 0;
          out_stats->pages_skipped = 0;
          out_stats->last_errno = 0;
          return true;
        }
      }
      return ReadViaProcessVm(reader->pid(), address, out, size, out_stats);
    }

    const bool fast_mode = allow_nonresident && !ignore_perms;
    return reader->ValidateAndReadEx(address,
                                     out,
                                     size,
                                     out_stats,
                                     allow_nonresident,
                                     ignore_perms,
                                     false,
                                     fast_mode);
  };

  while (true) {
    protocol::PacketHeader header{};
    if (!ReadAll(client_fd, &header, sizeof(header))) {
      break;
    }
    if (header.magic != protocol::kMagic) {
      break;
    }
    if (header.data_size > kMaxPayload) {
      break;
    }

    std::vector<uint8_t> payload(header.data_size);
    if (header.data_size > 0) {
      if (!ReadAll(client_fd, payload.data(), payload.size())) {
        break;
      }
    }
    if ((header.reserved & protocol::PACKET_FLAG_COMPRESSED) != 0) {
      if (payload.size() < offsetof(protocol::CompressedPayloadHeader, data)) {
        break;
      }
      const auto* comp = reinterpret_cast<const protocol::CompressedPayloadHeader*>(payload.data());
      const size_t raw_size = comp->raw_size;
      if (raw_size > kMaxPayload) {
        break;
      }
      const size_t comp_size = payload.size() - offsetof(protocol::CompressedPayloadHeader, data);
      std::vector<uint8_t> raw;
      if (!protocol::DecompressPayload(static_cast<protocol::CompressionType>(comp->algorithm),
                                       comp->data,
                                       comp_size,
                                       raw_size,
                                       &raw)) {
        break;
      }
      payload.swap(raw);
    }

    const auto cmd = static_cast<protocol::CommandType>(header.command);
    switch (cmd) {
      case protocol::CommandType::CMD_PING: {
        SendStatus(client_fd, cmd, 0);
        break;
      }
      case protocol::CommandType::CMD_ATTACH: {
        if (payload.size() < sizeof(protocol::AttachRequest)) {
          SendStatus(client_fd, cmd, -1);
          break;
        }
        const auto* req = reinterpret_cast<const protocol::AttachRequest*>(payload.data());
        reader = std::make_unique<SafeMemoryReader>(static_cast<pid_t>(req->pid));
        bool ok = reader->Open() && reader->RefreshMaps();
        InvalidateReadableCache();
        if (!ok) {
          LogAgent("[R3Agent] attach failed pid=%d", req->pid);
        } else {
          LogAgent("[R3Agent] attach ok pid=%d regions=%zu", req->pid, reader->regions().size());
        }
        scanner.SetReader(reader.get());
        scanner.Clear();
        SendStatus(client_fd, cmd, StatusCode(ok));
        break;
      }
      case protocol::CommandType::CMD_SCAN_FIRST:
      case protocol::CommandType::CMD_SCAN_NEXT: {
        if (!reader) {
          SendStatus(client_fd, cmd, -1);
          break;
        }
        const size_t header_size = offsetof(protocol::ScanRequest, data);
        if (payload.size() < header_size) {
          SendStatus(client_fd, cmd, -1);
          break;
        }
        const auto* req = reinterpret_cast<const protocol::ScanRequest*>(payload.data());
        const size_t value_len = req->value_len;
        if (payload.size() < header_size + value_len) {
          SendStatus(client_fd, cmd, -1);
          break;
        }

        const auto value_type = static_cast<protocol::ValueType>(req->value_type);
        const auto condition = static_cast<protocol::ComparisonType>(req->comparison_type);
        const size_t type_size = ValueSizeForType(value_type);
        if (type_size == 0 || value_len < type_size) {
          SendStatus(client_fd, cmd, -1);
          break;
        }

        scanner.SetScanRange(req->start_addr, req->end_addr);
        const bool use_pvm = (req->reserved & protocol::SCAN_FLAG_USE_PVM) != 0;
        const bool allow_nonresident = (req->reserved & protocol::SCAN_FLAG_ALLOW_NONRESIDENT) != 0;
        const bool byte_step = (req->reserved & protocol::SCAN_FLAG_BYTE_STEP) != 0;
        const bool strict = (req->reserved & protocol::SCAN_FLAG_STRICT) != 0;
        const bool require_writable = (req->reserved & protocol::SCAN_FLAG_REQUIRE_WRITABLE) != 0;
        const bool require_exec = (req->reserved & protocol::SCAN_FLAG_REQUIRE_EXEC) != 0;
        const bool require_private = (req->reserved & protocol::SCAN_FLAG_REQUIRE_PRIVATE) != 0;
        const bool require_image = (req->reserved & protocol::SCAN_FLAG_REQUIRE_IMAGE) != 0;
        const bool require_mapped = (req->reserved & protocol::SCAN_FLAG_REQUIRE_MAPPED) != 0;
        uint8_t type_mask = 0;
        if (require_private) type_mask |= 1u;
        if (require_image) type_mask |= 2u;
        if (require_mapped) type_mask |= 4u;
        const uint8_t gg_code =
            static_cast<uint8_t>((req->reserved & protocol::SCAN_FLAG_GG_MASK) >> protocol::SCAN_FLAG_GG_SHIFT);
        scanner.SetUsePvm(use_pvm);
        scanner.SetAllowNonresident(allow_nonresident);
        scanner.SetByteStep(byte_step);
        scanner.SetStrict(strict);
        scanner.SetRequireWritable(require_writable);
        scanner.SetRequireExecutable(require_exec);
        scanner.SetRegionTypeMask(type_mask);
        scanner.SetGGRegionCode(gg_code);

        if (strict) {
          if (!allow_nonresident || !byte_step) {
            SendStatus(client_fd, cmd, -1);
            break;
          }
        }

        const auto scan_begin = std::chrono::steady_clock::now();
        bool ok = false;
        if (cmd == protocol::CommandType::CMD_SCAN_FIRST) {
          ok = scanner.FirstScan(value_type, req->data, value_len, condition);
        } else {
          ok = scanner.NextScan(value_type, req->data, value_len, condition);
        }
        const auto scan_end = std::chrono::steady_clock::now();
        const double scan_ms =
            std::chrono::duration<double, std::milli>(scan_end - scan_begin).count();

        if (!ok) {
          LogAgent("[R3Agent] scan failed cmd=%u type=%u cond=%u flags=0x%X ms=%.3f",
                   static_cast<unsigned>(cmd),
                   static_cast<unsigned>(value_type),
                   static_cast<unsigned>(condition),
                   static_cast<unsigned>(req->reserved),
                   scan_ms);
          SendStatus(client_fd, cmd, -1);
          break;
        }

        const auto& results = scanner.results();
        const size_t total = results.size();
        const size_t returned = std::min(total, kMaxScanReturn);
        const size_t payload_size = sizeof(uint64_t) + returned * sizeof(uint64_t);

        std::vector<uint8_t> out(payload_size);
        uint64_t count = static_cast<uint64_t>(total);
        std::memcpy(out.data(), &count, sizeof(count));
        if (returned > 0) {
          std::memcpy(out.data() + sizeof(uint64_t), results.data(), returned * sizeof(uint64_t));
        }
        LogAgent("[R3Agent] scan ok cmd=%u type=%u cond=%u flags=0x%X total=%zu ms=%.3f",
                 static_cast<unsigned>(cmd),
                 static_cast<unsigned>(value_type),
                 static_cast<unsigned>(condition),
                 static_cast<unsigned>(req->reserved),
                 total,
                 scan_ms);
        SendPacket(client_fd, cmd, out.data(), static_cast<uint32_t>(out.size()));
        break;
      }
      case protocol::CommandType::CMD_SCAN_PAGE: {
        if (!reader) {
          SendStatus(client_fd, cmd, -1);
          break;
        }
        if (payload.size() < sizeof(protocol::ScanPageRequest)) {
          SendStatus(client_fd, cmd, -1);
          break;
        }
        const auto* req = reinterpret_cast<const protocol::ScanPageRequest*>(payload.data());
        const auto& results = scanner.results();
        const size_t total = results.size();
        size_t start = static_cast<size_t>(req->start_index);
        if (start > total) {
          start = total;
        }
        size_t max_count = req->max_count == 0 ? kMaxScanReturn : req->max_count;
        if (max_count > kMaxScanReturn) {
          max_count = kMaxScanReturn;
        }
        const size_t returned = std::min(max_count, total - start);

        const size_t payload_size = sizeof(uint64_t) + returned * sizeof(uint64_t);
        std::vector<uint8_t> out(payload_size);
        uint64_t count = static_cast<uint64_t>(total);
        std::memcpy(out.data(), &count, sizeof(count));
        if (returned > 0) {
          std::memcpy(out.data() + sizeof(uint64_t),
                      results.data() + start,
                      returned * sizeof(uint64_t));
        }
        SendPacket(client_fd, cmd, out.data(), static_cast<uint32_t>(out.size()));
        break;
      }
      case protocol::CommandType::CMD_READ_MEM: {
        if (!reader) {
          SendStatus(client_fd, cmd, -1);
          break;
        }
        if (payload.size() < sizeof(protocol::ReadMemRequest)) {
          SendStatus(client_fd, cmd, -1);
          break;
        }
        const auto* req = reinterpret_cast<const protocol::ReadMemRequest*>(payload.data());
        uint32_t size = req->size;
        if (size > kMaxReadSize) {
          size = kMaxReadSize;
        }

        std::vector<uint8_t> data(size, 0);
        SafeMemoryReader::ReadStats stats{};
        const bool no_compress = (req->reserved & protocol::READ_FLAG_NO_COMPRESS) != 0;
        const auto read_begin = std::chrono::steady_clock::now();

        const bool ok = ReadMemoryCommon(req->address,
                                         size,
                                         req->reserved,
                                         data.data(),
                                         &stats);

        if (!ok) {
          LogAgent("[R3Agent] read failed pid=%d addr=0x%llX size=%u flags=0x%X errno=%d read=%zu skip=%zu",
                   reader->pid(),
                   static_cast<unsigned long long>(req->address),
                   size,
                   req->reserved,
                   stats.last_errno,
                   stats.bytes_read,
                   stats.bytes_skipped);
        } else if (stats.bytes_read == 0) {
          LogAgent("[R3Agent] read zero pid=%d addr=0x%llX size=%u flags=0x%X",
                   reader->pid(),
                   static_cast<unsigned long long>(req->address),
                   size,
                   req->reserved);
        }
        const auto read_end = std::chrono::steady_clock::now();
        const double read_ms =
            std::chrono::duration<double, std::milli>(read_end - read_begin).count();
        static std::atomic<uint32_t> read_log_sample{0};
        const uint32_t sample_id = read_log_sample.fetch_add(1, std::memory_order_relaxed);
        if (!ok || (sample_id % 64u) == 0u) {
          LogAgent("[R3Agent] read stat pid=%d addr=0x%llX req=%u got=%zu skip=%zu pages=%zu/%zu syscalls=%zu flags=0x%X ms=%.3f",
                   reader->pid(),
                   static_cast<unsigned long long>(req->address),
                   size,
                   stats.bytes_read,
                   stats.bytes_skipped,
                   stats.pages_checked,
                   stats.pages_skipped,
                   stats.read_syscalls,
                   req->reserved,
                   read_ms);
        }

        const uint32_t bytes_read = static_cast<uint32_t>(stats.bytes_read);
        const size_t response_size = offsetof(protocol::ReadMemResponse, data) + bytes_read;
        std::vector<uint8_t> out(response_size);
        auto* resp = reinterpret_cast<protocol::ReadMemResponse*>(out.data());
        resp->code = StatusCode(ok);
        resp->bytes_read = bytes_read;
        if (bytes_read > 0) {
          std::memcpy(resp->data, data.data(), bytes_read);
        }
        if (no_compress) {
          SendPacketRaw(client_fd, cmd, out.data(), static_cast<uint32_t>(out.size()));
        } else {
          SendPacket(client_fd, cmd, out.data(), static_cast<uint32_t>(out.size()));
        }
        break;
      }
      case protocol::CommandType::CMD_READ_MEM_BATCH: {
        if (!reader) {
          SendStatus(client_fd, cmd, -1);
          break;
        }
        const size_t header_size = offsetof(protocol::ReadMemBatchRequest, ranges);
        if (payload.size() < header_size) {
          SendStatus(client_fd, cmd, -1);
          break;
        }
        const auto* req = reinterpret_cast<const protocol::ReadMemBatchRequest*>(payload.data());
        const uint32_t count = req->count;
        if (count == 0 || count > 128) {
          SendStatus(client_fd, cmd, -1);
          break;
        }
        const size_t expected = header_size + static_cast<size_t>(count) * sizeof(protocol::ReadMemBatchRange);
        if (payload.size() < expected) {
          SendStatus(client_fd, cmd, -1);
          break;
        }
        const bool no_compress = (req->flags & protocol::READ_FLAG_NO_COMPRESS) != 0;
        std::vector<protocol::ReadMemBatchResult> results(count);
        std::vector<uint8_t> blob;
        blob.reserve(static_cast<size_t>(count) * 1024);

        for (uint32_t i = 0; i < count; ++i) {
          const auto& range = req->ranges[i];
          uint32_t size = range.size;
          if (size > kMaxReadSize) {
            size = kMaxReadSize;
          }
          std::vector<uint8_t> data(size, 0);
          SafeMemoryReader::ReadStats stats{};
          const bool ok = ReadMemoryCommon(range.address,
                                           size,
                                           req->flags,
                                           data.data(),
                                           &stats);
          auto& out = results[i];
          out.code = StatusCode(ok);
          out.bytes_read = static_cast<uint32_t>(stats.bytes_read);
          if (ok && out.bytes_read > 0) {
            const size_t old = blob.size();
            blob.resize(old + out.bytes_read);
            std::memcpy(blob.data() + old, data.data(), out.bytes_read);
          }
        }

        const size_t resp_header = offsetof(protocol::ReadMemBatchResponse, results);
        const size_t resp_size = resp_header +
                                 static_cast<size_t>(count) * sizeof(protocol::ReadMemBatchResult) +
                                 blob.size();
        std::vector<uint8_t> out(resp_size);
        auto* resp = reinterpret_cast<protocol::ReadMemBatchResponse*>(out.data());
        resp->count = count;
        resp->reserved = 0;
        std::memcpy(resp->results,
                    results.data(),
                    static_cast<size_t>(count) * sizeof(protocol::ReadMemBatchResult));
        if (!blob.empty()) {
          std::memcpy(out.data() + resp_header + static_cast<size_t>(count) * sizeof(protocol::ReadMemBatchResult),
                      blob.data(),
                      blob.size());
        }
        if (no_compress) {
          SendPacketRaw(client_fd, cmd, out.data(), static_cast<uint32_t>(out.size()));
        } else {
          SendPacket(client_fd, cmd, out.data(), static_cast<uint32_t>(out.size()));
        }
        break;
      }
      case protocol::CommandType::CMD_GET_PROCESS_ICON: {
        if (payload.size() < sizeof(protocol::ProcessIconRequest)) {
          SendStatus(client_fd, cmd, -1);
          break;
        }
        const auto* req = reinterpret_cast<const protocol::ProcessIconRequest*>(payload.data());
        std::vector<uint8_t> icon_png;
        const bool ok = req->pid != 0 && LoadProcessIconPng(static_cast<pid_t>(req->pid), req->desired_size, &icon_png);

        protocol::ProcessIconResponse resp{};
        resp.code = ok ? 0 : -1;
        resp.bytes = ok ? static_cast<uint32_t>(icon_png.size()) : 0;
        resp.format = ok ? protocol::PROCESS_ICON_FMT_PNG : protocol::PROCESS_ICON_FMT_NONE;
        resp.reserved = 0;

        std::vector<uint8_t> out;
        AppendBytes(&out, &resp, offsetof(protocol::ProcessIconResponse, data));
        if (ok && !icon_png.empty()) {
          AppendBytes(&out, icon_png.data(), icon_png.size());
        }
        SendPacket(client_fd, cmd, out.data(), static_cast<uint32_t>(out.size()));
        break;
      }
      case protocol::CommandType::CMD_LIST_PROCESSES: {
        uint32_t max_count = 512;
        if (payload.size() >= sizeof(protocol::ProcessListRequest)) {
          const auto* req = reinterpret_cast<const protocol::ProcessListRequest*>(payload.data());
          if (req->max_count > 0) {
            max_count = req->max_count;
          }
        }
        if (max_count > kMaxProcessEntries) {
          max_count = kMaxProcessEntries;
        }

        std::vector<uint8_t> out;
        protocol::ProcessListHeader list_header{};
        list_header.count = 0;
        list_header.reserved = 0;
        AppendBytes(&out, &list_header, sizeof(list_header));

        DIR* dir = opendir("/proc");
        if (dir) {
          struct dirent* ent = nullptr;
          while ((ent = readdir(dir)) != nullptr) {
            if (!IsDigits(ent->d_name)) {
              continue;
            }
            if (list_header.count >= max_count) {
              break;
            }
            const pid_t pid = static_cast<pid_t>(std::atoi(ent->d_name));
            std::string name = ReadCmdline(pid);
            if (name.empty()) {
              name = ReadComm(pid);
            }
            if (name.empty()) {
              name = "unknown";
            }
            if (name.size() > 512) {
              name.resize(512);
            }

            protocol::ProcessEntry entry{};
            entry.pid = static_cast<uint32_t>(pid);
            entry.name_len = static_cast<uint16_t>(name.size());
            entry.reserved = 0;
            uint32_t uid = 0;
            if (ReadProcessUid(pid, &uid)) {
              entry.reserved = static_cast<uint16_t>(entry.reserved | protocol::PROCESS_ENTRY_FLAG_CLASSIFIED);
              if (IsLikelySystemUid(uid)) {
                entry.reserved = static_cast<uint16_t>(entry.reserved | protocol::PROCESS_ENTRY_FLAG_SYSTEM);
              }
            }
            AppendBytes(&out, &entry, offsetof(protocol::ProcessEntry, name));
            AppendBytes(&out, name.data(), name.size());
            list_header.count++;
          }
          closedir(dir);
        }

        std::memcpy(out.data(), &list_header, sizeof(list_header));
        SendPacket(client_fd, cmd, out.data(), static_cast<uint32_t>(out.size()));
        break;
      }
      case protocol::CommandType::CMD_LIST_MODULES: {
        uint32_t pid = 0;
        if (payload.size() >= sizeof(protocol::ModuleListRequest)) {
          const auto* req = reinterpret_cast<const protocol::ModuleListRequest*>(payload.data());
          pid = req->pid;
        }
        if (pid == 0 && reader) {
          pid = static_cast<uint32_t>(reader->pid());
        }
        if (pid == 0) {
          SendStatus(client_fd, cmd, -1);
          break;
        }

        char path[64] = {0};
        std::snprintf(path, sizeof(path), "/proc/%u/maps", pid);
        std::ifstream file(path);
        if (!file.is_open()) {
          SendStatus(client_fd, cmd, -1);
          break;
        }

        std::vector<uint8_t> out;
        protocol::ModuleListHeader list_header{};
        list_header.count = 0;
        list_header.reserved = 0;
        AppendBytes(&out, &list_header, sizeof(list_header));

        std::string line;
        while (std::getline(file, line)) {
          if (list_header.count >= kMaxModuleEntries) {
            break;
          }
          MapEntry entry;
          if (!ParseMapsLineSimple(line, &entry)) {
            continue;
          }
          protocol::ModuleEntry mod{};
          mod.start = entry.start;
          mod.end = entry.end;
          mod.perms = PermsToFlags(entry.perms);
          if (entry.path.size() > 1024) {
            entry.path.resize(1024);
          }
          mod.path_len = static_cast<uint32_t>(entry.path.size());
          AppendBytes(&out, &mod, offsetof(protocol::ModuleEntry, path));
          if (mod.path_len > 0) {
            AppendBytes(&out, entry.path.data(), entry.path.size());
          }
          list_header.count++;
        }

        std::memcpy(out.data(), &list_header, sizeof(list_header));
        SendPacket(client_fd, cmd, out.data(), static_cast<uint32_t>(out.size()));
        break;
      }
      case protocol::CommandType::CMD_GET_PROC_INFO: {
        uint32_t pid = 0;
        if (payload.size() >= sizeof(protocol::ProcInfoRequest)) {
          const auto* req = reinterpret_cast<const protocol::ProcInfoRequest*>(payload.data());
          pid = req->pid;
        }
        if (pid == 0 && reader) {
          pid = static_cast<uint32_t>(reader->pid());
        }

        protocol::ProcInfoResponse resp{};
        resp.code = -1;
        resp.arch = static_cast<uint8_t>(protocol::RegsArch::UNKNOWN);
        resp.pointer_size = 0;
        resp.reserved[0] = resp.reserved[1] = 0;

        if (pid != 0) {
          protocol::RegsArch arch = protocol::RegsArch::UNKNOWN;
          uint8_t ptr_size = 0;
          if (GetProcArch(static_cast<pid_t>(pid), &arch, &ptr_size)) {
            resp.code = 0;
            resp.arch = static_cast<uint8_t>(arch);
            resp.pointer_size = ptr_size;
          }
        }
        SendPacket(client_fd, cmd, &resp, sizeof(resp));
        break;
      }
      case protocol::CommandType::CMD_GET_REGS: {
        uint32_t pid = 0;
        if (payload.size() >= sizeof(protocol::GetRegsRequest)) {
          const auto* req = reinterpret_cast<const protocol::GetRegsRequest*>(payload.data());
          pid = req->pid;
        }
        if (pid == 0 && reader) {
          pid = static_cast<uint32_t>(reader->pid());
        }
        protocol::GetRegsResponse resp{};
        resp.code = -1;
        resp.arch = static_cast<uint8_t>(protocol::RegsArch::UNKNOWN);
        resp.reserved[0] = resp.reserved[1] = resp.reserved[2] = 0;
        std::memset(&resp.regs, 0, sizeof(resp.regs));

        const bool already_attached =
            (debug_attached && !debug_sigstop && debug_pid == static_cast<pid_t>(pid)) ||
            ptrace_bp_mgr.IsAttached(static_cast<pid_t>(pid));
        const bool keep_stopped =
            debug_attached && !debug_sigstop && debug_pid == static_cast<pid_t>(pid);

        if (pid != 0) {
#if defined(__aarch64__)
          protocol::RegsArch arch = protocol::RegsArch::UNKNOWN;
          protocol::Arm64Regs regs64{};
          protocol::Arm32Regs regs32{};
          if (GetRegsAarch64(static_cast<pid_t>(pid),
                             already_attached,
                             keep_stopped,
                             &arch,
                             &regs64,
                             &regs32)) {
            resp.code = 0;
            resp.arch = static_cast<uint8_t>(arch);
            if (arch == protocol::RegsArch::ARM64) {
              resp.regs.arm64 = regs64;
            } else if (arch == protocol::RegsArch::ARM32) {
              resp.regs.arm32 = regs32;
            }
          }
#elif defined(__arm__)
          protocol::Arm32Regs regs{};
          if (GetArm32Regs(static_cast<pid_t>(pid), &regs, already_attached, keep_stopped)) {
            resp.code = 0;
            resp.arch = static_cast<uint8_t>(protocol::RegsArch::ARM32);
            resp.regs.arm32 = regs;
          }
#endif
        }

        SendPacket(client_fd, cmd, &resp, sizeof(resp));
        break;
      }
      case protocol::CommandType::CMD_GET_POINTER_CHAIN: {
        if (!reader) {
          SendStatus(client_fd, cmd, -1);
          break;
        }
        const size_t header_size = offsetof(protocol::PointerChainRequest, offsets);
        if (payload.size() < header_size) {
          SendStatus(client_fd, cmd, -1);
          break;
        }
        const auto* req = reinterpret_cast<const protocol::PointerChainRequest*>(payload.data());
        const size_t count = req->count;
        const size_t expected = header_size + count * sizeof(uint64_t);
        if (payload.size() < expected || count == 0) {
          SendStatus(client_fd, cmd, -1);
          break;
        }

        std::vector<uint64_t> offsets(count);
        std::memcpy(offsets.data(), req->offsets, count * sizeof(uint64_t));

        uint64_t resolved = 0;
        bool ok = reader->ResolvePointerChain(req->base, offsets, req->pointer_size, &resolved);

        protocol::PointerChainResponse resp{};
        resp.code = StatusCode(ok);
        resp.reserved = 0;
        resp.address = resolved;
        SendPacket(client_fd, cmd, &resp, sizeof(resp));
        break;
      }
      case protocol::CommandType::CMD_PTR_INDEX_BUILD: {
        if (payload.size() < sizeof(protocol::PointerIndexBuildRequest)) {
          SendStatus(client_fd, cmd, -1);
          break;
        }
        const auto* req = reinterpret_cast<const protocol::PointerIndexBuildRequest*>(payload.data());
        const pid_t pid = static_cast<pid_t>(req->pid);
        if (pid > 0 && (!reader || reader->pid() != pid)) {
          reader = std::make_unique<SafeMemoryReader>(pid);
          bool ok = reader->Open() && reader->RefreshMaps();
          InvalidateReadableCache();
          scanner.SetReader(reader.get());
          scanner.Clear();
          if (!ok) {
            SendStatus(client_fd, cmd, -1);
            break;
          }
        }
        if (!reader) {
          SendStatus(client_fd, cmd, -1);
          break;
        }

        uint16_t pointer_size = req->pointer_size;
        if (pointer_size != 4 && pointer_size != 8) {
          protocol::RegsArch arch = protocol::RegsArch::UNKNOWN;
          uint8_t ptr_size = 0;
          if (!GetProcArch(reader->pid(), &arch, &ptr_size)) {
            SendStatus(client_fd, cmd, -1);
            break;
          }
          pointer_size = ptr_size;
        }
        if (pointer_size != 4 && pointer_size != 8) {
          SendStatus(client_fd, cmd, -1);
          break;
        }

        size_t max_entries = req->max_entries == 0 ? kMaxIndexEntries : req->max_entries;
        if (max_entries > kMaxIndexEntries) {
          max_entries = kMaxIndexEntries;
        }
        const bool use_pvm = (req->flags & protocol::PTR_INDEX_FLAG_USE_PVM) != 0;
        const bool allow_nonresident = (req->flags & protocol::PTR_INDEX_FLAG_ALLOW_NONRESIDENT) != 0;
        const bool byte_step = (req->flags & protocol::PTR_INDEX_FLAG_BYTE_STEP) != 0;
        const bool strict = (req->flags & protocol::PTR_INDEX_FLAG_STRICT) != 0;
        const uint32_t step = byte_step ? 1u : pointer_size;
        const uint64_t overlap = (byte_step && pointer_size > 1) ? (pointer_size - 1) : 0;

        if (reader->regions().empty()) {
          reader->RefreshMaps();
        }

        pointer_index.clear();
        pointer_index.reserve(std::min<size_t>(max_entries, kMaxIndexEntries));
        pointer_index_pointer_size = pointer_size;
        pointer_index_pid = static_cast<uint32_t>(reader->pid());

        bool truncated = false;
        bool read_failed = false;
        uint64_t read_fail_addr = 0;
        size_t read_fail_req = 0;
        size_t read_fail_got = 0;
        const auto index_begin = std::chrono::steady_clock::now();
        const uint64_t align_mask = pointer_size - 1;
        const uint32_t chunk_size = 256 * 1024;
        std::vector<uint8_t> buffer;
        buffer.reserve(chunk_size);

        for (const auto& region : reader->regions()) {
          if (!region.readable) {
            continue;
          }
          uint64_t cursor = byte_step ? region.start : ((region.start + align_mask) & ~align_mask);
          while (cursor < region.end) {
            const uint64_t remaining = region.end - cursor;
            uint32_t chunk = static_cast<uint32_t>(std::min<uint64_t>(remaining, chunk_size));
            if (!byte_step && pointer_size > 1) {
              chunk = static_cast<uint32_t>((chunk / pointer_size) * pointer_size);
            }
            if (chunk == 0) {
              break;
            }
            if (byte_step && chunk < pointer_size) {
              break;
            }
            buffer.resize(chunk);
            SafeMemoryReader::ReadStats stats{};
            const bool fast_mode = allow_nonresident && !strict;
            bool ok = reader->ValidateAndReadEx(cursor,
                                                buffer.data(),
                                                buffer.size(),
                                                &stats,
                                                allow_nonresident,
                                                false,
                                                use_pvm,
                                                fast_mode);
            if (!ok) {
              if (strict) {
                read_failed = true;
                read_fail_addr = cursor;
                read_fail_req = chunk;
                read_fail_got = 0;
                break;
              }
            }
            if (ok && stats.bytes_read > 0) {
              if (strict && stats.bytes_read != chunk) {
                read_failed = true;
                read_fail_addr = cursor;
                read_fail_req = chunk;
                read_fail_got = stats.bytes_read;
                break;
              }
              const size_t bytes = stats.bytes_read;
              const size_t limit = bytes >= pointer_size ? (bytes - pointer_size + 1) : 0;
              for (size_t offset = 0; offset < limit; offset += step) {
                uint64_t value = 0;
                if (pointer_size == 4) {
                  uint32_t v32 = 0;
                  std::memcpy(&v32, buffer.data() + offset, sizeof(v32));
                  value = static_cast<uint64_t>(v32);
                } else {
                  uint64_t v64 = 0;
                  std::memcpy(&v64, buffer.data() + offset, sizeof(v64));
                  value = StripTag64(v64);
                }
                if (value == 0) {
                  continue;
                }
                pointer_index.push_back({value, cursor + offset});
                if (pointer_index.size() >= max_entries) {
                  truncated = true;
                  break;
                }
              }
            }
            if (truncated) {
              break;
            }
            if (read_failed) {
              break;
            }
            uint64_t advance = chunk;
            if (byte_step && chunk > overlap) {
              advance = chunk - overlap;
            }
            cursor += advance;
          }
          if (truncated) {
            break;
          }
          if (read_failed) {
            break;
          }
        }

        if (!read_failed && !pointer_index.empty()) {
          std::sort(pointer_index.begin(),
                    pointer_index.end(),
                    [](const protocol::PointerIndexEntry& a, const protocol::PointerIndexEntry& b) {
                      if (a.value != b.value) {
                        return a.value < b.value;
                      }
                      return a.address < b.address;
                    });
          pointer_index.erase(std::unique(pointer_index.begin(),
                                          pointer_index.end(),
                                          [](const protocol::PointerIndexEntry& a,
                                             const protocol::PointerIndexEntry& b) {
                                            return a.value == b.value && a.address == b.address;
                                          }),
                              pointer_index.end());
          if (pointer_index.size() > max_entries) {
            pointer_index.resize(max_entries);
            truncated = true;
          }
        }

        protocol::PointerIndexBuildResponse resp{};
        if (read_failed) {
          pointer_index.clear();
          resp.code = -1;
          LogAgent("[R3Agent] ptr index strict read failed addr=0x%llx req=%zu got=%zu",
                   static_cast<unsigned long long>(read_fail_addr),
                   read_fail_req,
                   read_fail_got);
        } else {
          resp.code = 0;
        }
        resp.pointer_size = pointer_index_pointer_size;
        resp.reserved = 0;
        resp.count = static_cast<uint64_t>(pointer_index.size());
        resp.truncated = truncated ? 1u : 0u;
        resp.reserved2 = 0;
        const auto index_end = std::chrono::steady_clock::now();
        const double index_ms =
            std::chrono::duration<double, std::milli>(index_end - index_begin).count();
        LogAgent("[R3Agent] ptr index build pid=%u psize=%u count=%llu truncated=%u strict=%u byte_step=%u allow_nonresident=%u use_pvm=%u ms=%.3f",
                 pointer_index_pid,
                 static_cast<unsigned>(pointer_index_pointer_size),
                 static_cast<unsigned long long>(pointer_index.size()),
                 truncated ? 1u : 0u,
                 strict ? 1u : 0u,
                 byte_step ? 1u : 0u,
                 allow_nonresident ? 1u : 0u,
                 use_pvm ? 1u : 0u,
                 index_ms);
        SendPacket(client_fd, cmd, &resp, sizeof(resp));
        break;
      }
      case protocol::CommandType::CMD_PTR_INDEX_QUERY: {
        if (payload.size() < sizeof(protocol::PointerIndexQueryRequest)) {
          SendStatus(client_fd, cmd, -1);
          break;
        }
        const auto* req = reinterpret_cast<const protocol::PointerIndexQueryRequest*>(payload.data());
        const uint64_t total = static_cast<uint64_t>(pointer_index.size());
        uint64_t start = req->start_index;
        if (start > total) {
          start = total;
        }
        uint32_t max_count = req->max_count == 0 ? static_cast<uint32_t>(kMaxIndexReturn) : req->max_count;
        if (max_count > kMaxIndexReturn) {
          max_count = static_cast<uint32_t>(kMaxIndexReturn);
        }
        const uint32_t returned = static_cast<uint32_t>(std::min<uint64_t>(max_count, total - start));
        const size_t payload_size = offsetof(protocol::PointerIndexQueryResponse, entries) +
                                    static_cast<size_t>(returned) * sizeof(protocol::PointerIndexEntry);
        std::vector<uint8_t> out(payload_size);
        auto* resp = reinterpret_cast<protocol::PointerIndexQueryResponse*>(out.data());
        resp->total = total;
        resp->returned = returned;
        resp->reserved = 0;
        if (returned > 0) {
          std::memcpy(resp->entries,
                      pointer_index.data() + start,
                      static_cast<size_t>(returned) * sizeof(protocol::PointerIndexEntry));
        }
        SendPacket(client_fd, cmd, out.data(), static_cast<uint32_t>(out.size()));
        break;
      }
      case protocol::CommandType::CMD_PTR_INDEX_CLEAR: {
        pointer_index.clear();
        pointer_index_pid = 0;
        pointer_index_pointer_size = 0;
        SendStatus(client_fd, cmd, 0);
        break;
      }
      case protocol::CommandType::CMD_PTR_VERIFY_BATCH: {
        if (!reader) {
          SendStatus(client_fd, cmd, -1);
          break;
        }
        const size_t header_size = offsetof(protocol::PointerVerifyBatchRequest, bases);
        if (payload.size() < header_size) {
          SendStatus(client_fd, cmd, -1);
          break;
        }
        const auto* req = reinterpret_cast<const protocol::PointerVerifyBatchRequest*>(payload.data());
        const uint32_t count = req->count;
        const uint16_t depth = req->depth;
        if (count == 0) {
          SendStatus(client_fd, cmd, -1);
          break;
        }
        size_t pointer_size = req->pointer_size;
        if (pointer_size != 4 && pointer_size != 8) {
          protocol::RegsArch arch = protocol::RegsArch::UNKNOWN;
          uint8_t ptr_size = 0;
          if (!GetProcArch(reader->pid(), &arch, &ptr_size)) {
            SendStatus(client_fd, cmd, -1);
            break;
          }
          pointer_size = ptr_size;
        }
        if (pointer_size != 4 && pointer_size != 8) {
          SendStatus(client_fd, cmd, -1);
          break;
        }

        const size_t bases_size = static_cast<size_t>(count) * sizeof(uint64_t);
        const size_t offsets_size = static_cast<size_t>(count) * static_cast<size_t>(depth) * sizeof(int64_t);
        if (bases_size / sizeof(uint64_t) != count ||
            (depth != 0 && offsets_size / sizeof(int64_t) != static_cast<size_t>(count) * depth)) {
          SendStatus(client_fd, cmd, -1);
          break;
        }
        const size_t expected = header_size + bases_size + offsets_size;
        if (payload.size() < expected) {
          SendStatus(client_fd, cmd, -1);
          break;
        }

        const bool allow_nonresident = (req->flags & protocol::READ_FLAG_ALLOW_NONRESIDENT) != 0;
        const bool use_pvm = (req->flags & protocol::READ_FLAG_USE_PVM) != 0;
        const uint64_t* bases = req->bases;
        const auto* offsets = reinterpret_cast<const int64_t*>(
            reinterpret_cast<const uint8_t*>(bases) + bases_size);

        const size_t resp_size = offsetof(protocol::PointerVerifyBatchResponse, results) +
                                 static_cast<size_t>(count) * sizeof(protocol::PointerVerifyBatchResult);
        std::vector<uint8_t> out(resp_size);
        auto* resp = reinterpret_cast<protocol::PointerVerifyBatchResponse*>(out.data());
        resp->count = count;
        resp->reserved = 0;
        for (uint32_t i = 0; i < count; ++i) {
          const uint64_t base = bases[i];
          uint64_t resolved = 0;
          bool ok = true;
          if (depth == 0) {
            resolved = pointer_size == 8 ? StripTag64(base) : base;
          } else {
            ok = reader->ResolvePointerChainAfterDeref(base,
                                                       offsets + static_cast<size_t>(i) * depth,
                                                       depth,
                                                       pointer_size,
                                                       &resolved,
                                                       allow_nonresident,
                                                       use_pvm);
          }
          auto& entry = resp->results[i];
          entry.code = StatusCode(ok);
          entry.reserved = 0;
          entry.address = ok ? resolved : 0;
        }
        SendPacket(client_fd, cmd, out.data(), static_cast<uint32_t>(out.size()));
        break;
      }
      case protocol::CommandType::CMD_PTR_VERIFY_BATCH_V2: {
        if (!reader) {
          SendStatus(client_fd, cmd, -1);
          break;
        }
        const size_t header_size = offsetof(protocol::PointerVerifyBatchV2Request, bases);
        if (payload.size() < header_size) {
          SendStatus(client_fd, cmd, -1);
          break;
        }
        const auto* req = reinterpret_cast<const protocol::PointerVerifyBatchV2Request*>(payload.data());
        const uint32_t count = req->count;
        const uint16_t depth = req->depth;
        const uint32_t target_count = req->target_count;
        if (count == 0) {
          SendStatus(client_fd, cmd, -1);
          break;
        }
        size_t pointer_size = req->pointer_size;
        if (pointer_size != 4 && pointer_size != 8) {
          protocol::RegsArch arch = protocol::RegsArch::UNKNOWN;
          uint8_t ptr_size = 0;
          if (!GetProcArch(reader->pid(), &arch, &ptr_size)) {
            SendStatus(client_fd, cmd, -1);
            break;
          }
          pointer_size = ptr_size;
        }
        if (pointer_size != 4 && pointer_size != 8) {
          SendStatus(client_fd, cmd, -1);
          break;
        }

        const size_t bases_size = static_cast<size_t>(count) * sizeof(uint64_t);
        const size_t offsets_size = static_cast<size_t>(count) * static_cast<size_t>(depth) * sizeof(int64_t);
        const size_t targets_size = static_cast<size_t>(target_count) * sizeof(uint64_t);
        if (bases_size / sizeof(uint64_t) != count ||
            (depth != 0 && offsets_size / sizeof(int64_t) != static_cast<size_t>(count) * depth) ||
            (target_count != 0 && targets_size / sizeof(uint64_t) != target_count)) {
          SendStatus(client_fd, cmd, -1);
          break;
        }
        if (header_size > std::numeric_limits<size_t>::max() - bases_size ||
            header_size + bases_size > std::numeric_limits<size_t>::max() - offsets_size ||
            header_size + bases_size + offsets_size > std::numeric_limits<size_t>::max() - targets_size) {
          SendStatus(client_fd, cmd, -1);
          break;
        }
        const size_t expected = header_size + bases_size + offsets_size + targets_size;
        if (payload.size() < expected) {
          SendStatus(client_fd, cmd, -1);
          break;
        }

        const bool allow_nonresident = (req->flags & protocol::READ_FLAG_ALLOW_NONRESIDENT) != 0;
        const bool use_pvm = (req->flags & protocol::READ_FLAG_USE_PVM) != 0;
        const bool use_target_filter =
            (req->flags & protocol::PTR_VERIFY_BATCH_FLAG_TARGET_FILTER) != 0 && target_count > 0;

        const uint64_t* bases = req->bases;
        const auto* offsets = reinterpret_cast<const int64_t*>(
            reinterpret_cast<const uint8_t*>(bases) + bases_size);
        const uint64_t* targets = reinterpret_cast<const uint64_t*>(
            reinterpret_cast<const uint8_t*>(offsets) + offsets_size);

        std::vector<uint64_t> sorted_targets;
        if (use_target_filter) {
          sorted_targets.reserve(target_count);
          for (uint32_t i = 0; i < target_count; ++i) {
            uint64_t value = targets[i];
            if (pointer_size == 8) {
              value = StripTag64(value);
            }
            if (value != 0) {
              sorted_targets.push_back(value);
            }
          }
          if (!sorted_targets.empty()) {
            std::sort(sorted_targets.begin(), sorted_targets.end());
            sorted_targets.erase(std::unique(sorted_targets.begin(), sorted_targets.end()),
                                 sorted_targets.end());
          }
        }

        std::vector<uint32_t> matched_indices;
        matched_indices.reserve(std::min<uint32_t>(count, 1024u));
        for (uint32_t i = 0; i < count; ++i) {
          const uint64_t base = bases[i];
          uint64_t resolved = 0;
          bool ok = true;
          if (depth == 0) {
            resolved = pointer_size == 8 ? StripTag64(base) : base;
          } else {
            ok = reader->ResolvePointerChainAfterDeref(base,
                                                       offsets + static_cast<size_t>(i) * depth,
                                                       depth,
                                                       pointer_size,
                                                       &resolved,
                                                       allow_nonresident,
                                                       use_pvm);
          }
          if (!ok) {
            continue;
          }
          bool matched = true;
          if (use_target_filter) {
            const uint64_t key = pointer_size == 8 ? StripTag64(resolved) : resolved;
            matched = !sorted_targets.empty() &&
                      std::binary_search(sorted_targets.begin(), sorted_targets.end(), key);
          }
          if (matched) {
            matched_indices.push_back(i);
          }
        }

        const size_t resp_size = offsetof(protocol::PointerVerifyBatchV2Response, matched_indices) +
                                 matched_indices.size() * sizeof(uint32_t);
        std::vector<uint8_t> out(resp_size);
        auto* resp = reinterpret_cast<protocol::PointerVerifyBatchV2Response*>(out.data());
        resp->count = count;
        resp->matched_count = static_cast<uint32_t>(matched_indices.size());
        resp->reserved = 0;
        resp->reserved2 = 0;
        if (!matched_indices.empty()) {
          std::memcpy(resp->matched_indices,
                      matched_indices.data(),
                      matched_indices.size() * sizeof(uint32_t));
        }
        SendPacket(client_fd, cmd, out.data(), static_cast<uint32_t>(out.size()));
        break;
      }
      case protocol::CommandType::CMD_WRITE_MEM: {
        if (!reader) {
          SendStatus(client_fd, cmd, -1);
          break;
        }
        const size_t header_size = offsetof(protocol::WriteMemRequest, data);
        if (payload.size() < header_size) {
          SendStatus(client_fd, cmd, -1);
          break;
        }
        const auto* req = reinterpret_cast<const protocol::WriteMemRequest*>(payload.data());
        uint32_t size = req->size;
        if (size > kMaxWriteSize) {
          size = kMaxWriteSize;
        }
        if (payload.size() < header_size + size) {
          SendStatus(client_fd, cmd, -1);
          break;
        }

        SafeMemoryReader::WriteStats stats;
        bool ok = reader->ValidateAndWrite(req->address, req->data, size, &stats);

        protocol::WriteMemResponse resp{};
        resp.code = StatusCode(ok);
        resp.bytes_written = static_cast<uint32_t>(stats.bytes_written);
        SendPacket(client_fd, cmd, &resp, sizeof(resp));
        break;
      }
      case protocol::CommandType::CMD_DEBUG_ATTACH: {
        if (payload.size() < sizeof(protocol::DebugAttachRequest)) {
          SendStatus(client_fd, cmd, -1);
          break;
        }
        const auto* req = reinterpret_cast<const protocol::DebugAttachRequest*>(payload.data());
        const pid_t pid = static_cast<pid_t>(req->pid);
        const bool allow_sigstop = (req->reserved & protocol::DEBUG_ATTACH_FLAG_ALLOW_SIGSTOP) != 0;
        if (pid <= 0) {
          SendStatus(client_fd, cmd, -1);
          break;
        }
        if (ptrace_bp_mgr.IsAttached(pid)) {
          debug_attached = true;
          debug_pid = pid;
          debug_sigstop = false;
          debug_sigstop_sent = false;
          SendStatus(client_fd, cmd, 0);
          break;
        }
        if (debug_attached && debug_pid != pid) {
          if (debug_sigstop) {
            ResumeProcess(debug_pid);
          } else {
            DetachDebugger(debug_pid);
            if (debug_sigstop_sent) {
              ResumeProcess(debug_pid);
            }
          }
          debug_attached = false;
          debug_pid = 0;
          debug_sigstop = false;
          debug_sigstop_sent = false;
        }
        bool ok = debug_attached;
        if (!debug_attached) {
          debug_sigstop_sent = false;
          if (allow_sigstop) {
            if (StopProcess(pid)) {
              debug_sigstop_sent = true;
              if (AttachDebugger(pid)) {
                debug_attached = true;
                debug_pid = pid;
                debug_sigstop = false;
                ok = true;
                LogAgent("[R3Agent] debug attach using SIGSTOP+ptrace pid=%d", pid);
              } else {
                debug_attached = true;
                debug_pid = pid;
                debug_sigstop = true;
                ok = true;
                LogAgent("[R3Agent] debug attach using SIGSTOP pid=%d errno=%d", pid,
                         g_last_ptrace_errno.load());
              }
            } else {
              ok = AttachDebugger(pid);
              if (ok) {
                debug_attached = true;
                debug_pid = pid;
                debug_sigstop = false;
                debug_sigstop_sent = false;
              } else {
                LogAgent("[R3Agent] debug attach failed pid=%d errno=%d",
                         pid,
                         g_last_ptrace_errno.load());
              }
            }
          } else {
            ok = AttachDebugger(pid);
            if (ok) {
              debug_attached = true;
              debug_pid = pid;
              debug_sigstop = false;
              debug_sigstop_sent = false;
            } else {
              LogAgent("[R3Agent] debug attach failed pid=%d errno=%d",
                       pid,
                       g_last_ptrace_errno.load());
            }
          }
        }
        SendStatus(client_fd, cmd, StatusCode(ok));
        break;
      }
      case protocol::CommandType::CMD_DEBUG_DETACH: {
        bool ok = true;
        if (debug_attached) {
          if (ptrace_bp_mgr.IsAttached(debug_pid)) {
            debug_attached = false;
            debug_pid = 0;
            debug_sigstop = false;
            debug_sigstop_sent = false;
            SendStatus(client_fd, cmd, 0);
            break;
          }
          if (debug_sigstop) {
            ok = ResumeProcess(debug_pid);
          } else {
            ok = DetachDebugger(debug_pid);
            if (debug_sigstop_sent) {
              ok = ResumeProcess(debug_pid) && ok;
            }
          }
          debug_attached = false;
          debug_pid = 0;
          debug_sigstop = false;
          debug_sigstop_sent = false;
        }
        SendStatus(client_fd, cmd, StatusCode(ok));
        break;
      }
      case protocol::CommandType::CMD_GET_CAPS: {
        protocol::AgentCapabilitiesResponse resp{};
        resp.code = 0;
        resp.protocol_version = 1;
        resp.capability_flags = 0;
        resp.capability_flags |= protocol::AGENT_CAP_DEBUG_BP;
        resp.capability_flags |= protocol::AGENT_CAP_DEBUG_CONTROL_STEP;
        resp.capability_flags |= protocol::AGENT_CAP_READ_MEM_BATCH;
        resp.capability_flags |= protocol::AGENT_CAP_POINTER_INDEX;
        resp.capability_flags |= protocol::AGENT_CAP_CUSTOM_MEM_OP;
        resp.capability_flags |= protocol::AGENT_CAP_PLUGIN_MEM_PROVIDER;
        resp.max_read_batch = 128;
        resp.max_custom_mem = kMaxReadSize;
        resp.reserved0 = 0;
        resp.reserved1 = 0;
        SendPacket(client_fd, cmd, &resp, sizeof(resp));
        break;
      }
      case protocol::CommandType::CMD_DEBUG_CONTROL: {
        if (payload.size() < sizeof(protocol::DebugControlRequest)) {
          SendStatus(client_fd, cmd, -1);
          break;
        }
        const auto* req = reinterpret_cast<const protocol::DebugControlRequest*>(payload.data());
        const pid_t pid = static_cast<pid_t>(req->pid);
        if (pid <= 0) {
          SendStatus(client_fd, cmd, -1);
          break;
        }

        bool ok = false;
        std::string err;
        if (!(debug_attached && !debug_sigstop && debug_pid == pid)) {
          err = "debugger not attached";
        } else {
          switch (req->action) {
            case protocol::DEBUG_CTRL_STEP_IN:
              ok = DebugStepIn(pid, &err);
              break;
            case protocol::DEBUG_CTRL_STEP_OVER:
              ok = DebugStepOver(pid, &err);
              break;
            case protocol::DEBUG_CTRL_CONTINUE:
              err = "continue not supported in debug control";
              ok = false;
              break;
            default:
              err = "invalid debug action";
              ok = false;
              break;
          }
        }
        if (!ok && !err.empty()) {
          LogAgent("[R3Agent] debug control failed pid=%d action=%u err=%s",
                   pid,
                   static_cast<unsigned>(req->action),
                   err.c_str());
        }
        SendStatus(client_fd, cmd, StatusCode(ok));
        break;
      }
      case protocol::CommandType::CMD_CUSTOM_MEM_OP: {
        const size_t req_header = offsetof(protocol::CustomMemOpRequest, payload);
        if (payload.size() < req_header) {
          SendStatus(client_fd, cmd, -1);
          break;
        }
        const auto* req = reinterpret_cast<const protocol::CustomMemOpRequest*>(payload.data());
        const size_t total_payload =
            static_cast<size_t>(req->user_ctx_len) + static_cast<size_t>(req->write_data_len);
        if (req_header > payload.size() || total_payload > payload.size() - req_header) {
          SendStatus(client_fd, cmd, -1);
          break;
        }

        protocol::CustomMemOpResponse resp{};
        resp.code = -6;
        resp.provider_errno = 0;
        resp.sys_errno = 0;
        resp.bytes_done = 0;
        resp.elapsed_us = 0;
        resp.trace_id = req->trace_id;
        resp.read_data_len = 0;
        resp.reserved = 0;
        std::vector<uint8_t> read_data;

        const uint8_t* user_ctx = req->payload;
        const uint8_t* write_data = req->payload + req->user_ctx_len;
        const auto start_tp = std::chrono::steady_clock::now();

        pid_t pid = static_cast<pid_t>(req->pid);
        if (pid <= 0 && reader) {
          pid = reader->pid();
        }
        if (pid <= 0) {
          resp.code = -1;
        } else if (req->abi_version != 1) {
          resp.code = -1;
        } else if (req->op != protocol::CUSTOM_MEM_OP_READ && req->op != protocol::CUSTOM_MEM_OP_WRITE) {
          resp.code = -1;
        } else if (req->size == 0) {
          resp.code = -1;
        } else {
          int32_t syscall_no = (req->op == protocol::CUSTOM_MEM_OP_READ) ? req->syscall_read : req->syscall_write;
          if (syscall_no < 0) {
            resp.code = -2;
          } else {
            if (req->op == protocol::CUSTOM_MEM_OP_READ) {
              if (req->size > kMaxReadSize) {
                resp.code = -1;
              } else {
                read_data.assign(req->size, 0);
                errno = 0;
                long rc = syscall(static_cast<long>(syscall_no),
                                  static_cast<long>(pid),
                                  static_cast<unsigned long long>(req->address),
                                  reinterpret_cast<uintptr_t>(read_data.data()),
                                  static_cast<unsigned long>(req->size),
                                  reinterpret_cast<uintptr_t>(user_ctx),
                                  static_cast<unsigned long>(req->user_ctx_len),
                                  static_cast<unsigned long>(req->flags));
                if (rc < 0) {
                  resp.code = -5;
                  resp.sys_errno = errno;
                } else {
                  uint32_t done = static_cast<uint32_t>(rc);
                  if (done > req->size) {
                    done = req->size;
                  }
                  resp.code = 0;
                  resp.bytes_done = done;
                  resp.read_data_len = done;
                  read_data.resize(done);
                }
              }
            } else {
              if (req->size > kMaxWriteSize || req->write_data_len < req->size) {
                resp.code = -1;
              } else {
                errno = 0;
                long rc = syscall(static_cast<long>(syscall_no),
                                  static_cast<long>(pid),
                                  static_cast<unsigned long long>(req->address),
                                  reinterpret_cast<uintptr_t>(write_data),
                                  static_cast<unsigned long>(req->size),
                                  reinterpret_cast<uintptr_t>(user_ctx),
                                  static_cast<unsigned long>(req->user_ctx_len),
                                  static_cast<unsigned long>(req->flags));
                if (rc < 0) {
                  resp.code = -5;
                  resp.sys_errno = errno;
                } else {
                  uint32_t done = static_cast<uint32_t>(rc);
                  if (done == 0 && req->size > 0) {
                    done = req->size;
                  } else if (done > req->size) {
                    done = req->size;
                  }
                  resp.code = 0;
                  resp.bytes_done = done;
                }
              }
            }
          }
        }

        const auto end_tp = std::chrono::steady_clock::now();
        resp.elapsed_us = static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::microseconds>(end_tp - start_tp).count());

        const size_t resp_header = offsetof(protocol::CustomMemOpResponse, data);
        const size_t out_size = resp_header + read_data.size();
        std::vector<uint8_t> out(out_size, 0);
        auto* out_resp = reinterpret_cast<protocol::CustomMemOpResponse*>(out.data());
        *out_resp = resp;
        if (!read_data.empty()) {
          std::memcpy(out_resp->data, read_data.data(), read_data.size());
        }
        SendPacket(client_fd, cmd, out.data(), static_cast<uint32_t>(out.size()));
        break;
      }
      case protocol::CommandType::CMD_DEBUG_SET_BP: {
        if (payload.size() < sizeof(protocol::DebugBreakpointRequest)) {
          SendStatus(client_fd, cmd, -1);
          break;
        }
        const auto* req = reinterpret_cast<const protocol::DebugBreakpointRequest*>(payload.data());
        const pid_t pid = static_cast<pid_t>(req->pid);
        if (pid <= 0) {
          SendStatus(client_fd, cmd, -1);
          break;
        }
        LogAgent("[R3Agent] set bp req pid=%d backend=%u type=%u size=%u addr=0x%llx flags=0x%X",
                 pid,
                 static_cast<unsigned>(req->backend),
                 static_cast<unsigned>(req->type),
                 static_cast<unsigned>(req->size),
                 static_cast<unsigned long long>(req->address),
                 static_cast<unsigned>(req->flags));
        bool ok = false;
        std::string err;
        if (req->backend == protocol::DEBUG_BACKEND_PERF) {
          ok = perf_bp_mgr.Set(pid, req->address, req->type, req->size, req->flags, &err);
        } else if (req->backend == protocol::DEBUG_BACKEND_PTRACE) {
          ok = ptrace_bp_mgr.Set(pid, req->address, req->type, req->size, req->flags, &err);
        }
        if (!ok && !err.empty()) {
          LogAgent("[R3Agent] set bp failed: %s", err.c_str());
        } else if (!ok) {
          LogAgent("[R3Agent] set bp failed backend=%u addr=0x%llx type=%u size=%u",
                   static_cast<unsigned>(req->backend),
                   static_cast<unsigned long long>(req->address),
                   static_cast<unsigned>(req->type),
                   static_cast<unsigned>(req->size));
        }
        SendStatus(client_fd, cmd, StatusCode(ok));
        break;
      }
      case protocol::CommandType::CMD_DEBUG_CLR_BP: {
        if (payload.size() < sizeof(protocol::DebugBreakpointRequest)) {
          SendStatus(client_fd, cmd, -1);
          break;
        }
        const auto* req = reinterpret_cast<const protocol::DebugBreakpointRequest*>(payload.data());
        const pid_t pid = static_cast<pid_t>(req->pid);
        bool ok = true;
        const bool clear_all = (req->flags & protocol::DEBUG_BP_FLAG_CLEAR_ALL) != 0;
        if (req->backend == protocol::DEBUG_BACKEND_PERF) {
          if (clear_all || req->address == 0) {
            perf_bp_mgr.ClearAll();
          } else {
            ok = perf_bp_mgr.Clear(pid, req->address, req->type, req->size);
          }
        } else if (req->backend == protocol::DEBUG_BACKEND_PTRACE) {
          if (clear_all || req->address == 0) {
            ptrace_bp_mgr.ClearAll();
          } else {
            ok = ptrace_bp_mgr.Clear(pid, req->address, req->type, req->size);
          }
        } else {
          ok = false;
        }
        SendStatus(client_fd, cmd, StatusCode(ok));
        break;
      }
      case protocol::CommandType::CMD_DEBUG_POLL_BP: {
        if (payload.size() < sizeof(protocol::DebugBreakpointPollRequest)) {
          SendStatus(client_fd, cmd, -1);
          break;
        }
        const auto* req = reinterpret_cast<const protocol::DebugBreakpointPollRequest*>(payload.data());
        static int poll_log_count = 0;
        if (poll_log_count < 5) {
          LogAgent("[R3Agent] poll bp req backend=%u max=%u",
                   static_cast<unsigned>(req->backend),
                   static_cast<unsigned>(req->max_events));
          poll_log_count++;
        }
        std::vector<protocol::DebugBreakpointEvent> events;
        bool ok = false;
        if (req->backend == protocol::DEBUG_BACKEND_PERF) {
          ok = perf_bp_mgr.Poll(req->max_events, &events, reader.get());
        } else if (req->backend == protocol::DEBUG_BACKEND_PTRACE) {
          ok = ptrace_bp_mgr.Poll(req->max_events, &events);
        }
        if (!ok) {
          SendStatus(client_fd, cmd, -1);
          break;
        }
        const uint32_t count = static_cast<uint32_t>(events.size());
        const size_t payload_size = offsetof(protocol::DebugBreakpointPollResponse, events) +
                                    static_cast<size_t>(count) * sizeof(protocol::DebugBreakpointEvent);
        std::vector<uint8_t> out(payload_size);
        auto* resp = reinterpret_cast<protocol::DebugBreakpointPollResponse*>(out.data());
        resp->count = count;
        resp->reserved = 0;
        if (count > 0) {
          std::memcpy(resp->events, events.data(), count * sizeof(protocol::DebugBreakpointEvent));
        }
        SendPacket(client_fd, cmd, out.data(), static_cast<uint32_t>(out.size()));
        break;
      }
      default: {
        SendStatus(client_fd, cmd, -1);
        break;
      }
    }
  }

  if (debug_attached) {
    if (debug_sigstop) {
      ResumeProcess(debug_pid);
    } else {
      DetachDebugger(debug_pid);
      if (debug_sigstop_sent) {
        ResumeProcess(debug_pid);
      }
    }
    debug_attached = false;
    debug_pid = 0;
    debug_sigstop = false;
    debug_sigstop_sent = false;
  }
  perf_bp_mgr.ClearAll();
  ptrace_bp_mgr.ClearAll();
  close(client_fd);
}

using SetConFn = int (*)(const char*);

bool TrySetCon(const char* ctx) {
  if (!ctx || !*ctx) {
    return false;
  }
  void* handle = dlopen("libselinux.so", RTLD_LAZY);
  if (!handle) {
    return false;
  }
  auto fn = reinterpret_cast<SetConFn>(dlsym(handle, "setcon"));
  if (!fn) {
    dlclose(handle);
    return false;
  }
  const int rc = fn(ctx);
  dlclose(handle);
  return rc == 0;
}

bool ReadViaProcessVm(pid_t pid, uint64_t addr, void* out, size_t size, SafeMemoryReader::ReadStats* stats) {
  if (!out || size == 0) {
    return false;
  }
  struct iovec local_iov;
  local_iov.iov_base = out;
  local_iov.iov_len = size;
  struct iovec remote_iov;
  remote_iov.iov_base = reinterpret_cast<void*>(addr);
  remote_iov.iov_len = size;

  ssize_t n = ProcessVmReadvCompat(pid, &local_iov, 1, &remote_iov, 1, 0);
  const int saved_errno = n < 0 ? errno : 0;
  if (stats) {
    stats->bytes_requested = size;
    stats->bytes_read = n > 0 ? static_cast<size_t>(n) : 0;
    stats->bytes_skipped = n > 0 ? (size - static_cast<size_t>(n)) : size;
    stats->pages_checked = 0;
    stats->pages_skipped = 0;
    stats->read_syscalls = 1;
    stats->last_errno = saved_errno;
  }
  if (n < 0) {
    if (saved_errno == EIO || saved_errno == EFAULT) {
      return true;
    }
    std::fprintf(stderr,
                 "[R3Agent] process_vm_readv failed pid=%d addr=0x%llX size=%zu errno=%d\n",
                 pid,
                 static_cast<unsigned long long>(addr),
                 size,
                 saved_errno);
    return false;
  }
  return true;
}

bool SendStatus(int fd, protocol::CommandType cmd, int32_t code) {
  protocol::StatusResponse resp{};
  resp.code = code;
  resp.reserved = 0;
  return SendPacket(fd, cmd, &resp, sizeof(resp));
}

size_t ValueSizeForType(protocol::ValueType type) {
  switch (type) {
    case protocol::ValueType::U8:
      return sizeof(uint8_t);
    case protocol::ValueType::U16:
      return sizeof(uint16_t);
    case protocol::ValueType::U32:
      return sizeof(uint32_t);
    case protocol::ValueType::U64:
      return sizeof(uint64_t);
    case protocol::ValueType::FLOAT:
      return sizeof(float);
    case protocol::ValueType::DOUBLE:
      return sizeof(double);
    case protocol::ValueType::S32:
      return sizeof(int32_t);
    case protocol::ValueType::S64:
      return sizeof(int64_t);
    case protocol::ValueType::STRING:
    case protocol::ValueType::AOB:
    case protocol::ValueType::BINARY:
    case protocol::ValueType::ALL:
      return sizeof(uint8_t);
    default:
      return 0;
  }
}

bool IsDigits(const char* text) {
  if (!text || !*text) {
    return false;
  }
  for (const char* p = text; *p; ++p) {
    if (*p < '0' || *p > '9') {
      return false;
    }
  }
  return true;
}

bool ParseMapsLineSimple(const std::string& line, MapEntry* out) {
  if (!out) {
    return false;
  }
  std::istringstream iss(line);
  std::string range;
  std::string perms;
  std::string offset;
  std::string dev;
  std::string inode;

  if (!(iss >> range >> perms >> offset >> dev >> inode)) {
    return false;
  }

  std::string path;
  std::getline(iss, path);
  if (!path.empty() && path[0] == ' ') {
    path.erase(0, 1);
  }

  const size_t dash = range.find('-');
  if (dash == std::string::npos) {
    return false;
  }

  const std::string start_str = range.substr(0, dash);
  const std::string end_str = range.substr(dash + 1);
  char* endptr = nullptr;
  uint64_t start = strtoull(start_str.c_str(), &endptr, 16);
  if (endptr == start_str.c_str()) {
    return false;
  }
  endptr = nullptr;
  uint64_t end = strtoull(end_str.c_str(), &endptr, 16);
  if (endptr == end_str.c_str()) {
    return false;
  }

  out->start = start;
  out->end = end;
  out->perms = perms;
  out->path = path;
  return true;
}

uint32_t PermsToFlags(const std::string& perms) {
  uint32_t flags = 0;
  if (perms.size() >= 1 && perms[0] == 'r') {
    flags |= protocol::MODULE_PERM_READ;
  }
  if (perms.size() >= 2 && perms[1] == 'w') {
    flags |= protocol::MODULE_PERM_WRITE;
  }
  if (perms.size() >= 3 && perms[2] == 'x') {
    flags |= protocol::MODULE_PERM_EXEC;
  }
  if (perms.size() >= 4 && perms[3] == 'p') {
    flags |= protocol::MODULE_PERM_PRIVATE;
  }
  if (perms.size() >= 4 && perms[3] == 's') {
    flags |= protocol::MODULE_PERM_SHARED;
  }
  return flags;
}

std::string ReadCmdline(pid_t pid) {
  char path[64] = {0};
  std::snprintf(path, sizeof(path), "/proc/%d/cmdline", pid);
  FILE* fp = std::fopen(path, "rb");
  if (!fp) {
    return {};
  }
  char buf[512] = {0};
  size_t n = std::fread(buf, 1, sizeof(buf) - 1, fp);
  std::fclose(fp);
  if (n == 0) {
    return {};
  }
  for (size_t i = 0; i < n; ++i) {
    if (buf[i] == '\0') {
      buf[i] = ' ';
    }
  }
  std::string out(buf);
  while (!out.empty() && out.back() == ' ') {
    out.pop_back();
  }
  return out;
}

std::string ReadComm(pid_t pid) {
  char path[64] = {0};
  std::snprintf(path, sizeof(path), "/proc/%d/comm", pid);
  FILE* fp = std::fopen(path, "r");
  if (!fp) {
    return {};
  }
  char buf[256] = {0};
  if (!std::fgets(buf, sizeof(buf), fp)) {
    std::fclose(fp);
    return {};
  }
  std::fclose(fp);
  std::string out(buf);
  while (!out.empty() && (out.back() == '\n' || out.back() == '\r')) {
    out.pop_back();
  }
  return out;
}

bool ReadProcessUid(pid_t pid, uint32_t* out_uid) {
  if (!out_uid || pid <= 0) {
    return false;
  }
  // Fast path: /proc/<pid> directory owner uid matches process uid.
  char proc_path[64] = {0};
  std::snprintf(proc_path, sizeof(proc_path), "/proc/%d", pid);
  struct stat st{};
  if (stat(proc_path, &st) == 0) {
    *out_uid = static_cast<uint32_t>(st.st_uid);
    return true;
  }

  // Fallback: parse Uid from /proc/<pid>/status.
  char path[64] = {0};
  std::snprintf(path, sizeof(path), "/proc/%d/status", pid);
  FILE* fp = std::fopen(path, "r");
  if (!fp) {
    return false;
  }
  char line[256] = {0};
  while (std::fgets(line, sizeof(line), fp)) {
    if (std::strncmp(line, "Uid:", 4) != 0) {
      continue;
    }
    const char* p = line + 4;
    while (*p == ' ' || *p == '\t') {
      ++p;
    }
    char* endptr = nullptr;
    const unsigned long uid = std::strtoul(p, &endptr, 10);
    if (endptr == p) {
      continue;
    }
    *out_uid = static_cast<uint32_t>(uid);
    std::fclose(fp);
    return true;
  }
  std::fclose(fp);
  return false;
}

bool IsLikelySystemUid(uint32_t uid) {
  constexpr uint32_t kAppIdRange = 100000u;
  constexpr uint32_t kAidAppStart = 10000u;
  const uint32_t app_id = uid % kAppIdRange;
  return app_id < kAidAppStart;
}

void AppendBytes(std::vector<uint8_t>* out, const void* data, size_t size) {
  if (!out || !data || size == 0) {
    return;
  }
  const uint8_t* ptr = static_cast<const uint8_t*>(data);
  out->insert(out->end(), ptr, ptr + size);
}

#ifndef NT_PRSTATUS
#define NT_PRSTATUS 1
#endif

bool AttachDebugger(pid_t pid) {
  if (pid <= 0) {
    return false;
  }
  g_last_ptrace_errno.store(0);
  std::vector<pid_t> tids;
  tids.push_back(pid);
  bool partial = false;
  std::vector<pid_t> attached;
  auto attach_one = [&](pid_t tid, bool allow_selinux_retry) -> bool {
    auto try_seize = [&](pid_t target) -> bool {
#if defined(PTRACE_SEIZE) && defined(PTRACE_INTERRUPT)
      if (ptrace(PTRACE_SEIZE, target, nullptr, nullptr) == -1) {
        return false;
      }
      if (ptrace(PTRACE_INTERRUPT, target, nullptr, nullptr) == -1) {
        ptrace(PTRACE_DETACH, target, nullptr, nullptr);
        return false;
      }
      return true;
#else
      (void)target;
      return false;
#endif
    };

    bool attached_now = false;
    const int tracer = ReadTracerPid(tid);
    if (IsSameProcess(tracer)) {
      return true;
    }
    if (tracer > 0) {
#if defined(PTRACE_SEIZE) && defined(PTRACE_INTERRUPT)
      if (allow_selinux_retry) {
        if (try_seize(tid)) {
          attached_now = true;
          static int seize_log_count2 = 0;
          if (seize_log_count2 < 5) {
            LogAgent("[R3Agent] ptrace seize ok (tracer=%d) tid=%d", tracer, tid);
            seize_log_count2++;
          }
          goto wait_for_stop_label;
        }
      }
#endif
      static int tracer_log_count = 0;
      if (tracer_log_count < 5) {
        const std::string comm = ReadComm(tracer);
        const std::string cmdline = ReadCmdline(tracer);
        LogAgent("[R3Agent] tracer pid=%d comm=%s cmd=%s",
                 tracer,
                 comm.empty() ? "?" : comm.c_str(),
                 cmdline.empty() ? "?" : cmdline.c_str());
        tracer_log_count++;
      }
      if (!allow_selinux_retry) {
        partial = true;
        return true;
      }
      g_last_ptrace_errno.store(EBUSY);
      return false;
    }
#if defined(PTRACE_SEIZE) && defined(PTRACE_INTERRUPT)
    if (try_seize(tid)) {
      attached_now = true;
      goto wait_for_stop_label;
    }
    if (allow_selinux_retry) {
      const char* contexts[] = {
        "u:r:debuggerd:s0",
        "u:r:magisk:s0",
        "u:r:su:s0",
        "u:r:shell:s0"
      };
      for (const char* ctx : contexts) {
        if (TrySetCon(ctx)) {
          if (try_seize(tid)) {
            attached_now = true;
            break;
          }
        }
      }
      if (attached_now) {
        goto wait_for_stop_label;
      }
    }
#endif
    if (ptrace(PTRACE_ATTACH, tid, nullptr, nullptr) == -1) {
      const int err = errno;
      g_last_ptrace_errno.store(err);
      std::fprintf(stderr, "[R3Agent] ptrace attach failed tid=%d errno=%d\n", tid, err);
      if (err == EPERM && allow_selinux_retry) {
        const char* contexts[] = {
          "u:r:debuggerd:s0",
          "u:r:magisk:s0",
          "u:r:su:s0",
          "u:r:shell:s0"
        };
        for (const char* ctx : contexts) {
          if (TrySetCon(ctx)) {
            std::fprintf(stderr, "[R3Agent] setcon -> %s\n", ctx);
            if (ptrace(PTRACE_ATTACH, tid, nullptr, nullptr) != -1) {
              attached_now = true;
              break;
            }
            std::fprintf(stderr, "[R3Agent] ptrace retry failed tid=%d errno=%d\n", tid, errno);
          }
        }
      }
#if defined(PTRACE_SEIZE) && defined(PTRACE_INTERRUPT)
      if (!attached_now && (err == EPERM || err == EBUSY)) {
        if (try_seize(tid)) {
          attached_now = true;
          static int seize_log_count = 0;
          if (seize_log_count < 5) {
            LogAgent("[R3Agent] ptrace seize ok tid=%d errno=%d", tid, err);
            seize_log_count++;
          }
        }
      }
#endif
      if (!attached_now) {
        if (!allow_selinux_retry) {
          partial = true;
          return true;
        }
        return false;
      }
    } else {
      attached_now = true;
    }
wait_for_stop_label:
    if (!WaitForStop(tid, 5000)) {
      const char state = ReadProcState(tid);
      if (state == 'T' || state == 't') {
        attached.push_back(tid);
        return true;
      }
      g_last_ptrace_errno.store(ETIMEDOUT);
      ptrace(PTRACE_DETACH, tid, nullptr, nullptr);
      if (!allow_selinux_retry) {
        partial = true;
        return true;
      }
      return false;
    }
    attached.push_back(tid);
    return true;
  };

  for (pid_t tid : tids) {
    const bool allow_retry = (tid == pid);
    if (!attach_one(tid, allow_retry)) {
      for (pid_t atid : attached) {
        ptrace(PTRACE_DETACH, atid, nullptr, nullptr);
      }
      return false;
    }
  }
  if (partial) {
    g_last_ptrace_errno.store(EBUSY);
    LogAgent("[R3Agent] ptrace attach partial pid=%d", pid);
  }
  return true;
}

bool DetachDebugger(pid_t pid) {
  if (pid <= 0) {
    return false;
  }
  auto detach_one = [&](pid_t tid) -> bool {
    if (ptrace(PTRACE_DETACH, tid, nullptr, nullptr) != -1) {
      return true;
    }
    const int err = errno;
    bool interrupted = false;
    if (EnsureTraceeStopped(tid, 1000, &interrupted)) {
      if (ptrace(PTRACE_DETACH, tid, nullptr, nullptr) != -1) {
        return true;
      }
    }
    if (err == ESRCH) {
      return true;
    }
    LogAgent("[R3Agent] ptrace detach failed tid=%d errno=%d", tid, err);
    return false;
  };

  bool ok = true;
  std::vector<pid_t> tids = ListThreads(pid);
  if (tids.empty()) {
    return detach_one(pid);
  }
  for (pid_t tid : tids) {
    if (!IsSameProcess(ReadTracerPid(tid))) {
      continue;
    }
    if (!detach_one(tid)) {
      ok = false;
    }
  }
  return ok;
}

bool GetArm64Regs(pid_t pid, protocol::Arm64Regs* out, bool already_attached, bool keep_stopped) {
#if defined(__aarch64__)
  if (!out) {
    return false;
  }
  bool attached = already_attached;
  if (!attached) {
    if (!AttachDebugger(pid)) {
      return false;
    }
    attached = true;
  }
  bool interrupted = false;
  struct iovec iov;
  iov.iov_base = out;
  iov.iov_len = sizeof(*out);
  auto read_once = [&]() -> bool {
    iov.iov_len = sizeof(*out);
    return ptrace(PTRACE_GETREGSET, pid, (void*)NT_PRSTATUS, &iov) != -1;
  };
  bool ok = read_once();
  if (!ok && already_attached) {
    if (EnsureTraceeStopped(pid, 1000, &interrupted)) {
      ok = read_once();
    }
  }
  if (!ok) {
    if (!already_attached) {
      DetachDebugger(pid);
    } else if (interrupted && !keep_stopped) {
      ptrace(PTRACE_CONT, pid, nullptr, nullptr);
    }
    return false;
  }
  if (!already_attached) {
    DetachDebugger(pid);
  } else if (interrupted && !keep_stopped) {
    ptrace(PTRACE_CONT, pid, nullptr, nullptr);
  }
  return true;
#else
  (void)pid;
  (void)out;
  (void)already_attached;
  (void)keep_stopped;
  return false;
#endif
}

bool GetArm32Regs(pid_t pid, protocol::Arm32Regs* out, bool already_attached, bool keep_stopped) {
#if defined(__arm__)
  if (!out) {
    return false;
  }
  bool attached = already_attached;
  if (!attached) {
    if (!AttachDebugger(pid)) {
      return false;
    }
    attached = true;
  }
  bool interrupted = false;
  struct pt_regs regs;
  auto read_once = [&]() -> bool {
    return ptrace(PTRACE_GETREGS, pid, nullptr, &regs) != -1;
  };
  bool ok = read_once();
  if (!ok && already_attached) {
    if (EnsureTraceeStopped(pid, 1000, &interrupted)) {
      ok = read_once();
    }
  }
  if (!ok) {
    if (!already_attached) {
      DetachDebugger(pid);
    } else if (interrupted && !keep_stopped) {
      ptrace(PTRACE_CONT, pid, nullptr, nullptr);
    }
    return false;
  }
  for (int i = 0; i < 16; ++i) {
    out->regs[i] = static_cast<uint32_t>(regs.uregs[i]);
  }
  out->cpsr = static_cast<uint32_t>(regs.uregs[16]);
  out->orig_r0 = static_cast<uint32_t>(regs.uregs[17]);
  if (!already_attached) {
    DetachDebugger(pid);
  } else if (interrupted && !keep_stopped) {
    ptrace(PTRACE_CONT, pid, nullptr, nullptr);
  }
  return true;
#else
  (void)pid;
  (void)out;
  (void)already_attached;
  (void)keep_stopped;
  return false;
#endif
}

#if defined(__aarch64__)
struct CompatArmRegs32 {
  uint32_t uregs[18];
};

bool GetRegsAarch64(pid_t pid,
                    bool already_attached,
                    bool keep_stopped,
                    protocol::RegsArch* arch,
                    protocol::Arm64Regs* out64,
                    protocol::Arm32Regs* out32) {
  if (!arch) {
    return false;
  }
  bool attached = already_attached;
  if (!attached) {
    if (!AttachDebugger(pid)) {
      return false;
    }
    attached = true;
  }
  bool interrupted = false;

  constexpr size_t kRegset64Size = sizeof(struct user_pt_regs);
  constexpr size_t kRegset32Size = sizeof(CompatArmRegs32);
  const size_t buf_size = std::max(kRegset64Size, kRegset32Size);
  std::vector<uint8_t> buffer(buf_size);
  struct iovec iov;
  iov.iov_base = buffer.data();
  iov.iov_len = buffer.size();
  auto read_once = [&]() -> bool {
    iov.iov_len = buffer.size();
    return ptrace(PTRACE_GETREGSET, pid, (void*)NT_PRSTATUS, &iov) != -1;
  };
  bool ok = read_once();
  if (!ok && already_attached) {
    if (EnsureTraceeStopped(pid, 1000, &interrupted)) {
      ok = read_once();
    }
  }
  if (!ok) {
    std::fprintf(stderr, "[R3Agent] ptrace getregset failed pid=%d errno=%d\n", pid, errno);
    if (!already_attached) {
      DetachDebugger(pid);
    } else if (interrupted && !keep_stopped) {
      ptrace(PTRACE_CONT, pid, nullptr, nullptr);
    }
    return false;
  }
  if (!already_attached) {
    DetachDebugger(pid);
  } else if (interrupted && !keep_stopped) {
    ptrace(PTRACE_CONT, pid, nullptr, nullptr);
  }

  if (iov.iov_len >= sizeof(struct user_pt_regs)) {
    const struct user_pt_regs* regs = reinterpret_cast<const struct user_pt_regs*>(buffer.data());
    if (out64) {
      for (int i = 0; i < 31; ++i) {
        out64->regs[i] = regs->regs[i];
      }
      out64->sp = regs->sp;
      out64->pc = regs->pc;
      out64->pstate = regs->pstate;
    }
    *arch = protocol::RegsArch::ARM64;
    return true;
  }

  if (iov.iov_len >= sizeof(CompatArmRegs32)) {
    const CompatArmRegs32* regs32 = reinterpret_cast<const CompatArmRegs32*>(buffer.data());
    if (out32) {
      for (int i = 0; i < 16; ++i) {
        out32->regs[i] = regs32->uregs[i];
      }
      out32->cpsr = regs32->uregs[16];
      out32->orig_r0 = regs32->uregs[17];
    }
    *arch = protocol::RegsArch::ARM32;
    return true;
  }

  return false;
}
#endif

bool DebugStepIn(pid_t pid, std::string* err) {
  if (err) {
    err->clear();
  }
  if (pid <= 0) {
    if (err) {
      *err = "invalid pid";
    }
    return false;
  }
  bool interrupted = false;
  if (!EnsureTraceeStopped(pid, 1000, &interrupted)) {
    if (err) {
      *err = "tracee not stopped";
    }
    return false;
  }
  if (ptrace(PTRACE_SINGLESTEP, pid, nullptr, nullptr) == -1) {
    if (err) {
      char buf[96] = {0};
      std::snprintf(buf, sizeof(buf), "singlestep failed errno=%d", errno);
      *err = buf;
    }
    return false;
  }
  if (!WaitForStop(pid, 5000)) {
    if (err) {
      *err = "singlestep wait timeout";
    }
    return false;
  }
  return true;
}

#if defined(__aarch64__)
namespace {
bool ReadAarch64Regs(pid_t pid, struct user_pt_regs* out, std::string* err) {
  if (!out) {
    if (err) {
      *err = "invalid regs buffer";
    }
    return false;
  }
  struct iovec iov{};
  iov.iov_base = out;
  iov.iov_len = sizeof(*out);
  if (ptrace(PTRACE_GETREGSET, pid, reinterpret_cast<void*>(NT_PRSTATUS), &iov) == -1) {
    if (err) {
      char buf[96] = {0};
      std::snprintf(buf, sizeof(buf), "getregset failed errno=%d", errno);
      *err = buf;
    }
    return false;
  }
  return true;
}

bool WriteAarch64Regs(pid_t pid, const struct user_pt_regs& regs, std::string* err) {
  struct user_pt_regs copy = regs;
  struct iovec iov{};
  iov.iov_base = &copy;
  iov.iov_len = sizeof(copy);
  if (ptrace(PTRACE_SETREGSET, pid, reinterpret_cast<void*>(NT_PRSTATUS), &iov) == -1) {
    if (err) {
      char buf[96] = {0};
      std::snprintf(buf, sizeof(buf), "setregset failed errno=%d", errno);
      *err = buf;
    }
    return false;
  }
  return true;
}

bool ReadInsn32(pid_t pid, uint64_t address, uint32_t* out_insn, std::string* err) {
  if (!out_insn) {
    if (err) {
      *err = "invalid insn buffer";
    }
    return false;
  }
  const uint64_t word_addr = address & ~0x7ull;
  const bool upper = (address & 0x4u) != 0;
  errno = 0;
  long data = ptrace(PTRACE_PEEKTEXT, pid, reinterpret_cast<void*>(word_addr), nullptr);
  if (data == -1 && errno != 0) {
    if (err) {
      char buf[96] = {0};
      std::snprintf(buf, sizeof(buf), "peektext failed errno=%d", errno);
      *err = buf;
    }
    return false;
  }
  const uint64_t word = static_cast<uint64_t>(data);
  *out_insn = upper ? static_cast<uint32_t>(word >> 32) : static_cast<uint32_t>(word & 0xFFFFFFFFu);
  return true;
}

bool PatchInsn32(pid_t pid, uint64_t address, uint32_t replacement, uint32_t* out_original, std::string* err) {
  const uint64_t word_addr = address & ~0x7ull;
  const bool upper = (address & 0x4u) != 0;
  errno = 0;
  long data = ptrace(PTRACE_PEEKTEXT, pid, reinterpret_cast<void*>(word_addr), nullptr);
  if (data == -1 && errno != 0) {
    if (err) {
      char buf[96] = {0};
      std::snprintf(buf, sizeof(buf), "peektext failed errno=%d", errno);
      *err = buf;
    }
    return false;
  }
  const uint64_t word = static_cast<uint64_t>(data);
  const uint32_t original = upper ? static_cast<uint32_t>(word >> 32) : static_cast<uint32_t>(word & 0xFFFFFFFFu);
  uint64_t patched_word = word;
  if (upper) {
    patched_word = (word & 0x00000000FFFFFFFFull) | (static_cast<uint64_t>(replacement) << 32);
  } else {
    patched_word = (word & 0xFFFFFFFF00000000ull) | static_cast<uint64_t>(replacement);
  }
  if (ptrace(PTRACE_POKETEXT,
             pid,
             reinterpret_cast<void*>(word_addr),
             reinterpret_cast<void*>(static_cast<long>(patched_word))) == -1) {
    if (err) {
      char buf[96] = {0};
      std::snprintf(buf, sizeof(buf), "poketext failed errno=%d", errno);
      *err = buf;
    }
    return false;
  }
  if (out_original) {
    *out_original = original;
  }
  return true;
}

bool IsAarch64CallInstruction(uint32_t insn) {
  const bool bl_imm = (insn & 0xFC000000u) == 0x94000000u;
  const bool blr_reg = (insn & 0xFFFFFC1Fu) == 0xD63F0000u;
  return bl_imm || blr_reg;
}
}  // namespace
#endif

bool DebugStepOver(pid_t pid, std::string* err) {
  if (err) {
    err->clear();
  }
  if (pid <= 0) {
    if (err) {
      *err = "invalid pid";
    }
    return false;
  }
#if defined(__aarch64__)
  bool interrupted = false;
  if (!EnsureTraceeStopped(pid, 1000, &interrupted)) {
    if (err) {
      *err = "tracee not stopped";
    }
    return false;
  }

  struct user_pt_regs regs{};
  if (!ReadAarch64Regs(pid, &regs, err)) {
    return false;
  }
  const uint64_t pc = StripTag64(regs.pc);
  uint32_t insn = 0;
  if (!ReadInsn32(pid, pc, &insn, err)) {
    return false;
  }
  if (!IsAarch64CallInstruction(insn)) {
    return DebugStepIn(pid, err);
  }

  const uint64_t next_pc = pc + 4;
  uint32_t original_next = 0;
  if (!PatchInsn32(pid, next_pc, kAarch64BrkInsn, &original_next, err)) {
    return false;
  }

  if (ptrace(PTRACE_CONT, pid, nullptr, nullptr) == -1) {
    std::string restore_err;
    PatchInsn32(pid, next_pc, original_next, nullptr, &restore_err);
    if (err) {
      char buf[96] = {0};
      std::snprintf(buf, sizeof(buf), "continue failed errno=%d", errno);
      *err = buf;
    }
    return false;
  }

  const bool stopped = WaitForStop(pid, 5000);
  std::string restore_err;
  const bool restored = PatchInsn32(pid, next_pc, original_next, nullptr, &restore_err);
  if (!stopped) {
    if (err) {
      *err = "step-over wait timeout";
    }
    return false;
  }
  if (!restored) {
    if (err) {
      *err = restore_err.empty() ? "restore step-over breakpoint failed" : restore_err;
    }
    return false;
  }

  struct user_pt_regs after_regs{};
  if (ReadAarch64Regs(pid, &after_regs, nullptr)) {
    const uint64_t after_pc = StripTag64(after_regs.pc);
    if (after_pc == next_pc || after_pc == (next_pc + 4)) {
      after_regs.pc = next_pc;
      std::string setreg_err;
      WriteAarch64Regs(pid, after_regs, &setreg_err);
    }
  }
  return true;
#else
  return DebugStepIn(pid, err);
#endif
}
}

int main(int argc, char** argv) {
  std::signal(SIGPIPE, SIG_IGN);
  setvbuf(stdout, nullptr, _IONBF, 0);
  setvbuf(stderr, nullptr, _IONBF, 0);
  LogAgent("[R3Agent] start pid=%d", getpid());

  int port = kListenPort;
  if (argc > 1 && argv[1]) {
    char* endptr = nullptr;
    long parsed = std::strtol(argv[1], &endptr, 10);
    if (endptr != argv[1] && parsed > 0 && parsed < 65536) {
      port = static_cast<int>(parsed);
    }
  }

  int server_fd = socket(AF_INET, SOCK_STREAM, 0);
  if (server_fd < 0) {
    return 1;
  }

  int opt = 1;
  setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(static_cast<uint16_t>(port));
  addr.sin_addr.s_addr = htonl(INADDR_ANY);

  if (bind(server_fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
    close(server_fd);
    return 1;
  }

  if (listen(server_fd, 8) < 0) {
    close(server_fd);
    return 1;
  }

  while (true) {
    sockaddr_in client_addr{};
    socklen_t client_len = sizeof(client_addr);
    int client_fd = accept(server_fd, reinterpret_cast<sockaddr*>(&client_addr), &client_len);
    if (client_fd < 0) {
      if (errno == EINTR) {
        continue;
      }
      break;
    }

    std::thread(HandleClient, client_fd).detach();
  }

  close(server_fd);
  return 0;
}
