#include "SafeMemoryReader.h"

#include <algorithm>
#include <cerrno>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dlfcn.h>
#include <fstream>
#include <sstream>

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/syscall.h>
#include <unistd.h>

#if defined(__ANDROID__)
#include <android/log.h>
#include <sys/auxv.h>
#endif

namespace {
uint64_t AlignDown(uint64_t value, size_t align) {
  if (align == 0) {
    return value;
  }
  return value & ~(static_cast<uint64_t>(align) - 1u);
}

ssize_t PRead64Compat(int fd, void* buf, size_t len, uint64_t off) {
#if defined(__ANDROID__)
  return pread64(fd, buf, len, static_cast<off64_t>(off));
#else
  return pread(fd, buf, len, static_cast<off_t>(off));
#endif
}

ssize_t PWrite64Compat(int fd, const void* buf, size_t len, uint64_t off) {
#if defined(__ANDROID__)
  return pwrite64(fd, buf, len, static_cast<off64_t>(off));
#else
  return pwrite(fd, buf, len, static_cast<off_t>(off));
#endif
}

void* MMap64Compat(int fd, size_t len, uint64_t off) {
#if defined(__ANDROID__)
  return mmap64(nullptr, len, PROT_READ, MAP_SHARED, fd, static_cast<off64_t>(off));
#else
  return mmap(nullptr, len, PROT_READ, MAP_SHARED, fd, static_cast<off_t>(off));
#endif
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
}

SafeMemoryReader::SafeMemoryReader(pid_t pid)
    : pid_(pid),
      mem_fd_(-1),
      mem_w_fd_(-1),
      pagemap_fd_(-1),
      page_size_(0),
      mincore_enabled_(true),
      mincore_logged_(false),
      pagemap_logged_(false) {}

SafeMemoryReader::~SafeMemoryReader() { Close(); }

bool SafeMemoryReader::Open() {
  if (mem_fd_ >= 0) {
    return true;
  }

  char path[64] = {0};
  std::snprintf(path, sizeof(path), "/proc/%d/mem", pid_);
  mem_fd_ = open(path, O_RDONLY | O_LARGEFILE | O_CLOEXEC);
  return mem_fd_ >= 0;
}

bool SafeMemoryReader::OpenWrite() {
  if (mem_w_fd_ >= 0) {
    return true;
  }

  char path[64] = {0};
  std::snprintf(path, sizeof(path), "/proc/%d/mem", pid_);
  mem_w_fd_ = open(path, O_RDWR | O_LARGEFILE | O_CLOEXEC);
  return mem_w_fd_ >= 0;
}

bool SafeMemoryReader::OpenPagemap() {
  if (pagemap_fd_ >= 0) {
    return true;
  }

  char path[64] = {0};
  std::snprintf(path, sizeof(path), "/proc/%d/pagemap", pid_);
  pagemap_fd_ = open(path, O_RDONLY | O_CLOEXEC);
  return pagemap_fd_ >= 0;
}

void SafeMemoryReader::Close() {
  if (mem_fd_ >= 0) {
    close(mem_fd_);
    mem_fd_ = -1;
  }
  if (mem_w_fd_ >= 0) {
    close(mem_w_fd_);
    mem_w_fd_ = -1;
  }
  if (pagemap_fd_ >= 0) {
    close(pagemap_fd_);
    pagemap_fd_ = -1;
  }
}

bool SafeMemoryReader::EnsurePageSize() {
  if (page_size_ != 0) {
    return true;
  }

#if defined(__ANDROID__) && defined(AT_PAGESZ)
  unsigned long val = getauxval(AT_PAGESZ);
  if (val != 0) {
    page_size_ = static_cast<size_t>(val);
  }
#endif

  if (page_size_ == 0) {
    long val = sysconf(_SC_PAGESIZE);
    if (val > 0) {
      page_size_ = static_cast<size_t>(val);
    }
  }

  return page_size_ != 0;
}

uint64_t SafeMemoryReader::StripTag(uint64_t addr) const {
#if defined(__aarch64__)
  return addr & 0x00FFFFFFFFFFFFFFull;
#else
  return addr;
#endif
}

bool SafeMemoryReader::ParseMapsLine(const std::string& line, MemoryRegion* out) {
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
  out->readable = !perms.empty() && perms[0] == 'r';
  out->writable = perms.size() > 1 && perms[1] == 'w';
  out->executable = perms.size() > 2 && perms[2] == 'x';
  return true;
}

bool SafeMemoryReader::RefreshMaps() {
  regions_.clear();

  char path[64] = {0};
  std::snprintf(path, sizeof(path), "/proc/%d/maps", pid_);
  std::ifstream file(path);
  if (!file.is_open()) {
    return false;
  }

  std::string line;
  while (std::getline(file, line)) {
    MemoryRegion region;
    if (ParseMapsLine(line, &region)) {
      regions_.push_back(region);
    }
  }

  return !regions_.empty();
}

const std::vector<SafeMemoryReader::MemoryRegion>& SafeMemoryReader::regions() const {
  return regions_;
}

bool SafeMemoryReader::IsPageResident(uint64_t page_start) {
  if (mem_fd_ < 0) {
    return false;
  }
  if (!EnsurePageSize()) {
    return false;
  }

  const uint64_t aligned = AlignDown(page_start, page_size_);
  if (mincore_enabled_) {
    void* map = MMap64Compat(mem_fd_, page_size_, aligned);
    if (map != MAP_FAILED) {
      unsigned char vec = 0;
      const int rc = mincore(map, page_size_, &vec);
      const int saved_errno = errno;
      munmap(map, page_size_);

      if (rc == 0) {
        if ((vec & 0x1) != 0) {
          return true;
        }
        if (IsPageResidentPagemap(aligned)) {
          mincore_enabled_ = false;
          if (!mincore_logged_) {
#if defined(__ANDROID__)
            __android_log_print(ANDROID_LOG_WARN, "R3Agent",
                                "mincore unreliable, switching to pagemap");
#endif
            mincore_logged_ = true;
          }
          return true;
        }
        return false;
      }

      if (saved_errno == ENOSYS || saved_errno == EINVAL || saved_errno == EPERM) {
        mincore_enabled_ = false;
        if (!mincore_logged_) {
#if defined(__ANDROID__)
          __android_log_print(ANDROID_LOG_WARN, "R3Agent",
                              "mincore disabled errno=%d, using pagemap", saved_errno);
#endif
          mincore_logged_ = true;
        }
      }
    } else {
      if (errno == EPERM || errno == EACCES) {
        mincore_enabled_ = false;
        if (!mincore_logged_) {
#if defined(__ANDROID__)
          __android_log_print(ANDROID_LOG_WARN, "R3Agent",
                              "mincore mmap denied, using pagemap");
#endif
          mincore_logged_ = true;
        }
      }
    }
  }

  return IsPageResidentPagemap(aligned);
}

bool SafeMemoryReader::IsPageResidentPagemap(uint64_t page_start) {
  if (!EnsurePageSize()) {
    return false;
  }
  if (pagemap_fd_ < 0 && !OpenPagemap()) {
    if (!pagemap_logged_) {
#if defined(__ANDROID__)
      __android_log_print(ANDROID_LOG_WARN, "R3Agent",
                          "open pagemap failed");
#endif
      pagemap_logged_ = true;
    }
    return false;
  }

  const uint64_t page_index = page_start / page_size_;
  const uint64_t offset = page_index * sizeof(uint64_t);
  uint64_t entry = 0;
  const ssize_t n = PRead64Compat(pagemap_fd_, &entry, sizeof(entry), offset);
  if (n != static_cast<ssize_t>(sizeof(entry))) {
    if (!pagemap_logged_) {
#if defined(__ANDROID__)
      __android_log_print(ANDROID_LOG_WARN, "R3Agent",
                          "pagemap read failed");
#endif
      pagemap_logged_ = true;
    }
    return false;
  }

  constexpr uint64_t kPresentMask = 1ULL << 63;
  return (entry & kPresentMask) != 0;
}

bool SafeMemoryReader::ValidateAndRead(uint64_t addr, void* out, size_t size, ReadStats* stats) {
  return ValidateAndReadEx(addr, out, size, stats, false, false);
}

bool SafeMemoryReader::ValidateAndReadEx(uint64_t addr,
                                         void* out,
                                         size_t size,
                                         ReadStats* stats,
                                         bool allow_nonresident,
                                         bool ignore_perms) {
  return ValidateAndReadEx(addr, out, size, stats, allow_nonresident, ignore_perms, false, false);
}

bool SafeMemoryReader::ValidateAndReadEx(uint64_t addr,
                                         void* out,
                                         size_t size,
                                         ReadStats* stats,
                                         bool allow_nonresident,
                                         bool ignore_perms,
                                         bool use_pvm,
                                         bool fast_mode) {
  ReadStats local_stats;
  if (!stats) {
    stats = &local_stats;
  }

  stats->bytes_requested = size;
  stats->bytes_read = 0;
  stats->bytes_skipped = 0;
  stats->pages_checked = 0;
  stats->pages_skipped = 0;
  stats->read_syscalls = 0;
  stats->last_errno = 0;

  if (size == 0) {
    return true;
  }
  if (!out) {
    return false;
  }
  if (!EnsurePageSize()) {
    return false;
  }
  if (mem_fd_ < 0) {
    if (!Open()) {
      if (!use_pvm) {
        return false;
      }
      // process_vm_readv path can proceed without /proc/pid/mem;
      // skip mincore checks since mmap will be unavailable.
      allow_nonresident = true;
    }
  }
  if (regions_.empty() && !RefreshMaps()) {
    return false;
  }

  const uint64_t base = StripTag(addr);
  if (base > UINT64_MAX - static_cast<uint64_t>(size)) {
    return false;
  }
  const uint64_t end = base + static_cast<uint64_t>(size);

  auto read_once = [&](uint64_t cur, size_t chunk_len) -> ssize_t {
    ssize_t n = 0;
    if (use_pvm) {
      struct iovec local_iov;
      local_iov.iov_base = static_cast<char*>(out) + (cur - base);
      local_iov.iov_len = chunk_len;
      struct iovec remote_iov;
      remote_iov.iov_base = reinterpret_cast<void*>(cur);
      remote_iov.iov_len = chunk_len;
      n = ProcessVmReadvCompat(pid_, &local_iov, 1, &remote_iov, 1, 0);
      stats->read_syscalls++;
      if (n < 0) {
        const int e = errno;
        if ((e == ESRCH || e == EPERM || e == ENOSYS) &&
            (mem_fd_ >= 0 || Open())) {
          n = PRead64Compat(mem_fd_,
                            static_cast<char*>(out) + (cur - base),
                            chunk_len,
                            cur);
          stats->read_syscalls++;
        }
      }
    } else {
      n = PRead64Compat(mem_fd_,
                        static_cast<char*>(out) + (cur - base),
                        chunk_len,
                        cur);
      stats->read_syscalls++;
    }
    return n;
  };

  const bool use_fast_chunk_path = fast_mode && allow_nonresident && !ignore_perms;
  if (use_fast_chunk_path) {
    const size_t min_chunk = 64 * 1024;
    const size_t max_chunk = 4 * 1024 * 1024;
    size_t chunk_size = size / 8;
    if (chunk_size < min_chunk) {
      chunk_size = min_chunk;
    }
    if (chunk_size > max_chunk) {
      chunk_size = max_chunk;
    }
    if (chunk_size < page_size_) {
      chunk_size = page_size_;
    }
    chunk_size = (chunk_size / page_size_) * page_size_;
    if (chunk_size == 0) {
      chunk_size = page_size_;
    }

    for (const auto& region : regions_) {
      if (!ignore_perms && !region.readable) {
        continue;
      }
      if (region.end <= base || region.start >= end) {
        continue;
      }

      uint64_t cur = std::max(base, region.start);
      const uint64_t region_end = std::min(end, region.end);
      while (cur < region_end) {
        const size_t chunk_len =
            static_cast<size_t>(std::min<uint64_t>(region_end - cur, static_cast<uint64_t>(chunk_size)));
        const uint64_t pages = (chunk_len + page_size_ - 1) / page_size_;
        stats->pages_checked += static_cast<size_t>(pages);

        const ssize_t n = read_once(cur, chunk_len);
        if (n < 0) {
          const int e = errno;
          stats->last_errno = e;
          if (e == EIO || e == EFAULT) {
            stats->pages_skipped += static_cast<size_t>(pages);
            cur += chunk_len;
            continue;
          }
          return false;
        }

        stats->bytes_read += static_cast<size_t>(n);
        if (n < static_cast<ssize_t>(chunk_len)) {
          const size_t read_pages = (static_cast<size_t>(n) + page_size_ - 1) / page_size_;
          if (pages > read_pages) {
            stats->pages_skipped += (pages - read_pages);
          }
        }
        cur += chunk_len;
      }
    }

    if (stats->bytes_read <= size) {
      stats->bytes_skipped = size - stats->bytes_read;
    } else {
      stats->bytes_skipped = 0;
    }
    return true;
  }

  for (const auto& region : regions_) {
    if (!ignore_perms && !region.readable) {
      continue;
    }
    if (region.end <= base || region.start >= end) {
      continue;
    }

    uint64_t cur = std::max(base, region.start);
    const uint64_t region_end = std::min(end, region.end);

    while (cur < region_end) {
      const uint64_t page_start = AlignDown(cur, page_size_);
      const uint64_t page_end = page_start + page_size_;
      const uint64_t chunk_end = std::min(region_end, page_end);
      const size_t chunk_len = static_cast<size_t>(chunk_end - cur);

      stats->pages_checked++;
      if (!allow_nonresident) {
        if (!IsPageResident(page_start)) {
          stats->pages_skipped++;
          cur = chunk_end;
          continue;
        }
      }

      const ssize_t n = read_once(cur, chunk_len);
      if (n < 0) {
        const int e = errno;
        stats->last_errno = e;
        if (e == EIO || e == EFAULT) {
          stats->pages_skipped++;
          cur = chunk_end;
          continue;
        }
        return false;
      }

      stats->bytes_read += static_cast<size_t>(n);
      if (n < static_cast<ssize_t>(chunk_len)) {
        cur = chunk_end;
        continue;
      }

      cur = chunk_end;
    }
  }

  if (stats->bytes_read <= size) {
    stats->bytes_skipped = size - stats->bytes_read;
  } else {
    stats->bytes_skipped = 0;
  }

  return true;
}

bool SafeMemoryReader::ValidateAndWrite(uint64_t addr, const void* data, size_t size, WriteStats* stats) {
  WriteStats local_stats;
  if (!stats) {
    stats = &local_stats;
  }

  stats->bytes_requested = size;
  stats->bytes_written = 0;
  stats->bytes_skipped = 0;
  stats->pages_checked = 0;
  stats->pages_skipped = 0;
  stats->last_errno = 0;

  if (size == 0) {
    return true;
  }
  if (!data) {
    return false;
  }
  if (!EnsurePageSize()) {
    return false;
  }
  if (mem_fd_ < 0 && !Open()) {
    return false;
  }
  if (mem_w_fd_ < 0 && !OpenWrite()) {
    return false;
  }
  if (regions_.empty() && !RefreshMaps()) {
    return false;
  }

  const uint64_t base = StripTag(addr);
  if (base > UINT64_MAX - static_cast<uint64_t>(size)) {
    return false;
  }
  const uint64_t end = base + static_cast<uint64_t>(size);

  for (const auto& region : regions_) {
    if (!region.writable) {
      continue;
    }
    if (region.end <= base || region.start >= end) {
      continue;
    }

    uint64_t cur = std::max(base, region.start);
    const uint64_t region_end = std::min(end, region.end);

    while (cur < region_end) {
      const uint64_t page_start = AlignDown(cur, page_size_);
      const uint64_t page_end = page_start + page_size_;
      const uint64_t chunk_end = std::min(region_end, page_end);
      const size_t chunk_len = static_cast<size_t>(chunk_end - cur);

      stats->pages_checked++;
      if (!IsPageResident(page_start)) {
        stats->pages_skipped++;
        cur = chunk_end;
        continue;
      }

      const ssize_t n = PWrite64Compat(mem_w_fd_,
                                       static_cast<const char*>(data) + (cur - base),
                                       chunk_len,
                                       cur);
      if (n < 0) {
        const int e = errno;
        stats->last_errno = e;
        if (e == EIO || e == EFAULT) {
          stats->pages_skipped++;
          cur = chunk_end;
          continue;
        }
        return false;
      }

      stats->bytes_written += static_cast<size_t>(n);
      if (n < static_cast<ssize_t>(chunk_len)) {
        cur = chunk_end;
        continue;
      }

      cur = chunk_end;
    }
  }

  if (stats->bytes_written <= size) {
    stats->bytes_skipped = size - stats->bytes_written;
  } else {
    stats->bytes_skipped = 0;
  }

  return true;
}

bool SafeMemoryReader::ResolvePointerChain(uint64_t base,
                                           const std::vector<uint64_t>& offsets,
                                           size_t pointer_size,
                                           uint64_t* out_addr) {
  if (pointer_size != 4 && pointer_size != 8) {
    return false;
  }
  if (offsets.empty()) {
    if (out_addr) {
      *out_addr = StripTag(base);
    }
    return true;
  }

  uint64_t current = StripTag(base);
  for (size_t i = 0; i < offsets.size(); ++i) {
    if (current > UINT64_MAX - offsets[i]) {
      return false;
    }

    const uint64_t read_addr = current + offsets[i];
    ReadStats stats;

    if (pointer_size == 8) {
      uint64_t next = 0;
      if (!ValidateAndRead(read_addr, &next, sizeof(next), &stats)) {
        return false;
      }
      if (stats.bytes_read < sizeof(next)) {
        return false;
      }
      current = StripTag(next);
    } else {
      uint32_t next32 = 0;
      if (!ValidateAndRead(read_addr, &next32, sizeof(next32), &stats)) {
        return false;
      }
      if (stats.bytes_read < sizeof(next32)) {
        return false;
      }
      current = static_cast<uint64_t>(next32);
    }
  }

  if (out_addr) {
    *out_addr = current;
  }
  return true;
}

bool SafeMemoryReader::ResolvePointerChainAfterDeref(uint64_t base,
                                                     const int64_t* offsets,
                                                     size_t count,
                                                     size_t pointer_size,
                                                     uint64_t* out_addr,
                                                     bool allow_nonresident,
                                                     bool use_pvm) {
  if (pointer_size != 4 && pointer_size != 8) {
    return false;
  }
  uint64_t current = StripTag(base);
  if (!offsets || count == 0) {
    if (out_addr) {
      *out_addr = current;
    }
    return true;
  }

  for (size_t i = 0; i < count; ++i) {
    ReadStats stats{};
    if (pointer_size == 8) {
      uint64_t next = 0;
      if (!ValidateAndReadEx(current, &next, sizeof(next), &stats, allow_nonresident, false, use_pvm)) {
        return false;
      }
      if (stats.bytes_read < sizeof(next)) {
        return false;
      }
      next = StripTag(next);
      if (next == 0) {
        return false;
      }
      const int64_t off = offsets[i];
      if (off >= 0) {
        const uint64_t uoff = static_cast<uint64_t>(off);
        if (next > UINT64_MAX - uoff) {
          return false;
        }
        current = next + uoff;
      } else {
        const uint64_t uoff = static_cast<uint64_t>(-off);
        if (next < uoff) {
          return false;
        }
        current = next - uoff;
      }
    } else {
      uint32_t next32 = 0;
      if (!ValidateAndReadEx(current, &next32, sizeof(next32), &stats, allow_nonresident, false, use_pvm)) {
        return false;
      }
      if (stats.bytes_read < sizeof(next32)) {
        return false;
      }
      uint64_t next = static_cast<uint64_t>(next32);
      if (next == 0) {
        return false;
      }
      const int64_t off = offsets[i];
      if (off >= 0) {
        const uint64_t uoff = static_cast<uint64_t>(off);
        if (next > UINT64_MAX - uoff) {
          return false;
        }
        current = next + uoff;
      } else {
        const uint64_t uoff = static_cast<uint64_t>(-off);
        if (next < uoff) {
          return false;
        }
        current = next - uoff;
      }
    }
  }

  if (out_addr) {
    *out_addr = current;
  }
  return true;
}
