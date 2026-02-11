#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>
#include <sys/types.h>

class SafeMemoryReader {
 public:
  struct MemoryRegion {
    uint64_t start = 0;
    uint64_t end = 0;
    std::string perms;
    std::string path;
    bool readable = false;
    bool writable = false;
    bool executable = false;

    bool Contains(uint64_t addr) const { return addr >= start && addr < end; }
  };

  struct ReadStats {
    size_t bytes_requested = 0;
    size_t bytes_read = 0;
    size_t bytes_skipped = 0;
    size_t pages_checked = 0;
    size_t pages_skipped = 0;
    size_t read_syscalls = 0;
    int last_errno = 0;
  };

  struct WriteStats {
    size_t bytes_requested = 0;
    size_t bytes_written = 0;
    size_t bytes_skipped = 0;
    size_t pages_checked = 0;
    size_t pages_skipped = 0;
    int last_errno = 0;
  };

  explicit SafeMemoryReader(pid_t pid);
  ~SafeMemoryReader();

  bool Open();
  bool OpenWrite();
  bool OpenPagemap();
  void Close();

  pid_t pid() const { return pid_; }

  bool RefreshMaps();
  const std::vector<MemoryRegion>& regions() const;

  bool ValidateAndRead(uint64_t addr, void* out, size_t size, ReadStats* stats);
  bool ValidateAndReadEx(uint64_t addr,
                         void* out,
                         size_t size,
                         ReadStats* stats,
                         bool allow_nonresident,
                         bool ignore_perms);
  bool ValidateAndReadEx(uint64_t addr,
                         void* out,
                         size_t size,
                         ReadStats* stats,
                         bool allow_nonresident,
                         bool ignore_perms,
                         bool use_pvm,
                         bool fast_mode = false);
  bool ValidateAndWrite(uint64_t addr, const void* data, size_t size, WriteStats* stats);

  bool ResolvePointerChain(uint64_t base,
                           const std::vector<uint64_t>& offsets,
                           size_t pointer_size,
                           uint64_t* out_addr);
  bool ResolvePointerChainAfterDeref(uint64_t base,
                                     const int64_t* offsets,
                                     size_t count,
                                     size_t pointer_size,
                                     uint64_t* out_addr,
                                     bool allow_nonresident,
                                     bool use_pvm);

 private:
  bool EnsurePageSize();
  size_t page_size() const { return page_size_; }
  uint64_t StripTag(uint64_t addr) const;
  bool IsPageResident(uint64_t page_start);
  bool IsPageResidentPagemap(uint64_t page_start);
  bool ParseMapsLine(const std::string& line, MemoryRegion* out);

  pid_t pid_;
  int mem_fd_;
  int mem_w_fd_;
  int pagemap_fd_;
  size_t page_size_;
  bool mincore_enabled_;
  bool mincore_logged_;
  bool pagemap_logged_;
  std::vector<MemoryRegion> regions_;
};
