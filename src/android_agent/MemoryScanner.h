#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

#include "SafeMemoryReader.h"
#include "../protocol/Protocol.h"

class MemoryScanner {
 public:
  explicit MemoryScanner(SafeMemoryReader* reader);

  void SetReader(SafeMemoryReader* reader);
  void SetScanRange(uint64_t start_addr, uint64_t end_addr);
  void SetUsePvm(bool enable);
  void SetAllowNonresident(bool enable);
  void SetByteStep(bool enable);
  void SetStrict(bool enable);
  void SetRequireWritable(bool enable);
  void SetRequireExecutable(bool enable);
  void SetRegionTypeMask(uint8_t mask);
  void SetGGRegionCode(uint8_t code);
  void Clear();

  bool FirstScan(protocol::ValueType type, const void* value, size_t value_len,
                 protocol::ComparisonType condition);
  bool NextScan(protocol::ValueType type, const void* value, size_t value_len,
                protocol::ComparisonType condition);

  const std::vector<uint64_t>& results() const { return results_; }

 private:
  static size_t ValueSize(protocol::ValueType type);
  static bool LoadTarget(protocol::ValueType type, const void* value,
                         uint64_t* out_bits, double* out_fp);
  static bool CompareInteger(uint64_t actual, uint64_t target,
                             protocol::ComparisonType condition);
  static bool CompareIntegerSigned(int64_t actual, int64_t target,
                                   protocol::ComparisonType condition);
  static bool CompareFloat(double actual, double target,
                           protocol::ComparisonType condition);
  static int64_t BitsToSigned(protocol::ValueType type, uint64_t bits);

  bool ReadValue(uint64_t addr, protocol::ValueType type,
                 uint64_t* out_bits, double* out_fp);

  SafeMemoryReader* reader_;
  std::vector<uint64_t> results_;
  std::vector<uint64_t> last_values_;
  uint64_t scan_start_;
  uint64_t scan_end_;
  bool use_pvm_ = false;
  bool allow_nonresident_ = false;
  bool byte_step_ = false;
  bool strict_ = false;
  bool require_writable_ = false;
  bool require_executable_ = false;
  uint8_t region_type_mask_ = 0;
  uint8_t gg_region_code_ = 0;
};
