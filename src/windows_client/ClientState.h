#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "../protocol/Protocol.h"

struct ClientState {
  bool connected = false;
  std::string status;

  uint32_t pid = 0;

  struct ProcessInfo {
    uint32_t pid = 0;
    std::string name;
  };
  std::vector<ProcessInfo> processes;

  struct ModuleInfo {
    uint64_t start = 0;
    uint64_t end = 0;
    uint32_t perms = 0;
    std::string path;
  };
  std::vector<ModuleInfo> modules;

  protocol::ValueType value_type = protocol::ValueType::U32;
  protocol::ComparisonType condition = protocol::ComparisonType::EQ;
  uint64_t scan_start = 0;
  uint64_t scan_end = 0;
  std::string value_input = "";

  uint64_t scan_total = 0;
  uint64_t page_index = 0;
  uint32_t page_size = 128;
  std::vector<uint64_t> page_addresses;

  uint64_t mem_view_addr = 0;
  uint32_t mem_view_size = 256;
  std::vector<uint8_t> mem_view_data;

  protocol::RegsArch regs_arch = protocol::RegsArch::UNKNOWN;
  uint8_t pointer_size = 0;
  protocol::Arm64Regs regs64{};
  protocol::Arm32Regs regs32{};
  bool regs_valid = false;
};
