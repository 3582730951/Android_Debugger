#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "../protocol/Protocol.h"

namespace r3::windows_client_ng::app {

struct ProcessItem {
  uint32_t pid = 0;
  std::wstring name;
};

struct AddressEntry {
  bool active = false;
  std::wstring desc;
  uint64_t addr = 0;
  protocol::ValueType type = protocol::ValueType::U32;
  std::wstring value;
  bool value_hex = false;
  bool value_signed = false;
  bool is_pointer = false;
  bool frozen = false;
  std::vector<int64_t> offsets;
  std::vector<uint8_t> last_read_bytes;
  std::vector<uint8_t> freeze_bytes;
};

struct UiState {
  std::string host = "127.0.0.1";
  uint16_t port = 12345;

  bool connected = false;
  uint32_t pid = 0;

  uint64_t match_total = 0;
  std::wstring process_caption = L"未选择进程";
  std::wstring status = L"未连接";
  uint8_t arch = static_cast<uint8_t>(protocol::RegsArch::UNKNOWN);
  uint8_t pointer_size = 0;

  protocol::ValueType scan_value_type = protocol::ValueType::U32;
  protocol::ComparisonType scan_condition = protocol::ComparisonType::EQ;
  bool scan_value_hex = false;
  bool scan_use_pvm = true;
  bool scan_fast = true;
  bool scan_writable = true;
  bool scan_executable = false;
  bool scan_copy_on_write = false;
  bool scan_private = true;
  bool scan_image = false;
  bool scan_mapped = false;
  std::string scan_value_text = "0";
  std::string scan_start_text = "";
  std::string scan_end_text = "";
  uint64_t page_index = 0;
  uint32_t page_size = 128;
  std::vector<uint64_t> page_addresses;
  std::vector<AddressEntry> address_entries;

  std::vector<ProcessItem> processes;
};

}  // namespace r3::windows_client_ng::app
