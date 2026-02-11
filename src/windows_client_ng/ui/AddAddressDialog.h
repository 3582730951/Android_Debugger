#pragma once

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>

#include <cstdint>
#include <string>
#include <vector>

#include "protocol/Protocol.h"

namespace r3::windows_client_ng::ui {

struct AddAddressDialogPreset {
  uint64_t address = 0;
  std::wstring description;
  protocol::ValueType type = protocol::ValueType::U32;
};

struct AddAddressDialogResult {
  uint64_t address = 0;
  std::wstring description;
  protocol::ValueType type = protocol::ValueType::U32;
  bool value_hex = false;
  bool value_signed = false;
  bool is_pointer = false;
  std::vector<int64_t> offsets;
};

bool ShowAddAddressDialog(HWND owner,
                          const AddAddressDialogPreset& preset,
                          AddAddressDialogResult* out_result);

}  // namespace r3::windows_client_ng::ui
