#include "services/ClientService.h"

#include <algorithm>
#include <chrono>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <utility>

namespace r3::windows_client_ng::services {

namespace {

template <typename T>
void AppendLE(std::vector<uint8_t>* out, T value) {
  const uint8_t* ptr = reinterpret_cast<const uint8_t*>(&value);
  out->insert(out->end(), ptr, ptr + sizeof(T));
}

uint64_t ParseUnsigned(const std::string& text, bool force_hex, bool* ok) {
  if (ok) {
    *ok = false;
  }
  if (text.empty()) {
    if (ok) {
      *ok = true;
    }
    return 0;
  }
  char* endptr = nullptr;
  const int base = force_hex ? 16 : 0;
  uint64_t v = std::strtoull(text.c_str(), &endptr, base);
  if (endptr == text.c_str()) {
    return 0;
  }
  if (ok) {
    *ok = true;
  }
  return v;
}

int64_t ParseSigned(const std::string& text, bool force_hex, bool* ok) {
  if (ok) {
    *ok = false;
  }
  if (text.empty()) {
    if (ok) {
      *ok = true;
    }
    return 0;
  }
  char* endptr = nullptr;
  const int base = force_hex ? 16 : 0;
  int64_t v = std::strtoll(text.c_str(), &endptr, base);
  if (endptr == text.c_str()) {
    return 0;
  }
  if (ok) {
    *ok = true;
  }
  return v;
}

std::string TrimAscii(const std::string& text) {
  const char* ws = " \t\r\n";
  const size_t begin = text.find_first_not_of(ws);
  if (begin == std::string::npos) {
    return "";
  }
  const size_t end = text.find_last_not_of(ws);
  return text.substr(begin, end - begin + 1);
}

bool ParseAobText(const std::string& text, std::vector<uint8_t>* out_bytes) {
  if (!out_bytes) {
    return false;
  }
  out_bytes->clear();
  const std::string trimmed = TrimAscii(text);
  if (trimmed.empty()) {
    return false;
  }

  const bool has_delimiter = trimmed.find_first_of(" \t,;") != std::string::npos;
  if (!has_delimiter) {
    std::string compact;
    compact.reserve(trimmed.size());
    for (char ch : trimmed) {
      if (std::isspace(static_cast<unsigned char>(ch)) || ch == ',' || ch == ';') {
        continue;
      }
      if (ch == '?') {
        return false;
      }
      compact.push_back(ch);
    }
    if (compact.size() < 2 || (compact.size() % 2) != 0) {
      return false;
    }
    for (size_t i = 0; i < compact.size(); i += 2) {
      const std::string token = compact.substr(i, 2);
      char* endptr = nullptr;
      const unsigned long value = std::strtoul(token.c_str(), &endptr, 16);
      if (endptr == token.c_str() || *endptr != '\0' || value > 0xFFul) {
        return false;
      }
      out_bytes->push_back(static_cast<uint8_t>(value));
    }
    return !out_bytes->empty();
  }

  size_t pos = 0;
  while (pos < trimmed.size()) {
    while (pos < trimmed.size() &&
           (std::isspace(static_cast<unsigned char>(trimmed[pos])) || trimmed[pos] == ',' || trimmed[pos] == ';')) {
      ++pos;
    }
    if (pos >= trimmed.size()) {
      break;
    }
    size_t end = pos;
    while (end < trimmed.size() &&
           !(std::isspace(static_cast<unsigned char>(trimmed[end])) || trimmed[end] == ',' || trimmed[end] == ';')) {
      ++end;
    }
    std::string token = trimmed.substr(pos, end - pos);
    if (token == "?" || token == "??") {
      return false;
    }
    if (token.size() >= 2 && (token.rfind("0x", 0) == 0 || token.rfind("0X", 0) == 0)) {
      token = token.substr(2);
    }
    if (token.empty() || token.size() > 2) {
      return false;
    }
    char* endptr = nullptr;
    const unsigned long value = std::strtoul(token.c_str(), &endptr, 16);
    if (endptr == token.c_str() || *endptr != '\0' || value > 0xFFul) {
      return false;
    }
    out_bytes->push_back(static_cast<uint8_t>(value));
    pos = end;
  }
  return !out_bytes->empty();
}

bool ParseBinaryText(const std::string& text, std::vector<uint8_t>* out_bytes) {
  if (!out_bytes) {
    return false;
  }
  out_bytes->clear();
  std::string bits;
  bits.reserve(text.size());
  for (char ch : text) {
    if (ch == '0' || ch == '1') {
      bits.push_back(ch);
      continue;
    }
    if (std::isspace(static_cast<unsigned char>(ch)) || ch == '_') {
      continue;
    }
    return false;
  }
  if (bits.empty()) {
    return false;
  }
  const size_t rem = bits.size() % 8;
  if (rem != 0) {
    bits.insert(bits.begin(), 8 - rem, '0');
  }
  for (size_t i = 0; i < bits.size(); i += 8) {
    uint8_t value = 0;
    for (size_t b = 0; b < 8; ++b) {
      value <<= 1;
      if (bits[i + b] == '1') {
        value |= 1u;
      }
    }
    out_bytes->push_back(value);
  }
  return !out_bytes->empty();
}

uint64_t SteadyNowMicros() {
  return static_cast<uint64_t>(
      std::chrono::duration_cast<std::chrono::microseconds>(
          std::chrono::steady_clock::now().time_since_epoch())
          .count());
}

}  // namespace

bool ClientService::Connect(const std::string& host, uint16_t port, std::string* out_error) {
  if (net_.Connect(host.c_str(), port)) {
    capabilities_valid_ = false;
    attached_pid_ = 0;
    read_compression_runtime_ = ReadCompressionRuntime{};
    provider_runtime_.configured_enabled = custom_provider_.enabled;
    provider_runtime_.provider_id = custom_provider_.provider_id;
    return true;
  }
  if (out_error) {
    *out_error = "连接失败";
  }
  return false;
}

void ClientService::Disconnect() {
  net_.Disconnect();
  capabilities_valid_ = false;
  attached_pid_ = 0;
  read_compression_runtime_ = ReadCompressionRuntime{};
  provider_runtime_.configured_enabled = custom_provider_.enabled;
  provider_runtime_.fused = false;
  provider_runtime_.fail_streak = 0;
  provider_runtime_.last_error.clear();
}

bool ClientService::IsConnected() const { return net_.IsConnected(); }

bool ClientService::FetchCapabilities(AgentCapabilities* out_caps, std::string* out_error) {
  if (!out_caps) {
    if (out_error) {
      *out_error = "参数无效";
    }
    return false;
  }
  if (!net_.IsConnected()) {
    if (out_error) {
      *out_error = "未连接";
    }
    return false;
  }

  protocol::AgentCapabilitiesRequest req{};
  req.abi_version = 1;
  req.reserved = 0;
  protocol::PacketHeader header{};
  std::vector<uint8_t> payload;
  if (!net_.SendAndReceive(protocol::CommandType::CMD_GET_CAPS,
                           &req,
                           sizeof(req),
                           &header,
                           &payload)) {
    if (out_error) {
      *out_error = "能力协商失败";
    }
    return false;
  }
  if (payload.size() < sizeof(protocol::AgentCapabilitiesResponse)) {
    if (out_error) {
      *out_error = "能力协商响应无效";
    }
    return false;
  }

  const auto* resp = reinterpret_cast<const protocol::AgentCapabilitiesResponse*>(payload.data());
  if (resp->code != 0) {
    if (out_error) {
      *out_error = "能力协商错误";
    }
    return false;
  }
  capabilities_cache_.protocol_version = resp->protocol_version;
  capabilities_cache_.flags = resp->capability_flags;
  capabilities_cache_.max_read_batch = resp->max_read_batch;
  capabilities_cache_.max_custom_mem = resp->max_custom_mem;
  capabilities_valid_ = true;
  *out_caps = capabilities_cache_;
  return true;
}

void ClientService::SetCustomMemoryProviderConfig(const CustomMemoryProviderConfig& config) {
  custom_provider_ = config;
  if (custom_provider_.timeout_ms == 0) {
    custom_provider_.timeout_ms = 1000;
  }
  if (custom_provider_.abi_version == 0) {
    custom_provider_.abi_version = 1;
  }
  provider_runtime_ = ProviderRuntimeSnapshot{};
  provider_runtime_.configured_enabled = custom_provider_.enabled;
  provider_runtime_.provider_id = custom_provider_.provider_id;
}

void ClientService::SetMemoryOverrideHooks(ReadOverrideHook read_hook, WriteOverrideHook write_hook) {
  read_override_hook_ = std::move(read_hook);
  write_override_hook_ = std::move(write_hook);
}

void ClientService::ClearMemoryOverrideHooks() {
  read_override_hook_ = ReadOverrideHook{};
  write_override_hook_ = WriteOverrideHook{};
}

void ClientService::ForceProviderFallback(const std::string& reason) {
  provider_runtime_.fused = true;
  provider_runtime_.last_error = reason.empty() ? "forced fallback" : reason;
}

void ClientService::ClearProviderFuse() {
  provider_runtime_.fused = false;
  provider_runtime_.fail_streak = 0;
  provider_runtime_.last_error.clear();
}

void ClientService::RecordProviderSuccess(bool used_custom, uint64_t elapsed_us) {
  provider_runtime_.configured_enabled = custom_provider_.enabled;
  provider_runtime_.provider_id = custom_provider_.provider_id;
  provider_runtime_.last_used_custom = used_custom;
  provider_runtime_.last_fallback = !used_custom;
  provider_runtime_.last_code = 0;
  provider_runtime_.last_sys_errno = 0;
  provider_runtime_.last_elapsed_us = elapsed_us;
  if (provider_runtime_.avg_elapsed_us == 0) {
    provider_runtime_.avg_elapsed_us = elapsed_us;
  } else {
    provider_runtime_.avg_elapsed_us = (provider_runtime_.avg_elapsed_us * 7 + elapsed_us) / 8;
  }
  provider_runtime_.fail_streak = 0;
}

void ClientService::RecordProviderFailure(const std::string& error, int32_t code, int32_t sys_errno) {
  provider_runtime_.configured_enabled = custom_provider_.enabled;
  provider_runtime_.provider_id = custom_provider_.provider_id;
  provider_runtime_.last_used_custom = true;
  provider_runtime_.last_fallback = false;
  provider_runtime_.last_code = code;
  provider_runtime_.last_sys_errno = sys_errno;
  provider_runtime_.last_error = error;
  provider_runtime_.fail_streak++;
  if (provider_runtime_.fail_streak >= provider_runtime_.fail_threshold) {
    provider_runtime_.fused = true;
    if (provider_runtime_.last_error.empty()) {
      provider_runtime_.last_error = "provider fused by failures";
    }
  }
}

void ClientService::ResetTelemetry() {
  telemetry_ = TelemetrySnapshot{};
}

bool ClientService::ShouldDisableReadResponseCompression(uint32_t expected_bytes,
                                                         uint32_t request_flags) const {
  (void)expected_bytes;
  if ((request_flags & protocol::READ_FLAG_NO_COMPRESS) != 0u) {
    return true;
  }
  // QA override: disable read-response compression globally.
  return true;
}

void ClientService::UpdateReadCompressionRuntime(const NetClient::ExchangeStats& exchange) {
  if (exchange.roundtrip_ms <= 0.0 || exchange.response_payload_bytes == 0u) {
    return;
  }
  const double bytes_per_ms =
      static_cast<double>(exchange.response_payload_bytes) / exchange.roundtrip_ms;
  if (bytes_per_ms <= 0.0) {
    return;
  }

  constexpr double kEwmaKeep = 0.8;
  constexpr double kEwmaNew = 0.2;
  auto update = [&](double* ewma, uint32_t* samples) {
    if (*ewma <= 0.0) {
      *ewma = bytes_per_ms;
    } else {
      *ewma = (*ewma * kEwmaKeep) + (bytes_per_ms * kEwmaNew);
    }
    (*samples)++;
  };

  if (exchange.response_compressed) {
    update(&read_compression_runtime_.compressed_bytes_per_ms_ewma,
           &read_compression_runtime_.compressed_samples);
  } else {
    update(&read_compression_runtime_.raw_bytes_per_ms_ewma,
           &read_compression_runtime_.raw_samples);
  }
}

std::string ClientService::CustomMemCodeText(int32_t code) {
  switch (code) {
    case 0:
      return "success";
    case -1:
      return "invalid args";
    case -2:
      return "unsupported";
    case -3:
      return "timeout";
    case -4:
      return "permission denied";
    case -5:
      return "target unreachable";
    case -6:
      return "internal error";
    case -7:
      return "fallback requested";
    default:
      break;
  }
  return "unknown";
}

bool ClientService::FetchProcesses(std::vector<ProcessInfo>* out_processes, std::string* out_error) {
  if (!out_processes) {
    if (out_error) {
      *out_error = "参数无效";
    }
    return false;
  }
  if (!net_.IsConnected()) {
    if (out_error) {
      *out_error = "未连接";
    }
    return false;
  }

  protocol::ProcessListRequest req{};
  req.max_count = 2048;
  req.reserved = 0;

  protocol::PacketHeader header{};
  std::vector<uint8_t> payload;
  if (!net_.SendAndReceive(protocol::CommandType::CMD_LIST_PROCESSES,
                           &req,
                           sizeof(req),
                           &header,
                           &payload)) {
    if (out_error) {
      *out_error = "进程列表获取失败";
    }
    return false;
  }

  if (payload.size() < sizeof(protocol::ProcessListHeader)) {
    if (out_error) {
      *out_error = "进程列表响应无效";
    }
    return false;
  }

  out_processes->clear();
  const auto* hdr = reinterpret_cast<const protocol::ProcessListHeader*>(payload.data());
  size_t offset = sizeof(protocol::ProcessListHeader);
  uint32_t parsed = 0;

  while (offset + offsetof(protocol::ProcessEntry, name) <= payload.size()) {
    if (hdr->count != 0 && parsed >= hdr->count) {
      break;
    }
    const auto* entry = reinterpret_cast<const protocol::ProcessEntry*>(payload.data() + offset);
    const size_t header_size = offsetof(protocol::ProcessEntry, name);
    const size_t total_size = header_size + entry->name_len;
    if (offset + total_size > payload.size()) {
      break;
    }

    ProcessInfo info;
    info.pid = entry->pid;
    info.name.assign(reinterpret_cast<const char*>(entry->name), entry->name_len);
    info.system_hint_valid = (entry->reserved & protocol::PROCESS_ENTRY_FLAG_CLASSIFIED) != 0u;
    info.is_system = (entry->reserved & protocol::PROCESS_ENTRY_FLAG_SYSTEM) != 0u;
    out_processes->push_back(std::move(info));

    offset += total_size;
    parsed++;
  }
  return true;
}

bool ClientService::FetchProcessIcon(uint32_t pid,
                                     uint32_t desired_size,
                                     std::vector<uint8_t>* out_png,
                                     std::string* out_error) {
  if (!out_png) {
    if (out_error) {
      *out_error = "参数无效";
    }
    return false;
  }
  out_png->clear();
  if (!net_.IsConnected()) {
    if (out_error) {
      *out_error = "未连接";
    }
    return false;
  }
  if (pid == 0) {
    if (out_error) {
      *out_error = "无效PID";
    }
    return false;
  }

  protocol::ProcessIconRequest req{};
  req.pid = pid;
  req.desired_size = desired_size;

  protocol::PacketHeader header{};
  std::vector<uint8_t> payload;
  if (!net_.SendAndReceive(protocol::CommandType::CMD_GET_PROCESS_ICON,
                           &req,
                           sizeof(req),
                           &header,
                           &payload)) {
    if (out_error) {
      *out_error = "图标获取失败";
    }
    return false;
  }
  if (payload.size() < offsetof(protocol::ProcessIconResponse, data)) {
    if (out_error) {
      *out_error = "图标响应无效";
    }
    return false;
  }
  const auto* resp = reinterpret_cast<const protocol::ProcessIconResponse*>(payload.data());
  if (resp->code != 0 || resp->bytes == 0 || resp->format != protocol::PROCESS_ICON_FMT_PNG) {
    if (out_error) {
      *out_error = "无可用图标";
    }
    return false;
  }
  const size_t payload_size = offsetof(protocol::ProcessIconResponse, data) + static_cast<size_t>(resp->bytes);
  if (payload_size > payload.size()) {
    if (out_error) {
      *out_error = "图标响应损坏";
    }
    return false;
  }
  out_png->assign(resp->data, resp->data + resp->bytes);
  return true;
}

bool ClientService::Attach(uint32_t pid, std::string* out_error) {
  if (!net_.IsConnected()) {
    if (out_error) {
      *out_error = "未连接";
    }
    return false;
  }

  protocol::AttachRequest req{};
  req.pid = pid;
  req.reserved = 0;

  protocol::PacketHeader header{};
  std::vector<uint8_t> payload;
  if (!net_.SendAndReceive(protocol::CommandType::CMD_ATTACH,
                           &req,
                           sizeof(req),
                           &header,
                           &payload)) {
    if (out_error) {
      *out_error = "打开进程失败";
    }
    return false;
  }

  if (payload.size() < sizeof(protocol::StatusResponse)) {
    if (out_error) {
      *out_error = "打开进程响应无效";
    }
    return false;
  }
  const auto* resp = reinterpret_cast<const protocol::StatusResponse*>(payload.data());
  if (resp->code != 0) {
    if (out_error) {
      *out_error = "打开进程错误";
    }
    return false;
  }
  attached_pid_ = pid;
  read_compression_runtime_ = ReadCompressionRuntime{};
  return true;
}

bool ClientService::FetchProcInfo(uint8_t* out_arch, uint8_t* out_pointer_size, std::string* out_error) {
  if (!net_.IsConnected()) {
    if (out_error) {
      *out_error = "未连接";
    }
    return false;
  }
  protocol::ProcInfoRequest req{};
  req.pid = 0;
  req.reserved = 0;

  protocol::PacketHeader header{};
  std::vector<uint8_t> payload;
  if (!net_.SendAndReceive(protocol::CommandType::CMD_GET_PROC_INFO, &req, sizeof(req), &header, &payload)) {
    if (out_error) {
      *out_error = "进程信息获取失败";
    }
    return false;
  }
  if (payload.size() < sizeof(protocol::ProcInfoResponse)) {
    if (out_error) {
      *out_error = "进程信息响应无效";
    }
    return false;
  }
  const auto* resp = reinterpret_cast<const protocol::ProcInfoResponse*>(payload.data());
  if (resp->code != 0) {
    if (out_error) {
      *out_error = "进程信息错误";
    }
    return false;
  }
  if (out_arch) {
    *out_arch = resp->arch;
  }
  if (out_pointer_size) {
    *out_pointer_size = resp->pointer_size;
  }
  return true;
}

bool ClientService::BuildValueBytes(protocol::ValueType value_type,
                                    const std::string& text,
                                    bool value_hex,
                                    std::vector<uint8_t>* out_bytes,
                                    std::string* out_error) const {
  if (!out_bytes) {
    if (out_error) {
      *out_error = "参数无效";
    }
    return false;
  }
  out_bytes->clear();
  bool ok = false;

  switch (value_type) {
    case protocol::ValueType::U8: {
      uint8_t v = static_cast<uint8_t>(ParseUnsigned(text, value_hex, &ok));
      if (!ok) break;
      AppendLE(out_bytes, v);
      return true;
    }
    case protocol::ValueType::U16: {
      uint16_t v = static_cast<uint16_t>(ParseUnsigned(text, value_hex, &ok));
      if (!ok) break;
      AppendLE(out_bytes, v);
      return true;
    }
    case protocol::ValueType::U32: {
      uint32_t v = static_cast<uint32_t>(ParseUnsigned(text, value_hex, &ok));
      if (!ok) break;
      AppendLE(out_bytes, v);
      return true;
    }
    case protocol::ValueType::U64: {
      uint64_t v = ParseUnsigned(text, value_hex, &ok);
      if (!ok) break;
      AppendLE(out_bytes, v);
      return true;
    }
    case protocol::ValueType::S32: {
      int32_t v = static_cast<int32_t>(ParseSigned(text, value_hex, &ok));
      if (!ok) break;
      AppendLE(out_bytes, v);
      return true;
    }
    case protocol::ValueType::S64: {
      int64_t v = ParseSigned(text, value_hex, &ok);
      if (!ok) break;
      AppendLE(out_bytes, v);
      return true;
    }
    case protocol::ValueType::FLOAT: {
      if (text.empty()) {
        ok = true;
        float v0 = 0.0f;
        AppendLE(out_bytes, v0);
        return true;
      }
      char* endptr = nullptr;
      float v = std::strtof(text.c_str(), &endptr);
      if (endptr != text.c_str()) {
        ok = true;
        AppendLE(out_bytes, v);
        return true;
      }
      break;
    }
    case protocol::ValueType::DOUBLE: {
      if (text.empty()) {
        ok = true;
        double v0 = 0.0;
        AppendLE(out_bytes, v0);
        return true;
      }
      char* endptr = nullptr;
      double v = std::strtod(text.c_str(), &endptr);
      if (endptr != text.c_str()) {
        ok = true;
        AppendLE(out_bytes, v);
        return true;
      }
      break;
    }
    case protocol::ValueType::STRING: {
      const std::string raw = TrimAscii(text);
      if (raw.empty()) {
        break;
      }
      out_bytes->assign(raw.begin(), raw.end());
      return true;
    }
    case protocol::ValueType::AOB: {
      if (ParseAobText(text, out_bytes)) {
        return true;
      }
      break;
    }
    case protocol::ValueType::BINARY: {
      if (ParseBinaryText(text, out_bytes)) {
        return true;
      }
      break;
    }
    case protocol::ValueType::ALL: {
      const std::string raw = TrimAscii(text);
      if (raw.empty()) {
        break;
      }
      out_bytes->assign(raw.begin(), raw.end());
      return true;
    }
    default:
      break;
  }

  if (out_error) {
    if (value_type == protocol::ValueType::AOB) {
      *out_error = "AOB格式无效，示例: 90 90 00 FF";
    } else if (value_type == protocol::ValueType::BINARY) {
      *out_error = "Binary格式无效，仅支持0/1";
    } else if (value_type == protocol::ValueType::STRING) {
      *out_error = "字符串不能为空";
    } else {
      *out_error = "扫描值无效";
    }
  }
  return false;
}

bool ClientService::ScanImpl(protocol::CommandType cmd,
                             protocol::ValueType value_type,
                             protocol::ComparisonType comparison,
                             const std::string& value_text,
                             bool value_hex,
                             uint16_t flags,
                             uint64_t start_addr,
                             uint64_t end_addr,
                             uint64_t* out_total,
                             std::vector<uint64_t>* out_page_addresses,
                             std::string* out_error) {
  if (!out_total || !out_page_addresses) {
    if (out_error) {
      *out_error = "参数无效";
    }
    return false;
  }
  if (!net_.IsConnected()) {
    if (out_error) {
      *out_error = "未连接";
    }
    return false;
  }

  std::vector<uint8_t> value_bytes;
  if (!BuildValueBytes(value_type, value_text, value_hex, &value_bytes, out_error)) {
    return false;
  }

  const size_t req_size = offsetof(protocol::ScanRequest, data) + value_bytes.size();
  std::vector<uint8_t> req_buf(req_size);
  auto* req = reinterpret_cast<protocol::ScanRequest*>(req_buf.data());
  req->value_type = static_cast<uint8_t>(value_type);
  req->comparison_type = static_cast<uint8_t>(comparison);
  req->reserved = flags;
  req->start_addr = start_addr;
  req->end_addr = end_addr;
  req->value_len = static_cast<uint32_t>(value_bytes.size());
  std::memcpy(req->data, value_bytes.data(), value_bytes.size());

  protocol::PacketHeader header{};
  std::vector<uint8_t> payload;
  if (!net_.SendAndReceive(cmd, req_buf.data(), static_cast<uint32_t>(req_buf.size()), &header, &payload)) {
    if (out_error) {
      *out_error = "扫描请求失败";
    }
    return false;
  }
  if (payload.size() < sizeof(uint64_t)) {
    if (out_error) {
      *out_error = "扫描响应无效";
    }
    return false;
  }

  *out_total = 0;
  std::memcpy(out_total, payload.data(), sizeof(uint64_t));
  out_page_addresses->clear();
  const size_t count = (payload.size() - sizeof(uint64_t)) / sizeof(uint64_t);
  if (count > 0) {
    out_page_addresses->resize(count);
    std::memcpy(out_page_addresses->data(), payload.data() + sizeof(uint64_t), count * sizeof(uint64_t));
  }
  return true;
}

bool ClientService::ScanFirst(protocol::ValueType value_type,
                              protocol::ComparisonType comparison,
                              const std::string& value_text,
                              bool value_hex,
                              uint16_t flags,
                              uint64_t start_addr,
                              uint64_t end_addr,
                              uint64_t* out_total,
                              std::vector<uint64_t>* out_page_addresses,
                              std::string* out_error) {
  return ScanImpl(protocol::CommandType::CMD_SCAN_FIRST,
                  value_type,
                  comparison,
                  value_text,
                  value_hex,
                  flags,
                  start_addr,
                  end_addr,
                  out_total,
                  out_page_addresses,
                  out_error);
}

bool ClientService::ScanNext(protocol::ValueType value_type,
                             protocol::ComparisonType comparison,
                             const std::string& value_text,
                             bool value_hex,
                             uint16_t flags,
                             uint64_t start_addr,
                             uint64_t end_addr,
                             uint64_t* out_total,
                             std::vector<uint64_t>* out_page_addresses,
                             std::string* out_error) {
  return ScanImpl(protocol::CommandType::CMD_SCAN_NEXT,
                  value_type,
                  comparison,
                  value_text,
                  value_hex,
                  flags,
                  start_addr,
                  end_addr,
                  out_total,
                  out_page_addresses,
                  out_error);
}

bool ClientService::ScanPage(uint64_t page_index,
                             uint32_t page_size,
                             uint64_t* out_total,
                             std::vector<uint64_t>* out_page_addresses,
                             std::string* out_error) {
  if (!out_total || !out_page_addresses) {
    if (out_error) {
      *out_error = "参数无效";
    }
    return false;
  }
  if (!net_.IsConnected()) {
    if (out_error) {
      *out_error = "未连接";
    }
    return false;
  }

  protocol::ScanPageRequest req{};
  req.start_index = page_index * page_size;
  req.max_count = page_size;
  req.reserved = 0;

  protocol::PacketHeader header{};
  std::vector<uint8_t> payload;
  if (!net_.SendAndReceive(protocol::CommandType::CMD_SCAN_PAGE, &req, sizeof(req), &header, &payload)) {
    if (out_error) {
      *out_error = "扫描分页失败";
    }
    return false;
  }
  if (payload.size() < sizeof(uint64_t)) {
    if (out_error) {
      *out_error = "扫描分页响应无效";
    }
    return false;
  }
  *out_total = 0;
  std::memcpy(out_total, payload.data(), sizeof(uint64_t));
  out_page_addresses->clear();
  const size_t count = (payload.size() - sizeof(uint64_t)) / sizeof(uint64_t);
  if (count > 0) {
    out_page_addresses->resize(count);
    std::memcpy(out_page_addresses->data(), payload.data() + sizeof(uint64_t), count * sizeof(uint64_t));
  }
  return true;
}

bool ClientService::ReadMemoryViaCustomProvider(uint64_t address,
                                                uint32_t size,
                                                bool use_pvm,
                                                std::vector<uint8_t>* out_data,
                                                std::string* out_error) {
  if (!out_data) {
    if (out_error) {
      *out_error = "参数无效";
    }
    return false;
  }
  out_data->clear();
  if (!custom_provider_.enabled) {
    if (out_error) {
      *out_error = "未启用自定义provider";
    }
    RecordProviderFailure("provider disabled", -2, 0);
    return false;
  }
  if (custom_provider_.syscall_read < 0) {
    if (out_error) {
      *out_error = "自定义provider未配置读syscall";
    }
    RecordProviderFailure("read syscall not configured", -2, 0);
    return false;
  }
  if (!net_.IsConnected()) {
    if (out_error) {
      *out_error = "未连接";
    }
    RecordProviderFailure("not connected", -5, 0);
    return false;
  }
  if (size == 0) {
    if (out_error) {
      *out_error = "读取长度无效";
    }
    RecordProviderFailure("invalid size", -1, 0);
    return false;
  }
  if (capabilities_valid_ && (capabilities_cache_.flags & protocol::AGENT_CAP_CUSTOM_MEM_OP) == 0) {
    if (out_error) {
      *out_error = "服务端不支持自定义内存provider";
    }
    RecordProviderFailure("custom mem op unsupported", -2, 0);
    return false;
  }

  const size_t header_size = offsetof(protocol::CustomMemOpRequest, payload);
  const size_t total = header_size + custom_provider_.user_ctx.size();
  if (total > std::numeric_limits<uint32_t>::max()) {
    if (out_error) {
      *out_error = "自定义provider请求过大";
    }
    RecordProviderFailure("request too large", -1, 0);
    return false;
  }

  std::vector<uint8_t> req_buf(total, 0);
  auto* req = reinterpret_cast<protocol::CustomMemOpRequest*>(req_buf.data());
  req->pid = attached_pid_;
  req->abi_version = custom_provider_.abi_version;
  req->op = protocol::CUSTOM_MEM_OP_READ;
  req->flags = custom_provider_.flags;
  if (custom_provider_.allow_fallback) {
    req->flags |= protocol::CUSTOM_MEM_FLAG_ALLOW_FALLBACK;
  }
  if (use_pvm) {
    req->flags |= protocol::CUSTOM_MEM_FLAG_USE_PVM;
  }
  req->address = address;
  req->size = size;
  req->timeout_ms = custom_provider_.timeout_ms;
  req->trace_id = trace_seq_++;
  req->syscall_read = custom_provider_.syscall_read;
  req->syscall_write = custom_provider_.syscall_write;
  req->user_ctx_len = static_cast<uint32_t>(custom_provider_.user_ctx.size());
  req->write_data_len = 0;
  if (!custom_provider_.user_ctx.empty()) {
    std::memcpy(req->payload, custom_provider_.user_ctx.data(), custom_provider_.user_ctx.size());
  }

  protocol::PacketHeader header{};
  std::vector<uint8_t> payload;
  if (!net_.SendAndReceive(protocol::CommandType::CMD_CUSTOM_MEM_OP,
                           req,
                           static_cast<uint32_t>(req_buf.size()),
                           &header,
                           &payload)) {
    if (out_error) {
      *out_error = "自定义provider读取失败";
    }
    RecordProviderFailure("send/recv failed", -5, 0);
    return false;
  }

  const size_t resp_header = offsetof(protocol::CustomMemOpResponse, data);
  if (payload.size() < resp_header) {
    if (out_error) {
      *out_error = "自定义provider响应无效";
    }
    RecordProviderFailure("response invalid", -6, 0);
    return false;
  }
  const auto* resp = reinterpret_cast<const protocol::CustomMemOpResponse*>(payload.data());
  if (resp->code != 0) {
    if (out_error) {
      std::string text = "自定义provider读取错误: ";
      text += CustomMemCodeText(resp->code);
      if (resp->sys_errno != 0) {
        text += " errno=" + std::to_string(resp->sys_errno);
      }
      *out_error = text;
    }
    RecordProviderFailure(out_error ? *out_error : "provider read failed", resp->code, resp->sys_errno);
    return false;
  }
  const size_t bytes = resp->read_data_len;
  const size_t expected = resp_header + bytes;
  if (payload.size() < expected) {
    if (out_error) {
      *out_error = "自定义provider读取响应截断";
    }
    RecordProviderFailure("response truncated", -6, 0);
    return false;
  }
  out_data->assign(resp->data, resp->data + bytes);
  RecordProviderSuccess(true, resp->elapsed_us);
  return true;
}

bool ClientService::WriteMemoryViaCustomProvider(uint64_t address,
                                                 const std::vector<uint8_t>& bytes,
                                                 std::string* out_error) {
  if (!custom_provider_.enabled) {
    if (out_error) {
      *out_error = "未启用自定义provider";
    }
    RecordProviderFailure("provider disabled", -2, 0);
    return false;
  }
  if (custom_provider_.syscall_write < 0) {
    if (out_error) {
      *out_error = "自定义provider未配置写syscall";
    }
    RecordProviderFailure("write syscall not configured", -2, 0);
    return false;
  }
  if (!net_.IsConnected()) {
    if (out_error) {
      *out_error = "未连接";
    }
    RecordProviderFailure("not connected", -5, 0);
    return false;
  }
  if (bytes.empty()) {
    if (out_error) {
      *out_error = "写入数据为空";
    }
    RecordProviderFailure("empty write", -1, 0);
    return false;
  }
  if (capabilities_valid_ && (capabilities_cache_.flags & protocol::AGENT_CAP_CUSTOM_MEM_OP) == 0) {
    if (out_error) {
      *out_error = "服务端不支持自定义内存provider";
    }
    RecordProviderFailure("custom mem op unsupported", -2, 0);
    return false;
  }

  const size_t header_size = offsetof(protocol::CustomMemOpRequest, payload);
  const size_t payload_bytes = custom_provider_.user_ctx.size() + bytes.size();
  const size_t total = header_size + payload_bytes;
  if (total > std::numeric_limits<uint32_t>::max()) {
    if (out_error) {
      *out_error = "自定义provider请求过大";
    }
    RecordProviderFailure("request too large", -1, 0);
    return false;
  }

  std::vector<uint8_t> req_buf(total, 0);
  auto* req = reinterpret_cast<protocol::CustomMemOpRequest*>(req_buf.data());
  req->pid = attached_pid_;
  req->abi_version = custom_provider_.abi_version;
  req->op = protocol::CUSTOM_MEM_OP_WRITE;
  req->flags = custom_provider_.flags;
  if (custom_provider_.allow_fallback) {
    req->flags |= protocol::CUSTOM_MEM_FLAG_ALLOW_FALLBACK;
  }
  req->address = address;
  req->size = static_cast<uint32_t>(bytes.size());
  req->timeout_ms = custom_provider_.timeout_ms;
  req->trace_id = trace_seq_++;
  req->syscall_read = custom_provider_.syscall_read;
  req->syscall_write = custom_provider_.syscall_write;
  req->user_ctx_len = static_cast<uint32_t>(custom_provider_.user_ctx.size());
  req->write_data_len = static_cast<uint32_t>(bytes.size());
  uint8_t* payload_ptr = req->payload;
  if (!custom_provider_.user_ctx.empty()) {
    std::memcpy(payload_ptr, custom_provider_.user_ctx.data(), custom_provider_.user_ctx.size());
    payload_ptr += custom_provider_.user_ctx.size();
  }
  std::memcpy(payload_ptr, bytes.data(), bytes.size());

  protocol::PacketHeader header{};
  std::vector<uint8_t> payload;
  if (!net_.SendAndReceive(protocol::CommandType::CMD_CUSTOM_MEM_OP,
                           req,
                           static_cast<uint32_t>(req_buf.size()),
                           &header,
                           &payload)) {
    if (out_error) {
      *out_error = "自定义provider写入失败";
    }
    RecordProviderFailure("send/recv failed", -5, 0);
    return false;
  }

  const size_t resp_header = offsetof(protocol::CustomMemOpResponse, data);
  if (payload.size() < resp_header) {
    if (out_error) {
      *out_error = "自定义provider写入响应无效";
    }
    RecordProviderFailure("response invalid", -6, 0);
    return false;
  }
  const auto* resp = reinterpret_cast<const protocol::CustomMemOpResponse*>(payload.data());
  if (resp->code != 0) {
    if (out_error) {
      std::string text = "自定义provider写入错误: ";
      text += CustomMemCodeText(resp->code);
      if (resp->sys_errno != 0) {
        text += " errno=" + std::to_string(resp->sys_errno);
      }
      *out_error = text;
    }
    RecordProviderFailure(out_error ? *out_error : "provider write failed", resp->code, resp->sys_errno);
    return false;
  }
  if (resp->bytes_done < bytes.size()) {
    if (out_error) {
      *out_error = "自定义provider写入字节不足";
    }
    RecordProviderFailure("write short", -6, 0);
    return false;
  }
  RecordProviderSuccess(true, resp->elapsed_us);
  return true;
}

bool ClientService::ReadMemory(uint64_t address,
                               uint32_t size,
                               bool use_pvm,
                               std::vector<uint8_t>* out_data,
                               std::string* out_error) {
  const uint64_t begin_us = SteadyNowMicros();
  telemetry_.read_calls++;
  if (!out_data) {
    if (out_error) {
      *out_error = "参数无效";
    }
    telemetry_.read_time_us += (SteadyNowMicros() - begin_us);
    return false;
  }
  if (!net_.IsConnected()) {
    if (out_error) {
      *out_error = "未连接";
    }
    telemetry_.read_time_us += (SteadyNowMicros() - begin_us);
    return false;
  }

  if (read_override_hook_) {
    std::string hook_error;
    const OverrideAction action =
        read_override_hook_(attached_pid_, address, size, use_pvm, out_data, &hook_error);
    if (action == OverrideAction::kHandled) {
      telemetry_.read_ok++;
      telemetry_.read_custom_hits++;
      telemetry_.read_time_us += (SteadyNowMicros() - begin_us);
      return true;
    }
    if (action == OverrideAction::kError) {
      if (out_error) {
        *out_error = hook_error.empty() ? "插件事件读取失败" : hook_error;
      }
      telemetry_.read_time_us += (SteadyNowMicros() - begin_us);
      return false;
    }
  }

  if (custom_provider_.enabled && !provider_runtime_.fused) {
    std::string custom_error;
    if (ReadMemoryViaCustomProvider(address, size, use_pvm, out_data, &custom_error)) {
      telemetry_.read_ok++;
      telemetry_.read_custom_hits++;
      telemetry_.read_time_us += (SteadyNowMicros() - begin_us);
      return true;
    }
    if (!custom_provider_.allow_fallback) {
      if (out_error) {
        *out_error = custom_error.empty() ? "自定义provider读取失败" : custom_error;
      }
      telemetry_.read_time_us += (SteadyNowMicros() - begin_us);
      return false;
    }
    provider_runtime_.last_fallback = true;
    provider_runtime_.fallback_count++;
  } else if (custom_provider_.enabled && provider_runtime_.fused) {
    provider_runtime_.last_fallback = true;
    provider_runtime_.fallback_count++;
  }

  protocol::ReadMemRequest req{};
  req.address = address;
  req.size = size;
  uint32_t read_flags = use_pvm ? protocol::READ_FLAG_USE_PVM : 0u;
  if (ShouldDisableReadResponseCompression(size, read_flags)) {
    read_flags |= protocol::READ_FLAG_NO_COMPRESS;
  }
  req.reserved = read_flags;

  protocol::PacketHeader header{};
  std::vector<uint8_t> payload;
  if (!net_.SendAndReceive(protocol::CommandType::CMD_READ_MEM, &req, sizeof(req), &header, &payload)) {
    if (out_error) {
      *out_error = "内存读取失败";
    }
    telemetry_.read_time_us += (SteadyNowMicros() - begin_us);
    return false;
  }
  UpdateReadCompressionRuntime(net_.LastExchangeStats());

  if (payload.size() < offsetof(protocol::ReadMemResponse, data)) {
    if (out_error) {
      *out_error = "内存读取响应无效";
    }
    telemetry_.read_time_us += (SteadyNowMicros() - begin_us);
    return false;
  }
  const auto* resp = reinterpret_cast<const protocol::ReadMemResponse*>(payload.data());
  if (resp->code != 0) {
    if (out_error) {
      *out_error = "内存读取错误";
    }
    telemetry_.read_time_us += (SteadyNowMicros() - begin_us);
    return false;
  }

  const size_t bytes = resp->bytes_read;
  const size_t expected = offsetof(protocol::ReadMemResponse, data) + bytes;
  if (payload.size() < expected) {
    if (out_error) {
      *out_error = "内存读取响应截断";
    }
    telemetry_.read_time_us += (SteadyNowMicros() - begin_us);
    return false;
  }
  out_data->assign(resp->data, resp->data + bytes);
  telemetry_.read_ok++;
  if (custom_provider_.enabled) {
    RecordProviderSuccess(false, SteadyNowMicros() - begin_us);
  }
  telemetry_.read_time_us += (SteadyNowMicros() - begin_us);
  return true;
}

bool ClientService::ReadMemoryBatch(const std::vector<ReadRange>& ranges,
                                    uint32_t flags,
                                    std::vector<std::vector<uint8_t>>* out_buffers,
                                    std::string* out_error) {
  if (!out_buffers) {
    if (out_error) {
      *out_error = "参数无效";
    }
    return false;
  }
  out_buffers->clear();
  if (ranges.empty()) {
    if (out_error) {
      *out_error = "批量范围为空";
    }
    return false;
  }
  if (!net_.IsConnected()) {
    if (out_error) {
      *out_error = "未连接";
    }
    return false;
  }
  if (ranges.size() > std::numeric_limits<uint32_t>::max() ||
      ranges.size() > 128) {
    if (out_error) {
      *out_error = "批量范围过多";
    }
    return false;
  }

  const size_t header_size = offsetof(protocol::ReadMemBatchRequest, ranges);
  const size_t ranges_size = ranges.size() * sizeof(protocol::ReadMemBatchRange);
  if (header_size > std::numeric_limits<size_t>::max() - ranges_size) {
    if (out_error) {
      *out_error = "批量请求过大";
    }
    return false;
  }
  const size_t req_size = header_size + ranges_size;
  if (req_size > std::numeric_limits<uint32_t>::max()) {
    if (out_error) {
      *out_error = "批量请求过大";
    }
    return false;
  }

  std::vector<uint8_t> req_buf(req_size);
  auto* req = reinterpret_cast<protocol::ReadMemBatchRequest*>(req_buf.data());
  req->count = static_cast<uint32_t>(ranges.size());
  uint64_t total_requested = 0;
  for (const auto& range : ranges) {
    total_requested += static_cast<uint64_t>(range.size);
    if (total_requested >= static_cast<uint64_t>(std::numeric_limits<uint32_t>::max())) {
      total_requested = static_cast<uint64_t>(std::numeric_limits<uint32_t>::max());
      break;
    }
  }
  uint32_t req_flags = flags;
  if ((req_flags & protocol::READ_FLAG_NO_COMPRESS) == 0u &&
      ShouldDisableReadResponseCompression(static_cast<uint32_t>(total_requested), req_flags)) {
    req_flags |= protocol::READ_FLAG_NO_COMPRESS;
  }
  req->flags = req_flags;
  for (size_t i = 0; i < ranges.size(); ++i) {
    req->ranges[i].address = ranges[i].address;
    req->ranges[i].size = ranges[i].size;
    req->ranges[i].reserved = 0;
  }

  protocol::PacketHeader header{};
  std::vector<uint8_t> payload;
  if (!net_.SendAndReceive(protocol::CommandType::CMD_READ_MEM_BATCH,
                           req,
                           static_cast<uint32_t>(req_buf.size()),
                           &header,
                           &payload)) {
    if (out_error) {
      *out_error = "批量读取失败";
    }
    return false;
  }
  UpdateReadCompressionRuntime(net_.LastExchangeStats());

  const size_t resp_header = offsetof(protocol::ReadMemBatchResponse, results);
  if (payload.size() < resp_header) {
    if (out_error) {
      *out_error = "批量读取响应无效";
    }
    return false;
  }
  const auto* resp = reinterpret_cast<const protocol::ReadMemBatchResponse*>(payload.data());
  if (resp->count != ranges.size()) {
    if (out_error) {
      *out_error = "批量读取数量不匹配";
    }
    return false;
  }
  const size_t results_size = ranges.size() * sizeof(protocol::ReadMemBatchResult);
  if (resp_header > std::numeric_limits<size_t>::max() - results_size ||
      payload.size() < resp_header + results_size) {
    if (out_error) {
      *out_error = "批量读取响应截断";
    }
    return false;
  }
  const uint8_t* data_ptr = payload.data() + resp_header + results_size;
  const size_t data_size = payload.size() - (resp_header + results_size);
  size_t data_offset = 0;

  out_buffers->resize(ranges.size());
  for (size_t i = 0; i < ranges.size(); ++i) {
    const auto& result = resp->results[i];
    if (result.code != 0) {
      out_buffers->clear();
      if (out_error) {
        *out_error = "批量读取子项错误";
      }
      return false;
    }
    const size_t bytes = result.bytes_read;
    if (data_offset > data_size || bytes > data_size - data_offset) {
      out_buffers->clear();
      if (out_error) {
        *out_error = "批量读取数据截断";
      }
      return false;
    }
    (*out_buffers)[i].assign(data_ptr + data_offset, data_ptr + data_offset + bytes);
    data_offset += bytes;
  }
  return true;
}

bool ClientService::WriteMemory(uint64_t address,
                                const std::vector<uint8_t>& bytes,
                                std::string* out_error) {
  const uint64_t begin_us = SteadyNowMicros();
  telemetry_.write_calls++;
  if (!net_.IsConnected()) {
    if (out_error) {
      *out_error = "未连接";
    }
    telemetry_.write_time_us += (SteadyNowMicros() - begin_us);
    return false;
  }
  if (bytes.empty()) {
    if (out_error) {
      *out_error = "写入数据为空";
    }
    telemetry_.write_time_us += (SteadyNowMicros() - begin_us);
    return false;
  }

  if (write_override_hook_) {
    std::string hook_error;
    const OverrideAction action =
        write_override_hook_(attached_pid_, address, bytes, &hook_error);
    if (action == OverrideAction::kHandled) {
      telemetry_.write_ok++;
      telemetry_.write_custom_hits++;
      telemetry_.write_time_us += (SteadyNowMicros() - begin_us);
      return true;
    }
    if (action == OverrideAction::kError) {
      if (out_error) {
        *out_error = hook_error.empty() ? "插件事件写入失败" : hook_error;
      }
      telemetry_.write_time_us += (SteadyNowMicros() - begin_us);
      return false;
    }
  }

  if (custom_provider_.enabled && !provider_runtime_.fused) {
    std::string custom_error;
    if (WriteMemoryViaCustomProvider(address, bytes, &custom_error)) {
      telemetry_.write_ok++;
      telemetry_.write_custom_hits++;
      telemetry_.write_time_us += (SteadyNowMicros() - begin_us);
      return true;
    }
    if (!custom_provider_.allow_fallback) {
      if (out_error) {
        *out_error = custom_error.empty() ? "自定义provider写入失败" : custom_error;
      }
      telemetry_.write_time_us += (SteadyNowMicros() - begin_us);
      return false;
    }
    provider_runtime_.last_fallback = true;
    provider_runtime_.fallback_count++;
  } else if (custom_provider_.enabled && provider_runtime_.fused) {
    provider_runtime_.last_fallback = true;
    provider_runtime_.fallback_count++;
  }

  const size_t header_size = offsetof(protocol::WriteMemRequest, data);
  std::vector<uint8_t> buffer(header_size + bytes.size());
  auto* req = reinterpret_cast<protocol::WriteMemRequest*>(buffer.data());
  req->address = address;
  req->size = static_cast<uint32_t>(bytes.size());
  req->reserved = 0;
  std::memcpy(req->data, bytes.data(), bytes.size());

  protocol::PacketHeader header{};
  std::vector<uint8_t> payload;
  if (!net_.SendAndReceive(protocol::CommandType::CMD_WRITE_MEM,
                           buffer.data(),
                           static_cast<uint32_t>(buffer.size()),
                           &header,
                           &payload)) {
    if (out_error) {
      *out_error = "写入失败";
    }
    telemetry_.write_time_us += (SteadyNowMicros() - begin_us);
    return false;
  }
  if (payload.size() < sizeof(protocol::WriteMemResponse)) {
    if (out_error) {
      *out_error = "写入响应无效";
    }
    telemetry_.write_time_us += (SteadyNowMicros() - begin_us);
    return false;
  }
  const auto* resp = reinterpret_cast<const protocol::WriteMemResponse*>(payload.data());
  if (resp->code != 0 || resp->bytes_written < bytes.size()) {
    if (out_error) {
      *out_error = "写入错误";
    }
    telemetry_.write_time_us += (SteadyNowMicros() - begin_us);
    return false;
  }
  telemetry_.write_ok++;
  if (custom_provider_.enabled) {
    RecordProviderSuccess(false, SteadyNowMicros() - begin_us);
  }
  telemetry_.write_time_us += (SteadyNowMicros() - begin_us);
  return true;
}

bool ClientService::FetchRegs(uint32_t pid, RegsSnapshot* out_regs, std::string* out_error) {
  if (!out_regs) {
    if (out_error) {
      *out_error = "参数无效";
    }
    return false;
  }
  if (!net_.IsConnected()) {
    if (out_error) {
      *out_error = "未连接";
    }
    return false;
  }

  protocol::GetRegsRequest req{};
  req.pid = pid;
  req.reserved = 0;

  protocol::PacketHeader header{};
  std::vector<uint8_t> payload;
  if (!net_.SendAndReceive(protocol::CommandType::CMD_GET_REGS, &req, sizeof(req), &header, &payload)) {
    if (out_error) {
      *out_error = "寄存器获取失败";
    }
    return false;
  }
  if (payload.size() < sizeof(protocol::GetRegsResponse)) {
    if (out_error) {
      *out_error = "寄存器响应无效";
    }
    return false;
  }
  const auto* resp = reinterpret_cast<const protocol::GetRegsResponse*>(payload.data());
  if (resp->code != 0) {
    if (out_error) {
      *out_error = "寄存器读取错误";
    }
    return false;
  }

  out_regs->arch = static_cast<protocol::RegsArch>(resp->arch);
  out_regs->arm64 = protocol::Arm64Regs{};
  out_regs->arm32 = protocol::Arm32Regs{};
  if (out_regs->arch == protocol::RegsArch::ARM64) {
    out_regs->arm64 = resp->regs.arm64;
    return true;
  }
  if (out_regs->arch == protocol::RegsArch::ARM32) {
    out_regs->arm32 = resp->regs.arm32;
    return true;
  }

  if (out_error) {
    *out_error = "寄存器架构未知";
  }
  return false;
}

bool ClientService::DebugAttach(uint32_t pid, bool allow_sigstop, std::string* out_error) {
  if (!net_.IsConnected()) {
    if (out_error) {
      *out_error = "未连接";
    }
    return false;
  }
  if (pid == 0) {
    if (out_error) {
      *out_error = "PID 无效";
    }
    return false;
  }

  protocol::DebugAttachRequest req{};
  req.pid = pid;
  req.reserved = allow_sigstop ? protocol::DEBUG_ATTACH_FLAG_ALLOW_SIGSTOP : 0;

  protocol::PacketHeader header{};
  std::vector<uint8_t> payload;
  if (!net_.SendAndReceive(protocol::CommandType::CMD_DEBUG_ATTACH,
                           &req,
                           sizeof(req),
                           &header,
                           &payload)) {
    if (out_error) {
      *out_error = "调试附加失败";
    }
    return false;
  }
  if (payload.size() < sizeof(protocol::StatusResponse)) {
    if (out_error) {
      *out_error = "调试附加响应无效";
    }
    return false;
  }
  const auto* resp = reinterpret_cast<const protocol::StatusResponse*>(payload.data());
  if (resp->code != 0) {
    if (out_error) {
      *out_error = "调试附加错误";
    }
    return false;
  }
  return true;
}

bool ClientService::DebugDetach(std::string* out_error) {
  if (!net_.IsConnected()) {
    if (out_error) {
      *out_error = "未连接";
    }
    return false;
  }

  protocol::PacketHeader header{};
  std::vector<uint8_t> payload;
  if (!net_.SendAndReceive(protocol::CommandType::CMD_DEBUG_DETACH,
                           nullptr,
                           0,
                           &header,
                           &payload)) {
    if (out_error) {
      *out_error = "调试分离失败";
    }
    return false;
  }
  if (payload.size() < sizeof(protocol::StatusResponse)) {
    if (out_error) {
      *out_error = "调试分离响应无效";
    }
    return false;
  }
  const auto* resp = reinterpret_cast<const protocol::StatusResponse*>(payload.data());
  if (resp->code != 0) {
    if (out_error) {
      *out_error = "调试分离错误";
    }
    return false;
  }
  return true;
}

bool ClientService::DebugControl(uint32_t pid,
                                 protocol::DebugControlAction action,
                                 std::string* out_error) {
  if (!net_.IsConnected()) {
    if (out_error) {
      *out_error = "未连接";
    }
    return false;
  }
  if (pid == 0) {
    if (out_error) {
      *out_error = "PID 无效";
    }
    return false;
  }

  protocol::DebugControlRequest req{};
  req.pid = pid;
  req.action = static_cast<uint8_t>(action);
  req.reserved0 = 0;
  req.reserved1 = 0;

  protocol::PacketHeader header{};
  std::vector<uint8_t> payload;
  if (!net_.SendAndReceive(protocol::CommandType::CMD_DEBUG_CONTROL,
                           &req,
                           sizeof(req),
                           &header,
                           &payload)) {
    if (out_error) {
      *out_error = "调试控制失败";
    }
    return false;
  }
  if (payload.size() < sizeof(protocol::StatusResponse)) {
    if (out_error) {
      *out_error = "调试控制响应无效";
    }
    return false;
  }
  const auto* resp = reinterpret_cast<const protocol::StatusResponse*>(payload.data());
  if (resp->code != 0) {
    if (out_error) {
      *out_error = "调试控制错误";
    }
    return false;
  }
  return true;
}

bool ClientService::DebugStepIn(uint32_t pid, std::string* out_error) {
  return DebugControl(pid, protocol::DEBUG_CTRL_STEP_IN, out_error);
}

bool ClientService::DebugStepOver(uint32_t pid, std::string* out_error) {
  return DebugControl(pid, protocol::DEBUG_CTRL_STEP_OVER, out_error);
}

bool ClientService::PollBreakpoints(uint32_t pid,
                                    protocol::DebugBackend backend,
                                    uint8_t flags,
                                    uint32_t max_events,
                                    std::vector<BreakpointEvent>* out_events,
                                    std::string* out_error) {
  if (!out_events) {
    if (out_error) {
      *out_error = "参数无效";
    }
    return false;
  }
  out_events->clear();
  if (!net_.IsConnected()) {
    if (out_error) {
      *out_error = "未连接";
    }
    return false;
  }
  if (pid == 0) {
    if (out_error) {
      *out_error = "PID 无效";
    }
    return false;
  }

  protocol::DebugBreakpointPollRequest req{};
  req.pid = pid;
  req.backend = static_cast<uint8_t>(backend);
  req.flags = flags;
  req.reserved = 0;
  req.max_events = max_events == 0 ? 256 : max_events;

  protocol::PacketHeader header{};
  std::vector<uint8_t> payload;
  if (!net_.SendAndReceive(protocol::CommandType::CMD_DEBUG_POLL_BP,
                           &req,
                           sizeof(req),
                           &header,
                           &payload)) {
    if (out_error) {
      *out_error = "断点轮询失败";
    }
    return false;
  }
  const size_t resp_header = offsetof(protocol::DebugBreakpointPollResponse, events);
  if (payload.size() < resp_header) {
    if (out_error) {
      *out_error = "断点轮询响应无效";
    }
    return false;
  }

  const auto* resp = reinterpret_cast<const protocol::DebugBreakpointPollResponse*>(payload.data());
  const uint32_t count = resp->count;
  const size_t expected = resp_header +
                          static_cast<size_t>(count) * sizeof(protocol::DebugBreakpointEvent);
  if (payload.size() < expected) {
    if (out_error) {
      *out_error = "断点轮询响应截断";
    }
    return false;
  }

  out_events->reserve(count);
  for (uint32_t i = 0; i < count; ++i) {
    BreakpointEvent item{};
    item.address = resp->events[i].address;
    item.type = resp->events[i].type;
    item.size = resp->events[i].size;
    item.count = resp->events[i].count;
    out_events->push_back(item);
  }
  return true;
}

bool ClientService::FetchModules(uint32_t pid,
                                 std::vector<ModuleInfo>* out_modules,
                                 std::string* out_error) {
  if (!out_modules) {
    if (out_error) {
      *out_error = "参数无效";
    }
    return false;
  }
  if (!net_.IsConnected()) {
    if (out_error) {
      *out_error = "未连接";
    }
    return false;
  }

  protocol::ModuleListRequest req{};
  req.pid = pid;
  req.reserved = 0;

  protocol::PacketHeader header{};
  std::vector<uint8_t> payload;
  if (!net_.SendAndReceive(protocol::CommandType::CMD_LIST_MODULES, &req, sizeof(req), &header, &payload)) {
    if (out_error) {
      *out_error = "模块列表获取失败";
    }
    return false;
  }
  if (payload.size() < sizeof(protocol::ModuleListHeader)) {
    if (out_error) {
      *out_error = "模块列表响应无效";
    }
    return false;
  }

  out_modules->clear();
  const auto* hdr = reinterpret_cast<const protocol::ModuleListHeader*>(payload.data());
  size_t offset = sizeof(protocol::ModuleListHeader);
  uint32_t parsed = 0;
  while (offset + offsetof(protocol::ModuleEntry, path) <= payload.size()) {
    if (hdr->count != 0 && parsed >= hdr->count) {
      break;
    }
    const auto* entry = reinterpret_cast<const protocol::ModuleEntry*>(payload.data() + offset);
    const size_t header_size = offsetof(protocol::ModuleEntry, path);
    const size_t total_size = header_size + entry->path_len;
    if (offset + total_size > payload.size()) {
      break;
    }
    ModuleInfo info{};
    info.start = entry->start;
    info.end = entry->end;
    info.perms = entry->perms;
    if (entry->path_len > 0) {
      info.path.assign(reinterpret_cast<const char*>(entry->path), entry->path_len);
    }
    out_modules->push_back(std::move(info));
    offset += total_size;
    parsed++;
  }
  return true;
}

bool ClientService::BuildPointerIndex(uint32_t pid,
                                      uint16_t pointer_size,
                                      uint16_t flags,
                                      uint32_t max_entries,
                                      PointerIndexBuildResult* out_result,
                                      std::string* out_error) {
  if (!out_result) {
    if (out_error) {
      *out_error = "参数无效";
    }
    return false;
  }
  if (!net_.IsConnected()) {
    if (out_error) {
      *out_error = "未连接";
    }
    return false;
  }

  protocol::PointerIndexBuildRequest req{};
  req.pid = pid;
  req.pointer_size = pointer_size;
  req.flags = flags;
  req.max_entries = max_entries;
  req.reserved = 0;

  protocol::PacketHeader header{};
  std::vector<uint8_t> payload;
  if (!net_.SendAndReceive(protocol::CommandType::CMD_PTR_INDEX_BUILD,
                           &req,
                           sizeof(req),
                           &header,
                           &payload)) {
    if (out_error) {
      *out_error = "指针索引构建失败";
    }
    return false;
  }
  if (payload.size() < sizeof(protocol::PointerIndexBuildResponse)) {
    if (out_error) {
      *out_error = "指针索引响应无效";
    }
    return false;
  }

  const auto* resp = reinterpret_cast<const protocol::PointerIndexBuildResponse*>(payload.data());
  if (resp->code != 0) {
    if (out_error) {
      *out_error = "指针索引构建错误";
    }
    return false;
  }
  out_result->pointer_size = resp->pointer_size;
  out_result->count = resp->count;
  out_result->truncated = resp->truncated != 0;
  return true;
}

bool ClientService::QueryPointerIndex(uint64_t start_index,
                                      uint32_t max_count,
                                      uint64_t* out_total,
                                      std::vector<PointerIndexEntry>* out_entries,
                                      std::string* out_error) {
  if (!out_total || !out_entries) {
    if (out_error) {
      *out_error = "参数无效";
    }
    return false;
  }
  if (!net_.IsConnected()) {
    if (out_error) {
      *out_error = "未连接";
    }
    return false;
  }

  protocol::PointerIndexQueryRequest req{};
  req.start_index = start_index;
  req.max_count = max_count;
  req.reserved = 0;

  protocol::PacketHeader header{};
  std::vector<uint8_t> payload;
  if (!net_.SendAndReceive(protocol::CommandType::CMD_PTR_INDEX_QUERY,
                           &req,
                           sizeof(req),
                           &header,
                           &payload)) {
    if (out_error) {
      *out_error = "查询指针索引失败";
    }
    return false;
  }
  if (payload.size() < offsetof(protocol::PointerIndexQueryResponse, entries)) {
    if (out_error) {
      *out_error = "指针索引响应无效";
    }
    return false;
  }

  const auto* resp = reinterpret_cast<const protocol::PointerIndexQueryResponse*>(payload.data());
  const uint32_t returned = resp->returned;
  const size_t expected =
      offsetof(protocol::PointerIndexQueryResponse, entries) + static_cast<size_t>(returned) * sizeof(protocol::PointerIndexEntry);
  if (payload.size() < expected) {
    if (out_error) {
      *out_error = "指针索引响应截断";
    }
    return false;
  }

  *out_total = resp->total;
  out_entries->clear();
  out_entries->reserve(returned);
  for (uint32_t i = 0; i < returned; ++i) {
    PointerIndexEntry item{};
    item.value = resp->entries[i].value;
    item.address = resp->entries[i].address;
    out_entries->push_back(item);
  }
  return true;
}

bool ClientService::ClearPointerIndex(std::string* out_error) {
  if (!net_.IsConnected()) {
    if (out_error) {
      *out_error = "未连接";
    }
    return false;
  }

  protocol::PacketHeader header{};
  std::vector<uint8_t> payload;
  if (!net_.SendAndReceive(protocol::CommandType::CMD_PTR_INDEX_CLEAR,
                           nullptr,
                           0,
                           &header,
                           &payload)) {
    if (out_error) {
      *out_error = "清空指针索引失败";
    }
    return false;
  }
  if (payload.size() < sizeof(protocol::StatusResponse)) {
    if (out_error) {
      *out_error = "清空指针索引响应无效";
    }
    return false;
  }
  const auto* resp = reinterpret_cast<const protocol::StatusResponse*>(payload.data());
  if (resp->code != 0) {
    if (out_error) {
      *out_error = "清空指针索引错误";
    }
    return false;
  }
  return true;
}

bool ClientService::VerifyPointerChains(uint16_t pointer_size,
                                        uint16_t depth,
                                        uint32_t flags,
                                        const std::vector<PointerChain>& chains,
                                        size_t start,
                                        size_t count,
                                        std::vector<protocol::PointerVerifyBatchResult>* out_results,
                                        std::string* out_error) {
  if (!out_results) {
    if (out_error) {
      *out_error = "参数无效";
    }
    return false;
  }
  out_results->clear();
  if (!net_.IsConnected()) {
    if (out_error) {
      *out_error = "未连接";
    }
    return false;
  }
  if (count == 0 || start > chains.size() || count > chains.size() - start) {
    if (out_error) {
      *out_error = "链路范围无效";
    }
    return false;
  }
  if (count > std::numeric_limits<uint32_t>::max()) {
    if (out_error) {
      *out_error = "链路数量过大";
    }
    return false;
  }

  const size_t header_size = offsetof(protocol::PointerVerifyBatchRequest, bases);
  const size_t bases_size = count * sizeof(uint64_t);
  const size_t offsets_size = static_cast<size_t>(depth) * count * sizeof(int64_t);
  if (header_size > std::numeric_limits<size_t>::max() - bases_size ||
      header_size + bases_size > std::numeric_limits<size_t>::max() - offsets_size) {
    if (out_error) {
      *out_error = "链路请求过大";
    }
    return false;
  }
  const size_t payload_size = header_size + bases_size + offsets_size;
  if (payload_size > std::numeric_limits<uint32_t>::max()) {
    if (out_error) {
      *out_error = "链路请求过大";
    }
    return false;
  }

  std::vector<uint8_t> buffer(payload_size);
  auto* req = reinterpret_cast<protocol::PointerVerifyBatchRequest*>(buffer.data());
  req->count = static_cast<uint32_t>(count);
  req->pointer_size = pointer_size;
  req->depth = depth;
  req->flags = flags;
  req->reserved = 0;
  uint64_t* bases = req->bases;
  for (size_t i = 0; i < count; ++i) {
    const auto& chain = chains[start + i];
    if (chain.offsets.size() < depth) {
      if (out_error) {
        *out_error = "链路偏移不足";
      }
      return false;
    }
    bases[i] = chain.base;
  }
  auto* offsets = reinterpret_cast<int64_t*>(reinterpret_cast<uint8_t*>(bases) + bases_size);
  if (depth > 0) {
    for (size_t i = 0; i < count; ++i) {
      const auto& chain = chains[start + i];
      std::memcpy(offsets + i * depth, chain.offsets.data(), static_cast<size_t>(depth) * sizeof(int64_t));
    }
  }

  protocol::PacketHeader header{};
  std::vector<uint8_t> payload;
  if (!net_.SendAndReceive(protocol::CommandType::CMD_PTR_VERIFY_BATCH,
                           req,
                           static_cast<uint32_t>(buffer.size()),
                           &header,
                           &payload)) {
    if (out_error) {
      *out_error = "链路验证失败";
    }
    return false;
  }
  if (payload.size() < offsetof(protocol::PointerVerifyBatchResponse, results)) {
    if (out_error) {
      *out_error = "链路验证响应无效";
    }
    return false;
  }

  const auto* resp = reinterpret_cast<const protocol::PointerVerifyBatchResponse*>(payload.data());
  if (resp->count != count) {
    if (out_error) {
      *out_error = "链路验证数量不匹配";
    }
    return false;
  }
  const size_t expected =
      offsetof(protocol::PointerVerifyBatchResponse, results) + count * sizeof(protocol::PointerVerifyBatchResult);
  if (payload.size() < expected) {
    if (out_error) {
      *out_error = "链路验证响应截断";
    }
    return false;
  }
  out_results->assign(resp->results, resp->results + count);
  return true;
}

bool ClientService::VerifyPointerChainsFilter(uint16_t pointer_size,
                                              uint16_t depth,
                                              uint32_t flags,
                                              const std::vector<PointerChain>& chains,
                                              size_t start,
                                              size_t count,
                                              const std::vector<uint64_t>& targets,
                                              std::vector<uint32_t>* out_matched_indices,
                                              std::string* out_error) {
  if (!out_matched_indices) {
    if (out_error) {
      *out_error = "参数无效";
    }
    return false;
  }
  out_matched_indices->clear();
  if (!net_.IsConnected()) {
    if (out_error) {
      *out_error = "未连接";
    }
    return false;
  }
  if (count == 0 || targets.empty() || start > chains.size() || count > chains.size() - start) {
    if (out_error) {
      *out_error = "筛选参数无效";
    }
    return false;
  }
  if (count > std::numeric_limits<uint32_t>::max() ||
      targets.size() > std::numeric_limits<uint32_t>::max()) {
    if (out_error) {
      *out_error = "筛选参数超限";
    }
    return false;
  }

  const size_t header_size = offsetof(protocol::PointerVerifyBatchV2Request, bases);
  const size_t bases_size = count * sizeof(uint64_t);
  const size_t offsets_size = static_cast<size_t>(depth) * count * sizeof(int64_t);
  const size_t targets_size = targets.size() * sizeof(uint64_t);
  if (header_size > std::numeric_limits<size_t>::max() - bases_size ||
      header_size + bases_size > std::numeric_limits<size_t>::max() - offsets_size ||
      header_size + bases_size + offsets_size > std::numeric_limits<size_t>::max() - targets_size) {
    if (out_error) {
      *out_error = "筛选请求过大";
    }
    return false;
  }
  const size_t payload_size = header_size + bases_size + offsets_size + targets_size;
  if (payload_size > std::numeric_limits<uint32_t>::max()) {
    if (out_error) {
      *out_error = "筛选请求过大";
    }
    return false;
  }

  std::vector<uint8_t> buffer(payload_size);
  auto* req = reinterpret_cast<protocol::PointerVerifyBatchV2Request*>(buffer.data());
  req->count = static_cast<uint32_t>(count);
  req->pointer_size = pointer_size;
  req->depth = depth;
  req->flags = flags | protocol::PTR_VERIFY_BATCH_FLAG_TARGET_FILTER;
  req->target_count = static_cast<uint32_t>(targets.size());
  req->reserved = 0;
  uint64_t* bases = req->bases;
  for (size_t i = 0; i < count; ++i) {
    const auto& chain = chains[start + i];
    if (chain.offsets.size() < depth) {
      if (out_error) {
        *out_error = "链路偏移不足";
      }
      return false;
    }
    bases[i] = chain.base;
  }
  auto* offsets = reinterpret_cast<int64_t*>(reinterpret_cast<uint8_t*>(bases) + bases_size);
  if (depth > 0) {
    for (size_t i = 0; i < count; ++i) {
      const auto& chain = chains[start + i];
      std::memcpy(offsets + i * depth, chain.offsets.data(), static_cast<size_t>(depth) * sizeof(int64_t));
    }
  }
  auto* targets_ptr = reinterpret_cast<uint64_t*>(reinterpret_cast<uint8_t*>(offsets) + offsets_size);
  std::memcpy(targets_ptr, targets.data(), targets_size);

  protocol::PacketHeader header{};
  std::vector<uint8_t> payload;
  if (!net_.SendAndReceive(protocol::CommandType::CMD_PTR_VERIFY_BATCH_V2,
                           req,
                           static_cast<uint32_t>(buffer.size()),
                           &header,
                           &payload)) {
    if (out_error) {
      *out_error = "链路筛选失败";
    }
    return false;
  }
  if (payload.size() < offsetof(protocol::PointerVerifyBatchV2Response, matched_indices)) {
    if (out_error) {
      *out_error = "链路筛选响应无效";
    }
    return false;
  }

  const auto* resp = reinterpret_cast<const protocol::PointerVerifyBatchV2Response*>(payload.data());
  if (resp->count != count) {
    if (out_error) {
      *out_error = "链路筛选数量不匹配";
    }
    return false;
  }
  const size_t expected =
      offsetof(protocol::PointerVerifyBatchV2Response, matched_indices) + static_cast<size_t>(resp->matched_count) * sizeof(uint32_t);
  if (payload.size() < expected) {
    if (out_error) {
      *out_error = "链路筛选响应截断";
    }
    return false;
  }
  out_matched_indices->assign(resp->matched_indices, resp->matched_indices + resp->matched_count);
  for (uint32_t idx : *out_matched_indices) {
    if (idx >= count) {
      if (out_error) {
        *out_error = "链路筛选索引越界";
      }
      out_matched_indices->clear();
      return false;
    }
  }
  return true;
}

bool ClientService::ResolvePointerChain(uint64_t base,
                                        const std::vector<uint64_t>& offsets,
                                        uint32_t pointer_size,
                                        uint64_t* out_address,
                                        std::string* out_error) {
  if (!out_address) {
    if (out_error) {
      *out_error = "参数无效";
    }
    return false;
  }
  if (!net_.IsConnected()) {
    if (out_error) {
      *out_error = "未连接";
    }
    return false;
  }
  if (pointer_size != 4 && pointer_size != 8) {
    if (out_error) {
      *out_error = "指针宽度无效";
    }
    return false;
  }
  if (offsets.empty()) {
    *out_address = base;
    return true;
  }
  if (offsets.size() > std::numeric_limits<uint32_t>::max()) {
    if (out_error) {
      *out_error = "链路偏移过多";
    }
    return false;
  }

  const size_t header_size = offsetof(protocol::PointerChainRequest, offsets);
  const size_t offsets_size = offsets.size() * sizeof(uint64_t);
  if (header_size > std::numeric_limits<size_t>::max() - offsets_size) {
    if (out_error) {
      *out_error = "链路请求过大";
    }
    return false;
  }
  const size_t req_size = header_size + offsets_size;
  if (req_size > std::numeric_limits<uint32_t>::max()) {
    if (out_error) {
      *out_error = "链路请求过大";
    }
    return false;
  }

  std::vector<uint8_t> req_buf(req_size);
  auto* req = reinterpret_cast<protocol::PointerChainRequest*>(req_buf.data());
  req->base = base;
  req->count = static_cast<uint32_t>(offsets.size());
  req->pointer_size = pointer_size;
  std::memcpy(req->offsets, offsets.data(), offsets_size);

  protocol::PacketHeader header{};
  std::vector<uint8_t> payload;
  if (!net_.SendAndReceive(protocol::CommandType::CMD_GET_POINTER_CHAIN,
                           req,
                           static_cast<uint32_t>(req_buf.size()),
                           &header,
                           &payload)) {
    if (out_error) {
      *out_error = "链路解析失败";
    }
    return false;
  }
  if (payload.size() < sizeof(protocol::PointerChainResponse)) {
    if (out_error) {
      *out_error = "链路响应无效";
    }
    return false;
  }
  const auto* resp = reinterpret_cast<const protocol::PointerChainResponse*>(payload.data());
  if (resp->code != 0) {
    if (out_error) {
      *out_error = "链路解析错误";
    }
    return false;
  }
  *out_address = resp->address;
  return true;
}

bool ClientService::SetBreakpoint(uint32_t pid,
                                  protocol::DebugBackend backend,
                                  protocol::DebugBpType type,
                                  uint8_t size,
                                  uint8_t flags,
                                  uint64_t address,
                                  std::string* out_error) {
  if (!net_.IsConnected()) {
    if (out_error) {
      *out_error = "未连接";
    }
    return false;
  }
  protocol::DebugBreakpointRequest req{};
  req.pid = pid;
  req.backend = static_cast<uint8_t>(backend);
  req.type = static_cast<uint8_t>(type);
  req.size = size;
  req.flags = flags;
  req.address = address;

  protocol::PacketHeader header{};
  std::vector<uint8_t> payload;
  if (!net_.SendAndReceive(protocol::CommandType::CMD_DEBUG_SET_BP, &req, sizeof(req), &header, &payload)) {
    if (out_error) {
      *out_error = "设置断点失败";
    }
    return false;
  }
  if (payload.size() < sizeof(protocol::StatusResponse)) {
    if (out_error) {
      *out_error = "设置断点响应无效";
    }
    return false;
  }
  const auto* resp = reinterpret_cast<const protocol::StatusResponse*>(payload.data());
  if (resp->code != 0) {
    if (out_error) {
      *out_error = "设置断点错误";
    }
    return false;
  }
  return true;
}

bool ClientService::ClearBreakpoint(uint32_t pid,
                                    protocol::DebugBackend backend,
                                    protocol::DebugBpType type,
                                    uint8_t size,
                                    uint8_t flags,
                                    uint64_t address,
                                    std::string* out_error) {
  if (!net_.IsConnected()) {
    if (out_error) {
      *out_error = "未连接";
    }
    return false;
  }
  protocol::DebugBreakpointRequest req{};
  req.pid = pid;
  req.backend = static_cast<uint8_t>(backend);
  req.type = static_cast<uint8_t>(type);
  req.size = size;
  req.flags = flags;
  req.address = address;

  protocol::PacketHeader header{};
  std::vector<uint8_t> payload;
  if (!net_.SendAndReceive(protocol::CommandType::CMD_DEBUG_CLR_BP, &req, sizeof(req), &header, &payload)) {
    if (out_error) {
      *out_error = "清除断点失败";
    }
    return false;
  }
  if (payload.size() < sizeof(protocol::StatusResponse)) {
    if (out_error) {
      *out_error = "清除断点响应无效";
    }
    return false;
  }
  const auto* resp = reinterpret_cast<const protocol::StatusResponse*>(payload.data());
  if (resp->code != 0) {
    if (out_error) {
      *out_error = "清除断点错误";
    }
    return false;
  }
  return true;
}

}  // namespace r3::windows_client_ng::services
