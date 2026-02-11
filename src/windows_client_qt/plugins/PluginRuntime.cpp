#include "plugins/PluginRuntime.h"

#include <algorithm>
#include <cstddef>
#include <cstdlib>
#include <cstring>
#include <limits>

#include <QDebug>

namespace r3::windows_client_qt::plugins {

namespace {

constexpr uint32_t kFuseThreshold = 3;
PluginRuntime* g_register_runtime = nullptr;

void* HostAlloc(uint32_t bytes) {
  return std::malloc(bytes);
}

void HostFree(void* p) {
  std::free(p);
}

void HostLog(const char* text) {
  if (text && *text != '\0') {
    qDebug() << "[R3Plugin]" << text;
  }
}

int HostRegisterCallback(uint32_t event_id, R3ModuleEventCallbackFn callback, void* user_ctx) {
  if (!g_register_runtime) {
    return -1;
  }
  return g_register_runtime->RegisterEventHandler(event_id, callback, user_ctx);
}

QString Utf8Slice(const uint8_t* ptr, uint32_t len) {
  if (!ptr || len == 0) {
    return QString();
  }
  return QString::fromUtf8(reinterpret_cast<const char*>(ptr), static_cast<int>(len));
}

}  // namespace

PluginRuntime::~PluginRuntime() {
  Deactivate();
}

bool PluginRuntime::Activate(const PluginManifest& manifest, QString* out_error) {
  Deactivate();
  manifest_ = manifest;
  ResetFailures();
  SetStage(QStringLiteral("discover"));
  if (out_error) {
    out_error->clear();
  }

  if (manifest_.id.trimmed().isEmpty()) {
    SetLastError(QStringLiteral("plugin id为空"));
    if (out_error) {
      *out_error = last_error_;
    }
    return false;
  }

  SetStage(QStringLiteral("validate"));
  if (manifest_.mode.compare(QStringLiteral("in_process"), Qt::CaseInsensitive) == 0) {
    return ActivateInProcess(manifest_, out_error);
  }

  if (manifest_.mode.compare(QStringLiteral("out_of_process"), Qt::CaseInsensitive) == 0) {
    return ActivateOutOfProcess(manifest_, out_error);
  }

  // "manifest" mode: metadata + syscall defaults only.
  SetStage(QStringLiteral("serve(manifest-only)"));
  active_ = true;
  return true;
}

bool PluginRuntime::ActivateInProcess(const PluginManifest& manifest, QString* out_error) {
  if (manifest.entry.trimmed().isEmpty()) {
    SetLastError(QStringLiteral("in_process插件缺少entry"));
    if (out_error) {
      *out_error = last_error_;
    }
    return false;
  }

  SetStage(QStringLiteral("load"));
  library_.setFileName(manifest.entry);
  if (!library_.load()) {
    SetLastError(QStringLiteral("加载插件失败: %1").arg(library_.errorString()));
    if (out_error) {
      *out_error = last_error_;
    }
    return false;
  }
  in_process_loaded_ = true;

  query_fn_ = reinterpret_cast<QueryFn>(library_.resolve("R3Plugin_Query"));
  init_fn_ = reinterpret_cast<InitFn>(library_.resolve("R3Plugin_Init"));
  start_fn_ = reinterpret_cast<StartFn>(library_.resolve("R3Plugin_Start"));
  stop_fn_ = reinterpret_cast<StopFn>(library_.resolve("R3Plugin_Stop"));
  mem_op_fn_ = reinterpret_cast<MemOpFn>(library_.resolve("R3Plugin_MemOp"));
  analyze_fn_ = reinterpret_cast<AnalyzeFn>(library_.resolve("R3Plugin_Analyze"));
  free_fn_ = reinterpret_cast<FreeFn>(library_.resolve("R3Plugin_Free"));
  register_events_fn_ =
      reinterpret_cast<RegisterEventsFn>(library_.resolve("register_module_events_export"));
  if (!register_events_fn_) {
    register_events_fn_ =
        reinterpret_cast<RegisterEventsFn>(library_.resolve("R3Plugin_RegisterEvents"));
  }
  if (!query_fn_ || !init_fn_ || !start_fn_ || !stop_fn_ || !free_fn_) {
    SetLastError(QStringLiteral("插件导出函数不完整"));
    if (out_error) {
      *out_error = last_error_;
    }
    Deactivate();
    return false;
  }

  SetStage(QStringLiteral("init"));
  R3PluginInfo info{};
  info.struct_size = sizeof(info);
  if (query_fn_(&info) != 0) {
    SetLastError(QStringLiteral("R3Plugin_Query失败"));
    if (out_error) {
      *out_error = last_error_;
    }
    Deactivate();
    return false;
  }

  R3HostApi host{};
  host.abi_version = 1;
  host.struct_size = sizeof(host);
  host.alloc = &HostAlloc;
  host.free_ptr = &HostFree;
  host.log_utf8 = &HostLog;
  if (init_fn_(&host) != 0) {
    SetLastError(QStringLiteral("R3Plugin_Init失败"));
    if (out_error) {
      *out_error = last_error_;
    }
    Deactivate();
    return false;
  }

  SetStage(QStringLiteral("start"));
  if (start_fn_() != 0) {
    SetLastError(QStringLiteral("R3Plugin_Start失败"));
    if (out_error) {
      *out_error = last_error_;
    }
    Deactivate();
    return false;
  }

  if (register_events_fn_) {
    R3ModuleHostApiV1 host_v1{};
    host_v1.abi_version = 1;
    host_v1.struct_size = sizeof(host_v1);
    host_v1.register_callback = &HostRegisterCallback;
    host_v1.alloc = &HostAlloc;
    host_v1.free_ptr = &HostFree;
    host_v1.log_utf8 = &HostLog;
    g_register_runtime = this;
    const int rc = register_events_fn_(&host_v1);
    g_register_runtime = nullptr;
    if (rc != 0) {
      qDebug() << "[R3Plugin] register_module_events_export failed rc=" << rc;
    }
  }

  SetStage(QStringLiteral("serve"));
  active_ = true;
  return true;
}

bool PluginRuntime::ActivateOutOfProcess(const PluginManifest& manifest, QString* out_error) {
  if (manifest.entry.trimmed().isEmpty()) {
    SetLastError(QStringLiteral("out_of_process插件缺少entry"));
    if (out_error) {
      *out_error = last_error_;
    }
    return false;
  }
  SetStage(QStringLiteral("load"));
  oop_process_ = std::make_unique<QProcess>();
  oop_process_->setProgram(manifest.entry);
  oop_process_->setArguments(manifest.oop_args);
  oop_process_->setProcessChannelMode(QProcess::MergedChannels);
  oop_process_->start();
  if (!oop_process_->waitForStarted(1500)) {
    const QString proc_error = oop_process_->errorString().trimmed();
    SetLastError(QStringLiteral("启动out_of_process插件失败: %1")
                     .arg(proc_error.isEmpty() ? QStringLiteral("unknown") : proc_error));
    if (out_error) {
      *out_error = last_error_;
    }
    oop_process_.reset();
    return false;
  }
  SetStage(QStringLiteral("serve(out_of_process)"));
  active_ = true;
  return true;
}

void PluginRuntime::Deactivate() {
  if (oop_process_) {
    SetStage(QStringLiteral("stop"));
    oop_process_->terminate();
    if (!oop_process_->waitForFinished(1000)) {
      oop_process_->kill();
      oop_process_->waitForFinished(1000);
    }
    oop_process_.reset();
  }
  if (in_process_loaded_ && stop_fn_) {
    SetStage(QStringLiteral("stop"));
    stop_fn_();
  }
  if (in_process_loaded_ && library_.isLoaded()) {
    SetStage(QStringLiteral("unload"));
    library_.unload();
  }
  query_fn_ = nullptr;
  init_fn_ = nullptr;
  start_fn_ = nullptr;
  stop_fn_ = nullptr;
  mem_op_fn_ = nullptr;
  analyze_fn_ = nullptr;
  free_fn_ = nullptr;
  register_events_fn_ = nullptr;
  event_handlers_.clear();
  in_process_loaded_ = false;
  active_ = false;
}

PluginRuntime::RuntimeStatus PluginRuntime::Status() const {
  RuntimeStatus status;
  status.plugin_id = manifest_.id;
  status.plugin_name = manifest_.name;
  status.mode = manifest_.mode;
  status.stage = stage_;
  status.active = active_;
  status.fused = fused_;
  status.error_count = error_count_;
  status.last_error = last_error_;
  return status;
}

bool PluginRuntime::SupportsAnalysis() const {
  if (!active_ || fused_) {
    return false;
  }
  if (!analyze_fn_) {
    return false;
  }
  for (const QString& cap : manifest_.capabilities) {
    if (cap.compare(QStringLiteral("analysis.translate"), Qt::CaseInsensitive) == 0 ||
        cap.compare(QStringLiteral("analysis.vmp"), Qt::CaseInsensitive) == 0 ||
        cap.compare(QStringLiteral("analysis.annotation"), Qt::CaseInsensitive) == 0) {
      return true;
    }
  }
  return false;
}

bool PluginRuntime::SupportsMemoryEvent() const {
  if (!active_ || fused_) {
    return false;
  }
  if (event_handlers_.find(static_cast<uint32_t>(R3_MODULE_EVENT_READ_MEM)) != event_handlers_.end() ||
      event_handlers_.find(static_cast<uint32_t>(R3_MODULE_EVENT_WRITE_MEM)) != event_handlers_.end()) {
    return true;
  }
  if (mem_op_fn_) {
    return true;
  }
  return false;
}

void PluginRuntime::ResetFailures() {
  fused_ = false;
  error_count_ = 0;
  last_error_.clear();
}

void PluginRuntime::RecordFailure(const QString& reason) {
  error_count_++;
  if (!reason.trimmed().isEmpty()) {
    last_error_ = reason.trimmed();
  }
  if (error_count_ >= kFuseThreshold) {
    fused_ = true;
    if (last_error_.isEmpty()) {
      last_error_ = QStringLiteral("插件错误次数达到熔断阈值");
    }
  }
}

void PluginRuntime::ForceFuse(const QString& reason) {
  fused_ = true;
  if (!reason.trimmed().isEmpty()) {
    last_error_ = reason.trimmed();
  } else if (last_error_.isEmpty()) {
    last_error_ = QStringLiteral("已手动回退到内置链路");
  }
}

bool PluginRuntime::Analyze(const AnalysisRequest& request,
                            AnalysisResult* out_result,
                            QString* out_error) {
  if (out_error) {
    out_error->clear();
  }
  if (out_result) {
    *out_result = AnalysisResult{};
  }
  if (!out_result) {
    if (out_error) {
      *out_error = QStringLiteral("参数无效");
    }
    return false;
  }
  if (!SupportsAnalysis()) {
    if (out_error) {
      *out_error = QStringLiteral("插件未启用分析能力");
    }
    return false;
  }
  if (request.bytes.empty()) {
    if (out_error) {
      *out_error = QStringLiteral("分析输入字节为空");
    }
    return false;
  }

  const size_t header_size = offsetof(R3AnalysisReqV1, payload);
  const size_t payload_size = request.bytes.size() + request.regs_blob.size() + request.memory_window.size();
  if (header_size > std::numeric_limits<size_t>::max() - payload_size) {
    if (out_error) {
      *out_error = QStringLiteral("分析请求过大");
    }
    return false;
  }
  const size_t total_size = header_size + payload_size;
  if (total_size > std::numeric_limits<uint32_t>::max()) {
    if (out_error) {
      *out_error = QStringLiteral("分析请求过大");
    }
    return false;
  }

  std::vector<uint8_t> req_buf(total_size, 0);
  auto* req = reinterpret_cast<R3AnalysisReqV1*>(req_buf.data());
  req->abi_version = 1;
  req->struct_size = sizeof(R3AnalysisReqV1);
  req->arch = request.arch;
  req->reserved = 0;
  req->address = request.address;
  req->flags = 0;
  req->bytes_off = static_cast<uint32_t>(header_size);
  req->bytes_len = static_cast<uint32_t>(request.bytes.size());
  req->regs_off = req->bytes_off + req->bytes_len;
  req->regs_len = static_cast<uint32_t>(request.regs_blob.size());
  req->memory_off = req->regs_off + req->regs_len;
  req->memory_len = static_cast<uint32_t>(request.memory_window.size());
  req->reserved0 = 0;
  req->reserved1 = 0;

  uint8_t* p = req->payload;
  if (!request.bytes.empty()) {
    std::memcpy(p, request.bytes.data(), request.bytes.size());
    p += request.bytes.size();
  }
  if (!request.regs_blob.empty()) {
    std::memcpy(p, request.regs_blob.data(), request.regs_blob.size());
    p += request.regs_blob.size();
  }
  if (!request.memory_window.empty()) {
    std::memcpy(p, request.memory_window.data(), request.memory_window.size());
  }

  uint8_t* rsp_ptr = nullptr;
  uint32_t rsp_len = 0;
  const int rc = analyze_fn_(req_buf.data(),
                             static_cast<uint32_t>(req_buf.size()),
                             &rsp_ptr,
                             &rsp_len);
  if (rc != 0 || !rsp_ptr || rsp_len < sizeof(R3AnalysisRspV1)) {
    const QString error = QStringLiteral("插件分析失败 rc=%1").arg(rc);
    RecordFailure(error);
    if (out_error) {
      *out_error = error;
    }
    if (rsp_ptr && free_fn_) {
      free_fn_(rsp_ptr);
    }
    return false;
  }

  const auto* rsp = reinterpret_cast<const R3AnalysisRspV1*>(rsp_ptr);
  if (rsp->code != 0) {
    const QString error = QStringLiteral("插件分析返回错误 code=%1").arg(rsp->code);
    RecordFailure(error);
    if (out_error) {
      *out_error = error;
    }
    if (free_fn_) {
      free_fn_(rsp_ptr);
    }
    return false;
  }

  auto check_slice = [rsp_len](uint32_t off, uint32_t len) -> bool {
    if (len == 0) {
      return true;
    }
    if (off >= rsp_len) {
      return false;
    }
    return static_cast<uint64_t>(off) + static_cast<uint64_t>(len) <= static_cast<uint64_t>(rsp_len);
  };
  if (!check_slice(rsp->primary_off, rsp->primary_len) ||
      !check_slice(rsp->ir_off, rsp->ir_len) ||
      !check_slice(rsp->tags_off, rsp->tags_len)) {
    RecordFailure(QStringLiteral("插件分析响应越界"));
    if (out_error) {
      *out_error = QStringLiteral("插件分析响应越界");
    }
    if (free_fn_) {
      free_fn_(rsp_ptr);
    }
    return false;
  }

  const uint8_t* base = reinterpret_cast<const uint8_t*>(rsp_ptr);
  out_result->primary_text = Utf8Slice(base + rsp->primary_off, rsp->primary_len).trimmed();
  out_result->ir_text = Utf8Slice(base + rsp->ir_off, rsp->ir_len).trimmed();
  out_result->confidence = std::clamp(static_cast<int>(rsp->confidence), 0, 100);
  const QString tags_text = Utf8Slice(base + rsp->tags_off, rsp->tags_len);
  out_result->tags = tags_text.split(',', Qt::SkipEmptyParts);
  for (QString& tag : out_result->tags) {
    tag = tag.trimmed();
  }
  out_result->tags.removeAll(QString());

  if (free_fn_) {
    free_fn_(rsp_ptr);
  }
  error_count_ = 0;
  return true;
}

int PluginRuntime::RegisterEventHandler(uint32_t event_id,
                                        R3ModuleEventCallbackFn callback,
                                        void* user_ctx) {
  if (!callback) {
    return -1;
  }
  event_handlers_[event_id] = EventHandler{callback, user_ctx};
  return 0;
}

int PluginRuntime::DispatchEventToCallback(uint32_t event_id,
                                           uint32_t pid,
                                           uint64_t address,
                                           uint32_t size,
                                           uint32_t timeout_ms,
                                           uint32_t flags,
                                           const uint8_t* input_buf,
                                           uint32_t input_len,
                                           std::vector<uint8_t>* out_buf,
                                           QString* out_error) {
  if (out_error) {
    out_error->clear();
  }
  if (out_buf) {
    out_buf->clear();
  }
  auto it = event_handlers_.find(event_id);
  if (it == event_handlers_.end() || !it->second.fn) {
    return static_cast<int>(R3_MODULE_DISPATCH_PASS);
  }

  R3ModuleEventContext ctx{};
  ctx.abi_version = 1;
  ctx.event_id = event_id;
  ctx.flags = flags;
  ctx.reserved = 0;
  ctx.pid = pid;
  ctx.address = address;
  ctx.size = size;
  ctx.timeout_ms = timeout_ms;
  ctx.input_buf = input_buf;
  ctx.input_len = input_len;

  uint8_t* rsp_ptr = nullptr;
  uint32_t rsp_len = 0;
  const int32_t rc = it->second.fn(&ctx, it->second.user_ctx, &rsp_ptr, &rsp_len);

  auto free_rsp = [&]() {
    if (!rsp_ptr) {
      return;
    }
    if (free_fn_) {
      free_fn_(rsp_ptr);
    } else {
      std::free(rsp_ptr);
    }
    rsp_ptr = nullptr;
  };

  if (rc == static_cast<int32_t>(R3_MODULE_DISPATCH_PASS)) {
    free_rsp();
    return static_cast<int>(R3_MODULE_DISPATCH_PASS);
  }
  if (rc > 0) {
    if (out_buf && rsp_ptr && rsp_len > 0) {
      out_buf->assign(rsp_ptr, rsp_ptr + rsp_len);
    }
    free_rsp();
    error_count_ = 0;
    return static_cast<int>(R3_MODULE_DISPATCH_HANDLED);
  }

  QString err = QStringLiteral("插件事件错误 rc=%1").arg(rc);
  if (rsp_ptr && rsp_len > 0) {
    const QString text = Utf8Slice(rsp_ptr, rsp_len).trimmed();
    if (!text.isEmpty()) {
      err = text;
    }
  }
  free_rsp();
  RecordFailure(err);
  if (out_error) {
    *out_error = err;
  }
  return static_cast<int>(R3_MODULE_DISPATCH_ERROR);
}

int PluginRuntime::DispatchEventToMemOp(uint32_t op,
                                        uint32_t pid,
                                        uint64_t address,
                                        uint32_t size,
                                        uint32_t timeout_ms,
                                        uint32_t flags,
                                        const std::vector<uint8_t>& user_ctx,
                                        const uint8_t* write_data,
                                        uint32_t write_len,
                                        std::vector<uint8_t>* out_data,
                                        QString* out_error) {
  if (out_error) {
    out_error->clear();
  }
  if (out_data) {
    out_data->clear();
  }
  if (!mem_op_fn_) {
    return static_cast<int>(R3_MODULE_DISPATCH_PASS);
  }

  const size_t base_size = sizeof(R3SysMemReqV1);
  const size_t total_size = base_size + user_ctx.size() + write_len;
  if (total_size > std::numeric_limits<uint32_t>::max()) {
    if (out_error) {
      *out_error = QStringLiteral("插件内存事件请求过大");
    }
    return static_cast<int>(R3_MODULE_DISPATCH_ERROR);
  }

  std::vector<uint8_t> req_buf(total_size, 0);
  auto* req = reinterpret_cast<R3SysMemReqV1*>(req_buf.data());
  req->abi_version = 1;
  req->struct_size = sizeof(R3SysMemReqV1);
  req->op = op;
  req->flags = flags;
  req->pid = pid;
  req->tid_hint = 0;
  req->address = address;
  req->size = size;
  req->timeout_ms = timeout_ms == 0 ? 1000u : timeout_ms;
  req->trace_id = 0;
  req->user_ctx_off = user_ctx.empty() ? 0u : static_cast<uint32_t>(base_size);
  req->user_ctx_len = static_cast<uint32_t>(user_ctx.size());
  req->write_data_off = write_len == 0 ? 0u : static_cast<uint32_t>(base_size + user_ctx.size());
  req->write_data_len = write_len;
  req->reserved0 = 0;
  req->reserved1 = 0;

  if (!user_ctx.empty()) {
    std::memcpy(req_buf.data() + base_size, user_ctx.data(), user_ctx.size());
  }
  if (write_len > 0 && write_data) {
    std::memcpy(req_buf.data() + base_size + user_ctx.size(), write_data, write_len);
  }

  uint8_t* rsp_ptr = nullptr;
  uint32_t rsp_len = 0;
  const int rc = mem_op_fn_(req_buf.data(),
                            static_cast<uint32_t>(req_buf.size()),
                            &rsp_ptr,
                            &rsp_len);
  if (rc != 0 || !rsp_ptr || rsp_len < sizeof(R3SysMemRspV1)) {
    if (rsp_ptr) {
      if (free_fn_) {
        free_fn_(rsp_ptr);
      } else {
        std::free(rsp_ptr);
      }
    }
    const QString err = QStringLiteral("插件内存事件执行失败 rc=%1").arg(rc);
    RecordFailure(err);
    if (out_error) {
      *out_error = err;
    }
    return static_cast<int>(R3_MODULE_DISPATCH_ERROR);
  }

  const auto* rsp = reinterpret_cast<const R3SysMemRspV1*>(rsp_ptr);
  auto free_rsp = [&]() {
    if (free_fn_) {
      free_fn_(rsp_ptr);
    } else {
      std::free(rsp_ptr);
    }
    rsp_ptr = nullptr;
  };

  if (rsp->code == R3_MEM_OK) {
    if (out_data && op == R3_MEM_OP_READ && rsp->read_data_len > 0) {
      const uint32_t off = rsp->read_data_off;
      const uint32_t len = rsp->read_data_len;
      if (off >= rsp_len || static_cast<uint64_t>(off) + len > rsp_len) {
        free_rsp();
        const QString err = QStringLiteral("插件内存事件响应越界");
        RecordFailure(err);
        if (out_error) {
          *out_error = err;
        }
        return static_cast<int>(R3_MODULE_DISPATCH_ERROR);
      }
      const uint8_t* data_ptr = reinterpret_cast<const uint8_t*>(rsp_ptr) + off;
      out_data->assign(data_ptr, data_ptr + len);
    }
    free_rsp();
    error_count_ = 0;
    return static_cast<int>(R3_MODULE_DISPATCH_HANDLED);
  }

  if (rsp->code == R3_MEM_E_FALLBACK) {
    free_rsp();
    return static_cast<int>(R3_MODULE_DISPATCH_PASS);
  }

  QString err = QStringLiteral("插件内存事件错误 code=%1 sys=%2")
                    .arg(rsp->code)
                    .arg(rsp->sys_errno);
  if (rsp->extra_len > 0) {
    const uint32_t off = rsp->extra_off;
    const uint32_t len = rsp->extra_len;
    if (off < rsp_len && static_cast<uint64_t>(off) + len <= rsp_len) {
      const QString text = Utf8Slice(reinterpret_cast<const uint8_t*>(rsp_ptr) + off, len).trimmed();
      if (!text.isEmpty()) {
        err = text;
      }
    }
  }
  free_rsp();
  RecordFailure(err);
  if (out_error) {
    *out_error = err;
  }
  return static_cast<int>(R3_MODULE_DISPATCH_ERROR);
}

int PluginRuntime::DispatchReadMemoryEvent(uint32_t pid,
                                           uint64_t address,
                                           uint32_t size,
                                           uint32_t timeout_ms,
                                           bool use_pvm,
                                           const std::vector<uint8_t>& user_ctx,
                                           std::vector<uint8_t>* out_data,
                                           QString* out_message) {
  if (out_message) {
    out_message->clear();
  }
  if (out_data) {
    out_data->clear();
  }
  if (!SupportsMemoryEvent()) {
    return static_cast<int>(R3_MODULE_DISPATCH_PASS);
  }

  const uint32_t flags = use_pvm ? 0x2u : 0u;
  std::vector<uint8_t> callback_data;
  QString callback_error;
  const int callback_rc =
      DispatchEventToCallback(static_cast<uint32_t>(R3_MODULE_EVENT_READ_MEM),
                              pid,
                              address,
                              size,
                              timeout_ms,
                              flags,
                              nullptr,
                              0,
                              &callback_data,
                              &callback_error);
  if (callback_rc == static_cast<int>(R3_MODULE_DISPATCH_HANDLED)) {
    if (out_data) {
      *out_data = std::move(callback_data);
    }
    return callback_rc;
  }
  if (callback_rc == static_cast<int>(R3_MODULE_DISPATCH_ERROR)) {
    if (out_message) {
      *out_message = callback_error;
    }
    return callback_rc;
  }

  std::vector<uint8_t> mem_data;
  QString mem_error;
  const int mem_rc = DispatchEventToMemOp(R3_MEM_OP_READ,
                                          pid,
                                          address,
                                          size,
                                          timeout_ms,
                                          flags,
                                          user_ctx,
                                          nullptr,
                                          0,
                                          &mem_data,
                                          &mem_error);
  if (mem_rc == static_cast<int>(R3_MODULE_DISPATCH_HANDLED) && out_data) {
    *out_data = std::move(mem_data);
  }
  if (mem_rc == static_cast<int>(R3_MODULE_DISPATCH_ERROR) && out_message) {
    *out_message = mem_error;
  }
  return mem_rc;
}

int PluginRuntime::DispatchWriteMemoryEvent(uint32_t pid,
                                            uint64_t address,
                                            const std::vector<uint8_t>& bytes,
                                            uint32_t timeout_ms,
                                            const std::vector<uint8_t>& user_ctx,
                                            QString* out_message) {
  if (out_message) {
    out_message->clear();
  }
  if (!SupportsMemoryEvent()) {
    return static_cast<int>(R3_MODULE_DISPATCH_PASS);
  }

  QString callback_error;
  const int callback_rc =
      DispatchEventToCallback(static_cast<uint32_t>(R3_MODULE_EVENT_WRITE_MEM),
                              pid,
                              address,
                              static_cast<uint32_t>(bytes.size()),
                              timeout_ms,
                              0u,
                              bytes.data(),
                              static_cast<uint32_t>(bytes.size()),
                              nullptr,
                              &callback_error);
  if (callback_rc == static_cast<int>(R3_MODULE_DISPATCH_HANDLED)) {
    return callback_rc;
  }
  if (callback_rc == static_cast<int>(R3_MODULE_DISPATCH_ERROR)) {
    if (out_message) {
      *out_message = callback_error;
    }
    return callback_rc;
  }

  QString mem_error;
  const int mem_rc = DispatchEventToMemOp(R3_MEM_OP_WRITE,
                                          pid,
                                          address,
                                          static_cast<uint32_t>(bytes.size()),
                                          timeout_ms,
                                          0u,
                                          user_ctx,
                                          bytes.data(),
                                          static_cast<uint32_t>(bytes.size()),
                                          nullptr,
                                          &mem_error);
  if (mem_rc == static_cast<int>(R3_MODULE_DISPATCH_ERROR) && out_message) {
    *out_message = mem_error;
  }
  return mem_rc;
}

void PluginRuntime::SetStage(const QString& stage) {
  stage_ = stage;
}

void PluginRuntime::SetLastError(const QString& error) {
  last_error_ = error.trimmed();
}

}  // namespace r3::windows_client_qt::plugins
