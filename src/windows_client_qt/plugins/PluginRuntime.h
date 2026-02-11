#pragma once

#include <cstdint>
#include <memory>
#include <unordered_map>
#include <vector>

#include <QLibrary>
#include <QProcess>
#include <QString>
#include <QStringList>

#include "plugin_sdk/R3PluginApi.h"
#include "plugin_sdk/R3ModuleCompat.h"
#include "plugins/PluginCatalog.h"

namespace r3::windows_client_qt::plugins {

class PluginRuntime {
 public:
  struct AnalysisRequest {
    uint32_t arch = 0;
    uint64_t address = 0;
    std::vector<uint8_t> bytes;
    std::vector<uint8_t> regs_blob;
    std::vector<uint8_t> memory_window;
  };

  struct AnalysisResult {
    QString primary_text;
    QString ir_text;
    int confidence = 0;
    QStringList tags;
  };

  struct RuntimeStatus {
    QString plugin_id;
    QString plugin_name;
    QString mode;
    QString stage;
    bool active = false;
    bool fused = false;
    uint32_t error_count = 0;
    QString last_error;
  };

  PluginRuntime() = default;
  ~PluginRuntime();

  bool Activate(const PluginManifest& manifest, QString* out_error);
  void Deactivate();

  RuntimeStatus Status() const;
  bool IsActive() const { return active_; }
  bool IsFused() const { return fused_; }
  bool SupportsAnalysis() const;
  bool SupportsMemoryEvent() const;

  void ResetFailures();
  void RecordFailure(const QString& reason);
  void ForceFuse(const QString& reason);

  bool Analyze(const AnalysisRequest& request, AnalysisResult* out_result, QString* out_error);
  int DispatchReadMemoryEvent(uint32_t pid,
                              uint64_t address,
                              uint32_t size,
                              uint32_t timeout_ms,
                              bool use_pvm,
                              const std::vector<uint8_t>& user_ctx,
                              std::vector<uint8_t>* out_data,
                              QString* out_message);
  int DispatchWriteMemoryEvent(uint32_t pid,
                               uint64_t address,
                               const std::vector<uint8_t>& bytes,
                               uint32_t timeout_ms,
                               const std::vector<uint8_t>& user_ctx,
                               QString* out_message);
  int RegisterEventHandler(uint32_t event_id, R3ModuleEventCallbackFn callback, void* user_ctx);

 private:
  using QueryFn = int (*)(R3PluginInfo*);
  using InitFn = int (*)(const R3HostApi*);
  using StartFn = int (*)(void);
  using StopFn = int (*)(void);
  using MemOpFn = int (*)(const uint8_t*, uint32_t, uint8_t**, uint32_t*);
  using AnalyzeFn = int (*)(const uint8_t*, uint32_t, uint8_t**, uint32_t*);
  using FreeFn = void (*)(void*);
  using RegisterEventsFn = int (*)(const R3ModuleHostApiV1*);

  struct EventHandler {
    R3ModuleEventCallbackFn fn = nullptr;
    void* user_ctx = nullptr;
  };

  bool ActivateInProcess(const PluginManifest& manifest, QString* out_error);
  bool ActivateOutOfProcess(const PluginManifest& manifest, QString* out_error);
  int DispatchEventToCallback(uint32_t event_id,
                              uint32_t pid,
                              uint64_t address,
                              uint32_t size,
                              uint32_t timeout_ms,
                              uint32_t flags,
                              const uint8_t* input_buf,
                              uint32_t input_len,
                              std::vector<uint8_t>* out_buf,
                              QString* out_error);
  int DispatchEventToMemOp(uint32_t op,
                           uint32_t pid,
                           uint64_t address,
                           uint32_t size,
                           uint32_t timeout_ms,
                           uint32_t flags,
                           const std::vector<uint8_t>& user_ctx,
                           const uint8_t* write_data,
                           uint32_t write_len,
                           std::vector<uint8_t>* out_data,
                           QString* out_error);
  void SetStage(const QString& stage);
  void SetLastError(const QString& error);

  PluginManifest manifest_{};
  QLibrary library_;
  std::unique_ptr<QProcess> oop_process_;

  QueryFn query_fn_ = nullptr;
  InitFn init_fn_ = nullptr;
  StartFn start_fn_ = nullptr;
  StopFn stop_fn_ = nullptr;
  MemOpFn mem_op_fn_ = nullptr;
  AnalyzeFn analyze_fn_ = nullptr;
  FreeFn free_fn_ = nullptr;
  RegisterEventsFn register_events_fn_ = nullptr;
  std::unordered_map<uint32_t, EventHandler> event_handlers_;

  bool active_ = false;
  bool in_process_loaded_ = false;
  bool fused_ = false;
  uint32_t error_count_ = 0;
  QString stage_ = QStringLiteral("discover");
  QString last_error_;
};

}  // namespace r3::windows_client_qt::plugins
