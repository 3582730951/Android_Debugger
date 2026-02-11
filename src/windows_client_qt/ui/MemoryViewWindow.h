#pragma once

#include <cstdint>
#include <mutex>
#include <vector>

#include <QMainWindow>
#include <QModelIndex>

#include "services/ClientService.h"
#include "plugins/PluginRuntime.h"

QT_BEGIN_NAMESPACE
class QLabel;
class QLineEdit;
class QPushButton;
class QSplitter;
class QStandardItemModel;
class QTableView;
class QTimer;
class QWidget;
QT_END_NAMESPACE

namespace r3::windows_client_qt::ui {

class PointerToolsDialog;

class MemoryViewWindow : public QMainWindow {
  Q_OBJECT

 public:
  explicit MemoryViewWindow(QWidget* parent = nullptr);

  void SetService(r3::windows_client_ng::services::ClientService* service,
                  std::mutex* service_mutex,
                  uint32_t pid);
  void SetPluginRuntime(r3::windows_client_qt::plugins::PluginRuntime* runtime);
  void JumpToAddress(uint64_t address);

 signals:
  void RequestAddAddress(uint64_t address);

 private slots:
  void OnJumpClicked();
  void OnShowContextMenu(const QPoint& pos);
  void OnHexContextMenu(const QPoint& pos);
  void OnDisasmDoubleClicked(const QModelIndex& index);
  void OnHexDoubleClicked(const QModelIndex& index);
  void OnRefreshClicked();
  void OnToggleExecBreakpoint();
  void OnAddWriteBreakpoint();
  void OnAddReadBreakpoint();
  void OnAddReadWriteBreakpoint();
  void OnRemoveAddressBreakpoints();
  void OnClearAllBreakpoints();
  void OnDebugPauseProcess();
  void OnDebugContinueProcess();
  void OnDebugStepIn();
  void OnDebugStepOver();
  void OnClearBreakpointHitHistory();

 private:
  struct BreakpointEntry {
    uint64_t address = 0;
    protocol::DebugBpType type = protocol::DEBUG_BP_EXEC;
    uint8_t size = 4;
    protocol::DebugBackend backend = protocol::DEBUG_BACKEND_PERF;
    bool enabled = true;
    uint64_t hit_count = 0;
  };

  static uint64_t ParseNumberText(const QString& text, bool* ok);
  uint64_t ParseJumpAddress(const QString& text, bool* ok);
  bool EnsureModulesLoaded();
  void OpenPointerToolsAtTab(int tab_index);
  void RefreshProcInfo();
  void PopulateDisasmTable(uint64_t base, const std::vector<uint8_t>& data);
  void PopulateHexTable(uint64_t base, const std::vector<uint8_t>& data);
  void PollBreakpointEvents();
  void AppendBreakpointHit(uint64_t address,
                           protocol::DebugBpType type,
                           protocol::DebugBackend backend,
                           uint8_t size,
                           uint64_t count);
  void UpdateDebugPanelVisibility();
  void ResetRegisterPanel(const QString& tip);
  void UpdateRegisterPanel(const r3::windows_client_ng::services::ClientService::RegsSnapshot& regs);
  void RefreshBreakpointVisuals();
  void UpdateBreakpointStatusText();
  void SetBreakpointStatus(const QString& text);
  uint64_t SelectedDisasmAddress() const;
  uint64_t SelectedHexAddress() const;
  uint64_t SelectedAddressForBreakpoint() const;
  bool EnsureBreakpointReady(QString* out_error) const;
  bool AddBreakpoint(uint64_t address, protocol::DebugBpType type, uint8_t size, QString* out_error);
  bool AddBreakpointWithBackend(uint64_t address,
                                protocol::DebugBpType type,
                                uint8_t size,
                                protocol::DebugBackend backend,
                                QString* out_error);
  bool RemoveBreakpoint(uint64_t address,
                        protocol::DebugBpType type,
                        protocol::DebugBackend backend,
                        QString* out_error);
  bool RemoveAllBreakpointsAt(uint64_t address, QString* out_error);
  bool ClearAllBreakpointsOnDevice(QString* out_error);
  bool HasBreakpoint(uint64_t address, protocol::DebugBpType type) const;
  bool HasBreakpoint(uint64_t address,
                     protocol::DebugBpType type,
                     protocol::DebugBackend backend) const;
  bool HasAnyBreakpointAt(uint64_t address) const;
  QString BreakpointSummaryForAddress(uint64_t address) const;
  static QString BreakpointTypeShortText(protocol::DebugBpType type);
  static QString BreakpointBackendText(protocol::DebugBackend backend);
  QString BuildAddressAlias(uint64_t address) const;
  static QString BuildPermText(uint32_t perms);
  static QString BytesToHex(const uint8_t* data, size_t size);
  QString DecodeInstructionText(uint64_t address, const uint8_t* data, size_t size) const;
  QString BuildPluginComment(uint64_t address, const uint8_t* data, size_t size) const;
  static QString ModuleDisplayName(const r3::windows_client_ng::services::ClientService::ModuleInfo& module);

  bool RefreshBytes(uint64_t address);

  r3::windows_client_ng::services::ClientService* service_ = nullptr;
  std::mutex* service_mutex_ = nullptr;
  r3::windows_client_qt::plugins::PluginRuntime* plugin_runtime_ = nullptr;
  uint32_t pid_ = 0;
  uint64_t current_address_ = 0;
  protocol::RegsArch arch_ = protocol::RegsArch::UNKNOWN;
  uint8_t pointer_size_ = 0;

  std::vector<uint8_t> current_bytes_;
  std::vector<r3::windows_client_ng::services::ClientService::ModuleInfo> modules_;
  uint32_t modules_pid_ = 0;
  uint32_t proc_info_pid_ = 0;

  QLineEdit* address_edit_ = nullptr;
  QPushButton* jump_button_ = nullptr;
  QPushButton* refresh_button_ = nullptr;
  QLabel* info_label_ = nullptr;
  QLabel* breakpoint_label_ = nullptr;
  QLabel* register_label_ = nullptr;
  QLabel* breakpoint_hits_label_ = nullptr;

  QTableView* disasm_table_ = nullptr;
  QStandardItemModel* disasm_model_ = nullptr;
  QSplitter* top_splitter_ = nullptr;
  QWidget* debug_panel_ = nullptr;
  QTableView* register_table_ = nullptr;
  QStandardItemModel* register_model_ = nullptr;
  QTableView* breakpoint_hits_table_ = nullptr;
  QStandardItemModel* breakpoint_hits_model_ = nullptr;
  QTableView* hex_table_ = nullptr;
  QStandardItemModel* hex_model_ = nullptr;
  QTimer* breakpoint_poll_timer_ = nullptr;

  std::vector<BreakpointEntry> breakpoints_;
  protocol::DebugBackend breakpoint_backend_ = protocol::DEBUG_BACKEND_PERF;
  bool breakpoint_stop_on_hit_ = false;
  bool breakpoint_overlay_visible_ = true;
  QString breakpoint_status_;
  uint64_t breakpoint_hit_total_ = 0;
  uint64_t breakpoint_last_hit_addr_ = 0;
  bool debug_attached_ = false;
  bool debug_panel_visible_ = false;
  enum AnnotationMode : uint8_t {
    ANNO_BUILTIN = 0,
    ANNO_PLUGIN = 1,
    ANNO_MIXED = 2,
  };
  AnnotationMode annotation_mode_ = ANNO_MIXED;

  PointerToolsDialog* pointer_tools_ = nullptr;
};

}  // namespace r3::windows_client_qt::ui
