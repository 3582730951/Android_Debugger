#pragma once

#include <cstdint>
#include <mutex>
#include <optional>
#include <unordered_map>
#include <vector>

#include <QFutureWatcher>
#include <QMainWindow>
#include <QModelIndex>
#include <QPoint>
#include <QString>
#include <QStringList>

#include "services/ClientService.h"
#include "plugins/PluginCatalog.h"
#include "plugins/PluginRuntime.h"

QT_BEGIN_NAMESPACE
class QAction;
class QByteArray;
class QCheckBox;
class QComboBox;
class QIcon;
class QLabel;
class QLineEdit;
class QMenu;
class QPlainTextEdit;
class QPushButton;
class QResizeEvent;
class QSpinBox;
class QSplitter;
class QStandardItem;
class QStandardItemModel;
class QTableView;
class QTimer;
class QToolButton;
QT_END_NAMESPACE

namespace r3::windows_client_qt::ui {

class MemoryViewWindow;
class ProcessDialog;
class ModuleRangeDialog;
class PointerToolsDialog;
class SettingsDialog;
class PluginDevWindow;
class PluginFailureWindow;
class PluginProviderWindow;
class PluginRuntimeWindow;

class MainWindow : public QMainWindow {
  Q_OBJECT

 public:
  explicit MainWindow(QWidget* parent = nullptr);
  ~MainWindow() override;

 protected:
  void resizeEvent(QResizeEvent* event) override;

 private slots:
  void OnConnectClicked();
  void OnSelectProcessClicked();
  void OnFirstScanClicked();
  void OnNextScanClicked();
  void OnUndoScanClicked();
  void OnOpenMemoryViewClicked();
  void OnOpenModuleRangeClicked();
  void OnOpenSettingsClicked();
  void OnOpenPointerToolsClicked();
  void OnOpenPointerScanClicked();
  void OnOpenPointerCompareClicked();
  void OnOpenStructureTraverseClicked();
  void OnOpenPluginProviderClicked();
  void OnOpenPluginRuntimeClicked();
  void OnOpenPluginDevClicked();
  void OnOpenPluginFailureOutputClicked();
  void OnPluginSelfCheckClicked();
  void OnPluginFallbackClicked();

  void OnScanResultDoubleClicked(const QModelIndex& index);
  void OnScanContextMenuRequested(const QPoint& pos);
  void OnAddressContextMenuRequested(const QPoint& pos);
  void OnQuickAddSelected();
  void OnQuickAddAndEditSelected();
  void OnAddressRefreshTick();
  void OnAddressItemChanged(QStandardItem* item);
  void OnScanTaskFinished();

  void OnAutoStartupFinished();

 private:
  void BuildUi();
  void BuildMenuAndToolbar();
  void BuildCenterLayout();
  void BuildScanTable();
  void BuildAddressTable();
  void BuildControlPanel(QWidget* parent);

  void LoadSettings();
  void SaveSettings();

  void UpdateConnectionUi();
  void UpdateStatus(const QString& text);
  void WarmupSecondaryWindows();

  bool EnsureConnected();
  bool ConnectToService(const QString& host, uint16_t port);
  void DisconnectService();

  bool AttachProcess(uint32_t pid, const QString& name);
  void RefreshProcessListAndOpenDialog();

  uint16_t BuildScanFlags() const;
  protocol::ValueType CurrentScanValueType() const;
  protocol::ComparisonType CurrentComparisonType() const;
  void PopulateScanResultRows(const std::vector<uint64_t>& addresses, uint64_t total);
  void StartScan(bool first_scan);
  void SetScanBusy(bool busy);

  void AddAddressEntry(uint64_t address, bool open_editor);
  std::optional<uint64_t> SelectedScanAddress() const;
  std::optional<uint64_t> SelectedAddressListAddress() const;

  static uint64_t ParseAddressText(const QString& text, bool* ok);
  static QString Hex64(uint64_t value);
  static QString ValueTypeDisplayName(protocol::ValueType value_type);
  static bool ValueTypeFromDisplayName(const QString& text, protocol::ValueType* out_type);
  static uint32_t ValueTypeByteSize(protocol::ValueType value_type);
  static QString FormatValueText(protocol::ValueType value_type, const std::vector<uint8_t>& bytes);
  static bool BuildWriteBytes(protocol::ValueType value_type,
                              const QString& value_text,
                              std::vector<uint8_t>* out_bytes);

  void OpenMemoryViewAt(uint64_t address);
  void OpenPointerToolsAtTab(int tab_index);
  void WriteAddressRowValue(int row);
  void ApplyAddressRefreshResult();

  void TryAutoStartup();
  bool ProbeAndPushAgent();
  void ReloadPluginCatalog();
  void ApplyCustomProviderConfig();
  std::vector<uint8_t> ParsePluginUserCtxBytes(QString* out_error) const;
  void DumpTelemetrySnapshot(const QString& reason);
  void UpdatePluginProviderStatusPanel();
  QString BuildPluginModuleStateText(
      const r3::windows_client_ng::services::ClientService::ProviderRuntimeSnapshot& provider) const;
  void UpdatePluginFailureEntryLayout();
  bool RunPluginSelfCheck(QString* out_report);
  void SyncPluginFailureOutputWindow();
  void RecordPluginLoadFailure(const QString& text);
  void EnsureMemoryViewWindow();
  void EnsurePointerToolsWindow();
  void EnsureProcessDialog();
  void SyncProcessDialogFromCache();
  void EnsurePluginProviderWindow();
  void EnsurePluginRuntimeWindow();
  void EnsurePluginDevWindow();
  void EnsurePluginFailureWindow();

  QIcon LoadCachedIcon(uint32_t pid) const;
  void SaveCachedIcon(uint32_t pid, const QByteArray& png_data) const;
  QString IconCachePath(uint32_t pid) const;

  std::mutex service_mutex_;
  r3::windows_client_ng::services::ClientService service_;

  bool connected_ = false;
  uint32_t attached_pid_ = 0;
  QString attached_process_name_;

  uint64_t scan_total_ = 0;
  std::vector<uint64_t> current_scan_addresses_;
  std::unordered_map<uint64_t, QString> previous_scan_values_;
  std::vector<r3::windows_client_ng::services::ClientService::ModuleInfo> module_cache_;
  uint32_t module_cache_pid_ = 0;
  bool module_cache_ready_ = false;

  QString settings_path_;
  QString plugin_root_path_;
  QString plugin_selected_id_;
  bool plugin_enabled_ = false;
  bool plugin_force_builtin_fallback_ = false;
  bool plugin_allow_fallback_ = true;
  int plugin_timeout_ms_ = 1000;
  int plugin_syscall_read_ = -1;
  int plugin_syscall_write_ = -1;
  QString plugin_user_ctx_hex_;
  int plugin_loaded_count_ = 0;
  int plugin_load_failed_count_ = 0;
  QStringList plugin_load_failure_messages_;
  std::vector<r3::windows_client_ng::services::ProcessInfo> process_cache_;
  bool process_cache_ready_ = false;
  uint64_t process_cache_generation_ = 0;
  uint64_t process_dialog_generation_ = 0;
  r3::windows_client_qt::plugins::PluginCatalog plugin_catalog_;
  r3::windows_client_qt::plugins::PluginRuntime plugin_runtime_;

  QFutureWatcher<bool> auto_startup_watcher_;
  bool auto_startup_running_ = false;

  struct AddressRefreshJob {
    int row = -1;
    uint64_t address = 0;
    protocol::ValueType value_type = protocol::ValueType::U32;
    bool freeze = false;
    QString value_text;
  };

  struct AddressValueUpdate {
    int row = -1;
    QString value_text;
  };

  struct AddressRefreshResult {
    std::vector<AddressValueUpdate> updates;
    int freeze_write_failures = 0;
  };

  struct ScanTaskResult {
    bool ok = false;
    QString error;
    uint64_t total = 0;
    std::vector<uint64_t> addresses;
  };

  QFutureWatcher<AddressRefreshResult> address_refresh_watcher_;
  bool address_refresh_in_flight_ = false;
  bool address_refresh_pending_ = false;
  QFutureWatcher<ScanTaskResult> scan_watcher_;
  bool scan_in_flight_ = false;
  bool scan_task_is_first_ = true;

  QAction* action_connect_ = nullptr;
  QAction* action_select_process_ = nullptr;
  QAction* action_open_memory_ = nullptr;
  QAction* action_module_range_ = nullptr;
  QAction* action_settings_ = nullptr;
  QAction* action_pointer_tools_ = nullptr;
  QAction* action_pointer_scan_ = nullptr;
  QAction* action_pointer_compare_ = nullptr;
  QAction* action_structure_traverse_ = nullptr;
  QAction* action_plugin_provider_ = nullptr;
  QAction* action_plugin_runtime_ = nullptr;
  QAction* action_plugin_dev_ = nullptr;
  QAction* action_plugin_failure_output_ = nullptr;

  QLabel* process_label_ = nullptr;
  QLineEdit* host_edit_ = nullptr;
  QSpinBox* port_spin_ = nullptr;
  QLineEdit* adb_path_edit_ = nullptr;
  QCheckBox* auto_start_check_ = nullptr;
  QPushButton* plugin_failure_output_button_ = nullptr;
  QToolButton* plugin_failure_output_dropdown_button_ = nullptr;
  QMenu* plugin_failure_output_menu_ = nullptr;

  QLineEdit* scan_value_edit_ = nullptr;
  QCheckBox* scan_hex_check_ = nullptr;
  QComboBox* scan_compare_combo_ = nullptr;
  QComboBox* scan_value_type_combo_ = nullptr;
  QComboBox* scan_region_combo_ = nullptr;
  QLineEdit* scan_start_edit_ = nullptr;
  QLineEdit* scan_end_edit_ = nullptr;
  QCheckBox* flag_use_pvm_check_ = nullptr;
  QCheckBox* flag_writable_check_ = nullptr;
  QCheckBox* flag_exec_check_ = nullptr;
  QCheckBox* flag_private_check_ = nullptr;
  QCheckBox* flag_image_check_ = nullptr;
  QCheckBox* flag_mapped_check_ = nullptr;
  QPushButton* first_scan_button_ = nullptr;
  QPushButton* next_scan_button_ = nullptr;
  QPushButton* undo_scan_button_ = nullptr;

  QTableView* scan_table_ = nullptr;
  QStandardItemModel* scan_model_ = nullptr;

  QTableView* address_table_ = nullptr;
  QStandardItemModel* address_model_ = nullptr;
  bool address_model_updating_ = false;
  QTimer* address_timer_ = nullptr;

  MemoryViewWindow* memory_view_ = nullptr;
  ProcessDialog* process_dialog_ = nullptr;
  PointerToolsDialog* pointer_tools_ = nullptr;
  PluginProviderWindow* plugin_provider_window_ = nullptr;
  PluginRuntimeWindow* plugin_runtime_window_ = nullptr;
  PluginDevWindow* plugin_dev_window_ = nullptr;
  PluginFailureWindow* plugin_failure_window_ = nullptr;
};

}  // namespace r3::windows_client_qt::ui
