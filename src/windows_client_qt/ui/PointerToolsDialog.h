#pragma once

#include <cstdint>
#include <mutex>
#include <vector>

#include <QDialog>
#include <QPoint>
#include <QString>

#include "services/ClientService.h"

QT_BEGIN_NAMESPACE
class QCheckBox;
class QComboBox;
class QLabel;
class QLineEdit;
class QSpinBox;
class QStandardItemModel;
class QTableView;
class QTreeWidget;
class QTreeWidgetItem;
class QTabWidget;
class QWidget;
QT_END_NAMESPACE

namespace r3::windows_client_qt::ui {

class PointerToolsDialog : public QDialog {
  Q_OBJECT

 public:
  enum ToolTab {
    kPointerScanTab = 0,
    kPointerCompareTab = 1,
    kStructureTraverseTab = 2,
  };

  explicit PointerToolsDialog(QWidget* parent = nullptr);

  void SetService(r3::windows_client_ng::services::ClientService* service,
                  std::mutex* service_mutex,
                  uint32_t pid);
  void OpenTab(ToolTab tab);

 private slots:
  void OnRunPointerScan();
  void OnBrowsePointerScanOutput();

  void OnBrowseCompareFileA();
  void OnBrowseCompareFileB();
  void OnRunPointerCompare();

  void OnRunStructureTraverse();
  void OnTraverseItemExpanded(QTreeWidgetItem* item);
  void OnTraverseContextMenu(const QPoint& pos);

 private:
  struct PointerChainRecord {
    uint64_t base = 0;
    std::vector<int64_t> offsets;
  };

  void BuildUi();
  QWidget* BuildPointerScanTab();
  QWidget* BuildPointerCompareTab();
  QWidget* BuildStructureTraverseTab();

  bool EnsureServiceReady(QString* out_error) const;
  bool FetchPointerSize(uint32_t* out_pointer_size) const;
  bool EnsureTraverseModulesLoaded();

  uint16_t BuildPointerIndexFlags() const;
  bool QueryEntirePointerIndex(std::vector<r3::windows_client_ng::services::ClientService::PointerIndexEntry>* out_entries,
                               QString* out_error);
  bool BuildChainsToTarget(uint64_t target,
                           int depth,
                           int64_t max_offset,
                           uint32_t max_results,
                           std::vector<PointerChainRecord>* out_chains,
                           QString* out_error);

  bool SavePointerChainFile(const QString& path,
                            const std::vector<PointerChainRecord>& chains,
                            int depth,
                            int64_t max_offset,
                            uint32_t pointer_size,
                            uint64_t target,
                            QString* out_error) const;
  bool LoadPointerChainFile(const QString& path,
                            std::vector<PointerChainRecord>* out_chains,
                            QString* out_error) const;

  void PopulatePointerChainTable(QStandardItemModel* model,
                                 const std::vector<PointerChainRecord>& chains) const;

  static uint64_t ParseAddressText(const QString& text, bool* ok);
  static bool ParseSignedOffset(const QString& text, int64_t* out_value);
  static QString Hex64(uint64_t value);
  static QString FormatOffset(int64_t value);
  static QString ChainKey(const PointerChainRecord& chain);
  static QString FormatChainDisplay(const PointerChainRecord& chain);

  QString DefaultPointerScanOutputPath() const;
  QString DefaultPointerCompareOutputPath(const QString& file_a) const;

  bool ReadBytes(uint64_t address, uint32_t size, bool use_pvm, std::vector<uint8_t>* out_bytes) const;
  bool IsLikelyPointer(uint64_t value, uint32_t pointer_size);
  void PopulateTraverseRows(QTreeWidgetItem* parent, uint64_t base, int depth);
  void AttachTraverseTypeEditor(QTreeWidgetItem* item);
  void RefreshTraverseRow(QTreeWidgetItem* item);
  void UpdateTraverseExpandState(QTreeWidgetItem* item, bool can_expand);

  r3::windows_client_ng::services::ClientService* service_ = nullptr;
  std::mutex* service_mutex_ = nullptr;
  uint32_t pid_ = 0;

  QTabWidget* tabs_ = nullptr;

  QComboBox* scan_pointer_size_combo_ = nullptr;
  QLineEdit* scan_target_edit_ = nullptr;
  QSpinBox* scan_depth_spin_ = nullptr;
  QSpinBox* scan_max_offset_spin_ = nullptr;
  QSpinBox* scan_max_entries_spin_ = nullptr;
  QSpinBox* scan_max_results_spin_ = nullptr;
  QCheckBox* scan_flag_use_pvm_check_ = nullptr;
  QCheckBox* scan_flag_nonresident_check_ = nullptr;
  QCheckBox* scan_flag_byte_step_check_ = nullptr;
  QCheckBox* scan_flag_strict_check_ = nullptr;
  QLineEdit* scan_output_edit_ = nullptr;
  QLabel* scan_status_label_ = nullptr;
  QTableView* scan_table_ = nullptr;
  QStandardItemModel* scan_model_ = nullptr;

  QLineEdit* compare_file_a_edit_ = nullptr;
  QLineEdit* compare_file_b_edit_ = nullptr;
  QLabel* compare_status_label_ = nullptr;
  QTableView* compare_table_ = nullptr;
  QStandardItemModel* compare_model_ = nullptr;

  QLineEdit* traverse_base_edit_ = nullptr;
  QSpinBox* traverse_count_spin_ = nullptr;
  QSpinBox* traverse_stride_spin_ = nullptr;
  QComboBox* traverse_pointer_size_combo_ = nullptr;
  QCheckBox* traverse_use_pvm_check_ = nullptr;
  QCheckBox* traverse_auto_pointer_check_ = nullptr;
  QLabel* traverse_status_label_ = nullptr;
  QTreeWidget* traverse_tree_ = nullptr;

  std::vector<r3::windows_client_ng::services::ClientService::ModuleInfo> traverse_modules_;
  uint32_t traverse_modules_pid_ = 0;
};

}  // namespace r3::windows_client_qt::ui
