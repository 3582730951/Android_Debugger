#include "ui/PointerToolsDialog.h"

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <limits>
#include <unordered_set>
#include <utility>

#include <QAbstractItemView>
#include <QCheckBox>
#include <QComboBox>
#include <QDateTime>
#include <QDialogButtonBox>
#include <QDir>
#include <QFile>
#include <QFileDialog>
#include <QFileInfo>
#include <QFormLayout>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QMenu>
#include <QMessageBox>
#include <QPushButton>
#include <QSpinBox>
#include <QStandardItem>
#include <QStandardItemModel>
#include <QStringConverter>
#include <QStringList>
#include <QTabWidget>
#include <QTableView>
#include <QTextStream>
#include <QTreeWidget>
#include <QTreeWidgetItem>
#include <QVBoxLayout>
#include <QWidget>

namespace r3::windows_client_qt::ui {

namespace {
constexpr int kRoleTraverseAddress = Qt::UserRole + 300;
constexpr int kRoleTraverseDepth = Qt::UserRole + 301;
constexpr int kRoleTraversePointerValue = Qt::UserRole + 302;
constexpr int kRoleTraversePointerCandidate = Qt::UserRole + 303;
constexpr int kRoleTraverseForcedPointer = Qt::UserRole + 304;
constexpr int kRoleTraverseChildrenLoaded = Qt::UserRole + 305;
constexpr int kRoleTraverseDummy = Qt::UserRole + 306;

constexpr int kTraverseMaxDepth = 8;

QString ToQString(const std::string& text) {
  return QString::fromUtf8(text.c_str(), static_cast<int>(text.size()));
}

template <typename T>
T ReadLE(const std::vector<uint8_t>& bytes) {
  T value{};
  if (bytes.size() >= sizeof(T)) {
    std::memcpy(&value, bytes.data(), sizeof(T));
  }
  return value;
}

QString JoinOffsets(const std::vector<int64_t>& offsets) {
  QStringList items;
  items.reserve(static_cast<int>(offsets.size()));
  for (int64_t off : offsets) {
    const QString abs_hex = QString::number(static_cast<qulonglong>(off >= 0 ? off : -off), 16).toUpper();
    items.push_back(off >= 0 ? QStringLiteral("+0x%1").arg(abs_hex) : QStringLiteral("-0x%1").arg(abs_hex));
  }
  return items.join(QLatin1Char(','));
}
}  // namespace

PointerToolsDialog::PointerToolsDialog(QWidget* parent) : QDialog(parent) {
  BuildUi();
  setWindowTitle(QStringLiteral("指针工具"));
  resize(1080, 760);
}

void PointerToolsDialog::SetService(r3::windows_client_ng::services::ClientService* service,
                                    std::mutex* service_mutex,
                                    uint32_t pid) {
  service_ = service;
  service_mutex_ = service_mutex;
  if (pid_ != pid) {
    traverse_modules_.clear();
    traverse_modules_pid_ = 0;
  }
  pid_ = pid;

  uint32_t pointer_size = 0;
  if (FetchPointerSize(&pointer_size) && (pointer_size == 4 || pointer_size == 8)) {
    const int idx_scan = scan_pointer_size_combo_->findData(static_cast<int>(pointer_size));
    if (idx_scan >= 0) {
      scan_pointer_size_combo_->setCurrentIndex(idx_scan);
    }
    const int idx_traverse = traverse_pointer_size_combo_->findData(static_cast<int>(pointer_size));
    if (idx_traverse >= 0) {
      traverse_pointer_size_combo_->setCurrentIndex(idx_traverse);
    }
  }
}

void PointerToolsDialog::OpenTab(ToolTab tab) {
  if (!tabs_) {
    return;
  }
  const int index = static_cast<int>(tab);
  if (index >= 0 && index < tabs_->count()) {
    tabs_->setCurrentIndex(index);
  }
  switch (tab) {
    case kPointerScanTab:
      setWindowTitle(QStringLiteral("指针扫描"));
      break;
    case kPointerCompareTab:
      setWindowTitle(QStringLiteral("指针对比"));
      break;
    case kStructureTraverseTab:
      setWindowTitle(QStringLiteral("结构遍历"));
      break;
    default:
      setWindowTitle(QStringLiteral("指针工具"));
      break;
  }
}

void PointerToolsDialog::BuildUi() {
  auto* root = new QVBoxLayout(this);
  root->setContentsMargins(10, 10, 10, 10);
  root->setSpacing(8);

  tabs_ = new QTabWidget(this);
  tabs_->addTab(BuildPointerScanTab(), QStringLiteral("指针扫描"));
  tabs_->addTab(BuildPointerCompareTab(), QStringLiteral("指针对比"));
  tabs_->addTab(BuildStructureTraverseTab(), QStringLiteral("结构遍历"));
  root->addWidget(tabs_, 1);

  auto* buttons = new QDialogButtonBox(QDialogButtonBox::Close, this);
  connect(buttons, &QDialogButtonBox::rejected, this, &QDialog::close);
  connect(buttons, &QDialogButtonBox::accepted, this, &QDialog::close);
  root->addWidget(buttons);
}

QWidget* PointerToolsDialog::BuildPointerScanTab() {
  auto* page = new QWidget(this);
  auto* layout = new QVBoxLayout(page);
  layout->setContentsMargins(0, 0, 0, 0);
  layout->setSpacing(8);

  auto* form = new QFormLayout();
  form->setContentsMargins(0, 0, 0, 0);

  scan_target_edit_ = new QLineEdit(QStringLiteral("0x0"), page);
  scan_pointer_size_combo_ = new QComboBox(page);
  scan_pointer_size_combo_->addItem(QStringLiteral("4"), 4);
  scan_pointer_size_combo_->addItem(QStringLiteral("8"), 8);

  scan_depth_spin_ = new QSpinBox(page);
  scan_depth_spin_->setRange(1, 8);
  scan_depth_spin_->setValue(3);

  scan_max_offset_spin_ = new QSpinBox(page);
  scan_max_offset_spin_->setRange(1, 0x7fffffff);
  scan_max_offset_spin_->setValue(4096);

  scan_max_entries_spin_ = new QSpinBox(page);
  scan_max_entries_spin_->setRange(1000, 5000000);
  scan_max_entries_spin_->setValue(500000);

  scan_max_results_spin_ = new QSpinBox(page);
  scan_max_results_spin_->setRange(10, 200000);
  scan_max_results_spin_->setValue(20000);

  scan_flag_use_pvm_check_ = new QCheckBox(QStringLiteral("使用PVM"), page);
  scan_flag_use_pvm_check_->setChecked(true);
  scan_flag_nonresident_check_ = new QCheckBox(QStringLiteral("允许非驻留"), page);
  scan_flag_byte_step_check_ = new QCheckBox(QStringLiteral("按字节步进"), page);
  scan_flag_strict_check_ = new QCheckBox(QStringLiteral("严格模式"), page);

  scan_output_edit_ = new QLineEdit(DefaultPointerScanOutputPath(), page);
  auto* browse_output_btn = new QPushButton(QStringLiteral("选择输出"), page);
  connect(browse_output_btn, &QPushButton::clicked, this, &PointerToolsDialog::OnBrowsePointerScanOutput);

  auto* output_row = new QHBoxLayout();
  output_row->setContentsMargins(0, 0, 0, 0);
  output_row->addWidget(scan_output_edit_, 1);
  output_row->addWidget(browse_output_btn);

  auto* flags_row = new QHBoxLayout();
  flags_row->setContentsMargins(0, 0, 0, 0);
  flags_row->addWidget(scan_flag_use_pvm_check_);
  flags_row->addWidget(scan_flag_nonresident_check_);
  flags_row->addWidget(scan_flag_byte_step_check_);
  flags_row->addWidget(scan_flag_strict_check_);
  flags_row->addStretch(1);

  form->addRow(QStringLiteral("目标地址"), scan_target_edit_);
  form->addRow(QStringLiteral("指针宽度"), scan_pointer_size_combo_);
  form->addRow(QStringLiteral("搜索层数"), scan_depth_spin_);
  form->addRow(QStringLiteral("最大偏移"), scan_max_offset_spin_);
  form->addRow(QStringLiteral("最大索引"), scan_max_entries_spin_);
  form->addRow(QStringLiteral("结果上限"), scan_max_results_spin_);
  form->addRow(QStringLiteral("索引选项"), flags_row);
  form->addRow(QStringLiteral("结果文件"), output_row);
  layout->addLayout(form);

  auto* run_btn = new QPushButton(QStringLiteral("开始指针扫描"), page);
  connect(run_btn, &QPushButton::clicked, this, &PointerToolsDialog::OnRunPointerScan);
  layout->addWidget(run_btn);

  scan_status_label_ = new QLabel(QStringLiteral("等待扫描"), page);
  layout->addWidget(scan_status_label_);

  scan_table_ = new QTableView(page);
  scan_table_->setSelectionBehavior(QAbstractItemView::SelectRows);
  scan_table_->setSelectionMode(QAbstractItemView::ExtendedSelection);
  scan_table_->setAlternatingRowColors(true);
  scan_table_->setEditTriggers(QAbstractItemView::NoEditTriggers);
  scan_table_->verticalHeader()->hide();
  scan_table_->horizontalHeader()->setStretchLastSection(true);

  scan_model_ = new QStandardItemModel(this);
  scan_model_->setColumnCount(3);
  scan_model_->setHeaderData(0, Qt::Horizontal, QStringLiteral("链路"));
  scan_model_->setHeaderData(1, Qt::Horizontal, QStringLiteral("基址"));
  scan_model_->setHeaderData(2, Qt::Horizontal, QStringLiteral("偏移序列"));
  scan_table_->setModel(scan_model_);
  scan_table_->setColumnWidth(0, 520);
  scan_table_->setColumnWidth(1, 180);
  layout->addWidget(scan_table_, 1);

  return page;
}

QWidget* PointerToolsDialog::BuildPointerCompareTab() {
  auto* page = new QWidget(this);
  auto* layout = new QVBoxLayout(page);
  layout->setContentsMargins(0, 0, 0, 0);
  layout->setSpacing(8);

  auto* form = new QFormLayout();
  form->setContentsMargins(0, 0, 0, 0);

  compare_file_a_edit_ = new QLineEdit(page);
  compare_file_b_edit_ = new QLineEdit(page);

  auto* browse_a_btn = new QPushButton(QStringLiteral("选择文件A"), page);
  auto* browse_b_btn = new QPushButton(QStringLiteral("选择文件B"), page);
  connect(browse_a_btn, &QPushButton::clicked, this, &PointerToolsDialog::OnBrowseCompareFileA);
  connect(browse_b_btn, &QPushButton::clicked, this, &PointerToolsDialog::OnBrowseCompareFileB);

  auto* row_a = new QHBoxLayout();
  row_a->setContentsMargins(0, 0, 0, 0);
  row_a->addWidget(compare_file_a_edit_, 1);
  row_a->addWidget(browse_a_btn);

  auto* row_b = new QHBoxLayout();
  row_b->setContentsMargins(0, 0, 0, 0);
  row_b->addWidget(compare_file_b_edit_, 1);
  row_b->addWidget(browse_b_btn);

  form->addRow(QStringLiteral("结果文件A"), row_a);
  form->addRow(QStringLiteral("结果文件B"), row_b);
  layout->addLayout(form);

  auto* run_btn = new QPushButton(QStringLiteral("开始对比"), page);
  connect(run_btn, &QPushButton::clicked, this, &PointerToolsDialog::OnRunPointerCompare);
  layout->addWidget(run_btn);

  compare_status_label_ = new QLabel(QStringLiteral("等待对比"), page);
  layout->addWidget(compare_status_label_);

  compare_table_ = new QTableView(page);
  compare_table_->setSelectionBehavior(QAbstractItemView::SelectRows);
  compare_table_->setSelectionMode(QAbstractItemView::ExtendedSelection);
  compare_table_->setAlternatingRowColors(true);
  compare_table_->setEditTriggers(QAbstractItemView::NoEditTriggers);
  compare_table_->verticalHeader()->hide();
  compare_table_->horizontalHeader()->setStretchLastSection(true);

  compare_model_ = new QStandardItemModel(this);
  compare_model_->setColumnCount(3);
  compare_model_->setHeaderData(0, Qt::Horizontal, QStringLiteral("公共链路"));
  compare_model_->setHeaderData(1, Qt::Horizontal, QStringLiteral("基址"));
  compare_model_->setHeaderData(2, Qt::Horizontal, QStringLiteral("偏移序列"));
  compare_table_->setModel(compare_model_);
  compare_table_->setColumnWidth(0, 520);
  compare_table_->setColumnWidth(1, 180);
  layout->addWidget(compare_table_, 1);

  return page;
}

QWidget* PointerToolsDialog::BuildStructureTraverseTab() {
  auto* page = new QWidget(this);
  auto* layout = new QVBoxLayout(page);
  layout->setContentsMargins(0, 0, 0, 0);
  layout->setSpacing(8);

  auto* form = new QFormLayout();
  form->setContentsMargins(0, 0, 0, 0);

  traverse_base_edit_ = new QLineEdit(QStringLiteral("0x0"), page);
  traverse_count_spin_ = new QSpinBox(page);
  traverse_count_spin_->setRange(1, 512);
  traverse_count_spin_->setValue(64);
  traverse_stride_spin_ = new QSpinBox(page);
  traverse_stride_spin_->setRange(1, 64);
  traverse_stride_spin_->setValue(4);

  traverse_pointer_size_combo_ = new QComboBox(page);
  traverse_pointer_size_combo_->addItem(QStringLiteral("4"), 4);
  traverse_pointer_size_combo_->addItem(QStringLiteral("8"), 8);
  traverse_pointer_size_combo_->setCurrentIndex(1);

  traverse_use_pvm_check_ = new QCheckBox(QStringLiteral("使用PVM"), page);
  traverse_use_pvm_check_->setChecked(true);
  traverse_auto_pointer_check_ = new QCheckBox(QStringLiteral("自动识别指针"), page);
  traverse_auto_pointer_check_->setChecked(true);

  auto* flags = new QHBoxLayout();
  flags->setContentsMargins(0, 0, 0, 0);
  flags->addWidget(traverse_use_pvm_check_);
  flags->addWidget(traverse_auto_pointer_check_);
  flags->addStretch(1);

  form->addRow(QStringLiteral("起始地址"), traverse_base_edit_);
  form->addRow(QStringLiteral("遍历长度"), traverse_count_spin_);
  form->addRow(QStringLiteral("步长"), traverse_stride_spin_);
  form->addRow(QStringLiteral("指针宽度"), traverse_pointer_size_combo_);
  form->addRow(QStringLiteral("遍历选项"), flags);
  layout->addLayout(form);

  auto* run_btn = new QPushButton(QStringLiteral("开始结构遍历"), page);
  connect(run_btn, &QPushButton::clicked, this, &PointerToolsDialog::OnRunStructureTraverse);
  layout->addWidget(run_btn);

  traverse_status_label_ = new QLabel(QStringLiteral("等待遍历"), page);
  layout->addWidget(traverse_status_label_);

  traverse_tree_ = new QTreeWidget(page);
  traverse_tree_->setColumnCount(4);
  traverse_tree_->setHeaderLabels({QStringLiteral("地址"), QStringLiteral("类型"), QStringLiteral("数值"), QStringLiteral("指针")});
  traverse_tree_->setAlternatingRowColors(true);
  traverse_tree_->setContextMenuPolicy(Qt::CustomContextMenu);
  traverse_tree_->header()->setStretchLastSection(false);
  traverse_tree_->header()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
  traverse_tree_->header()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
  traverse_tree_->header()->setSectionResizeMode(2, QHeaderView::Stretch);
  traverse_tree_->header()->setSectionResizeMode(3, QHeaderView::ResizeToContents);
  layout->addWidget(traverse_tree_, 1);

  connect(traverse_tree_, &QTreeWidget::itemExpanded, this, &PointerToolsDialog::OnTraverseItemExpanded);
  connect(traverse_tree_, &QTreeWidget::customContextMenuRequested, this, &PointerToolsDialog::OnTraverseContextMenu);

  return page;
}

bool PointerToolsDialog::EnsureServiceReady(QString* out_error) const {
  if (!service_ || !service_mutex_ || pid_ == 0) {
    if (out_error) {
      *out_error = QStringLiteral("请先连接并附加进程");
    }
    return false;
  }
  return true;
}

bool PointerToolsDialog::FetchPointerSize(uint32_t* out_pointer_size) const {
  if (!out_pointer_size) {
    return false;
  }
  *out_pointer_size = 0;
  if (!service_ || !service_mutex_) {
    return false;
  }
  uint8_t arch = 0;
  uint8_t ptr = 0;
  std::string error;
  bool ok = false;
  {
    const std::lock_guard<std::mutex> lock(*service_mutex_);
    ok = service_->FetchProcInfo(&arch, &ptr, &error);
  }
  if (!ok || (ptr != 4 && ptr != 8)) {
    return false;
  }
  *out_pointer_size = ptr;
  return true;
}

uint16_t PointerToolsDialog::BuildPointerIndexFlags() const {
  uint16_t flags = 0;
  if (scan_flag_use_pvm_check_->isChecked()) {
    flags |= protocol::PTR_INDEX_FLAG_USE_PVM;
  }
  if (scan_flag_nonresident_check_->isChecked()) {
    flags |= protocol::PTR_INDEX_FLAG_ALLOW_NONRESIDENT;
  }
  if (scan_flag_byte_step_check_->isChecked()) {
    flags |= protocol::PTR_INDEX_FLAG_BYTE_STEP;
  }
  if (scan_flag_strict_check_->isChecked()) {
    flags |= protocol::PTR_INDEX_FLAG_STRICT;
  }
  return flags;
}

bool PointerToolsDialog::QueryEntirePointerIndex(
    std::vector<r3::windows_client_ng::services::ClientService::PointerIndexEntry>* out_entries,
    QString* out_error) {
  if (!out_entries) {
    if (out_error) {
      *out_error = QStringLiteral("参数无效");
    }
    return false;
  }
  out_entries->clear();
  if (!service_ || !service_mutex_) {
    if (out_error) {
      *out_error = QStringLiteral("服务未就绪");
    }
    return false;
  }

  static constexpr uint32_t kPageSize = 2000;
  uint64_t total = 0;
  uint64_t start = 0;
  for (int guard = 0; guard < 200000; ++guard) {
    std::vector<r3::windows_client_ng::services::ClientService::PointerIndexEntry> page;
    std::string error;
    bool ok = false;
    {
      const std::lock_guard<std::mutex> lock(*service_mutex_);
      ok = service_->QueryPointerIndex(start, kPageSize, &total, &page, &error);
    }
    if (!ok) {
      if (out_error) {
        *out_error = ToQString(error);
      }
      out_entries->clear();
      return false;
    }
    if (start == 0 && total > 0) {
      const uint64_t reserve_count = std::min<uint64_t>(total, 3000000ull);
      out_entries->reserve(static_cast<size_t>(reserve_count));
    }
    out_entries->insert(out_entries->end(), page.begin(), page.end());
    if (page.empty() || out_entries->size() >= total) {
      break;
    }
    start += page.size();
  }
  return true;
}

bool PointerToolsDialog::BuildChainsToTarget(uint64_t target,
                                             int depth,
                                             int64_t max_offset,
                                             uint32_t max_results,
                                             std::vector<PointerChainRecord>* out_chains,
                                             QString* out_error) {
  if (!out_chains || depth <= 0 || max_offset <= 0) {
    if (out_error) {
      *out_error = QStringLiteral("扫描参数无效");
    }
    return false;
  }
  out_chains->clear();

  std::vector<r3::windows_client_ng::services::ClientService::PointerIndexEntry> entries;
  if (!QueryEntirePointerIndex(&entries, out_error)) {
    return false;
  }
  if (entries.empty()) {
    return true;
  }

  std::sort(entries.begin(), entries.end(), [](const auto& a, const auto& b) {
    if (a.value != b.value) {
      return a.value < b.value;
    }
    return a.address < b.address;
  });

  auto append_candidates = [&](uint64_t wanted,
                               const std::vector<PointerChainRecord>* tails,
                               std::vector<PointerChainRecord>* out) {
    const uint64_t max_u = static_cast<uint64_t>(max_offset);
    const uint64_t low = wanted > max_u ? (wanted - max_u) : 0;
    const uint64_t high = wanted > ((std::numeric_limits<uint64_t>::max)() - max_u)
                              ? (std::numeric_limits<uint64_t>::max)()
                              : (wanted + max_u);

    const auto begin_it = std::lower_bound(entries.begin(), entries.end(), low, [](const auto& lhs, uint64_t value) {
      return lhs.value < value;
    });

    for (auto it = begin_it; it != entries.end() && it->value <= high; ++it) {
      int64_t off = 0;
      if (wanted >= it->value) {
        const uint64_t delta = wanted - it->value;
        if (delta > static_cast<uint64_t>((std::numeric_limits<int64_t>::max)())) {
          continue;
        }
        off = static_cast<int64_t>(delta);
      } else {
        const uint64_t delta = it->value - wanted;
        if (delta > static_cast<uint64_t>((std::numeric_limits<int64_t>::max)())) {
          continue;
        }
        off = -static_cast<int64_t>(delta);
      }
      if (off < -max_offset || off > max_offset) {
        continue;
      }

      if (!tails) {
        PointerChainRecord chain;
        chain.base = it->address;
        chain.offsets.push_back(off);
        out->push_back(std::move(chain));
      } else {
        for (const auto& tail : *tails) {
          if (tail.base != wanted) {
            continue;
          }
          PointerChainRecord chain;
          chain.base = it->address;
          chain.offsets.reserve(tail.offsets.size() + 1);
          chain.offsets.push_back(off);
          chain.offsets.insert(chain.offsets.end(), tail.offsets.begin(), tail.offsets.end());
          out->push_back(std::move(chain));
        }
      }
    }
  };

  std::unordered_set<std::string> seen;
  std::vector<PointerChainRecord> current_level;
  append_candidates(target, nullptr, &current_level);

  for (const auto& chain : current_level) {
    const std::string key = ChainKey(chain).toStdString();
    if (seen.insert(key).second) {
      out_chains->push_back(chain);
      if (out_chains->size() >= max_results) {
        return true;
      }
    }
  }

  for (int layer = 2; layer <= depth; ++layer) {
    if (current_level.empty()) {
      break;
    }
    std::vector<PointerChainRecord> next_level;
    next_level.reserve(current_level.size() * 2);
    for (const auto& chain : current_level) {
      append_candidates(chain.base, &current_level, &next_level);
      if (next_level.size() >= max_results) {
        break;
      }
    }
    current_level.clear();
    for (const auto& chain : next_level) {
      const std::string key = ChainKey(chain).toStdString();
      if (seen.insert(key).second) {
        out_chains->push_back(chain);
        current_level.push_back(chain);
        if (out_chains->size() >= max_results) {
          return true;
        }
      }
    }
  }
  return true;
}
void PointerToolsDialog::OnRunPointerScan() {
  QString ready_error;
  if (!EnsureServiceReady(&ready_error)) {
    QMessageBox::warning(this, QStringLiteral("指针扫描"), ready_error);
    return;
  }

  bool addr_ok = false;
  const uint64_t target = ParseAddressText(scan_target_edit_->text(), &addr_ok);
  if (!addr_ok || target == 0) {
    QMessageBox::warning(this, QStringLiteral("指针扫描"), QStringLiteral("目标地址无效"));
    return;
  }

  const int depth = scan_depth_spin_->value();
  const int64_t max_offset = static_cast<int64_t>(scan_max_offset_spin_->value());
  const uint32_t max_entries = static_cast<uint32_t>(scan_max_entries_spin_->value());
  const uint32_t max_results = static_cast<uint32_t>(scan_max_results_spin_->value());
  const uint16_t pointer_size = static_cast<uint16_t>(scan_pointer_size_combo_->currentData().toInt());

  r3::windows_client_ng::services::ClientService::PointerIndexBuildResult build_result{};
  std::string build_error;
  bool build_ok = false;
  {
    const std::lock_guard<std::mutex> lock(*service_mutex_);
    build_ok = service_->BuildPointerIndex(pid_, pointer_size, BuildPointerIndexFlags(), max_entries, &build_result, &build_error);
  }
  if (!build_ok) {
    QMessageBox::warning(this, QStringLiteral("指针扫描"), QStringLiteral("构建索引失败: %1").arg(ToQString(build_error)));
    return;
  }

  std::vector<PointerChainRecord> chains;
  QString scan_error;
  if (!BuildChainsToTarget(target, depth, max_offset, max_results, &chains, &scan_error)) {
    QMessageBox::warning(this, QStringLiteral("指针扫描"), QStringLiteral("搜索失败: %1").arg(scan_error));
    return;
  }

  QString output_path = scan_output_edit_->text().trimmed();
  if (output_path.isEmpty()) {
    output_path = DefaultPointerScanOutputPath();
    scan_output_edit_->setText(output_path);
  }

  QString save_error;
  if (!SavePointerChainFile(output_path, chains, depth, max_offset, pointer_size, target, &save_error)) {
    QMessageBox::warning(this, QStringLiteral("指针扫描"), QStringLiteral("保存结果失败: %1").arg(save_error));
    return;
  }

  PopulatePointerChainTable(scan_model_, chains);
  scan_status_label_->setText(QStringLiteral("完成: index=%1, chains=%2, 文件=%3")
                                  .arg(QString::number(static_cast<qulonglong>(build_result.count)))
                                  .arg(chains.size())
                                  .arg(output_path));
}

void PointerToolsDialog::OnBrowsePointerScanOutput() {
  const QString path = QFileDialog::getSaveFileName(this,
                                                    QStringLiteral("选择输出文件"),
                                                    scan_output_edit_->text().trimmed().isEmpty() ? DefaultPointerScanOutputPath()
                                                                                                  : scan_output_edit_->text().trimmed(),
                                                    QStringLiteral("Pointer Result (*.r3p *.txt);;All Files (*.*)"));
  if (!path.isEmpty()) {
    scan_output_edit_->setText(path);
  }
}

QString PointerToolsDialog::DefaultPointerScanOutputPath() const {
  const QString stamp = QDateTime::currentDateTime().toString(QStringLiteral("yyyyMMdd_HHmmss"));
  QDir dir(QDir::current().filePath(QStringLiteral("seach_point")));
  if (!dir.exists()) {
    QDir().mkpath(dir.absolutePath());
  }
  return dir.filePath(QStringLiteral("scan_%1.r3p").arg(stamp));
}

bool PointerToolsDialog::SavePointerChainFile(const QString& path,
                                              const std::vector<PointerChainRecord>& chains,
                                              int depth,
                                              int64_t max_offset,
                                              uint32_t pointer_size,
                                              uint64_t target,
                                              QString* out_error) const {
  QFile file(path);
  if (!file.open(QIODevice::WriteOnly | QIODevice::Truncate | QIODevice::Text)) {
    if (out_error) {
      *out_error = QStringLiteral("无法写入文件");
    }
    return false;
  }

  QTextStream ts(&file);
  ts.setEncoding(QStringConverter::Utf8);
  ts << "# R3_POINTER_SCAN_V1\n";
  ts << "# created=" << QDateTime::currentDateTime().toString(Qt::ISODate) << "\n";
  ts << "# pid=" << pid_ << "\n";
  ts << "# pointer_size=" << pointer_size << "\n";
  ts << "# depth=" << depth << "\n";
  ts << "# max_offset=" << max_offset << "\n";
  ts << "# target=" << Hex64(target) << "\n";
  for (const auto& chain : chains) {
    ts << Hex64(chain.base) << "|" << JoinOffsets(chain.offsets) << "\n";
  }
  return true;
}

bool PointerToolsDialog::ParseSignedOffset(const QString& text, int64_t* out_value) {
  if (!out_value) {
    return false;
  }
  QString token = text.trimmed();
  if (token.isEmpty()) {
    return false;
  }
  bool negative = false;
  if (token.startsWith(QLatin1Char('+'))) {
    token.remove(0, 1);
  } else if (token.startsWith(QLatin1Char('-'))) {
    negative = true;
    token.remove(0, 1);
  }
  int base = 10;
  if (token.startsWith(QStringLiteral("0x"), Qt::CaseInsensitive)) {
    base = 16;
    token = token.mid(2);
  }
  bool ok = false;
  const qulonglong raw = token.toULongLong(&ok, base);
  if (!ok) {
    return false;
  }
  if (raw > static_cast<qulonglong>((std::numeric_limits<int64_t>::max)())) {
    return false;
  }
  int64_t value = static_cast<int64_t>(raw);
  if (negative) {
    value = -value;
  }
  *out_value = value;
  return true;
}

bool PointerToolsDialog::LoadPointerChainFile(const QString& path,
                                              std::vector<PointerChainRecord>* out_chains,
                                              QString* out_error) const {
  if (!out_chains) {
    if (out_error) {
      *out_error = QStringLiteral("参数无效");
    }
    return false;
  }
  out_chains->clear();

  QFile file(path);
  if (!file.open(QIODevice::ReadOnly | QIODevice::Text)) {
    if (out_error) {
      *out_error = QStringLiteral("无法读取文件");
    }
    return false;
  }

  QTextStream ts(&file);
  ts.setEncoding(QStringConverter::Utf8);
  while (!ts.atEnd()) {
    const QString line = ts.readLine().trimmed();
    if (line.isEmpty() || line.startsWith(QLatin1Char('#'))) {
      continue;
    }
    const int sep = line.indexOf(QLatin1Char('|'));
    if (sep <= 0) {
      continue;
    }

    bool base_ok = false;
    const uint64_t base = ParseAddressText(line.left(sep), &base_ok);
    if (!base_ok || base == 0) {
      continue;
    }

    PointerChainRecord chain;
    chain.base = base;
    const QString offsets_text = line.mid(sep + 1);
    const QStringList tokens = offsets_text.split(QLatin1Char(','), Qt::SkipEmptyParts);
    for (const QString& token : tokens) {
      int64_t offset = 0;
      if (!ParseSignedOffset(token, &offset)) {
        chain.offsets.clear();
        break;
      }
      chain.offsets.push_back(offset);
    }
    if (!chain.offsets.empty()) {
      out_chains->push_back(std::move(chain));
    }
  }

  if (out_chains->empty()) {
    if (out_error) {
      *out_error = QStringLiteral("文件中未找到有效指针链");
    }
    return false;
  }
  return true;
}

QString PointerToolsDialog::DefaultPointerCompareOutputPath(const QString& file_a) const {
  const QString stamp = QDateTime::currentDateTime().toString(QStringLiteral("yyyyMMdd_HHmmss"));
  QFileInfo fi(file_a);
  const QDir dir = fi.exists() ? fi.absoluteDir() : QDir::current();
  return dir.filePath(QStringLiteral("%1_Comparison_results.txt").arg(stamp));
}

void PointerToolsDialog::OnBrowseCompareFileA() {
  const QString path = QFileDialog::getOpenFileName(this,
                                                    QStringLiteral("选择指针结果文件A"),
                                                    QDir::currentPath(),
                                                    QStringLiteral("Pointer Result (*.r3p *.txt);;All Files (*.*)"));
  if (!path.isEmpty()) {
    compare_file_a_edit_->setText(path);
  }
}

void PointerToolsDialog::OnBrowseCompareFileB() {
  const QString path = QFileDialog::getOpenFileName(this,
                                                    QStringLiteral("选择指针结果文件B"),
                                                    QDir::currentPath(),
                                                    QStringLiteral("Pointer Result (*.r3p *.txt);;All Files (*.*)"));
  if (!path.isEmpty()) {
    compare_file_b_edit_->setText(path);
  }
}

void PointerToolsDialog::OnRunPointerCompare() {
  const QString file_a = compare_file_a_edit_->text().trimmed();
  const QString file_b = compare_file_b_edit_->text().trimmed();
  if (file_a.isEmpty() || file_b.isEmpty()) {
    QMessageBox::warning(this, QStringLiteral("指针对比"), QStringLiteral("请先选择两份指针结果文件"));
    return;
  }

  std::vector<PointerChainRecord> chains_a;
  std::vector<PointerChainRecord> chains_b;
  QString load_error;
  if (!LoadPointerChainFile(file_a, &chains_a, &load_error)) {
    QMessageBox::warning(this, QStringLiteral("指针对比"), QStringLiteral("读取文件A失败: %1").arg(load_error));
    return;
  }
  if (!LoadPointerChainFile(file_b, &chains_b, &load_error)) {
    QMessageBox::warning(this, QStringLiteral("指针对比"), QStringLiteral("读取文件B失败: %1").arg(load_error));
    return;
  }

  std::unordered_set<std::string> set_a;
  set_a.reserve(chains_a.size() * 2 + 1);
  for (const auto& chain : chains_a) {
    set_a.insert(ChainKey(chain).toStdString());
  }

  std::vector<PointerChainRecord> common;
  common.reserve((std::min)(chains_a.size(), chains_b.size()));
  std::unordered_set<std::string> seen_common;
  for (const auto& chain : chains_b) {
    const std::string key = ChainKey(chain).toStdString();
    if (set_a.find(key) == set_a.end()) {
      continue;
    }
    if (seen_common.insert(key).second) {
      common.push_back(chain);
    }
  }

  const QString output_path = DefaultPointerCompareOutputPath(file_a);
  QFile out(output_path);
  if (!out.open(QIODevice::WriteOnly | QIODevice::Truncate | QIODevice::Text)) {
    QMessageBox::warning(this, QStringLiteral("指针对比"), QStringLiteral("无法写入对比结果文件"));
    return;
  }
  QTextStream ts(&out);
  ts.setEncoding(QStringConverter::Utf8);
  ts << "# R3_POINTER_COMPARE_V1\n";
  ts << "# created=" << QDateTime::currentDateTime().toString(Qt::ISODate) << "\n";
  ts << "# file_a=" << file_a << "\n";
  ts << "# file_b=" << file_b << "\n";
  ts << "# common_count=" << common.size() << "\n";
  for (const auto& chain : common) {
    ts << Hex64(chain.base) << "|" << JoinOffsets(chain.offsets) << "\n";
  }

  PopulatePointerChainTable(compare_model_, common);
  compare_status_label_->setText(QStringLiteral("完成: A=%1, B=%2, 公共=%3, 文件=%4")
                                     .arg(chains_a.size())
                                     .arg(chains_b.size())
                                     .arg(common.size())
                                     .arg(output_path));
}

void PointerToolsDialog::PopulatePointerChainTable(QStandardItemModel* model,
                                                   const std::vector<PointerChainRecord>& chains) const {
  if (!model) {
    return;
  }
  model->removeRows(0, model->rowCount());
  model->setRowCount(static_cast<int>(chains.size()));
  for (int row = 0; row < static_cast<int>(chains.size()); ++row) {
    const auto& chain = chains[static_cast<size_t>(row)];
    auto* c0 = new QStandardItem(FormatChainDisplay(chain));
    auto* c1 = new QStandardItem(Hex64(chain.base));
    auto* c2 = new QStandardItem(JoinOffsets(chain.offsets));
    c1->setTextAlignment(Qt::AlignRight | Qt::AlignVCenter);
    model->setItem(row, 0, c0);
    model->setItem(row, 1, c1);
    model->setItem(row, 2, c2);
  }
}

uint64_t PointerToolsDialog::ParseAddressText(const QString& text, bool* ok) {
  if (ok) {
    *ok = false;
  }
  QString token = text.trimmed();
  if (token.isEmpty()) {
    return 0;
  }
  if (token.startsWith(QLatin1Char('[')) && token.endsWith(QLatin1Char(']')) && token.size() > 2) {
    token = token.mid(1, token.size() - 2);
  }
  int base = 10;
  if (token.startsWith(QStringLiteral("0x"), Qt::CaseInsensitive)) {
    token = token.mid(2);
    base = 16;
  }
  bool parsed = false;
  const qulonglong value = token.toULongLong(&parsed, base);
  if (ok) {
    *ok = parsed;
  }
  return parsed ? static_cast<uint64_t>(value) : 0;
}

QString PointerToolsDialog::Hex64(uint64_t value) {
  return QStringLiteral("0x%1").arg(QString::number(value, 16).toUpper());
}

QString PointerToolsDialog::FormatOffset(int64_t value) {
  const qulonglong abs_value = static_cast<qulonglong>(value >= 0 ? value : -value);
  const QString hex = QString::number(abs_value, 16).toUpper();
  return value >= 0 ? QStringLiteral("+0x%1").arg(hex) : QStringLiteral("-0x%1").arg(hex);
}

QString PointerToolsDialog::ChainKey(const PointerChainRecord& chain) {
  QString key = Hex64(chain.base).toLower();
  key.push_back(QLatin1Char('|'));
  for (size_t i = 0; i < chain.offsets.size(); ++i) {
    if (i > 0) {
      key.push_back(QLatin1Char(','));
    }
    key.append(QString::number(chain.offsets[i]));
  }
  return key;
}

QString PointerToolsDialog::FormatChainDisplay(const PointerChainRecord& chain) {
  QString text = QStringLiteral("[%1]").arg(Hex64(chain.base));
  for (int64_t off : chain.offsets) {
    text.append(QStringLiteral(" -> %1").arg(FormatOffset(off)));
  }
  return text;
}
bool PointerToolsDialog::EnsureTraverseModulesLoaded() {
  if (!service_ || !service_mutex_ || pid_ == 0) {
    return false;
  }
  if (traverse_modules_pid_ == pid_ && !traverse_modules_.empty()) {
    return true;
  }
  std::vector<r3::windows_client_ng::services::ClientService::ModuleInfo> modules;
  std::string error;
  bool ok = false;
  {
    const std::lock_guard<std::mutex> lock(*service_mutex_);
    ok = service_->FetchModules(pid_, &modules, &error);
  }
  if (!ok) {
    traverse_modules_.clear();
    traverse_modules_pid_ = 0;
    return false;
  }
  traverse_modules_ = std::move(modules);
  traverse_modules_pid_ = pid_;
  return true;
}

bool PointerToolsDialog::ReadBytes(uint64_t address,
                                   uint32_t size,
                                   bool use_pvm,
                                   std::vector<uint8_t>* out_bytes) const {
  if (!out_bytes || !service_ || !service_mutex_ || size == 0) {
    return false;
  }
  out_bytes->clear();
  std::string error;
  bool ok = false;
  {
    const std::lock_guard<std::mutex> lock(*service_mutex_);
    ok = service_->ReadMemory(address, size, use_pvm, out_bytes, &error);
  }
  return ok && out_bytes->size() >= size;
}

bool PointerToolsDialog::IsLikelyPointer(uint64_t value, uint32_t pointer_size) {
  if (!traverse_auto_pointer_check_->isChecked()) {
    return false;
  }
  if (value == 0 || (pointer_size != 4 && pointer_size != 8)) {
    return false;
  }
  if ((value % pointer_size) != 0) {
    return false;
  }
  if (!EnsureTraverseModulesLoaded()) {
    return false;
  }
  bool in_module = false;
  for (const auto& module : traverse_modules_) {
    if (value >= module.start && value < module.end) {
      in_module = true;
      break;
    }
  }
  if (!in_module) {
    return false;
  }
  std::vector<uint8_t> probe;
  return ReadBytes(value, 1, traverse_use_pvm_check_->isChecked(), &probe);
}

void PointerToolsDialog::UpdateTraverseExpandState(QTreeWidgetItem* item, bool can_expand) {
  if (!item || item->data(0, kRoleTraverseDummy).toBool()) {
    return;
  }
  const bool loaded = item->data(0, kRoleTraverseChildrenLoaded).toBool();
  if (can_expand && !loaded) {
    if (item->childCount() == 0) {
      auto* dummy = new QTreeWidgetItem();
      dummy->setData(0, kRoleTraverseDummy, true);
      dummy->setText(2, QStringLiteral("展开后加载"));
      item->addChild(dummy);
    }
    item->setChildIndicatorPolicy(QTreeWidgetItem::ShowIndicator);
    return;
  }

  if (!can_expand && !loaded) {
    while (item->childCount() > 0) {
      delete item->takeChild(0);
    }
    item->setChildIndicatorPolicy(QTreeWidgetItem::DontShowIndicator);
  } else {
    item->setChildIndicatorPolicy(QTreeWidgetItem::ShowIndicator);
  }
}

void PointerToolsDialog::AttachTraverseTypeEditor(QTreeWidgetItem* item) {
  if (!item || !traverse_tree_) {
    return;
  }
  auto* combo = new QComboBox(traverse_tree_);
  combo->addItem(QStringLiteral("Auto"));
  combo->addItem(QStringLiteral("Pointer"));
  combo->addItem(QStringLiteral("1 Byte"));
  combo->addItem(QStringLiteral("2 Bytes"));
  combo->addItem(QStringLiteral("4 Bytes"));
  combo->addItem(QStringLiteral("8 Bytes"));
  combo->addItem(QStringLiteral("4 Bytes(Signed)"));
  combo->addItem(QStringLiteral("8 Bytes(Signed)"));
  combo->addItem(QStringLiteral("Float"));
  combo->addItem(QStringLiteral("Double"));
  traverse_tree_->setItemWidget(item, 1, combo);
  connect(combo, QOverload<int>::of(&QComboBox::currentIndexChanged), this, [this, item](int) {
    if (!item) {
      return;
    }
    item->setData(0, kRoleTraverseChildrenLoaded, false);
    while (item->childCount() > 0) {
      delete item->takeChild(0);
    }
    if (item->isExpanded()) {
      item->setExpanded(false);
    }
    RefreshTraverseRow(item);
  });
}

void PointerToolsDialog::RefreshTraverseRow(QTreeWidgetItem* item) {
  if (!item || item->data(0, kRoleTraverseDummy).toBool()) {
    return;
  }
  const uint64_t address = item->data(0, kRoleTraverseAddress).toULongLong();
  if (address == 0) {
    item->setText(2, QStringLiteral("-"));
    item->setText(3, QStringLiteral(""));
    return;
  }

  const uint32_t pointer_size = static_cast<uint32_t>(traverse_pointer_size_combo_->currentData().toInt());
  const bool use_pvm = traverse_use_pvm_check_->isChecked();
  const bool forced_pointer = item->data(0, kRoleTraverseForcedPointer).toBool();

  QString type_name = QStringLiteral("Auto");
  if (auto* combo = qobject_cast<QComboBox*>(traverse_tree_->itemWidget(item, 1))) {
    type_name = combo->currentText();
  }

  QString value_text = QStringLiteral("<读取失败>");
  bool pointer_candidate = false;
  uint64_t pointer_value = 0;

  auto read_pointer = [&]() -> bool {
    std::vector<uint8_t> bytes;
    if (!ReadBytes(address, pointer_size, use_pvm, &bytes)) {
      return false;
    }
    if (pointer_size == 8) {
      pointer_value = ReadLE<uint64_t>(bytes);
    } else {
      pointer_value = static_cast<uint64_t>(ReadLE<uint32_t>(bytes));
    }
    value_text = Hex64(pointer_value);
    return true;
  };

  if (type_name == QStringLiteral("Pointer")) {
    if (read_pointer()) {
      pointer_candidate = true;
    }
  } else if (type_name == QStringLiteral("Auto")) {
    if (read_pointer()) {
      pointer_candidate = IsLikelyPointer(pointer_value, pointer_size);
      if (!pointer_candidate) {
        std::vector<uint8_t> u32_bytes;
        if (ReadBytes(address, 4, use_pvm, &u32_bytes)) {
          const uint32_t v = ReadLE<uint32_t>(u32_bytes);
          value_text = QStringLiteral("%1 (0x%2)").arg(v).arg(QString::number(v, 16).toUpper());
        }
      }
    }
  } else {
    std::vector<uint8_t> bytes;
    if (type_name == QStringLiteral("1 Byte")) {
      if (ReadBytes(address, 1, use_pvm, &bytes)) {
        value_text = QString::number(ReadLE<uint8_t>(bytes));
      }
    } else if (type_name == QStringLiteral("2 Bytes")) {
      if (ReadBytes(address, 2, use_pvm, &bytes)) {
        value_text = QString::number(ReadLE<uint16_t>(bytes));
      }
    } else if (type_name == QStringLiteral("4 Bytes")) {
      if (ReadBytes(address, 4, use_pvm, &bytes)) {
        value_text = QString::number(ReadLE<uint32_t>(bytes));
      }
    } else if (type_name == QStringLiteral("8 Bytes")) {
      if (ReadBytes(address, 8, use_pvm, &bytes)) {
        value_text = QString::number(static_cast<qulonglong>(ReadLE<uint64_t>(bytes)));
      }
    } else if (type_name == QStringLiteral("4 Bytes(Signed)")) {
      if (ReadBytes(address, 4, use_pvm, &bytes)) {
        value_text = QString::number(ReadLE<int32_t>(bytes));
      }
    } else if (type_name == QStringLiteral("8 Bytes(Signed)")) {
      if (ReadBytes(address, 8, use_pvm, &bytes)) {
        value_text = QString::number(static_cast<qint64>(ReadLE<int64_t>(bytes)));
      }
    } else if (type_name == QStringLiteral("Float")) {
      if (ReadBytes(address, 4, use_pvm, &bytes)) {
        value_text = QString::number(ReadLE<float>(bytes), 'g', 9);
      }
    } else if (type_name == QStringLiteral("Double")) {
      if (ReadBytes(address, 8, use_pvm, &bytes)) {
        value_text = QString::number(ReadLE<double>(bytes), 'g', 17);
      }
    }

    if (traverse_auto_pointer_check_->isChecked()) {
      std::vector<uint8_t> ptr_bytes;
      if (ReadBytes(address, pointer_size, use_pvm, &ptr_bytes)) {
        pointer_value = pointer_size == 8 ? ReadLE<uint64_t>(ptr_bytes) : static_cast<uint64_t>(ReadLE<uint32_t>(ptr_bytes));
        pointer_candidate = IsLikelyPointer(pointer_value, pointer_size);
      }
    }
  }

  if (forced_pointer) {
    if (pointer_value == 0) {
      (void)read_pointer();
    }
    pointer_candidate = true;
  }

  item->setText(2, value_text);
  item->setText(3, pointer_candidate ? QStringLiteral("▶") : QStringLiteral(""));
  item->setData(0, kRoleTraversePointerValue, static_cast<qulonglong>(pointer_value));
  item->setData(0, kRoleTraversePointerCandidate, pointer_candidate);
  UpdateTraverseExpandState(item, pointer_candidate);
}

void PointerToolsDialog::PopulateTraverseRows(QTreeWidgetItem* parent, uint64_t base, int depth) {
  if (!traverse_tree_) {
    return;
  }
  if (depth >= kTraverseMaxDepth) {
    return;
  }
  const int count = traverse_count_spin_->value();
  const int stride = traverse_stride_spin_->value();
  for (int i = 0; i < count; ++i) {
    const uint64_t offset = static_cast<uint64_t>(static_cast<uint64_t>(i) * static_cast<uint64_t>(stride));
    if (base > (std::numeric_limits<uint64_t>::max)() - offset) {
      break;
    }
    const uint64_t address = base + offset;
    auto* item = parent ? new QTreeWidgetItem(parent) : new QTreeWidgetItem(traverse_tree_);
    item->setText(0, Hex64(address));
    item->setData(0, kRoleTraverseAddress, static_cast<qulonglong>(address));
    item->setData(0, kRoleTraverseDepth, depth);
    item->setData(0, kRoleTraverseChildrenLoaded, false);
    item->setData(0, kRoleTraverseForcedPointer, false);
    item->setData(0, kRoleTraversePointerCandidate, false);
    item->setData(0, kRoleTraversePointerValue, static_cast<qulonglong>(0));
    AttachTraverseTypeEditor(item);
    RefreshTraverseRow(item);
  }
}

void PointerToolsDialog::OnRunStructureTraverse() {
  QString ready_error;
  if (!EnsureServiceReady(&ready_error)) {
    QMessageBox::warning(this, QStringLiteral("结构遍历"), ready_error);
    return;
  }
  bool ok = false;
  const uint64_t base = ParseAddressText(traverse_base_edit_->text(), &ok);
  if (!ok || base == 0) {
    QMessageBox::warning(this, QStringLiteral("结构遍历"), QStringLiteral("起始地址无效"));
    return;
  }

  uint32_t pointer_size = 0;
  if (FetchPointerSize(&pointer_size) && (pointer_size == 4 || pointer_size == 8)) {
    const int idx = traverse_pointer_size_combo_->findData(static_cast<int>(pointer_size));
    if (idx >= 0) {
      traverse_pointer_size_combo_->setCurrentIndex(idx);
    }
  }

  traverse_tree_->clear();
  traverse_modules_.clear();
  traverse_modules_pid_ = 0;
  (void)EnsureTraverseModulesLoaded();
  PopulateTraverseRows(nullptr, base, 0);
  traverse_status_label_->setText(QStringLiteral("完成: 基址=%1, 长度=%2, 步长=%3")
                                      .arg(Hex64(base))
                                      .arg(traverse_count_spin_->value())
                                      .arg(traverse_stride_spin_->value()));
}

void PointerToolsDialog::OnTraverseItemExpanded(QTreeWidgetItem* item) {
  if (!item || item->data(0, kRoleTraverseDummy).toBool()) {
    return;
  }
  if (item->data(0, kRoleTraverseChildrenLoaded).toBool()) {
    return;
  }
  const bool pointer_candidate = item->data(0, kRoleTraversePointerCandidate).toBool() ||
                                 item->data(0, kRoleTraverseForcedPointer).toBool();
  if (!pointer_candidate) {
    return;
  }
  const uint64_t next_base = item->data(0, kRoleTraversePointerValue).toULongLong();
  if (next_base == 0) {
    return;
  }
  const int depth = item->data(0, kRoleTraverseDepth).toInt();
  if (depth + 1 >= kTraverseMaxDepth) {
    return;
  }
  while (item->childCount() > 0) {
    delete item->takeChild(0);
  }
  PopulateTraverseRows(item, next_base, depth + 1);
  item->setData(0, kRoleTraverseChildrenLoaded, true);
  UpdateTraverseExpandState(item, true);
}

void PointerToolsDialog::OnTraverseContextMenu(const QPoint& pos) {
  if (!traverse_tree_) {
    return;
  }
  QTreeWidgetItem* item = traverse_tree_->itemAt(pos);
  if (!item || item->data(0, kRoleTraverseDummy).toBool()) {
    return;
  }
  QMenu menu(this);
  const bool forced = item->data(0, kRoleTraverseForcedPointer).toBool();
  QAction* toggle_ptr = menu.addAction(forced ? QStringLiteral("取消指针标记") : QStringLiteral("强制标记为指针"));
  QAction* refresh_item = menu.addAction(QStringLiteral("刷新当前项"));
  QAction* picked = menu.exec(traverse_tree_->viewport()->mapToGlobal(pos));
  if (!picked) {
    return;
  }
  if (picked == toggle_ptr) {
    item->setData(0, kRoleTraverseForcedPointer, !forced);
    item->setData(0, kRoleTraverseChildrenLoaded, false);
    while (item->childCount() > 0) {
      delete item->takeChild(0);
    }
    if (item->isExpanded()) {
      item->setExpanded(false);
    }
    RefreshTraverseRow(item);
    return;
  }
  if (picked == refresh_item) {
    item->setData(0, kRoleTraverseChildrenLoaded, false);
    while (item->childCount() > 0) {
      delete item->takeChild(0);
    }
    if (item->isExpanded()) {
      item->setExpanded(false);
    }
    RefreshTraverseRow(item);
  }
}

}  // namespace r3::windows_client_qt::ui
