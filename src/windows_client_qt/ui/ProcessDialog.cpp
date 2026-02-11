#include "ui/ProcessDialog.h"

#include <algorithm>

#include <QAbstractItemView>
#include <QDialogButtonBox>
#include <QHeaderView>
#include <QIcon>
#include <QKeySequence>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QRegularExpression>
#include <QShortcut>
#include <QStringList>
#include <QStandardItem>
#include <QStandardItemModel>
#include <QTableView>
#include <QTabWidget>
#include <QTimer>
#include <QVBoxLayout>

namespace r3::windows_client_qt::ui {

namespace {
constexpr int kPidRole = Qt::UserRole + 1;
constexpr int kNameRole = Qt::UserRole + 2;
constexpr int kSystemRole = Qt::UserRole + 3;

QString ToQString(const std::string& text) {
  return QString::fromUtf8(text.c_str(), static_cast<int>(text.size()));
}
}  // namespace

ProcessDialog::ProcessFilterProxy::ProcessFilterProxy(QObject* parent) : QSortFilterProxyModel(parent) {
  setFilterCaseSensitivity(Qt::CaseInsensitive);
}

void ProcessDialog::ProcessFilterProxy::SetKeyword(const QString& keyword) {
  keyword_ = keyword.trimmed();
  beginFilterChange();
  endFilterChange(QSortFilterProxyModel::Direction::Rows);
}

void ProcessDialog::ProcessFilterProxy::SetShowSystem(bool show_system) {
  show_system_ = show_system;
  beginFilterChange();
  endFilterChange(QSortFilterProxyModel::Direction::Rows);
}

bool ProcessDialog::ProcessFilterProxy::filterAcceptsRow(int source_row, const QModelIndex& source_parent) const {
  const QModelIndex pid_index = sourceModel()->index(source_row, 1, source_parent);
  const QModelIndex name_index = sourceModel()->index(source_row, 2, source_parent);
  const uint32_t pid = sourceModel()->data(pid_index, kPidRole).toUInt();
  const QString name = sourceModel()->data(name_index, kNameRole).toString();
  const QString pid_text = sourceModel()->data(pid_index, Qt::DisplayRole).toString();

  const QVariant system_value = sourceModel()->data(name_index, kSystemRole);
  const bool is_system = system_value.isValid() ? system_value.toBool() : ProcessDialog::IsSystemProcess(pid, name);
  if (show_system_ != is_system) {
    return false;
  }
  if (keyword_.isEmpty()) {
    return true;
  }
  return name.contains(keyword_, Qt::CaseInsensitive) || pid_text.contains(keyword_, Qt::CaseInsensitive);
}

ProcessDialog::ProcessDialog(QWidget* parent) : QDialog(parent) {
  BuildUi();
  setWindowTitle(QStringLiteral("进程列表"));
  resize(980, 680);
}

void ProcessDialog::BuildUi() {
  auto* root = new QVBoxLayout(this);
  root->setContentsMargins(10, 10, 10, 10);
  root->setSpacing(8);

  tabs_ = new QTabWidget(this);
  tabs_->addTab(new QWidget(this), QStringLiteral("应用程序"));
  tabs_->addTab(new QWidget(this), QStringLiteral("系统进程"));
  tabs_->setDocumentMode(true);
  root->addWidget(tabs_);

  filter_edit_ = new QLineEdit(this);
  filter_edit_->setPlaceholderText(QStringLiteral("过滤进程（Ctrl+F）"));
  root->addWidget(filter_edit_);

  table_ = new QTableView(this);
  table_->setSelectionBehavior(QAbstractItemView::SelectRows);
  table_->setSelectionMode(QAbstractItemView::SingleSelection);
  table_->setAlternatingRowColors(true);
  table_->setEditTriggers(QAbstractItemView::NoEditTriggers);
  table_->verticalHeader()->hide();
  table_->verticalHeader()->setDefaultSectionSize(24);
  table_->verticalHeader()->setSectionResizeMode(QHeaderView::Fixed);
  table_->setIconSize(QSize(16, 16));
  table_->setWordWrap(false);
  table_->horizontalHeader()->setStretchLastSection(true);
  table_->horizontalHeader()->setDefaultAlignment(Qt::AlignLeft | Qt::AlignVCenter);
  root->addWidget(table_, 1);

  status_label_ = new QLabel(this);
  root->addWidget(status_label_);

  auto* button_box = new QDialogButtonBox(this);
  open_button_ = button_box->addButton(QStringLiteral("打开"), QDialogButtonBox::AcceptRole);
  cancel_button_ = button_box->addButton(QStringLiteral("取消"), QDialogButtonBox::RejectRole);
  root->addWidget(button_box);

  source_model_ = new QStandardItemModel(this);
  source_model_->setColumnCount(3);
  source_model_->setHeaderData(0, Qt::Horizontal, QStringLiteral("图标"));
  source_model_->setHeaderData(1, Qt::Horizontal, QStringLiteral("PID"));
  source_model_->setHeaderData(2, Qt::Horizontal, QStringLiteral("进程名"));

  proxy_model_ = new ProcessFilterProxy(this);
  proxy_model_->setSourceModel(source_model_);
  table_->setModel(proxy_model_);
  append_timer_ = new QTimer(this);
  append_timer_->setInterval(0);
  append_timer_->setSingleShot(false);
  connect(append_timer_, &QTimer::timeout, this, &ProcessDialog::AppendProcessRowsChunk);

  table_->setColumnWidth(0, 48);
  table_->setColumnWidth(1, 110);

  connect(tabs_, &QTabWidget::currentChanged, this, &ProcessDialog::OnTabChanged);
  connect(filter_edit_, &QLineEdit::textChanged, this, &ProcessDialog::OnFilterChanged);
  connect(open_button_, &QPushButton::clicked, this, &ProcessDialog::OnOpenClicked);
  connect(cancel_button_, &QPushButton::clicked, this, &ProcessDialog::reject);
  connect(table_, &QTableView::doubleClicked, this, &ProcessDialog::OnOpenClicked);

  auto* shortcut = new QShortcut(QKeySequence(QStringLiteral("Ctrl+F")), this);
  connect(shortcut, &QShortcut::activated, filter_edit_, qOverload<>(&QLineEdit::setFocus));

  SetLoading(false);
  OnTabChanged(0);
}

void ProcessDialog::SetProcesses(const std::vector<r3::windows_client_ng::services::ProcessInfo>& processes) {
  if (append_timer_) {
    append_timer_->stop();
  }
  pending_processes_ = processes;
  pending_row_index_ = 0;

  source_model_->blockSignals(false);
  source_model_->removeRows(0, source_model_->rowCount());
  AppendProcessRowsChunk();
  if (append_timer_ && pending_row_index_ < static_cast<int>(pending_processes_.size())) {
    append_timer_->start();
  } else {
    OnFilterChanged(filter_edit_->text());
    UpdateStatusText();
  }
}

void ProcessDialog::AppendProcessRowsChunk() {
  if (!source_model_) {
    return;
  }
  const int total = static_cast<int>(pending_processes_.size());
  if (pending_row_index_ >= total) {
    if (append_timer_) {
      append_timer_->stop();
    }
    OnFilterChanged(filter_edit_ ? filter_edit_->text() : QString());
    UpdateStatusText();
    return;
  }

  constexpr int kChunkRows = 160;
  const int start = pending_row_index_;
  const int end = std::min(total, start + kChunkRows);

  source_model_->insertRows(start, end - start);
  for (int row = start; row < end; ++row) {
    const auto& proc = pending_processes_[static_cast<size_t>(row)];

    auto* icon_item = new QStandardItem();
    icon_item->setData(proc.pid, kPidRole);
    icon_item->setEditable(false);

    auto* pid_item = new QStandardItem(QString::number(proc.pid));
    pid_item->setTextAlignment(Qt::AlignRight | Qt::AlignVCenter);
    pid_item->setData(proc.pid, kPidRole);
    pid_item->setEditable(false);

    const QString name = ToQString(proc.name);
    const bool is_system = proc.system_hint_valid ? proc.is_system : IsSystemProcess(proc.pid, name);
    auto* name_item = new QStandardItem(name);
    name_item->setData(name, kNameRole);
    name_item->setData(proc.pid, kPidRole);
    name_item->setData(is_system, kSystemRole);
    name_item->setEditable(false);
    icon_item->setData(is_system, kSystemRole);
    pid_item->setData(is_system, kSystemRole);

    source_model_->setItem(row, 0, icon_item);
    source_model_->setItem(row, 1, pid_item);
    source_model_->setItem(row, 2, name_item);
  }

  pending_row_index_ = end;
  if (pending_row_index_ >= total) {
    if (append_timer_) {
      append_timer_->stop();
    }
    OnFilterChanged(filter_edit_ ? filter_edit_->text() : QString());
    UpdateStatusText();
  }
}

void ProcessDialog::SetBusyText(const QString& text) {
  if (status_label_) {
    status_label_->setText(text);
  }
}

bool ProcessDialog::IsLoading() const { return loading_; }

void ProcessDialog::SetLoading(bool loading) {
  loading_ = loading;
  if (table_) {
    table_->setEnabled(!loading);
  }
  if (open_button_) {
    open_button_->setEnabled(!loading);
  }
  if (filter_edit_) {
    filter_edit_->setEnabled(!loading);
  }
  if (loading) {
    SetBusyText(QStringLiteral("正在获取进程列表..."));
  } else {
    UpdateStatusText();
  }
}

void ProcessDialog::UpdateIcon(uint32_t pid, const QIcon& icon) {
  for (int row = 0; row < source_model_->rowCount(); ++row) {
    auto* item = source_model_->item(row, 0);
    if (!item) {
      continue;
    }
    if (item->data(kPidRole).toUInt() == pid) {
      item->setIcon(icon);
      return;
    }
  }
}

std::optional<ProcessDialog::ProcessSelection> ProcessDialog::SelectedProcess() const {
  const QModelIndex proxy_index = table_->currentIndex();
  if (!proxy_index.isValid()) {
    return std::nullopt;
  }
  const QModelIndex proxy_row_index = proxy_model_->index(proxy_index.row(), 2);
  const QModelIndex source_row_index = proxy_model_->mapToSource(proxy_row_index);
  if (!source_row_index.isValid()) {
    return std::nullopt;
  }
  const QModelIndex pid_index = source_model_->index(source_row_index.row(), 1);
  const QModelIndex name_index = source_model_->index(source_row_index.row(), 2);

  ProcessSelection result;
  result.pid = source_model_->data(pid_index, kPidRole).toUInt();
  result.name = source_model_->data(name_index, kNameRole).toString();
  if (result.pid == 0) {
    return std::nullopt;
  }
  return result;
}

bool ProcessDialog::IsSystemProcess(uint32_t pid, const QString& name) {
  const QString n = name.trimmed().toLower();
  if (n.isEmpty()) {
    return true;
  }
  if (n.startsWith('[') || n.contains('/')) {
    return true;
  }
  static const QRegularExpression kPackageNameRegex(
      QStringLiteral(R"(^[a-z][a-z0-9_]*(\.[a-z0-9_]+)+(:[a-z0-9_]+)?$)"));
  const bool looks_package = kPackageNameRegex.match(n).hasMatch();

  if (n.startsWith(QStringLiteral("com.android.")) ||
      n.startsWith(QStringLiteral("com.google.android.")) ||
      n == QStringLiteral("android") ||
      n.startsWith(QStringLiteral("android.")) ||
      n.startsWith(QStringLiteral("androidx.")) ||
      n.startsWith(QStringLiteral("vendor."))) {
    return true;
  }
  if (looks_package) {
    return false;
  }
  if (n.contains('.')) {
    return false;
  }

  static const QStringList kSystemPrefixes = {
      QStringLiteral("init"),
      QStringLiteral("ueventd"),
      QStringLiteral("logd"),
      QStringLiteral("lmkd"),
      QStringLiteral("servicemanager"),
      QStringLiteral("hwservicemanager"),
      QStringLiteral("vndservicemanager"),
      QStringLiteral("adbd"),
      QStringLiteral("zygote"),
      QStringLiteral("zygote64"),
      QStringLiteral("system_server"),
      QStringLiteral("surfaceflinger"),
      QStringLiteral("audioserver"),
      QStringLiteral("mediaserver"),
      QStringLiteral("cameraserver"),
      QStringLiteral("vold"),
      QStringLiteral("netd"),
      QStringLiteral("wificond"),
      QStringLiteral("statsd"),
      QStringLiteral("keystore"),
      QStringLiteral("installd"),
      QStringLiteral("thermal-engine"),
      QStringLiteral("android.hardware"),
      QStringLiteral("vendor."),
  };
  for (const QString& prefix : kSystemPrefixes) {
    if (n == prefix || n.startsWith(prefix)) {
      return true;
    }
  }

  // Android app uid usually starts from 10000.
  if (pid >= 10000u) {
    return false;
  }
  return true;
}

void ProcessDialog::OnTabChanged(int index) {
  proxy_model_->SetShowSystem(index == 1);
  UpdateStatusText();
}

void ProcessDialog::OnFilterChanged(const QString& text) {
  proxy_model_->SetKeyword(text);
  UpdateStatusText();
}

void ProcessDialog::OnOpenClicked() {
  if (loading_) {
    return;
  }
  if (!SelectedProcess().has_value()) {
    return;
  }
  accept();
}

void ProcessDialog::UpdateStatusText() {
  if (loading_) {
    return;
  }
  const int visible = proxy_model_ ? proxy_model_->rowCount() : 0;
  const int total = source_model_ ? source_model_->rowCount() : 0;
  SetBusyText(QStringLiteral("已筛选: %1 / %2").arg(visible).arg(total));
}

}  // namespace r3::windows_client_qt::ui
