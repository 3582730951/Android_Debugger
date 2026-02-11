#include "ui/ModuleRangeDialog.h"

#include <QAbstractItemView>
#include <QDialogButtonBox>
#include <QHeaderView>
#include <QLabel>
#include <QLineEdit>
#include <QStandardItem>
#include <QStandardItemModel>
#include <QTableView>
#include <QVBoxLayout>

namespace r3::windows_client_qt::ui {

namespace {
constexpr int kStartRole = Qt::UserRole + 20;
constexpr int kEndRole = Qt::UserRole + 21;
constexpr int kPathRole = Qt::UserRole + 22;

QString PermsText(uint32_t perms) {
  QString text;
  text += (perms & protocol::MODULE_PERM_READ) ? QLatin1Char('r') : QLatin1Char('-');
  text += (perms & protocol::MODULE_PERM_WRITE) ? QLatin1Char('w') : QLatin1Char('-');
  text += (perms & protocol::MODULE_PERM_EXEC) ? QLatin1Char('x') : QLatin1Char('-');
  text += (perms & protocol::MODULE_PERM_PRIVATE) ? QLatin1Char('p') : QLatin1Char('-');
  text += (perms & protocol::MODULE_PERM_SHARED) ? QLatin1Char('s') : QLatin1Char('-');
  return text;
}

QString Hex64(uint64_t value) {
  return QStringLiteral("0x%1").arg(QString::number(value, 16).toUpper());
}

QString NormalizeModuleText(const QString& text) {
  QString out = text;
  while (!out.isEmpty() && out.front().isSpace()) {
    out.remove(0, 1);
  }
  return out.trimmed();
}
}  // namespace

ModuleRangeDialog::ModuleFilterProxy::ModuleFilterProxy(QObject* parent) : QSortFilterProxyModel(parent) {}

void ModuleRangeDialog::ModuleFilterProxy::SetKeyword(const QString& keyword) {
  keyword_ = keyword.trimmed();
  beginFilterChange();
  endFilterChange(QSortFilterProxyModel::Direction::Rows);
}

bool ModuleRangeDialog::ModuleFilterProxy::filterAcceptsRow(int source_row, const QModelIndex& source_parent) const {
  if (keyword_.isEmpty()) {
    return true;
  }
  for (int col = 0; col < sourceModel()->columnCount(); ++col) {
    const QModelIndex idx = sourceModel()->index(source_row, col, source_parent);
    if (sourceModel()->data(idx, Qt::DisplayRole).toString().contains(keyword_, Qt::CaseInsensitive)) {
      return true;
    }
  }
  return false;
}

ModuleRangeDialog::ModuleRangeDialog(QWidget* parent) : QDialog(parent) {
  BuildUi();
  setWindowTitle(QStringLiteral("选择模块范围"));
  resize(980, 620);
}

void ModuleRangeDialog::BuildUi() {
  auto* root = new QVBoxLayout(this);
  root->setContentsMargins(10, 10, 10, 10);
  root->setSpacing(8);

  filter_edit_ = new QLineEdit(this);
  filter_edit_->setPlaceholderText(QStringLiteral("筛选模块名或地址"));
  root->addWidget(filter_edit_);

  table_ = new QTableView(this);
  table_->setSelectionBehavior(QAbstractItemView::SelectRows);
  table_->setSelectionMode(QAbstractItemView::SingleSelection);
  table_->setAlternatingRowColors(true);
  table_->setEditTriggers(QAbstractItemView::NoEditTriggers);
  table_->verticalHeader()->hide();
  table_->verticalHeader()->setDefaultSectionSize(24);
  table_->verticalHeader()->setSectionResizeMode(QHeaderView::Fixed);
  table_->setWordWrap(false);
  table_->horizontalHeader()->setStretchLastSection(true);
  table_->horizontalHeader()->setDefaultAlignment(Qt::AlignLeft | Qt::AlignVCenter);
  root->addWidget(table_, 1);

  footer_label_ = new QLabel(this);
  root->addWidget(footer_label_);

  auto* buttons = new QDialogButtonBox(this);
  buttons->addButton(QStringLiteral("应用范围"), QDialogButtonBox::AcceptRole);
  buttons->addButton(QStringLiteral("取消"), QDialogButtonBox::RejectRole);
  root->addWidget(buttons);

  source_model_ = new QStandardItemModel(this);
  source_model_->setColumnCount(5);
  source_model_->setHeaderData(0, Qt::Horizontal, QStringLiteral("模块名"));
  source_model_->setHeaderData(1, Qt::Horizontal, QStringLiteral("权限"));
  source_model_->setHeaderData(2, Qt::Horizontal, QStringLiteral("起始"));
  source_model_->setHeaderData(3, Qt::Horizontal, QStringLiteral("结束"));
  source_model_->setHeaderData(4, Qt::Horizontal, QStringLiteral("路径"));

  proxy_model_ = new ModuleFilterProxy(this);
  proxy_model_->setSourceModel(source_model_);
  table_->setModel(proxy_model_);
  table_->setColumnWidth(0, 220);
  table_->setColumnWidth(1, 100);
  table_->setColumnWidth(2, 180);
  table_->setColumnWidth(3, 180);

  connect(filter_edit_, &QLineEdit::textChanged, this, &ModuleRangeDialog::OnFilterTextChanged);
  connect(buttons, &QDialogButtonBox::accepted, this, &ModuleRangeDialog::OnApplyClicked);
  connect(buttons, &QDialogButtonBox::rejected, this, &ModuleRangeDialog::reject);
  connect(table_, &QTableView::doubleClicked, this, &ModuleRangeDialog::OnApplyClicked);
}

void ModuleRangeDialog::SetModules(const std::vector<r3::windows_client_ng::services::ClientService::ModuleInfo>& modules) {
  table_->setUpdatesEnabled(false);
  source_model_->blockSignals(true);
  source_model_->removeRows(0, source_model_->rowCount());
  source_model_->setRowCount(static_cast<int>(modules.size()));

  for (int row = 0; row < static_cast<int>(modules.size()); ++row) {
    const auto& mod = modules[static_cast<size_t>(row)];
    const QString full_path = NormalizeModuleText(QString::fromUtf8(mod.path.c_str(), static_cast<int>(mod.path.size())));
    const QString module_name = full_path.section('/', -1, -1).section('\\', -1, -1);

    auto* name_item = new QStandardItem(module_name.isEmpty() ? full_path : module_name);
    name_item->setData(static_cast<qulonglong>(mod.start), kStartRole);
    name_item->setData(static_cast<qulonglong>(mod.end), kEndRole);
    name_item->setData(full_path, kPathRole);

    auto* perms_item = new QStandardItem(PermsText(mod.perms));
    auto* start_item = new QStandardItem(Hex64(mod.start));
    auto* end_item = new QStandardItem(Hex64(mod.end));
    auto* path_item = new QStandardItem(full_path);

    const Qt::Alignment align = Qt::AlignLeft | Qt::AlignVCenter;
    name_item->setTextAlignment(align);
    perms_item->setTextAlignment(align);
    start_item->setTextAlignment(align);
    end_item->setTextAlignment(align);
    path_item->setTextAlignment(align);

    source_model_->setItem(row, 0, name_item);
    source_model_->setItem(row, 1, perms_item);
    source_model_->setItem(row, 2, start_item);
    source_model_->setItem(row, 3, end_item);
    source_model_->setItem(row, 4, path_item);
  }
  source_model_->blockSignals(false);
  table_->setUpdatesEnabled(true);

  footer_label_->setText(QStringLiteral("可选模块: %1 / %1").arg(modules.size()));
}

void ModuleRangeDialog::SetFooterText(const QString& text) {
  if (!footer_label_) {
    return;
  }
  footer_label_->setText(text);
}

std::optional<ModuleRangeDialog::RangeResult> ModuleRangeDialog::SelectedRange() const {
  const QModelIndex proxy = table_->currentIndex();
  if (!proxy.isValid()) {
    return std::nullopt;
  }
  const QModelIndex source = proxy_model_->mapToSource(proxy.sibling(proxy.row(), 0));
  if (!source.isValid()) {
    return std::nullopt;
  }
  RangeResult result;
  const auto start = source_model_->data(source, kStartRole).toULongLong();
  const auto end = source_model_->data(source, kEndRole).toULongLong();
  if (start == 0 || end == 0 || end <= start) {
    return std::nullopt;
  }
  result.start = start;
  result.end = end;
  result.path = source_model_->data(source, kPathRole).toString();
  return result;
}

void ModuleRangeDialog::OnFilterTextChanged(const QString& text) {
  proxy_model_->SetKeyword(text);
  footer_label_->setText(QStringLiteral("可选模块: %1 / %2")
                             .arg(proxy_model_->rowCount())
                             .arg(source_model_->rowCount()));
}

void ModuleRangeDialog::OnApplyClicked() {
  if (!SelectedRange().has_value()) {
    return;
  }
  accept();
}

}  // namespace r3::windows_client_qt::ui
