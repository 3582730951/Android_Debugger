#include "ui/PluginProviderWindow.h"

#include <algorithm>
#include <cstdint>

#include <QByteArray>
#include <QCheckBox>
#include <QComboBox>
#include <QDesktopServices>
#include <QDialogButtonBox>
#include <QDir>
#include <QFormLayout>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QMap>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QRegularExpression>
#include <QSpinBox>
#include <QStringList>
#include <QUrl>
#include <QVBoxLayout>

namespace r3::windows_client_qt::ui {

namespace {

template <typename T>
void AppendLe(std::vector<uint8_t>* out, T value) {
  const uint8_t* p = reinterpret_cast<const uint8_t*>(&value);
  out->insert(out->end(), p, p + sizeof(T));
}

QByteArray HexBytes(const std::vector<uint8_t>& data) {
  QByteArray out;
  for (size_t i = 0; i < data.size(); ++i) {
    if (i > 0) {
      out.append(' ');
    }
    out.append(QByteArray::number(data[i], 16).rightJustified(2, '0').toUpper());
  }
  return out;
}

bool ParseUnsigned64(const QString& text, qulonglong* out) {
  if (!out) {
    return false;
  }
  QString t = text.trimmed();
  if (t.isEmpty()) {
    return false;
  }
  int base = 10;
  if (t.startsWith(QStringLiteral("0x"), Qt::CaseInsensitive)) {
    t = t.mid(2);
    base = 16;
  }
  bool ok = false;
  const qulonglong v = t.toULongLong(&ok, base);
  if (!ok) {
    return false;
  }
  *out = v;
  return true;
}

bool ParseSigned64(const QString& text, qlonglong* out) {
  if (!out) {
    return false;
  }
  QString t = text.trimmed();
  if (t.isEmpty()) {
    return false;
  }
  int base = 10;
  bool neg = false;
  if (t.startsWith('-')) {
    neg = true;
    t = t.mid(1);
  }
  if (t.startsWith(QStringLiteral("0x"), Qt::CaseInsensitive)) {
    t = t.mid(2);
    base = 16;
  }
  bool ok = false;
  qulonglong mag = t.toULongLong(&ok, base);
  if (!ok) {
    return false;
  }
  qlonglong value = neg ? -static_cast<qlonglong>(mag) : static_cast<qlonglong>(mag);
  *out = value;
  return true;
}

QMap<QString, QString> ParseKeyValueText(const QString& text) {
  QMap<QString, QString> map;
  const QStringList lines = text.split('\n');
  for (QString line : lines) {
    line = line.trimmed();
    if (line.isEmpty() || line.startsWith('#') || line.startsWith("//")) {
      continue;
    }
    const int eq = line.indexOf('=');
    if (eq <= 0) {
      continue;
    }
    const QString key = line.left(eq).trimmed();
    const QString value = line.mid(eq + 1).trimmed();
    if (!key.isEmpty()) {
      map.insert(key, value);
    }
  }
  return map;
}

}  // namespace

PluginProviderWindow::PluginProviderWindow(QWidget* parent) : QDialog(parent) {
  BuildUi();
  setWindowTitle(QStringLiteral("插件与自定义syscall"));
  resize(860, 700);
}

void PluginProviderWindow::BuildUi() {
  auto* root = new QVBoxLayout(this);
  root->setContentsMargins(12, 12, 12, 12);
  root->setSpacing(10);

  workflow_label_ = new QLabel(
      QStringLiteral("流程建议: 1) 打开插件开发中心学习IDA/C风格并开发插件 -> "
                     "2) 使用 tools/plugin_compile_pack.ps1 编译+打包 -> "
                     "3) 回到本窗口扫描插件并启用"),
      this);
  workflow_label_->setWordWrap(true);
  root->addWidget(workflow_label_);

  auto* dev_entry_row = new QWidget(this);
  auto* dev_entry_layout = new QHBoxLayout(dev_entry_row);
  dev_entry_layout->setContentsMargins(0, 0, 0, 0);
  dev_entry_layout->setSpacing(6);
  open_plugin_root_button_ = new QPushButton(QStringLiteral("打开插件目录"), this);
  dev_entry_layout->addWidget(open_plugin_root_button_);
  dev_entry_layout->addStretch(1);
  open_plugin_dev_button_ = new QPushButton(QStringLiteral("去插件开发中心"), this);
  dev_entry_layout->addWidget(open_plugin_dev_button_);
  root->addWidget(dev_entry_row);

  auto* plugin_group = new QGroupBox(QStringLiteral("插件与自定义syscall"), this);
  auto* plugin_form = new QFormLayout(plugin_group);
  plugin_form->setContentsMargins(10, 10, 10, 10);
  plugin_form->setSpacing(8);

  plugin_root_edit_ = new QLineEdit(this);
  plugin_scan_button_ = new QPushButton(QStringLiteral("扫描插件"), this);
  auto* plugin_root_row = new QWidget(this);
  auto* plugin_root_layout = new QHBoxLayout(plugin_root_row);
  plugin_root_layout->setContentsMargins(0, 0, 0, 0);
  plugin_root_layout->setSpacing(6);
  plugin_root_layout->addWidget(plugin_root_edit_, 1);
  plugin_root_layout->addWidget(plugin_scan_button_);
  plugin_combo_ = new QComboBox(this);
  plugin_enable_check_ = new QCheckBox(QStringLiteral("启用插件内存Provider"), this);
  plugin_fallback_check_ = new QCheckBox(QStringLiteral("失败自动回退到内置读写链路"), this);
  plugin_timeout_spin_ = new QSpinBox(this);
  plugin_timeout_spin_->setRange(1, 60000);
  plugin_timeout_spin_->setSuffix(QStringLiteral(" ms"));
  plugin_timeout_spin_->setSingleStep(100);
  plugin_syscall_read_spin_ = new QSpinBox(this);
  plugin_syscall_read_spin_->setRange(-1, 1000000);
  plugin_syscall_write_spin_ = new QSpinBox(this);
  plugin_syscall_write_spin_->setRange(-1, 1000000);
  plugin_user_ctx_edit_ = new QLineEdit(this);
  plugin_user_ctx_edit_->setPlaceholderText(QStringLiteral("示例: 01 00 00 00 2A 00 00 00"));
  plugin_desc_label_ = new QLabel(QStringLiteral("-"), this);
  plugin_desc_label_->setWordWrap(true);
  plugin_generate_ctx_button_ = new QPushButton(QStringLiteral("根据Quickstart生成UserCtx"), this);
  plugin_quickstart_input_ = new QPlainTextEdit(this);
  plugin_quickstart_input_->setPlaceholderText(QStringLiteral("格式: key=value，每行一个"));
  plugin_quickstart_input_->setFixedHeight(90);
  plugin_quickstart_view_ = new QPlainTextEdit(this);
  plugin_quickstart_view_->setReadOnly(true);
  plugin_quickstart_view_->setMaximumBlockCount(200);
  plugin_quickstart_view_->setPlaceholderText(
      QStringLiteral("quickstart 字段说明会显示在这里，帮助测试同学快速配置。"));
  plugin_quickstart_view_->setFixedHeight(130);

  plugin_form->addRow(QStringLiteral("插件根目录"), plugin_root_row);
  plugin_form->addRow(QStringLiteral("可用插件"), plugin_combo_);
  plugin_form->addRow(QString(), plugin_enable_check_);
  plugin_form->addRow(QString(), plugin_fallback_check_);
  plugin_form->addRow(QStringLiteral("超时"), plugin_timeout_spin_);
  plugin_form->addRow(QStringLiteral("读 syscall"), plugin_syscall_read_spin_);
  plugin_form->addRow(QStringLiteral("写 syscall"), plugin_syscall_write_spin_);
  plugin_form->addRow(QStringLiteral("UserCtx(hex)"), plugin_user_ctx_edit_);
  plugin_form->addRow(QStringLiteral("插件说明"), plugin_desc_label_);
  plugin_form->addRow(QStringLiteral("Quickstart"), plugin_quickstart_view_);
  plugin_form->addRow(QStringLiteral("Quickstart输入"), plugin_quickstart_input_);
  plugin_form->addRow(QString(), plugin_generate_ctx_button_);
  root->addWidget(plugin_group, 1);

  auto* buttons = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, this);
  connect(buttons, &QDialogButtonBox::accepted, this, &PluginProviderWindow::accept);
  connect(buttons, &QDialogButtonBox::rejected, this, &PluginProviderWindow::reject);
  root->addWidget(buttons);

  connect(plugin_combo_,
          static_cast<void (QComboBox::*)(int)>(&QComboBox::currentIndexChanged),
          this,
          &PluginProviderWindow::OnPluginSelectionChanged);
  connect(plugin_generate_ctx_button_,
          &QPushButton::clicked,
          this,
          &PluginProviderWindow::OnGenerateUserCtxFromQuickstart);
  connect(plugin_scan_button_, &QPushButton::clicked, this, &PluginProviderWindow::OnScanPluginsClicked);
  connect(open_plugin_root_button_, &QPushButton::clicked, this, &PluginProviderWindow::OnOpenPluginRootClicked);
  connect(open_plugin_dev_button_, &QPushButton::clicked, this, [this]() {
    emit OpenPluginDevWindowRequested();
    reject();
  });
}

void PluginProviderWindow::SetPluginEntries(
    const std::vector<r3::windows_client_qt::plugins::PluginManifest>& plugins) {
  plugin_entries_ = plugins;
  plugin_combo_->blockSignals(true);
  plugin_combo_->clear();
  plugin_combo_->addItem(QStringLiteral("(不使用插件)"), QString());
  for (const auto& p : plugin_entries_) {
    plugin_combo_->addItem(QStringLiteral("%1 (%2)").arg(p.name, p.id), p.id);
  }
  plugin_combo_->blockSignals(false);
  OnPluginSelectionChanged(plugin_combo_->currentIndex());
}

void PluginProviderWindow::SetData(const ProviderSettings& data) {
  plugin_root_edit_->setText(data.plugin_root_path);
  plugin_enable_check_->setChecked(data.plugin_enabled);
  plugin_fallback_check_->setChecked(data.plugin_allow_fallback);
  plugin_timeout_spin_->setValue((std::max)(1, data.plugin_timeout_ms));
  plugin_syscall_read_spin_->setValue(data.plugin_syscall_read);
  plugin_syscall_write_spin_->setValue(data.plugin_syscall_write);
  plugin_user_ctx_edit_->setText(data.plugin_user_ctx_hex);

  if (!data.plugin_id.isEmpty()) {
    const int idx = plugin_combo_->findData(data.plugin_id);
    if (idx >= 0) {
      plugin_combo_->setCurrentIndex(idx);
    }
  }
  OnPluginSelectionChanged(plugin_combo_->currentIndex());
}

PluginProviderWindow::ProviderSettings PluginProviderWindow::Data() const {
  ProviderSettings data;
  data.plugin_root_path = plugin_root_edit_->text().trimmed();
  data.plugin_id = plugin_combo_->currentData().toString().trimmed();
  data.plugin_enabled = plugin_enable_check_->isChecked();
  data.plugin_allow_fallback = plugin_fallback_check_->isChecked();
  data.plugin_timeout_ms = plugin_timeout_spin_->value();
  data.plugin_syscall_read = plugin_syscall_read_spin_->value();
  data.plugin_syscall_write = plugin_syscall_write_spin_->value();
  data.plugin_user_ctx_hex = plugin_user_ctx_edit_->text().trimmed();
  return data;
}

void PluginProviderWindow::OnPluginSelectionChanged(int index) {
  if (index <= 0 || index - 1 >= static_cast<int>(plugin_entries_.size())) {
    plugin_desc_label_->setText(QStringLiteral("-"));
    plugin_quickstart_view_->setPlainText(QString());
    plugin_quickstart_input_->setPlainText(QString());
    return;
  }

  const auto& p = plugin_entries_[static_cast<size_t>(index - 1)];
  const QString desc = p.description.trimmed().isEmpty() ? QStringLiteral("(无描述)") : p.description.trimmed();
  plugin_desc_label_->setText(QStringLiteral("%1  v%2").arg(desc, p.version));
  if (p.syscall_read >= 0) {
    plugin_syscall_read_spin_->setValue(p.syscall_read);
  }
  if (p.syscall_write >= 0) {
    plugin_syscall_write_spin_->setValue(p.syscall_write);
  }
  if (p.timeout_ms > 0) {
    plugin_timeout_spin_->setValue(p.timeout_ms);
  }
  if (plugin_user_ctx_edit_->text().trimmed().isEmpty() && !p.default_user_ctx_hex.trimmed().isEmpty()) {
    plugin_user_ctx_edit_->setText(p.default_user_ctx_hex.trimmed());
  }

  QStringList lines;
  lines << QStringLiteral("ID: %1").arg(p.id);
  lines << QStringLiteral("能力: %1").arg(p.capabilities.join(QStringLiteral(", ")));
  if (!p.quickstart_fields.empty()) {
    lines << QStringLiteral("");
    lines << QStringLiteral("推荐配置字段:");
    QStringList input_template;
    for (const auto& f : p.quickstart_fields) {
      QString line = QStringLiteral("- %1 (%2)").arg(f.label, f.type);
      if (!f.default_value.trimmed().isEmpty()) {
        line.append(QStringLiteral(" 默认=%1").arg(f.default_value));
      }
      if (!f.description.trimmed().isEmpty()) {
        line.append(QStringLiteral("  %1").arg(f.description.trimmed()));
      }
      lines << line;
      input_template << QStringLiteral("%1=%2").arg(f.id, f.default_value);
    }
    plugin_quickstart_input_->setPlainText(input_template.join('\n'));
  } else {
    lines << QStringLiteral("未提供 quickstart 字段定义。");
    plugin_quickstart_input_->setPlainText(QString());
  }
  plugin_quickstart_view_->setPlainText(lines.join('\n'));
}

void PluginProviderWindow::OnGenerateUserCtxFromQuickstart() {
  const int index = plugin_combo_->currentIndex();
  if (index <= 0 || index - 1 >= static_cast<int>(plugin_entries_.size())) {
    return;
  }
  const auto& p = plugin_entries_[static_cast<size_t>(index - 1)];
  if (p.quickstart_fields.empty()) {
    return;
  }

  const QMap<QString, QString> values = ParseKeyValueText(plugin_quickstart_input_->toPlainText());
  std::vector<uint8_t> out;
  out.reserve(128);
  for (const auto& field : p.quickstart_fields) {
    const QString raw = values.value(field.id, field.default_value).trimmed();
    const QString t = field.type.trimmed().toLower();
    if (t == QStringLiteral("u8")) {
      qulonglong v = 0;
      if (!ParseUnsigned64(raw, &v)) {
        continue;
      }
      out.push_back(static_cast<uint8_t>(v & 0xFFu));
      continue;
    }
    if (t == QStringLiteral("u16")) {
      qulonglong v = 0;
      if (!ParseUnsigned64(raw, &v)) {
        continue;
      }
      AppendLe<uint16_t>(&out, static_cast<uint16_t>(v & 0xFFFFu));
      continue;
    }
    if (t == QStringLiteral("u32")) {
      qulonglong v = 0;
      if (!ParseUnsigned64(raw, &v)) {
        continue;
      }
      AppendLe<uint32_t>(&out, static_cast<uint32_t>(v & 0xFFFFFFFFu));
      continue;
    }
    if (t == QStringLiteral("u64")) {
      qulonglong v = 0;
      if (!ParseUnsigned64(raw, &v)) {
        continue;
      }
      AppendLe<uint64_t>(&out, static_cast<uint64_t>(v));
      continue;
    }
    if (t == QStringLiteral("s32")) {
      qlonglong v = 0;
      if (!ParseSigned64(raw, &v)) {
        continue;
      }
      AppendLe<int32_t>(&out, static_cast<int32_t>(v));
      continue;
    }
    if (t == QStringLiteral("s64")) {
      qlonglong v = 0;
      if (!ParseSigned64(raw, &v)) {
        continue;
      }
      AppendLe<int64_t>(&out, static_cast<int64_t>(v));
      continue;
    }
    if (t == QStringLiteral("string")) {
      const QByteArray bytes = raw.toUtf8();
      out.insert(out.end(), bytes.begin(), bytes.end());
      out.push_back(0);
      continue;
    }
    if (t == QStringLiteral("hexbytes")) {
      const QStringList parts = raw.split(QRegularExpression("\\s+"), Qt::SkipEmptyParts);
      for (QString part : parts) {
        part = part.trimmed();
        if (part.startsWith(QStringLiteral("0x"), Qt::CaseInsensitive)) {
          part = part.mid(2);
        }
        bool ok = false;
        int value = part.toInt(&ok, 16);
        if (ok && value >= 0 && value <= 255) {
          out.push_back(static_cast<uint8_t>(value));
        }
      }
      continue;
    }
  }
  plugin_user_ctx_edit_->setText(QString::fromLatin1(HexBytes(out)));
}

void PluginProviderWindow::OnScanPluginsClicked() {
  const QString root = plugin_root_edit_->text().trimmed();
  r3::windows_client_qt::plugins::PluginCatalog catalog;
  QString error;
  if (!catalog.LoadFromRoot(root, &error)) {
    plugin_desc_label_->setText(QStringLiteral("扫描失败: %1").arg(error));
    return;
  }
  const QString keep_id = plugin_combo_->currentData().toString().trimmed();
  SetPluginEntries(catalog.Plugins());
  if (!keep_id.isEmpty()) {
    const int idx = plugin_combo_->findData(keep_id);
    if (idx >= 0) {
      plugin_combo_->setCurrentIndex(idx);
    }
  }
  plugin_desc_label_->setText(QStringLiteral("扫描完成，共 %1 个插件").arg(plugin_entries_.size()));
}

void PluginProviderWindow::OnOpenPluginRootClicked() {
  QString root = plugin_root_edit_->text().trimmed();
  if (root.isEmpty()) {
    return;
  }
  QDir dir(root);
  if (!dir.exists()) {
    QDir().mkpath(root);
  }
  QDesktopServices::openUrl(QUrl::fromLocalFile(QDir(root).absolutePath()));
}

}  // namespace r3::windows_client_qt::ui
