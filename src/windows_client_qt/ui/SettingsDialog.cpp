#include "ui/SettingsDialog.h"

#include <algorithm>
#include <cstdint>

#include <QByteArray>
#include <QCheckBox>
#include <QComboBox>
#include <QDialogButtonBox>
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

SettingsDialog::SettingsDialog(QWidget* parent) : QDialog(parent) {
  BuildUi();
  setWindowTitle(QStringLiteral("设置"));
  resize(760, 680);
}

void SettingsDialog::BuildUi() {
  auto* root = new QVBoxLayout(this);
  root->setContentsMargins(12, 12, 12, 12);
  root->setSpacing(10);

  auto* basic_group = new QGroupBox(QStringLiteral("基础设置"), this);
  auto* basic_form = new QFormLayout(basic_group);
  basic_form->setContentsMargins(10, 10, 10, 10);
  basic_form->setSpacing(8);

  host_edit_ = new QLineEdit(this);
  port_spin_ = new QSpinBox(this);
  port_spin_->setRange(1, 65535);
  adb_edit_ = new QLineEdit(this);
  auto_start_check_ = new QCheckBox(QStringLiteral("启动后自动检测设备、推送并连接"), this);

  default_value_type_combo_ = new QComboBox(this);
  default_value_type_combo_->addItem(QStringLiteral("1 Byte"));
  default_value_type_combo_->addItem(QStringLiteral("2 Bytes"));
  default_value_type_combo_->addItem(QStringLiteral("4 Bytes"));
  default_value_type_combo_->addItem(QStringLiteral("8 Bytes"));
  default_value_type_combo_->addItem(QStringLiteral("Float"));
  default_value_type_combo_->addItem(QStringLiteral("Double"));
  default_value_type_combo_->addItem(QStringLiteral("String"));
  default_value_type_combo_->addItem(QStringLiteral("Array of Byte"));
  default_value_type_combo_->addItem(QStringLiteral("Binary"));
  default_value_type_combo_->addItem(QStringLiteral("All"));

  default_compare_combo_ = new QComboBox(this);
  default_compare_combo_->addItem(QStringLiteral("精确数值 (=)"));
  default_compare_combo_->addItem(QStringLiteral("不等于 (!=)"));
  default_compare_combo_->addItem(QStringLiteral("大于 (>)"));
  default_compare_combo_->addItem(QStringLiteral("小于 (<)"));
  default_compare_combo_->addItem(QStringLiteral("已改变"));
  default_compare_combo_->addItem(QStringLiteral("未改变"));

  refresh_interval_spin_ = new QSpinBox(this);
  refresh_interval_spin_->setRange(100, 2000);
  refresh_interval_spin_->setSingleStep(50);
  refresh_interval_spin_->setSuffix(QStringLiteral(" ms"));

  basic_form->addRow(QStringLiteral("主机"), host_edit_);
  basic_form->addRow(QStringLiteral("端口"), port_spin_);
  basic_form->addRow(QStringLiteral("ADB"), adb_edit_);
  basic_form->addRow(QString(), auto_start_check_);
  basic_form->addRow(QStringLiteral("默认数值类型"), default_value_type_combo_);
  basic_form->addRow(QStringLiteral("默认扫描类型"), default_compare_combo_);
  basic_form->addRow(QStringLiteral("地址刷新周期"), refresh_interval_spin_);
  root->addWidget(basic_group);

  plugin_dev_entry_row_ = new QWidget(this);
  auto* dev_entry_layout = new QHBoxLayout(plugin_dev_entry_row_);
  dev_entry_layout->setContentsMargins(0, 0, 0, 0);
  dev_entry_layout->setSpacing(6);
  dev_entry_layout->addStretch(1);
  open_plugin_dev_button_ = new QPushButton(QStringLiteral("打开插件开发窗口"), this);
  dev_entry_layout->addWidget(open_plugin_dev_button_);
  root->addWidget(plugin_dev_entry_row_);

  plugin_group_ = new QGroupBox(QStringLiteral("插件与自定义syscall"), this);
  auto* plugin_form = new QFormLayout(plugin_group_);
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

  root->addWidget(plugin_group_, 1);

  auto* buttons = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, this);
  connect(buttons, &QDialogButtonBox::accepted, this, &SettingsDialog::accept);
  connect(buttons, &QDialogButtonBox::rejected, this, &SettingsDialog::reject);
  root->addWidget(buttons);

  connect(plugin_combo_,
          static_cast<void (QComboBox::*)(int)>(&QComboBox::currentIndexChanged),
          this,
          &SettingsDialog::OnPluginSelectionChanged);
  connect(plugin_generate_ctx_button_,
          &QPushButton::clicked,
          this,
          &SettingsDialog::OnGenerateUserCtxFromQuickstart);
  connect(plugin_scan_button_,
          &QPushButton::clicked,
          this,
          &SettingsDialog::OnScanPluginsClicked);
  connect(open_plugin_dev_button_, &QPushButton::clicked, this, [this]() {
    emit OpenPluginDevWindowRequested();
  });
}

void SettingsDialog::SetPluginSectionVisible(bool visible) {
  if (plugin_dev_entry_row_) {
    plugin_dev_entry_row_->setVisible(visible);
  }
  if (plugin_group_) {
    plugin_group_->setVisible(visible);
  }
}

void SettingsDialog::SetPluginEntries(const std::vector<r3::windows_client_qt::plugins::PluginManifest>& plugins) {
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

void SettingsDialog::SetData(const SettingsData& data) {
  host_edit_->setText(data.host);
  port_spin_->setValue(static_cast<int>(data.port));
  adb_edit_->setText(data.adb_path);
  auto_start_check_->setChecked(data.auto_start);

  if (data.default_value_type >= 0 && data.default_value_type < default_value_type_combo_->count()) {
    default_value_type_combo_->setCurrentIndex(data.default_value_type);
  }
  if (data.default_compare_type >= 0 && data.default_compare_type < default_compare_combo_->count()) {
    default_compare_combo_->setCurrentIndex(data.default_compare_type);
  }
  refresh_interval_spin_->setValue(data.value_refresh_ms);

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

SettingsDialog::SettingsData SettingsDialog::Data() const {
  SettingsData data;
  data.host = host_edit_->text().trimmed();
  data.port = static_cast<uint16_t>(port_spin_->value());
  data.adb_path = adb_edit_->text().trimmed();
  data.auto_start = auto_start_check_->isChecked();
  data.default_value_type = default_value_type_combo_->currentIndex();
  data.default_compare_type = default_compare_combo_->currentIndex();
  data.value_refresh_ms = refresh_interval_spin_->value();

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

void SettingsDialog::OnPluginSelectionChanged(int index) {
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

void SettingsDialog::OnGenerateUserCtxFromQuickstart() {
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

void SettingsDialog::OnScanPluginsClicked() {
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

}  // namespace r3::windows_client_qt::ui
