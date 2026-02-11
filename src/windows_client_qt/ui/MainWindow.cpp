
#include "ui/MainWindow.h"

#include <algorithm>
#include <cstring>
#include <utility>

#include <QAction>
#include <QApplication>
#include <QCheckBox>
#include <QClipboard>
#include <QComboBox>
#include <QDateTime>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QFormLayout>
#include <QGroupBox>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QMenu>
#include <QMenuBar>
#include <QMessageBox>
#include <QProcess>
#include <QPushButton>
#include <QPixmap>
#include <QRegularExpression>
#include <QResizeEvent>
#include <QShortcut>
#include <QSettings>
#include <QSpinBox>
#include <QSplitter>
#include <QStandardItem>
#include <QStandardItemModel>
#include <QStatusBar>
#include <QTableView>
#include <QTextStream>
#include <QTimer>
#include <QToolButton>
#include <QToolBar>
#include <QVBoxLayout>
#include <QWidget>
#include <QtConcurrent/QtConcurrent>

#include "plugin_sdk/R3ModuleCompat.h"
#include "ui/MemoryViewWindow.h"
#include "ui/ModuleRangeDialog.h"
#include "ui/PointerToolsDialog.h"
#include "ui/PluginDevWindow.h"
#include "ui/PluginFailureWindow.h"
#include "ui/PluginProviderWindow.h"
#include "ui/PluginRuntimeWindow.h"
#include "ui/ProcessDialog.h"
#include "ui/SettingsDialog.h"

namespace r3::windows_client_qt::ui {

namespace {
constexpr int kAddressRole = Qt::UserRole + 100;
constexpr int kTypeRole = Qt::UserRole + 101;

QString ToQString(const std::string& text) {
  return QString::fromUtf8(text.c_str(), static_cast<int>(text.size()));
}

std::string ToStdString(const QString& text) {
  const QByteArray utf8 = text.toUtf8();
  return std::string(utf8.constData(), static_cast<size_t>(utf8.size()));
}

bool LooksDeviceLine(const QString& line) {
  return line.contains('\t') && line.endsWith(QStringLiteral("device"));
}

QString TrimAscii(const QString& text) {
  return text.trimmed();
}

bool ParseAobText(const QString& text, std::vector<uint8_t>* out) {
  if (!out) {
    return false;
  }
  out->clear();
  const QString trimmed = TrimAscii(text);
  if (trimmed.isEmpty()) {
    return false;
  }
  QStringList parts = trimmed.split(QRegularExpression("\\s+"), Qt::SkipEmptyParts);
  if (parts.size() == 1 && !parts[0].contains(',')) {
    QString compact = parts[0];
    compact.remove(' ');
    compact.remove(',');
    compact.remove(';');
    if ((compact.size() % 2) != 0) {
      return false;
    }
    parts.clear();
    for (int i = 0; i < compact.size(); i += 2) {
      parts.push_back(compact.mid(i, 2));
    }
  }
  for (QString part : parts) {
    part = part.trimmed();
    if (part.startsWith(QStringLiteral("0x"), Qt::CaseInsensitive)) {
      part = part.mid(2);
    }
    bool ok = false;
    const int v = part.toInt(&ok, 16);
    if (!ok || v < 0 || v > 0xFF) {
      return false;
    }
    out->push_back(static_cast<uint8_t>(v));
  }
  return !out->empty();
}

bool ParseBinaryText(const QString& text, std::vector<uint8_t>* out) {
  if (!out) {
    return false;
  }
  out->clear();
  QString bits;
  bits.reserve(text.size());
  for (QChar ch : text) {
    if (ch == QLatin1Char('0') || ch == QLatin1Char('1')) {
      bits.push_back(ch);
    } else if (ch.isSpace() || ch == QLatin1Char('_')) {
      continue;
    } else {
      return false;
    }
  }
  if (bits.isEmpty()) {
    return false;
  }
  const int rem = bits.size() % 8;
  if (rem != 0) {
    bits.prepend(QString(8 - rem, QLatin1Char('0')));
  }
  for (int i = 0; i < bits.size(); i += 8) {
    uint8_t v = 0;
    for (int j = 0; j < 8; ++j) {
      v <<= 1;
      if (bits[i + j] == QLatin1Char('1')) {
        v |= 1u;
      }
    }
    out->push_back(v);
  }
  return !out->empty();
}
}  // namespace

MainWindow::MainWindow(QWidget* parent) : QMainWindow(parent) {
  settings_path_ = QDir::current().filePath(QStringLiteral("settings/windows_client_qt.ini"));
  BuildUi();
  LoadSettings();
  UpdateConnectionUi();
  connect(address_model_, &QStandardItemModel::itemChanged, this, &MainWindow::OnAddressItemChanged);
  connect(&address_refresh_watcher_, &QFutureWatcher<AddressRefreshResult>::finished, this,
          &MainWindow::ApplyAddressRefreshResult);
  connect(&scan_watcher_, &QFutureWatcher<ScanTaskResult>::finished, this, &MainWindow::OnScanTaskFinished);

  address_timer_ = new QTimer(this);
  address_timer_->setInterval(450);
  connect(address_timer_, &QTimer::timeout, this, &MainWindow::OnAddressRefreshTick);
  address_timer_->start();

  connect(&auto_startup_watcher_, &QFutureWatcher<bool>::finished, this, &MainWindow::OnAutoStartupFinished);
  QTimer::singleShot(250, this, &MainWindow::TryAutoStartup);
  QTimer::singleShot(0, this, [this]() {
    ReloadPluginCatalog();
    ApplyCustomProviderConfig();
  });
  QTimer::singleShot(900, this, &MainWindow::WarmupSecondaryWindows);
}

MainWindow::~MainWindow() {
  if (scan_watcher_.isRunning()) {
    scan_watcher_.waitForFinished();
  }
  if (address_refresh_watcher_.isRunning()) {
    address_refresh_watcher_.waitForFinished();
  }
  if (auto_startup_watcher_.isRunning()) {
    auto_startup_watcher_.waitForFinished();
  }
  DumpTelemetrySnapshot(QStringLiteral("app_exit"));
  SaveSettings();
  DisconnectService();
}

void MainWindow::resizeEvent(QResizeEvent* event) {
  QMainWindow::resizeEvent(event);
  UpdatePluginFailureEntryLayout();
}

void MainWindow::WarmupSecondaryWindows() {
  QTimer::singleShot(0, this, [this]() { EnsureMemoryViewWindow(); });
  QTimer::singleShot(60, this, [this]() { EnsureProcessDialog(); });
  QTimer::singleShot(120, this, [this]() { EnsurePointerToolsWindow(); });
  QTimer::singleShot(180, this, [this]() { EnsurePluginProviderWindow(); });
  QTimer::singleShot(220, this, [this]() { EnsurePluginDevWindow(); });
  QTimer::singleShot(280, this, [this]() { EnsurePluginRuntimeWindow(); });
  QTimer::singleShot(320, this, [this]() { EnsurePluginFailureWindow(); });
}

void MainWindow::BuildUi() {
  setWindowTitle(QStringLiteral("R3 Android Debug Client (Qt)"));
  resize(1366, 860);
  setMinimumSize(1180, 720);
  BuildMenuAndToolbar();
  BuildCenterLayout();
  statusBar()->showMessage(QStringLiteral("就绪"));
}

void MainWindow::BuildMenuAndToolbar() {
  QMenu* file_menu = menuBar()->addMenu(QStringLiteral("文件(F)"));
  QMenu* view_menu = menuBar()->addMenu(QStringLiteral("视图(V)"));
  QMenu* debug_menu = menuBar()->addMenu(QStringLiteral("调试"));
  QMenu* plugin_menu = menuBar()->addMenu(QStringLiteral("插件(P)"));
  QMenu* pointer_menu = debug_menu->addMenu(QStringLiteral("指针工具"));

  action_connect_ = file_menu->addAction(QStringLiteral("连接"));
  action_select_process_ = file_menu->addAction(QStringLiteral("打开进程"));
  action_settings_ = file_menu->addAction(QStringLiteral("设置"));
  file_menu->addSeparator();
  action_pointer_scan_ = pointer_menu->addAction(QStringLiteral("指针扫描"));
  action_pointer_compare_ = pointer_menu->addAction(QStringLiteral("指针对比"));
  action_structure_traverse_ = pointer_menu->addAction(QStringLiteral("结构遍历"));
  pointer_menu->addSeparator();
  action_pointer_tools_ = pointer_menu->addAction(QStringLiteral("打开指针工具(综合)"));
  action_plugin_provider_ = plugin_menu->addAction(QStringLiteral("插件与自定义syscall"));
  action_plugin_runtime_ = plugin_menu->addAction(QStringLiteral("插件运行状态"));
  plugin_menu->addSeparator();
  action_plugin_dev_ = plugin_menu->addAction(QStringLiteral("插件开发中心"));
  action_plugin_failure_output_ = plugin_menu->addAction(QStringLiteral("插件加载失败输出"));
  action_pointer_scan_->setShortcut(QKeySequence(QStringLiteral("Ctrl+Alt+1")));
  action_pointer_compare_->setShortcut(QKeySequence(QStringLiteral("Ctrl+Alt+2")));
  action_structure_traverse_->setShortcut(QKeySequence(QStringLiteral("Ctrl+Alt+3")));
  action_pointer_tools_->setShortcut(QKeySequence(QStringLiteral("Ctrl+Shift+P")));
  action_module_range_ = view_menu->addAction(QStringLiteral("模块范围"));
  action_open_memory_ = view_menu->addAction(QStringLiteral("Memory View"));
  action_select_process_->setShortcut(QKeySequence(QStringLiteral("Ctrl+P")));
  action_open_memory_->setShortcut(QKeySequence(QStringLiteral("Ctrl+M")));
  QAction* quit = file_menu->addAction(QStringLiteral("退出"));

  auto* tb = addToolBar(QStringLiteral("主工具栏"));
  tb->setMovable(false);
  tb->addAction(action_select_process_);
  tb->addAction(action_connect_);
  tb->addAction(action_module_range_);
  tb->addAction(action_open_memory_);
  tb->addAction(action_pointer_scan_);
  tb->addAction(action_pointer_compare_);
  tb->addAction(action_structure_traverse_);
  tb->addAction(action_plugin_provider_);
  tb->addAction(action_plugin_runtime_);
  tb->addAction(action_plugin_dev_);
  tb->addAction(action_settings_);

  connect(action_connect_, &QAction::triggered, this, &MainWindow::OnConnectClicked);
  connect(action_select_process_, &QAction::triggered, this, &MainWindow::OnSelectProcessClicked);
  connect(action_module_range_, &QAction::triggered, this, &MainWindow::OnOpenModuleRangeClicked);
  connect(action_open_memory_, &QAction::triggered, this, &MainWindow::OnOpenMemoryViewClicked);
  connect(action_settings_, &QAction::triggered, this, &MainWindow::OnOpenSettingsClicked);
  connect(action_pointer_tools_, &QAction::triggered, this, &MainWindow::OnOpenPointerToolsClicked);
  connect(action_pointer_scan_, &QAction::triggered, this, &MainWindow::OnOpenPointerScanClicked);
  connect(action_pointer_compare_, &QAction::triggered, this, &MainWindow::OnOpenPointerCompareClicked);
  connect(action_structure_traverse_, &QAction::triggered, this, &MainWindow::OnOpenStructureTraverseClicked);
  connect(action_plugin_provider_, &QAction::triggered, this, &MainWindow::OnOpenPluginProviderClicked);
  connect(action_plugin_runtime_, &QAction::triggered, this, &MainWindow::OnOpenPluginRuntimeClicked);
  connect(action_plugin_dev_, &QAction::triggered, this, &MainWindow::OnOpenPluginDevClicked);
  connect(action_plugin_failure_output_, &QAction::triggered, this, &MainWindow::OnOpenPluginFailureOutputClicked);
  connect(quit, &QAction::triggered, this, &MainWindow::close);
}

void MainWindow::BuildCenterLayout() {
  auto* central = new QWidget(this);
  auto* root = new QVBoxLayout(central);
  root->setContentsMargins(10, 10, 10, 10);

  auto* top_row = new QHBoxLayout();
  top_row->setContentsMargins(0, 0, 0, 0);
  top_row->setSpacing(6);
  process_label_ = new QLabel(QStringLiteral("未选择进程"), central);
  top_row->addWidget(process_label_, 1);
  plugin_failure_output_button_ = new QPushButton(QStringLiteral("插件加载失败输出"), central);
  top_row->addWidget(plugin_failure_output_button_, 0, Qt::AlignRight);
  plugin_failure_output_menu_ = new QMenu(this);
  plugin_failure_output_menu_->addAction(action_plugin_failure_output_);
  plugin_failure_output_dropdown_button_ = new QToolButton(central);
  plugin_failure_output_dropdown_button_->setPopupMode(QToolButton::InstantPopup);
  plugin_failure_output_dropdown_button_->setText(QStringLiteral("插件"));
  plugin_failure_output_dropdown_button_->setMenu(plugin_failure_output_menu_);
  plugin_failure_output_dropdown_button_->hide();
  top_row->addWidget(plugin_failure_output_dropdown_button_, 0, Qt::AlignRight);
  root->addLayout(top_row);

  auto* vsplit = new QSplitter(Qt::Vertical, central);
  auto* hsplit = new QSplitter(Qt::Horizontal, vsplit);

  auto* left = new QWidget(hsplit);
  auto* left_layout = new QVBoxLayout(left);
  left_layout->setContentsMargins(0, 0, 0, 0);
  BuildScanTable();
  left_layout->addWidget(scan_table_);

  auto* right = new QWidget(hsplit);
  BuildControlPanel(right);

  hsplit->addWidget(left);
  hsplit->addWidget(right);
  hsplit->setStretchFactor(0, 6);
  hsplit->setStretchFactor(1, 4);

  auto* bottom = new QWidget(vsplit);
  auto* bottom_layout = new QVBoxLayout(bottom);
  bottom_layout->setContentsMargins(0, 0, 0, 0);
  BuildAddressTable();
  bottom_layout->addWidget(address_table_);

  vsplit->addWidget(hsplit);
  vsplit->addWidget(bottom);
  vsplit->setStretchFactor(0, 7);
  vsplit->setStretchFactor(1, 3);
  root->addWidget(vsplit, 1);
  setCentralWidget(central);
  UpdatePluginFailureEntryLayout();
}

void MainWindow::BuildScanTable() {
  scan_table_ = new QTableView(this);
  scan_table_->setSelectionBehavior(QAbstractItemView::SelectRows);
  scan_table_->setSelectionMode(QAbstractItemView::ExtendedSelection);
  scan_table_->setAlternatingRowColors(true);
  scan_table_->setEditTriggers(QAbstractItemView::NoEditTriggers);
  scan_table_->setContextMenuPolicy(Qt::CustomContextMenu);
  scan_table_->verticalHeader()->hide();
  scan_table_->horizontalHeader()->setStretchLastSection(true);

  scan_model_ = new QStandardItemModel(this);
  scan_model_->setColumnCount(3);
  scan_model_->setHeaderData(0, Qt::Horizontal, QStringLiteral("地址"));
  scan_model_->setHeaderData(1, Qt::Horizontal, QStringLiteral("当前值"));
  scan_model_->setHeaderData(2, Qt::Horizontal, QStringLiteral("先前值"));
  scan_table_->setModel(scan_model_);

  connect(scan_table_, &QTableView::doubleClicked, this, &MainWindow::OnScanResultDoubleClicked);
  connect(scan_table_, &QTableView::customContextMenuRequested, this, &MainWindow::OnScanContextMenuRequested);

  auto* shortcut_insert = new QShortcut(QKeySequence(Qt::Key_Insert), scan_table_);
  connect(shortcut_insert, &QShortcut::activated, this, &MainWindow::OnQuickAddSelected);
  auto* shortcut_ctrl_enter = new QShortcut(QKeySequence(QStringLiteral("Ctrl+Return")), scan_table_);
  connect(shortcut_ctrl_enter, &QShortcut::activated, this, &MainWindow::OnQuickAddAndEditSelected);
}
void MainWindow::BuildAddressTable() {
  address_table_ = new QTableView(this);
  address_table_->setSelectionBehavior(QAbstractItemView::SelectRows);
  address_table_->setSelectionMode(QAbstractItemView::ExtendedSelection);
  address_table_->setAlternatingRowColors(true);
  address_table_->setContextMenuPolicy(Qt::CustomContextMenu);
  address_table_->verticalHeader()->hide();
  address_table_->horizontalHeader()->setStretchLastSection(true);

  address_model_ = new QStandardItemModel(this);
  address_model_->setColumnCount(6);
  address_model_->setHeaderData(0, Qt::Horizontal, QStringLiteral("激活"));
  address_model_->setHeaderData(1, Qt::Horizontal, QStringLiteral("冻结"));
  address_model_->setHeaderData(2, Qt::Horizontal, QStringLiteral("描述"));
  address_model_->setHeaderData(3, Qt::Horizontal, QStringLiteral("地址"));
  address_model_->setHeaderData(4, Qt::Horizontal, QStringLiteral("类型"));
  address_model_->setHeaderData(5, Qt::Horizontal, QStringLiteral("数值"));
  address_table_->setModel(address_model_);

  connect(address_table_, &QTableView::customContextMenuRequested, this, &MainWindow::OnAddressContextMenuRequested);
}

void MainWindow::BuildControlPanel(QWidget* parent) {
  auto* layout = new QVBoxLayout(parent);
  layout->setContentsMargins(0, 0, 0, 0);

  auto* conn_box = new QWidget(parent);
  auto* conn_form = new QFormLayout(conn_box);
  host_edit_ = new QLineEdit(QStringLiteral("127.0.0.1"), conn_box);
  port_spin_ = new QSpinBox(conn_box);
  port_spin_->setRange(1, 65535);
  port_spin_->setValue(12345);
  adb_path_edit_ = new QLineEdit(QStringLiteral("E:/gjzs/adb.exe"), conn_box);
  auto_start_check_ = new QCheckBox(QStringLiteral("启动自动检测设备并连接"), conn_box);
  auto_start_check_->setChecked(true);
  auto* connect_btn = new QPushButton(QStringLiteral("连接/断开"), conn_box);

  conn_form->addRow(QStringLiteral("主机"), host_edit_);
  conn_form->addRow(QStringLiteral("端口"), port_spin_);
  conn_form->addRow(QStringLiteral("ADB"), adb_path_edit_);
  conn_form->addRow(QString(), auto_start_check_);
  conn_form->addRow(QString(), connect_btn);
  connect(connect_btn, &QPushButton::clicked, this, &MainWindow::OnConnectClicked);
  layout->addWidget(conn_box);

  auto* scan_box = new QWidget(parent);
  auto* form = new QFormLayout(scan_box);

  scan_value_edit_ = new QLineEdit(QStringLiteral("0"), scan_box);
  scan_hex_check_ = new QCheckBox(QStringLiteral("十六进制"), scan_box);

  scan_compare_combo_ = new QComboBox(scan_box);
  scan_compare_combo_->addItem(QStringLiteral("精确数值 (=)"), static_cast<int>(protocol::ComparisonType::EQ));
  scan_compare_combo_->addItem(QStringLiteral("不等于 (!=)"), static_cast<int>(protocol::ComparisonType::NE));
  scan_compare_combo_->addItem(QStringLiteral("大于 (>)"), static_cast<int>(protocol::ComparisonType::GT));
  scan_compare_combo_->addItem(QStringLiteral("小于 (<)"), static_cast<int>(protocol::ComparisonType::LT));
  scan_compare_combo_->addItem(QStringLiteral("已改变"), static_cast<int>(protocol::ComparisonType::CHANGED));
  scan_compare_combo_->addItem(QStringLiteral("未改变"), static_cast<int>(protocol::ComparisonType::UNCHANGED));

  scan_value_type_combo_ = new QComboBox(scan_box);
  scan_value_type_combo_->addItem(QStringLiteral("1 Byte"), static_cast<int>(protocol::ValueType::U8));
  scan_value_type_combo_->addItem(QStringLiteral("2 Bytes"), static_cast<int>(protocol::ValueType::U16));
  scan_value_type_combo_->addItem(QStringLiteral("4 Bytes"), static_cast<int>(protocol::ValueType::U32));
  scan_value_type_combo_->addItem(QStringLiteral("8 Bytes"), static_cast<int>(protocol::ValueType::U64));
  scan_value_type_combo_->addItem(QStringLiteral("4 Bytes(Signed)"), static_cast<int>(protocol::ValueType::S32));
  scan_value_type_combo_->addItem(QStringLiteral("8 Bytes(Signed)"), static_cast<int>(protocol::ValueType::S64));
  scan_value_type_combo_->addItem(QStringLiteral("Float"), static_cast<int>(protocol::ValueType::FLOAT));
  scan_value_type_combo_->addItem(QStringLiteral("Double"), static_cast<int>(protocol::ValueType::DOUBLE));
  scan_value_type_combo_->addItem(QStringLiteral("String"), static_cast<int>(protocol::ValueType::STRING));
  scan_value_type_combo_->addItem(QStringLiteral("Array of Byte"), static_cast<int>(protocol::ValueType::AOB));
  scan_value_type_combo_->addItem(QStringLiteral("Binary"), static_cast<int>(protocol::ValueType::BINARY));
  scan_value_type_combo_->addItem(QStringLiteral("All"), static_cast<int>(protocol::ValueType::ALL));

  scan_region_combo_ = new QComboBox(scan_box);
  scan_region_combo_->addItem(QStringLiteral("All"), static_cast<int>(protocol::GG_REGION_NONE));
  scan_region_combo_->addItem(QStringLiteral("XA"), static_cast<int>(protocol::GG_REGION_XA));
  scan_region_combo_->addItem(QStringLiteral("A"), static_cast<int>(protocol::GG_REGION_A));
  scan_region_combo_->addItem(QStringLiteral("O"), static_cast<int>(protocol::GG_REGION_O));
  scan_region_combo_->addItem(QStringLiteral(".bss"), static_cast<int>(protocol::GG_REGION_BSS));
  scan_region_combo_->addItem(QStringLiteral("jh"), static_cast<int>(protocol::GG_REGION_JH));
  scan_region_combo_->addItem(QStringLiteral("ch"), static_cast<int>(protocol::GG_REGION_CH));
  scan_region_combo_->addItem(QStringLiteral("ca"), static_cast<int>(protocol::GG_REGION_CA));
  scan_region_combo_->addItem(QStringLiteral("ps"), static_cast<int>(protocol::GG_REGION_PS));
  scan_region_combo_->addItem(QStringLiteral("J"), static_cast<int>(protocol::GG_REGION_J));
  scan_region_combo_->addItem(QStringLiteral("S"), static_cast<int>(protocol::GG_REGION_S));
  scan_region_combo_->addItem(QStringLiteral("As"), static_cast<int>(protocol::GG_REGION_AS));
  scan_region_combo_->addItem(QStringLiteral("V"), static_cast<int>(protocol::GG_REGION_V));
  scan_region_combo_->addItem(QStringLiteral("XS"), static_cast<int>(protocol::GG_REGION_XS));

  scan_start_edit_ = new QLineEdit(scan_box);
  scan_end_edit_ = new QLineEdit(scan_box);

  flag_use_pvm_check_ = new QCheckBox(QStringLiteral("PVM"), scan_box);
  flag_use_pvm_check_->setChecked(true);
  flag_writable_check_ = new QCheckBox(QStringLiteral("只可写"), scan_box);
  flag_writable_check_->setChecked(true);
  flag_exec_check_ = new QCheckBox(QStringLiteral("可执行"), scan_box);
  flag_private_check_ = new QCheckBox(QStringLiteral("私有"), scan_box);
  flag_private_check_->setChecked(true);
  flag_image_check_ = new QCheckBox(QStringLiteral("镜像"), scan_box);
  flag_mapped_check_ = new QCheckBox(QStringLiteral("映射"), scan_box);

  form->addRow(QStringLiteral("数值"), scan_value_edit_);
  form->addRow(QString(), scan_hex_check_);
  form->addRow(QStringLiteral("扫描类型"), scan_compare_combo_);
  form->addRow(QStringLiteral("数值类型"), scan_value_type_combo_);
  form->addRow(QStringLiteral("内存区域"), scan_region_combo_);
  form->addRow(QStringLiteral("起始"), scan_start_edit_);
  form->addRow(QStringLiteral("结束"), scan_end_edit_);
  form->addRow(QString(), flag_use_pvm_check_);
  form->addRow(QString(), flag_writable_check_);
  form->addRow(QString(), flag_exec_check_);
  form->addRow(QString(), flag_private_check_);
  form->addRow(QString(), flag_image_check_);
  form->addRow(QString(), flag_mapped_check_);

  auto* row = new QHBoxLayout();
  first_scan_button_ = new QPushButton(QStringLiteral("首次扫描"), scan_box);
  next_scan_button_ = new QPushButton(QStringLiteral("再次扫描"), scan_box);
  undo_scan_button_ = new QPushButton(QStringLiteral("撤销扫描"), scan_box);
  row->addWidget(first_scan_button_);
  row->addWidget(next_scan_button_);
  row->addWidget(undo_scan_button_);
  form->addRow(QString(), row);

  auto* mod_btn = new QPushButton(QStringLiteral("模块范围..."), scan_box);
  form->addRow(QString(), mod_btn);

  connect(first_scan_button_, &QPushButton::clicked, this, &MainWindow::OnFirstScanClicked);
  connect(next_scan_button_, &QPushButton::clicked, this, &MainWindow::OnNextScanClicked);
  connect(undo_scan_button_, &QPushButton::clicked, this, &MainWindow::OnUndoScanClicked);
  connect(mod_btn, &QPushButton::clicked, this, &MainWindow::OnOpenModuleRangeClicked);

  layout->addWidget(scan_box, 1);

  connect(plugin_failure_output_button_, &QPushButton::clicked, this, &MainWindow::OnOpenPluginFailureOutputClicked);
}
void MainWindow::LoadSettings() {
  QDir().mkpath(QFileInfo(settings_path_).absolutePath());
  QSettings ini(settings_path_, QSettings::IniFormat);
  host_edit_->setText(ini.value(QStringLiteral("connection/host"), host_edit_->text()).toString());
  port_spin_->setValue(ini.value(QStringLiteral("connection/port"), port_spin_->value()).toInt());
  adb_path_edit_->setText(ini.value(QStringLiteral("connection/adb"), adb_path_edit_->text()).toString());
  auto_start_check_->setChecked(ini.value(QStringLiteral("startup/auto"), true).toBool());
  scan_value_edit_->setText(ini.value(QStringLiteral("scan/value"), scan_value_edit_->text()).toString());
  scan_hex_check_->setChecked(ini.value(QStringLiteral("scan/hex"), false).toBool());
  scan_start_edit_->setText(ini.value(QStringLiteral("scan/start"), QString()).toString());
  scan_end_edit_->setText(ini.value(QStringLiteral("scan/end"), QString()).toString());

  const int compare_value = ini.value(QStringLiteral("scan/compare"), scan_compare_combo_->currentData()).toInt();
  const int compare_idx = scan_compare_combo_->findData(compare_value);
  if (compare_idx >= 0) {
    scan_compare_combo_->setCurrentIndex(compare_idx);
  }
  const int value_type = ini.value(QStringLiteral("scan/value_type"), scan_value_type_combo_->currentData()).toInt();
  const int value_idx = scan_value_type_combo_->findData(value_type);
  if (value_idx >= 0) {
    scan_value_type_combo_->setCurrentIndex(value_idx);
  }
  const int region_value = ini.value(QStringLiteral("scan/region"), scan_region_combo_->currentData()).toInt();
  const int region_idx = scan_region_combo_->findData(region_value);
  if (region_idx >= 0) {
    scan_region_combo_->setCurrentIndex(region_idx);
  }
  flag_use_pvm_check_->setChecked(ini.value(QStringLiteral("scan/use_pvm"), flag_use_pvm_check_->isChecked()).toBool());
  flag_writable_check_->setChecked(ini.value(QStringLiteral("scan/writable"), flag_writable_check_->isChecked()).toBool());
  flag_exec_check_->setChecked(ini.value(QStringLiteral("scan/exec"), flag_exec_check_->isChecked()).toBool());
  flag_private_check_->setChecked(ini.value(QStringLiteral("scan/private"), flag_private_check_->isChecked()).toBool());
  flag_image_check_->setChecked(ini.value(QStringLiteral("scan/image"), flag_image_check_->isChecked()).toBool());
  flag_mapped_check_->setChecked(ini.value(QStringLiteral("scan/mapped"), flag_mapped_check_->isChecked()).toBool());
  const int refresh_ms = ini.value(QStringLiteral("address/refresh_ms"), 450).toInt();
  if (address_timer_) {
    address_timer_->setInterval(std::clamp(refresh_ms, 100, 2000));
  }

  plugin_root_path_ = ini.value(QStringLiteral("plugin/root"),
                                QDir::current().filePath(QStringLiteral("plugins")))
                          .toString()
                          .trimmed();
  plugin_selected_id_ = ini.value(QStringLiteral("plugin/selected_id"), QString()).toString().trimmed();
  plugin_enabled_ = ini.value(QStringLiteral("plugin/enabled"), false).toBool();
  plugin_allow_fallback_ = ini.value(QStringLiteral("plugin/allow_fallback"), true).toBool();
  plugin_timeout_ms_ = ini.value(QStringLiteral("plugin/timeout_ms"), 1000).toInt();
  plugin_timeout_ms_ = std::clamp(plugin_timeout_ms_, 1, 60000);
  plugin_syscall_read_ = ini.value(QStringLiteral("plugin/syscall_read"), -1).toInt();
  plugin_syscall_write_ = ini.value(QStringLiteral("plugin/syscall_write"), -1).toInt();
  plugin_user_ctx_hex_ = ini.value(QStringLiteral("plugin/user_ctx_hex"), QString()).toString().trimmed();
}

void MainWindow::SaveSettings() {
  QDir().mkpath(QFileInfo(settings_path_).absolutePath());
  QSettings ini(settings_path_, QSettings::IniFormat);
  ini.setValue(QStringLiteral("connection/host"), host_edit_->text());
  ini.setValue(QStringLiteral("connection/port"), port_spin_->value());
  ini.setValue(QStringLiteral("connection/adb"), adb_path_edit_->text());
  ini.setValue(QStringLiteral("startup/auto"), auto_start_check_->isChecked());
  ini.setValue(QStringLiteral("scan/value"), scan_value_edit_->text());
  ini.setValue(QStringLiteral("scan/hex"), scan_hex_check_->isChecked());
  ini.setValue(QStringLiteral("scan/start"), scan_start_edit_->text());
  ini.setValue(QStringLiteral("scan/end"), scan_end_edit_->text());
  ini.setValue(QStringLiteral("scan/compare"), scan_compare_combo_->currentData());
  ini.setValue(QStringLiteral("scan/value_type"), scan_value_type_combo_->currentData());
  ini.setValue(QStringLiteral("scan/region"), scan_region_combo_->currentData());
  ini.setValue(QStringLiteral("scan/use_pvm"), flag_use_pvm_check_->isChecked());
  ini.setValue(QStringLiteral("scan/writable"), flag_writable_check_->isChecked());
  ini.setValue(QStringLiteral("scan/exec"), flag_exec_check_->isChecked());
  ini.setValue(QStringLiteral("scan/private"), flag_private_check_->isChecked());
  ini.setValue(QStringLiteral("scan/image"), flag_image_check_->isChecked());
  ini.setValue(QStringLiteral("scan/mapped"), flag_mapped_check_->isChecked());
  ini.setValue(QStringLiteral("address/refresh_ms"), address_timer_ ? address_timer_->interval() : 450);

  ini.setValue(QStringLiteral("plugin/root"), plugin_root_path_);
  ini.setValue(QStringLiteral("plugin/selected_id"), plugin_selected_id_);
  ini.setValue(QStringLiteral("plugin/enabled"), plugin_enabled_);
  ini.setValue(QStringLiteral("plugin/allow_fallback"), plugin_allow_fallback_);
  ini.setValue(QStringLiteral("plugin/timeout_ms"), plugin_timeout_ms_);
  ini.setValue(QStringLiteral("plugin/syscall_read"), plugin_syscall_read_);
  ini.setValue(QStringLiteral("plugin/syscall_write"), plugin_syscall_write_);
  ini.setValue(QStringLiteral("plugin/user_ctx_hex"), plugin_user_ctx_hex_);
}

void MainWindow::ReloadPluginCatalog() {
  const bool optional_plugin_mode = !plugin_enabled_ && plugin_selected_id_.trimmed().isEmpty();
  const auto is_missing_root = [](const QString& text) {
    return text.contains(QStringLiteral("插件目录不存在"));
  };

  QString error;
  if (!plugin_catalog_.LoadFromRoot(plugin_root_path_, &error)) {
    const QString trimmed = error.trimmed();
    const bool ignore_missing_root = optional_plugin_mode && is_missing_root(trimmed);
    if (ignore_missing_root) {
      UpdateStatus(QStringLiteral("插件目录未配置，当前使用内置链路"));
    } else {
      UpdateStatus(QStringLiteral("插件目录加载失败: %1").arg(error));
      if (!trimmed.isEmpty()) {
        RecordPluginLoadFailure(QStringLiteral("扫描失败: %1").arg(trimmed));
      }
    }
  }
  plugin_loaded_count_ = plugin_catalog_.LastLoadedCount();
  plugin_load_failure_messages_ = plugin_catalog_.LastFailureMessages();
  if (optional_plugin_mode) {
    QStringList filtered;
    filtered.reserve(plugin_load_failure_messages_.size());
    for (const QString& line : plugin_load_failure_messages_) {
      if (is_missing_root(line)) {
        continue;
      }
      filtered.push_back(line);
    }
    plugin_load_failure_messages_ = filtered;
  }
  plugin_load_failed_count_ = static_cast<int>(plugin_load_failure_messages_.size());
  UpdatePluginProviderStatusPanel();
}

std::vector<uint8_t> MainWindow::ParsePluginUserCtxBytes(QString* out_error) const {
  if (out_error) {
    out_error->clear();
  }
  std::vector<uint8_t> out;
  const QString text = plugin_user_ctx_hex_.trimmed();
  if (text.isEmpty()) {
    return out;
  }
  if (!ParseAobText(text, &out)) {
    if (out_error) {
      *out_error = QStringLiteral("插件UserCtx格式无效，示例: 01 00 02 00");
    }
    out.clear();
  }
  return out;
}

void MainWindow::ApplyCustomProviderConfig() {
  r3::windows_client_ng::services::ClientService::CustomMemoryProviderConfig cfg;
  cfg.enabled = false;
  r3::windows_client_ng::services::ClientService::ReadOverrideHook read_hook;
  r3::windows_client_ng::services::ClientService::WriteOverrideHook write_hook;
  std::optional<r3::windows_client_qt::plugins::PluginManifest> selected;
  if (!plugin_selected_id_.trimmed().isEmpty()) {
    selected = plugin_catalog_.FindById(plugin_selected_id_);
    if (!selected.has_value() && plugin_enabled_) {
      UpdateStatus(QStringLiteral("插件未找到: %1").arg(plugin_selected_id_));
    }
  }

  const bool should_activate_plugin = plugin_enabled_ && selected.has_value();
  if (should_activate_plugin) {
    QString runtime_error;
    if (!plugin_runtime_.Activate(*selected, &runtime_error)) {
      RecordPluginLoadFailure(QStringLiteral("激活失败 [%1]: %2")
                                  .arg(selected->id, runtime_error.trimmed().isEmpty()
                                                           ? QStringLiteral("unknown")
                                                           : runtime_error.trimmed()));
      if (!runtime_error.trimmed().isEmpty()) {
        UpdateStatus(QStringLiteral("插件激活失败: %1").arg(runtime_error));
      }
    }
  } else {
    plugin_runtime_.Deactivate();
  }

  if (plugin_enabled_ && selected.has_value()) {
    if (!plugin_force_builtin_fallback_) {
      cfg.enabled = true;
      cfg.allow_fallback = plugin_allow_fallback_;
      cfg.timeout_ms = static_cast<uint32_t>(std::clamp(plugin_timeout_ms_, 1, 60000));
      cfg.syscall_read = plugin_syscall_read_;
      cfg.syscall_write = plugin_syscall_write_;
      cfg.provider_id = ToStdString(selected->id);
      QString parse_error;
      cfg.user_ctx = ParsePluginUserCtxBytes(&parse_error);
      if (!parse_error.isEmpty()) {
        UpdateStatus(parse_error);
      }
    } else {
      cfg.enabled = false;
    }
  }

  if (cfg.enabled && plugin_runtime_.IsActive() && plugin_runtime_.SupportsMemoryEvent()) {
    const uint32_t timeout_ms = cfg.timeout_ms;
    const std::vector<uint8_t> user_ctx = cfg.user_ctx;
    read_hook = [this, timeout_ms, user_ctx](uint32_t pid,
                                             uint64_t address,
                                             uint32_t size,
                                             bool use_pvm,
                                             std::vector<uint8_t>* out_data,
                                             std::string* out_error) {
      QString message;
      std::vector<uint8_t> data;
      const int rc = plugin_runtime_.DispatchReadMemoryEvent(
          pid, address, size, timeout_ms, use_pvm, user_ctx, &data, &message);
      if (rc == static_cast<int>(R3_MODULE_DISPATCH_HANDLED)) {
        if (out_data) {
          *out_data = std::move(data);
        }
        return r3::windows_client_ng::services::ClientService::OverrideAction::kHandled;
      }
      if (rc == static_cast<int>(R3_MODULE_DISPATCH_ERROR)) {
        if (out_error) {
          *out_error = ToStdString(
              message.trimmed().isEmpty() ? QStringLiteral("插件事件读取失败") : message.trimmed());
        }
        return r3::windows_client_ng::services::ClientService::OverrideAction::kError;
      }
      return r3::windows_client_ng::services::ClientService::OverrideAction::kPass;
    };
    write_hook = [this, timeout_ms, user_ctx](uint32_t pid,
                                              uint64_t address,
                                              const std::vector<uint8_t>& bytes,
                                              std::string* out_error) {
      QString message;
      const int rc =
          plugin_runtime_.DispatchWriteMemoryEvent(pid, address, bytes, timeout_ms, user_ctx, &message);
      if (rc == static_cast<int>(R3_MODULE_DISPATCH_HANDLED)) {
        return r3::windows_client_ng::services::ClientService::OverrideAction::kHandled;
      }
      if (rc == static_cast<int>(R3_MODULE_DISPATCH_ERROR)) {
        if (out_error) {
          *out_error = ToStdString(
              message.trimmed().isEmpty() ? QStringLiteral("插件事件写入失败") : message.trimmed());
        }
        return r3::windows_client_ng::services::ClientService::OverrideAction::kError;
      }
      return r3::windows_client_ng::services::ClientService::OverrideAction::kPass;
    };
  }
  {
    const std::lock_guard<std::mutex> lock(service_mutex_);
    service_.SetCustomMemoryProviderConfig(cfg);
    if (read_hook || write_hook) {
      service_.SetMemoryOverrideHooks(std::move(read_hook), std::move(write_hook));
    } else {
      service_.ClearMemoryOverrideHooks();
    }
    if (plugin_force_builtin_fallback_) {
      service_.ForceProviderFallback("manual fallback");
      plugin_runtime_.ForceFuse(QStringLiteral("manual fallback"));
    } else {
      service_.ClearProviderFuse();
      plugin_runtime_.ResetFailures();
    }
  }
  UpdatePluginProviderStatusPanel();
}

void MainWindow::DumpTelemetrySnapshot(const QString& reason) {
  r3::windows_client_ng::services::ClientService::TelemetrySnapshot t{};
  {
    const std::lock_guard<std::mutex> lock(service_mutex_);
    t = service_.GetTelemetrySnapshot();
  }
  QDir().mkpath(QStringLiteral("memory"));
  QFile f(QStringLiteral("memory/perf_windows_client_qt.log"));
  if (!f.open(QIODevice::WriteOnly | QIODevice::Append | QIODevice::Text)) {
    return;
  }
  QTextStream ts(&f);
  ts << QDateTime::currentDateTime().toString(Qt::ISODate) << " reason=" << reason
     << " read_calls=" << static_cast<qulonglong>(t.read_calls)
     << " read_ok=" << static_cast<qulonglong>(t.read_ok)
     << " read_custom_hits=" << static_cast<qulonglong>(t.read_custom_hits)
     << " read_time_us=" << static_cast<qulonglong>(t.read_time_us)
     << " write_calls=" << static_cast<qulonglong>(t.write_calls)
     << " write_ok=" << static_cast<qulonglong>(t.write_ok)
     << " write_custom_hits=" << static_cast<qulonglong>(t.write_custom_hits)
     << " write_time_us=" << static_cast<qulonglong>(t.write_time_us) << "\n";
}

QString MainWindow::BuildPluginModuleStateText(
    const r3::windows_client_ng::services::ClientService::ProviderRuntimeSnapshot& provider) const {
  if (!plugin_enabled_) {
    return QStringLiteral("未启用插件Provider");
  }
  if (plugin_selected_id_.trimmed().isEmpty()) {
    return QStringLiteral("未选择插件模块");
  }
  if (!plugin_runtime_.IsActive()) {
    return QStringLiteral("模块未激活");
  }
  if (!plugin_runtime_.SupportsMemoryEvent()) {
    return QStringLiteral("模块已加载（未注册内存事件）");
  }
  if (!connected_) {
    return QStringLiteral("模块已加载（未连接设备）");
  }
  if (attached_pid_ == 0) {
    return QStringLiteral("模块已加载（未附加进程）");
  }
  if (plugin_force_builtin_fallback_) {
    return QStringLiteral("已手动回退到内置provider");
  }
  if (provider.fused) {
    const QString reason = ToQString(provider.last_error).trimmed();
    return reason.isEmpty() ? QStringLiteral("已熔断回退到内置provider")
                            : QStringLiteral("已熔断回退: %1").arg(reason);
  }
  const QString provider_id = ToQString(provider.provider_id).trimmed();
  if (!provider.configured_enabled) {
    return QStringLiteral("模块已加载（当前未启用）");
  }
  return provider_id.isEmpty() ? QStringLiteral("模块已加载并生效")
                               : QStringLiteral("模块已加载并生效 (%1)").arg(provider_id);
}

void MainWindow::UpdatePluginFailureEntryLayout() {
  if (!plugin_failure_output_button_ || !plugin_failure_output_dropdown_button_) {
    return;
  }
  constexpr int kCompactThresholdWidth = 1320;
  const bool compact = width() < kCompactThresholdWidth;
  plugin_failure_output_button_->setVisible(!compact);
  plugin_failure_output_dropdown_button_->setVisible(compact);
}

void MainWindow::UpdatePluginProviderStatusPanel() {
  r3::windows_client_ng::services::ClientService::ProviderRuntimeSnapshot provider{};
  {
    const std::lock_guard<std::mutex> lock(service_mutex_);
    provider = service_.GetProviderRuntimeSnapshot();
  }
  plugin_loaded_count_ = plugin_catalog_.LastLoadedCount();
  if (plugin_loaded_count_ < static_cast<int>(plugin_catalog_.Plugins().size())) {
    plugin_loaded_count_ = static_cast<int>(plugin_catalog_.Plugins().size());
  }
  const double avg_ms = static_cast<double>(provider.avg_elapsed_us) / 1000.0;
  if (plugin_runtime_window_) {
    plugin_runtime_window_->SetRuntimeState(BuildPluginModuleStateText(provider),
                                            plugin_loaded_count_,
                                            plugin_load_failed_count_,
                                            avg_ms,
                                            plugin_force_builtin_fallback_);
  }
  SyncPluginFailureOutputWindow();
}

void MainWindow::RecordPluginLoadFailure(const QString& text) {
  const QString line = text.trimmed();
  if (line.isEmpty()) {
    return;
  }
  if (!plugin_load_failure_messages_.isEmpty() && plugin_load_failure_messages_.back() == line) {
    return;
  }
  plugin_load_failure_messages_.push_back(line);
  while (plugin_load_failure_messages_.size() > 200) {
    plugin_load_failure_messages_.removeFirst();
  }
  plugin_load_failed_count_ = static_cast<int>(plugin_load_failure_messages_.size());
}

void MainWindow::SyncPluginFailureOutputWindow() {
  r3::windows_client_ng::services::ClientService::ProviderRuntimeSnapshot provider{};
  {
    const std::lock_guard<std::mutex> lock(service_mutex_);
    provider = service_.GetProviderRuntimeSnapshot();
  }
  const double avg_ms = static_cast<double>(provider.avg_elapsed_us) / 1000.0;
  const QString btn_text =
      plugin_load_failed_count_ > 0
          ? QStringLiteral("插件加载失败输出 (%1)").arg(plugin_load_failed_count_)
          : QStringLiteral("插件加载失败输出");
  if (plugin_failure_output_button_) {
    plugin_failure_output_button_->setText(btn_text);
  }
  if (plugin_failure_output_dropdown_button_) {
    const QString compact_text =
        plugin_load_failed_count_ > 0 ? QStringLiteral("插件输出 (%1)").arg(plugin_load_failed_count_)
                                      : QStringLiteral("插件输出");
    plugin_failure_output_dropdown_button_->setText(compact_text);
    plugin_failure_output_dropdown_button_->setToolTip(btn_text);
  }
  if (action_plugin_failure_output_) {
    action_plugin_failure_output_->setText(btn_text);
  }
  if (plugin_failure_window_) {
    plugin_failure_window_->SetSummary(plugin_loaded_count_, plugin_load_failed_count_, avg_ms);
    plugin_failure_window_->SetFailureMessages(plugin_load_failure_messages_);
  }
  UpdatePluginFailureEntryLayout();
}

bool MainWindow::RunPluginSelfCheck(QString* out_report) {
  if (out_report) {
    out_report->clear();
  }
  if (!EnsureConnected() || attached_pid_ == 0) {
    if (out_report) {
      *out_report = QStringLiteral("未连接或未附加进程");
    }
    return false;
  }

  uint64_t read_addr = 0;
  uint64_t write_addr = 0;
  {
    std::vector<r3::windows_client_ng::services::ClientService::ModuleInfo> modules;
    std::string error;
    bool ok = false;
    {
      const std::lock_guard<std::mutex> lock(service_mutex_);
      ok = service_.FetchModules(attached_pid_, &modules, &error);
    }
    if (!ok || modules.empty()) {
      if (out_report) {
        *out_report = ok ? QStringLiteral("模块列表为空") : QStringLiteral("获取模块失败: %1").arg(ToQString(error));
      }
      return false;
    }
    for (const auto& m : modules) {
      if ((m.perms & protocol::MODULE_PERM_READ) && m.start != 0) {
        read_addr = m.start;
        break;
      }
    }
    for (const auto& m : modules) {
      if ((m.perms & protocol::MODULE_PERM_READ) && (m.perms & protocol::MODULE_PERM_WRITE) && m.start != 0) {
        write_addr = m.start;
        break;
      }
    }
  }
  if (read_addr == 0) {
    if (out_report) {
      *out_report = QStringLiteral("未找到可读地址用于自检");
    }
    return false;
  }

  QStringList lines;
  bool all_ok = true;
  std::vector<uint8_t> read4;
  {
    std::string error;
    bool ok = false;
    {
      const std::lock_guard<std::mutex> lock(service_mutex_);
      ok = service_.ReadMemory(read_addr, 4, true, &read4, &error);
    }
    lines << QStringLiteral("[read smoke] %1  addr=%2")
                 .arg(ok ? QStringLiteral("OK") : QStringLiteral("FAIL"))
                 .arg(Hex64(read_addr));
    if (!ok) {
      all_ok = false;
      lines << QStringLiteral("  error: %1").arg(ToQString(error));
    }
  }

  {
    const std::lock_guard<std::mutex> lock(service_mutex_);
    auto cfg = service_.GetCustomMemoryProviderConfig();
    if (cfg.enabled) {
      const int32_t old_read = cfg.syscall_read;
      cfg.syscall_read = -1;
      cfg.allow_fallback = true;
      service_.SetCustomMemoryProviderConfig(cfg);

      std::vector<uint8_t> data;
      std::string error;
      const bool ok = service_.ReadMemory(read_addr, 4, true, &data, &error);
      lines << QStringLiteral("[fallback smoke] %1  addr=%2")
                   .arg(ok ? QStringLiteral("OK") : QStringLiteral("FAIL"))
                   .arg(Hex64(read_addr));
      if (!ok) {
        all_ok = false;
        lines << QStringLiteral("  error: %1").arg(ToQString(error));
      }
      cfg.syscall_read = old_read;
      service_.SetCustomMemoryProviderConfig(cfg);
    } else {
      lines << QStringLiteral("[fallback smoke] SKIP (插件provider未启用)");
    }
  }

  if (write_addr != 0 && !read4.empty()) {
    std::string error;
    bool ok = false;
    {
      const std::lock_guard<std::mutex> lock(service_mutex_);
      ok = service_.WriteMemory(write_addr, read4, &error);
    }
    lines << QStringLiteral("[write smoke] %1  addr=%2")
                 .arg(ok ? QStringLiteral("OK") : QStringLiteral("FAIL"))
                 .arg(Hex64(write_addr));
    if (!ok) {
      all_ok = false;
      lines << QStringLiteral("  error: %1").arg(ToQString(error));
    }
  } else {
    lines << QStringLiteral("[write smoke] SKIP (未找到可写地址)");
  }

  if (out_report) {
    *out_report = lines.join('\n');
  }
  return all_ok;
}

void MainWindow::UpdateConnectionUi() {
  if (action_connect_) {
    action_connect_->setText(connected_ ? QStringLiteral("断开") : QStringLiteral("连接"));
  }
}

void MainWindow::UpdateStatus(const QString& text) { statusBar()->showMessage(text, 6000); }

bool MainWindow::EnsureConnected() {
  if (connected_) {
    return true;
  }
  return ConnectToService(host_edit_->text(), static_cast<uint16_t>(port_spin_->value()));
}

bool MainWindow::ConnectToService(const QString& host, uint16_t port) {
  std::string error;
  bool ok = false;
  r3::windows_client_ng::services::ClientService::AgentCapabilities caps{};
  bool caps_ok = false;
  {
    const std::lock_guard<std::mutex> lock(service_mutex_);
    ok = service_.Connect(ToStdString(host), port, &error);
    if (ok) {
      std::string cap_error;
      caps_ok = service_.FetchCapabilities(&caps, &cap_error);
      if (!caps_ok && !cap_error.empty()) {
        error = cap_error;
      }
    }
  }
  connected_ = ok;
  UpdateConnectionUi();
  if (!ok) {
    UpdateStatus(QStringLiteral("连接失败: %1").arg(ToQString(error)));
    return false;
  }
  ApplyCustomProviderConfig();
  UpdatePluginProviderStatusPanel();
  if (caps_ok) {
    UpdateStatus(QStringLiteral("已连接 %1:%2  协议v%3  能力=0x%4")
                     .arg(host)
                     .arg(port)
                     .arg(caps.protocol_version)
                     .arg(QString::number(static_cast<qulonglong>(caps.flags), 16)));
  } else {
    UpdateStatus(QStringLiteral("已连接 %1:%2（能力协商失败，按兼容模式运行）").arg(host).arg(port));
  }

  // Prime process list synchronously so first picker open is instant.
  std::vector<r3::windows_client_ng::services::ProcessInfo> prefetched_processes;
  bool prefetched_ok = false;
  {
    const std::lock_guard<std::mutex> lock(service_mutex_);
    std::string prefetch_error;
    prefetched_ok = service_.FetchProcesses(&prefetched_processes, &prefetch_error);
  }
  if (prefetched_ok) {
    process_cache_ = std::move(prefetched_processes);
    process_cache_ready_ = !process_cache_.empty();
    ++process_cache_generation_;
    SyncProcessDialogFromCache();
    return true;
  }

  struct ProcessPrefetchResult {
    bool ok = false;
    std::vector<r3::windows_client_ng::services::ProcessInfo> processes;
  };
  auto* process_prefetch = new QFutureWatcher<ProcessPrefetchResult>(this);
  connect(process_prefetch, &QFutureWatcher<ProcessPrefetchResult>::finished, this, [this, process_prefetch]() {
    const ProcessPrefetchResult result = process_prefetch->result();
    if (connected_ && result.ok) {
      process_cache_ = result.processes;
      process_cache_ready_ = !process_cache_.empty();
      ++process_cache_generation_;
      SyncProcessDialogFromCache();
    }
    process_prefetch->deleteLater();
  });
  process_prefetch->setFuture(QtConcurrent::run([this]() {
    ProcessPrefetchResult result;
    std::string error;
    {
      const std::lock_guard<std::mutex> lock(service_mutex_);
      result.ok = service_.FetchProcesses(&result.processes, &error);
    }
    return result;
  }));
  return true;
}

void MainWindow::DisconnectService() {
  DumpTelemetrySnapshot(QStringLiteral("disconnect"));
  {
    const std::lock_guard<std::mutex> lock(service_mutex_);
    service_.Disconnect();
  }
  connected_ = false;
  attached_pid_ = 0;
  attached_process_name_.clear();
  process_cache_.clear();
  process_cache_ready_ = false;
  process_cache_generation_ = 0;
  process_dialog_generation_ = 0;
  module_cache_.clear();
  module_cache_pid_ = 0;
  module_cache_ready_ = false;
  if (process_label_) {
    process_label_->setText(QStringLiteral("未选择进程"));
  }
  UpdateConnectionUi();
  UpdatePluginProviderStatusPanel();
}

void MainWindow::OnConnectClicked() {
  if (connected_) {
    DisconnectService();
    UpdateStatus(QStringLiteral("已断开连接"));
    return;
  }
  ConnectToService(host_edit_->text(), static_cast<uint16_t>(port_spin_->value()));
}

bool MainWindow::AttachProcess(uint32_t pid, const QString& name) {
  if (!EnsureConnected()) {
    return false;
  }
  std::string error;
  bool ok = false;
  {
    const std::lock_guard<std::mutex> lock(service_mutex_);
    ok = service_.Attach(pid, &error);
  }
  if (!ok) {
    QMessageBox::warning(this, QStringLiteral("附加失败"), ToQString(error));
    return false;
  }
  attached_pid_ = pid;
  attached_process_name_ = name;
  module_cache_.clear();
  module_cache_pid_ = pid;
  module_cache_ready_ = false;
  process_label_->setText(QStringLiteral("PID %1 - %2").arg(pid).arg(name));
  UpdateStatus(QStringLiteral("已附加 %1").arg(name));

  struct ModulePrefetchResult {
    bool ok = false;
    std::vector<r3::windows_client_ng::services::ClientService::ModuleInfo> modules;
  };
  auto* module_prefetch = new QFutureWatcher<ModulePrefetchResult>(this);
  const uint32_t target_pid = pid;
  connect(module_prefetch, &QFutureWatcher<ModulePrefetchResult>::finished, this, [this, module_prefetch, target_pid]() {
    const ModulePrefetchResult result = module_prefetch->result();
    if (result.ok && attached_pid_ == target_pid) {
      module_cache_ = result.modules;
      module_cache_pid_ = target_pid;
      module_cache_ready_ = !module_cache_.empty();
    }
    module_prefetch->deleteLater();
  });
  module_prefetch->setFuture(QtConcurrent::run([this, target_pid]() {
    ModulePrefetchResult result;
    std::string error;
    {
      const std::lock_guard<std::mutex> lock(service_mutex_);
      result.ok = service_.FetchModules(target_pid, &result.modules, &error);
    }
    return result;
  }));
  return true;
}

void MainWindow::OnSelectProcessClicked() { RefreshProcessListAndOpenDialog(); }

void MainWindow::RefreshProcessListAndOpenDialog() {
  if (!EnsureConnected()) {
    return;
  }
  EnsureProcessDialog();
  if (!process_dialog_) {
    return;
  }
  const bool resume_address_timer = address_timer_ && address_timer_->isActive();
  if (resume_address_timer) {
    address_timer_->stop();
  }
  auto* dialog = process_dialog_;
  dialog->SetLoading(true);
  dialog->SetBusyText(QStringLiteral("正在获取进程列表..."));

  const bool has_cached_processes = process_cache_ready_ && !process_cache_.empty();
  if (has_cached_processes) {
    SyncProcessDialogFromCache();
    dialog->SetLoading(false);
    dialog->SetBusyText(QStringLiteral("已加载缓存: %1 项").arg(process_cache_.size()));
  }

  struct FetchResult {
    bool ok = false;
    QString error;
    std::vector<r3::windows_client_ng::services::ProcessInfo> processes;
  };
  if (!has_cached_processes) {
    QFutureWatcher<FetchResult> fetch_watcher(dialog);
    connect(&fetch_watcher,
            &QFutureWatcher<FetchResult>::finished,
            dialog,
            [this, dialog, &fetch_watcher]() {
      const FetchResult result = fetch_watcher.result();
      dialog->SetLoading(false);
      if (!result.ok) {
        if (process_cache_ready_ && !process_cache_.empty()) {
          dialog->SetBusyText(QStringLiteral("刷新失败，已保留缓存结果"));
        } else {
          dialog->SetBusyText(QStringLiteral("获取进程失败"));
          QMessageBox::warning(dialog, QStringLiteral("进程列表"), result.error);
        }
        return;
      }

      process_cache_ = result.processes;
      process_cache_ready_ = true;
      ++process_cache_generation_;
      SyncProcessDialogFromCache();
      dialog->SetBusyText(QStringLiteral("已更新: %1 项").arg(process_cache_.size()));
    });
    fetch_watcher.setFuture(QtConcurrent::run([this]() {
      FetchResult result;
      std::string error;
      {
        const std::lock_guard<std::mutex> lock(service_mutex_);
        result.ok = service_.FetchProcesses(&result.processes, &error);
      }
      if (!result.ok) {
        result.error = ToQString(error);
      }
      return result;
    }));
  }

  const int dialog_result = dialog->exec();
  if (resume_address_timer && address_timer_) {
    address_timer_->start();
  }
  if (dialog_result != QDialog::Accepted) {
    return;
  }
  const auto selected = dialog->SelectedProcess();
  if (!selected.has_value()) {
    return;
  }
  AttachProcess(selected->pid, selected->name);

  const uint32_t selected_pid = selected->pid;
  (void)QtConcurrent::run([this, selected_pid]() {
    std::vector<uint8_t> png;
    std::string error;
    bool ok = false;
    {
      const std::lock_guard<std::mutex> lock(service_mutex_);
      ok = service_.FetchProcessIcon(selected_pid, 48, &png, &error);
    }
    if (!ok || png.empty()) {
      return;
    }
    SaveCachedIcon(selected_pid, QByteArray(reinterpret_cast<const char*>(png.data()), static_cast<int>(png.size())));
  });
}
uint16_t MainWindow::BuildScanFlags() const {
  uint16_t flags = 0;
  if (flag_use_pvm_check_->isChecked()) flags |= protocol::SCAN_FLAG_USE_PVM;
  if (flag_writable_check_->isChecked()) flags |= protocol::SCAN_FLAG_REQUIRE_WRITABLE;
  if (flag_exec_check_->isChecked()) flags |= protocol::SCAN_FLAG_REQUIRE_EXEC;
  if (flag_private_check_->isChecked()) flags |= protocol::SCAN_FLAG_REQUIRE_PRIVATE;
  if (flag_image_check_->isChecked()) flags |= protocol::SCAN_FLAG_REQUIRE_IMAGE;
  if (flag_mapped_check_->isChecked()) flags |= protocol::SCAN_FLAG_REQUIRE_MAPPED;
  const int region_code = scan_region_combo_->currentData().toInt();
  if (region_code > 0) {
    flags = static_cast<uint16_t>(flags | ((region_code << protocol::SCAN_FLAG_GG_SHIFT) & protocol::SCAN_FLAG_GG_MASK));
  }
  return flags;
}

protocol::ValueType MainWindow::CurrentScanValueType() const {
  return static_cast<protocol::ValueType>(scan_value_type_combo_->currentData().toInt());
}

protocol::ComparisonType MainWindow::CurrentComparisonType() const {
  return static_cast<protocol::ComparisonType>(scan_compare_combo_->currentData().toInt());
}

void MainWindow::OnFirstScanClicked() {
  StartScan(true);
}

void MainWindow::OnNextScanClicked() {
  StartScan(false);
}

void MainWindow::OnUndoScanClicked() {
  if (scan_in_flight_) {
    UpdateStatus(QStringLiteral("扫描进行中，请稍候"));
    return;
  }
  scan_total_ = 0;
  current_scan_addresses_.clear();
  previous_scan_values_.clear();
  scan_model_->removeRows(0, scan_model_->rowCount());
  UpdateStatus(QStringLiteral("扫描结果已清空"));
}

void MainWindow::SetScanBusy(bool busy) {
  if (first_scan_button_) {
    first_scan_button_->setEnabled(!busy);
  }
  if (next_scan_button_) {
    next_scan_button_->setEnabled(!busy);
  }
  if (undo_scan_button_) {
    undo_scan_button_->setEnabled(!busy);
  }
}

void MainWindow::StartScan(bool first_scan) {
  if (scan_in_flight_) {
    UpdateStatus(QStringLiteral("扫描进行中，请稍候"));
    return;
  }
  if (!EnsureConnected() || attached_pid_ == 0) {
    QMessageBox::information(this, QStringLiteral("扫描"), QStringLiteral("请先连接并选择进程"));
    return;
  }
  bool ok_start = true;
  bool ok_end = true;
  const uint64_t start = ParseAddressText(scan_start_edit_->text(), &ok_start);
  const uint64_t end = ParseAddressText(scan_end_edit_->text(), &ok_end);
  const protocol::ValueType vt = CurrentScanValueType();
  const protocol::ComparisonType cmp = CurrentComparisonType();
  if (!ok_start || !ok_end) {
    QMessageBox::warning(this, QStringLiteral("扫描"), QStringLiteral("地址格式无效"));
    return;
  }
  if ((vt == protocol::ValueType::STRING || vt == protocol::ValueType::AOB || vt == protocol::ValueType::BINARY || vt == protocol::ValueType::ALL) &&
      !(cmp == protocol::ComparisonType::EQ || cmp == protocol::ComparisonType::NE)) {
    QMessageBox::warning(this, QStringLiteral("扫描"), QStringLiteral("String/AOB/Binary/All 仅支持 = 与 !="));
    return;
  }

  struct ScanTaskRequest {
    bool first = true;
    protocol::ValueType value_type = protocol::ValueType::U32;
    protocol::ComparisonType compare = protocol::ComparisonType::EQ;
    std::string value_text;
    bool value_hex = false;
    uint16_t flags = 0;
    uint64_t start = 0;
    uint64_t end = 0;
  };
  ScanTaskRequest req;
  req.first = first_scan;
  req.value_type = vt;
  req.compare = cmp;
  req.value_text = ToStdString(scan_value_edit_->text());
  req.value_hex = scan_hex_check_->isChecked();
  req.flags = BuildScanFlags();
  req.start = start;
  req.end = end;

  if (first_scan) {
    previous_scan_values_.clear();
  } else {
    previous_scan_values_.clear();
    for (int row = 0; row < scan_model_->rowCount(); ++row) {
      const uint64_t addr = scan_model_->data(scan_model_->index(row, 0), kAddressRole).toULongLong();
      if (addr == 0) {
        continue;
      }
      const QString current_text = scan_model_->data(scan_model_->index(row, 1)).toString().trimmed();
      if (current_text.isEmpty() || current_text == QStringLiteral("-")) {
        continue;
      }
      previous_scan_values_[addr] = current_text;
    }
  }

  scan_in_flight_ = true;
  scan_task_is_first_ = first_scan;
  SetScanBusy(true);
  UpdateStatus(first_scan ? QStringLiteral("正在首次扫描...") : QStringLiteral("正在再次扫描..."));

  const auto future = QtConcurrent::run([this, req]() {
    ScanTaskResult result;
    std::string error;
    bool ok = false;
    {
      const std::lock_guard<std::mutex> lock(service_mutex_);
      if (req.first) {
        ok = service_.ScanFirst(req.value_type,
                                req.compare,
                                req.value_text,
                                req.value_hex,
                                req.flags,
                                req.start,
                                req.end,
                                &result.total,
                                &result.addresses,
                                &error);
      } else {
        ok = service_.ScanNext(req.value_type,
                               req.compare,
                               req.value_text,
                               req.value_hex,
                               req.flags,
                               req.start,
                               req.end,
                               &result.total,
                               &result.addresses,
                               &error);
      }
    }
    result.ok = ok;
    if (!ok) {
      result.error = QString::fromUtf8(error.c_str());
    }
    return result;
  });
  scan_watcher_.setFuture(future);
}

void MainWindow::OnScanTaskFinished() {
  scan_in_flight_ = false;
  SetScanBusy(false);

  const ScanTaskResult result = scan_watcher_.result();
  if (!result.ok) {
    QMessageBox::warning(this,
                         scan_task_is_first_ ? QStringLiteral("首次扫描失败") : QStringLiteral("再次扫描失败"),
                         result.error);
    return;
  }
  scan_total_ = result.total;
  current_scan_addresses_ = result.addresses;
  PopulateScanResultRows(current_scan_addresses_, scan_total_);
}

void MainWindow::PopulateScanResultRows(const std::vector<uint64_t>& addresses, uint64_t total) {
  scan_model_->removeRows(0, scan_model_->rowCount());
  std::vector<uint64_t> rows = addresses;
  if (rows.empty() && total > 0 && EnsureConnected()) {
    std::vector<uint64_t> page;
    std::string error;
    uint64_t page_total = 0;
    {
      const std::lock_guard<std::mutex> lock(service_mutex_);
      if (service_.ScanPage(0, 256, &page_total, &page, &error)) {
        rows.swap(page);
        total = page_total;
      }
    }
  }
  scan_model_->setRowCount(static_cast<int>(rows.size()));
  const protocol::ValueType vt = CurrentScanValueType();
  const uint32_t value_size = ValueTypeByteSize(vt);
  for (int i = 0; i < static_cast<int>(rows.size()); ++i) {
    const uint64_t addr = rows[static_cast<size_t>(i)];
    auto* c0 = new QStandardItem(Hex64(addr));
    c0->setData(static_cast<qulonglong>(addr), kAddressRole);
    auto* c1 = new QStandardItem(QStringLiteral("-"));
    auto* c2 = new QStandardItem(QStringLiteral("-"));
    c0->setTextAlignment(Qt::AlignRight | Qt::AlignVCenter);
    c1->setTextAlignment(Qt::AlignRight | Qt::AlignVCenter);
    c2->setTextAlignment(Qt::AlignRight | Qt::AlignVCenter);
    scan_model_->setItem(i, 0, c0);
    scan_model_->setItem(i, 1, c1);
    scan_model_->setItem(i, 2, c2);
  }

  std::vector<QString> current_values(rows.size(), QStringLiteral("-"));
  if (value_size > 0 && !rows.empty()) {
    static constexpr size_t kBatchLimit = 128;
    for (size_t begin = 0; begin < rows.size(); begin += kBatchLimit) {
      const size_t end = (std::min)(rows.size(), begin + kBatchLimit);

      std::vector<r3::windows_client_ng::services::ClientService::ReadRange> ranges;
      ranges.reserve(end - begin);
      for (size_t i = begin; i < end; ++i) {
        ranges.push_back(r3::windows_client_ng::services::ClientService::ReadRange{rows[i], value_size});
      }

      std::vector<std::vector<uint8_t>> buffers;
      std::string error;
      bool ok = false;
      {
        const std::lock_guard<std::mutex> lock(service_mutex_);
        ok = service_.ReadMemoryBatch(ranges, protocol::READ_FLAG_USE_PVM, &buffers, &error);
      }
      if (ok && buffers.size() == (end - begin)) {
        for (size_t i = begin; i < end; ++i) {
          current_values[i] = FormatValueText(vt, buffers[i - begin]);
        }
        continue;
      }

      for (size_t i = begin; i < end; ++i) {
        std::vector<uint8_t> bytes;
        std::string single_error;
        bool single_ok = false;
        {
          const std::lock_guard<std::mutex> lock(service_mutex_);
          single_ok = service_.ReadMemory(rows[i], value_size, true, &bytes, &single_error);
        }
        if (single_ok && !bytes.empty()) {
          current_values[i] = FormatValueText(vt, bytes);
        }
      }
    }
  }

  for (int i = 0; i < static_cast<int>(rows.size()); ++i) {
    const QString current = current_values[static_cast<size_t>(i)];
    scan_model_->setData(scan_model_->index(i, 1), current);

    QString previous = current;
    if (!scan_task_is_first_) {
      const auto it = previous_scan_values_.find(rows[static_cast<size_t>(i)]);
      if (it != previous_scan_values_.end()) {
        previous = it->second;
      }
    }
    scan_model_->setData(scan_model_->index(i, 2), previous);
  }
  UpdateStatus(QStringLiteral("匹配 %1 条，当前页 %2").arg(total).arg(rows.size()));
}
void MainWindow::OnScanResultDoubleClicked(const QModelIndex& index) {
  if (!index.isValid()) {
    return;
  }
  const bool alt = QApplication::keyboardModifiers().testFlag(Qt::AltModifier);
  const auto addr = SelectedScanAddress();
  if (!addr.has_value()) {
    return;
  }
  if (alt) {
    OpenMemoryViewAt(*addr);
  } else {
    AddAddressEntry(*addr, false);
  }
}

std::optional<uint64_t> MainWindow::SelectedScanAddress() const {
  const QModelIndex idx = scan_table_->currentIndex();
  if (!idx.isValid()) return std::nullopt;
  const auto value = scan_model_->data(idx.sibling(idx.row(), 0), kAddressRole).toULongLong();
  if (value == 0) return std::nullopt;
  return static_cast<uint64_t>(value);
}

std::optional<uint64_t> MainWindow::SelectedAddressListAddress() const {
  const QModelIndex idx = address_table_->currentIndex();
  if (!idx.isValid()) return std::nullopt;
  const auto value = address_model_->data(idx.sibling(idx.row(), 3), kAddressRole).toULongLong();
  if (value == 0) return std::nullopt;
  return static_cast<uint64_t>(value);
}

void MainWindow::AddAddressEntry(uint64_t address, bool open_editor) {
  const int row = address_model_->rowCount();
  address_model_->setRowCount(row + 1);

  auto* c0 = new QStandardItem();
  c0->setCheckable(true);
  c0->setCheckState(Qt::Checked);
  auto* c1 = new QStandardItem();
  c1->setCheckable(true);
  auto* c2 = new QStandardItem(QStringLiteral("地址_%1").arg(row + 1));
  auto* c3 = new QStandardItem(Hex64(address));
  c3->setData(static_cast<qulonglong>(address), kAddressRole);
  const protocol::ValueType vt = CurrentScanValueType();
  auto* c4 = new QStandardItem(ValueTypeDisplayName(vt));
  c4->setData(static_cast<int>(vt), kTypeRole);
  auto* c5 = new QStandardItem(scan_value_edit_->text());
  c3->setTextAlignment(Qt::AlignRight | Qt::AlignVCenter);
  c5->setTextAlignment(Qt::AlignRight | Qt::AlignVCenter);

  address_model_->setItem(row, 0, c0);
  address_model_->setItem(row, 1, c1);
  address_model_->setItem(row, 2, c2);
  address_model_->setItem(row, 3, c3);
  address_model_->setItem(row, 4, c4);
  address_model_->setItem(row, 5, c5);

  const QModelIndex value_idx = address_model_->index(row, 5);
  address_table_->setCurrentIndex(value_idx);
  if (open_editor) {
    address_table_->edit(value_idx);
  }
}

void MainWindow::OnScanContextMenuRequested(const QPoint& pos) {
  QMenu menu(this);
  QAction* add = menu.addAction(QStringLiteral("添加到地址列表"));
  QAction* add_batch = menu.addAction(QStringLiteral("批量添加选中项"));
  QAction* add_edit = menu.addAction(QStringLiteral("添加并编辑"));
  QAction* open_mem = menu.addAction(QStringLiteral("在 Memory View 打开"));
  QAction* copy_addr = menu.addAction(QStringLiteral("复制地址"));
  QAction* copy_addr_val = menu.addAction(QStringLiteral("复制地址+当前值"));

  QAction* picked = menu.exec(scan_table_->viewport()->mapToGlobal(pos));
  if (!picked) return;
  const auto addr = SelectedScanAddress();
  if (!addr.has_value()) return;

  if (picked == add) {
    AddAddressEntry(*addr, false);
  } else if (picked == add_batch) {
    const auto rows = scan_table_->selectionModel()->selectedRows();
    for (const QModelIndex& idx : rows) {
      const auto v = scan_model_->data(idx.sibling(idx.row(), 0), kAddressRole).toULongLong();
      if (v != 0) {
        AddAddressEntry(static_cast<uint64_t>(v), false);
      }
    }
  } else if (picked == add_edit) {
    AddAddressEntry(*addr, true);
  } else if (picked == open_mem) {
    OpenMemoryViewAt(*addr);
  } else if (picked == copy_addr) {
    QApplication::clipboard()->setText(Hex64(*addr));
  } else if (picked == copy_addr_val) {
    const QString value = scan_model_->data(scan_table_->currentIndex().sibling(scan_table_->currentIndex().row(), 1)).toString();
    QApplication::clipboard()->setText(QStringLiteral("%1 | %2").arg(Hex64(*addr), value));
  }
}

void MainWindow::OnAddressContextMenuRequested(const QPoint& pos) {
  QMenu menu(this);
  QAction* edit_value = menu.addAction(QStringLiteral("修改数值"));
  QAction* jump_mem = menu.addAction(QStringLiteral("跳转 Memory View"));
  QAction* freeze_selected = menu.addAction(QStringLiteral("批量冻结"));
  QAction* unfreeze_selected = menu.addAction(QStringLiteral("批量解冻"));
  QAction* copy_row = menu.addAction(QStringLiteral("复制完整条目"));
  QAction* del = menu.addAction(QStringLiteral("删除选中"));
  QAction* picked = menu.exec(address_table_->viewport()->mapToGlobal(pos));
  if (!picked) return;

  const QModelIndex cur = address_table_->currentIndex();
  if (!cur.isValid()) return;
  if (picked == edit_value) {
    address_table_->edit(address_model_->index(cur.row(), 5));
  } else if (picked == jump_mem) {
    const auto addr = SelectedAddressListAddress();
    if (addr.has_value()) OpenMemoryViewAt(*addr);
  } else if (picked == freeze_selected) {
    const auto rows = address_table_->selectionModel()->selectedRows();
    for (const QModelIndex& idx : rows) {
      if (auto* item = address_model_->item(idx.row(), 1)) {
        item->setCheckState(Qt::Checked);
      }
    }
  } else if (picked == unfreeze_selected) {
    const auto rows = address_table_->selectionModel()->selectedRows();
    for (const QModelIndex& idx : rows) {
      if (auto* item = address_model_->item(idx.row(), 1)) {
        item->setCheckState(Qt::Unchecked);
      }
    }
  } else if (picked == copy_row) {
    const QString text = QStringLiteral("%1 | %2 | %3")
                             .arg(address_model_->data(address_model_->index(cur.row(), 3)).toString())
                             .arg(address_model_->data(address_model_->index(cur.row(), 4)).toString())
                             .arg(address_model_->data(address_model_->index(cur.row(), 5)).toString());
    QApplication::clipboard()->setText(text);
  } else if (picked == del) {
    const auto rows = address_table_->selectionModel()->selectedRows();
    QList<int> ids;
    for (const QModelIndex& idx : rows) ids.push_back(idx.row());
    std::sort(ids.begin(), ids.end(), std::greater<int>());
    for (int row : ids) address_model_->removeRow(row);
  }
}

void MainWindow::OnQuickAddSelected() {
  const auto addr = SelectedScanAddress();
  if (!addr.has_value()) {
    return;
  }
  AddAddressEntry(*addr, false);
}

void MainWindow::OnQuickAddAndEditSelected() {
  const auto addr = SelectedScanAddress();
  if (!addr.has_value()) {
    return;
  }
  AddAddressEntry(*addr, true);
}

void MainWindow::OnOpenMemoryViewClicked() {
  auto addr = SelectedScanAddress();
  if (!addr.has_value()) addr = SelectedAddressListAddress();
  if (!addr.has_value()) addr = static_cast<uint64_t>(0x1000);
  OpenMemoryViewAt(*addr);
}

void MainWindow::OpenMemoryViewAt(uint64_t address) {
  EnsureMemoryViewWindow();
  memory_view_->SetService(&service_, &service_mutex_, attached_pid_);
  memory_view_->SetPluginRuntime(&plugin_runtime_);
  memory_view_->show();
  memory_view_->raise();
  memory_view_->activateWindow();
  memory_view_->JumpToAddress(address);
}

void MainWindow::OnOpenModuleRangeClicked() {
  if (!EnsureConnected() || attached_pid_ == 0) {
    QMessageBox::information(this, QStringLiteral("模块范围"), QStringLiteral("请先连接并选择进程"));
    return;
  }
  ModuleRangeDialog dialog(this);

  if (module_cache_ready_ && module_cache_pid_ == attached_pid_ && !module_cache_.empty()) {
    dialog.SetModules(module_cache_);
    dialog.SetFooterText(QStringLiteral("可选模块: %1 / %1（缓存）").arg(module_cache_.size()));
  } else {
    dialog.SetModules({});
    dialog.SetFooterText(QStringLiteral("正在加载模块范围..."));
  }

  struct FetchResult {
    bool ok = false;
    QString error;
    std::vector<r3::windows_client_ng::services::ClientService::ModuleInfo> modules;
  };
  QFutureWatcher<FetchResult> fetch_watcher(&dialog);
  const uint32_t target_pid = attached_pid_;
  connect(&fetch_watcher, &QFutureWatcher<FetchResult>::finished, &dialog, [this, &dialog, &fetch_watcher, target_pid]() {
    const FetchResult result = fetch_watcher.result();
    if (!result.ok) {
      if (module_cache_ready_ && module_cache_pid_ == target_pid && !module_cache_.empty()) {
        dialog.SetFooterText(QStringLiteral("模块刷新失败，当前显示缓存"));
      } else {
        dialog.SetFooterText(QStringLiteral("模块加载失败"));
        QMessageBox::warning(&dialog, QStringLiteral("模块范围"), result.error);
      }
      return;
    }
    module_cache_ = result.modules;
    module_cache_pid_ = target_pid;
    module_cache_ready_ = true;
    dialog.SetModules(module_cache_);
  });

  fetch_watcher.setFuture(QtConcurrent::run([this, target_pid]() {
    FetchResult result;
    std::string error;
    {
      const std::lock_guard<std::mutex> lock(service_mutex_);
      result.ok = service_.FetchModules(target_pid, &result.modules, &error);
    }
    if (!result.ok) {
      result.error = ToQString(error);
    }
    return result;
  }));

  if (dialog.exec() != QDialog::Accepted) return;
  const auto range = dialog.SelectedRange();
  if (!range.has_value()) return;
  scan_start_edit_->setText(Hex64(range->start));
  scan_end_edit_->setText(Hex64(range->end));
}

void MainWindow::OnOpenSettingsClicked() {
  SettingsDialog dialog(this);
  dialog.SetPluginSectionVisible(false);
  SettingsDialog::SettingsData data;
  data.host = host_edit_->text();
  data.port = static_cast<uint16_t>(port_spin_->value());
  data.adb_path = adb_path_edit_->text();
  data.auto_start = auto_start_check_->isChecked();
  data.default_value_type = scan_value_type_combo_->currentIndex();
  data.default_compare_type = scan_compare_combo_->currentIndex();
  data.value_refresh_ms = address_timer_ ? address_timer_->interval() : 450;
  dialog.SetData(data);
  if (dialog.exec() != QDialog::Accepted) {
    return;
  }

  const auto updated = dialog.Data();
  host_edit_->setText(updated.host);
  port_spin_->setValue(static_cast<int>(updated.port));
  adb_path_edit_->setText(updated.adb_path);
  auto_start_check_->setChecked(updated.auto_start);
  if (updated.default_value_type >= 0 && updated.default_value_type < scan_value_type_combo_->count()) {
    scan_value_type_combo_->setCurrentIndex(updated.default_value_type);
  }
  if (updated.default_compare_type >= 0 && updated.default_compare_type < scan_compare_combo_->count()) {
    scan_compare_combo_->setCurrentIndex(updated.default_compare_type);
  }
  if (address_timer_) {
    address_timer_->setInterval(updated.value_refresh_ms);
  }
  SaveSettings();
  UpdateStatus(QStringLiteral("设置已更新"));
}

void MainWindow::OnPluginSelfCheckClicked() {
  QString report;
  const bool ok = RunPluginSelfCheck(&report);
  UpdatePluginProviderStatusPanel();
  QMessageBox::information(this,
                           ok ? QStringLiteral("插件自检通过") : QStringLiteral("插件自检失败"),
                           report.isEmpty() ? QStringLiteral("(无输出)") : report);
}

void MainWindow::OnPluginFallbackClicked() {
  plugin_force_builtin_fallback_ = !plugin_force_builtin_fallback_;
  ApplyCustomProviderConfig();
  UpdatePluginProviderStatusPanel();
  UpdateStatus(plugin_force_builtin_fallback_ ? QStringLiteral("已切换到内置provider")
                                              : QStringLiteral("已恢复插件provider"));
}

void MainWindow::OnOpenPointerToolsClicked() {
  OpenPointerToolsAtTab(-1);
}

void MainWindow::OnOpenPointerScanClicked() {
  OpenPointerToolsAtTab(static_cast<int>(PointerToolsDialog::kPointerScanTab));
}

void MainWindow::OnOpenPointerCompareClicked() {
  OpenPointerToolsAtTab(static_cast<int>(PointerToolsDialog::kPointerCompareTab));
}

void MainWindow::OnOpenStructureTraverseClicked() {
  OpenPointerToolsAtTab(static_cast<int>(PointerToolsDialog::kStructureTraverseTab));
}

void MainWindow::OnOpenPluginProviderClicked() {
  EnsurePluginProviderWindow();
  plugin_provider_window_->SetPluginEntries(plugin_catalog_.Plugins());

  PluginProviderWindow::ProviderSettings data;
  data.plugin_root_path = plugin_root_path_;
  data.plugin_id = plugin_selected_id_;
  data.plugin_enabled = plugin_enabled_;
  data.plugin_allow_fallback = plugin_allow_fallback_;
  data.plugin_timeout_ms = plugin_timeout_ms_;
  data.plugin_syscall_read = plugin_syscall_read_;
  data.plugin_syscall_write = plugin_syscall_write_;
  data.plugin_user_ctx_hex = plugin_user_ctx_hex_;
  plugin_provider_window_->SetData(data);

  if (plugin_provider_window_->exec() != QDialog::Accepted) {
    return;
  }

  const auto updated = plugin_provider_window_->Data();
  plugin_root_path_ = updated.plugin_root_path;
  plugin_selected_id_ = updated.plugin_id;
  plugin_enabled_ = updated.plugin_enabled;
  plugin_allow_fallback_ = updated.plugin_allow_fallback;
  plugin_timeout_ms_ = updated.plugin_timeout_ms;
  plugin_syscall_read_ = updated.plugin_syscall_read;
  plugin_syscall_write_ = updated.plugin_syscall_write;
  plugin_user_ctx_hex_ = updated.plugin_user_ctx_hex;
  plugin_force_builtin_fallback_ = false;

  ReloadPluginCatalog();
  ApplyCustomProviderConfig();
  SaveSettings();
  UpdateStatus(QStringLiteral("插件配置已更新"));
}

void MainWindow::OnOpenPluginRuntimeClicked() {
  EnsurePluginRuntimeWindow();
  UpdatePluginProviderStatusPanel();
  plugin_runtime_window_->show();
  plugin_runtime_window_->raise();
  plugin_runtime_window_->activateWindow();
}

void MainWindow::OnOpenPluginDevClicked() {
  EnsurePluginDevWindow();
  plugin_dev_window_->show();
  plugin_dev_window_->raise();
  plugin_dev_window_->activateWindow();
}

void MainWindow::OnOpenPluginFailureOutputClicked() {
  EnsurePluginFailureWindow();
  SyncPluginFailureOutputWindow();
  plugin_failure_window_->show();
  plugin_failure_window_->raise();
  plugin_failure_window_->activateWindow();
}

void MainWindow::OpenPointerToolsAtTab(int tab_index) {
  EnsurePointerToolsWindow();
  pointer_tools_->SetService(&service_, &service_mutex_, attached_pid_);
  if (tab_index >= static_cast<int>(PointerToolsDialog::kPointerScanTab) &&
      tab_index <= static_cast<int>(PointerToolsDialog::kStructureTraverseTab)) {
    pointer_tools_->OpenTab(static_cast<PointerToolsDialog::ToolTab>(tab_index));
  } else {
    pointer_tools_->setWindowTitle(QStringLiteral("指针工具"));
  }
  pointer_tools_->show();
  pointer_tools_->raise();
  pointer_tools_->activateWindow();
}

void MainWindow::EnsureMemoryViewWindow() {
  if (memory_view_) {
    return;
  }
  memory_view_ = new MemoryViewWindow(this);
  memory_view_->setAttribute(Qt::WA_DeleteOnClose, false);
  memory_view_->SetService(&service_, &service_mutex_, attached_pid_);
  memory_view_->SetPluginRuntime(&plugin_runtime_);
  connect(memory_view_, &MemoryViewWindow::RequestAddAddress, this, [this](uint64_t a) { AddAddressEntry(a, false); });
  memory_view_->hide();
}

void MainWindow::EnsureProcessDialog() {
  if (process_dialog_) {
    SyncProcessDialogFromCache();
    return;
  }
  process_dialog_ = new ProcessDialog(this);
  SyncProcessDialogFromCache();
}

void MainWindow::SyncProcessDialogFromCache() {
  if (!process_dialog_ || !process_cache_ready_) {
    return;
  }
  if (process_dialog_generation_ == process_cache_generation_) {
    return;
  }
  process_dialog_->SetProcesses(process_cache_);
  process_dialog_generation_ = process_cache_generation_;
}

void MainWindow::EnsurePointerToolsWindow() {
  if (pointer_tools_) {
    return;
  }
  pointer_tools_ = new PointerToolsDialog(this);
  pointer_tools_->setAttribute(Qt::WA_DeleteOnClose, false);
  pointer_tools_->SetService(&service_, &service_mutex_, attached_pid_);
  pointer_tools_->hide();
}

void MainWindow::EnsurePluginProviderWindow() {
  if (plugin_provider_window_) {
    return;
  }
  plugin_provider_window_ = new PluginProviderWindow(this);
  plugin_provider_window_->setAttribute(Qt::WA_DeleteOnClose, false);
  connect(plugin_provider_window_,
          &PluginProviderWindow::OpenPluginDevWindowRequested,
          this,
          &MainWindow::OnOpenPluginDevClicked);
  plugin_provider_window_->hide();
}

void MainWindow::EnsurePluginRuntimeWindow() {
  if (plugin_runtime_window_) {
    return;
  }
  plugin_runtime_window_ = new PluginRuntimeWindow(this);
  plugin_runtime_window_->setAttribute(Qt::WA_DeleteOnClose, false);
  connect(plugin_runtime_window_,
          &PluginRuntimeWindow::PluginSelfCheckRequested,
          this,
          &MainWindow::OnPluginSelfCheckClicked);
  connect(plugin_runtime_window_,
          &PluginRuntimeWindow::PluginFallbackToggleRequested,
          this,
          &MainWindow::OnPluginFallbackClicked);
  UpdatePluginProviderStatusPanel();
  plugin_runtime_window_->hide();
}

void MainWindow::EnsurePluginDevWindow() {
  if (plugin_dev_window_) {
    return;
  }
  plugin_dev_window_ = new PluginDevWindow(this);
  plugin_dev_window_->setAttribute(Qt::WA_DeleteOnClose, false);
  plugin_dev_window_->hide();
}

void MainWindow::EnsurePluginFailureWindow() {
  if (plugin_failure_window_) {
    return;
  }
  plugin_failure_window_ = new PluginFailureWindow(this);
  plugin_failure_window_->setAttribute(Qt::WA_DeleteOnClose, false);
  plugin_failure_window_->hide();
}

bool MainWindow::ValueTypeFromDisplayName(const QString& text, protocol::ValueType* out_type) {
  if (!out_type) {
    return false;
  }
  const QString t = text.trimmed().toLower();
  if (t == QStringLiteral("1 byte")) {
    *out_type = protocol::ValueType::U8;
    return true;
  }
  if (t == QStringLiteral("2 bytes")) {
    *out_type = protocol::ValueType::U16;
    return true;
  }
  if (t == QStringLiteral("4 bytes")) {
    *out_type = protocol::ValueType::U32;
    return true;
  }
  if (t == QStringLiteral("8 bytes")) {
    *out_type = protocol::ValueType::U64;
    return true;
  }
  if (t.contains(QStringLiteral("signed")) && t.contains(QStringLiteral("4"))) {
    *out_type = protocol::ValueType::S32;
    return true;
  }
  if (t.contains(QStringLiteral("signed")) && t.contains(QStringLiteral("8"))) {
    *out_type = protocol::ValueType::S64;
    return true;
  }
  if (t == QStringLiteral("float")) {
    *out_type = protocol::ValueType::FLOAT;
    return true;
  }
  if (t == QStringLiteral("double")) {
    *out_type = protocol::ValueType::DOUBLE;
    return true;
  }
  if (t == QStringLiteral("string")) {
    *out_type = protocol::ValueType::STRING;
    return true;
  }
  if (t == QStringLiteral("array of byte")) {
    *out_type = protocol::ValueType::AOB;
    return true;
  }
  if (t == QStringLiteral("binary")) {
    *out_type = protocol::ValueType::BINARY;
    return true;
  }
  if (t == QStringLiteral("all")) {
    *out_type = protocol::ValueType::ALL;
    return true;
  }
  return false;
}

uint32_t MainWindow::ValueTypeByteSize(protocol::ValueType value_type) {
  switch (value_type) {
    case protocol::ValueType::U8:
      return 1;
    case protocol::ValueType::U16:
      return 2;
    case protocol::ValueType::U32:
    case protocol::ValueType::S32:
    case protocol::ValueType::FLOAT:
      return 4;
    case protocol::ValueType::U64:
    case protocol::ValueType::S64:
    case protocol::ValueType::DOUBLE:
      return 8;
    case protocol::ValueType::STRING:
    case protocol::ValueType::AOB:
    case protocol::ValueType::BINARY:
    case protocol::ValueType::ALL:
      return 32;
    default:
      return 4;
  }
}

QString MainWindow::FormatValueText(protocol::ValueType value_type, const std::vector<uint8_t>& bytes) {
  if (bytes.empty()) {
    return QStringLiteral("-");
  }
  auto read_u16 = [&bytes]() -> uint16_t {
    if (bytes.size() < 2) return 0;
    return static_cast<uint16_t>(bytes[0] | (static_cast<uint16_t>(bytes[1]) << 8));
  };
  auto read_u32 = [&bytes]() -> uint32_t {
    if (bytes.size() < 4) return 0;
    return static_cast<uint32_t>(bytes[0] | (bytes[1] << 8) | (bytes[2] << 16) | (bytes[3] << 24));
  };
  auto read_u64 = [&bytes]() -> uint64_t {
    if (bytes.size() < 8) return 0;
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i) {
      v |= (static_cast<uint64_t>(bytes[static_cast<size_t>(i)]) << (8 * i));
    }
    return v;
  };
  switch (value_type) {
    case protocol::ValueType::U8:
      return QString::number(bytes[0]);
    case protocol::ValueType::U16:
      return QString::number(read_u16());
    case protocol::ValueType::U32:
      return QString::number(read_u32());
    case protocol::ValueType::U64:
      return QString::number(static_cast<qulonglong>(read_u64()));
    case protocol::ValueType::S32:
      return QString::number(static_cast<int32_t>(read_u32()));
    case protocol::ValueType::S64:
      return QString::number(static_cast<qint64>(read_u64()));
    case protocol::ValueType::FLOAT: {
      if (bytes.size() < 4) return QStringLiteral("-");
      float v = 0.0f;
      std::memcpy(&v, bytes.data(), sizeof(float));
      return QString::number(v, 'g', 9);
    }
    case protocol::ValueType::DOUBLE: {
      if (bytes.size() < 8) return QStringLiteral("-");
      double v = 0.0;
      std::memcpy(&v, bytes.data(), sizeof(double));
      return QString::number(v, 'g', 17);
    }
    case protocol::ValueType::STRING:
      return QString::fromUtf8(reinterpret_cast<const char*>(bytes.data()), static_cast<int>(bytes.size()));
    case protocol::ValueType::AOB:
    case protocol::ValueType::BINARY:
    case protocol::ValueType::ALL: {
      QString out;
      for (size_t i = 0; i < bytes.size(); ++i) {
        if (i > 0) {
          out.append(' ');
        }
        out.append(QString::number(bytes[i], 16).toUpper().rightJustified(2, QLatin1Char('0')));
      }
      return out;
    }
    default:
      return QStringLiteral("-");
  }
}

bool MainWindow::BuildWriteBytes(protocol::ValueType value_type,
                                 const QString& value_text,
                                 std::vector<uint8_t>* out_bytes) {
  if (!out_bytes) {
    return false;
  }
  out_bytes->clear();
  const QString text = value_text.trimmed();
  bool ok = false;
  switch (value_type) {
    case protocol::ValueType::U8: {
      const int v = text.toInt(&ok, 0);
      if (!ok || v < 0 || v > 0xFF) return false;
      out_bytes->push_back(static_cast<uint8_t>(v));
      return true;
    }
    case protocol::ValueType::U16: {
      const int v = text.toInt(&ok, 0);
      if (!ok || v < 0 || v > 0xFFFF) return false;
      out_bytes->push_back(static_cast<uint8_t>(v & 0xFF));
      out_bytes->push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
      return true;
    }
    case protocol::ValueType::U32:
    case protocol::ValueType::S32: {
      const qint64 v = text.toLongLong(&ok, 0);
      if (!ok) return false;
      const uint32_t u = static_cast<uint32_t>(v);
      for (int i = 0; i < 4; ++i) out_bytes->push_back(static_cast<uint8_t>((u >> (8 * i)) & 0xFF));
      return true;
    }
    case protocol::ValueType::U64:
    case protocol::ValueType::S64: {
      const qint64 v = text.toLongLong(&ok, 0);
      if (!ok) return false;
      const uint64_t u = static_cast<uint64_t>(v);
      for (int i = 0; i < 8; ++i) out_bytes->push_back(static_cast<uint8_t>((u >> (8 * i)) & 0xFF));
      return true;
    }
    case protocol::ValueType::FLOAT: {
      const float v = text.toFloat(&ok);
      if (!ok) return false;
      out_bytes->resize(sizeof(float));
      std::memcpy(out_bytes->data(), &v, sizeof(float));
      return true;
    }
    case protocol::ValueType::DOUBLE: {
      const double v = text.toDouble(&ok);
      if (!ok) return false;
      out_bytes->resize(sizeof(double));
      std::memcpy(out_bytes->data(), &v, sizeof(double));
      return true;
    }
    case protocol::ValueType::STRING:
      if (text.isEmpty()) return false;
      {
        const QByteArray utf8 = text.toUtf8();
        out_bytes->assign(reinterpret_cast<const uint8_t*>(utf8.constData()),
                          reinterpret_cast<const uint8_t*>(utf8.constData()) + utf8.size());
      }
      return true;
    case protocol::ValueType::AOB:
      return ParseAobText(text, out_bytes);
    case protocol::ValueType::BINARY:
      return ParseBinaryText(text, out_bytes);
    case protocol::ValueType::ALL:
      if (text.isEmpty()) return false;
      {
        const QByteArray utf8 = text.toUtf8();
        out_bytes->assign(reinterpret_cast<const uint8_t*>(utf8.constData()),
                          reinterpret_cast<const uint8_t*>(utf8.constData()) + utf8.size());
      }
      return true;
    default:
      return false;
  }
}

void MainWindow::OnAddressItemChanged(QStandardItem* item) {
  if (!item || address_model_updating_) {
    return;
  }
  const int row = item->row();
  const int col = item->column();
  if (row < 0 || row >= address_model_->rowCount()) {
    return;
  }
  if (col == 5) {
    WriteAddressRowValue(row);
  }
}

void MainWindow::WriteAddressRowValue(int row) {
  if (!EnsureConnected() || attached_pid_ == 0 || row < 0 || row >= address_model_->rowCount()) {
    return;
  }
  const auto addr = address_model_->data(address_model_->index(row, 3), kAddressRole).toULongLong();
  if (addr == 0) {
    return;
  }
  protocol::ValueType vt = protocol::ValueType::U32;
  const QVariant vt_data = address_model_->data(address_model_->index(row, 4), kTypeRole);
  if (vt_data.isValid()) {
    vt = static_cast<protocol::ValueType>(vt_data.toInt());
  } else {
    ValueTypeFromDisplayName(address_model_->data(address_model_->index(row, 4)).toString(), &vt);
  }
  std::vector<uint8_t> bytes;
  if (!BuildWriteBytes(vt, address_model_->data(address_model_->index(row, 5)).toString(), &bytes) || bytes.empty()) {
    return;
  }
  std::string error;
  bool ok = false;
  {
    const std::lock_guard<std::mutex> lock(service_mutex_);
    ok = service_.WriteMemory(static_cast<uint64_t>(addr), bytes, &error);
  }
  if (!ok) {
    UpdateStatus(QStringLiteral("写入失败: %1").arg(ToQString(error)));
    return;
  }
  UpdateStatus(QStringLiteral("已写入 %1").arg(Hex64(static_cast<uint64_t>(addr))));
}

void MainWindow::ApplyAddressRefreshResult() {
  address_refresh_in_flight_ = false;
  if (!address_model_) {
    return;
  }

  const AddressRefreshResult result = address_refresh_watcher_.result();
  if (!result.updates.empty()) {
    address_model_updating_ = true;
    for (const auto& update : result.updates) {
      if (update.row < 0 || update.row >= address_model_->rowCount()) {
        continue;
      }
      address_model_->setData(address_model_->index(update.row, 5), update.value_text);
    }
    address_model_updating_ = false;
  }

  if (result.freeze_write_failures > 0) {
    UpdateStatus(QStringLiteral("冻结写入失败 %1 项").arg(result.freeze_write_failures));
  }

  if (address_refresh_pending_) {
    address_refresh_pending_ = false;
    QTimer::singleShot(0, this, &MainWindow::OnAddressRefreshTick);
  }
}

void MainWindow::OnAddressRefreshTick() {
  UpdatePluginProviderStatusPanel();
  if (!connected_ || attached_pid_ == 0 || !address_model_ || address_model_->rowCount() == 0) {
    address_refresh_pending_ = false;
    return;
  }
  if (address_refresh_in_flight_) {
    address_refresh_pending_ = true;
    return;
  }

  std::vector<AddressRefreshJob> jobs;
  jobs.reserve(static_cast<size_t>((std::min)(address_model_->rowCount(), 512)));
  for (int row = 0; row < address_model_->rowCount(); ++row) {
    const bool active = address_model_->item(row, 0) && address_model_->item(row, 0)->checkState() == Qt::Checked;
    if (!active) {
      continue;
    }

    const auto addr = address_model_->data(address_model_->index(row, 3), kAddressRole).toULongLong();
    if (addr == 0) {
      continue;
    }
    protocol::ValueType vt = protocol::ValueType::U32;
    const QVariant vt_data = address_model_->data(address_model_->index(row, 4), kTypeRole);
    if (vt_data.isValid()) {
      vt = static_cast<protocol::ValueType>(vt_data.toInt());
    } else {
      ValueTypeFromDisplayName(address_model_->data(address_model_->index(row, 4)).toString(), &vt);
    }
    AddressRefreshJob job;
    job.row = row;
    job.address = static_cast<uint64_t>(addr);
    job.value_type = vt;
    job.freeze = address_model_->item(row, 1) && address_model_->item(row, 1)->checkState() == Qt::Checked;
    job.value_text = address_model_->data(address_model_->index(row, 5)).toString();
    jobs.push_back(std::move(job));
    if (jobs.size() >= 512) {
      break;
    }
  }
  if (jobs.empty()) {
    address_refresh_pending_ = false;
    return;
  }

  address_refresh_in_flight_ = true;
  address_refresh_pending_ = false;
  const auto future = QtConcurrent::run([this, jobs]() {
    AddressRefreshResult result;

    for (const auto& job : jobs) {
      if (!job.freeze) {
        continue;
      }
      std::vector<uint8_t> bytes;
      if (!BuildWriteBytes(job.value_type, job.value_text, &bytes) || bytes.empty()) {
        continue;
      }
      std::string error;
      bool ok = false;
      {
        const std::lock_guard<std::mutex> lock(service_mutex_);
        ok = service_.WriteMemory(job.address, bytes, &error);
      }
      if (!ok) {
        result.freeze_write_failures += 1;
      }
    }

    struct RangeRef {
      int row = -1;
      protocol::ValueType value_type = protocol::ValueType::U32;
    };
    std::vector<r3::windows_client_ng::services::ClientService::ReadRange> ranges;
    std::vector<RangeRef> refs;
    ranges.reserve(jobs.size());
    refs.reserve(jobs.size());
    for (const auto& job : jobs) {
      const uint32_t read_size = ValueTypeByteSize(job.value_type);
      if (read_size == 0) {
        continue;
      }
      ranges.push_back(r3::windows_client_ng::services::ClientService::ReadRange{job.address, read_size});
      refs.push_back(RangeRef{job.row, job.value_type});
    }

    if (ranges.empty()) {
      return result;
    }

    std::vector<std::vector<uint8_t>> buffers;
    std::string error;
    bool ok = false;
    {
      const std::lock_guard<std::mutex> lock(service_mutex_);
      ok = service_.ReadMemoryBatch(ranges, protocol::READ_FLAG_USE_PVM, &buffers, &error);
    }
    if (!ok || buffers.size() != refs.size()) {
      return result;
    }

    result.updates.reserve(refs.size());
    for (size_t i = 0; i < refs.size(); ++i) {
      AddressValueUpdate update;
      update.row = refs[i].row;
      update.value_text = FormatValueText(refs[i].value_type, buffers[i]);
      result.updates.push_back(std::move(update));
    }
    return result;
  });
  address_refresh_watcher_.setFuture(future);
}
void MainWindow::TryAutoStartup() {
  if (auto_startup_running_ || !auto_start_check_->isChecked()) return;
  auto_startup_running_ = true;
  UpdateStatus(QStringLiteral("正在检测ADB设备..."));
  auto_startup_watcher_.setFuture(QtConcurrent::run([this]() { return ProbeAndPushAgent(); }));
}

bool MainWindow::ProbeAndPushAgent() {
  const QString adb = adb_path_edit_->text().trimmed();
  if (adb.isEmpty() || !QFileInfo::exists(adb)) return false;

  QProcess probe;
  probe.start(adb, {QStringLiteral("devices")});
  if (!probe.waitForFinished(2500)) return false;
  const QString output = QString::fromUtf8(probe.readAllStandardOutput());
  bool has_device = false;
  for (const QString& line : output.split('\n', Qt::SkipEmptyParts)) {
    if (LooksDeviceLine(line.trimmed())) {
      has_device = true;
      break;
    }
  }
  if (!has_device) return false;

  const QString ps = QStringLiteral("powershell");
  const QString push_script = QDir::current().filePath(QStringLiteral("tools/push_run_agent.ps1"));
  const QString forward_script = QDir::current().filePath(QStringLiteral("tools/adb_forward.ps1"));

  QProcess push;
  push.start(ps, {QStringLiteral("-ExecutionPolicy"), QStringLiteral("Bypass"), QStringLiteral("-File"), push_script,
                  QStringLiteral("-Adb"), adb, QStringLiteral("-Run")});
  if (!push.waitForFinished(12000) || push.exitCode() != 0) return false;

  QProcess forward;
  forward.start(ps, {QStringLiteral("-ExecutionPolicy"), QStringLiteral("Bypass"), QStringLiteral("-File"),
                     forward_script, QStringLiteral("-Adb"), adb});
  if (!forward.waitForFinished(5000) || forward.exitCode() != 0) return false;

  return true;
}

void MainWindow::OnAutoStartupFinished() {
  auto_startup_running_ = false;
  if (!auto_startup_watcher_.result()) {
    UpdateStatus(QStringLiteral("自动设备检测完成: 未发现设备或推送失败"));
    return;
  }
  UpdateStatus(QStringLiteral("自动推送完成，正在连接..."));
  ConnectToService(host_edit_->text(), static_cast<uint16_t>(port_spin_->value()));
}

uint64_t MainWindow::ParseAddressText(const QString& text, bool* ok) {
  if (ok) *ok = true;
  QString s = text.trimmed();
  if (s.isEmpty()) return 0;
  int base = 10;
  if (s.startsWith(QStringLiteral("0x"), Qt::CaseInsensitive)) {
    s = s.mid(2);
    base = 16;
  }
  bool parsed = false;
  const uint64_t v = s.toULongLong(&parsed, base);
  if (ok) *ok = parsed;
  return parsed ? v : 0;
}

QString MainWindow::Hex64(uint64_t value) {
  return QStringLiteral("0x%1").arg(QString::number(value, 16).toUpper());
}

QString MainWindow::ValueTypeDisplayName(protocol::ValueType value_type) {
  switch (value_type) {
    case protocol::ValueType::U8: return QStringLiteral("1 Byte");
    case protocol::ValueType::U16: return QStringLiteral("2 Bytes");
    case protocol::ValueType::U32: return QStringLiteral("4 Bytes");
    case protocol::ValueType::U64: return QStringLiteral("8 Bytes");
    case protocol::ValueType::S32: return QStringLiteral("4 Bytes(Signed)");
    case protocol::ValueType::S64: return QStringLiteral("8 Bytes(Signed)");
    case protocol::ValueType::FLOAT: return QStringLiteral("Float");
    case protocol::ValueType::DOUBLE: return QStringLiteral("Double");
    case protocol::ValueType::STRING: return QStringLiteral("String");
    case protocol::ValueType::AOB: return QStringLiteral("Array of Byte");
    case protocol::ValueType::BINARY: return QStringLiteral("Binary");
    case protocol::ValueType::ALL: return QStringLiteral("All");
    default: return QStringLiteral("Unknown");
  }
}

QIcon MainWindow::LoadCachedIcon(uint32_t pid) const {
  const QString path = IconCachePath(pid);
  if (!QFileInfo::exists(path)) return QIcon();
  QPixmap pix;
  if (!pix.load(path, "PNG")) return QIcon();
  return QIcon(pix);
}

void MainWindow::SaveCachedIcon(uint32_t pid, const QByteArray& png_data) const {
  if (png_data.isEmpty()) return;
  const QString path = IconCachePath(pid);
  QDir().mkpath(QFileInfo(path).absolutePath());
  QFile file(path);
  if (!file.open(QIODevice::WriteOnly | QIODevice::Truncate)) return;
  file.write(png_data);
}

QString MainWindow::IconCachePath(uint32_t pid) const {
  const QString dir = QDir::current().filePath(QStringLiteral("settings/process_icon_cache"));
  return QDir(dir).filePath(QStringLiteral("%1.png").arg(pid));
}

}  // namespace r3::windows_client_qt::ui
