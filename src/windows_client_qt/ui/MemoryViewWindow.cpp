#include "ui/MemoryViewWindow.h"

#include <algorithm>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <cstring>

#include <capstone/capstone.h>

#include <QAbstractItemView>
#include <QAction>
#include <QActionGroup>
#include <QApplication>
#include <QBrush>
#include <QClipboard>
#include <QColor>
#include <QDateTime>
#include <QFileInfo>
#include <QFont>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QMenu>
#include <QMenuBar>
#include <QMessageBox>
#include <QPushButton>
#include <QShortcut>
#include <QSplitter>
#include <QStandardItem>
#include <QStandardItemModel>
#include <QStringList>
#include <QTableView>
#include <QTimer>
#include <QVBoxLayout>
#include <QWidget>

#include "ui/PointerToolsDialog.h"

namespace r3::windows_client_qt::ui {

namespace {
constexpr int kAddressRole = Qt::UserRole + 1;

QString Hex64(uint64_t value) {
  return QStringLiteral("0x%1").arg(QString::number(value, 16).toUpper());
}

QString ToQString(const std::string& text) {
  return QString::fromUtf8(text.c_str(), static_cast<int>(text.size()));
}

QString ArchText(protocol::RegsArch arch) {
  switch (arch) {
    case protocol::RegsArch::ARM64:
      return QStringLiteral("ARM64");
    case protocol::RegsArch::ARM32:
      return QStringLiteral("ARM32");
    default:
      return QStringLiteral("UNKNOWN");
  }
}

bool ContainsCI(const QString& text, const QString& token) {
  return text.contains(token, Qt::CaseInsensitive);
}

bool StartsWithPath(const QString& path, const QString& prefix) {
  return path.startsWith(prefix, Qt::CaseInsensitive);
}

bool EndsWithPath(const QString& path, const QString& suffix) {
  return path.endsWith(suffix, Qt::CaseInsensitive);
}

struct ModuleProps {
  bool exec = false;
  bool rw = false;
  bool anon = false;
  bool heap = false;
  bool stack = false;
  bool java = false;
  bool java_heap = false;
  bool ashmem = false;
  bool system = false;
  bool app = false;
  bool dev = false;
  bool file = false;
};

ModuleProps BuildModuleProps(const r3::windows_client_ng::services::ClientService::ModuleInfo& module) {
  ModuleProps props{};
  const QString path = ToQString(module.path).trimmed();
  const bool has_path = !path.isEmpty();
  const bool bracket = has_path && path.startsWith(QLatin1Char('['));

  props.exec = (module.perms & protocol::MODULE_PERM_EXEC) != 0;
  props.rw = (module.perms & protocol::MODULE_PERM_READ) && (module.perms & protocol::MODULE_PERM_WRITE);
  props.dev = StartsWithPath(path, QStringLiteral("/dev"));
  props.system = StartsWithPath(path, QStringLiteral("/system")) ||
                 StartsWithPath(path, QStringLiteral("/apex")) ||
                 StartsWithPath(path, QStringLiteral("/vendor")) ||
                 StartsWithPath(path, QStringLiteral("/product")) ||
                 StartsWithPath(path, QStringLiteral("/odm")) ||
                 StartsWithPath(path, QStringLiteral("/system_ext"));
  props.app = StartsWithPath(path, QStringLiteral("/data/app")) ||
              StartsWithPath(path, QStringLiteral("/data/user")) ||
              StartsWithPath(path, QStringLiteral("/data/data")) ||
              StartsWithPath(path, QStringLiteral("/mnt/asec"));

  props.anon = !has_path || bracket || ContainsCI(path, QStringLiteral("anon"));
  props.heap = ContainsCI(path, QStringLiteral("[heap]")) ||
               ContainsCI(path, QStringLiteral("libc_malloc")) ||
               ContainsCI(path, QStringLiteral("scudo")) ||
               ContainsCI(path, QStringLiteral("malloc"));
  props.stack = ContainsCI(path, QStringLiteral("[stack")) || ContainsCI(path, QStringLiteral("stack:"));

  props.java_heap = ContainsCI(path, QStringLiteral("dalvik-heap")) ||
                    ContainsCI(path, QStringLiteral("dalvik main")) ||
                    ContainsCI(path, QStringLiteral("zygote space")) ||
                    ContainsCI(path, QStringLiteral("alloc space")) ||
                    ContainsCI(path, QStringLiteral("large object")) ||
                    ContainsCI(path, QStringLiteral("main space"));
  props.java = ContainsCI(path, QStringLiteral("dalvik")) ||
               ContainsCI(path, QStringLiteral("art")) ||
               ContainsCI(path, QStringLiteral("oat")) ||
               ContainsCI(path, QStringLiteral("vdex")) ||
               ContainsCI(path, QStringLiteral("dex"));
  props.ashmem = ContainsCI(path, QStringLiteral("ashmem")) || ContainsCI(path, QStringLiteral("memfd"));
  props.file = has_path && !bracket && !props.dev;
  return props;
}

struct GGSegment {
  QString code;
  QString name;
};

GGSegment ClassifyGGSegment(const r3::windows_client_ng::services::ClientService::ModuleInfo& module) {
  const ModuleProps props = BuildModuleProps(module);
  const QString path = ToQString(module.path).trimmed();
  const bool readable = (module.perms & protocol::MODULE_PERM_READ) != 0;
  if (!readable) {
    return {QStringLiteral("O"), QStringLiteral("Other")};
  }
  if (ContainsCI(path, QStringLiteral("ppsspp"))) {
    return {QStringLiteral("ps"), QStringLiteral("PPSSPP")};
  }
  if (props.java_heap) {
    return {QStringLiteral("jh"), QStringLiteral("Java Heap")};
  }
  if (props.heap) {
    return {QStringLiteral("ch"), QStringLiteral("C++ Heap")};
  }
  if (ContainsCI(path, QStringLiteral("alloc"))) {
    return {QStringLiteral("ca"), QStringLiteral("C++ Alloc")};
  }
  if (props.anon) {
    return {QStringLiteral("A"), QStringLiteral("Anonymous")};
  }
  if (props.file && props.rw && !props.exec && ContainsCI(path, QStringLiteral(".bss"))) {
    return {QStringLiteral(".bss"), QStringLiteral("C++ .bss")};
  }
  if (props.java) {
    return {QStringLiteral("J"), QStringLiteral("Java")};
  }
  if (props.stack) {
    return {QStringLiteral("S"), QStringLiteral("Stack")};
  }
  if (props.ashmem) {
    return {QStringLiteral("As"), QStringLiteral("Ashmem")};
  }
  if (props.exec && props.app) {
    return {QStringLiteral("XA"), QStringLiteral("Code App")};
  }
  if (props.exec && props.system) {
    return {QStringLiteral("XS"), QStringLiteral("Code System")};
  }
  if (props.dev && (ContainsCI(path, QStringLiteral("video")) || ContainsCI(path, QStringLiteral("kgsl")) ||
                    ContainsCI(path, QStringLiteral("gpu")) || ContainsCI(path, QStringLiteral("graphics")))) {
    return {QStringLiteral("V"), QStringLiteral("Video")};
  }
  return {QStringLiteral("O"), QStringLiteral("Other")};
}

QString GGSegmentText(const r3::windows_client_ng::services::ClientService::ModuleInfo& module) {
  const GGSegment gg = ClassifyGGSegment(module);
  if (gg.name.isEmpty()) {
    return gg.code;
  }
  return QStringLiteral("%1(%2)").arg(gg.code, gg.name);
}
}  // namespace

MemoryViewWindow::MemoryViewWindow(QWidget* parent) : QMainWindow(parent) {
  setWindowTitle(QStringLiteral("Memory View"));
  resize(1400, 900);
  setMinimumSize(1100, 680);

  QMenu* file_menu = menuBar()->addMenu(QStringLiteral("文件"));
  QMenu* search_menu = menuBar()->addMenu(QStringLiteral("搜索"));
  QMenu* view_menu = menuBar()->addMenu(QStringLiteral("视图"));
  QMenu* debug_menu = menuBar()->addMenu(QStringLiteral("调试"));
  QMenu* tool_menu = menuBar()->addMenu(QStringLiteral("工具"));
  menuBar()->addMenu(QStringLiteral("内核工具"));
  menuBar()->setStyleSheet(QStringLiteral(
      "QMenuBar::item { padding: 6px 12px; margin: 0 2px; }"
      "QMenu::item { padding: 7px 28px 7px 12px; min-height: 24px; }"));

  QAction* close_action = file_menu->addAction(QStringLiteral("关闭"));
  QAction* jump_action = search_menu->addAction(QStringLiteral("跳转地址/模块"));
  QAction* refresh_action = view_menu->addAction(QStringLiteral("刷新"));
  QMenu* annotation_menu = view_menu->addMenu(QStringLiteral("注释来源"));
  QActionGroup* annotation_group = new QActionGroup(this);
  QAction* annotation_builtin_action = annotation_menu->addAction(QStringLiteral("内置注释"));
  QAction* annotation_plugin_action = annotation_menu->addAction(QStringLiteral("插件注释"));
  QAction* annotation_mixed_action = annotation_menu->addAction(QStringLiteral("混合模式"));
  annotation_builtin_action->setCheckable(true);
  annotation_plugin_action->setCheckable(true);
  annotation_mixed_action->setCheckable(true);
  annotation_group->addAction(annotation_builtin_action);
  annotation_group->addAction(annotation_plugin_action);
  annotation_group->addAction(annotation_mixed_action);
  annotation_mixed_action->setChecked(true);
  QAction* add_selected_action = tool_menu->addAction(QStringLiteral("添加选中地址到列表"));
  tool_menu->addSeparator();
  QMenu* pointer_menu = tool_menu->addMenu(QStringLiteral("指针工具"));
  QAction* pointer_scan_action = pointer_menu->addAction(QStringLiteral("指针扫描"));
  QAction* pointer_compare_action = pointer_menu->addAction(QStringLiteral("指针对比"));
  QAction* structure_traverse_action = pointer_menu->addAction(QStringLiteral("结构遍历"));
  QAction* toggle_bp_view_action = debug_menu->addAction(QStringLiteral("显示断点标记"));
  toggle_bp_view_action->setCheckable(true);
  toggle_bp_view_action->setChecked(true);
  debug_menu->addSeparator();
  QMenu* bp_backend_menu = debug_menu->addMenu(QStringLiteral("断点后端"));
  QActionGroup* bp_backend_group = new QActionGroup(this);
  QAction* bp_backend_ptrace = bp_backend_menu->addAction(QStringLiteral("ptrace"));
  QAction* bp_backend_perf = bp_backend_menu->addAction(QStringLiteral("perf"));
  bp_backend_ptrace->setCheckable(true);
  bp_backend_perf->setCheckable(true);
  bp_backend_group->addAction(bp_backend_ptrace);
  bp_backend_group->addAction(bp_backend_perf);
  bp_backend_perf->setChecked(true);
  QAction* bp_stop_on_hit_action = debug_menu->addAction(QStringLiteral("命中暂停"));
  bp_stop_on_hit_action->setCheckable(true);
  bp_stop_on_hit_action->setChecked(false);
  QAction* bp_toggle_exec_action = debug_menu->addAction(QStringLiteral("切换执行断点 (F2)"));
  QAction* bp_add_write_action = debug_menu->addAction(QStringLiteral("添加写入断点"));
  QAction* bp_add_read_action = debug_menu->addAction(QStringLiteral("添加读取断点"));
  QAction* bp_add_rw_action = debug_menu->addAction(QStringLiteral("添加读写断点"));
  QAction* bp_remove_here_action = debug_menu->addAction(QStringLiteral("删除当前地址断点"));
  QAction* bp_clear_all_action = debug_menu->addAction(QStringLiteral("清空全部断点"));
  debug_menu->addSeparator();
  QAction* bp_pause_action = debug_menu->addAction(QStringLiteral("暂停进程"));
  QAction* bp_continue_action = debug_menu->addAction(QStringLiteral("继续运行 (F9)"));
  QAction* bp_step_in_action = debug_menu->addAction(QStringLiteral("单步步入 (F7)"));
  QAction* bp_step_over_action = debug_menu->addAction(QStringLiteral("单步步过 (F8)"));
  QAction* bp_clear_hits_action = debug_menu->addAction(QStringLiteral("清空命中记录"));
  QAction* bp_read_regs_action = debug_menu->addAction(QStringLiteral("读取当前寄存器快照"));

  jump_action->setShortcut(QKeySequence(QStringLiteral("Ctrl+G")));
  refresh_action->setShortcut(QKeySequence(Qt::Key_F5));
  add_selected_action->setShortcut(QKeySequence(Qt::Key_Insert));
  bp_toggle_exec_action->setShortcut(QKeySequence(Qt::Key_F2));
  bp_continue_action->setShortcut(QKeySequence(Qt::Key_F9));
  bp_step_in_action->setShortcut(QKeySequence(Qt::Key_F7));
  bp_step_over_action->setShortcut(QKeySequence(Qt::Key_F8));
  pointer_scan_action->setShortcut(QKeySequence(QStringLiteral("Ctrl+Alt+1")));
  pointer_compare_action->setShortcut(QKeySequence(QStringLiteral("Ctrl+Alt+2")));
  structure_traverse_action->setShortcut(QKeySequence(QStringLiteral("Ctrl+Alt+3")));

  auto* central = new QWidget(this);
  auto* root = new QVBoxLayout(central);
  root->setContentsMargins(8, 8, 8, 8);
  root->setSpacing(6);

  auto* row = new QHBoxLayout();
  address_edit_ = new QLineEdit(central);
  address_edit_->setPlaceholderText(QStringLiteral("输入地址或模块表达式，如 0x7D000000 或 libc.so+0x120"));
  jump_button_ = new QPushButton(QStringLiteral("跳转"), central);
  refresh_button_ = new QPushButton(QStringLiteral("刷新"), central);
  row->addWidget(address_edit_, 1);
  row->addWidget(jump_button_);
  row->addWidget(refresh_button_);
  root->addLayout(row);

  info_label_ = new QLabel(QStringLiteral("未绑定进程"), central);
  root->addWidget(info_label_);
  breakpoint_label_ = new QLabel(QStringLiteral("断点: 0  后端: perf  命中暂停: 关"), central);
  root->addWidget(breakpoint_label_);

  auto* splitter = new QSplitter(Qt::Vertical, central);
  top_splitter_ = new QSplitter(Qt::Horizontal, splitter);

  disasm_table_ = new QTableView(top_splitter_);
  disasm_table_->setSelectionBehavior(QAbstractItemView::SelectRows);
  disasm_table_->setSelectionMode(QAbstractItemView::SingleSelection);
  disasm_table_->setAlternatingRowColors(true);
  disasm_table_->setEditTriggers(QAbstractItemView::NoEditTriggers);
  disasm_table_->setContextMenuPolicy(Qt::CustomContextMenu);
  disasm_table_->verticalHeader()->hide();

  disasm_model_ = new QStandardItemModel(this);
  disasm_model_->setColumnCount(4);
  disasm_model_->setHeaderData(0, Qt::Horizontal, QStringLiteral("地址(模块+offset)"));
  disasm_model_->setHeaderData(1, Qt::Horizontal, QStringLiteral("字节"));
  disasm_model_->setHeaderData(2, Qt::Horizontal, QStringLiteral("操作码"));
  disasm_model_->setHeaderData(3, Qt::Horizontal, QStringLiteral("注释"));
  disasm_table_->setModel(disasm_model_);
  disasm_table_->horizontalHeader()->setStretchLastSection(true);
  disasm_table_->setColumnWidth(0, 420);
  disasm_table_->setColumnWidth(1, 220);
  disasm_table_->setColumnWidth(2, 260);

  debug_panel_ = new QWidget(top_splitter_);
  auto* reg_layout = new QVBoxLayout(debug_panel_);
  reg_layout->setContentsMargins(0, 0, 0, 0);
  reg_layout->setSpacing(4);
  register_label_ = new QLabel(QStringLiteral("断点寄存器: 等待命中"), debug_panel_);
  reg_layout->addWidget(register_label_);
  register_table_ = new QTableView(debug_panel_);
  register_table_->setSelectionBehavior(QAbstractItemView::SelectRows);
  register_table_->setSelectionMode(QAbstractItemView::SingleSelection);
  register_table_->setAlternatingRowColors(true);
  register_table_->setEditTriggers(QAbstractItemView::NoEditTriggers);
  register_table_->verticalHeader()->hide();
  register_model_ = new QStandardItemModel(this);
  register_model_->setColumnCount(3);
  register_model_->setHeaderData(0, Qt::Horizontal, QStringLiteral("寄存器"));
  register_model_->setHeaderData(1, Qt::Horizontal, QStringLiteral("十六进制"));
  register_model_->setHeaderData(2, Qt::Horizontal, QStringLiteral("十进制"));
  register_table_->setModel(register_model_);
  register_table_->horizontalHeader()->setStretchLastSection(true);
  register_table_->setColumnWidth(0, 90);
  register_table_->setColumnWidth(1, 190);
  reg_layout->addWidget(register_table_, 3);
  breakpoint_hits_label_ = new QLabel(QStringLiteral("命中记录(最近): 0"), debug_panel_);
  reg_layout->addWidget(breakpoint_hits_label_);
  breakpoint_hits_table_ = new QTableView(debug_panel_);
  breakpoint_hits_table_->setSelectionBehavior(QAbstractItemView::SelectRows);
  breakpoint_hits_table_->setSelectionMode(QAbstractItemView::SingleSelection);
  breakpoint_hits_table_->setAlternatingRowColors(true);
  breakpoint_hits_table_->setEditTriggers(QAbstractItemView::NoEditTriggers);
  breakpoint_hits_table_->verticalHeader()->hide();
  breakpoint_hits_model_ = new QStandardItemModel(this);
  breakpoint_hits_model_->setColumnCount(4);
  breakpoint_hits_model_->setHeaderData(0, Qt::Horizontal, QStringLiteral("时间"));
  breakpoint_hits_model_->setHeaderData(1, Qt::Horizontal, QStringLiteral("地址"));
  breakpoint_hits_model_->setHeaderData(2, Qt::Horizontal, QStringLiteral("类型/后端"));
  breakpoint_hits_model_->setHeaderData(3, Qt::Horizontal, QStringLiteral("次数"));
  breakpoint_hits_table_->setModel(breakpoint_hits_model_);
  breakpoint_hits_table_->horizontalHeader()->setStretchLastSection(true);
  breakpoint_hits_table_->setColumnWidth(0, 110);
  breakpoint_hits_table_->setColumnWidth(1, 170);
  breakpoint_hits_table_->setColumnWidth(2, 140);
  reg_layout->addWidget(breakpoint_hits_table_, 2);
  debug_panel_->setVisible(false);
  debug_panel_visible_ = false;

  hex_table_ = new QTableView(splitter);
  hex_table_->setSelectionBehavior(QAbstractItemView::SelectItems);
  hex_table_->setSelectionMode(QAbstractItemView::SingleSelection);
  hex_table_->setAlternatingRowColors(true);
  hex_table_->setEditTriggers(QAbstractItemView::NoEditTriggers);
  hex_table_->setContextMenuPolicy(Qt::CustomContextMenu);
  hex_table_->verticalHeader()->hide();

  hex_model_ = new QStandardItemModel(this);
  hex_model_->setColumnCount(18);
  hex_model_->setHeaderData(0, Qt::Horizontal, QStringLiteral("地址"));
  for (int i = 0; i < 16; ++i) {
    hex_model_->setHeaderData(i + 1, Qt::Horizontal, QStringLiteral("%1").arg(QString::number(i, 16).toUpper()));
  }
  hex_model_->setHeaderData(17, Qt::Horizontal, QStringLiteral("ASCII"));
  hex_table_->setModel(hex_model_);
  hex_table_->horizontalHeader()->setStretchLastSection(true);
  hex_table_->setColumnWidth(0, 140);
  for (int i = 1; i <= 16; ++i) {
    hex_table_->setColumnWidth(i, 46);
  }
  hex_table_->setColumnWidth(17, 280);

  QFont mono = disasm_table_->font();
  mono.setFamily(QStringLiteral("Consolas"));
  mono.setPointSize(11);
  disasm_table_->setFont(mono);
  register_table_->setFont(mono);
  breakpoint_hits_table_->setFont(mono);
  hex_table_->setFont(mono);

  top_splitter_->setStretchFactor(0, 1);
  top_splitter_->setStretchFactor(1, 1);
  top_splitter_->setChildrenCollapsible(false);
  top_splitter_->setSizes(QList<int>({1, 0}));
  splitter->addWidget(top_splitter_);
  splitter->addWidget(hex_table_);
  splitter->setStretchFactor(0, 5);
  splitter->setStretchFactor(1, 6);
  root->addWidget(splitter, 1);
  setCentralWidget(central);

  connect(close_action, &QAction::triggered, this, &QWidget::close);
  connect(jump_action, &QAction::triggered, this, [this]() {
    address_edit_->setFocus();
    address_edit_->selectAll();
  });
  connect(refresh_action, &QAction::triggered, this, &MemoryViewWindow::OnRefreshClicked);
  connect(add_selected_action, &QAction::triggered, this, [this]() {
    uint64_t addr = SelectedDisasmAddress();
    if (addr == 0) {
      addr = SelectedHexAddress();
    }
    if (addr == 0) {
      addr = current_address_;
    }
    emit RequestAddAddress(addr);
  });
  connect(pointer_scan_action, &QAction::triggered, this, [this]() {
    OpenPointerToolsAtTab(static_cast<int>(PointerToolsDialog::kPointerScanTab));
  });
  connect(pointer_compare_action, &QAction::triggered, this, [this]() {
    OpenPointerToolsAtTab(static_cast<int>(PointerToolsDialog::kPointerCompareTab));
  });
  connect(structure_traverse_action, &QAction::triggered, this, [this]() {
    OpenPointerToolsAtTab(static_cast<int>(PointerToolsDialog::kStructureTraverseTab));
  });
  connect(annotation_builtin_action, &QAction::triggered, this, [this]() {
    annotation_mode_ = ANNO_BUILTIN;
    RefreshBreakpointVisuals();
  });
  connect(annotation_plugin_action, &QAction::triggered, this, [this]() {
    annotation_mode_ = ANNO_PLUGIN;
    RefreshBreakpointVisuals();
  });
  connect(annotation_mixed_action, &QAction::triggered, this, [this]() {
    annotation_mode_ = ANNO_MIXED;
    RefreshBreakpointVisuals();
  });
  connect(toggle_bp_view_action, &QAction::toggled, this, [this](bool checked) {
    breakpoint_overlay_visible_ = checked;
    RefreshBreakpointVisuals();
  });
  connect(bp_backend_ptrace, &QAction::triggered, this, [this]() {
    breakpoint_backend_ = protocol::DEBUG_BACKEND_PTRACE;
    UpdateBreakpointStatusText();
  });
  connect(bp_backend_perf, &QAction::triggered, this, [this]() {
    breakpoint_backend_ = protocol::DEBUG_BACKEND_PERF;
    UpdateBreakpointStatusText();
  });
  connect(bp_stop_on_hit_action, &QAction::toggled, this, [this](bool checked) {
    breakpoint_stop_on_hit_ = checked;
    UpdateBreakpointStatusText();
  });
  connect(bp_toggle_exec_action, &QAction::triggered, this, &MemoryViewWindow::OnToggleExecBreakpoint);
  connect(bp_add_write_action, &QAction::triggered, this, &MemoryViewWindow::OnAddWriteBreakpoint);
  connect(bp_add_read_action, &QAction::triggered, this, &MemoryViewWindow::OnAddReadBreakpoint);
  connect(bp_add_rw_action, &QAction::triggered, this, &MemoryViewWindow::OnAddReadWriteBreakpoint);
  connect(bp_remove_here_action, &QAction::triggered, this, &MemoryViewWindow::OnRemoveAddressBreakpoints);
  connect(bp_clear_all_action, &QAction::triggered, this, &MemoryViewWindow::OnClearAllBreakpoints);
  connect(bp_pause_action, &QAction::triggered, this, &MemoryViewWindow::OnDebugPauseProcess);
  connect(bp_continue_action, &QAction::triggered, this, &MemoryViewWindow::OnDebugContinueProcess);
  connect(bp_step_in_action, &QAction::triggered, this, &MemoryViewWindow::OnDebugStepIn);
  connect(bp_step_over_action, &QAction::triggered, this, &MemoryViewWindow::OnDebugStepOver);
  connect(bp_clear_hits_action, &QAction::triggered, this, &MemoryViewWindow::OnClearBreakpointHitHistory);
  connect(bp_read_regs_action, &QAction::triggered, this, [this]() {
    QString ready_error;
    if (!EnsureBreakpointReady(&ready_error)) {
      ResetRegisterPanel(QStringLiteral("寄存器读取失败: %1").arg(ready_error));
      SetBreakpointStatus(ready_error);
      return;
    }
    r3::windows_client_ng::services::ClientService::RegsSnapshot regs{};
    std::string error;
    bool ok = false;
    {
      const std::lock_guard<std::mutex> lock(*service_mutex_);
      ok = service_->FetchRegs(pid_, &regs, &error);
    }
    if (!ok) {
      const QString text = ToQString(error).trimmed().isEmpty() ? QStringLiteral("读取寄存器失败")
                                                                 : ToQString(error).trimmed();
      ResetRegisterPanel(QStringLiteral("寄存器读取失败: %1").arg(text));
      SetBreakpointStatus(text);
      return;
    }
    UpdateRegisterPanel(regs);
    SetBreakpointStatus(QStringLiteral("已刷新寄存器快照"));
  });

  connect(jump_button_, &QPushButton::clicked, this, &MemoryViewWindow::OnJumpClicked);
  connect(refresh_button_, &QPushButton::clicked, this, &MemoryViewWindow::OnRefreshClicked);
  connect(address_edit_, &QLineEdit::returnPressed, this, &MemoryViewWindow::OnJumpClicked);
  connect(disasm_table_, &QTableView::customContextMenuRequested, this, &MemoryViewWindow::OnShowContextMenu);
  connect(hex_table_, &QTableView::customContextMenuRequested, this, &MemoryViewWindow::OnHexContextMenu);
  connect(disasm_table_, &QTableView::doubleClicked, this, &MemoryViewWindow::OnDisasmDoubleClicked);
  connect(hex_table_, &QTableView::doubleClicked, this, &MemoryViewWindow::OnHexDoubleClicked);

  auto* goto_shortcut = new QShortcut(QKeySequence(QStringLiteral("Ctrl+G")), this);
  connect(goto_shortcut, &QShortcut::activated, this, [this]() {
    address_edit_->setFocus();
    address_edit_->selectAll();
  });
  auto* refresh_shortcut = new QShortcut(QKeySequence(Qt::Key_F5), this);
  connect(refresh_shortcut, &QShortcut::activated, this, &MemoryViewWindow::OnRefreshClicked);
  auto* toggle_bp_shortcut = new QShortcut(QKeySequence(Qt::Key_F2), this);
  connect(toggle_bp_shortcut, &QShortcut::activated, this, &MemoryViewWindow::OnToggleExecBreakpoint);
  auto* continue_shortcut = new QShortcut(QKeySequence(Qt::Key_F9), this);
  connect(continue_shortcut, &QShortcut::activated, this, &MemoryViewWindow::OnDebugContinueProcess);
  auto* step_in_shortcut = new QShortcut(QKeySequence(Qt::Key_F7), this);
  connect(step_in_shortcut, &QShortcut::activated, this, &MemoryViewWindow::OnDebugStepIn);
  auto* step_over_shortcut = new QShortcut(QKeySequence(Qt::Key_F8), this);
  connect(step_over_shortcut, &QShortcut::activated, this, &MemoryViewWindow::OnDebugStepOver);
  breakpoint_poll_timer_ = new QTimer(this);
  breakpoint_poll_timer_->setInterval(250);
  connect(breakpoint_poll_timer_, &QTimer::timeout, this, &MemoryViewWindow::PollBreakpointEvents);
  breakpoint_poll_timer_->start();

  ResetRegisterPanel(QStringLiteral("断点寄存器: 等待命中"));
  UpdateDebugPanelVisibility();
  UpdateBreakpointStatusText();
}

void MemoryViewWindow::SetService(r3::windows_client_ng::services::ClientService* service,
                                  std::mutex* service_mutex,
                                  uint32_t pid) {
  service_ = service;
  service_mutex_ = service_mutex;
  if (pid_ != pid) {
    modules_.clear();
    modules_pid_ = 0;
    proc_info_pid_ = 0;
    arch_ = protocol::RegsArch::UNKNOWN;
    pointer_size_ = 0;
    debug_attached_ = false;
    breakpoint_hit_total_ = 0;
    breakpoint_last_hit_addr_ = 0;
    if (!breakpoints_.empty()) {
      breakpoints_.clear();
      breakpoint_status_ = QStringLiteral("进程切换，已清空本地断点");
    }
    if (breakpoint_hits_model_) {
      breakpoint_hits_model_->removeRows(0, breakpoint_hits_model_->rowCount());
    }
    if (breakpoint_hits_label_) {
      breakpoint_hits_label_->setText(QStringLiteral("命中记录(最近): 0"));
    }
    ResetRegisterPanel(pid == 0 ? QStringLiteral("断点寄存器: 未绑定进程")
                                : QStringLiteral("断点寄存器: 等待命中"));
  }
  pid_ = pid;
  if (pointer_tools_) {
    pointer_tools_->SetService(service_, service_mutex_, pid_);
  }
  UpdateBreakpointStatusText();
  RefreshBreakpointVisuals();
}

void MemoryViewWindow::SetPluginRuntime(r3::windows_client_qt::plugins::PluginRuntime* runtime) {
  plugin_runtime_ = runtime;
}

void MemoryViewWindow::OpenPointerToolsAtTab(int tab_index) {
  if (!pointer_tools_) {
    pointer_tools_ = new PointerToolsDialog(this);
    pointer_tools_->setAttribute(Qt::WA_DeleteOnClose, false);
  }
  pointer_tools_->SetService(service_, service_mutex_, pid_);
  if (tab_index >= static_cast<int>(PointerToolsDialog::kPointerScanTab) &&
      tab_index <= static_cast<int>(PointerToolsDialog::kStructureTraverseTab)) {
    pointer_tools_->OpenTab(static_cast<PointerToolsDialog::ToolTab>(tab_index));
  }
  pointer_tools_->show();
  pointer_tools_->raise();
  pointer_tools_->activateWindow();
}

void MemoryViewWindow::JumpToAddress(uint64_t address) {
  current_address_ = address;
  address_edit_->setText(Hex64(address));
  RefreshBytes(address);
}

void MemoryViewWindow::OnJumpClicked() {
  bool ok = false;
  const uint64_t address = ParseJumpAddress(address_edit_->text(), &ok);
  if (!ok) {
    QMessageBox::warning(this, QStringLiteral("跳转失败"), QStringLiteral("地址/模块表达式无效"));
    return;
  }
  JumpToAddress(address);
}

void MemoryViewWindow::OnRefreshClicked() {
  if (current_address_ == 0) {
    OnJumpClicked();
    return;
  }
  RefreshBytes(current_address_);
}

void MemoryViewWindow::OnToggleExecBreakpoint() {
  const uint64_t addr = SelectedAddressForBreakpoint();
  if (addr == 0) {
    SetBreakpointStatus(QStringLiteral("断点地址无效"));
    return;
  }
  QString error;
  if (HasBreakpoint(addr, protocol::DEBUG_BP_EXEC)) {
    QString err1;
    QString err2;
    const bool ok_ptrace =
        RemoveBreakpoint(addr, protocol::DEBUG_BP_EXEC, protocol::DEBUG_BACKEND_PTRACE, &err1);
    const bool ok_perf =
        RemoveBreakpoint(addr, protocol::DEBUG_BP_EXEC, protocol::DEBUG_BACKEND_PERF, &err2);
    if (!ok_ptrace && !ok_perf) {
      error = !err1.isEmpty() ? err1 : err2;
      SetBreakpointStatus(error);
      return;
    }
    SetBreakpointStatus(QStringLiteral("已删除执行断点: %1").arg(Hex64(addr)));
  } else {
    if (!AddBreakpoint(addr, protocol::DEBUG_BP_EXEC, 4, &error)) {
      SetBreakpointStatus(error);
      return;
    }
    SetBreakpointStatus(QStringLiteral("已添加执行断点: %1").arg(Hex64(addr)));
  }
  RefreshBreakpointVisuals();
}

void MemoryViewWindow::OnAddWriteBreakpoint() {
  const uint64_t addr = SelectedAddressForBreakpoint();
  if (addr == 0) {
    SetBreakpointStatus(QStringLiteral("断点地址无效"));
    return;
  }
  uint8_t watch_size = 4;
  if (hex_table_ && hex_table_->hasFocus()) {
    watch_size = 1;
  } else if (pointer_size_ == 4 || pointer_size_ == 8) {
    watch_size = std::min<uint8_t>(pointer_size_, 4);
  }
  QString error;
  if (!AddBreakpoint(addr, protocol::DEBUG_BP_WRITE, watch_size, &error)) {
    SetBreakpointStatus(error);
    return;
  }
  SetBreakpointStatus(QStringLiteral("已添加写入断点: %1").arg(Hex64(addr)));
  RefreshBreakpointVisuals();
}

void MemoryViewWindow::OnAddReadBreakpoint() {
  const uint64_t addr = SelectedAddressForBreakpoint();
  if (addr == 0) {
    SetBreakpointStatus(QStringLiteral("断点地址无效"));
    return;
  }
  uint8_t watch_size = 4;
  if (hex_table_ && hex_table_->hasFocus()) {
    watch_size = 1;
  } else if (pointer_size_ == 4 || pointer_size_ == 8) {
    watch_size = std::min<uint8_t>(pointer_size_, 4);
  }
  QString error;
  if (!AddBreakpoint(addr, protocol::DEBUG_BP_READ, watch_size, &error)) {
    SetBreakpointStatus(error);
    return;
  }
  SetBreakpointStatus(QStringLiteral("已添加读取断点: %1").arg(Hex64(addr)));
  RefreshBreakpointVisuals();
}

void MemoryViewWindow::OnAddReadWriteBreakpoint() {
  const uint64_t addr = SelectedAddressForBreakpoint();
  if (addr == 0) {
    SetBreakpointStatus(QStringLiteral("断点地址无效"));
    return;
  }
  uint8_t watch_size = 4;
  if (hex_table_ && hex_table_->hasFocus()) {
    watch_size = 1;
  } else if (pointer_size_ == 4 || pointer_size_ == 8) {
    watch_size = std::min<uint8_t>(pointer_size_, 4);
  }
  QString error;
  if (!AddBreakpoint(addr, protocol::DEBUG_BP_READWRITE, watch_size, &error)) {
    SetBreakpointStatus(error);
    return;
  }
  SetBreakpointStatus(QStringLiteral("已添加读写断点: %1").arg(Hex64(addr)));
  RefreshBreakpointVisuals();
}

void MemoryViewWindow::OnRemoveAddressBreakpoints() {
  const uint64_t addr = SelectedAddressForBreakpoint();
  if (addr == 0) {
    SetBreakpointStatus(QStringLiteral("断点地址无效"));
    return;
  }
  QString error;
  if (!RemoveAllBreakpointsAt(addr, &error)) {
    SetBreakpointStatus(error);
    return;
  }
  SetBreakpointStatus(QStringLiteral("已删除当前地址断点: %1").arg(Hex64(addr)));
  RefreshBreakpointVisuals();
}

void MemoryViewWindow::OnClearAllBreakpoints() {
  QString error;
  if (!ClearAllBreakpointsOnDevice(&error)) {
    SetBreakpointStatus(error);
    return;
  }
  breakpoints_.clear();
  breakpoint_hit_total_ = 0;
  breakpoint_last_hit_addr_ = 0;
  if (breakpoint_hits_model_) {
    breakpoint_hits_model_->removeRows(0, breakpoint_hits_model_->rowCount());
  }
  if (breakpoint_hits_label_) {
    breakpoint_hits_label_->setText(QStringLiteral("命中记录(最近): 0"));
  }
  ResetRegisterPanel(QStringLiteral("断点寄存器: 等待命中"));
  SetBreakpointStatus(QStringLiteral("已清空全部断点"));
  RefreshBreakpointVisuals();
}

void MemoryViewWindow::OnDebugPauseProcess() {
  QString ready_error;
  if (!EnsureBreakpointReady(&ready_error)) {
    SetBreakpointStatus(ready_error);
    return;
  }
  std::string error;
  bool ok = false;
  {
    const std::lock_guard<std::mutex> lock(*service_mutex_);
    ok = service_->DebugAttach(pid_, true, &error);
  }
  if (!ok) {
    const QString text = ToQString(error).trimmed().isEmpty() ? QStringLiteral("暂停失败")
                                                               : ToQString(error).trimmed();
    SetBreakpointStatus(text);
    return;
  }
  debug_attached_ = true;

  r3::windows_client_ng::services::ClientService::RegsSnapshot regs{};
  std::string regs_error;
  bool regs_ok = false;
  {
    const std::lock_guard<std::mutex> lock(*service_mutex_);
    regs_ok = service_->FetchRegs(pid_, &regs, &regs_error);
  }
  if (regs_ok) {
    UpdateRegisterPanel(regs);
    uint64_t pc = 0;
    if (regs.arch == protocol::RegsArch::ARM64) {
      pc = regs.arm64.pc;
    } else if (regs.arch == protocol::RegsArch::ARM32) {
      pc = regs.arm32.regs[15];
    }
    if (pc != 0) {
      JumpToAddress(pc);
    } else {
      RefreshBreakpointVisuals();
    }
  } else {
    const QString text = ToQString(regs_error).trimmed();
    ResetRegisterPanel(text.isEmpty() ? QStringLiteral("已暂停，但读取寄存器失败")
                                      : QStringLiteral("已暂停，但读取寄存器失败: %1").arg(text));
    RefreshBreakpointVisuals();
  }
  SetBreakpointStatus(QStringLiteral("进程已暂停"));
}

void MemoryViewWindow::OnDebugContinueProcess() {
  QString ready_error;
  if (!EnsureBreakpointReady(&ready_error)) {
    SetBreakpointStatus(ready_error);
    return;
  }
  std::string error;
  bool ok = false;
  {
    const std::lock_guard<std::mutex> lock(*service_mutex_);
    ok = service_->DebugDetach(&error);
  }
  if (!ok) {
    const QString text = ToQString(error).trimmed();
    if (!debug_attached_) {
      SetBreakpointStatus(QStringLiteral("当前未处于暂停调试状态"));
    } else {
      SetBreakpointStatus(text.isEmpty() ? QStringLiteral("继续运行失败") : text);
    }
    return;
  }
  debug_attached_ = false;
  SetBreakpointStatus(QStringLiteral("已继续运行"));
  RefreshBreakpointVisuals();
}

void MemoryViewWindow::OnDebugStepIn() {
  QString ready_error;
  if (!EnsureBreakpointReady(&ready_error)) {
    SetBreakpointStatus(ready_error);
    return;
  }
  if (breakpoint_backend_ != protocol::DEBUG_BACKEND_PTRACE) {
    SetBreakpointStatus(QStringLiteral("仅 ptrace 模式支持 F7/F8"));
    return;
  }
  if (!debug_attached_) {
    OnDebugPauseProcess();
    if (!debug_attached_) {
      return;
    }
  }

  std::string error;
  bool ok = false;
  {
    const std::lock_guard<std::mutex> lock(*service_mutex_);
    ok = service_->DebugStepIn(pid_, &error);
  }
  if (!ok) {
    const QString text = ToQString(error).trimmed();
    SetBreakpointStatus(text.isEmpty() ? QStringLiteral("单步步入失败") : text);
    return;
  }

  r3::windows_client_ng::services::ClientService::RegsSnapshot regs{};
  std::string regs_error;
  bool regs_ok = false;
  {
    const std::lock_guard<std::mutex> lock(*service_mutex_);
    regs_ok = service_->FetchRegs(pid_, &regs, &regs_error);
  }
  if (regs_ok) {
    UpdateRegisterPanel(regs);
    uint64_t pc = 0;
    if (regs.arch == protocol::RegsArch::ARM64) {
      pc = regs.arm64.pc;
    } else if (regs.arch == protocol::RegsArch::ARM32) {
      pc = regs.arm32.regs[15];
    }
    if (pc != 0) {
      JumpToAddress(pc);
    } else {
      RefreshBreakpointVisuals();
    }
  } else {
    const QString text = ToQString(regs_error).trimmed();
    ResetRegisterPanel(text.isEmpty() ? QStringLiteral("单步完成，但读取寄存器失败")
                                      : QStringLiteral("单步完成，但读取寄存器失败: %1").arg(text));
    RefreshBreakpointVisuals();
  }
  SetBreakpointStatus(QStringLiteral("单步步入完成"));
}

void MemoryViewWindow::OnDebugStepOver() {
  QString ready_error;
  if (!EnsureBreakpointReady(&ready_error)) {
    SetBreakpointStatus(ready_error);
    return;
  }
  if (breakpoint_backend_ != protocol::DEBUG_BACKEND_PTRACE) {
    SetBreakpointStatus(QStringLiteral("仅 ptrace 模式支持 F7/F8"));
    return;
  }
  if (!debug_attached_) {
    OnDebugPauseProcess();
    if (!debug_attached_) {
      return;
    }
  }

  std::string error;
  bool ok = false;
  {
    const std::lock_guard<std::mutex> lock(*service_mutex_);
    ok = service_->DebugStepOver(pid_, &error);
  }
  if (!ok) {
    const QString text = ToQString(error).trimmed();
    SetBreakpointStatus(text.isEmpty() ? QStringLiteral("单步步过失败") : text);
    return;
  }

  r3::windows_client_ng::services::ClientService::RegsSnapshot regs{};
  std::string regs_error;
  bool regs_ok = false;
  {
    const std::lock_guard<std::mutex> lock(*service_mutex_);
    regs_ok = service_->FetchRegs(pid_, &regs, &regs_error);
  }
  if (regs_ok) {
    UpdateRegisterPanel(regs);
    uint64_t pc = 0;
    if (regs.arch == protocol::RegsArch::ARM64) {
      pc = regs.arm64.pc;
    } else if (regs.arch == protocol::RegsArch::ARM32) {
      pc = regs.arm32.regs[15];
    }
    if (pc != 0) {
      JumpToAddress(pc);
    } else {
      RefreshBreakpointVisuals();
    }
  } else {
    const QString text = ToQString(regs_error).trimmed();
    ResetRegisterPanel(text.isEmpty() ? QStringLiteral("步过完成，但读取寄存器失败")
                                      : QStringLiteral("步过完成，但读取寄存器失败: %1").arg(text));
    RefreshBreakpointVisuals();
  }
  SetBreakpointStatus(QStringLiteral("单步步过完成"));
}

void MemoryViewWindow::OnClearBreakpointHitHistory() {
  if (breakpoint_hits_model_) {
    breakpoint_hits_model_->removeRows(0, breakpoint_hits_model_->rowCount());
  }
  if (breakpoint_hits_label_) {
    breakpoint_hits_label_->setText(QStringLiteral("命中记录(最近): 0"));
  }
  breakpoint_hit_total_ = 0;
  breakpoint_last_hit_addr_ = 0;
  SetBreakpointStatus(QStringLiteral("已清空命中记录"));
  RefreshBreakpointVisuals();
}

void MemoryViewWindow::OnShowContextMenu(const QPoint& pos) {
  uint64_t addr = SelectedDisasmAddress();
  if (addr == 0) {
    addr = current_address_;
  }
  const bool ptrace_mode = breakpoint_backend_ == protocol::DEBUG_BACKEND_PTRACE;
  const bool has_exec = HasBreakpoint(addr, protocol::DEBUG_BP_EXEC);
  const bool has_exec_sw = HasBreakpoint(addr, protocol::DEBUG_BP_EXEC, protocol::DEBUG_BACKEND_PTRACE);
  const bool has_exec_hw = HasBreakpoint(addr, protocol::DEBUG_BP_EXEC, protocol::DEBUG_BACKEND_PERF);
  const bool has_any = HasAnyBreakpointAt(addr);

  QMenu menu(this);
  QAction* copy_addr = menu.addAction(QStringLiteral("复制地址"));
  QAction* copy_alias = menu.addAction(QStringLiteral("复制模块+offset"));
  QAction* copy_bytes = menu.addAction(QStringLiteral("复制字节文本"));
  QAction* jump_here = menu.addAction(QStringLiteral("跳转到此"));
  menu.addSeparator();
  QAction* add_addr = menu.addAction(QStringLiteral("添加到地址列表"));
  QAction* refresh_action = menu.addAction(QStringLiteral("刷新"));
  menu.addSeparator();
  QAction* toggle_exec = nullptr;
  QAction* toggle_exec_soft = nullptr;
  QAction* toggle_exec_hard = nullptr;
  if (ptrace_mode) {
    QMenu* exec_menu = menu.addMenu(QStringLiteral("执行断点类型"));
    toggle_exec_soft = exec_menu->addAction(has_exec_sw ? QStringLiteral("删除软件断点 (BRK/ptrace)")
                                                        : QStringLiteral("添加软件断点 (BRK/ptrace)"));
    toggle_exec_hard = exec_menu->addAction(has_exec_hw ? QStringLiteral("删除硬件断点 (perf)")
                                                        : QStringLiteral("添加硬件断点 (perf)"));
  } else {
    toggle_exec =
        menu.addAction(has_exec ? QStringLiteral("删除执行断点 (F2)") : QStringLiteral("添加执行断点 (F2)"));
  }
  QAction* add_write = menu.addAction(QStringLiteral("添加写入断点"));
  QAction* add_read = menu.addAction(QStringLiteral("添加读取断点"));
  QAction* add_rw = menu.addAction(QStringLiteral("添加读写断点"));
  QAction* remove_here = menu.addAction(QStringLiteral("删除当前地址全部断点"));
  remove_here->setEnabled(has_any);
  QAction* clear_all = menu.addAction(QStringLiteral("清空全部断点"));
  menu.addSeparator();
  QAction* pause_dbg = menu.addAction(QStringLiteral("暂停进程"));
  QAction* continue_dbg = menu.addAction(QStringLiteral("继续运行 (F9)"));
  QAction* clear_hits = menu.addAction(QStringLiteral("清空命中记录"));

  QAction* picked = menu.exec(disasm_table_->viewport()->mapToGlobal(pos));
  if (!picked) {
    return;
  }
  if (picked == copy_addr) {
    QApplication::clipboard()->setText(Hex64(addr));
    return;
  }
  if (picked == copy_alias) {
    QApplication::clipboard()->setText(BuildAddressAlias(addr));
    return;
  }
  if (picked == copy_bytes) {
    const QModelIndex idx = disasm_table_->currentIndex();
    const QString bytes = idx.isValid() ? disasm_model_->data(idx.sibling(idx.row(), 1)).toString() : QString();
    QApplication::clipboard()->setText(bytes);
    return;
  }
  if (picked == jump_here) {
    JumpToAddress(addr);
    return;
  }
  if (picked == add_addr) {
    emit RequestAddAddress(addr);
    return;
  }
  if (picked == refresh_action) {
    RefreshBytes(current_address_);
    return;
  }
  if (picked == toggle_exec) {
    OnToggleExecBreakpoint();
    return;
  }
  if (picked == toggle_exec_soft || picked == toggle_exec_hard) {
    const protocol::DebugBackend backend =
        (picked == toggle_exec_soft) ? protocol::DEBUG_BACKEND_PTRACE : protocol::DEBUG_BACKEND_PERF;
    const bool existed = (backend == protocol::DEBUG_BACKEND_PTRACE) ? has_exec_sw : has_exec_hw;
    QString error;
    if (existed) {
      if (!RemoveBreakpoint(addr, protocol::DEBUG_BP_EXEC, backend, &error)) {
        SetBreakpointStatus(error.isEmpty() ? QStringLiteral("删除执行断点失败") : error);
        return;
      }
      SetBreakpointStatus(QStringLiteral("已删除执行断点: %1 [%2]")
                              .arg(Hex64(addr), BreakpointBackendText(backend)));
    } else {
      if (!AddBreakpointWithBackend(addr, protocol::DEBUG_BP_EXEC, 4, backend, &error)) {
        SetBreakpointStatus(error.isEmpty() ? QStringLiteral("设置执行断点失败") : error);
        return;
      }
      SetBreakpointStatus(QStringLiteral("已添加执行断点: %1 [%2]")
                              .arg(Hex64(addr), BreakpointBackendText(backend)));
    }
    RefreshBreakpointVisuals();
    return;
  }
  if (picked == add_write) {
    OnAddWriteBreakpoint();
    return;
  }
  if (picked == add_read) {
    OnAddReadBreakpoint();
    return;
  }
  if (picked == add_rw) {
    OnAddReadWriteBreakpoint();
    return;
  }
  if (picked == remove_here) {
    OnRemoveAddressBreakpoints();
    return;
  }
  if (picked == clear_all) {
    OnClearAllBreakpoints();
    return;
  }
  if (picked == pause_dbg) {
    OnDebugPauseProcess();
    return;
  }
  if (picked == continue_dbg) {
    OnDebugContinueProcess();
    return;
  }
  if (picked == clear_hits) {
    OnClearBreakpointHitHistory();
    return;
  }
}

void MemoryViewWindow::OnHexContextMenu(const QPoint& pos) {
  uint64_t addr = SelectedHexAddress();
  if (addr == 0) {
    addr = current_address_;
  }
  const bool ptrace_mode = breakpoint_backend_ == protocol::DEBUG_BACKEND_PTRACE;
  const bool has_exec = HasBreakpoint(addr, protocol::DEBUG_BP_EXEC);
  const bool has_exec_sw = HasBreakpoint(addr, protocol::DEBUG_BP_EXEC, protocol::DEBUG_BACKEND_PTRACE);
  const bool has_exec_hw = HasBreakpoint(addr, protocol::DEBUG_BP_EXEC, protocol::DEBUG_BACKEND_PERF);
  const bool has_any = HasAnyBreakpointAt(addr);

  QMenu menu(this);
  QAction* copy_addr = menu.addAction(QStringLiteral("复制地址"));
  QAction* copy_row = menu.addAction(QStringLiteral("复制本行字节"));
  QAction* jump_here = menu.addAction(QStringLiteral("跳转到此"));
  menu.addSeparator();
  QAction* add_addr = menu.addAction(QStringLiteral("添加到地址列表"));
  menu.addSeparator();
  QAction* toggle_exec = nullptr;
  QAction* toggle_exec_soft = nullptr;
  QAction* toggle_exec_hard = nullptr;
  if (ptrace_mode) {
    QMenu* exec_menu = menu.addMenu(QStringLiteral("执行断点类型"));
    toggle_exec_soft = exec_menu->addAction(has_exec_sw ? QStringLiteral("删除软件断点 (BRK/ptrace)")
                                                        : QStringLiteral("添加软件断点 (BRK/ptrace)"));
    toggle_exec_hard = exec_menu->addAction(has_exec_hw ? QStringLiteral("删除硬件断点 (perf)")
                                                        : QStringLiteral("添加硬件断点 (perf)"));
  } else {
    toggle_exec =
        menu.addAction(has_exec ? QStringLiteral("删除执行断点 (F2)") : QStringLiteral("添加执行断点 (F2)"));
  }
  QAction* add_write = menu.addAction(QStringLiteral("添加写入断点"));
  QAction* add_read = menu.addAction(QStringLiteral("添加读取断点"));
  QAction* add_rw = menu.addAction(QStringLiteral("添加读写断点"));
  QAction* remove_here = menu.addAction(QStringLiteral("删除当前地址全部断点"));
  remove_here->setEnabled(has_any);
  QAction* clear_all = menu.addAction(QStringLiteral("清空全部断点"));
  menu.addSeparator();
  QAction* pause_dbg = menu.addAction(QStringLiteral("暂停进程"));
  QAction* continue_dbg = menu.addAction(QStringLiteral("继续运行 (F9)"));
  QAction* clear_hits = menu.addAction(QStringLiteral("清空命中记录"));

  QAction* picked = menu.exec(hex_table_->viewport()->mapToGlobal(pos));
  if (!picked) {
    return;
  }
  if (picked == copy_addr) {
    QApplication::clipboard()->setText(Hex64(addr));
    return;
  }
  if (picked == copy_row) {
    const QModelIndex idx = hex_table_->currentIndex();
    if (!idx.isValid()) {
      return;
    }
    QString line;
    for (int col = 1; col <= 16; ++col) {
      const QString token = hex_model_->data(idx.sibling(idx.row(), col)).toString();
      if (token.isEmpty()) {
        continue;
      }
      if (!line.isEmpty()) {
        line.append(' ');
      }
      line.append(token);
    }
    QApplication::clipboard()->setText(line);
    return;
  }
  if (picked == jump_here) {
    JumpToAddress(addr);
    return;
  }
  if (picked == add_addr) {
    emit RequestAddAddress(addr);
    return;
  }
  if (picked == toggle_exec) {
    OnToggleExecBreakpoint();
    return;
  }
  if (picked == toggle_exec_soft || picked == toggle_exec_hard) {
    const protocol::DebugBackend backend =
        (picked == toggle_exec_soft) ? protocol::DEBUG_BACKEND_PTRACE : protocol::DEBUG_BACKEND_PERF;
    const bool existed = (backend == protocol::DEBUG_BACKEND_PTRACE) ? has_exec_sw : has_exec_hw;
    QString error;
    if (existed) {
      if (!RemoveBreakpoint(addr, protocol::DEBUG_BP_EXEC, backend, &error)) {
        SetBreakpointStatus(error.isEmpty() ? QStringLiteral("删除执行断点失败") : error);
        return;
      }
      SetBreakpointStatus(QStringLiteral("已删除执行断点: %1 [%2]")
                              .arg(Hex64(addr), BreakpointBackendText(backend)));
    } else {
      if (!AddBreakpointWithBackend(addr, protocol::DEBUG_BP_EXEC, 4, backend, &error)) {
        SetBreakpointStatus(error.isEmpty() ? QStringLiteral("设置执行断点失败") : error);
        return;
      }
      SetBreakpointStatus(QStringLiteral("已添加执行断点: %1 [%2]")
                              .arg(Hex64(addr), BreakpointBackendText(backend)));
    }
    RefreshBreakpointVisuals();
    return;
  }
  if (picked == add_write) {
    OnAddWriteBreakpoint();
    return;
  }
  if (picked == add_read) {
    OnAddReadBreakpoint();
    return;
  }
  if (picked == add_rw) {
    OnAddReadWriteBreakpoint();
    return;
  }
  if (picked == remove_here) {
    OnRemoveAddressBreakpoints();
    return;
  }
  if (picked == clear_all) {
    OnClearAllBreakpoints();
    return;
  }
  if (picked == pause_dbg) {
    OnDebugPauseProcess();
    return;
  }
  if (picked == continue_dbg) {
    OnDebugContinueProcess();
    return;
  }
  if (picked == clear_hits) {
    OnClearBreakpointHitHistory();
  }
}

void MemoryViewWindow::OnDisasmDoubleClicked(const QModelIndex& index) {
  if (!index.isValid()) {
    return;
  }
  const uint64_t addr = disasm_model_->data(index.sibling(index.row(), 0), kAddressRole).toULongLong();
  if (addr != 0) {
    JumpToAddress(addr);
  }
}

void MemoryViewWindow::OnHexDoubleClicked(const QModelIndex& index) {
  if (!index.isValid()) {
    return;
  }
  uint64_t base = hex_model_->data(index.sibling(index.row(), 0), kAddressRole).toULongLong();
  if (base == 0) {
    return;
  }
  if (index.column() >= 1 && index.column() <= 16) {
    const QString token = hex_model_->data(index).toString();
    if (!token.isEmpty()) {
      base += static_cast<uint64_t>(index.column() - 1);
    }
  }
  JumpToAddress(base);
}

bool MemoryViewWindow::RefreshBytes(uint64_t address) {
  if (!service_ || !service_mutex_) {
    info_label_->setText(QStringLiteral("未绑定服务"));
    disasm_model_->removeRows(0, disasm_model_->rowCount());
    hex_model_->removeRows(0, hex_model_->rowCount());
    return false;
  }

  RefreshProcInfo();
  (void)EnsureModulesLoaded();

  std::vector<uint8_t> bytes;
  std::string error;
  {
    const std::lock_guard<std::mutex> lock(*service_mutex_);
    if (!service_->ReadMemory(address, 1024, true, &bytes, &error)) {
      info_label_->setText(QStringLiteral("读取失败: %1").arg(ToQString(error)));
      disasm_model_->removeRows(0, disasm_model_->rowCount());
      hex_model_->removeRows(0, hex_model_->rowCount());
      return false;
    }
  }

  current_address_ = address;
  current_bytes_ = bytes;
  PopulateDisasmTable(address, current_bytes_);
  PopulateHexTable(address, current_bytes_);

  QString perm_text = QStringLiteral("---");
  QString segment_text = QStringLiteral("O(Other)");
  for (const auto& module : modules_) {
    if (address >= module.start && address < module.end) {
      perm_text = BuildPermText(module.perms);
      segment_text = GGSegmentText(module);
      break;
    }
  }
  info_label_->setText(QStringLiteral("地址: %1  别名: %2  架构: %3  指针: %4  保护: %5  段: %6  长度: %7")
                           .arg(Hex64(address),
                                BuildAddressAlias(address),
                                ArchText(arch_),
                                QString::number(pointer_size_),
                                perm_text,
                                segment_text)
                           .arg(current_bytes_.size()));
  UpdateBreakpointStatusText();
  return true;
}

void MemoryViewWindow::PollBreakpointEvents() {
  if (!isVisible() || !service_ || !service_mutex_ || pid_ == 0 || breakpoints_.empty()) {
    return;
  }
  bool connected = false;
  {
    const std::lock_guard<std::mutex> lock(*service_mutex_);
    connected = service_->IsConnected();
  }
  if (!connected) {
    return;
  }

  bool has_perf = false;
  bool has_ptrace = false;
  for (const auto& bp : breakpoints_) {
    if (!bp.enabled) {
      continue;
    }
    if (bp.backend == protocol::DEBUG_BACKEND_PERF) {
      has_perf = true;
    } else if (bp.backend == protocol::DEBUG_BACKEND_PTRACE) {
      has_ptrace = true;
    }
  }
  if (!has_perf && !has_ptrace) {
    return;
  }

  uint64_t hit_total = 0;
  uint64_t hit_addr = 0;
  protocol::DebugBpType hit_type = protocol::DEBUG_BP_EXEC;
  uint8_t hit_size = 0;
  protocol::DebugBackend hit_backend = breakpoint_backend_;

  auto poll_one = [&](protocol::DebugBackend backend) {
    std::vector<r3::windows_client_ng::services::ClientService::BreakpointEvent> events;
    std::string error;
    bool ok = false;
    {
      const std::lock_guard<std::mutex> lock(*service_mutex_);
      ok = service_->PollBreakpoints(pid_, backend, 0, 128, &events, &error);
    }
    if (!ok || events.empty()) {
      return;
    }
    for (const auto& ev : events) {
      for (auto& bp : breakpoints_) {
        if (!bp.enabled || bp.backend != backend) {
          continue;
        }
        const bool type_match = static_cast<uint32_t>(bp.type) == ev.type;
        const bool size_match = (ev.size == 0) || (bp.size == static_cast<uint8_t>(ev.size));
        if (!type_match || !size_match || bp.address != ev.address) {
          continue;
        }
        bp.hit_count += ev.count;
        if (ev.count > 0) {
          hit_total += ev.count;
          hit_addr = ev.address;
          hit_type = bp.type;
          hit_size = bp.size;
          hit_backend = backend;
          AppendBreakpointHit(ev.address, bp.type, backend, bp.size, ev.count);
        }
        break;
      }
    }
  };

  if (has_perf) {
    poll_one(protocol::DEBUG_BACKEND_PERF);
  }
  if (has_ptrace) {
    poll_one(protocol::DEBUG_BACKEND_PTRACE);
  }
  if (hit_total == 0) {
    return;
  }
  if (breakpoint_stop_on_hit_) {
    debug_attached_ = true;
  }

  breakpoint_hit_total_ += hit_total;
  breakpoint_last_hit_addr_ = hit_addr;
  SetBreakpointStatus(QStringLiteral("命中 %1 次 @ %2 [%3/%4 size=%5]")
                          .arg(hit_total)
                          .arg(Hex64(hit_addr))
                          .arg(BreakpointTypeShortText(hit_type))
                          .arg(BreakpointBackendText(hit_backend))
                          .arg(hit_size));

  r3::windows_client_ng::services::ClientService::RegsSnapshot regs{};
  std::string regs_error;
  bool regs_ok = false;
  {
    const std::lock_guard<std::mutex> lock(*service_mutex_);
    regs_ok = service_->FetchRegs(pid_, &regs, &regs_error);
  }
  if (regs_ok) {
    UpdateRegisterPanel(regs);
  } else {
    const QString err = ToQString(regs_error).trimmed();
    ResetRegisterPanel(err.isEmpty() ? QStringLiteral("断点命中，但寄存器读取失败")
                                     : QStringLiteral("断点命中，但寄存器读取失败: %1").arg(err));
  }

  if (hit_addr != 0) {
    JumpToAddress(hit_addr);
  } else {
    RefreshBreakpointVisuals();
  }
}

void MemoryViewWindow::AppendBreakpointHit(uint64_t address,
                                           protocol::DebugBpType type,
                                           protocol::DebugBackend backend,
                                           uint8_t size,
                                           uint64_t count) {
  if (!breakpoint_hits_model_ || count == 0) {
    return;
  }
  breakpoint_hits_model_->insertRow(0);
  auto* c0 = new QStandardItem(QDateTime::currentDateTime().toString(QStringLiteral("HH:mm:ss.zzz")));
  auto* c1 = new QStandardItem(Hex64(address));
  auto* c2 = new QStandardItem(
      QStringLiteral("%1 / %2 / %3B").arg(BreakpointTypeShortText(type), BreakpointBackendText(backend)).arg(size));
  auto* c3 = new QStandardItem(QString::number(static_cast<qulonglong>(count)));
  c0->setTextAlignment(Qt::AlignCenter);
  c1->setTextAlignment(Qt::AlignRight | Qt::AlignVCenter);
  c2->setTextAlignment(Qt::AlignLeft | Qt::AlignVCenter);
  c3->setTextAlignment(Qt::AlignRight | Qt::AlignVCenter);
  breakpoint_hits_model_->setItem(0, 0, c0);
  breakpoint_hits_model_->setItem(0, 1, c1);
  breakpoint_hits_model_->setItem(0, 2, c2);
  breakpoint_hits_model_->setItem(0, 3, c3);
  while (breakpoint_hits_model_->rowCount() > 200) {
    breakpoint_hits_model_->removeRow(breakpoint_hits_model_->rowCount() - 1);
  }
  if (breakpoint_hits_label_) {
    breakpoint_hits_label_->setText(QStringLiteral("命中记录(最近): %1").arg(breakpoint_hits_model_->rowCount()));
  }
  if (breakpoint_hits_table_) {
    breakpoint_hits_table_->resizeRowsToContents();
    breakpoint_hits_table_->setCurrentIndex(breakpoint_hits_model_->index(0, 0));
  }
}

void MemoryViewWindow::UpdateDebugPanelVisibility() {
  if (!top_splitter_ || !debug_panel_) {
    return;
  }
  const bool should_show = !breakpoints_.empty() && breakpoint_hit_total_ > 0;
  const bool currently_visible = debug_panel_->isVisible();
  if (debug_panel_visible_ == should_show && currently_visible == should_show) {
    return;
  }
  debug_panel_visible_ = should_show;
  debug_panel_->setVisible(should_show);
  if (should_show) {
    top_splitter_->setSizes(QList<int>({1, 1}));
  } else {
    top_splitter_->setSizes(QList<int>({1, 0}));
  }
}

void MemoryViewWindow::ResetRegisterPanel(const QString& tip) {
  if (register_model_) {
    register_model_->removeRows(0, register_model_->rowCount());
    register_model_->setRowCount(1);
    auto* c0 = new QStandardItem(QStringLiteral("-"));
    auto* c1 = new QStandardItem(QStringLiteral("-"));
    auto* c2 = new QStandardItem(QStringLiteral("-"));
    register_model_->setItem(0, 0, c0);
    register_model_->setItem(0, 1, c1);
    register_model_->setItem(0, 2, c2);
  }
  if (register_label_) {
    const QString text = tip.trimmed().isEmpty() ? QStringLiteral("断点寄存器: 等待命中") : tip.trimmed();
    register_label_->setText(text);
  }
}

void MemoryViewWindow::UpdateRegisterPanel(const r3::windows_client_ng::services::ClientService::RegsSnapshot& regs) {
  if (!register_model_) {
    return;
  }
  register_model_->removeRows(0, register_model_->rowCount());

  auto add_row = [this](const QString& name, uint64_t value, int hex_width) {
    const int row = register_model_->rowCount();
    register_model_->setRowCount(row + 1);
    auto* c0 = new QStandardItem(name);
    auto* c1 =
        new QStandardItem(QStringLiteral("0x%1").arg(QString::number(value, 16).toUpper().rightJustified(hex_width, QLatin1Char('0'))));
    auto* c2 = new QStandardItem(QString::number(static_cast<qulonglong>(value)));
    c0->setTextAlignment(Qt::AlignLeft | Qt::AlignVCenter);
    c1->setTextAlignment(Qt::AlignRight | Qt::AlignVCenter);
    c2->setTextAlignment(Qt::AlignRight | Qt::AlignVCenter);
    register_model_->setItem(row, 0, c0);
    register_model_->setItem(row, 1, c1);
    register_model_->setItem(row, 2, c2);
  };

  QString arch_text = QStringLiteral("UNKNOWN");
  if (regs.arch == protocol::RegsArch::ARM64) {
    arch_text = QStringLiteral("ARM64");
    for (int i = 0; i < 31; ++i) {
      add_row(QStringLiteral("x%1").arg(i), regs.arm64.regs[i], 16);
    }
    add_row(QStringLiteral("sp"), regs.arm64.sp, 16);
    add_row(QStringLiteral("pc"), regs.arm64.pc, 16);
    add_row(QStringLiteral("pstate"), regs.arm64.pstate, 16);
  } else if (regs.arch == protocol::RegsArch::ARM32) {
    arch_text = QStringLiteral("ARM32");
    for (int i = 0; i < 16; ++i) {
      add_row(QStringLiteral("r%1").arg(i), regs.arm32.regs[i], 8);
    }
    add_row(QStringLiteral("cpsr"), regs.arm32.cpsr, 8);
    add_row(QStringLiteral("orig_r0"), regs.arm32.orig_r0, 8);
  } else {
    ResetRegisterPanel(QStringLiteral("寄存器架构未知"));
    return;
  }

  if (register_table_) {
    register_table_->resizeRowsToContents();
    register_table_->scrollToTop();
  }
  if (register_label_) {
    QString title = QStringLiteral("断点寄存器: %1  更新时间: %2")
                        .arg(arch_text, QDateTime::currentDateTime().toString(QStringLiteral("HH:mm:ss.zzz")));
    if (breakpoint_last_hit_addr_ != 0) {
      title.append(QStringLiteral("  最近命中: %1").arg(Hex64(breakpoint_last_hit_addr_)));
    }
    register_label_->setText(title);
  }
}

void MemoryViewWindow::RefreshProcInfo() {
  if (!service_ || !service_mutex_ || pid_ == 0 || proc_info_pid_ == pid_) {
    return;
  }
  uint8_t arch = static_cast<uint8_t>(protocol::RegsArch::UNKNOWN);
  uint8_t ptr = 0;
  std::string error;
  bool ok = false;
  {
    const std::lock_guard<std::mutex> lock(*service_mutex_);
    ok = service_->FetchProcInfo(&arch, &ptr, &error);
  }
  proc_info_pid_ = pid_;
  if (ok) {
    arch_ = static_cast<protocol::RegsArch>(arch);
    pointer_size_ = ptr;
  } else {
    arch_ = protocol::RegsArch::UNKNOWN;
    pointer_size_ = 0;
  }
}

bool MemoryViewWindow::EnsureModulesLoaded() {
  if (!service_ || !service_mutex_ || pid_ == 0) {
    return false;
  }
  if (modules_pid_ == pid_ && !modules_.empty()) {
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
    modules_.clear();
    modules_pid_ = 0;
    return false;
  }

  std::sort(modules.begin(), modules.end(), [](const auto& a, const auto& b) {
    if (a.start != b.start) {
      return a.start < b.start;
    }
    return a.end < b.end;
  });
  modules_ = std::move(modules);
  modules_pid_ = pid_;
  return true;
}

uint64_t MemoryViewWindow::ParseNumberText(const QString& text, bool* ok) {
  if (ok) {
    *ok = false;
  }
  QString t = text.trimmed();
  if (t.isEmpty()) {
    return 0;
  }
  int base = 10;
  if (t.startsWith(QStringLiteral("0x"), Qt::CaseInsensitive)) {
    t = t.mid(2);
    base = 16;
  }
  bool parsed = false;
  const qulonglong value = t.toULongLong(&parsed, base);
  if (ok) {
    *ok = parsed;
  }
  return static_cast<uint64_t>(value);
}

uint64_t MemoryViewWindow::ParseJumpAddress(const QString& text, bool* ok) {
  if (ok) {
    *ok = false;
  }
  const QString input = text.trimmed();
  if (input.isEmpty()) {
    return 0;
  }

  bool parsed_number = false;
  const uint64_t direct = ParseNumberText(input, &parsed_number);
  if (parsed_number) {
    if (ok) {
      *ok = true;
    }
    return direct;
  }

  if (!EnsureModulesLoaded() || modules_.empty()) {
    return 0;
  }

  QString expr = input;
  expr.remove('[');
  expr.remove(']');

  QString module_key = expr.trimmed();
  uint64_t offset = 0;
  const int plus = expr.indexOf('+');
  if (plus >= 0) {
    module_key = expr.left(plus).trimmed();
    bool offset_ok = false;
    offset = ParseNumberText(expr.mid(plus + 1).trimmed(), &offset_ok);
    if (!offset_ok) {
      return 0;
    }
  }
  if (module_key.isEmpty()) {
    return 0;
  }

  const QString key_lower = module_key.toLower();
  const r3::windows_client_ng::services::ClientService::ModuleInfo* best = nullptr;
  int best_score = -1;
  for (const auto& module : modules_) {
    const QString path = ToQString(module.path).trimmed();
    const QString name = ModuleDisplayName(module);
    const QString path_lower = path.toLower();
    const QString name_lower = name.toLower();

    int score = -1;
    if (name_lower == key_lower || path_lower == key_lower) {
      score = 3;
    } else if (name_lower.contains(key_lower)) {
      score = 2;
    } else if (path_lower.contains(key_lower)) {
      score = 1;
    }
    if (score > best_score) {
      best_score = score;
      best = &module;
    }
  }
  if (!best || best_score < 0) {
    return 0;
  }

  if (ok) {
    *ok = true;
  }
  return best->start + offset;
}

uint64_t MemoryViewWindow::SelectedAddressForBreakpoint() const {
  uint64_t addr = SelectedDisasmAddress();
  if (addr == 0) {
    addr = SelectedHexAddress();
  }
  if (addr == 0) {
    addr = current_address_;
  }
  return addr;
}

bool MemoryViewWindow::EnsureBreakpointReady(QString* out_error) const {
  if (out_error) {
    out_error->clear();
  }
  if (!service_ || !service_mutex_) {
    if (out_error) {
      *out_error = QStringLiteral("未绑定服务");
    }
    return false;
  }
  if (pid_ == 0) {
    if (out_error) {
      *out_error = QStringLiteral("请先打开进程");
    }
    return false;
  }
  bool connected = false;
  {
    const std::lock_guard<std::mutex> lock(*service_mutex_);
    connected = service_->IsConnected();
  }
  if (!connected) {
    if (out_error) {
      *out_error = QStringLiteral("服务未连接");
    }
    return false;
  }
  return true;
}

bool MemoryViewWindow::AddBreakpoint(uint64_t address,
                                     protocol::DebugBpType type,
                                     uint8_t size,
                                     QString* out_error) {
  return AddBreakpointWithBackend(address, type, size, breakpoint_backend_, out_error);
}

bool MemoryViewWindow::AddBreakpointWithBackend(uint64_t address,
                                                protocol::DebugBpType type,
                                                uint8_t size,
                                                protocol::DebugBackend backend,
                                                QString* out_error) {
  if (out_error) {
    out_error->clear();
  }
  QString ready_error;
  if (!EnsureBreakpointReady(&ready_error)) {
    if (out_error) {
      *out_error = ready_error;
    }
    return false;
  }

  if (size == 0) {
    size = 1;
  } else if (size > 8) {
    size = 8;
  }

  if (backend == protocol::DEBUG_BACKEND_PTRACE && type != protocol::DEBUG_BP_EXEC) {
    if (out_error) {
      *out_error = QStringLiteral("ptrace 仅支持执行断点");
    }
    return false;
  }

  for (const auto& bp : breakpoints_) {
    if (bp.enabled && bp.address == address && bp.type == type && bp.backend == backend) {
      return true;
    }
  }

  std::string error;
  const uint8_t flags = breakpoint_stop_on_hit_ ? protocol::DEBUG_BP_FLAG_STOP_ON_HIT : 0;
  bool ok = false;
  {
    const std::lock_guard<std::mutex> lock(*service_mutex_);
    ok = service_->SetBreakpoint(pid_, backend, type, size, flags, address, &error);
  }
  if (!ok) {
    if (out_error) {
      *out_error = ToQString(error).trimmed();
      if (out_error->isEmpty()) {
        *out_error = QStringLiteral("设置断点失败");
      }
    }
    return false;
  }

  BreakpointEntry entry;
  entry.address = address;
  entry.type = type;
  entry.size = size;
  entry.backend = backend;
  entry.enabled = true;
  entry.hit_count = 0;
  breakpoints_.push_back(entry);
  return true;
}

bool MemoryViewWindow::RemoveBreakpoint(uint64_t address,
                                        protocol::DebugBpType type,
                                        protocol::DebugBackend backend,
                                        QString* out_error) {
  if (out_error) {
    out_error->clear();
  }
  QString ready_error;
  if (!EnsureBreakpointReady(&ready_error)) {
    if (out_error) {
      *out_error = ready_error;
    }
    return false;
  }

  std::vector<size_t> remove_idx;
  QString first_error;
  for (size_t i = 0; i < breakpoints_.size(); ++i) {
    const auto& bp = breakpoints_[i];
    if (bp.address != address || bp.type != type || bp.backend != backend) {
      continue;
    }
    std::string error;
    bool ok = false;
    {
      const std::lock_guard<std::mutex> lock(*service_mutex_);
      ok = service_->ClearBreakpoint(pid_, bp.backend, bp.type, bp.size, 0, bp.address, &error);
    }
    if (ok) {
      remove_idx.push_back(i);
    } else if (first_error.isEmpty()) {
      first_error = ToQString(error).trimmed();
      if (first_error.isEmpty()) {
        first_error = QStringLiteral("删除断点失败");
      }
    }
  }

  std::sort(remove_idx.begin(), remove_idx.end(), std::greater<size_t>());
  for (size_t idx : remove_idx) {
    breakpoints_.erase(breakpoints_.begin() + static_cast<std::ptrdiff_t>(idx));
  }

  if (!first_error.isEmpty()) {
    if (out_error) {
      *out_error = first_error;
    }
    return false;
  }
  return true;
}

bool MemoryViewWindow::RemoveAllBreakpointsAt(uint64_t address, QString* out_error) {
  if (out_error) {
    out_error->clear();
  }
  QString ready_error;
  if (!EnsureBreakpointReady(&ready_error)) {
    if (out_error) {
      *out_error = ready_error;
    }
    return false;
  }

  std::vector<size_t> remove_idx;
  QString first_error;
  for (size_t i = 0; i < breakpoints_.size(); ++i) {
    const auto& bp = breakpoints_[i];
    if (bp.address != address) {
      continue;
    }
    std::string error;
    bool ok = false;
    {
      const std::lock_guard<std::mutex> lock(*service_mutex_);
      ok = service_->ClearBreakpoint(pid_, bp.backend, bp.type, bp.size, 0, bp.address, &error);
    }
    if (ok) {
      remove_idx.push_back(i);
    } else if (first_error.isEmpty()) {
      first_error = ToQString(error).trimmed();
      if (first_error.isEmpty()) {
        first_error = QStringLiteral("删除断点失败");
      }
    }
  }

  std::sort(remove_idx.begin(), remove_idx.end(), std::greater<size_t>());
  for (size_t idx : remove_idx) {
    breakpoints_.erase(breakpoints_.begin() + static_cast<std::ptrdiff_t>(idx));
  }

  if (!first_error.isEmpty()) {
    if (out_error) {
      *out_error = first_error;
    }
    return false;
  }
  return true;
}

bool MemoryViewWindow::ClearAllBreakpointsOnDevice(QString* out_error) {
  if (out_error) {
    out_error->clear();
  }
  QString ready_error;
  if (!EnsureBreakpointReady(&ready_error)) {
    if (out_error) {
      *out_error = ready_error;
    }
    return false;
  }

  std::vector<protocol::DebugBackend> backends;
  for (const auto& bp : breakpoints_) {
    bool exists = false;
    for (const auto& backend : backends) {
      if (backend == bp.backend) {
        exists = true;
        break;
      }
    }
    if (!exists) {
      backends.push_back(bp.backend);
    }
  }
  if (backends.empty()) {
    backends.push_back(breakpoint_backend_);
  }

  QString first_error;
  for (const auto& backend : backends) {
    std::string error;
    bool ok = false;
    {
      const std::lock_guard<std::mutex> lock(*service_mutex_);
      ok = service_->ClearBreakpoint(pid_,
                                     backend,
                                     protocol::DEBUG_BP_EXEC,
                                     0,
                                     protocol::DEBUG_BP_FLAG_CLEAR_ALL,
                                     0,
                                     &error);
    }
    if (!ok && first_error.isEmpty()) {
      first_error = ToQString(error).trimmed();
      if (first_error.isEmpty()) {
        first_error = QStringLiteral("清空断点失败");
      }
    }
  }
  if (!first_error.isEmpty()) {
    if (out_error) {
      *out_error = first_error;
    }
    return false;
  }
  return true;
}

bool MemoryViewWindow::HasBreakpoint(uint64_t address, protocol::DebugBpType type) const {
  for (const auto& bp : breakpoints_) {
    if (bp.enabled && bp.address == address && bp.type == type) {
      return true;
    }
  }
  return false;
}

bool MemoryViewWindow::HasBreakpoint(uint64_t address,
                                     protocol::DebugBpType type,
                                     protocol::DebugBackend backend) const {
  for (const auto& bp : breakpoints_) {
    if (bp.enabled && bp.address == address && bp.type == type && bp.backend == backend) {
      return true;
    }
  }
  return false;
}

bool MemoryViewWindow::HasAnyBreakpointAt(uint64_t address) const {
  for (const auto& bp : breakpoints_) {
    if (bp.enabled && bp.address == address) {
      return true;
    }
  }
  return false;
}

QString MemoryViewWindow::BreakpointSummaryForAddress(uint64_t address) const {
  QStringList tags;
  for (const auto& bp : breakpoints_) {
    if (!bp.enabled || bp.address != address) {
      continue;
    }
    QString tag = QStringLiteral("%1@%2").arg(BreakpointTypeShortText(bp.type), BreakpointBackendText(bp.backend));
    if (bp.hit_count > 0) {
      tag.append(QStringLiteral("#%1").arg(bp.hit_count));
    }
    tags << tag;
  }
  tags.removeDuplicates();
  return tags.join(QStringLiteral(","));
}

QString MemoryViewWindow::BreakpointTypeShortText(protocol::DebugBpType type) {
  switch (type) {
    case protocol::DEBUG_BP_EXEC:
      return QStringLiteral("X");
    case protocol::DEBUG_BP_WRITE:
      return QStringLiteral("W");
    case protocol::DEBUG_BP_READ:
      return QStringLiteral("R");
    case protocol::DEBUG_BP_READWRITE:
      return QStringLiteral("RW");
    default:
      return QStringLiteral("?");
  }
}

QString MemoryViewWindow::BreakpointBackendText(protocol::DebugBackend backend) {
  switch (backend) {
    case protocol::DEBUG_BACKEND_PTRACE:
      return QStringLiteral("ptrace");
    case protocol::DEBUG_BACKEND_PERF:
      return QStringLiteral("perf");
    default:
      return QStringLiteral("unknown");
  }
}

void MemoryViewWindow::SetBreakpointStatus(const QString& text) {
  breakpoint_status_ = text.trimmed();
  UpdateBreakpointStatusText();
}

void MemoryViewWindow::UpdateBreakpointStatusText() {
  if (!breakpoint_label_) {
    return;
  }
  UpdateDebugPanelVisibility();
  QString text = QStringLiteral("断点: %1  后端: %2  命中暂停: %3  调试状态: %4")
                     .arg(breakpoints_.size())
                     .arg(BreakpointBackendText(breakpoint_backend_))
                     .arg(breakpoint_stop_on_hit_ ? QStringLiteral("开") : QStringLiteral("关"))
                     .arg(debug_attached_ ? QStringLiteral("暂停") : QStringLiteral("运行"));
  if (breakpoint_hit_total_ > 0) {
    text.append(QStringLiteral("  命中总计: %1").arg(breakpoint_hit_total_));
  }
  if (breakpoint_last_hit_addr_ != 0) {
    text.append(QStringLiteral("  最近命中: %1").arg(Hex64(breakpoint_last_hit_addr_)));
  }
  if (!breakpoint_status_.isEmpty()) {
    text.append(QStringLiteral("  状态: %1").arg(breakpoint_status_));
  }
  breakpoint_label_->setText(text);
}

void MemoryViewWindow::RefreshBreakpointVisuals() {
  UpdateBreakpointStatusText();
  if (current_bytes_.empty() || current_address_ == 0) {
    return;
  }
  PopulateDisasmTable(current_address_, current_bytes_);
  PopulateHexTable(current_address_, current_bytes_);
}

QString MemoryViewWindow::ModuleDisplayName(const r3::windows_client_ng::services::ClientService::ModuleInfo& module) {
  const QString path = ToQString(module.path).trimmed();
  if (path.isEmpty()) {
    return QStringLiteral("(anonymous)");
  }
  if (path.startsWith('[')) {
    return path;
  }
  const QString file = QFileInfo(path).fileName();
  return file.isEmpty() ? path : file;
}

QString MemoryViewWindow::BuildAddressAlias(uint64_t address) const {
  for (const auto& module : modules_) {
    if (address < module.start || address >= module.end) {
      continue;
    }
    const QString name = ModuleDisplayName(module);
    const uint64_t offset = address - module.start;
    return QStringLiteral("[%1]+0x%2").arg(name, QString::number(offset, 16).toUpper());
  }
  return Hex64(address);
}

QString MemoryViewWindow::BuildPermText(uint32_t perms) {
  QString text;
  text += (perms & protocol::MODULE_PERM_READ) ? QChar('r') : QChar('-');
  text += (perms & protocol::MODULE_PERM_WRITE) ? QChar('w') : QChar('-');
  text += (perms & protocol::MODULE_PERM_EXEC) ? QChar('x') : QChar('-');
  if (perms & protocol::MODULE_PERM_PRIVATE) {
    text += QChar('p');
  } else if (perms & protocol::MODULE_PERM_SHARED) {
    text += QChar('s');
  } else {
    text += QChar('-');
  }
  return text;
}

QString MemoryViewWindow::BytesToHex(const uint8_t* data, size_t size) {
  QString out;
  out.reserve(static_cast<int>(size * 3));
  for (size_t i = 0; i < size; ++i) {
    if (i > 0) {
      out.append(' ');
    }
    out.append(QString::number(data[i], 16).toUpper().rightJustified(2, QLatin1Char('0')));
  }
  return out;
}

QString MemoryViewWindow::DecodeInstructionText(uint64_t address, const uint8_t* data, size_t size) const {
  if (!data || size == 0) {
    return QStringLiteral("??");
  }

  if (arch_ == protocol::RegsArch::ARM64 && size >= 4) {
    uint32_t insn = 0;
    std::memcpy(&insn, data, sizeof(insn));
    if (insn == 0xD503201F) {
      return QStringLiteral("nop");
    }
    if (insn == 0xD65F03C0) {
      return QStringLiteral("ret");
    }
    if ((insn & 0xFC000000u) == 0x14000000u) {
      int32_t imm26 = static_cast<int32_t>(insn & 0x03FFFFFFu);
      if ((imm26 & 0x02000000) != 0) {
        imm26 |= static_cast<int32_t>(0xFC000000u);
      }
      const int64_t off = static_cast<int64_t>(imm26) << 2;
      return QStringLiteral("b %1").arg(Hex64(static_cast<uint64_t>(static_cast<int64_t>(address) + off)));
    }
    if ((insn & 0xFC000000u) == 0x94000000u) {
      int32_t imm26 = static_cast<int32_t>(insn & 0x03FFFFFFu);
      if ((imm26 & 0x02000000) != 0) {
        imm26 |= static_cast<int32_t>(0xFC000000u);
      }
      const int64_t off = static_cast<int64_t>(imm26) << 2;
      return QStringLiteral("bl %1").arg(Hex64(static_cast<uint64_t>(static_cast<int64_t>(address) + off)));
    }
    return QStringLiteral(".inst 0x%1").arg(QString::number(insn, 16).toUpper().rightJustified(8, QLatin1Char('0')));
  }

  if (size >= 4) {
    uint32_t word = 0;
    std::memcpy(&word, data, sizeof(word));
    return QStringLiteral(".word 0x%1").arg(QString::number(word, 16).toUpper().rightJustified(8, QLatin1Char('0')));
  }
  return QStringLiteral("db %1").arg(BytesToHex(data, size));
}

QString MemoryViewWindow::BuildPluginComment(uint64_t address, const uint8_t* data, size_t size) const {
  if (!plugin_runtime_ || !plugin_runtime_->IsActive() || size == 0 || !data) {
    return QString();
  }
  if (annotation_mode_ == ANNO_BUILTIN) {
    return QString();
  }
  if (!plugin_runtime_->SupportsAnalysis()) {
    return QString();
  }

  r3::windows_client_qt::plugins::PluginRuntime::AnalysisRequest request{};
  request.arch = static_cast<uint32_t>(arch_ == protocol::RegsArch::ARM64
                                           ? 1
                                           : (arch_ == protocol::RegsArch::ARM32 ? 2 : 0));
  request.address = address;
  request.bytes.assign(data, data + size);

  r3::windows_client_qt::plugins::PluginRuntime::AnalysisResult result{};
  QString error;
  if (!plugin_runtime_->Analyze(request, &result, &error)) {
    return QString();
  }

  QStringList parts;
  if (!result.primary_text.trimmed().isEmpty()) {
    parts << result.primary_text.trimmed();
  }
  if (!result.ir_text.trimmed().isEmpty()) {
    parts << QStringLiteral("IR:%1").arg(result.ir_text.trimmed());
  }
  if (!result.tags.isEmpty()) {
    parts << QStringLiteral("tags=%1").arg(result.tags.join(','));
  }
  if (result.confidence > 0) {
    parts << QStringLiteral("conf=%1").arg(result.confidence);
  }
  return parts.join(QStringLiteral(" "));
}

void MemoryViewWindow::PopulateDisasmTable(uint64_t base, const std::vector<uint8_t>& data) {
  const uint64_t selected_addr = SelectedDisasmAddress();
  disasm_model_->removeRows(0, disasm_model_->rowCount());
  if (data.empty()) {
    return;
  }

  struct DisasmRow {
    uint64_t addr = 0;
    size_t size = 0;
    QString text;
    QString comment;
  };
  std::vector<DisasmRow> rows;
  rows.reserve(160);

  csh cs_handle = 0;
  cs_insn* cs_instruction = nullptr;
  bool capstone_ready = false;
  if (arch_ == protocol::RegsArch::ARM64) {
    capstone_ready = (cs_open(CS_ARCH_AARCH64, CS_MODE_ARM, &cs_handle) == CS_ERR_OK);
  } else if (arch_ == protocol::RegsArch::ARM32) {
    capstone_ready = (cs_open(CS_ARCH_ARM, CS_MODE_ARM, &cs_handle) == CS_ERR_OK);
  }
  if (capstone_ready) {
    cs_option(cs_handle, CS_OPT_DETAIL, CS_OPT_OFF);
    cs_option(cs_handle, CS_OPT_SKIPDATA, CS_OPT_ON);
    cs_instruction = cs_malloc(cs_handle);
    capstone_ready = (cs_instruction != nullptr);
  }

  size_t off = 0;
  while (off < data.size() && rows.size() < 160) {
    const uint64_t addr = base + static_cast<uint64_t>(off);
    QString builtin_comment;
    for (const auto& module : modules_) {
      if (addr >= module.start && addr < module.end) {
        builtin_comment = QStringLiteral("%1  %2  %3")
                              .arg(ModuleDisplayName(module), BuildPermText(module.perms), GGSegmentText(module));
        break;
      }
    }

    size_t chunk = 0;
    QString op_text;
    if (capstone_ready) {
      const uint8_t* cursor = data.data() + off;
      size_t remaining = data.size() - off;
      uint64_t pc = addr;
      if (cs_disasm_iter(cs_handle, &cursor, &remaining, &pc, cs_instruction)) {
        chunk = static_cast<size_t>(std::max<uint16_t>(1, cs_instruction->size));
        const QString mnemonic = QString::fromLatin1(cs_instruction->mnemonic);
        const QString op_str = QString::fromLatin1(cs_instruction->op_str);
        op_text = op_str.isEmpty() ? mnemonic : QStringLiteral("%1 %2").arg(mnemonic, op_str);
      }
    }
    if (chunk == 0) {
      const size_t fallback = (arch_ == protocol::RegsArch::ARM64 || arch_ == protocol::RegsArch::ARM32) ? 4 : 1;
      chunk = (std::min)(fallback, data.size() - off);
      if (chunk == 0) {
        break;
      }
      op_text = DecodeInstructionText(addr, data.data() + off, chunk);
    }

    DisasmRow row;
    row.addr = addr;
    row.size = chunk;
    row.text = op_text;
    const QString plugin_comment = BuildPluginComment(addr, data.data() + off, chunk);
    if (annotation_mode_ == ANNO_BUILTIN) {
      row.comment = builtin_comment;
    } else if (annotation_mode_ == ANNO_PLUGIN) {
      row.comment = plugin_comment;
    } else {
      if (!builtin_comment.isEmpty() && !plugin_comment.isEmpty()) {
        row.comment = QStringLiteral("%1 | %2").arg(builtin_comment, plugin_comment);
      } else if (!plugin_comment.isEmpty()) {
        row.comment = plugin_comment;
      } else {
        row.comment = builtin_comment;
      }
    }
    rows.push_back(std::move(row));
    off += chunk;
  }

  if (cs_instruction) {
    cs_free(cs_instruction, 1);
  }
  if (cs_handle != 0) {
    cs_close(&cs_handle);
  }

  disasm_model_->setRowCount(static_cast<int>(rows.size()));
  for (int i = 0; i < static_cast<int>(rows.size()); ++i) {
    const DisasmRow& row = rows[static_cast<size_t>(i)];
    const size_t offset = static_cast<size_t>(row.addr - base);
    auto* c0 = new QStandardItem(QStringLiteral("%1  (%2)").arg(BuildAddressAlias(row.addr), Hex64(row.addr)));
    auto* c1 = new QStandardItem(BytesToHex(data.data() + offset, row.size));
    auto* c2 = new QStandardItem(row.text);
    auto* c3 = new QStandardItem(row.comment);
    c0->setData(static_cast<qulonglong>(row.addr), kAddressRole);

    const QString bp_summary = BreakpointSummaryForAddress(row.addr);
    if (breakpoint_overlay_visible_ && !bp_summary.isEmpty()) {
      c0->setText(QStringLiteral("● %1").arg(c0->text()));
      const QColor mark_color(255, 128, 128);
      const QColor mark_bg(72, 34, 34);
      c0->setForeground(QBrush(mark_color));
      c1->setForeground(QBrush(mark_color));
      c2->setForeground(QBrush(mark_color));
      c3->setForeground(QBrush(mark_color));
      c0->setBackground(QBrush(mark_bg));
      c1->setBackground(QBrush(mark_bg));
      c2->setBackground(QBrush(mark_bg));
      c3->setBackground(QBrush(mark_bg));
      if (c3->text().isEmpty()) {
        c3->setText(QStringLiteral("BP:%1").arg(bp_summary));
      } else {
        c3->setText(QStringLiteral("%1 | BP:%2").arg(c3->text(), bp_summary));
      }
      const QString tip =
          QStringLiteral("断点: %1").arg(bp_summary);
      c0->setToolTip(tip);
      c1->setToolTip(tip);
      c2->setToolTip(tip);
      c3->setToolTip(tip);
    }

    disasm_model_->setItem(i, 0, c0);
    disasm_model_->setItem(i, 1, c1);
    disasm_model_->setItem(i, 2, c2);
    disasm_model_->setItem(i, 3, c3);
  }
  disasm_table_->resizeRowsToContents();
  if (disasm_model_->rowCount() > 0) {
    int target_row = -1;
    if (selected_addr != 0) {
      for (int row = 0; row < disasm_model_->rowCount(); ++row) {
        const uint64_t addr =
            disasm_model_->data(disasm_model_->index(row, 0), kAddressRole).toULongLong();
        if (addr == selected_addr) {
          target_row = row;
          break;
        }
      }
    }
    if (target_row < 0) {
      target_row = 0;
    }
    disasm_table_->setCurrentIndex(disasm_model_->index(target_row, 0));
  }
}

void MemoryViewWindow::PopulateHexTable(uint64_t base, const std::vector<uint8_t>& data) {
  const uint64_t selected_addr = SelectedHexAddress();
  hex_model_->removeRows(0, hex_model_->rowCount());
  if (data.empty()) {
    return;
  }

  const int rows = static_cast<int>((data.size() + 15) / 16);
  hex_model_->setRowCount(rows);
  for (int row = 0; row < rows; ++row) {
    const uint64_t row_addr = base + static_cast<uint64_t>(row * 16);
    auto* c0 = new QStandardItem(Hex64(row_addr));
    c0->setData(static_cast<qulonglong>(row_addr), kAddressRole);
    c0->setTextAlignment(Qt::AlignRight | Qt::AlignVCenter);
    hex_model_->setItem(row, 0, c0);

    QString ascii;
    ascii.reserve(16);
    bool row_has_bp = false;
    QStringList row_bp_tags;
    for (int col = 0; col < 16; ++col) {
      const size_t idx = static_cast<size_t>(row * 16 + col);
      auto* item = new QStandardItem();
      item->setTextAlignment(Qt::AlignCenter);
      const uint64_t cell_addr = row_addr + static_cast<uint64_t>(col);
      const QString bp_summary = BreakpointSummaryForAddress(cell_addr);
      if (!bp_summary.isEmpty()) {
        row_has_bp = true;
        row_bp_tags << QStringLiteral("%1:%2").arg(Hex64(cell_addr), bp_summary);
      }
      if (idx < data.size()) {
        const uint8_t b = data[idx];
        item->setText(QString::number(b, 16).toUpper().rightJustified(2, QLatin1Char('0')));
        ascii.append(std::isprint(static_cast<unsigned char>(b)) ? QChar(static_cast<char>(b)) : QChar('.'));
      } else {
        item->setText(QString());
        ascii.append(QChar(' '));
      }
      if (breakpoint_overlay_visible_ && !bp_summary.isEmpty()) {
        const QColor mark_color(255, 128, 128);
        const QColor mark_bg(72, 34, 34);
        item->setForeground(QBrush(mark_color));
        item->setBackground(QBrush(mark_bg));
        item->setToolTip(QStringLiteral("断点: %1").arg(bp_summary));
      }
      hex_model_->setItem(row, col + 1, item);
    }
    auto* c_ascii = new QStandardItem(ascii);
    if (breakpoint_overlay_visible_ && row_has_bp) {
      const QColor mark_color(255, 128, 128);
      const QColor mark_bg(72, 34, 34);
      c0->setForeground(QBrush(mark_color));
      c0->setBackground(QBrush(mark_bg));
      c_ascii->setForeground(QBrush(mark_color));
      c_ascii->setBackground(QBrush(mark_bg));
      c0->setToolTip(row_bp_tags.join(QStringLiteral("\n")));
      c_ascii->setToolTip(row_bp_tags.join(QStringLiteral("\n")));
    }
    hex_model_->setItem(row, 17, c_ascii);
  }
  hex_table_->resizeRowsToContents();
  if (selected_addr >= base && selected_addr < base + static_cast<uint64_t>(data.size())) {
    const uint64_t delta = selected_addr - base;
    const int row = static_cast<int>(delta / 16);
    const int col = static_cast<int>(delta % 16) + 1;
    if (row >= 0 && row < hex_model_->rowCount() && col >= 1 && col <= 16) {
      hex_table_->setCurrentIndex(hex_model_->index(row, col));
    }
  }
}

uint64_t MemoryViewWindow::SelectedDisasmAddress() const {
  if (!disasm_table_ || !disasm_model_) {
    return 0;
  }
  const QModelIndex idx = disasm_table_->currentIndex();
  if (!idx.isValid()) {
    return 0;
  }
  return disasm_model_->data(idx.sibling(idx.row(), 0), kAddressRole).toULongLong();
}

uint64_t MemoryViewWindow::SelectedHexAddress() const {
  if (!hex_table_ || !hex_model_) {
    return 0;
  }
  const QModelIndex idx = hex_table_->currentIndex();
  if (!idx.isValid()) {
    return 0;
  }
  uint64_t addr = hex_model_->data(idx.sibling(idx.row(), 0), kAddressRole).toULongLong();
  if (addr == 0) {
    return 0;
  }
  if (idx.column() >= 1 && idx.column() <= 16) {
    const QString token = hex_model_->data(idx).toString();
    if (!token.isEmpty()) {
      addr += static_cast<uint64_t>(idx.column() - 1);
    }
  }
  return addr;
}

}  // namespace r3::windows_client_qt::ui
