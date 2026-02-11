#include "ui/PluginDevWindow.h"

#include <QPlainTextEdit>
#include <QTabWidget>
#include <QVBoxLayout>

namespace r3::windows_client_qt::ui {

namespace {

QPlainTextEdit* MakeReadOnlyPage(const QString& text, QWidget* parent) {
  auto* view = new QPlainTextEdit(parent);
  view->setReadOnly(true);
  view->setPlainText(text.trimmed());
  return view;
}

}  // namespace

PluginDevWindow::PluginDevWindow(QWidget* parent) : QDialog(parent) {
  setWindowTitle(QStringLiteral("插件开发中心"));
  resize(980, 760);

  auto* root = new QVBoxLayout(this);
  auto* tabs = new QTabWidget(this);
  root->addWidget(tabs, 1);

  const QString workflow_page = QStringLiteral(R"(
统一流程（开发 -> 编译打包 -> 启用）:
1. 生成插件工程
   powershell -ExecutionPolicy Bypass -File .\tools\plugin_new.ps1 `
     -PluginId com.company.demo.bridge `
     -Name DemoBridge `
     -Author QA

2. 按 IDA/C 风格写插件逻辑（在生成工程的 src/PluginMain.cpp）
   - 用 module_name/module_version/module_author/init_module 宏描述模块
   - 用 register_module_events 注册事件回调

3. 一键编译并打包
   powershell -ExecutionPolicy Bypass -File .\tools\plugin_compile_pack.ps1 `
     -PluginProjectRoot .\plugin_projects\com.company.demo.bridge

4. 在“插件与自定义syscall”窗口:
   - 设定插件根目录（默认 .\plugins）
   - 点击“扫描插件”
   - 选择插件并勾选“启用插件内存Provider”
   - OK 应用

产物目录（可直接放到插件专用目录）:
plugins\<plugin_id>\
  plugin.json
  schema\quickstart.json
  docs\README.md
  bin\win64\<plugin>.dll
)");

  const QString ida_page = QStringLiteral(R"(
IDA风格快速上手建议（1~2天）:
阶段A: 最小闭环
- 先只实现 init_module + 元数据宏，让插件可加载
- 回调全部返回 R3_MODULE_DISPATCH_PASS，确认宿主流程不受影响

阶段B: 单事件突破
- 先实现 READ_MEM 或 WRITE_MEM 一个事件
- 事件参数在 R3ModuleEventContext，输出通过 out_buf/out_len 返回
- 出错返回 R3_MODULE_DISPATCH_ERROR，让UI直接展示错误

阶段C: 稳定化
- 加日志（host->log_utf8）
- 明确 user_ctx 结构体版本号
- 在 quickstart.json 暴露测试侧参数，减少硬编码

核心头文件:
- src/plugin_sdk/R3ModuleCompat.h
- src/plugin_sdk/R3PluginApi.h
)");

  const QString callback_page = QStringLiteral(R"(
最小宏约定:
- init_module(...)
- module_name(...)
- module_version(...)
- module_author(...)

事件注册模板:
#include "plugin_sdk/R3ModuleCompat.h"

static int32_t OnRead(const R3ModuleEventContext* ctx, void* user, uint8_t** out, uint32_t* out_len) {
  return R3_MODULE_DISPATCH_PASS;
}

static int RegisterEvents(const R3ModuleHostApiV1* host) {
  if (!host || !host->register_callback) return -1;
  if (host->register_callback(R3_MODULE_EVENT_READ_MEM, &OnRead, nullptr) != 0) return -2;
  return 0;
}

static int PluginInit(void) { return 0; }
module_name("com.example.demo");
module_version("1.0.0");
module_author("QA");
init_module(PluginInit);
register_module_events(RegisterEvents);

返回值约定:
- R3_MODULE_DISPATCH_PASS: 不处理，走默认流程
- R3_MODULE_DISPATCH_HANDLED: 插件已处理，跳过默认流程
- R3_MODULE_DISPATCH_ERROR: UI直接展示错误文本
)");

  const QString tools_page = QStringLiteral(R"(
工具1: 工程脚手架
- tools/plugin_new.ps1
- 目标: 30秒生成可编译插件工程

工具2: 编译+打包一体化
- tools/plugin_compile_pack.ps1
- 目标: 直接输出 plugins/<plugin_id>/ 标准包目录

工具3: 纯打包（已有DLL时）
- tools/plugin_packager.ps1

常用命令:
powershell -ExecutionPolicy Bypass -File .\tools\plugin_new.ps1 -PluginId com.demo.sample -Name Sample
powershell -ExecutionPolicy Bypass -File .\tools\plugin_compile_pack.ps1 -PluginProjectRoot .\plugin_projects\com.demo.sample
)");

  tabs->addTab(MakeReadOnlyPage(workflow_page, tabs), QStringLiteral("流程总览"));
  tabs->addTab(MakeReadOnlyPage(ida_page, tabs), QStringLiteral("IDA学习路径"));
  tabs->addTab(MakeReadOnlyPage(callback_page, tabs), QStringLiteral("宏与回调"));
  tabs->addTab(MakeReadOnlyPage(tools_page, tabs), QStringLiteral("编译打包工具"));
}

}  // namespace r3::windows_client_qt::ui
