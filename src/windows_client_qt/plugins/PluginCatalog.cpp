#include "plugins/PluginCatalog.h"

#include <algorithm>

#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonValue>

namespace r3::windows_client_qt::plugins {

namespace {

QString ReadTextFile(const QString& path, QString* out_error) {
  QFile f(path);
  if (!f.open(QIODevice::ReadOnly)) {
    if (out_error) {
      *out_error = QStringLiteral("无法打开文件: %1").arg(path);
    }
    return QString();
  }
  const QByteArray data = f.readAll();
  return QString::fromUtf8(data.constData(), data.size());
}

bool ParseQuickstart(const QString& path, std::vector<QuickstartField>* out_fields, QString* out_error) {
  if (!out_fields) {
    return false;
  }
  out_fields->clear();
  if (path.isEmpty()) {
    return true;
  }
  QString err;
  const QString text = ReadTextFile(path, &err);
  if (text.isEmpty()) {
    if (out_error) {
      *out_error = err;
    }
    return false;
  }
  QJsonParseError pe{};
  const QJsonDocument doc = QJsonDocument::fromJson(text.toUtf8(), &pe);
  if (pe.error != QJsonParseError::NoError || !doc.isObject()) {
    if (out_error) {
      *out_error = QStringLiteral("quickstart.json格式错误: %1").arg(pe.errorString());
    }
    return false;
  }
  const QJsonObject root = doc.object();
  const QJsonArray fields = root.value(QStringLiteral("fields")).toArray();
  out_fields->reserve(static_cast<size_t>(fields.size()));
  for (const QJsonValue& v : fields) {
    if (!v.isObject()) {
      continue;
    }
    const QJsonObject o = v.toObject();
    QuickstartField f;
    f.id = o.value(QStringLiteral("id")).toString().trimmed();
    f.label = o.value(QStringLiteral("label")).toString().trimmed();
    f.type = o.value(QStringLiteral("type")).toString().trimmed();
    f.default_value = o.value(QStringLiteral("default")).toString();
    f.description = o.value(QStringLiteral("description")).toString();
    if (f.id.isEmpty()) {
      continue;
    }
    if (f.label.isEmpty()) {
      f.label = f.id;
    }
    if (f.type.isEmpty()) {
      f.type = QStringLiteral("string");
    }
    out_fields->push_back(std::move(f));
  }
  return true;
}

QString TrimmedPathJoin(const QString& base_dir, const QString& rel_or_abs) {
  const QString raw = rel_or_abs.trimmed();
  if (raw.isEmpty()) {
    return QString();
  }
  QFileInfo fi(raw);
  if (fi.isAbsolute()) {
    return fi.absoluteFilePath();
  }
  return QDir(base_dir).absoluteFilePath(raw);
}

QStringList ParseStringList(const QJsonValue& v) {
  QStringList out;
  if (!v.isArray()) {
    return out;
  }
  const QJsonArray arr = v.toArray();
  for (const QJsonValue& item : arr) {
    const QString text = item.toString().trimmed();
    if (!text.isEmpty()) {
      out.push_back(text);
    }
  }
  return out;
}

}  // namespace

bool PluginCatalog::LoadFromRoot(const QString& root_path, QString* out_error) {
  if (out_error) {
    out_error->clear();
  }
  plugins_.clear();
  last_loaded_count_ = 0;
  last_failed_count_ = 0;
  last_failure_messages_.clear();

  auto add_failure = [&](const QString& plugin_dir, const QString& reason) {
    last_failed_count_++;
    const QString text = QStringLiteral("[%1] %2")
                             .arg(plugin_dir.trimmed().isEmpty() ? QStringLiteral("unknown") : plugin_dir,
                                  reason.trimmed().isEmpty() ? QStringLiteral("unknown error") : reason.trimmed());
    last_failure_messages_.push_back(text);
  };

  const QString root = root_path.trimmed();
  if (root.isEmpty()) {
    return true;
  }
  QDir root_dir(root);
  if (!root_dir.exists()) {
    add_failure(root, QStringLiteral("插件目录不存在"));
    if (out_error) {
      *out_error = QStringLiteral("插件目录不存在: %1").arg(root);
    }
    return false;
  }

  const QFileInfoList dirs =
      root_dir.entryInfoList(QDir::Dirs | QDir::NoDotAndDotDot, QDir::Name | QDir::IgnoreCase);
  for (const QFileInfo& d : dirs) {
    const QString plugin_json = QDir(d.absoluteFilePath()).filePath(QStringLiteral("plugin.json"));
    if (!QFileInfo::exists(plugin_json)) {
      continue;
    }

    QString err;
    const QString text = ReadTextFile(plugin_json, &err);
    if (text.isEmpty()) {
      add_failure(d.fileName(), err.isEmpty() ? QStringLiteral("读取plugin.json失败") : err);
      continue;
    }
    QJsonParseError pe{};
    const QJsonDocument doc = QJsonDocument::fromJson(text.toUtf8(), &pe);
    if (pe.error != QJsonParseError::NoError || !doc.isObject()) {
      add_failure(d.fileName(), QStringLiteral("plugin.json格式错误: %1").arg(pe.errorString()));
      continue;
    }
    const QJsonObject o = doc.object();
    PluginManifest m;
    m.id = o.value(QStringLiteral("id")).toString().trimmed();
    m.name = o.value(QStringLiteral("name")).toString().trimmed();
    m.version = o.value(QStringLiteral("version")).toString().trimmed();
    m.description = o.value(QStringLiteral("description")).toString().trimmed();
    m.plugin_dir = d.absoluteFilePath();
    m.mode = o.value(QStringLiteral("mode")).toString().trimmed().toLower();
    if (m.mode.isEmpty()) {
      m.mode = QStringLiteral("manifest");
    }
    m.entry = TrimmedPathJoin(m.plugin_dir, o.value(QStringLiteral("entry")).toString());
    m.oop_args = ParseStringList(o.value(QStringLiteral("oop_args")));
    m.abi = o.value(QStringLiteral("abi")).toString().trimmed();
    m.min_host_version = o.value(QStringLiteral("min_host_version")).toString().trimmed();
    m.max_host_version = o.value(QStringLiteral("max_host_version")).toString().trimmed();
    m.supported_arch = ParseStringList(o.value(QStringLiteral("supported_arch")));
    m.priority = o.value(QStringLiteral("priority")).toInt(100);
    if (m.priority < 0) {
      m.priority = 0;
    }
    if (m.priority > 1000000) {
      m.priority = 1000000;
    }

    const QJsonArray caps = o.value(QStringLiteral("capabilities")).toArray();
    for (const QJsonValue& cap : caps) {
      const QString c = cap.toString().trimmed();
      if (!c.isEmpty()) {
        m.capabilities.push_back(c);
      }
    }

    const QJsonObject mem = o.value(QStringLiteral("memory_provider")).toObject();
    if (!mem.isEmpty()) {
      m.syscall_read = mem.value(QStringLiteral("syscall_read")).toInt(-1);
      m.syscall_write = mem.value(QStringLiteral("syscall_write")).toInt(-1);
      m.timeout_ms = (std::max)(1, mem.value(QStringLiteral("timeout_ms")).toInt(1000));
      m.default_user_ctx_hex = mem.value(QStringLiteral("user_ctx_hex")).toString().trimmed();
    }

    QString quickstart = TrimmedPathJoin(m.plugin_dir, o.value(QStringLiteral("quickstart")).toString());
    if (quickstart.isEmpty()) {
      quickstart = QDir(m.plugin_dir).filePath(QStringLiteral("schema/quickstart.json"));
    }
    if (!QFileInfo::exists(quickstart)) {
      quickstart = QDir(m.plugin_dir).filePath(QStringLiteral("quickstart.json"));
    }
    if (QFileInfo::exists(quickstart)) {
      std::vector<QuickstartField> fields;
      QString quick_err;
      if (ParseQuickstart(quickstart, &fields, &quick_err)) {
        m.quickstart_fields = std::move(fields);
      }
    }

    if (m.id.isEmpty()) {
      m.id = d.fileName();
    }
    if (m.name.isEmpty()) {
      m.name = m.id;
    }
    if (m.mode == QStringLiteral("in_process") && m.entry.isEmpty()) {
      add_failure(d.fileName(), QStringLiteral("in_process插件缺少entry"));
      continue;
    }
    plugins_.push_back(std::move(m));
  }
  std::sort(plugins_.begin(), plugins_.end(), [](const PluginManifest& a, const PluginManifest& b) {
    if (a.priority != b.priority) {
      return a.priority < b.priority;
    }
    return a.name.compare(b.name, Qt::CaseInsensitive) < 0;
  });
  last_loaded_count_ = static_cast<int>(plugins_.size());
  return true;
}

std::optional<PluginManifest> PluginCatalog::FindById(const QString& id) const {
  const QString key = id.trimmed();
  if (key.isEmpty()) {
    return std::nullopt;
  }
  for (const auto& p : plugins_) {
    if (p.id.compare(key, Qt::CaseInsensitive) == 0) {
      return p;
    }
  }
  return std::nullopt;
}

}  // namespace r3::windows_client_qt::plugins
