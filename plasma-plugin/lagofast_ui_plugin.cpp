#include <QObject>
#include <QWidget>
#include <QLabel>
#include <QVBoxLayout>
#include <QVariantMap>
#include <KPluginFactory>
#include <NetworkManagerQt/VpnSetting>
#include <NetworkManagerQt/ConnectionSettings>

class SettingWidget : public QWidget
{
    Q_OBJECT
public:
    explicit SettingWidget(const NetworkManager::Setting::Ptr &setting = NetworkManager::Setting::Ptr(), QWidget *parent = nullptr, Qt::WindowFlags f = {})
        : QWidget(parent, f) {}
    ~SettingWidget() override = default;
    virtual void loadConfig(const NetworkManager::Setting::Ptr &) {}
    virtual void loadSecrets(const NetworkManager::Setting::Ptr &) {}
    virtual QVariantMap setting() const = 0;
};

class VpnUiPlugin : public QObject
{
    Q_OBJECT
public:
    explicit VpnUiPlugin(QObject *parent = nullptr, const QVariantList & = QVariantList());
    ~VpnUiPlugin() override;

    virtual SettingWidget *widget(const NetworkManager::VpnSetting::Ptr &setting, QWidget *parent) = 0;
    virtual SettingWidget *askUser(const NetworkManager::VpnSetting::Ptr &setting, const QStringList &hints, QWidget *parent) = 0;
    virtual QString suggestedFileName(const NetworkManager::ConnectionSettings::Ptr &connection) const = 0;
};

class LagofastSettingWidget : public SettingWidget
{
    Q_OBJECT
public:
    explicit LagofastSettingWidget(QWidget *parent = nullptr) : SettingWidget(NetworkManager::Setting::Ptr(), parent) {
        auto *layout = new QVBoxLayout(this);
        auto *label = new QLabel(QStringLiteral("<b>LagoFast Gaming Booster</b><br/>"
                                                "Connection is managed automatically via OAuth session.<br/>"
                                                "Game traffic is dynamically routed to the lowest-latency node."), this);
        label->setWordWrap(true);
        layout->addWidget(label);
        layout->addStretch();
    }
    ~LagofastSettingWidget() override = default;

    QVariantMap setting() const override {
        return QVariantMap();
    }
};

class LagofastUiPlugin : public VpnUiPlugin
{
    Q_OBJECT
public:
    explicit LagofastUiPlugin(QObject *parent = nullptr, const QVariantList &args = QVariantList())
        : VpnUiPlugin(parent, args) {}
    ~LagofastUiPlugin() override = default;

    SettingWidget *widget(const NetworkManager::VpnSetting::Ptr &, QWidget *parent) override {
        return new LagofastSettingWidget(parent);
    }

    SettingWidget *askUser(const NetworkManager::VpnSetting::Ptr &, const QStringList &, QWidget *) override {
        return nullptr;
    }

    QString suggestedFileName(const NetworkManager::ConnectionSettings::Ptr &) const override {
        return QStringLiteral("lagofast.conf");
    }
};

K_PLUGIN_CLASS_WITH_JSON(LagofastUiPlugin, "lagofast.json")

#include "lagofast_ui_plugin.moc"
