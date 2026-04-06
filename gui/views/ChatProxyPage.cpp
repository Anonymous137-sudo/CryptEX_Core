#include "ChatProxyPage.hpp"
#include "ChatTheme.hpp"
#include "rpc/RpcClient.hpp"

#include <QCheckBox>
#include <QFormLayout>
#include <QJsonArray>
#include <QJsonObject>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QSpinBox>
#include <QVBoxLayout>
#include <QHBoxLayout>

ChatProxyPage::ChatProxyPage(QWidget* parent)
    : QWidget(parent) {
    auto* root = new QVBoxLayout(this);
    root->setContentsMargins(12, 12, 12, 12);
    root->setSpacing(12);

    auto* title = new QLabel(QStringLiteral("Tor / SOCKS5 Proxy"), this);
    title->setObjectName(QStringLiteral("pageTitle"));
    root->addWidget(title);

    statusValue_ = new QLabel(QStringLiteral("Configure a SOCKS5 proxy for chat routing and peer bootstrap."), this);
    statusValue_->setWordWrap(true);
    root->addWidget(statusValue_);

    auto* form = new QFormLayout();
    enabledCheck_ = new QCheckBox(QStringLiteral("Enable SOCKS5 proxy"), this);
    hostEdit_ = new QLineEdit(this);
    portSpin_ = new QSpinBox(this);
    portSpin_->setRange(1, 65535);
    portSpin_->setValue(9050);
    remoteDnsCheck_ = new QCheckBox(QStringLiteral("Resolve DNS through proxy"), this);
    remoteDnsCheck_->setChecked(true);
    form->addRow(QString(), enabledCheck_);
    form->addRow(QStringLiteral("Proxy Host"), hostEdit_);
    form->addRow(QStringLiteral("Proxy Port"), portSpin_);
    form->addRow(QString(), remoteDnsCheck_);
    root->addLayout(form);

    auto* buttonRow = new QWidget(this);
    auto* buttonLayout = new QHBoxLayout(buttonRow);
    buttonLayout->setContentsMargins(0, 0, 0, 0);
    refreshButton_ = new QPushButton(QStringLiteral("Reload"), this);
    saveButton_ = new QPushButton(QStringLiteral("Save Proxy"), this);
    buttonLayout->addWidget(refreshButton_);
    buttonLayout->addStretch(1);
    buttonLayout->addWidget(saveButton_);
    root->addWidget(buttonRow);

    connect(refreshButton_, &QPushButton::clicked, this, [this]() { refresh(); });
    connect(saveButton_, &QPushButton::clicked, this, [this]() { save(); });
}

void ChatProxyPage::setRpcClient(RpcClient* client) {
    rpc_ = client;
}

void ChatProxyPage::setStatus(const QString& text, bool error) {
    statusValue_->setText(text);
    statusValue_->setStyleSheet(error ? chatui::errorColorStyle() : QString());
}

void ChatProxyPage::refresh() {
    if (!rpc_) {
        setStatus(QStringLiteral("RPC client not configured."), true);
        return;
    }
    rpc_->call(QStringLiteral("getchatproxyconfig"), {}, this,
        [this](const QJsonValue& result) {
            const auto obj = result.toObject();
            enabledCheck_->setChecked(obj.value(QStringLiteral("enabled")).toBool(false));
            hostEdit_->setText(obj.value(QStringLiteral("host")).toString());
            portSpin_->setValue(static_cast<int>(obj.value(QStringLiteral("port")).toInteger(9050)));
            remoteDnsCheck_->setChecked(obj.value(QStringLiteral("remote_dns")).toBool(true));
            setStatus(QStringLiteral("Loaded current proxy configuration."));
        },
        [this](const QString& error) { setStatus(error, true); });
}

void ChatProxyPage::save() {
    if (!rpc_) return;
    QJsonObject object;
    object.insert(QStringLiteral("enabled"), enabledCheck_->isChecked());
    object.insert(QStringLiteral("host"), hostEdit_->text().trimmed());
    object.insert(QStringLiteral("port"), portSpin_->value());
    object.insert(QStringLiteral("remote_dns"), remoteDnsCheck_->isChecked());
    rpc_->call(QStringLiteral("setchatproxyconfig"), QJsonArray{object}, this,
        [this](const QJsonValue&) {
            setStatus(QStringLiteral("Proxy configuration saved."));
            refresh();
        },
        [this](const QString& error) { setStatus(error, true); });
}
