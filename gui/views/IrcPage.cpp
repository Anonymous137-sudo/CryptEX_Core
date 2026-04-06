#include "IrcPage.hpp"
#include "ChatTheme.hpp"
#include "rpc/RpcClient.hpp"

#include <QCheckBox>
#include <QFormLayout>
#include <QHeaderView>
#include <QJsonArray>
#include <QJsonObject>
#include <QLabel>
#include <QLineEdit>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QSpinBox>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QVBoxLayout>
#include <QHBoxLayout>

IrcPage::IrcPage(QWidget* parent)
    : QWidget(parent) {
    auto* root = new QVBoxLayout(this);
    root->setContentsMargins(12, 12, 12, 12);
    root->setSpacing(12);

    auto* title = new QLabel(QStringLiteral("IRC Bridge"), this);
    title->setObjectName(QStringLiteral("pageTitle"));
    root->addWidget(title);

    statusValue_ = new QLabel(QStringLiteral("Configure a basic IRC bridge for operator chat and public coordination."), this);
    statusValue_->setWordWrap(true);
    root->addWidget(statusValue_);

    auto* form = new QFormLayout();
    enabledCheck_ = new QCheckBox(QStringLiteral("Enable IRC profile"), this);
    serverEdit_ = new QLineEdit(this);
    portSpin_ = new QSpinBox(this);
    portSpin_->setRange(1, 65535);
    portSpin_->setValue(6667);
    nickEdit_ = new QLineEdit(this);
    usernameEdit_ = new QLineEdit(this);
    realnameEdit_ = new QLineEdit(this);
    channelEdit_ = new QLineEdit(this);
    tlsCheck_ = new QCheckBox(QStringLiteral("Use TLS"), this);
    form->addRow(QString(), enabledCheck_);
    form->addRow(QStringLiteral("Server"), serverEdit_);
    form->addRow(QStringLiteral("Port"), portSpin_);
    form->addRow(QStringLiteral("Nick"), nickEdit_);
    form->addRow(QStringLiteral("Username"), usernameEdit_);
    form->addRow(QStringLiteral("Real Name"), realnameEdit_);
    form->addRow(QStringLiteral("Channel"), channelEdit_);
    form->addRow(QString(), tlsCheck_);
    root->addLayout(form);

    messageEdit_ = new QPlainTextEdit(this);
    messageEdit_->setPlaceholderText(QStringLiteral("Write an IRC message to send to the configured channel."));
    root->addWidget(messageEdit_);

    auto* buttonRow = new QWidget(this);
    auto* buttonLayout = new QHBoxLayout(buttonRow);
    buttonLayout->setContentsMargins(0, 0, 0, 0);
    refreshButton_ = new QPushButton(QStringLiteral("Reload"), this);
    saveButton_ = new QPushButton(QStringLiteral("Save IRC"), this);
    sendButton_ = new QPushButton(QStringLiteral("Send IRC Message"), this);
    buttonLayout->addWidget(refreshButton_);
    buttonLayout->addWidget(saveButton_);
    buttonLayout->addStretch(1);
    buttonLayout->addWidget(sendButton_);
    root->addWidget(buttonRow);

    logTable_ = new QTableWidget(this);
    logTable_->setColumnCount(4);
    logTable_->setHorizontalHeaderLabels({QStringLiteral("Time"),
                                          QStringLiteral("Direction"),
                                          QStringLiteral("Channel"),
                                          QStringLiteral("Message")});
    logTable_->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    logTable_->horizontalHeader()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
    logTable_->horizontalHeader()->setSectionResizeMode(2, QHeaderView::ResizeToContents);
    logTable_->horizontalHeader()->setSectionResizeMode(3, QHeaderView::Stretch);
    logTable_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    root->addWidget(logTable_, 1);

    connect(refreshButton_, &QPushButton::clicked, this, [this]() { refresh(); });
    connect(saveButton_, &QPushButton::clicked, this, [this]() { saveConfig(); });
    connect(sendButton_, &QPushButton::clicked, this, [this]() { sendMessage(); });
}

void IrcPage::setRpcClient(RpcClient* client) {
    rpc_ = client;
}

void IrcPage::setStatus(const QString& text, bool error) {
    statusValue_->setText(text);
    statusValue_->setStyleSheet(error ? chatui::errorColorStyle() : QString());
}

void IrcPage::refresh() {
    if (!rpc_) {
        setStatus(QStringLiteral("RPC client not configured."), true);
        return;
    }

    rpc_->call(QStringLiteral("getircconfig"), {}, this,
        [this](const QJsonValue& result) {
            const auto obj = result.toObject();
            enabledCheck_->setChecked(obj.value(QStringLiteral("enabled")).toBool(false));
            serverEdit_->setText(obj.value(QStringLiteral("server")).toString());
            portSpin_->setValue(static_cast<int>(obj.value(QStringLiteral("port")).toInteger(6667)));
            nickEdit_->setText(obj.value(QStringLiteral("nick")).toString());
            usernameEdit_->setText(obj.value(QStringLiteral("username")).toString());
            realnameEdit_->setText(obj.value(QStringLiteral("realname")).toString());
            channelEdit_->setText(obj.value(QStringLiteral("channel")).toString());
            tlsCheck_->setChecked(obj.value(QStringLiteral("use_tls")).toBool(false));
        },
        [this](const QString& error) { setStatus(error, true); });

    rpc_->call(QStringLiteral("getirclog"), QJsonArray{100}, this,
        [this](const QJsonValue& result) {
            const auto rows = result.toArray();
            logTable_->setRowCount(rows.size());
            for (int i = 0; i < rows.size(); ++i) {
                const auto obj = rows.at(i).toObject();
                logTable_->setItem(i, 0, new QTableWidgetItem(QString::number(obj.value(QStringLiteral("timestamp")).toInteger())));
                logTable_->setItem(i, 1, new QTableWidgetItem(obj.value(QStringLiteral("direction")).toString()));
                logTable_->setItem(i, 2, new QTableWidgetItem(obj.value(QStringLiteral("channel")).toString()));
                logTable_->setItem(i, 3, new QTableWidgetItem(obj.value(QStringLiteral("message")).toString()));
            }
            setStatus(QStringLiteral("IRC configuration and log loaded."));
        },
        [this](const QString& error) { setStatus(error, true); });
}

void IrcPage::saveConfig() {
    if (!rpc_) return;
    QJsonObject object;
    object.insert(QStringLiteral("enabled"), enabledCheck_->isChecked());
    object.insert(QStringLiteral("server"), serverEdit_->text().trimmed());
    object.insert(QStringLiteral("port"), portSpin_->value());
    object.insert(QStringLiteral("nick"), nickEdit_->text().trimmed());
    object.insert(QStringLiteral("username"), usernameEdit_->text().trimmed());
    object.insert(QStringLiteral("realname"), realnameEdit_->text().trimmed());
    object.insert(QStringLiteral("channel"), channelEdit_->text().trimmed());
    object.insert(QStringLiteral("use_tls"), tlsCheck_->isChecked());
    rpc_->call(QStringLiteral("setircconfig"), QJsonArray{object}, this,
        [this](const QJsonValue&) {
            setStatus(QStringLiteral("IRC configuration saved."));
            refresh();
        },
        [this](const QString& error) { setStatus(error, true); });
}

void IrcPage::sendMessage() {
    if (!rpc_) return;
    const auto message = messageEdit_->toPlainText().trimmed();
    if (message.isEmpty()) {
        setStatus(QStringLiteral("IRC message is required."), true);
        return;
    }
    QJsonObject object;
    object.insert(QStringLiteral("message"), message);
    object.insert(QStringLiteral("server"), serverEdit_->text().trimmed());
    object.insert(QStringLiteral("port"), portSpin_->value());
    object.insert(QStringLiteral("nick"), nickEdit_->text().trimmed());
    object.insert(QStringLiteral("username"), usernameEdit_->text().trimmed());
    object.insert(QStringLiteral("realname"), realnameEdit_->text().trimmed());
    object.insert(QStringLiteral("channel"), channelEdit_->text().trimmed());
    object.insert(QStringLiteral("use_tls"), tlsCheck_->isChecked());
    rpc_->call(QStringLiteral("sendircmessage"), QJsonArray{object}, this,
        [this](const QJsonValue& result) {
            const auto obj = result.toObject();
            messageEdit_->clear();
            setStatus(QStringLiteral("IRC bridge status: %1").arg(obj.value(QStringLiteral("status")).toString()));
            refresh();
        },
        [this](const QString& error) { setStatus(error, true); });
}
