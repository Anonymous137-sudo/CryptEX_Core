#include "ChatPage.hpp"
#include "rpc/RpcClient.hpp"

#include <QComboBox>
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

ChatPage::ChatPage(QWidget* parent)
    : QWidget(parent) {
    auto* root = new QVBoxLayout(this);
    root->setContentsMargins(12, 12, 12, 12);
    root->setSpacing(12);

    setStyleSheet(
        "QLabel { color: #63ff7d; }"
        "QLineEdit, QPlainTextEdit, QSpinBox, QComboBox { background: #050505; color: #63ff7d; "
        "border: 1px solid #1e4f23; border-radius: 3px; selection-background-color: #1e4f23; "
        "font-family: Menlo, Monaco, monospace; }"
        "QPushButton { background: #112914; color: #8bff9f; border: 1px solid #1e4f23; border-radius: 4px; padding: 5px 12px; }"
        "QPushButton:hover { background: #16361a; }"
        "QPushButton:pressed { background: #0d2210; }"
        "QTableWidget { background: #000000; color: #5dff74; gridline-color: #17391b; border: 1px solid #1e4f23; "
        "selection-background-color: #16361a; font-family: Menlo, Monaco, monospace; }"
        "QHeaderView::section { background: #0d0d0d; color: #7dff90; border: 1px solid #1e4f23; padding: 4px; }");

    auto* title = new QLabel(QStringLiteral("Secure Chat"));
    title->setObjectName(QStringLiteral("pageTitle"));
    root->addWidget(title);

    infoValue_ = new QLabel(QStringLiteral("-"));
    infoValue_->setTextInteractionFlags(Qt::TextSelectableByMouse);
    statusValue_ = new QLabel(QStringLiteral("-"));
    statusValue_->setWordWrap(true);
    root->addWidget(infoValue_);
    root->addWidget(statusValue_);

    inboxTable_ = new QTableWidget(this);
    inboxTable_->setColumnCount(7);
    inboxTable_->setHorizontalHeaderLabels({QStringLiteral("Time"), QStringLiteral("Direction"), QStringLiteral("Scope"), QStringLiteral("Sender"), QStringLiteral("Channel/Peer"), QStringLiteral("Message"), QStringLiteral("Status")});
    inboxTable_->horizontalHeader()->setStretchLastSection(true);
    inboxTable_->horizontalHeader()->setSectionResizeMode(5, QHeaderView::Stretch);
    inboxTable_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    inboxTable_->setSelectionBehavior(QAbstractItemView::SelectRows);
    inboxTable_->verticalHeader()->setVisible(false);
    inboxTable_->setAlternatingRowColors(false);
    inboxTable_->setShowGrid(true);
    root->addWidget(inboxTable_, 1);

    auto* compose = new QFormLayout();
    limitSpin_ = new QSpinBox(this);
    limitSpin_->setRange(1, 500);
    limitSpin_->setValue(50);
    modeCombo_ = new QComboBox(this);
    modeCombo_->addItems({QStringLiteral("Public"), QStringLiteral("Private")});
    peerEdit_ = new QLineEdit(QStringLiteral("127.0.0.1:9333"), this);
    channelEdit_ = new QLineEdit(QStringLiteral("general"), this);
    recipientEdit_ = new QLineEdit(this);
    recipientPubkeyEdit_ = new QLineEdit(this);
    messageEdit_ = new QPlainTextEdit(this);
    messageEdit_->setPlaceholderText(QStringLiteral("Write a message..."));
    messageEdit_->setStyleSheet(
        "QPlainTextEdit { background: #000000; color: #5dff74; border: 1px solid #1e4f23; "
        "border-radius: 3px; selection-background-color: #1e4f23; font-family: Menlo, Monaco, monospace; }");
    sendButton_ = new QPushButton(QStringLiteral("Send"), this);

    compose->addRow(QStringLiteral("Inbox Limit"), limitSpin_);
    compose->addRow(QStringLiteral("Mode"), modeCombo_);
    compose->addRow(QStringLiteral("Peer"), peerEdit_);
    compose->addRow(QStringLiteral("Channel"), channelEdit_);
    compose->addRow(QStringLiteral("Recipient Address"), recipientEdit_);
    compose->addRow(QStringLiteral("Recipient Pubkey"), recipientPubkeyEdit_);
    compose->addRow(QStringLiteral("Message"), messageEdit_);
    compose->addRow(QString(), sendButton_);
    root->addLayout(compose);

    connect(modeCombo_, &QComboBox::currentIndexChanged, this, [this]() { updateModeUi(); });
    connect(sendButton_, &QPushButton::clicked, this, [this]() { sendMessage(); });
    updateModeUi();
}

void ChatPage::setRpcClient(RpcClient* client) {
    rpc_ = client;
}

void ChatPage::setStatus(const QString& text, bool error) {
    statusValue_->setText(text);
    statusValue_->setStyleSheet(error ? QStringLiteral("color:#a61b1b;") : QString());
}

void ChatPage::updateModeUi() {
    const bool isPrivate = modeCombo_->currentIndex() == 1;
    channelEdit_->setVisible(!isPrivate);
    recipientEdit_->setVisible(isPrivate);
    recipientPubkeyEdit_->setVisible(isPrivate);
}

void ChatPage::refresh() {
    if (!rpc_) {
        setStatus(QStringLiteral("RPC client not configured."), true);
        return;
    }

    setStatus(QStringLiteral("Refreshing inbox..."));
    rpc_->call(QStringLiteral("getchatinfo"), {}, this,
        [this](const QJsonValue& result) {
            const auto obj = result.toObject();
            infoValue_->setText(QStringLiteral("Messages: %1 | Wallet loaded: %2 | History: %3")
                .arg(obj.value(QStringLiteral("messages")).toInteger())
                .arg(obj.value(QStringLiteral("wallet_loaded")).toBool() ? QStringLiteral("yes") : QStringLiteral("no"))
                .arg(obj.value(QStringLiteral("historyfile")).toString()));
            setStatus(QStringLiteral("Chat backend ready."));
        },
        [this](const QString& error) { setStatus(error, true); });

    QJsonArray params;
    params.append(limitSpin_->value());
    rpc_->call(QStringLiteral("getchatinbox"), params, this,
        [this](const QJsonValue& result) {
            const auto rows = result.toArray();
            inboxTable_->setRowCount(rows.size());
            for (int i = 0; i < rows.size(); ++i) {
                const auto obj = rows.at(i).toObject();
                const auto scope = obj.value(QStringLiteral("private")).toBool() ? QStringLiteral("Private") : QStringLiteral("Public");
                const auto channelOrPeer = obj.value(QStringLiteral("channel")).toString();
                inboxTable_->setItem(i, 0, new QTableWidgetItem(QString::number(obj.value(QStringLiteral("timestamp")).toInteger())));
                inboxTable_->setItem(i, 1, new QTableWidgetItem(obj.value(QStringLiteral("direction")).toString()));
                inboxTable_->setItem(i, 2, new QTableWidgetItem(scope));
                inboxTable_->setItem(i, 3, new QTableWidgetItem(obj.value(QStringLiteral("sender_address")).toString()));
                inboxTable_->setItem(i, 4, new QTableWidgetItem(channelOrPeer.isEmpty() ? obj.value(QStringLiteral("peer_label")).toString() : channelOrPeer));
                inboxTable_->setItem(i, 5, new QTableWidgetItem(obj.value(QStringLiteral("message")).toString()));
                inboxTable_->setItem(i, 6, new QTableWidgetItem(obj.value(QStringLiteral("status")).toString()));
            }
        },
        [this](const QString& error) { setStatus(error, true); });
}

void ChatPage::sendMessage() {
    if (!rpc_) {
        setStatus(QStringLiteral("RPC client not configured."), true);
        return;
    }

    const bool isPrivate = modeCombo_->currentIndex() == 1;
    if (peerEdit_->text().trimmed().isEmpty()) {
        setStatus(QStringLiteral("Peer endpoint is required."), true);
        return;
    }
    if (messageEdit_->toPlainText().trimmed().isEmpty()) {
        setStatus(QStringLiteral("Message text is required."), true);
        return;
    }

    QJsonArray params;
    params.append(peerEdit_->text().trimmed());
    if (!isPrivate) {
        if (channelEdit_->text().trimmed().isEmpty()) {
            setStatus(QStringLiteral("Channel is required for public chat."), true);
            return;
        }
        params.append(channelEdit_->text().trimmed());
        params.append(messageEdit_->toPlainText());
    } else {
        if (recipientEdit_->text().trimmed().isEmpty() || recipientPubkeyEdit_->text().trimmed().isEmpty()) {
            setStatus(QStringLiteral("Recipient address and pubkey are required for private chat."), true);
            return;
        }
        params.append(recipientEdit_->text().trimmed());
        params.append(recipientPubkeyEdit_->text().trimmed());
        params.append(messageEdit_->toPlainText());
    }

    rpc_->call(isPrivate ? QStringLiteral("sendchatprivate") : QStringLiteral("sendchatpublic"), params, this,
        [this](const QJsonValue& result) {
            const auto obj = result.toObject();
            setStatus(QStringLiteral("Chat sent. id=%1 status=%2")
                .arg(obj.value(QStringLiteral("messageid")).toString())
                .arg(obj.value(QStringLiteral("status")).toString()));
            messageEdit_->clear();
            refresh();
        },
        [this](const QString& error) { setStatus(error, true); });
}
