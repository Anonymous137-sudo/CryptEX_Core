#include "SendPage.hpp"
#include "rpc/RpcClient.hpp"

#include <QDoubleSpinBox>
#include <QFormLayout>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QJsonArray>
#include <QJsonObject>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QVBoxLayout>
#include <cmath>

namespace {
QLabel* makeValueLabel() {
    auto* label = new QLabel(QStringLiteral("-"));
    label->setObjectName(QStringLiteral("valueLabel"));
    label->setTextInteractionFlags(Qt::TextSelectableByMouse);
    label->setWordWrap(true);
    return label;
}
}

SendPage::SendPage(QWidget* parent) : QWidget(parent) {
    auto* root = new QVBoxLayout(this);
    root->setContentsMargins(12, 12, 12, 12);
    root->setSpacing(12);

    auto* title = new QLabel(QStringLiteral("Send"), this);
    title->setObjectName(QStringLiteral("pageTitle"));
    root->addWidget(title);

    auto* summaryBox = new QGroupBox(QStringLiteral("Wallet status"), this);
    auto* summaryLayout = new QFormLayout(summaryBox);
    walletTypeValue_ = makeValueLabel();
    approvalValue_ = makeValueLabel();
    spendableValue_ = makeValueLabel();
    lockedValue_ = makeValueLabel();
    statusValue_ = makeValueLabel();
    summaryLayout->addRow(QStringLiteral("Wallet type"), walletTypeValue_);
    summaryLayout->addRow(QStringLiteral("Chain approval"), approvalValue_);
    summaryLayout->addRow(QStringLiteral("Spendable"), spendableValue_);
    summaryLayout->addRow(QStringLiteral("Locked"), lockedValue_);
    summaryLayout->addRow(QStringLiteral("Status"), statusValue_);
    root->addWidget(summaryBox);

    auto* sendBox = new QGroupBox(QStringLiteral("Create transaction"), this);
    auto* sendLayout = new QFormLayout(sendBox);
    sendToEdit_ = new QLineEdit(this);
    sendToEdit_->setPlaceholderText(QStringLiteral("Recipient address"));
    amountSpin_ = new QDoubleSpinBox(this);
    amountSpin_->setDecimals(8);
    amountSpin_->setRange(0.00000001, 1000000000.0);
    amountSpin_->setValue(1.0);
    opReturnEdit_ = new QLineEdit(this);
    opReturnEdit_->setPlaceholderText(QStringLiteral("Optional memo"));

    auto* buttonRow = new QWidget(this);
    auto* buttonLayout = new QHBoxLayout(buttonRow);
    buttonLayout->setContentsMargins(0, 0, 0, 0);
    refreshButton_ = new QPushButton(QStringLiteral("Refresh"), this);
    sendButton_ = new QPushButton(QStringLiteral("Send"), this);
    buttonLayout->addWidget(refreshButton_);
    buttonLayout->addStretch(1);
    buttonLayout->addWidget(sendButton_);

    sendLayout->addRow(QStringLiteral("Recipient"), sendToEdit_);
    sendLayout->addRow(QStringLiteral("Amount"), amountSpin_);
    sendLayout->addRow(QStringLiteral("Memo (OP_RETURN)"), opReturnEdit_);
    sendLayout->addRow(QString(), buttonRow);
    root->addWidget(sendBox);
    root->addStretch(1);

    connect(refreshButton_, &QPushButton::clicked, this, [this]() { refresh(); });
    connect(sendButton_, &QPushButton::clicked, this, [this]() { sendPayment(); });
    sendButton_->setEnabled(false);
}

void SendPage::setRpcClient(RpcClient* client) {
    rpc_ = client;
}

QString SendPage::formatCoins(qint64 sats) {
    const qint64 whole = sats / 100000000LL;
    const qint64 frac = qAbs(sats % 100000000LL);
    return QStringLiteral("%1.%2 CryptEX").arg(whole).arg(frac, 8, 10, QLatin1Char('0'));
}

void SendPage::setStatus(const QString& text, bool error) {
    statusValue_->setText(text);
    statusValue_->setStyleSheet(error ? QStringLiteral("color:#d36b6b;") : QString());
}

void SendPage::refresh() {
    if (!rpc_) {
        setStatus(QStringLiteral("RPC client not configured."), true);
        return;
    }
    rpc_->call(QStringLiteral("getwalletinfo"), {}, this,
        [this](const QJsonValue& result) {
            const auto obj = result.toObject();
            const auto format = obj.value(QStringLiteral("address_format")).toString();
            walletTypeValue_->setText(format.isEmpty() ? QStringLiteral("base64") : format);
            chainApproved_ = obj.value(QStringLiteral("chain_approved")).toBool(false);
            approvalValue_->setText(chainApproved_ ? QStringLiteral("Approved") : QStringLiteral("Locked until sync approval"));
            approvalValue_->setStyleSheet(chainApproved_ ? QString() : QStringLiteral("color:#d6b25e;"));
            spendableValue_->setText(formatCoins(obj.value(QStringLiteral("balance_sats")).toInteger()));
            lockedValue_->setText(formatCoins(obj.value(QStringLiteral("locked_balance_sats")).toInteger()));
            sendButton_->setEnabled(chainApproved_);
            setStatus(chainApproved_ ? QStringLiteral("Ready to send.")
                                     : QStringLiteral("Sending stays locked until the local chain is approved."));
        },
        [this](const QString& error) {
            chainApproved_ = false;
            walletTypeValue_->setText(QStringLiteral("-"));
            approvalValue_->setText(QStringLiteral("-"));
            spendableValue_->setText(QStringLiteral("-"));
            lockedValue_->setText(QStringLiteral("-"));
            sendButton_->setEnabled(false);
            if (error.contains(QStringLiteral("no wallet is open"), Qt::CaseInsensitive)) {
                setStatus(QStringLiteral("Open a wallet from Wallet Manager before sending."), true);
            } else {
                setStatus(error, true);
            }
        });
}

void SendPage::sendPayment() {
    if (!rpc_) {
        setStatus(QStringLiteral("RPC client not configured."), true);
        return;
    }
    if (!chainApproved_) {
        setStatus(QStringLiteral("Sending is disabled until the local chain is fully approved."), true);
        return;
    }
    const auto recipient = sendToEdit_->text().trimmed();
    if (recipient.isEmpty()) {
        setStatus(QStringLiteral("Recipient address is required."), true);
        return;
    }
    const qint64 sats = static_cast<qint64>(std::llround(amountSpin_->value() * 100000000.0));
    if (sats <= 0) {
        setStatus(QStringLiteral("Amount must be greater than zero."), true);
        return;
    }

    QJsonArray params;
    params.push_back(recipient);
    params.push_back(sats);
    if (!opReturnEdit_->text().trimmed().isEmpty()) {
        QJsonObject options;
        options.insert(QStringLiteral("op_return"), opReturnEdit_->text().trimmed());
        params.push_back(options);
    }

    rpc_->call(QStringLiteral("sendtoaddress"), params, this,
        [this](const QJsonValue& result) {
            sendToEdit_->clear();
            opReturnEdit_->clear();
            setStatus(QStringLiteral("Transaction queued: %1").arg(result.toString()));
            refresh();
        },
        [this](const QString& error) {
            setStatus(error, true);
        });
}
