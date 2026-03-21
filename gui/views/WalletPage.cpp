#include "WalletPage.hpp"
#include "rpc/RpcClient.hpp"

#include <cmath>
#include <QCheckBox>
#include <QDoubleSpinBox>
#include <QFormLayout>
#include <QGroupBox>
#include <QHeaderView>
#include <QJsonArray>
#include <QJsonObject>
#include <QLabel>
#include <QLineEdit>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QVBoxLayout>
#include <QHBoxLayout>

namespace {
QLabel* makeSelectableLabel() {
    auto* label = new QLabel(QStringLiteral("-"));
    label->setTextInteractionFlags(Qt::TextSelectableByMouse);
    label->setWordWrap(true);
    return label;
}
}

WalletPage::WalletPage(QWidget* parent)
    : QWidget(parent) {
    auto* root = new QVBoxLayout(this);
    auto* title = new QLabel(QStringLiteral("Wallet Summary"));
    title->setObjectName(QStringLiteral("pageTitle"));
    root->addWidget(title);

    auto* summaryBox = new QGroupBox(QStringLiteral("Overview"), this);
    auto* form = new QFormLayout(summaryBox);
    modeValue_ = makeSelectableLabel();
    primaryValue_ = makeSelectableLabel();
    addressCountValue_ = makeSelectableLabel();
    spendableValue_ = makeSelectableLabel();
    immatureValue_ = makeSelectableLabel();
    totalValue_ = makeSelectableLabel();
    statusValue_ = makeSelectableLabel();

    form->addRow(QStringLiteral("Mode"), modeValue_);
    form->addRow(QStringLiteral("Primary Address"), primaryValue_);
    form->addRow(QStringLiteral("Address Count"), addressCountValue_);
    form->addRow(QStringLiteral("Spendable"), spendableValue_);
    form->addRow(QStringLiteral("Immature"), immatureValue_);
    form->addRow(QStringLiteral("Total"), totalValue_);
    form->addRow(QStringLiteral("Status"), statusValue_);
    root->addWidget(summaryBox);

    auto* actionRow = new QWidget(this);
    auto* actionLayout = new QHBoxLayout(actionRow);
    actionLayout->setContentsMargins(0, 0, 0, 0);
    refreshButton_ = new QPushButton(QStringLiteral("Refresh"), this);
    newAddressButton_ = new QPushButton(QStringLiteral("New Address"), this);
    rescanButton_ = new QPushButton(QStringLiteral("Rescan"), this);
    mnemonicButton_ = new QPushButton(QStringLiteral("Reveal Mnemonic"), this);
    includeMempoolCheck_ = new QCheckBox(QStringLiteral("Include mempool in history"), this);
    actionLayout->addWidget(refreshButton_);
    actionLayout->addWidget(newAddressButton_);
    actionLayout->addWidget(rescanButton_);
    actionLayout->addWidget(mnemonicButton_);
    actionLayout->addWidget(includeMempoolCheck_);
    actionLayout->addStretch(1);
    root->addWidget(actionRow);

    addressTable_ = new QTableWidget(this);
    addressTable_->setColumnCount(1);
    addressTable_->setHorizontalHeaderLabels({QStringLiteral("Wallet Addresses")});
    addressTable_->horizontalHeader()->setStretchLastSection(true);
    addressTable_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    addressTable_->setSelectionBehavior(QAbstractItemView::SelectRows);
    root->addWidget(addressTable_, 1);

    utxoTable_ = new QTableWidget(this);
    utxoTable_->setColumnCount(5);
    utxoTable_->setHorizontalHeaderLabels({QStringLiteral("TXID"), QStringLiteral("Vout"), QStringLiteral("Amount"), QStringLiteral("Height"), QStringLiteral("Address")});
    utxoTable_->horizontalHeader()->setStretchLastSection(true);
    utxoTable_->horizontalHeader()->setSectionResizeMode(0, QHeaderView::Stretch);
    utxoTable_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    utxoTable_->setSelectionBehavior(QAbstractItemView::SelectRows);
    root->addWidget(utxoTable_, 1);

    historyTable_ = new QTableWidget(this);
    historyTable_->setColumnCount(1);
    historyTable_->setHorizontalHeaderLabels({QStringLiteral("History")});
    historyTable_->horizontalHeader()->setStretchLastSection(true);
    historyTable_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    historyTable_->setSelectionBehavior(QAbstractItemView::SelectRows);
    root->addWidget(historyTable_, 1);

    auto* sendBox = new QGroupBox(QStringLiteral("Send Payment"), this);
    auto* sendLayout = new QFormLayout(sendBox);
    sendToEdit_ = new QLineEdit(this);
    sendAmountSpin_ = new QDoubleSpinBox(this);
    sendAmountSpin_->setDecimals(8);
    sendAmountSpin_->setRange(0.00000001, 1000000000.0);
    sendAmountSpin_->setValue(1.0);
    opReturnEdit_ = new QLineEdit(this);
    opReturnEdit_->setPlaceholderText(QStringLiteral("Optional OP_RETURN note"));
    sendButton_ = new QPushButton(QStringLiteral("Send"), this);
    sendLayout->addRow(QStringLiteral("Recipient"), sendToEdit_);
    sendLayout->addRow(QStringLiteral("Amount"), sendAmountSpin_);
    sendLayout->addRow(QStringLiteral("OP_RETURN"), opReturnEdit_);
    sendLayout->addRow(QString(), sendButton_);
    root->addWidget(sendBox);

    mnemonicView_ = new QPlainTextEdit(this);
    mnemonicView_->setReadOnly(true);
    mnemonicView_->setPlaceholderText(QStringLiteral("Mnemonic will only be shown after you explicitly request it."));
    root->addWidget(mnemonicView_, 1);

    connect(refreshButton_, &QPushButton::clicked, this, [this]() { refresh(); });
    connect(newAddressButton_, &QPushButton::clicked, this, [this]() { requestNewAddress(); });
    connect(rescanButton_, &QPushButton::clicked, this, [this]() { requestRescan(); });
    connect(mnemonicButton_, &QPushButton::clicked, this, [this]() { requestMnemonic(); });
    connect(sendButton_, &QPushButton::clicked, this, [this]() { sendPayment(); });
    connect(includeMempoolCheck_, &QCheckBox::toggled, this, [this]() { refresh(); });
}

void WalletPage::setRpcClient(RpcClient* client) {
    rpc_ = client;
}

QString WalletPage::formatCoins(qint64 sats) {
    const qint64 whole = sats / 100000000LL;
    const qint64 frac = qAbs(sats % 100000000LL);
    return QStringLiteral("%1.%2 CryptEX")
        .arg(whole)
        .arg(frac, 8, 10, QLatin1Char('0'));
}

void WalletPage::setStatus(const QString& text, bool error) {
    statusValue_->setText(text);
    statusValue_->setStyleSheet(error ? QStringLiteral("color:#a61b1b;") : QString());
}

void WalletPage::refresh() {
    if (!rpc_) {
        setStatus(QStringLiteral("RPC client not configured."), true);
        return;
    }

    setStatus(QStringLiteral("Refreshing..."));
    rpc_->call(QStringLiteral("getwalletinfo"), {}, this,
        [this](const QJsonValue& result) {
            const auto obj = result.toObject();
            modeValue_->setText(obj.value(QStringLiteral("mode")).toString(QStringLiteral("-")));
            primaryValue_->setText(obj.value(QStringLiteral("primaryaddress")).toString(QStringLiteral("-")));
            addressCountValue_->setText(QString::number(obj.value(QStringLiteral("addresscount")).toInteger()));
            const auto spendable = obj.value(QStringLiteral("balance_sats")).toInteger();
            const auto immature = obj.value(QStringLiteral("immature_balance_sats")).toInteger();
            const auto total = obj.value(QStringLiteral("total_balance_sats")).toInteger();
            spendableValue_->setText(formatCoins(spendable));
            immatureValue_->setText(formatCoins(immature));
            totalValue_->setText(formatCoins(total));
            setStatus(QStringLiteral("Wallet loaded."));
        },
        [this](const QString& error) { setStatus(error, true); });

    rpc_->call(QStringLiteral("getwalletaddresses"), {}, this,
        [this](const QJsonValue& result) {
            const auto rows = result.toArray();
            addressTable_->setRowCount(rows.size());
            for (int i = 0; i < rows.size(); ++i) {
                addressTable_->setItem(i, 0, new QTableWidgetItem(rows.at(i).toString()));
            }
        },
        [this](const QString& error) { setStatus(error, true); });

    rpc_->call(QStringLiteral("listunspent"), {}, this,
        [this](const QJsonValue& result) {
            const auto rows = result.toArray();
            utxoTable_->setRowCount(rows.size());
            for (int i = 0; i < rows.size(); ++i) {
                const auto obj = rows.at(i).toObject();
                utxoTable_->setItem(i, 0, new QTableWidgetItem(obj.value(QStringLiteral("txid")).toString()));
                utxoTable_->setItem(i, 1, new QTableWidgetItem(QString::number(obj.value(QStringLiteral("vout")).toInteger())));
                utxoTable_->setItem(i, 2, new QTableWidgetItem(formatCoins(obj.value(QStringLiteral("amount_sats")).toInteger())));
                utxoTable_->setItem(i, 3, new QTableWidgetItem(QString::number(obj.value(QStringLiteral("height")).toInteger())));
                utxoTable_->setItem(i, 4, new QTableWidgetItem(obj.value(QStringLiteral("address")).toString()));
            }
        },
        [this](const QString& error) { setStatus(error, true); });

    QJsonArray historyParams;
    historyParams.append(includeMempoolCheck_->isChecked());
    rpc_->call(QStringLiteral("getwallethistory"), historyParams, this,
        [this](const QJsonValue& result) {
            const auto rows = result.toArray();
            historyTable_->setRowCount(rows.size());
            for (int i = 0; i < rows.size(); ++i) {
                historyTable_->setItem(i, 0, new QTableWidgetItem(rows.at(i).toString()));
            }
        },
        [this](const QString& error) { setStatus(error, true); });
}

void WalletPage::requestNewAddress() {
    if (!rpc_) {
        setStatus(QStringLiteral("RPC client not configured."), true);
        return;
    }
    rpc_->call(QStringLiteral("getnewaddress"), {}, this,
        [this](const QJsonValue& result) {
            setStatus(QStringLiteral("New address created: %1").arg(result.toString()));
            refresh();
        },
        [this](const QString& error) { setStatus(error, true); });
}

void WalletPage::requestMnemonic() {
    if (!rpc_) {
        setStatus(QStringLiteral("RPC client not configured."), true);
        return;
    }
    rpc_->call(QStringLiteral("dumpmnemonic"), {}, this,
        [this](const QJsonValue& result) {
            mnemonicView_->setPlainText(result.toString());
            setStatus(QStringLiteral("Mnemonic revealed. Keep it offline and private."));
        },
        [this](const QString& error) { setStatus(error, true); });
}

void WalletPage::requestRescan() {
    if (!rpc_) {
        setStatus(QStringLiteral("RPC client not configured."), true);
        return;
    }
    QJsonArray params;
    params.append(20);
    rpc_->call(QStringLiteral("rescanwallet"), params, this,
        [this](const QJsonValue& result) {
            const auto obj = result.toObject();
            setStatus(QStringLiteral("Rescan complete. Discovered %1 addresses.")
                .arg(obj.value(QStringLiteral("discovered")).toInteger()));
            refresh();
        },
        [this](const QString& error) { setStatus(error, true); });
}

void WalletPage::sendPayment() {
    if (!rpc_) {
        setStatus(QStringLiteral("RPC client not configured."), true);
        return;
    }
    if (sendToEdit_->text().trimmed().isEmpty()) {
        setStatus(QStringLiteral("Recipient address is required."), true);
        return;
    }

    const qint64 sats = static_cast<qint64>(std::llround(sendAmountSpin_->value() * 100000000.0));
    if (sats <= 0) {
        setStatus(QStringLiteral("Amount must be greater than zero."), true);
        return;
    }

    QJsonArray params;
    params.append(sendToEdit_->text().trimmed());
    params.append(static_cast<qint64>(sats));
    if (!opReturnEdit_->text().trimmed().isEmpty()) {
        params.append(opReturnEdit_->text().trimmed());
    }
    rpc_->call(QStringLiteral("sendtoaddress"), params, this,
        [this](const QJsonValue& result) {
            setStatus(QStringLiteral("Transaction queued: %1").arg(result.toString()));
            opReturnEdit_->clear();
            refresh();
        },
        [this](const QString& error) { setStatus(error, true); });
}
