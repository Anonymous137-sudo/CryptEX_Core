#include "WalletPage.hpp"
#include "AddressFormatDialog.hpp"
#include "rpc/RpcClient.hpp"

#include <cmath>
#include <QCheckBox>
#include <QDateTime>
#include <QDoubleSpinBox>
#include <QFormLayout>
#include <QGroupBox>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QJsonArray>
#include <QJsonObject>
#include <QLabel>
#include <QLineEdit>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QScrollBar>
#include <QSignalBlocker>
#include <QSplitter>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QVBoxLayout>
#include <QTimer>
#include <memory>

namespace {

QLabel* makeSelectableLabel() {
    auto* label = new QLabel(QStringLiteral("-"));
    label->setTextInteractionFlags(Qt::TextSelectableByMouse);
    label->setWordWrap(true);
    return label;
}

QString boolText(bool value, const QString& trueText, const QString& falseText) {
    return value ? trueText : falseText;
}

QString joinArray(const QJsonArray& rows) {
    QStringList parts;
    parts.reserve(rows.size());
    for (const auto& row : rows) parts.push_back(row.toString());
    return parts.join(QStringLiteral(", "));
}

} // namespace

WalletPage::WalletPage(QWidget* parent)
    : QWidget(parent) {
    auto* root = new QVBoxLayout(this);
    auto* title = new QLabel(QStringLiteral("Wallet Summary"));
    title->setObjectName(QStringLiteral("pageTitle"));
    root->addWidget(title);

    auto* summaryBox = new QGroupBox(QStringLiteral("Overview"), this);
    auto* form = new QFormLayout(summaryBox);
    modeValue_ = makeSelectableLabel();
    formatValue_ = makeSelectableLabel();
    displayFormatValue_ = makeSelectableLabel();
    primaryValue_ = makeSelectableLabel();
    addressCountValue_ = makeSelectableLabel();
    approvalValue_ = makeSelectableLabel();
    spendableValue_ = makeSelectableLabel();
    immatureValue_ = makeSelectableLabel();
    lockedValue_ = makeSelectableLabel();
    totalValue_ = makeSelectableLabel();
    statusValue_ = makeSelectableLabel();

    form->addRow(QStringLiteral("Mode"), modeValue_);
    form->addRow(QStringLiteral("Wallet Type"), formatValue_);
    form->addRow(QStringLiteral("Address Display"), displayFormatValue_);
    form->addRow(QStringLiteral("Primary Address"), primaryValue_);
    form->addRow(QStringLiteral("Address Count"), addressCountValue_);
    form->addRow(QStringLiteral("Chain Approval"), approvalValue_);
    form->addRow(QStringLiteral("Spendable"), spendableValue_);
    form->addRow(QStringLiteral("Immature"), immatureValue_);
    form->addRow(QStringLiteral("Locked"), lockedValue_);
    form->addRow(QStringLiteral("Total"), totalValue_);
    form->addRow(QStringLiteral("Status"), statusValue_);
    root->addWidget(summaryBox);

    auto* actionRow = new QWidget(this);
    auto* actionLayout = new QHBoxLayout(actionRow);
    actionLayout->setContentsMargins(0, 0, 0, 0);
    refreshButton_ = new QPushButton(QStringLiteral("Refresh"), this);
    changeWalletTypeButton_ = new QPushButton(QStringLiteral("Change Wallet Type"), this);
    newAddressButton_ = new QPushButton(QStringLiteral("New Address"), this);
    rescanButton_ = new QPushButton(QStringLiteral("Rescan"), this);
    mnemonicButton_ = new QPushButton(QStringLiteral("Reveal Mnemonic"), this);
    includeMempoolCheck_ = new QCheckBox(QStringLiteral("Include mempool"), this);
    actionLayout->addWidget(refreshButton_);
    actionLayout->addWidget(changeWalletTypeButton_);
    actionLayout->addWidget(newAddressButton_);
    actionLayout->addWidget(rescanButton_);
    actionLayout->addWidget(mnemonicButton_);
    actionLayout->addWidget(includeMempoolCheck_);
    actionLayout->addStretch(1);
    root->addWidget(actionRow);

    auto* mainSplitter = new QSplitter(Qt::Vertical, this);

    auto* addressSection = new QWidget(this);
    auto* addressLayout = new QVBoxLayout(addressSection);
    addressLayout->setContentsMargins(0, 0, 0, 0);
    auto* addressTitle = new QLabel(QStringLiteral("Address Book"), this);
    addressTitle->setObjectName(QStringLiteral("sectionTitle"));
    addressLayout->addWidget(addressTitle);

    addressTable_ = new QTableWidget(this);
    addressTable_->setColumnCount(5);
    addressTable_->setHorizontalHeaderLabels({
        QStringLiteral("Label"),
        QStringLiteral("Address"),
        QStringLiteral("Pubkey"),
        QStringLiteral("Primary"),
        QStringLiteral("Index")
    });
    addressTable_->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    addressTable_->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Stretch);
    addressTable_->horizontalHeader()->setSectionResizeMode(2, QHeaderView::Stretch);
    addressTable_->horizontalHeader()->setSectionResizeMode(3, QHeaderView::ResizeToContents);
    addressTable_->horizontalHeader()->setSectionResizeMode(4, QHeaderView::ResizeToContents);
    addressTable_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    addressTable_->setSelectionBehavior(QAbstractItemView::SelectRows);
    addressTable_->setSelectionMode(QAbstractItemView::SingleSelection);
    addressTable_->setWordWrap(false);
    addressTable_->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
    addressLayout->addWidget(addressTable_, 1);

    auto* labelRow = new QWidget(this);
    auto* labelLayout = new QHBoxLayout(labelRow);
    labelLayout->setContentsMargins(0, 0, 0, 0);
    labelAddressEdit_ = new QLineEdit(this);
    labelAddressEdit_->setPlaceholderText(QStringLiteral("Selected address"));
    labelAddressEdit_->setReadOnly(true);
    labelEdit_ = new QLineEdit(this);
    labelEdit_->setPlaceholderText(QStringLiteral("Label"));
    saveLabelButton_ = new QPushButton(QStringLiteral("Save Label"), this);
    labelLayout->addWidget(labelAddressEdit_, 3);
    labelLayout->addWidget(labelEdit_, 2);
    labelLayout->addWidget(saveLabelButton_);
    addressLayout->addWidget(labelRow);

    mainSplitter->addWidget(addressSection);

    auto* spendSection = new QWidget(this);
    auto* spendLayout = new QVBoxLayout(spendSection);
    spendLayout->setContentsMargins(0, 0, 0, 0);
    auto* spendTitle = new QLabel(QStringLiteral("Coin Control"), this);
    spendTitle->setObjectName(QStringLiteral("sectionTitle"));
    spendLayout->addWidget(spendTitle);

    utxoTable_ = new QTableWidget(this);
    utxoTable_->setColumnCount(5);
    utxoTable_->setHorizontalHeaderLabels({
        QStringLiteral("TXID"),
        QStringLiteral("Vout"),
        QStringLiteral("Amount"),
        QStringLiteral("Height"),
        QStringLiteral("Address")
    });
    utxoTable_->horizontalHeader()->setSectionResizeMode(0, QHeaderView::Stretch);
    utxoTable_->horizontalHeader()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
    utxoTable_->horizontalHeader()->setSectionResizeMode(2, QHeaderView::ResizeToContents);
    utxoTable_->horizontalHeader()->setSectionResizeMode(3, QHeaderView::ResizeToContents);
    utxoTable_->horizontalHeader()->setSectionResizeMode(4, QHeaderView::Stretch);
    utxoTable_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    utxoTable_->setSelectionBehavior(QAbstractItemView::SelectRows);
    utxoTable_->setSelectionMode(QAbstractItemView::ExtendedSelection);
    utxoTable_->setWordWrap(false);
    utxoTable_->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
    spendLayout->addWidget(utxoTable_, 1);

    auto* sendBox = new QGroupBox(QStringLiteral("Send Payment"), this);
    auto* sendLayout = new QFormLayout(sendBox);
    sendToEdit_ = new QLineEdit(this);
    sendAmountSpin_ = new QDoubleSpinBox(this);
    sendAmountSpin_->setDecimals(8);
    sendAmountSpin_->setRange(0.00000001, 1000000000.0);
    sendAmountSpin_->setValue(1.0);
    changeAddressEdit_ = new QLineEdit(this);
    changeAddressEdit_->setPlaceholderText(QStringLiteral("Optional custom change address"));
    opReturnEdit_ = new QLineEdit(this);
    opReturnEdit_->setPlaceholderText(QStringLiteral("Optional OP_RETURN note"));
    sendButton_ = new QPushButton(QStringLiteral("Send"), this);
    changeWalletTypeButton_->setEnabled(false);
    newAddressButton_->setEnabled(false);
    rescanButton_->setEnabled(false);
    mnemonicButton_->setEnabled(false);
    saveLabelButton_->setEnabled(false);
    sendButton_->setEnabled(false);
    sendLayout->addRow(QStringLiteral("Recipient"), sendToEdit_);
    sendLayout->addRow(QStringLiteral("Amount"), sendAmountSpin_);
    sendLayout->addRow(QStringLiteral("Change Address"), changeAddressEdit_);
    sendLayout->addRow(QStringLiteral("OP_RETURN"), opReturnEdit_);
    sendLayout->addRow(QStringLiteral("Coin Control"), new QLabel(QStringLiteral("Select UTXO rows above to force exact inputs."), this));
    sendLayout->addRow(QString(), sendButton_);
    spendLayout->addWidget(sendBox);

    mainSplitter->addWidget(spendSection);

    auto* historySection = new QWidget(this);
    auto* historyLayout = new QVBoxLayout(historySection);
    historyLayout->setContentsMargins(0, 0, 0, 0);
    auto* historyTitle = new QLabel(QStringLiteral("Transaction Activity"), this);
    historyTitle->setObjectName(QStringLiteral("sectionTitle"));
    historyLayout->addWidget(historyTitle);

    historyTable_ = new QTableWidget(this);
    historyTable_->setColumnCount(6);
    historyTable_->setHorizontalHeaderLabels({
        QStringLiteral("Time"),
        QStringLiteral("Type"),
        QStringLiteral("Net"),
        QStringLiteral("Confs"),
        QStringLiteral("Counterparty"),
        QStringLiteral("TXID")
    });
    historyTable_->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    historyTable_->horizontalHeader()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
    historyTable_->horizontalHeader()->setSectionResizeMode(2, QHeaderView::ResizeToContents);
    historyTable_->horizontalHeader()->setSectionResizeMode(3, QHeaderView::ResizeToContents);
    historyTable_->horizontalHeader()->setSectionResizeMode(4, QHeaderView::Stretch);
    historyTable_->horizontalHeader()->setSectionResizeMode(5, QHeaderView::Stretch);
    historyTable_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    historyTable_->setSelectionBehavior(QAbstractItemView::SelectRows);
    historyTable_->setSelectionMode(QAbstractItemView::SingleSelection);
    historyTable_->setWordWrap(false);
    historyTable_->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
    historyLayout->addWidget(historyTable_, 1);

    txDetailView_ = new QPlainTextEdit(this);
    txDetailView_->setReadOnly(true);
    txDetailView_->setPlaceholderText(QStringLiteral("Select a transaction to inspect its full details."));
    historyLayout->addWidget(txDetailView_, 1);

    mainSplitter->addWidget(historySection);
    mainSplitter->setStretchFactor(0, 2);
    mainSplitter->setStretchFactor(1, 2);
    mainSplitter->setStretchFactor(2, 3);
    root->addWidget(mainSplitter, 1);

    mnemonicView_ = new QPlainTextEdit(this);
    mnemonicView_->setReadOnly(true);
    mnemonicView_->setPlaceholderText(QStringLiteral("Mnemonic will only be shown after you explicitly request it."));
    root->addWidget(mnemonicView_, 1);

    connect(refreshButton_, &QPushButton::clicked, this, [this]() { refresh(); });
    connect(changeWalletTypeButton_, &QPushButton::clicked, this, [this]() { requestWalletTypeChange(); });
    connect(newAddressButton_, &QPushButton::clicked, this, [this]() { requestNewAddress(); });
    connect(rescanButton_, &QPushButton::clicked, this, [this]() { requestRescan(); });
    connect(mnemonicButton_, &QPushButton::clicked, this, [this]() { requestMnemonic(); });
    connect(saveLabelButton_, &QPushButton::clicked, this, [this]() { saveLabel(); });
    connect(sendButton_, &QPushButton::clicked, this, [this]() { sendPayment(); });
    connect(includeMempoolCheck_, &QCheckBox::toggled, this, [this]() { refresh(); });
    // The itemSelectionChanged signals will be connected after the first refresh.
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

QString WalletPage::formatTimestamp(qint64 timestamp) {
    if (timestamp <= 0) return QStringLiteral("-");
    return QDateTime::fromSecsSinceEpoch(timestamp).toString(QStringLiteral("yyyy-MM-dd hh:mm:ss"));
}

void WalletPage::setStatus(const QString& text, bool error) {
    statusValue_->setText(text);
    statusValue_->setStyleSheet(error ? QStringLiteral("color:#a61b1b;") : QString());
}

QString WalletPage::selectAddressFormat(const QString& title) {
    AddressFormatDialog dialog(title,
                               preferredAddressFormat_.isEmpty() ? currentWalletFormat_ : preferredAddressFormat_,
                               title.contains(QStringLiteral("Wallet Type"), Qt::CaseInsensitive)
                                   ? QStringLiteral("Choose the wallet's stored default address format. This persists across refreshes and restarts.")
                                   : QStringLiteral("Choose how this address should be displayed."),
                               this);
    if (dialog.exec() != QDialog::Accepted) {
        return {};
    }
    preferredAddressFormat_ = dialog.selectedFormat();
    if (displayFormatValue_) {
        displayFormatValue_->setText(preferredAddressFormat_);
    }
    return preferredAddressFormat_;
}

QString WalletPage::addressFromObject(const QJsonObject& obj, const QString& baseKey) const {
    const auto normalized = preferredAddressFormat_.trimmed().toLower();
    QString key = baseKey;
    if (normalized == QStringLiteral("base64")) key += QStringLiteral("_base64");
    else if (normalized == QStringLiteral("base58")) key += QStringLiteral("_base58");
    else if (normalized == QStringLiteral("hex")) key += QStringLiteral("_hex");
    else if (normalized == QStringLiteral("bech32")) key += QStringLiteral("_bech32");
    const auto value = obj.value(key).toString();
    if (!value.isEmpty()) return value;
    return obj.value(baseKey).toString();
}

void WalletPage::syncLabelEditorFromSelection() {
    const auto items = addressTable_->selectedItems();
    if (items.isEmpty()) {
        labelAddressEdit_->clear();
        labelEdit_->clear();
        return;
    }
    const int row = items.first()->row();
    const auto* addressItem = addressTable_->item(row, 1);
    const auto* labelItem = addressTable_->item(row, 0);
    labelAddressEdit_->setText(addressItem ? addressItem->text() : QString());
    labelEdit_->setText(labelItem ? labelItem->text() : QString());
}

QString WalletPage::selectedAddressKey() const {
    const auto items = addressTable_->selectedItems();
    if (items.isEmpty()) return {};
    const int row = items.first()->row();
    const auto* item = addressTable_->item(row, 1);
    return item ? item->data(Qt::UserRole).toString() : QString();
}

QString WalletPage::selectedHistoryTxid() const {
    const auto items = historyTable_->selectedItems();
    if (items.isEmpty()) return detailTxid_;
    const int row = items.first()->row();
    const auto* item = historyTable_->item(row, 5);
    return item ? item->text() : detailTxid_;
}

void WalletPage::restoreAddressSelection(const QString& addressKey) {
    if (addressKey.trimmed().isEmpty()) return;
    for (int row = 0; row < addressTable_->rowCount(); ++row) {
        const auto* item = addressTable_->item(row, 1);
        if (item && item->data(Qt::UserRole).toString() == addressKey) {
            addressTable_->selectRow(row);
            syncLabelEditorFromSelection();
            return;
        }
    }
}

void WalletPage::restoreHistorySelection(const QString& txid) {
    if (txid.trimmed().isEmpty()) return;
    for (int row = 0; row < historyTable_->rowCount(); ++row) {
        const auto* item = historyTable_->item(row, 5);
        if (item && item->text() == txid) {
            historyTable_->selectRow(row);
            detailTxid_ = txid;
            requestTransactionDetail(txid);
            return;
        }
    }
}

void WalletPage::refresh() {
    if (!rpc_) {
        setStatus(QStringLiteral("RPC client not configured."), true);
        return;
    }

    // Disconnect selection signals to avoid triggering during population
    disconnect(addressTable_, &QTableWidget::itemSelectionChanged, this, nullptr);
    disconnect(historyTable_, &QTableWidget::itemSelectionChanged, this, nullptr);

    setStatus(QStringLiteral("Refreshing..."));
    const int generation = ++refreshGeneration_;
    const auto previouslySelectedAddress = selectedAddressKey();
    const auto previouslySelectedTxid = selectedHistoryTxid();

    // Counter for 4 RPC calls
    auto pending = std::make_shared<int>(4);
    auto reenable = [this, pending]() {
        if (--(*pending) == 0) {
            connect(addressTable_, &QTableWidget::itemSelectionChanged, this, [this]() { syncLabelEditorFromSelection(); });
            connect(historyTable_, &QTableWidget::itemSelectionChanged, this, [this]() {
                QTimer::singleShot(0, this, [this]() {
                    const auto items = historyTable_->selectedItems();
                    if (items.isEmpty()) return;
                    const auto* first = items.first();
                    const auto txid = historyTable_->item(first->row(), 5)->text();
                    requestTransactionDetail(txid);
                });
            });
        }
    };

    // Call 1: getwalletinfo
    rpc_->call(QStringLiteral("getwalletinfo"), {}, this,
        [this, generation, reenable](const QJsonValue& result) {
            if (generation != refreshGeneration_) {
                reenable();
                return;
            }
            const auto obj = result.toObject();
            modeValue_->setText(obj.value(QStringLiteral("mode")).toString(QStringLiteral("-")));
            // Set format label from address_format field
            const QString formatStr = obj.value(QStringLiteral("address_format")).toString();
            currentWalletFormat_ = formatStr.isEmpty() ? QStringLiteral("base64") : formatStr;
            formatValue_->setText(currentWalletFormat_);
            displayFormatValue_->setText(preferredAddressFormat_.isEmpty() ? currentWalletFormat_ : preferredAddressFormat_);
            primaryValue_->setText(addressFromObject(obj, QStringLiteral("primaryaddress")));
            addressCountValue_->setText(QString::number(obj.value(QStringLiteral("addresscount")).toInteger()));
            chainApproved_ = obj.value(QStringLiteral("chain_approved")).toBool(false);
            const auto spendable = obj.value(QStringLiteral("balance_sats")).toInteger();
            const auto immature = obj.value(QStringLiteral("immature_balance_sats")).toInteger();
            const auto locked = obj.value(QStringLiteral("locked_balance_sats")).toInteger();
            const auto total = obj.value(QStringLiteral("total_balance_sats")).toInteger();
            approvalValue_->setText(chainApproved_ ? QStringLiteral("Approved") : QStringLiteral("Locked until full sync approval"));
            approvalValue_->setStyleSheet(chainApproved_ ? QString() : QStringLiteral("color:#d6b25e;"));
            spendableValue_->setText(formatCoins(spendable));
            immatureValue_->setText(formatCoins(immature));
            lockedValue_->setText(formatCoins(locked));
            totalValue_->setText(formatCoins(total));
            changeWalletTypeButton_->setEnabled(true);
            newAddressButton_->setEnabled(true);
            rescanButton_->setEnabled(true);
            mnemonicButton_->setEnabled(true);
            saveLabelButton_->setEnabled(true);
            sendButton_->setEnabled(chainApproved_);
            setStatus(chainApproved_
                ? QStringLiteral("Wallet loaded.")
                : QStringLiteral("Wallet loaded, but funds are locked until the local chain is fully approved."));
            reenable();
        },
        [this, generation, reenable](const QString& error) {
            if (generation != refreshGeneration_) {
                reenable();
                return;
            }
            chainApproved_ = false;
            formatValue_->setText(QStringLiteral("-"));
            displayFormatValue_->setText(QStringLiteral("-"));
            primaryValue_->setText(QStringLiteral("-"));
            addressCountValue_->setText(QStringLiteral("-"));
            approvalValue_->setText(QStringLiteral("-"));
            approvalValue_->setStyleSheet(QString());
            spendableValue_->setText(QStringLiteral("-"));
            immatureValue_->setText(QStringLiteral("-"));
            lockedValue_->setText(QStringLiteral("-"));
            totalValue_->setText(QStringLiteral("-"));
            changeWalletTypeButton_->setEnabled(false);
            newAddressButton_->setEnabled(false);
            rescanButton_->setEnabled(false);
            mnemonicButton_->setEnabled(false);
            saveLabelButton_->setEnabled(false);
            sendButton_->setEnabled(false);
            if (error.contains(QStringLiteral("no wallet is open"), Qt::CaseInsensitive)) {
                addressTable_->setRowCount(0);
                utxoTable_->setRowCount(0);
                historyTable_->setRowCount(0);
                txDetailView_->clear();
                setStatus(QStringLiteral("No wallet open. Use Settings > Wallet Session to create or open a wallet."));
            } else if (error.contains(QStringLiteral("wallet RPC requires"), Qt::CaseInsensitive) ||
                       error.contains(QStringLiteral("walletpass"), Qt::CaseInsensitive)) {
                setStatus(QStringLiteral("Wallet password is required after restart. Enter Wallet Pass in Settings and restart or reconnect the backend."), true);
            } else {
                setStatus(error, true);
            }
            reenable();
        });

    // Call 2: getwalletaddressbook
    rpc_->call(QStringLiteral("getwalletaddressbook"), {}, this,
        [this, generation, previouslySelectedAddress, reenable](const QJsonValue& result) {
            if (generation != refreshGeneration_) {
                reenable();
                return;
            }
            const auto rows = result.toArray();
            const QSignalBlocker blocker(addressTable_);
            addressTable_->setUpdatesEnabled(false);
            addressTable_->setRowCount(rows.size());
            for (int i = 0; i < rows.size(); ++i) {
                const auto obj = rows.at(i).toObject();
                addressTable_->setItem(i, 0, new QTableWidgetItem(obj.value(QStringLiteral("label")).toString()));
                auto* addressItem = new QTableWidgetItem(addressFromObject(obj, QStringLiteral("address")));
                addressItem->setData(Qt::UserRole, obj.value(QStringLiteral("address_base64")).toString());
                addressTable_->setItem(i, 1, addressItem);
                addressTable_->setItem(i, 2, new QTableWidgetItem(obj.value(QStringLiteral("pubkey_b64")).toString()));
                addressTable_->setItem(i, 3, new QTableWidgetItem(boolText(obj.value(QStringLiteral("primary")).toBool(), QStringLiteral("Yes"), QStringLiteral("No"))));
                addressTable_->setItem(i, 4, new QTableWidgetItem(QString::number(obj.value(QStringLiteral("hd_index")).toInteger())));
            }
            addressTable_->setUpdatesEnabled(true);
            if (!previouslySelectedAddress.isEmpty()) {
                restoreAddressSelection(previouslySelectedAddress);
            } else if (rows.size() > 0 && addressTable_->currentRow() < 0) {
                addressTable_->selectRow(0);
            }
            if (addressTable_->currentRow() >= 0) {
                syncLabelEditorFromSelection();
            }
            reenable();
        },
        [this, generation, reenable](const QString& error) {
            if (generation != refreshGeneration_) {
                reenable();
                return;
            }
            addressTable_->setRowCount(0);
            if (!error.contains(QStringLiteral("no wallet is open"), Qt::CaseInsensitive)) {
                setStatus(error, true);
            }
            reenable();
        });

    // Call 3: listunspent
    rpc_->call(QStringLiteral("listunspent"), {}, this,
        [this, generation, reenable](const QJsonValue& result) {
            if (generation != refreshGeneration_) {
                reenable();
                return;
            }
            const auto rows = result.toArray();
            const auto verticalPosition = utxoTable_->verticalScrollBar()->value();
            const QSignalBlocker blocker(utxoTable_);
            utxoTable_->setUpdatesEnabled(false);
            utxoTable_->setRowCount(rows.size());
            for (int i = 0; i < rows.size(); ++i) {
                const auto obj = rows.at(i).toObject();
                utxoTable_->setItem(i, 0, new QTableWidgetItem(obj.value(QStringLiteral("txid")).toString()));
                utxoTable_->setItem(i, 1, new QTableWidgetItem(QString::number(obj.value(QStringLiteral("vout")).toInteger())));
                utxoTable_->setItem(i, 2, new QTableWidgetItem(formatCoins(obj.value(QStringLiteral("amount_sats")).toInteger())));
                utxoTable_->setItem(i, 3, new QTableWidgetItem(QString::number(obj.value(QStringLiteral("height")).toInteger())));
                utxoTable_->setItem(i, 4, new QTableWidgetItem(obj.value(QStringLiteral("address")).toString()));
            }
            utxoTable_->setUpdatesEnabled(true);
            utxoTable_->verticalScrollBar()->setValue(verticalPosition);
            reenable();
        },
        [this, generation, reenable](const QString& error) {
            if (generation != refreshGeneration_) {
                reenable();
                return;
            }
            utxoTable_->setRowCount(0);
            if (error.contains(QStringLiteral("no wallet is open"), Qt::CaseInsensitive)) {
                reenable();
                return;
            }
            if (error.contains(QStringLiteral("locked until"), Qt::CaseInsensitive)) {
                setStatus(QStringLiteral("UTXOs hidden until the chain is fully approved."));
            } else {
                setStatus(error, true);
            }
            reenable();
        });

    // Call 4: getwallettransactions
    QJsonArray historyParams;
    historyParams.append(includeMempoolCheck_->isChecked());
    rpc_->call(QStringLiteral("getwallettransactions"), historyParams, this,
        [this, generation, previouslySelectedTxid, reenable](const QJsonValue& result) {
            if (generation != refreshGeneration_) {
                reenable();
                return;
            }
            const auto rows = result.toArray();
            const auto verticalPosition = historyTable_->verticalScrollBar()->value();
            const QSignalBlocker blocker(historyTable_);
            historyTable_->setUpdatesEnabled(false);
            historyTable_->setRowCount(rows.size());
            for (int i = 0; i < rows.size(); ++i) {
                const auto obj = rows.at(i).toObject();
                historyTable_->setItem(i, 0, new QTableWidgetItem(formatTimestamp(obj.value(QStringLiteral("timestamp")).toInteger())));
                historyTable_->setItem(i, 1, new QTableWidgetItem(obj.value(QStringLiteral("direction")).toString()));
                historyTable_->setItem(i, 2, new QTableWidgetItem(formatCoins(obj.value(QStringLiteral("net_sats")).toInteger())));
                historyTable_->setItem(i, 3, new QTableWidgetItem(QString::number(obj.value(QStringLiteral("confirmations")).toInteger())));
                historyTable_->setItem(i, 4, new QTableWidgetItem(obj.value(QStringLiteral("summary_address")).toString()));
                historyTable_->setItem(i, 5, new QTableWidgetItem(obj.value(QStringLiteral("txid")).toString()));
            }
            historyTable_->setUpdatesEnabled(true);
            historyTable_->verticalScrollBar()->setValue(verticalPosition);
            if (!previouslySelectedTxid.isEmpty()) {
                restoreHistorySelection(previouslySelectedTxid);
            } else if (rows.size() > 0) {
                historyTable_->selectRow(0);
                const auto* txidItem = historyTable_->item(0, 5);
                if (txidItem) {
                    detailTxid_ = txidItem->text();
                    requestTransactionDetail(detailTxid_);
                }
            } else {
                detailTxid_.clear();
                txDetailView_->clear();
            }
            reenable();
        },
        [this, generation, reenable](const QString& error) {
            if (generation != refreshGeneration_) {
                reenable();
                return;
            }
            historyTable_->setRowCount(0);
            txDetailView_->clear();
            if (!error.contains(QStringLiteral("no wallet is open"), Qt::CaseInsensitive)) {
                setStatus(error, true);
            }
            reenable();
        });
}

void WalletPage::requestNewAddress() {
    if (!rpc_) {
        setStatus(QStringLiteral("RPC client not configured."), true);
        return;
    }
    const auto format = selectAddressFormat(QStringLiteral("Create Address"));
    if (format.isEmpty()) return;
    rpc_->call(QStringLiteral("getnewaddress"), QJsonArray{format}, this,
        [this](const QJsonValue& result) {
            setStatus(QStringLiteral("New address created: %1").arg(result.toString()));
            refresh();
        },
        [this](const QString& error) { setStatus(error, true); });
}

void WalletPage::requestWalletTypeChange() {
    if (!rpc_) {
        setStatus(QStringLiteral("RPC client not configured."), true);
        return;
    }
    const auto format = selectAddressFormat(QStringLiteral("Change Wallet Type"));
    if (format.isEmpty()) return;
    rpc_->call(QStringLiteral("setwalletformat"), QJsonArray{format}, this,
        [this, format](const QJsonValue&) {
            currentWalletFormat_ = format;
            preferredAddressFormat_ = format;
            formatValue_->setText(format);
            displayFormatValue_->setText(format);
            setStatus(QStringLiteral("Wallet type changed to %1.").arg(format));
            emit walletTypeChanged();
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

void WalletPage::saveLabel() {
    if (!rpc_) {
        setStatus(QStringLiteral("RPC client not configured."), true);
        return;
    }
    if (labelAddressEdit_->text().trimmed().isEmpty()) {
        setStatus(QStringLiteral("Select an address before saving a label."), true);
        return;
    }

    QJsonArray params;
    params.append(labelAddressEdit_->text().trimmed());
    params.append(labelEdit_->text().trimmed());
    rpc_->call(QStringLiteral("setaddresslabel"), params, this,
        [this](const QJsonValue&) {
            setStatus(QStringLiteral("Address label saved."));
            refresh();
        },
        [this](const QString& error) { setStatus(error, true); });
}

void WalletPage::requestTransactionDetail(const QString& txid) {
    if (!rpc_ || txid.trimmed().isEmpty()) return;
    detailTxid_ = txid.trimmed();
    QJsonArray params;
    params.append(detailTxid_);
    params.append(includeMempoolCheck_->isChecked());
    rpc_->call(QStringLiteral("getwallettransaction"), params, this,
        [this, requestedTxid = detailTxid_](const QJsonValue& result) {
            if (requestedTxid != detailTxid_) return;
            const auto obj = result.toObject();
            QStringList lines;
            lines << QStringLiteral("TXID: %1").arg(obj.value(QStringLiteral("txid")).toString());
            lines << QStringLiteral("Direction: %1").arg(obj.value(QStringLiteral("direction")).toString());
            lines << QStringLiteral("Summary Address: %1").arg(obj.value(QStringLiteral("summary_address")).toString());
            lines << QStringLiteral("Net: %1").arg(formatCoins(obj.value(QStringLiteral("net_sats")).toInteger()));
            lines << QStringLiteral("Received: %1").arg(formatCoins(obj.value(QStringLiteral("received_sats")).toInteger()));
            lines << QStringLiteral("Sent: %1").arg(formatCoins(obj.value(QStringLiteral("sent_sats")).toInteger()));
            lines << QStringLiteral("Fee: %1").arg(formatCoins(obj.value(QStringLiteral("fee_sats")).toInteger()));
            lines << QStringLiteral("Timestamp: %1").arg(formatTimestamp(obj.value(QStringLiteral("timestamp")).toInteger()));
            if (!obj.value(QStringLiteral("block_height")).isNull()) {
                lines << QStringLiteral("Block Height: %1").arg(obj.value(QStringLiteral("block_height")).toInteger());
            }
            lines << QStringLiteral("Confirmations: %1").arg(obj.value(QStringLiteral("confirmations")).toInteger());
            lines << QStringLiteral("Coinbase: %1").arg(boolText(obj.value(QStringLiteral("coinbase")).toBool(), QStringLiteral("Yes"), QStringLiteral("No")));
            lines << QStringLiteral("In Mempool: %1").arg(boolText(obj.value(QStringLiteral("in_mempool")).toBool(), QStringLiteral("Yes"), QStringLiteral("No")));
            lines << QStringLiteral("From: %1").arg(joinArray(obj.value(QStringLiteral("from_addresses")).toArray()));
            lines << QStringLiteral("To: %1").arg(joinArray(obj.value(QStringLiteral("to_addresses")).toArray()));
            txDetailView_->setPlainText(lines.join(QLatin1Char('\n')));
        },
        [this, requestedTxid = detailTxid_](const QString& error) {
            if (requestedTxid != detailTxid_) return;
            txDetailView_->setPlainText(error);
        });
}

void WalletPage::sendPayment() {
    if (!rpc_) {
        setStatus(QStringLiteral("RPC client not configured."), true);
        return;
    }
    if (!chainApproved_) {
        setStatus(QStringLiteral("Sending is disabled until the local chain is fully approved."), true);
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

    QJsonObject options;
    if (!opReturnEdit_->text().trimmed().isEmpty()) {
        options.insert(QStringLiteral("op_return"), opReturnEdit_->text().trimmed());
    }
    if (!changeAddressEdit_->text().trimmed().isEmpty()) {
        options.insert(QStringLiteral("change_address"), changeAddressEdit_->text().trimmed());
    }

    QJsonArray selectedInputs;
    const auto selectedRows = utxoTable_->selectionModel() ? utxoTable_->selectionModel()->selectedRows() : QModelIndexList{};
    for (const auto& index : selectedRows) {
        const int row = index.row();
        QJsonObject input;
        input.insert(QStringLiteral("txid"), utxoTable_->item(row, 0)->text());
        input.insert(QStringLiteral("vout"), utxoTable_->item(row, 1)->text().toInt());
        selectedInputs.append(input);
    }
    if (!selectedInputs.isEmpty()) {
        options.insert(QStringLiteral("inputs"), selectedInputs);
    }
    if (!options.isEmpty()) {
        params.append(options);
    }

    rpc_->call(QStringLiteral("sendtoaddress"), params, this,
        [this, selectedCount = selectedRows.size()](const QJsonValue& result) {
            setStatus(selectedCount > 0
                ? QStringLiteral("Transaction queued with %1 selected inputs: %2").arg(selectedCount).arg(result.toString())
                : QStringLiteral("Transaction queued: %1").arg(result.toString()));
            opReturnEdit_->clear();
            refresh();
        },
        [this](const QString& error) { setStatus(error, true); });
}
