#include "ReceivePage.hpp"
#include "AddressFormatDialog.hpp"
#include "rpc/RpcClient.hpp"

#include <QApplication>
#include <QClipboard>
#include <QFormLayout>
#include <QGroupBox>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QJsonArray>
#include <QJsonObject>
#include <QLabel>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QVBoxLayout>

namespace {
QLabel* makeValueLabel() {
    auto* label = new QLabel(QStringLiteral("-"));
    label->setObjectName(QStringLiteral("valueLabel"));
    label->setTextInteractionFlags(Qt::TextSelectableByMouse);
    label->setWordWrap(true);
    return label;
}
}

ReceivePage::ReceivePage(QWidget* parent) : QWidget(parent) {
    auto* root = new QVBoxLayout(this);
    root->setContentsMargins(12, 12, 12, 12);
    root->setSpacing(12);

    auto* title = new QLabel(QStringLiteral("Receive"), this);
    title->setObjectName(QStringLiteral("pageTitle"));
    root->addWidget(title);

    auto* overviewBox = new QGroupBox(QStringLiteral("Receiving wallet"), this);
    auto* overviewLayout = new QFormLayout(overviewBox);
    walletTypeValue_ = makeValueLabel();
    displayFormatValue_ = makeValueLabel();
    addressCountValue_ = makeValueLabel();
    statusValue_ = makeValueLabel();
    overviewLayout->addRow(QStringLiteral("Wallet type"), walletTypeValue_);
    overviewLayout->addRow(QStringLiteral("Address display"), displayFormatValue_);
    overviewLayout->addRow(QStringLiteral("Address count"), addressCountValue_);
    overviewLayout->addRow(QStringLiteral("Status"), statusValue_);
    root->addWidget(overviewBox);

    auto* primaryBox = new QGroupBox(QStringLiteral("Primary receive address"), this);
    auto* primaryLayout = new QVBoxLayout(primaryBox);
    primaryAddressView_ = new QPlainTextEdit(this);
    primaryAddressView_->setReadOnly(true);
    primaryAddressView_->setPlaceholderText(QStringLiteral("Open a wallet to show the current receive address."));
    primaryAddressView_->setMaximumHeight(88);
    auto* buttonRow = new QWidget(this);
    auto* buttonLayout = new QHBoxLayout(buttonRow);
    buttonLayout->setContentsMargins(0, 0, 0, 0);
    newAddressButton_ = new QPushButton(QStringLiteral("New Address"), this);
    unusedAddressButton_ = new QPushButton(QStringLiteral("Unused Address"), this);
    copyAddressButton_ = new QPushButton(QStringLiteral("Copy"), this);
    buttonLayout->addWidget(newAddressButton_);
    buttonLayout->addWidget(unusedAddressButton_);
    buttonLayout->addStretch(1);
    buttonLayout->addWidget(copyAddressButton_);
    primaryLayout->addWidget(primaryAddressView_);
    primaryLayout->addWidget(buttonRow);
    root->addWidget(primaryBox);

    auto* listBox = new QGroupBox(QStringLiteral("Recent receive addresses"), this);
    auto* listLayout = new QVBoxLayout(listBox);
    addressTable_ = new QTableWidget(this);
    addressTable_->setColumnCount(4);
    addressTable_->setHorizontalHeaderLabels({QStringLiteral("Label"), QStringLiteral("Address"), QStringLiteral("Primary"), QStringLiteral("Index")});
    addressTable_->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    addressTable_->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Stretch);
    addressTable_->horizontalHeader()->setSectionResizeMode(2, QHeaderView::ResizeToContents);
    addressTable_->horizontalHeader()->setSectionResizeMode(3, QHeaderView::ResizeToContents);
    addressTable_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    addressTable_->setSelectionBehavior(QAbstractItemView::SelectRows);
    addressTable_->setSelectionMode(QAbstractItemView::SingleSelection);
    listLayout->addWidget(addressTable_);
    root->addWidget(listBox, 1);

    connect(newAddressButton_, &QPushButton::clicked, this, [this]() { requestNewAddress(); });
    connect(unusedAddressButton_, &QPushButton::clicked, this, [this]() { requestUnusedAddress(); });
    connect(copyAddressButton_, &QPushButton::clicked, this, [this]() { copyPrimaryAddress(); });

    newAddressButton_->setEnabled(false);
    unusedAddressButton_->setEnabled(false);
    copyAddressButton_->setEnabled(false);
}

void ReceivePage::setRpcClient(RpcClient* client) {
    rpc_ = client;
}

void ReceivePage::setStatus(const QString& text, bool error) {
    statusValue_->setText(text);
    statusValue_->setStyleSheet(error ? QStringLiteral("color:#d36b6b;") : QString());
}

QString ReceivePage::selectAddressFormat(const QString& title) {
    AddressFormatDialog dialog(title,
                               preferredAddressFormat_.isEmpty() ? currentWalletFormat_ : preferredAddressFormat_,
                               QString(),
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

QString ReceivePage::addressFromObject(const QJsonObject& obj, const QString& baseKey) const {
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

void ReceivePage::refresh() {
    if (!rpc_) {
        setStatus(QStringLiteral("RPC client not configured."), true);
        return;
    }

    rpc_->call(QStringLiteral("getwalletinfo"), {}, this,
        [this](const QJsonValue& result) {
            const auto obj = result.toObject();
            const auto format = obj.value(QStringLiteral("address_format")).toString();
            currentWalletFormat_ = format.isEmpty() ? QStringLiteral("base64") : format;
            walletTypeValue_->setText(currentWalletFormat_);
            displayFormatValue_->setText(preferredAddressFormat_.isEmpty() ? currentWalletFormat_ : preferredAddressFormat_);
            addressCountValue_->setText(QString::number(obj.value(QStringLiteral("addresscount")).toInteger()));
            primaryAddressView_->setPlainText(addressFromObject(obj, QStringLiteral("primaryaddress")));
            newAddressButton_->setEnabled(true);
            unusedAddressButton_->setEnabled(true);
            copyAddressButton_->setEnabled(!primaryAddressView_->toPlainText().trimmed().isEmpty());
            setStatus(QStringLiteral("Wallet ready for receiving."));
        },
        [this](const QString& error) {
            walletTypeValue_->setText(QStringLiteral("-"));
            displayFormatValue_->setText(QStringLiteral("-"));
            addressCountValue_->setText(QStringLiteral("-"));
            primaryAddressView_->clear();
            newAddressButton_->setEnabled(false);
            unusedAddressButton_->setEnabled(false);
            copyAddressButton_->setEnabled(false);
            if (error.contains(QStringLiteral("no wallet is open"), Qt::CaseInsensitive)) {
                setStatus(QStringLiteral("Open a wallet from Wallet Manager to receive funds."), true);
            } else {
                setStatus(error, true);
            }
        });

    rpc_->call(QStringLiteral("getwalletaddressbook"), {}, this,
        [this](const QJsonValue& result) {
            const auto rows = result.toArray();
            addressTable_->setRowCount(rows.size());
            for (int i = 0; i < rows.size(); ++i) {
                const auto obj = rows.at(i).toObject();
                addressTable_->setItem(i, 0, new QTableWidgetItem(obj.value(QStringLiteral("label")).toString()));
                auto* addressItem = new QTableWidgetItem(addressFromObject(obj, QStringLiteral("address")));
                addressItem->setData(Qt::UserRole, obj.value(QStringLiteral("address_base64")).toString());
                addressTable_->setItem(i, 1, addressItem);
                addressTable_->setItem(i, 2, new QTableWidgetItem(obj.value(QStringLiteral("primary")).toBool() ? QStringLiteral("Yes") : QStringLiteral("No")));
                addressTable_->setItem(i, 3, new QTableWidgetItem(QString::number(obj.value(QStringLiteral("hd_index")).toInteger())));
            }
        },
        [this](const QString& error) {
            addressTable_->setRowCount(0);
            if (!error.contains(QStringLiteral("no wallet is open"), Qt::CaseInsensitive)) {
                setStatus(error, true);
            }
        });
}

void ReceivePage::requestNewAddress() {
    if (!rpc_) return;
    const auto format = selectAddressFormat(QStringLiteral("Create Receive Address"));
    if (format.isEmpty()) return;
    rpc_->call(QStringLiteral("getnewaddress"), QJsonArray{format}, this,
        [this](const QJsonValue& result) {
            primaryAddressView_->setPlainText(result.toString());
            copyAddressButton_->setEnabled(true);
            setStatus(QStringLiteral("Generated a fresh receive address."));
            refresh();
        },
        [this](const QString& error) {
            setStatus(error, true);
        });
}

void ReceivePage::requestUnusedAddress() {
    if (!rpc_) return;
    const auto format = selectAddressFormat(QStringLiteral("Fetch Unused Address"));
    if (format.isEmpty()) return;
    rpc_->call(QStringLiteral("getunusedaddress"), QJsonArray{format}, this,
        [this](const QJsonValue& result) {
            primaryAddressView_->setPlainText(result.toString());
            copyAddressButton_->setEnabled(true);
            setStatus(QStringLiteral("Fetched an unused receive address."));
            refresh();
        },
        [this](const QString& error) {
            setStatus(error, true);
        });
}

void ReceivePage::copyPrimaryAddress() {
    const auto address = primaryAddressView_->toPlainText().trimmed();
    if (address.isEmpty()) {
        setStatus(QStringLiteral("No address to copy."), true);
        return;
    }
    if (auto* clipboard = QApplication::clipboard()) {
        clipboard->setText(address);
        setStatus(QStringLiteral("Address copied to clipboard."));
    }
}
