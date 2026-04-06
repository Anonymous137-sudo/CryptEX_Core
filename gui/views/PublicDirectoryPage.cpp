#include "PublicDirectoryPage.hpp"
#include "ChatTheme.hpp"
#include "rpc/RpcClient.hpp"

#include <QDateTime>
#include <QHeaderView>
#include <QJsonArray>
#include <QJsonObject>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QVBoxLayout>
#include <QHBoxLayout>

PublicDirectoryPage::PublicDirectoryPage(QWidget* parent)
    : QWidget(parent) {
    auto* root = new QVBoxLayout(this);
    root->setContentsMargins(12, 12, 12, 12);
    root->setSpacing(12);

    auto* title = new QLabel(QStringLiteral("Public Blockchain Address Manager"), this);
    title->setObjectName(QStringLiteral("pageTitle"));
    root->addWidget(title);

    statusValue_ = new QLabel(QStringLiteral("This directory is built from observed chain addresses with live presence layered on top when known."), this);
    statusValue_->setWordWrap(true);
    root->addWidget(statusValue_);

    auto* toolbar = new QWidget(this);
    auto* toolbarLayout = new QHBoxLayout(toolbar);
    toolbarLayout->setContentsMargins(0, 0, 0, 0);
    filterEdit_ = new QLineEdit(this);
    filterEdit_->setPlaceholderText(QStringLiteral("Filter by address, IP, peer, or pubkey"));
    messageButton_ = new QPushButton(QStringLiteral("Message"), this);
    callButton_ = new QPushButton(QStringLiteral("Call"), this);
    saveContactButton_ = new QPushButton(QStringLiteral("Save Contact"), this);
    refreshButton_ = new QPushButton(QStringLiteral("Refresh Directory"), this);
    toolbarLayout->addWidget(filterEdit_, 1);
    toolbarLayout->addWidget(messageButton_);
    toolbarLayout->addWidget(callButton_);
    toolbarLayout->addWidget(saveContactButton_);
    toolbarLayout->addWidget(refreshButton_);
    root->addWidget(toolbar);

    table_ = new QTableWidget(this);
    table_->setColumnCount(7);
    table_->setHorizontalHeaderLabels({QStringLiteral("Address"),
                                       QStringLiteral("Balance"),
                                       QStringLiteral("TX Count"),
                                       QStringLiteral("Last Activity"),
                                       QStringLiteral("Presence"),
                                       QStringLiteral("IP / Peer"),
                                       QStringLiteral("Public Key")});
    table_->horizontalHeader()->setSectionResizeMode(0, QHeaderView::Stretch);
    table_->horizontalHeader()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
    table_->horizontalHeader()->setSectionResizeMode(2, QHeaderView::ResizeToContents);
    table_->horizontalHeader()->setSectionResizeMode(3, QHeaderView::ResizeToContents);
    table_->horizontalHeader()->setSectionResizeMode(4, QHeaderView::ResizeToContents);
    table_->horizontalHeader()->setSectionResizeMode(5, QHeaderView::Stretch);
    table_->horizontalHeader()->setSectionResizeMode(6, QHeaderView::Stretch);
    table_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    table_->setSelectionBehavior(QAbstractItemView::SelectRows);
    root->addWidget(table_, 1);

    connect(refreshButton_, &QPushButton::clicked, this, [this]() { refresh(); });
    connect(filterEdit_, &QLineEdit::textChanged, this, [this]() { applyFilter(); });
    connect(table_, &QTableWidget::itemSelectionChanged, this, [this]() { updateActionState(); });
    connect(table_, &QTableWidget::cellDoubleClicked, this, [this](int, int) { messageSelectedAddress(); });
    connect(messageButton_, &QPushButton::clicked, this, [this]() { messageSelectedAddress(); });
    connect(callButton_, &QPushButton::clicked, this, [this]() { callSelectedAddress(); });
    connect(saveContactButton_, &QPushButton::clicked, this, [this]() { saveSelectedAddress(); });
    updateActionState();
}

void PublicDirectoryPage::setRpcClient(RpcClient* client) {
    rpc_ = client;
}

QString PublicDirectoryPage::formatCoins(qint64 sats) {
    const qint64 whole = sats / 100000000LL;
    const qint64 frac = qAbs(sats % 100000000LL);
    return QStringLiteral("%1.%2").arg(whole).arg(frac, 8, 10, QLatin1Char('0'));
}

QString PublicDirectoryPage::formatTimestamp(qint64 unixTs) {
    if (unixTs <= 0) return QStringLiteral("-");
    const auto dt = QDateTime::fromSecsSinceEpoch(unixTs);
    return dt.isValid() ? dt.toString(QStringLiteral("yyyy-MM-dd HH:mm:ss")) : QString::number(unixTs);
}

void PublicDirectoryPage::setStatus(const QString& text, bool error) {
    statusValue_->setText(text);
    statusValue_->setStyleSheet(error ? chatui::errorColorStyle() : QString());
}

void PublicDirectoryPage::refreshStatusSummary(int rowCount) {
    const auto walletNote = walletLoaded_
        ? QStringLiteral("Wallet pubkeys are available for local addresses.")
        : QStringLiteral("Open a wallet to expose owned pubkeys here.");
    setStatus(QStringLiteral("Loaded %1 observed chain address(es). Presence and IP only appear when this node has actually observed that address live. %2")
        .arg(rowCount)
        .arg(walletNote));
}

void PublicDirectoryPage::refresh() {
    if (!rpc_) {
        setStatus(QStringLiteral("RPC client not configured."), true);
        return;
    }

    auto loadDirectory = [this]() {
        rpc_->call(QStringLiteral("getpublicaddressdirectory"), QJsonArray{5000}, this,
            [this](const QJsonValue& result) {
            const auto rows = result.toArray();
            entries_.clear();
            entries_.reserve(rows.size());
            table_->setRowCount(rows.size());
            for (int i = 0; i < rows.size(); ++i) {
                const auto obj = rows.at(i).toObject();
                entries_.push_back(obj);
                table_->setItem(i, 0, new QTableWidgetItem(obj.value(QStringLiteral("address")).toString()));
                table_->setItem(i, 1, new QTableWidgetItem(formatCoins(obj.value(QStringLiteral("balance_sats")).toInteger())));
                table_->setItem(i, 2, new QTableWidgetItem(QString::number(obj.value(QStringLiteral("tx_count")).toInteger())));
                table_->setItem(i, 3, new QTableWidgetItem(formatTimestamp(obj.value(QStringLiteral("last_timestamp")).toInteger())));
                const auto peer = obj.value(QStringLiteral("peer")).toString();
                const auto isSelf = (peer == QStringLiteral("self"));
                const auto presence = isSelf
                    ? QStringLiteral("Self")
                    : (obj.value(QStringLiteral("online")).toBool() ? QStringLiteral("Online") : QStringLiteral("Offline"));
                table_->setItem(i, 4, new QTableWidgetItem(presence));
                const auto ip = obj.value(QStringLiteral("ip")).toString();
                table_->setItem(i, 5, new QTableWidgetItem(ip.isEmpty() ? peer : ip));
                table_->setItem(i, 6, new QTableWidgetItem(obj.value(QStringLiteral("pubkey_b64")).toString()));
            }
            refreshStatusSummary(rows.size());
            applyFilter();
            updateActionState();
            },
            [this](const QString& error) { setStatus(error, true); });
    };

    rpc_->call(QStringLiteral("getwalletsessioninfo"), {}, this,
        [this, loadDirectory](const QJsonValue& result) {
            walletLoaded_ = result.toObject().value(QStringLiteral("wallet_loaded")).toBool(false);
            loadDirectory();
        },
        [this, loadDirectory](const QString&) {
            walletLoaded_ = false;
            loadDirectory();
        });
}

void PublicDirectoryPage::applyFilter() {
    const auto needle = filterEdit_->text().trimmed();
    for (int row = 0; row < table_->rowCount(); ++row) {
        bool visible = needle.isEmpty();
        if (!visible) {
            for (int column = 0; column < table_->columnCount(); ++column) {
                const auto* item = table_->item(row, column);
                if (item && item->text().contains(needle, Qt::CaseInsensitive)) {
                    visible = true;
                    break;
                }
            }
        }
        table_->setRowHidden(row, !visible);
    }
    updateActionState();
}

QJsonObject PublicDirectoryPage::selectedEntry() const {
    const auto items = table_->selectedItems();
    if (items.isEmpty()) {
        return {};
    }
    const int row = items.first()->row();
    if (row < 0 || row >= entries_.size()) {
        return {};
    }
    return entries_.at(row);
}

void PublicDirectoryPage::updateActionState() {
    const auto entry = selectedEntry();
    const bool hasSelection = !entry.isEmpty();
    if (messageButton_) messageButton_->setEnabled(hasSelection);
    if (callButton_) callButton_->setEnabled(hasSelection);
    if (saveContactButton_) saveContactButton_->setEnabled(hasSelection);
}

void PublicDirectoryPage::messageSelectedAddress() {
    const auto entry = selectedEntry();
    if (entry.isEmpty()) {
        setStatus(QStringLiteral("Select an address from the public directory first."), true);
        return;
    }
    emit messageRequested(entry.value(QStringLiteral("address")).toString().trimmed(),
                          entry.value(QStringLiteral("pubkey_b64")).toString().trimmed(),
                          entry.value(QStringLiteral("peer")).toString().trimmed());
    setStatus(QStringLiteral("Loaded the selected address into the private composer."));
}

void PublicDirectoryPage::callSelectedAddress() {
    const auto entry = selectedEntry();
    if (entry.isEmpty()) {
        setStatus(QStringLiteral("Select an address from the public directory first."), true);
        return;
    }
    emit callRequested(entry.value(QStringLiteral("address")).toString().trimmed(),
                       entry.value(QStringLiteral("pubkey_b64")).toString().trimmed(),
                       entry.value(QStringLiteral("peer")).toString().trimmed());
    setStatus(QStringLiteral("Loaded the selected address into the voice-call page."));
}

void PublicDirectoryPage::saveSelectedAddress() {
    if (!rpc_) {
        setStatus(QStringLiteral("RPC client not configured."), true);
        return;
    }
    const auto entry = selectedEntry();
    if (entry.isEmpty()) {
        setStatus(QStringLiteral("Select an address from the public directory first."), true);
        return;
    }
    QJsonObject contact;
    contact.insert(QStringLiteral("address"), entry.value(QStringLiteral("address")).toString().trimmed());
    contact.insert(QStringLiteral("pubkey_b64"), entry.value(QStringLiteral("pubkey_b64")).toString().trimmed());
    contact.insert(QStringLiteral("peer"), entry.value(QStringLiteral("peer")).toString().trimmed());
    contact.insert(QStringLiteral("label"), entry.value(QStringLiteral("peer")).toString().trimmed() == QStringLiteral("self")
                                             ? QStringLiteral("Self")
                                             : QStringLiteral("Directory Contact"));
    contact.insert(QStringLiteral("notes"), QStringLiteral("Saved from the public blockchain address manager"));
    rpc_->call(QStringLiteral("upsertchatprivatecontact"), QJsonArray{contact}, this,
               [this](const QJsonValue&) {
                   setStatus(QStringLiteral("Saved the selected address into Private Manager."));
               },
               [this](const QString& error) { setStatus(error, true); });
}
