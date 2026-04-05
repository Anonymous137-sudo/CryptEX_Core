#include "TransactionsPage.hpp"
#include "rpc/RpcClient.hpp"

#include <QCheckBox>
#include <QDateTime>
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
#include <cmath>

TransactionsPage::TransactionsPage(QWidget* parent) : QWidget(parent) {
    auto* root = new QVBoxLayout(this);
    root->setContentsMargins(12, 12, 12, 12);
    root->setSpacing(12);

    auto* title = new QLabel(QStringLiteral("Transactions"), this);
    title->setObjectName(QStringLiteral("pageTitle"));
    root->addWidget(title);

    auto* controls = new QWidget(this);
    auto* controlsLayout = new QHBoxLayout(controls);
    controlsLayout->setContentsMargins(0, 0, 0, 0);
    statusValue_ = new QLabel(QStringLiteral("-"), this);
    statusValue_->setWordWrap(true);
    includeMempoolCheck_ = new QCheckBox(QStringLiteral("Include mempool"), this);
    refreshButton_ = new QPushButton(QStringLiteral("Refresh"), this);
    controlsLayout->addWidget(statusValue_, 1);
    controlsLayout->addWidget(includeMempoolCheck_);
    controlsLayout->addWidget(refreshButton_);
    root->addWidget(controls);

    historyTable_ = new QTableWidget(this);
    historyTable_->setColumnCount(6);
    historyTable_->setHorizontalHeaderLabels({QStringLiteral("Time"), QStringLiteral("Type"), QStringLiteral("Net"), QStringLiteral("Confs"), QStringLiteral("Counterparty"), QStringLiteral("TXID")});
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
    root->addWidget(historyTable_, 1);

    detailView_ = new QPlainTextEdit(this);
    detailView_->setReadOnly(true);
    detailView_->setPlaceholderText(QStringLiteral("Select a transaction to inspect its details."));
    root->addWidget(detailView_, 1);

    connect(refreshButton_, &QPushButton::clicked, this, [this]() { refresh(); });
    connect(includeMempoolCheck_, &QCheckBox::toggled, this, [this]() { refresh(); });
    connect(historyTable_, &QTableWidget::itemSelectionChanged, this, [this]() {
        const auto items = historyTable_->selectedItems();
        if (items.isEmpty()) return;
        const auto* txidItem = historyTable_->item(items.first()->row(), 5);
        if (txidItem) requestTransactionDetail(txidItem->text());
    });
}

void TransactionsPage::setRpcClient(RpcClient* client) {
    rpc_ = client;
}

QString TransactionsPage::formatCoins(qint64 sats) {
    const qint64 whole = sats / 100000000LL;
    const qint64 frac = qAbs(sats % 100000000LL);
    return QStringLiteral("%1.%2 CryptEX").arg(whole).arg(frac, 8, 10, QLatin1Char('0'));
}

QString TransactionsPage::formatTimestamp(qint64 timestamp) {
    if (timestamp <= 0) return QStringLiteral("-");
    return QDateTime::fromSecsSinceEpoch(timestamp).toString(QStringLiteral("yyyy-MM-dd hh:mm:ss"));
}

void TransactionsPage::setStatus(const QString& text, bool error) {
    statusValue_->setText(text);
    statusValue_->setStyleSheet(error ? QStringLiteral("color:#d36b6b;") : QString());
}

void TransactionsPage::refresh() {
    if (!rpc_) {
        setStatus(QStringLiteral("RPC client not configured."), true);
        return;
    }

    QJsonArray params;
    params.append(includeMempoolCheck_->isChecked());
    rpc_->call(QStringLiteral("getwallettransactions"), params, this,
        [this](const QJsonValue& result) {
            const auto rows = result.toArray();
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
            if (rows.isEmpty()) {
                detailTxid_.clear();
                detailView_->clear();
                setStatus(QStringLiteral("No transactions yet."));
            } else {
                if (historyTable_->currentRow() < 0) {
                    historyTable_->selectRow(0);
                }
                setStatus(QStringLiteral("Loaded %1 transactions.").arg(rows.size()));
            }
        },
        [this](const QString& error) {
            historyTable_->setRowCount(0);
            detailView_->clear();
            if (error.contains(QStringLiteral("no wallet is open"), Qt::CaseInsensitive)) {
                setStatus(QStringLiteral("Open a wallet from Wallet Manager to inspect transactions."), true);
            } else {
                setStatus(error, true);
            }
        });
}

void TransactionsPage::requestTransactionDetail(const QString& txid) {
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
            lines << QStringLiteral("Counterparty: %1").arg(obj.value(QStringLiteral("summary_address")).toString());
            lines << QStringLiteral("Net: %1").arg(formatCoins(obj.value(QStringLiteral("net_sats")).toInteger()));
            lines << QStringLiteral("Received: %1").arg(formatCoins(obj.value(QStringLiteral("received_sats")).toInteger()));
            lines << QStringLiteral("Sent: %1").arg(formatCoins(obj.value(QStringLiteral("sent_sats")).toInteger()));
            lines << QStringLiteral("Fee: %1").arg(formatCoins(obj.value(QStringLiteral("fee_sats")).toInteger()));
            lines << QStringLiteral("Timestamp: %1").arg(formatTimestamp(obj.value(QStringLiteral("timestamp")).toInteger()));
            lines << QStringLiteral("Confirmations: %1").arg(obj.value(QStringLiteral("confirmations")).toInteger());
            lines << QStringLiteral("Coinbase: %1").arg(obj.value(QStringLiteral("coinbase")).toBool() ? QStringLiteral("Yes") : QStringLiteral("No"));
            detailView_->setPlainText(lines.join(QLatin1Char('\n')));
        },
        [this, requestedTxid = detailTxid_](const QString& error) {
            if (requestedTxid != detailTxid_) return;
            detailView_->setPlainText(error);
        });
}
