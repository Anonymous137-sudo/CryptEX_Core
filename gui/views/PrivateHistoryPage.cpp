#include "PrivateHistoryPage.hpp"

#include "ChatEntryDialog.hpp"
#include "ChatTheme.hpp"
#include "rpc/RpcClient.hpp"

#include <QDateTime>
#include <QHeaderView>
#include <QJsonArray>
#include <QJsonObject>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QSpinBox>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QVBoxLayout>
#include <functional>

namespace {

void deletePrivateHistoryMessage(RpcClient* rpc,
                                 QWidget* context,
                                 const QString& messageId,
                                 const std::function<void()>& onDone,
                                 const std::function<void(const QString&)>& onError) {
    if (!rpc || messageId.trimmed().isEmpty()) {
        if (onError) onError(QStringLiteral("Message ID is required for deletion."));
        return;
    }
    rpc->call(QStringLiteral("deletechatmessage"), QJsonArray{messageId}, context,
        [onDone](const QJsonValue&) {
            if (onDone) onDone();
        },
        [onError](const QString& error) {
            if (onError) onError(error);
        });
}

}

PrivateHistoryPage::PrivateHistoryPage(QWidget* parent)
    : QWidget(parent) {
    auto* root = new QVBoxLayout(this);
    root->setContentsMargins(12, 12, 12, 12);
    root->setSpacing(12);

    auto* title = new QLabel(QStringLiteral("Private Chat History"), this);
    title->setObjectName(QStringLiteral("pageTitle"));
    root->addWidget(title);

    statusValue_ = new QLabel(QStringLiteral("Read-only private-message history with full detail view."), this);
    statusValue_->setWordWrap(true);
    root->addWidget(statusValue_);

    auto* toolbar = new QWidget(this);
    auto* toolbarLayout = new QHBoxLayout(toolbar);
    toolbarLayout->setContentsMargins(0, 0, 0, 0);
    toolbarLayout->setSpacing(8);
    searchEdit_ = new QLineEdit(this);
    searchEdit_->setPlaceholderText(QStringLiteral("Filter by address, message, peer, or status"));
    limitSpin_ = new QSpinBox(this);
    limitSpin_->setRange(10, 5000);
    limitSpin_->setValue(500);
    refreshButton_ = new QPushButton(QStringLiteral("Refresh History"), this);
    toolbarLayout->addWidget(searchEdit_, 1);
    toolbarLayout->addWidget(limitSpin_);
    toolbarLayout->addWidget(refreshButton_);
    root->addWidget(toolbar);

    table_ = new QTableWidget(this);
    table_->setColumnCount(6);
    table_->setHorizontalHeaderLabels({QStringLiteral("Time"),
                                       QStringLiteral("Direction"),
                                       QStringLiteral("Counterparty"),
                                       QStringLiteral("Message"),
                                       QStringLiteral("Status"),
                                       QStringLiteral("Peer")});
    table_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    table_->setSelectionBehavior(QAbstractItemView::SelectRows);
    table_->verticalHeader()->setVisible(false);
    table_->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    table_->horizontalHeader()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
    table_->horizontalHeader()->setSectionResizeMode(2, QHeaderView::Stretch);
    table_->horizontalHeader()->setSectionResizeMode(3, QHeaderView::Stretch);
    table_->horizontalHeader()->setSectionResizeMode(4, QHeaderView::ResizeToContents);
    table_->horizontalHeader()->setSectionResizeMode(5, QHeaderView::ResizeToContents);
    root->addWidget(table_, 1);

    connect(refreshButton_, &QPushButton::clicked, this, [this]() { refresh(); });
    connect(searchEdit_, &QLineEdit::textChanged, this, [this]() { applyFilter(); });
    connect(table_, &QTableWidget::cellDoubleClicked, this, [this](int row, int) { openEntry(row); });
}

void PrivateHistoryPage::setRpcClient(RpcClient* client) {
    rpc_ = client;
}

QString PrivateHistoryPage::formatTimestamp(qint64 unixTs) {
    if (unixTs <= 0) return QStringLiteral("-");
    const auto dt = QDateTime::fromSecsSinceEpoch(unixTs);
    return dt.isValid() ? dt.toString(QStringLiteral("yyyy-MM-dd HH:mm:ss")) : QString::number(unixTs);
}

void PrivateHistoryPage::setStatus(const QString& text, bool error) {
    statusValue_->setText(text);
    statusValue_->setStyleSheet(error ? chatui::errorColorStyle() : QString());
}

void PrivateHistoryPage::refresh() {
    if (!rpc_) {
        setStatus(QStringLiteral("RPC client not configured."), true);
        return;
    }

    QJsonObject filters;
    filters.insert(QStringLiteral("private_only"), true);
    rpc_->call(QStringLiteral("getchatinbox"), QJsonArray{limitSpin_->value(), filters}, this,
        [this](const QJsonValue& result) {
            const auto rows = result.toArray();
            entries_.clear();
            entries_.reserve(rows.size());
            table_->setRowCount(rows.size());
            for (int i = 0; i < rows.size(); ++i) {
                const auto obj = rows.at(i).toObject();
                entries_.push_back(obj);
                const auto outgoing = obj.value(QStringLiteral("direction")).toString() == QStringLiteral("out");
                const auto counterparty = outgoing
                    ? obj.value(QStringLiteral("recipient")).toString()
                    : obj.value(QStringLiteral("sender")).toString();
                table_->setItem(i, 0, new QTableWidgetItem(formatTimestamp(obj.value(QStringLiteral("timestamp")).toInteger())));
                table_->setItem(i, 1, new QTableWidgetItem(obj.value(QStringLiteral("direction")).toString()));
                table_->setItem(i, 2, new QTableWidgetItem(counterparty));
                table_->setItem(i, 3, new QTableWidgetItem(obj.value(QStringLiteral("message")).toString()));
                table_->setItem(i, 4, new QTableWidgetItem(obj.value(QStringLiteral("status")).toString()));
                table_->setItem(i, 5, new QTableWidgetItem(obj.value(QStringLiteral("peer")).toString()));
            }
            setStatus(QStringLiteral("Loaded %1 private message(s).").arg(rows.size()));
            applyFilter();
        },
        [this](const QString& error) { setStatus(error, true); });
}

void PrivateHistoryPage::openEntry(int row) {
    if (row < 0 || row >= entries_.size()) return;
    ChatEntryDialog dialog(ChatEntryDialog::Mode::PrivateHistory, this);
    dialog.setEntry(entries_.at(row));
    connect(&dialog, &ChatEntryDialog::privateReplyRequested,
            this, &PrivateHistoryPage::replyRequested);
    connect(&dialog, &ChatEntryDialog::deleteRequested,
            this, [this](const QString& messageId) {
                deletePrivateHistoryMessage(rpc_,
                                            this,
                                            messageId,
                                            [this]() {
                                                setStatus(QStringLiteral("Private message deleted from local messenger history."));
                                                refresh();
                                            },
                                            [this](const QString& error) { setStatus(error, true); });
            });
    dialog.exec();
}

void PrivateHistoryPage::applyFilter() {
    const auto needle = searchEdit_->text().trimmed();
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
}
