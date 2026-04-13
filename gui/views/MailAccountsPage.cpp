#include "MailAccountsPage.hpp"

#include "rpc/RpcClient.hpp"

#include <QGuiApplication>
#include <QClipboard>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QJsonArray>
#include <QJsonObject>
#include <QLabel>
#include <QPushButton>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QVBoxLayout>
#include <QAbstractItemView>

MailAccountsPage::MailAccountsPage(QWidget* parent)
    : QWidget(parent) {
    auto* root = new QVBoxLayout(this);
    root->setContentsMargins(14, 14, 14, 14);
    root->setSpacing(10);

    auto* title = new QLabel(QStringLiteral("Mail Identities"), this);
    title->setObjectName(QStringLiteral("pageTitle"));
    root->addWidget(title);

    auto* actions = new QHBoxLayout();
    refreshButton_ = new QPushButton(QStringLiteral("Refresh"), this);
    copyButton_ = new QPushButton(QStringLiteral("Copy Alias"), this);
    actions->addWidget(refreshButton_);
    actions->addWidget(copyButton_);
    actions->addStretch(1);
    root->addLayout(actions);

    table_ = new QTableWidget(this);
    table_->setColumnCount(5);
    table_->setHorizontalHeaderLabels({QStringLiteral("Mail Address"), QStringLiteral("Wallet Address"), QStringLiteral("Label"), QStringLiteral("Primary"), QStringLiteral("PubKey")});
    table_->horizontalHeader()->setSectionResizeMode(0, QHeaderView::Stretch);
    table_->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Stretch);
    table_->horizontalHeader()->setSectionResizeMode(2, QHeaderView::ResizeToContents);
    table_->horizontalHeader()->setSectionResizeMode(3, QHeaderView::ResizeToContents);
    table_->horizontalHeader()->setSectionResizeMode(4, QHeaderView::ResizeToContents);
    table_->setSelectionBehavior(QAbstractItemView::SelectRows);
    table_->setSelectionMode(QAbstractItemView::SingleSelection);
    table_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    root->addWidget(table_, 1);

    statusValue_ = new QLabel(QStringLiteral("Ready."), this);
    statusValue_->setWordWrap(true);
    root->addWidget(statusValue_);

    connect(refreshButton_, &QPushButton::clicked, this, [this]() { refresh(); });
    connect(copyButton_, &QPushButton::clicked, this, [this]() { copySelectedAlias(); });
}

void MailAccountsPage::setRpcClient(RpcClient* client) {
    rpc_ = client;
}

void MailAccountsPage::setStatus(const QString& text, bool error) {
    statusValue_->setText(text);
    statusValue_->setStyleSheet(error ? QStringLiteral("color:#ff88a3;") : QString());
}

void MailAccountsPage::refresh() {
    if (!rpc_) return;
    rpc_->call(QStringLiteral("getp2pmailaccounts"), QJsonArray{}, this,
        [this](const QJsonValue& result) {
            entries_.clear();
            table_->setRowCount(0);
            const auto array = result.toArray();
            table_->setRowCount(array.size());
            for (int row = 0; row < array.size(); ++row) {
                const auto obj = array.at(row).toObject();
                entries_.push_back(obj);
                auto* aliasItem = new QTableWidgetItem(obj.value(QStringLiteral("mail_address")).toString());
                aliasItem->setData(Qt::UserRole, obj.value(QStringLiteral("mail_address")).toString());
                table_->setItem(row, 0, aliasItem);
                table_->setItem(row, 1, new QTableWidgetItem(obj.value(QStringLiteral("address")).toString()));
                table_->setItem(row, 2, new QTableWidgetItem(obj.value(QStringLiteral("label")).toString()));
                table_->setItem(row, 3, new QTableWidgetItem(obj.value(QStringLiteral("primary")).toBool(false) ? QStringLiteral("Yes") : QStringLiteral("No")));
                table_->setItem(row, 4, new QTableWidgetItem(obj.value(QStringLiteral("pubkey_b64")).toString().isEmpty() ? QStringLiteral("No") : QStringLiteral("Yes")));
            }
            setStatus(QStringLiteral("Loaded %1 mail identities.").arg(array.size()), false);
            if (table_->rowCount() > 0) table_->selectRow(0);
        },
        [this](const QString& error) {
            setStatus(QStringLiteral("Unable to load mail identities: %1").arg(error), true);
        });
}

void MailAccountsPage::copySelectedAlias() {
    const auto items = table_->selectedItems();
    if (items.isEmpty()) {
        setStatus(QStringLiteral("Select a mail identity first."), true);
        return;
    }
    const int row = items.first()->row();
    const auto* aliasItem = table_->item(row, 0);
    if (!aliasItem) return;
    QGuiApplication::clipboard()->setText(aliasItem->text());
    setStatus(QStringLiteral("Copied %1").arg(aliasItem->text()), false);
}
