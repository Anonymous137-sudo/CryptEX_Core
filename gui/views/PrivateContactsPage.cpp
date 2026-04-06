#include "PrivateContactsPage.hpp"
#include "ChatTheme.hpp"
#include "rpc/RpcClient.hpp"

#include <QFormLayout>
#include <QHeaderView>
#include <QJsonArray>
#include <QJsonObject>
#include <QLabel>
#include <QLineEdit>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QSplitter>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QVBoxLayout>
#include <QHBoxLayout>

PrivateContactsPage::PrivateContactsPage(QWidget* parent)
    : QWidget(parent) {
    auto* root = new QVBoxLayout(this);
    root->setContentsMargins(12, 12, 12, 12);
    root->setSpacing(12);

    auto* title = new QLabel(QStringLiteral("Private Contact Manager"), this);
    title->setObjectName(QStringLiteral("pageTitle"));
    root->addWidget(title);

    statusValue_ = new QLabel(QStringLiteral("Private contacts are stored locally for direct encrypted chat."), this);
    statusValue_->setWordWrap(true);
    root->addWidget(statusValue_);

    auto* splitter = new QSplitter(Qt::Vertical, this);
    splitter->setChildrenCollapsible(false);
    root->addWidget(splitter, 1);

    table_ = new QTableWidget(this);
    table_->setColumnCount(6);
    table_->setHorizontalHeaderLabels({QStringLiteral("Label"),
                                       QStringLiteral("Address"),
                                       QStringLiteral("Pubkey"),
                                       QStringLiteral("RSA"),
                                       QStringLiteral("Peer"),
                                       QStringLiteral("Last Used")});
    table_->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    table_->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Stretch);
    table_->horizontalHeader()->setSectionResizeMode(2, QHeaderView::Stretch);
    table_->horizontalHeader()->setSectionResizeMode(3, QHeaderView::ResizeToContents);
    table_->horizontalHeader()->setSectionResizeMode(4, QHeaderView::ResizeToContents);
    table_->horizontalHeader()->setSectionResizeMode(5, QHeaderView::ResizeToContents);
    table_->setSelectionBehavior(QAbstractItemView::SelectRows);
    table_->setSelectionMode(QAbstractItemView::SingleSelection);
    table_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    splitter->addWidget(table_);

    auto* editorPane = new QWidget(this);
    auto* editorRoot = new QVBoxLayout(editorPane);
    editorRoot->setContentsMargins(0, 0, 0, 0);
    editorRoot->setSpacing(10);
    auto* editor = new QFormLayout();
    labelEdit_ = new QLineEdit(editorPane);
    addressEdit_ = new QLineEdit(editorPane);
    pubkeyEdit_ = new QLineEdit(editorPane);
    rsaPubkeyEdit_ = new QPlainTextEdit(editorPane);
    rsaPubkeyEdit_->setPlaceholderText(QStringLiteral("Optional RSA public key PEM for RSA-encrypted private chat"));
    rsaPubkeyEdit_->setMaximumHeight(88);
    peerEdit_ = new QLineEdit(editorPane);
    notesEdit_ = new QPlainTextEdit(editorPane);
    notesEdit_->setPlaceholderText(QStringLiteral("Optional notes for this private contact"));
    editor->addRow(QStringLiteral("Label"), labelEdit_);
    editor->addRow(QStringLiteral("Address"), addressEdit_);
    editor->addRow(QStringLiteral("Recipient Pubkey"), pubkeyEdit_);
    editor->addRow(QStringLiteral("Recipient RSA"), rsaPubkeyEdit_);
    editor->addRow(QStringLiteral("Direct Peer"), peerEdit_);
    editor->addRow(QStringLiteral("Notes"), notesEdit_);
    editorRoot->addLayout(editor);

    auto* buttonRow = new QWidget(editorPane);
    auto* buttonLayout = new QHBoxLayout(buttonRow);
    buttonLayout->setContentsMargins(0, 0, 0, 0);
    saveButton_ = new QPushButton(QStringLiteral("Save Contact"), this);
    removeButton_ = new QPushButton(QStringLiteral("Remove"), this);
    useButton_ = new QPushButton(QStringLiteral("Use In Private Chat"), this);
    voiceButton_ = new QPushButton(QStringLiteral("Use In Voice Call"), this);
    buttonLayout->addWidget(saveButton_);
    buttonLayout->addWidget(removeButton_);
    buttonLayout->addStretch(1);
    buttonLayout->addWidget(useButton_);
    buttonLayout->addWidget(voiceButton_);
    editorRoot->addWidget(buttonRow);
    splitter->addWidget(editorPane);
    splitter->setStretchFactor(0, 3);
    splitter->setStretchFactor(1, 2);

    connect(table_, &QTableWidget::itemSelectionChanged, this, [this]() { syncEditorFromSelection(); });
    connect(saveButton_, &QPushButton::clicked, this, [this]() { saveContact(); });
    connect(removeButton_, &QPushButton::clicked, this, [this]() { removeSelectedContact(); });
    connect(useButton_, &QPushButton::clicked, this, [this]() { useSelectedContact(); });
    connect(voiceButton_, &QPushButton::clicked, this, [this]() { useSelectedContactForVoice(); });
}

void PrivateContactsPage::setRpcClient(RpcClient* client) {
    rpc_ = client;
}

void PrivateContactsPage::setStatus(const QString& text, bool error) {
    statusValue_->setText(text);
    statusValue_->setStyleSheet(error ? chatui::errorColorStyle() : QString());
}

void PrivateContactsPage::refresh() {
    if (!rpc_) {
        setStatus(QStringLiteral("RPC client not configured."), true);
        return;
    }

    rpc_->call(QStringLiteral("getchatprivatecontacts"), {}, this,
        [this](const QJsonValue& result) {
            const auto rows = result.toArray();
            table_->setRowCount(rows.size());
            for (int i = 0; i < rows.size(); ++i) {
                const auto obj = rows.at(i).toObject();
                auto* labelItem = new QTableWidgetItem(obj.value(QStringLiteral("label")).toString());
                auto* addressItem = new QTableWidgetItem(obj.value(QStringLiteral("address")).toString());
                addressItem->setData(Qt::UserRole, obj.value(QStringLiteral("address_base64")).toString());
                auto* pubkeyItem = new QTableWidgetItem(obj.value(QStringLiteral("pubkey_b64")).toString());
                pubkeyItem->setData(Qt::UserRole, obj.value(QStringLiteral("rsa_pubkey_pem")).toString());
                auto* rsaItem = new QTableWidgetItem(obj.value(QStringLiteral("rsa_pubkey_pem")).toString().trimmed().isEmpty()
                                                         ? QStringLiteral("-")
                                                         : QStringLiteral("configured"));
                auto* peerItem = new QTableWidgetItem(obj.value(QStringLiteral("peer")).toString());
                auto* lastUsedItem = new QTableWidgetItem(QString::number(obj.value(QStringLiteral("last_used_at")).toInteger()));
                lastUsedItem->setData(Qt::UserRole, obj.value(QStringLiteral("notes")).toString());
                table_->setItem(i, 0, labelItem);
                table_->setItem(i, 1, addressItem);
                table_->setItem(i, 2, pubkeyItem);
                table_->setItem(i, 3, rsaItem);
                table_->setItem(i, 4, peerItem);
                table_->setItem(i, 5, lastUsedItem);
            }
            setStatus(QStringLiteral("Loaded %1 private contact(s).").arg(rows.size()));
            if (rows.size() > 0 && table_->currentRow() < 0) {
                table_->selectRow(0);
            }
        },
        [this](const QString& error) { setStatus(error, true); });
}

void PrivateContactsPage::syncEditorFromSelection() {
    const auto items = table_->selectedItems();
    if (items.isEmpty()) {
        return;
    }
    const int row = items.first()->row();
    labelEdit_->setText(table_->item(row, 0) ? table_->item(row, 0)->text() : QString());
    addressEdit_->setText(table_->item(row, 1) ? table_->item(row, 1)->text() : QString());
    pubkeyEdit_->setText(table_->item(row, 2) ? table_->item(row, 2)->text() : QString());
    rsaPubkeyEdit_->setPlainText(table_->item(row, 2) ? table_->item(row, 2)->data(Qt::UserRole).toString() : QString());
    peerEdit_->setText(table_->item(row, 4) ? table_->item(row, 4)->text() : QString());
    notesEdit_->setPlainText(table_->item(row, 5) ? table_->item(row, 5)->data(Qt::UserRole).toString() : QString());
}

void PrivateContactsPage::saveContact() {
    if (!rpc_) return;
    if (addressEdit_->text().trimmed().isEmpty()) {
        setStatus(QStringLiteral("Address is required."), true);
        return;
    }
    if (pubkeyEdit_->text().trimmed().isEmpty() && rsaPubkeyEdit_->toPlainText().trimmed().isEmpty()) {
        setStatus(QStringLiteral("Recipient secp pubkey or RSA public key is required for private chat."), true);
        return;
    }
    QJsonObject object;
    object.insert(QStringLiteral("label"), labelEdit_->text().trimmed());
    object.insert(QStringLiteral("address"), addressEdit_->text().trimmed());
    object.insert(QStringLiteral("pubkey_b64"), pubkeyEdit_->text().trimmed());
    object.insert(QStringLiteral("rsa_pubkey_pem"), rsaPubkeyEdit_->toPlainText().trimmed());
    object.insert(QStringLiteral("peer"), peerEdit_->text().trimmed());
    object.insert(QStringLiteral("notes"), notesEdit_->toPlainText().trimmed());
    rpc_->call(QStringLiteral("upsertchatprivatecontact"), QJsonArray{object}, this,
        [this](const QJsonValue&) {
            setStatus(QStringLiteral("Private contact saved."));
            refresh();
        },
        [this](const QString& error) { setStatus(error, true); });
}

void PrivateContactsPage::removeSelectedContact() {
    if (!rpc_) return;
    const auto address = addressEdit_->text().trimmed();
    if (address.isEmpty()) {
        setStatus(QStringLiteral("Select a contact to remove."), true);
        return;
    }
    rpc_->call(QStringLiteral("removechatprivatecontact"), QJsonArray{address}, this,
        [this](const QJsonValue&) {
            setStatus(QStringLiteral("Private contact removed."));
            refresh();
        },
        [this](const QString& error) { setStatus(error, true); });
}

void PrivateContactsPage::useSelectedContact() {
    const auto address = addressEdit_->text().trimmed();
    const auto pubkey = pubkeyEdit_->text().trimmed();
    const auto rsaPubkey = rsaPubkeyEdit_->toPlainText().trimmed();
    if (address.isEmpty() || (pubkey.isEmpty() && rsaPubkey.isEmpty())) {
        setStatus(QStringLiteral("Select a saved private contact first."), true);
        return;
    }
    emit composePrivateMessage(address,
                               pubkey,
                               peerEdit_->text().trimmed(),
                               rsaPubkey);
    setStatus(QStringLiteral("Private contact loaded into the composer."));
}

void PrivateContactsPage::useSelectedContactForVoice() {
    const auto address = addressEdit_->text().trimmed();
    const auto pubkey = pubkeyEdit_->text().trimmed();
    if (address.isEmpty() || pubkey.isEmpty()) {
        setStatus(QStringLiteral("Voice calls require a saved contact with a secp256k1 pubkey."), true);
        return;
    }
    emit startVoiceCall(address, pubkey, peerEdit_->text().trimmed());
    setStatus(QStringLiteral("Private contact loaded into the voice call page."));
}
