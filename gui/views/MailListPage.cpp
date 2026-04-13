#include "MailListPage.hpp"

#include "MailEntryDialog.hpp"
#include "rpc/RpcClient.hpp"

#include <QDateTime>
#include <QAbstractItemView>
#include <QFormLayout>
#include <QHeaderView>
#include <QHBoxLayout>
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
#include <QStringList>

namespace {
QString formatTimestamp(qint64 ts) {
    if (ts <= 0) return QStringLiteral("-");
    return QDateTime::fromSecsSinceEpoch(ts).toString(QStringLiteral("yyyy-MM-dd HH:mm:ss"));
}

QString quotedBody(const QString& body) {
    QStringList lines = body.split('\n');
    for (QString& line : lines) {
        line.prepend(QStringLiteral("> "));
    }
    return lines.join('\n');
}
}

MailListPage::MailListPage(Folder folder, QWidget* parent)
    : QWidget(parent), folder_(folder) {
    auto* root = new QVBoxLayout(this);
    root->setContentsMargins(14, 14, 14, 14);
    root->setSpacing(10);

    auto* title = new QLabel(folder_ == Folder::Inbox ? QStringLiteral("Inbox") : QStringLiteral("Sent"), this);
    title->setObjectName(QStringLiteral("pageTitle"));
    root->addWidget(title);

    auto* controls = new QHBoxLayout();
    filterEdit_ = new QLineEdit(this);
    filterEdit_->setPlaceholderText(QStringLiteral("Filter by address, subject, or body"));
    refreshButton_ = new QPushButton(QStringLiteral("Refresh"), this);
    openButton_ = new QPushButton(QStringLiteral("Open"), this);
    deleteButton_ = new QPushButton(QStringLiteral("Delete"), this);
    replyButton_ = new QPushButton(QStringLiteral("Reply"), this);
    controls->addWidget(filterEdit_, 1);
    controls->addWidget(refreshButton_);
    controls->addWidget(openButton_);
    controls->addWidget(deleteButton_);
    controls->addWidget(replyButton_);
    root->addLayout(controls);

    splitter_ = new QSplitter(Qt::Horizontal, this);
    splitter_->setChildrenCollapsible(false);
    splitter_->setHandleWidth(6);

    table_ = new QTableWidget(splitter_);
    table_->setColumnCount(4);
    table_->setHorizontalHeaderLabels({QStringLiteral("Time"), folder_ == Folder::Inbox ? QStringLiteral("From") : QStringLiteral("To"), QStringLiteral("Subject"), QStringLiteral("Status")});
    table_->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    table_->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Stretch);
    table_->horizontalHeader()->setSectionResizeMode(2, QHeaderView::Stretch);
    table_->horizontalHeader()->setSectionResizeMode(3, QHeaderView::ResizeToContents);
    table_->setSelectionBehavior(QAbstractItemView::SelectRows);
    table_->setSelectionMode(QAbstractItemView::SingleSelection);
    table_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    table_->setMinimumWidth(380);

    auto* preview = new QWidget(splitter_);
    auto* previewLayout = new QVBoxLayout(preview);
    previewLayout->setContentsMargins(10, 4, 10, 4);
    previewLayout->setSpacing(10);

    subjectValue_ = new QLabel(QStringLiteral("Select a mail item"), preview);
    subjectValue_->setStyleSheet(QStringLiteral("font-size:18px;font-weight:700;color:#e7ffff;"));
    subjectValue_->setWordWrap(true);
    previewLayout->addWidget(subjectValue_);

    auto* metaForm = new QFormLayout();
    fromValue_ = new QLabel(QStringLiteral("-"), preview);
    toValue_ = new QLabel(QStringLiteral("-"), preview);
    timeValue_ = new QLabel(QStringLiteral("-"), preview);
    metaValue_ = new QLabel(QStringLiteral("-"), preview);
    attachmentValue_ = new QLabel(QStringLiteral("-"), preview);
    fromValue_->setWordWrap(true);
    toValue_->setWordWrap(true);
    metaValue_->setWordWrap(true);
    attachmentValue_->setWordWrap(true);
    metaForm->addRow(QStringLiteral("From"), fromValue_);
    metaForm->addRow(QStringLiteral("To"), toValue_);
    metaForm->addRow(QStringLiteral("Time"), timeValue_);
    metaForm->addRow(QStringLiteral("Meta"), metaValue_);
    metaForm->addRow(QStringLiteral("Attachment"), attachmentValue_);
    previewLayout->addLayout(metaForm);

    bodyView_ = new QPlainTextEdit(preview);
    bodyView_->setReadOnly(true);
    bodyView_->setMinimumHeight(280);
    previewLayout->addWidget(bodyView_, 1);

    splitter_->setStretchFactor(0, 2);
    splitter_->setStretchFactor(1, 3);
    splitter_->setSizes({420, 560});
    root->addWidget(splitter_, 1);

    statusValue_ = new QLabel(QStringLiteral("Ready."), this);
    statusValue_->setWordWrap(true);
    root->addWidget(statusValue_);

    connect(refreshButton_, &QPushButton::clicked, this, [this]() { refresh(); });
    connect(openButton_, &QPushButton::clicked, this, [this]() { openSelected(); });
    connect(deleteButton_, &QPushButton::clicked, this, [this]() { deleteSelected(); });
    connect(replyButton_, &QPushButton::clicked, this, [this]() { replySelected(); });
    connect(filterEdit_, &QLineEdit::textChanged, this, [this]() { applyFilter(); });
    connect(table_, &QTableWidget::itemSelectionChanged, this, [this]() { updatePreview(); });
    connect(table_, &QTableWidget::itemDoubleClicked, this, [this](QTableWidgetItem*) { openSelected(); });

    openButton_->setEnabled(false);
    deleteButton_->setEnabled(false);
    replyButton_->setEnabled(false);
}

void MailListPage::setRpcClient(RpcClient* client) {
    rpc_ = client;
}

QString MailListPage::folderKey() const {
    return folder_ == Folder::Inbox ? QStringLiteral("inbox") : QStringLiteral("sent");
}

QString MailListPage::folderLabel() const {
    return folder_ == Folder::Inbox ? QStringLiteral("Inbox") : QStringLiteral("Sent");
}

void MailListPage::setStatus(const QString& text, bool error) {
    statusValue_->setText(text);
    statusValue_->setStyleSheet(error ? QStringLiteral("color:#ff88a3;") : QString());
}

void MailListPage::refresh() {
    if (!rpc_) return;
    QJsonObject filter;
    filter.insert(QStringLiteral("folder"), folderKey());
    filter.insert(QStringLiteral("limit"), 200);
    rpc_->call(QStringLiteral("getp2pmail"), QJsonArray{filter}, this,
        [this](const QJsonValue& result) {
            entries_.clear();
            const auto array = result.toArray();
            for (const auto& value : array) {
                entries_.push_back(value.toObject());
            }
            applyFilter();
            setStatus(QStringLiteral("Loaded %1 %2 item(s).").arg(array.size()).arg(folderKey()), false);
        },
        [this](const QString& error) {
            setStatus(QStringLiteral("Unable to load %1: %2").arg(folderLabel(), error), true);
        });
}

void MailListPage::applyFilter() {
    const auto filter = filterEdit_->text().trimmed();
    table_->setRowCount(0);
    int rowIndex = 0;
    for (const auto& entry : entries_) {
        const QString haystack = (entry.value(QStringLiteral("sender_mail_address")).toString() + QStringLiteral(" ") +
                                  entry.value(QStringLiteral("recipient_mail_address")).toString() + QStringLiteral(" ") +
                                  entry.value(QStringLiteral("subject")).toString() + QStringLiteral(" ") +
                                  entry.value(QStringLiteral("message")).toString()).toLower();
        if (!filter.isEmpty() && !haystack.contains(filter.toLower())) {
            continue;
        }
        table_->insertRow(rowIndex);
        auto* timeItem = new QTableWidgetItem(formatTimestamp(entry.value(QStringLiteral("timestamp")).toInteger()));
        timeItem->setData(Qt::UserRole, rowIndex);
        table_->setItem(rowIndex, 0, timeItem);
        table_->setItem(rowIndex, 1, new QTableWidgetItem(folder_ == Folder::Inbox
            ? entry.value(QStringLiteral("sender_mail_address")).toString(entry.value(QStringLiteral("sender")).toString())
            : entry.value(QStringLiteral("recipient_mail_address")).toString(entry.value(QStringLiteral("recipient")).toString())));
        table_->setItem(rowIndex, 2, new QTableWidgetItem(entry.value(QStringLiteral("subject")).toString(QStringLiteral("(no subject)"))));
        table_->setItem(rowIndex, 3, new QTableWidgetItem(entry.value(QStringLiteral("status")).toString()));
        ++rowIndex;
    }
    if (table_->rowCount() > 0) table_->selectRow(0);
    else updatePreview();
}

QJsonObject MailListPage::selectedEntry() const {
    const auto items = table_->selectedItems();
    if (items.isEmpty()) return {};
    const int row = items.first()->row();
    return entryForVisibleRow(row);
}

QJsonObject MailListPage::entryForVisibleRow(int row) const {
    if (row < 0 || row >= table_->rowCount()) return {};
    int visibleIndex = row;
    int matched = -1;
    const auto filter = filterEdit_->text().trimmed().toLower();
    for (const auto& entry : entries_) {
        const QString haystack = (entry.value(QStringLiteral("sender_mail_address")).toString() + QStringLiteral(" ") +
                                  entry.value(QStringLiteral("recipient_mail_address")).toString() + QStringLiteral(" ") +
                                  entry.value(QStringLiteral("subject")).toString() + QStringLiteral(" ") +
                                  entry.value(QStringLiteral("message")).toString()).toLower();
        if (!filter.isEmpty() && !haystack.contains(filter)) continue;
        ++matched;
        if (matched == visibleIndex) return entry;
    }
    return {};
}

void MailListPage::updatePreview() {
    const auto entry = selectedEntry();
    if (entry.isEmpty()) {
        subjectValue_->setText(QStringLiteral("Select a mail item"));
        fromValue_->setText(QStringLiteral("-"));
        toValue_->setText(QStringLiteral("-"));
        timeValue_->setText(QStringLiteral("-"));
        metaValue_->setText(QStringLiteral("-"));
        attachmentValue_->setText(QStringLiteral("-"));
        bodyView_->clear();
        openButton_->setEnabled(false);
        deleteButton_->setEnabled(false);
        replyButton_->setEnabled(false);
        return;
    }
    subjectValue_->setText(entry.value(QStringLiteral("subject")).toString(QStringLiteral("(no subject)")));
    fromValue_->setText(entry.value(QStringLiteral("sender_mail_address")).toString(entry.value(QStringLiteral("sender")).toString()));
    toValue_->setText(entry.value(QStringLiteral("recipient_mail_address")).toString(entry.value(QStringLiteral("recipient")).toString()));
    timeValue_->setText(formatTimestamp(entry.value(QStringLiteral("timestamp")).toInteger()));
    metaValue_->setText(QStringLiteral("status=%1 | encryption=%2 | peer=%3")
                        .arg(entry.value(QStringLiteral("status")).toString(),
                             entry.value(QStringLiteral("encryption_mode")).toString(),
                             entry.value(QStringLiteral("peer")).toString(QStringLiteral("network"))));
    attachmentValue_->setText(entry.value(QStringLiteral("attachment_name")).toString().isEmpty()
        ? QStringLiteral("None")
        : QStringLiteral("%1 (%2)").arg(entry.value(QStringLiteral("attachment_name")).toString(),
                                         entry.value(QStringLiteral("attachment_path")).toString()));
    bodyView_->setPlainText(entry.value(QStringLiteral("message")).toString());
    openButton_->setEnabled(true);
    deleteButton_->setEnabled(true);
    replyButton_->setEnabled(true);
}

void MailListPage::openSelected() {
    const auto entry = selectedEntry();
    if (entry.isEmpty()) {
        setStatus(QStringLiteral("Select a mail item first."), true);
        return;
    }
    MailEntryDialog dialog(entry, this);
    dialog.exec();
}

void MailListPage::deleteSelected() {
    const auto entry = selectedEntry();
    if (entry.isEmpty() || !rpc_) {
        setStatus(QStringLiteral("Select a mail item first."), true);
        return;
    }
    rpc_->call(QStringLiteral("deletep2pmail"), QJsonArray{entry.value(QStringLiteral("messageid")).toString()}, this,
        [this](const QJsonValue&) {
            setStatus(QStringLiteral("Mail item deleted locally."), false);
            refresh();
        },
        [this](const QString& error) {
            setStatus(QStringLiteral("Unable to delete mail: %1").arg(error), true);
        });
}

void MailListPage::replySelected() {
    const auto entry = selectedEntry();
    if (entry.isEmpty()) {
        setStatus(QStringLiteral("Select a mail item first."), true);
        return;
    }
    const QString target = folder_ == Folder::Inbox
        ? entry.value(QStringLiteral("sender_mail_address")).toString(entry.value(QStringLiteral("sender")).toString())
        : entry.value(QStringLiteral("recipient_mail_address")).toString(entry.value(QStringLiteral("recipient")).toString());
    QString subject = entry.value(QStringLiteral("subject")).toString();
    if (!subject.startsWith(QStringLiteral("Re:"), Qt::CaseInsensitive)) {
        subject = QStringLiteral("Re: ") + subject;
    }
    const QString body = QStringLiteral("\n\n") + quotedBody(entry.value(QStringLiteral("message")).toString());
    emit replyRequested(target, subject, body);
}
