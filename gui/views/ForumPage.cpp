#include "ForumPage.hpp"
#include "ChatEntryDialog.hpp"
#include "ChatTheme.hpp"
#include "rpc/RpcClient.hpp"

#include <QClipboard>
#include <QDateTime>
#include <QFormLayout>
#include <QFrame>
#include <QGuiApplication>
#include <QHBoxLayout>
#include <QJsonArray>
#include <QJsonObject>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QScrollArea>
#include <QSpinBox>
#include <QToolTip>
#include <QVBoxLayout>
#include <functional>

ForumPage::ForumPage(QWidget* parent)
    : QWidget(parent) {
    auto* root = new QVBoxLayout(this);
    root->setContentsMargins(12, 12, 12, 12);
    root->setSpacing(12);

    auto* title = new QLabel(QStringLiteral("Public Forum"), this);
    title->setObjectName(QStringLiteral("pageTitle"));
    root->addWidget(title);

    statusValue_ = new QLabel(QStringLiteral("Public channels now render as a card feed with thread-style actions and full post drill-down."), this);
    statusValue_->setWordWrap(true);
    root->addWidget(statusValue_);

    auto* controls = new QWidget(this);
    auto* controlsLayout = new QHBoxLayout(controls);
    controlsLayout->setContentsMargins(0, 0, 0, 0);
    controlsLayout->setSpacing(10);

    auto* form = new QFormLayout();
    form->setContentsMargins(0, 0, 0, 0);
    form->setHorizontalSpacing(10);
    form->setVerticalSpacing(6);

    channelEdit_ = new QLineEdit(this);
    channelEdit_->setPlaceholderText(QStringLiteral("Optional channel filter"));
    searchEdit_ = new QLineEdit(this);
    searchEdit_->setPlaceholderText(QStringLiteral("Search sender, channel, peer, status, or message body"));
    limitSpin_ = new QSpinBox(this);
    limitSpin_->setRange(10, 5000);
    limitSpin_->setValue(500);
    refreshButton_ = new QPushButton(QStringLiteral("Refresh Feed"), this);
    refreshButton_->setObjectName(QStringLiteral("forumAccentButton"));

    form->addRow(QStringLiteral("Channel"), channelEdit_);
    form->addRow(QStringLiteral("Cards"), limitSpin_);
    controlsLayout->addLayout(form);
    controlsLayout->addWidget(searchEdit_, 1);
    controlsLayout->addWidget(refreshButton_);
    root->addWidget(controls);

    scrollArea_ = new QScrollArea(this);
    scrollArea_->setWidgetResizable(true);
    scrollArea_->setFrameShape(QFrame::NoFrame);
    cardsHost_ = new QWidget(scrollArea_);
    cardsLayout_ = new QVBoxLayout(cardsHost_);
    cardsLayout_->setContentsMargins(0, 0, 0, 0);
    cardsLayout_->setSpacing(12);
    cardsLayout_->addStretch(1);
    scrollArea_->setWidget(cardsHost_);
    root->addWidget(scrollArea_, 1);

    connect(refreshButton_, &QPushButton::clicked, this, [this]() { refresh(); });
    connect(searchEdit_, &QLineEdit::textChanged, this, [this]() { applyFilter(); });
    connect(channelEdit_, &QLineEdit::returnPressed, this, [this]() { refresh(); });
}

void ForumPage::setRpcClient(RpcClient* client) {
    rpc_ = client;
}

QString ForumPage::formatTimestamp(qint64 unixTs) {
    if (unixTs <= 0) return QStringLiteral("-");
    const auto dt = QDateTime::fromSecsSinceEpoch(unixTs);
    return dt.isValid() ? dt.toString(QStringLiteral("yyyy-MM-dd HH:mm:ss")) : QString::number(unixTs);
}

QString ForumPage::excerptForCard(const QString& message) {
    const auto normalized = message.simplified();
    if (normalized.size() <= 280) {
        return normalized;
    }
    return normalized.left(277) + QStringLiteral("...");
}

QString ForumPage::searchableText(const QJsonObject& entry) {
    return QStringLiteral("%1 %2 %3 %4 %5")
        .arg(entry.value(QStringLiteral("sender")).toString(),
             entry.value(QStringLiteral("channel")).toString(),
             entry.value(QStringLiteral("peer")).toString(),
             entry.value(QStringLiteral("status")).toString(),
             entry.value(QStringLiteral("message")).toString());
}

void ForumPage::setStatus(const QString& text, bool error) {
    statusValue_->setText(text);
    statusValue_->setStyleSheet(error ? chatui::errorColorStyle() : QString());
}

void ForumPage::refresh() {
    if (!rpc_) {
        setStatus(QStringLiteral("RPC client not configured."), true);
        return;
    }

    QJsonObject filters;
    filters.insert(QStringLiteral("private_only"), false);
    if (!channelEdit_->text().trimmed().isEmpty()) {
        filters.insert(QStringLiteral("channel"), channelEdit_->text().trimmed());
    }

    rpc_->call(QStringLiteral("getchatinbox"), QJsonArray{limitSpin_->value(), filters}, this,
        [this](const QJsonValue& result) {
            const auto rows = result.toArray();
            entries_.clear();
            entries_.reserve(rows.size());
            for (const auto& row : rows) {
                entries_.push_back(row.toObject());
            }
            rebuildCards();
            setStatus(QStringLiteral("Loaded %1 public forum card(s).").arg(rows.size()));
            applyFilter();
        },
        [this](const QString& error) { setStatus(error, true); });
}

void deleteForumMessage(RpcClient* rpc,
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

void ForumPage::rebuildCards() {
    while (cardsLayout_->count() > 0) {
        auto* item = cardsLayout_->takeAt(0);
        if (!item) {
            continue;
        }
        if (auto* widget = item->widget()) {
            widget->deleteLater();
        }
        delete item;
    }
    cardWidgets_.clear();

    if (entries_.isEmpty()) {
        auto* emptyLabel = new QLabel(QStringLiteral("No forum posts match the current channel filter yet."), cardsHost_);
        emptyLabel->setWordWrap(true);
        emptyLabel->setObjectName(QStringLiteral("forumMeta"));
        cardsLayout_->addWidget(emptyLabel);
        cardsLayout_->addStretch(1);
        return;
    }

    for (int index = 0; index < entries_.size(); ++index) {
        const auto& entry = entries_.at(index);

        auto* card = new QFrame(cardsHost_);
        card->setObjectName(QStringLiteral("forumCard"));
        auto* layout = new QVBoxLayout(card);
        layout->setContentsMargins(14, 14, 14, 14);
        layout->setSpacing(10);

        auto* topRow = new QHBoxLayout();
        topRow->setSpacing(8);
        auto* channelChip = new QLabel(QStringLiteral("#%1").arg(entry.value(QStringLiteral("channel")).toString(QStringLiteral("general"))), card);
        channelChip->setObjectName(QStringLiteral("forumChannelChip"));
        auto* timeLabel = new QLabel(formatTimestamp(entry.value(QStringLiteral("timestamp")).toInteger()), card);
        timeLabel->setObjectName(QStringLiteral("forumMeta"));
        topRow->addWidget(channelChip, 0, Qt::AlignLeft);
        topRow->addStretch(1);
        topRow->addWidget(timeLabel, 0, Qt::AlignRight);
        layout->addLayout(topRow);

        auto* senderLabel = new QLabel(entry.value(QStringLiteral("sender")).toString(QStringLiteral("Unknown sender")), card);
        senderLabel->setObjectName(QStringLiteral("forumSender"));
        senderLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
        layout->addWidget(senderLabel);

        const auto peer = entry.value(QStringLiteral("peer")).toString();
        const auto status = entry.value(QStringLiteral("status")).toString();
        auto* metaLabel = new QLabel(QStringLiteral("Peer: %1  |  Status: %2")
                                         .arg(peer.isEmpty() ? QStringLiteral("-") : peer,
                                              status.isEmpty() ? QStringLiteral("-") : status),
                                     card);
        metaLabel->setObjectName(QStringLiteral("forumMeta"));
        metaLabel->setWordWrap(true);
        layout->addWidget(metaLabel);

        auto* bodyLabel = new QLabel(excerptForCard(entry.value(QStringLiteral("message")).toString()), card);
        bodyLabel->setObjectName(QStringLiteral("forumExcerpt"));
        bodyLabel->setWordWrap(true);
        bodyLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
        layout->addWidget(bodyLabel);

        auto* footerRow = new QHBoxLayout();
        footerRow->setSpacing(8);

        auto* statusChip = new QLabel(status.isEmpty() ? QStringLiteral("observed") : status, card);
        statusChip->setObjectName(QStringLiteral("forumStatusChip"));
        footerRow->addWidget(statusChip, 0, Qt::AlignLeft);
        footerRow->addStretch(1);

        auto* shareButton = new QPushButton(QStringLiteral("Share"), card);
        shareButton->setObjectName(QStringLiteral("forumGhostButton"));
        auto* commentButton = new QPushButton(QStringLiteral("Comment"), card);
        commentButton->setObjectName(QStringLiteral("forumGhostButton"));
        auto* deleteButton = new QPushButton(QStringLiteral("Delete"), card);
        deleteButton->setObjectName(QStringLiteral("forumGhostButton"));
        auto* openButton = new QPushButton(QStringLiteral("Open Thread"), card);
        openButton->setObjectName(QStringLiteral("forumAccentButton"));
        footerRow->addWidget(shareButton);
        footerRow->addWidget(commentButton);
        footerRow->addWidget(deleteButton);
        footerRow->addWidget(openButton);
        layout->addLayout(footerRow);

        connect(openButton, &QPushButton::clicked, this, [this, index]() { openEntry(index); });
        connect(commentButton, &QPushButton::clicked, this, [this, index]() {
            const auto sender = entries_.at(index).value(QStringLiteral("sender")).toString().trimmed();
            const auto channel = entries_.at(index).value(QStringLiteral("channel")).toString().trimmed();
            const auto draft = sender.isEmpty() ? QString() : QStringLiteral("@%1 ").arg(sender);
            emit commentRequested(channel, draft);
        });
        connect(shareButton, &QPushButton::clicked, this, [this, index, shareButton]() {
            const auto& entry = entries_.at(index);
            const QString summary = QStringLiteral(
                "Forum post\n"
                "Time: %1\n"
                "Sender: %2\n"
                "Channel: #%3\n"
                "Peer: %4\n"
                "Status: %5\n"
                "Message ID: %6\n\n"
                "%7")
                .arg(formatTimestamp(entry.value(QStringLiteral("timestamp")).toInteger()),
                     entry.value(QStringLiteral("sender")).toString(),
                     entry.value(QStringLiteral("channel")).toString(QStringLiteral("general")),
                     entry.value(QStringLiteral("peer")).toString(),
                     entry.value(QStringLiteral("status")).toString(),
                     entry.value(QStringLiteral("messageid")).toString(),
                     entry.value(QStringLiteral("message")).toString());
            if (auto* clipboard = QGuiApplication::clipboard()) {
                clipboard->setText(summary);
            }
            QToolTip::showText(shareButton->mapToGlobal(shareButton->rect().center()),
                               QStringLiteral("Copied share payload to clipboard."),
                               shareButton);
        });
        connect(deleteButton, &QPushButton::clicked, this, [this, index]() {
            deleteForumMessage(rpc_,
                               this,
                               entries_.at(index).value(QStringLiteral("messageid")).toString(),
                               [this]() {
                                   setStatus(QStringLiteral("Forum post deleted from local messenger history."));
                                   refresh();
                               },
                               [this](const QString& error) { setStatus(error, true); });
        });

        cardsLayout_->addWidget(card);
        cardWidgets_.push_back(card);
    }

    cardsLayout_->addStretch(1);
}

void ForumPage::openEntry(int index) {
    if (index < 0 || index >= entries_.size()) return;
    ChatEntryDialog dialog(ChatEntryDialog::Mode::Forum, this);
    dialog.setEntry(entries_.at(index));
    connect(&dialog, &ChatEntryDialog::publicCommentRequested,
            this, &ForumPage::commentRequested);
    connect(&dialog, &ChatEntryDialog::deleteRequested,
            this, [this](const QString& messageId) {
                deleteForumMessage(rpc_,
                                   this,
                                   messageId,
                                   [this]() {
                                       setStatus(QStringLiteral("Forum post deleted from local messenger history."));
                                       refresh();
                                   },
                                   [this](const QString& error) { setStatus(error, true); });
            });
    dialog.exec();
}

void ForumPage::applyFilter() {
    const auto needle = searchEdit_->text().trimmed();
    for (int index = 0; index < cardWidgets_.size() && index < entries_.size(); ++index) {
        bool visible = needle.isEmpty();
        if (!visible) {
            visible = searchableText(entries_.at(index)).contains(needle, Qt::CaseInsensitive);
        }
        cardWidgets_.at(index)->setVisible(visible);
    }
}
