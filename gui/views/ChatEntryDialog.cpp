#include "ChatEntryDialog.hpp"
#include "ChatTheme.hpp"

#include <QClipboard>
#include <QDateTime>
#include <QDesktopServices>
#include <QDialogButtonBox>
#include <QFormLayout>
#include <QGuiApplication>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QLabel>
#include <QMessageBox>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QToolTip>
#include <QUrl>
#include <QVBoxLayout>

ChatEntryDialog::ChatEntryDialog(Mode mode, QWidget* parent)
    : QDialog(parent),
      mode_(mode) {
    setModal(true);
    resize(760, 560);
    setMinimumSize(640, 460);
    setWindowTitle(mode_ == Mode::Forum ? QStringLiteral("Forum Post") : QStringLiteral("Private Message"));
    chatui::applyCyberpunkTheme(this);

    auto* root = new QVBoxLayout(this);
    root->setContentsMargins(12, 12, 12, 12);
    root->setSpacing(12);

    headingValue_ = new QLabel(QStringLiteral("-"), this);
    headingValue_->setWordWrap(true);
    headingValue_->setTextInteractionFlags(Qt::TextSelectableByMouse);
    root->addWidget(headingValue_);

    messageValue_ = new QPlainTextEdit(this);
    messageValue_->setReadOnly(true);
    messageValue_->setMinimumHeight(240);
    root->addWidget(messageValue_, 1);

    auto* detailsBox = new QGroupBox(QStringLiteral("Details"), this);
    auto* detailsForm = new QFormLayout(detailsBox);
    senderValue_ = new QLabel(QStringLiteral("-"), detailsBox);
    recipientValue_ = new QLabel(QStringLiteral("-"), detailsBox);
    channelValue_ = new QLabel(QStringLiteral("-"), detailsBox);
    timeValue_ = new QLabel(QStringLiteral("-"), detailsBox);
    peerValue_ = new QLabel(QStringLiteral("-"), detailsBox);
    statusValue_ = new QLabel(QStringLiteral("-"), detailsBox);
    messageIdValue_ = new QLabel(QStringLiteral("-"), detailsBox);
    contentTypeValue_ = new QLabel(QStringLiteral("-"), detailsBox);
    attachmentPathValue_ = new QLabel(QStringLiteral("-"), detailsBox);
    for (auto* label : {senderValue_, recipientValue_, channelValue_, timeValue_, peerValue_, statusValue_, messageIdValue_, contentTypeValue_, attachmentPathValue_}) {
        label->setWordWrap(true);
        label->setTextInteractionFlags(Qt::TextSelectableByMouse);
    }
    detailsForm->addRow(QStringLiteral("Sender"), senderValue_);
    detailsForm->addRow(QStringLiteral("Recipient"), recipientValue_);
    detailsForm->addRow(QStringLiteral("Channel"), channelValue_);
    detailsForm->addRow(QStringLiteral("Time"), timeValue_);
    detailsForm->addRow(QStringLiteral("Peer"), peerValue_);
    detailsForm->addRow(QStringLiteral("Status"), statusValue_);
    detailsForm->addRow(QStringLiteral("Message ID"), messageIdValue_);
    detailsForm->addRow(QStringLiteral("Content"), contentTypeValue_);
    detailsForm->addRow(QStringLiteral("Attachment"), attachmentPathValue_);
    root->addWidget(detailsBox);

    auto* transcriptBox = new QGroupBox(QStringLiteral("Transcript"), this);
    auto* transcriptLayout = new QVBoxLayout(transcriptBox);
    transcriptValue_ = new QPlainTextEdit(transcriptBox);
    transcriptValue_->setReadOnly(true);
    transcriptValue_->setPlaceholderText(QStringLiteral("No transcript stored for this message."));
    transcriptValue_->setMinimumHeight(96);
    transcriptLayout->addWidget(transcriptValue_);
    root->addWidget(transcriptBox);

    auto* actions = new QHBoxLayout();
    commentButton_ = new QPushButton(mode_ == Mode::Forum ? QStringLiteral("Comment") : QStringLiteral("Reply"), this);
    shareButton_ = new QPushButton(QStringLiteral("Share"), this);
    deleteButton_ = new QPushButton(QStringLiteral("Delete"), this);
    openAttachmentButton_ = new QPushButton(QStringLiteral("Open Attachment"), this);
    upvoteButton_ = new QPushButton(QStringLiteral("Upvote"), this);
    downvoteButton_ = new QPushButton(QStringLiteral("Downvote"), this);
    voteValue_ = new QLabel(QStringLiteral("Vote: 0"), this);
    voteValue_->setVisible(mode_ == Mode::Forum);
    upvoteButton_->setVisible(mode_ == Mode::Forum);
    downvoteButton_->setVisible(mode_ == Mode::Forum);
    actions->addWidget(commentButton_);
    actions->addWidget(shareButton_);
    actions->addWidget(deleteButton_);
    actions->addWidget(openAttachmentButton_);
    actions->addStretch(1);
    actions->addWidget(voteValue_);
    actions->addWidget(upvoteButton_);
    actions->addWidget(downvoteButton_);
    root->addLayout(actions);

    auto* closeBox = new QDialogButtonBox(QDialogButtonBox::Close, this);
    root->addWidget(closeBox);

    connect(commentButton_, &QPushButton::clicked, this, [this]() { handleCommentOrReply(); });
    connect(shareButton_, &QPushButton::clicked, this, [this]() { shareEntry(); });
    connect(deleteButton_, &QPushButton::clicked, this, [this]() { deleteEntry(); });
    connect(openAttachmentButton_, &QPushButton::clicked, this, [this]() { openAttachment(); });
    connect(upvoteButton_, &QPushButton::clicked, this, [this]() {
        voteDelta_ += 1;
        updateVoteLabel();
    });
    connect(downvoteButton_, &QPushButton::clicked, this, [this]() {
        voteDelta_ -= 1;
        updateVoteLabel();
    });
    connect(closeBox, &QDialogButtonBox::rejected, this, &QDialog::reject);
}

QString ChatEntryDialog::formatTimestamp(qint64 unixTs) {
    if (unixTs <= 0) return QStringLiteral("-");
    const auto dt = QDateTime::fromSecsSinceEpoch(unixTs);
    return dt.isValid() ? dt.toString(QStringLiteral("yyyy-MM-dd HH:mm:ss")) : QString::number(unixTs);
}

void ChatEntryDialog::updateVoteLabel() {
    voteValue_->setText(QStringLiteral("Vote: %1").arg(voteDelta_));
}

void ChatEntryDialog::setEntry(const QJsonObject& entry) {
    entry_ = entry;
    voteDelta_ = 0;
    updateVoteLabel();

    const auto sender = entry_.value(QStringLiteral("sender")).toString();
    const auto recipient = entry_.value(QStringLiteral("recipient")).toString();
    const auto channel = entry_.value(QStringLiteral("channel")).toString();
    const auto message = entry_.value(QStringLiteral("message")).toString();
    const auto status = entry_.value(QStringLiteral("status")).toString();
    const auto peer = entry_.value(QStringLiteral("peer")).toString();
    const auto messageId = entry_.value(QStringLiteral("messageid")).toString();
    const auto contentType = entry_.value(QStringLiteral("content_type")).toString();
    const auto attachmentName = entry_.value(QStringLiteral("attachment_name")).toString();
    const auto attachmentPath = entry_.value(QStringLiteral("attachment_path")).toString();
    const auto audioPrivacy = entry_.value(QStringLiteral("audio_privacy")).toString();
    const auto encryptionMode = entry_.value(QStringLiteral("encryption_mode")).toString();
    const auto transcript = entry_.value(QStringLiteral("transcript")).toString();
    const auto heading = mode_ == Mode::Forum
        ? QStringLiteral("%1 in #%2").arg(sender.isEmpty() ? QStringLiteral("Unknown sender") : sender,
                                          channel.isEmpty() ? QStringLiteral("general") : channel)
        : QStringLiteral("%1 message %2").arg(entry_.value(QStringLiteral("direction")).toString() == QStringLiteral("out")
                                              ? QStringLiteral("Outgoing")
                                              : QStringLiteral("Incoming"),
                                              sender.isEmpty() ? recipient : sender);
    headingValue_->setText(heading);
    messageValue_->setPlainText(message);
    senderValue_->setText(sender.isEmpty() ? QStringLiteral("-") : sender);
    recipientValue_->setText(recipient.isEmpty() ? QStringLiteral("-") : recipient);
    channelValue_->setText(channel.isEmpty() ? QStringLiteral("-") : channel);
    timeValue_->setText(formatTimestamp(entry_.value(QStringLiteral("timestamp")).toInteger()));
    peerValue_->setText(peer.isEmpty() ? QStringLiteral("-") : peer);
    statusValue_->setText(status.isEmpty() ? QStringLiteral("-") : status);
    messageIdValue_->setText(messageId.isEmpty() ? QStringLiteral("-") : messageId);
    QString contentSummary = contentType.isEmpty() ? QStringLiteral("text") : contentType;
    if (!audioPrivacy.isEmpty() && audioPrivacy != QStringLiteral("none")) {
        contentSummary += QStringLiteral(" / %1").arg(audioPrivacy);
    }
    if (!encryptionMode.isEmpty()) {
        contentSummary += QStringLiteral(" / %1").arg(encryptionMode);
    }
    contentTypeValue_->setText(contentSummary);
    attachmentPathValue_->setText(attachmentPath.isEmpty() ? QStringLiteral("-")
                                                           : QStringLiteral("%1\n%2").arg(attachmentName, attachmentPath));
    transcriptValue_->setPlainText(transcript);
    transcriptValue_->parentWidget()->setVisible(!transcript.trimmed().isEmpty());
    openAttachmentButton_->setVisible(!attachmentPath.isEmpty());
    deleteButton_->setEnabled(!messageId.isEmpty());
}

void ChatEntryDialog::handleCommentOrReply() {
    if (mode_ == Mode::Forum) {
        const auto sender = entry_.value(QStringLiteral("sender")).toString().trimmed();
        const auto channel = entry_.value(QStringLiteral("channel")).toString().trimmed();
        const auto draft = sender.isEmpty() ? QString() : QStringLiteral("@%1 ").arg(sender);
        emit publicCommentRequested(channel, draft);
    } else {
        const auto outgoing = entry_.value(QStringLiteral("direction")).toString() == QStringLiteral("out");
        const auto address = outgoing
            ? entry_.value(QStringLiteral("recipient")).toString().trimmed()
            : entry_.value(QStringLiteral("sender")).toString().trimmed();
        const auto pubkey = outgoing
            ? entry_.value(QStringLiteral("recipient_pubkey")).toString().trimmed()
            : entry_.value(QStringLiteral("sender_pubkey")).toString().trimmed();
        emit privateReplyRequested(address, pubkey, entry_.value(QStringLiteral("peer")).toString().trimmed(), QString());
    }
    accept();
}

void ChatEntryDialog::shareEntry() {
    QString summary;
    if (mode_ == Mode::Forum) {
        summary = QStringLiteral(
            "Forum post\n"
            "Time: %1\n"
            "Sender: %2\n"
            "Channel: #%3\n"
            "Peer: %4\n"
            "Status: %5\n"
            "Message ID: %6\n\n"
            "Content: %7\n"
            "Attachment: %8\n\n"
            "Transcript: %9\n\n"
            "%10")
            .arg(formatTimestamp(entry_.value(QStringLiteral("timestamp")).toInteger()))
            .arg(entry_.value(QStringLiteral("sender")).toString())
            .arg(entry_.value(QStringLiteral("channel")).toString())
            .arg(entry_.value(QStringLiteral("peer")).toString())
            .arg(entry_.value(QStringLiteral("status")).toString())
            .arg(entry_.value(QStringLiteral("messageid")).toString())
            .arg(entry_.value(QStringLiteral("content_type")).toString())
            .arg(entry_.value(QStringLiteral("attachment_path")).toString())
            .arg(entry_.value(QStringLiteral("transcript")).toString())
            .arg(entry_.value(QStringLiteral("message")).toString());
    } else {
        summary = QStringLiteral(
            "Private message\n"
            "Time: %1\n"
            "Sender: %2\n"
            "Recipient: %3\n"
            "Peer: %4\n"
            "Status: %5\n"
            "Message ID: %6\n\n"
            "Content: %7\n"
            "Attachment: %8\n\n"
            "Transcript: %9\n\n"
            "%10")
            .arg(formatTimestamp(entry_.value(QStringLiteral("timestamp")).toInteger()))
            .arg(entry_.value(QStringLiteral("sender")).toString())
            .arg(entry_.value(QStringLiteral("recipient")).toString())
            .arg(entry_.value(QStringLiteral("peer")).toString())
            .arg(entry_.value(QStringLiteral("status")).toString())
            .arg(entry_.value(QStringLiteral("messageid")).toString())
            .arg(entry_.value(QStringLiteral("content_type")).toString())
            .arg(entry_.value(QStringLiteral("attachment_path")).toString())
            .arg(entry_.value(QStringLiteral("transcript")).toString())
            .arg(entry_.value(QStringLiteral("message")).toString());
    }
    if (auto* clipboard = QGuiApplication::clipboard()) {
        clipboard->setText(summary);
    }
    QToolTip::showText(shareButton_->mapToGlobal(shareButton_->rect().center()),
                       QStringLiteral("Copied share payload to clipboard."),
                       shareButton_);
}

void ChatEntryDialog::deleteEntry() {
    const auto messageId = entry_.value(QStringLiteral("messageid")).toString().trimmed();
    if (messageId.isEmpty()) {
        return;
    }
    const auto answer = QMessageBox::warning(
        this,
        QStringLiteral("Delete Message"),
        QStringLiteral("Delete this message from the local messenger history?\n\nMessage ID: %1").arg(messageId),
        QMessageBox::Yes | QMessageBox::No,
        QMessageBox::No);
    if (answer != QMessageBox::Yes) {
        return;
    }
    emit deleteRequested(messageId);
    accept();
}

void ChatEntryDialog::openAttachment() {
    const auto path = entry_.value(QStringLiteral("attachment_path")).toString().trimmed();
    if (path.isEmpty()) {
        return;
    }
    QDesktopServices::openUrl(QUrl::fromLocalFile(path));
}
