#include "MailEntryDialog.hpp"

#include "ChatTheme.hpp"

#include <QDesktopServices>
#include <QDateTime>
#include <QDialogButtonBox>
#include <QFile>
#include <QFileDialog>
#include <QFileInfo>
#include <QFormLayout>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QJsonObject>
#include <QLabel>
#include <QPixmap>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QUrl>
#include <QVBoxLayout>

namespace {
QString valueOrDash(const QJsonObject& entry, const char* key) {
    const QString value = entry.value(QString::fromUtf8(key)).toString().trimmed();
    return value.isEmpty() ? QStringLiteral("-") : value;
}

QString formattedMailTime(const QJsonObject& entry) {
    const QString explicitTime = entry.value(QStringLiteral("time")).toString().trimmed();
    if (!explicitTime.isEmpty()) return explicitTime;
    const auto ts = entry.value(QStringLiteral("timestamp")).toInteger();
    if (ts <= 0) return QStringLiteral("-");
    return QDateTime::fromSecsSinceEpoch(ts).toString(QStringLiteral("yyyy-MM-dd HH:mm:ss"));
}

QString attachmentSummary(const QJsonObject& entry) {
    const QString name = entry.value(QStringLiteral("attachment_name")).toString().trimmed();
    const QString mime = entry.value(QStringLiteral("mime_type")).toString().trimmed();
    const auto size = entry.value(QStringLiteral("attachment_size")).toInteger();
    QStringList parts;
    if (!name.isEmpty()) parts.push_back(name);
    if (!mime.isEmpty()) parts.push_back(mime);
    if (size > 0) parts.push_back(QStringLiteral("%1 bytes").arg(size));
    return parts.isEmpty() ? QStringLiteral("-") : parts.join(QStringLiteral(" | "));
}
}

MailEntryDialog::MailEntryDialog(const QJsonObject& entry, QWidget* parent)
    : QDialog(parent), entry_(entry) {
    setWindowTitle(QStringLiteral("Mail Detail"));
    resize(880, 720);
    setMinimumSize(720, 560);
    chatui::applyCyberpunkTheme(this);

    auto* root = new QVBoxLayout(this);
    root->setContentsMargins(12, 12, 12, 12);
    root->setSpacing(10);

    auto* title = new QLabel(entry.value(QStringLiteral("subject")).toString(QStringLiteral("(no subject)")), this);
    title->setObjectName(QStringLiteral("pageTitle"));
    title->setWordWrap(true);
    root->addWidget(title);

    auto* metaBox = new QGroupBox(QStringLiteral("Mail Metadata"), this);
    auto* meta = new QFormLayout(metaBox);
    meta->addRow(QStringLiteral("From"), new QLabel(valueOrDash(entry_, "sender_mail_address"), metaBox));
    const QString toValue = entry_.value(QStringLiteral("mail_to")).toString().trimmed().isEmpty()
        ? valueOrDash(entry_, "recipient_mail_address")
        : entry_.value(QStringLiteral("mail_to")).toString().trimmed();
    meta->addRow(QStringLiteral("To"), new QLabel(toValue, metaBox));
    const QString ccValue = entry_.value(QStringLiteral("mail_cc")).toString().trimmed();
    if (!ccValue.isEmpty()) {
        auto* ccLabel = new QLabel(ccValue, metaBox);
        ccLabel->setWordWrap(true);
        meta->addRow(QStringLiteral("Cc"), ccLabel);
    }
    const QString bccValue = entry_.value(QStringLiteral("mail_bcc")).toString().trimmed();
    if (!bccValue.isEmpty()) {
        auto* bccLabel = new QLabel(bccValue, metaBox);
        bccLabel->setWordWrap(true);
        meta->addRow(QStringLiteral("Bcc"), bccLabel);
    }
    meta->addRow(QStringLiteral("Time"), new QLabel(formattedMailTime(entry_), metaBox));
    meta->addRow(QStringLiteral("Status"), new QLabel(valueOrDash(entry_, "status"), metaBox));
    meta->addRow(QStringLiteral("Encryption"), new QLabel(valueOrDash(entry_, "encryption_mode"), metaBox));
    meta->addRow(QStringLiteral("Peer"), new QLabel(valueOrDash(entry_, "peer"), metaBox));
    attachmentInfoValue_ = new QLabel(attachmentSummary(entry_), metaBox);
    attachmentInfoValue_->setWordWrap(true);
    meta->addRow(QStringLiteral("Attachment"), attachmentInfoValue_);
    meta->addRow(QStringLiteral("Path"), new QLabel(valueOrDash(entry_, "attachment_path"), metaBox));
    root->addWidget(metaBox);

    imagePreviewLabel_ = new QLabel(this);
    imagePreviewLabel_->setObjectName(QStringLiteral("imagePreviewSurface"));
    imagePreviewLabel_->setAlignment(Qt::AlignCenter);
    imagePreviewLabel_->setMinimumHeight(220);
    imagePreviewLabel_->setVisible(false);

    const QString attachmentPath = entry_.value(QStringLiteral("attachment_path")).toString();
    const QString mimeType = entry_.value(QStringLiteral("mime_type")).toString();
    if (!attachmentPath.isEmpty() && mimeType.startsWith(QStringLiteral("image/"))) {
        QPixmap pixmap(attachmentPath);
        if (!pixmap.isNull()) {
            imagePreviewLabel_->setPixmap(pixmap.scaled(760, 260, Qt::KeepAspectRatio, Qt::SmoothTransformation));
            imagePreviewLabel_->setVisible(true);
        }
    }
    root->addWidget(imagePreviewLabel_);

    messageView_ = new QPlainTextEdit(this);
    messageView_->setReadOnly(true);
    messageView_->setPlainText(entry_.value(QStringLiteral("message")).toString());
    messageView_->setMinimumHeight(220);
    root->addWidget(messageView_, 1);

    const QString transcript = entry_.value(QStringLiteral("transcript")).toString().trimmed();
    if (!transcript.isEmpty()) {
        auto* transcriptBox = new QGroupBox(QStringLiteral("Transcript / Caption"), this);
        auto* transcriptLayout = new QVBoxLayout(transcriptBox);
        auto* transcriptView = new QPlainTextEdit(transcriptBox);
        transcriptView->setReadOnly(true);
        transcriptView->setPlainText(transcript);
        transcriptView->setMinimumHeight(120);
        transcriptLayout->addWidget(transcriptView);
        root->addWidget(transcriptBox);
    }

    auto* attachmentButtons = new QHBoxLayout();
    openAttachmentButton_ = new QPushButton(QStringLiteral("Open Attachment"), this);
    saveAttachmentButton_ = new QPushButton(QStringLiteral("Save Copy"), this);
    attachmentButtons->addWidget(openAttachmentButton_);
    attachmentButtons->addWidget(saveAttachmentButton_);
    attachmentButtons->addStretch(1);
    root->addLayout(attachmentButtons);

    const bool hasAttachment = !attachmentPath.trimmed().isEmpty();
    openAttachmentButton_->setEnabled(hasAttachment);
    saveAttachmentButton_->setEnabled(hasAttachment);

    auto* box = new QDialogButtonBox(QDialogButtonBox::Close, this);
    root->addWidget(box);

    connect(openAttachmentButton_, &QPushButton::clicked, this, [this]() { openAttachment(); });
    connect(saveAttachmentButton_, &QPushButton::clicked, this, [this]() { saveAttachmentCopy(); });
    connect(box, &QDialogButtonBox::rejected, this, &QDialog::reject);
}

void MailEntryDialog::openAttachment() {
    const QString path = entry_.value(QStringLiteral("attachment_path")).toString();
    if (path.trimmed().isEmpty()) return;
    QDesktopServices::openUrl(QUrl::fromLocalFile(path));
}

void MailEntryDialog::saveAttachmentCopy() {
    const QString source = entry_.value(QStringLiteral("attachment_path")).toString();
    if (source.trimmed().isEmpty()) return;
    const QFileInfo info(source);
    const QString destination = QFileDialog::getSaveFileName(this,
                                                             QStringLiteral("Save Attachment Copy"),
                                                             info.fileName());
    if (destination.isEmpty()) return;
    QFile::remove(destination);
    QFile::copy(source, destination);
}
