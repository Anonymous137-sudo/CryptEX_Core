#include "MailComposePage.hpp"

#include "ChatTheme.hpp"
#include "rpc/RpcClient.hpp"

#include <QComboBox>
#include <QCheckBox>
#include <QFileDialog>
#include <QFormLayout>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QJsonArray>
#include <QJsonObject>
#include <QLabel>
#include <QLineEdit>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QVBoxLayout>

namespace {
QString summarizeRecipient(const QJsonObject& obj) {
    if (obj.isEmpty()) return QStringLiteral("Recipient lookup pending.");
    if (!obj.value(QStringLiteral("found")).toBool(false)) {
        return QStringLiteral("No known peer/key mapping yet. Save the contact or wait for directory discovery.");
    }
    return QStringLiteral("Resolved via %1 | peer: %2 | ECDH: %3 | RSA: %4")
        .arg(obj.value(QStringLiteral("source")).toString(QStringLiteral("directory")))
        .arg(obj.value(QStringLiteral("peer")).toString(QStringLiteral("network")))
        .arg(obj.value(QStringLiteral("pubkey_b64")).toString().isEmpty() ? QStringLiteral("no") : QStringLiteral("yes"))
        .arg(obj.value(QStringLiteral("rsa_pubkey_pem")).toString().isEmpty() ? QStringLiteral("no") : QStringLiteral("yes"));
}
}

MailComposePage::MailComposePage(QWidget* parent)
    : QWidget(parent) {
    auto* root = new QVBoxLayout(this);
    root->setContentsMargins(14, 14, 14, 14);
    root->setSpacing(12);

    auto* title = new QLabel(QStringLiteral("P2P Mail Composer"), this);
    title->setObjectName(QStringLiteral("pageTitle"));
    root->addWidget(title);

    auto* routeBox = new QGroupBox(QStringLiteral("Route"), this);
    auto* routeLayout = new QFormLayout(routeBox);
    fromCombo_ = new QComboBox(routeBox);
    toEdit_ = new QLineEdit(routeBox);
    toEdit_->setPlaceholderText(QStringLiteral("recipient@p2pmail.crx or wallet address"));
    ccEdit_ = new QLineEdit(routeBox);
    ccEdit_->setPlaceholderText(QStringLiteral("Optional, comma-separated"));
    bccEdit_ = new QLineEdit(routeBox);
    bccEdit_->setPlaceholderText(QStringLiteral("Optional, comma-separated"));
    auto* toRow = new QWidget(routeBox);
    auto* toRowLayout = new QHBoxLayout(toRow);
    toRowLayout->setContentsMargins(0, 0, 0, 0);
    toRowLayout->setSpacing(8);
    toRowLayout->addWidget(toEdit_, 1);
    resolveButton_ = new QPushButton(QStringLiteral("Resolve"), toRow);
    toRowLayout->addWidget(resolveButton_);
    recipientSummaryValue_ = new QLabel(QStringLiteral("Recipient lookup pending."), routeBox);
    recipientSummaryValue_->setWordWrap(true);
    routeLayout->addRow(QStringLiteral("From"), fromCombo_);
    routeLayout->addRow(QStringLiteral("To"), toRow);
    routeLayout->addRow(QStringLiteral("Cc"), ccEdit_);
    routeLayout->addRow(QStringLiteral("Bcc"), bccEdit_);
    routeLayout->addRow(QStringLiteral("Recipient"), recipientSummaryValue_);
    securitySummaryValue_ = new QLabel(QStringLiteral("Mail security: loading..."), routeBox);
    securitySummaryValue_->setWordWrap(true);
    routeLayout->addRow(QStringLiteral("Security"), securitySummaryValue_);
    root->addWidget(routeBox);

    auto* messageBox = new QGroupBox(QStringLiteral("Message"), this);
    auto* messageLayout = new QFormLayout(messageBox);
    subjectEdit_ = new QLineEdit(messageBox);
    subjectEdit_->setPlaceholderText(QStringLiteral("Subject"));
    encryptionCombo_ = new QComboBox(messageBox);
    encryptionCombo_->addItem(QStringLiteral("Auto"), QString());
    encryptionCombo_->addItem(QStringLiteral("ECDH + AES-GCM"), QStringLiteral("ecdh"));
    encryptionCombo_->addItem(QStringLiteral("RSA-OAEP + AES-GCM"), QStringLiteral("rsa"));
    kdfCombo_ = new QComboBox(messageBox);
    kdfCombo_->addItem(QStringLiteral("Auto"), QString());
    kdfCombo_->addItem(QStringLiteral("Argon2id"), QStringLiteral("argon2id"));
    kdfCombo_->addItem(QStringLiteral("Scrypt"), QStringLiteral("scrypt"));
    kdfCombo_->addItem(QStringLiteral("PBKDF2"), QStringLiteral("pbkdf2"));
    mediaTypeCombo_ = new QComboBox(messageBox);
    mediaTypeCombo_->addItem(QStringLiteral("Text"), QStringLiteral("text"));
    mediaTypeCombo_->addItem(QStringLiteral("File Attachment"), QStringLiteral("file"));
    mediaTypeCombo_->addItem(QStringLiteral("Image Attachment"), QStringLiteral("image"));
    mediaTypeCombo_->addItem(QStringLiteral("Video Attachment"), QStringLiteral("video"));
    mediaTypeCombo_->addItem(QStringLiteral("Audio Attachment"), QStringLiteral("audio"));
    auto* attachmentRow = new QWidget(messageBox);
    auto* attachmentLayout = new QHBoxLayout(attachmentRow);
    attachmentLayout->setContentsMargins(0, 0, 0, 0);
    attachmentLayout->setSpacing(8);
    attachmentEdit_ = new QLineEdit(attachmentRow);
    attachmentEdit_->setPlaceholderText(QStringLiteral("Optional attachment"));
    attachButton_ = new QPushButton(QStringLiteral("Attach"), attachmentRow);
    clearAttachmentButton_ = new QPushButton(QStringLiteral("Clear"), attachmentRow);
    attachmentLayout->addWidget(attachmentEdit_, 1);
    attachmentLayout->addWidget(attachButton_);
    attachmentLayout->addWidget(clearAttachmentButton_);
    obfuscateAudioCheck_ = new QCheckBox(QStringLiteral("Deepen / cloak audio"), messageBox);
    transcriptEdit_ = new QLineEdit(messageBox);
    transcriptEdit_->setPlaceholderText(QStringLiteral("Optional attachment transcript / caption"));
    totpCodeEdit_ = new QLineEdit(messageBox);
    totpCodeEdit_->setPlaceholderText(QStringLiteral("6-digit mail 2FA code"));
    totpCodeEdit_->setMaxLength(6);
    bodyEdit_ = new QPlainTextEdit(messageBox);
    bodyEdit_->setPlaceholderText(QStringLiteral("Write the message body..."));
    bodyEdit_->setMinimumHeight(280);
    messageLayout->addRow(QStringLiteral("Subject"), subjectEdit_);
    messageLayout->addRow(QStringLiteral("Encryption"), encryptionCombo_);
    messageLayout->addRow(QStringLiteral("KDF"), kdfCombo_);
    messageLayout->addRow(QStringLiteral("Media Type"), mediaTypeCombo_);
    messageLayout->addRow(QStringLiteral("Attachment"), attachmentRow);
    messageLayout->addRow(QString(), obfuscateAudioCheck_);
    messageLayout->addRow(QStringLiteral("Transcript"), transcriptEdit_);
    messageLayout->addRow(QStringLiteral("2FA"), totpCodeEdit_);
    messageLayout->addRow(QStringLiteral("Body"), bodyEdit_);
    root->addWidget(messageBox, 1);

    auto* footer = new QHBoxLayout();
    statusValue_ = new QLabel(QStringLiteral("Ready."), this);
    statusValue_->setWordWrap(true);
    footer->addWidget(statusValue_, 1);
    sendButton_ = new QPushButton(QStringLiteral("Send Mail"), this);
    sendButton_->setObjectName(QStringLiteral("forumAccentButton"));
    footer->addWidget(sendButton_);
    root->addLayout(footer);

    connect(resolveButton_, &QPushButton::clicked, this, [this]() { resolveRecipient(true); });
    connect(toEdit_, &QLineEdit::editingFinished, this, [this]() { resolveRecipient(false); });
    connect(attachButton_, &QPushButton::clicked, this, [this]() { chooseAttachment(); });
    connect(clearAttachmentButton_, &QPushButton::clicked, this, [this]() { clearAttachment(); });
    connect(sendButton_, &QPushButton::clicked, this, [this]() { sendMail(); });
    connect(mediaTypeCombo_, &QComboBox::currentIndexChanged, this, [this](int) {
        const bool audio = mediaTypeCombo_->currentData().toString() == QStringLiteral("audio");
        obfuscateAudioCheck_->setEnabled(audio);
        if (!audio) {
            obfuscateAudioCheck_->setChecked(false);
        }
    });
    obfuscateAudioCheck_->setEnabled(false);
    totpCodeEdit_->setEnabled(false);
}

void MailComposePage::setRpcClient(RpcClient* client) {
    rpc_ = client;
    refreshAccounts();
    refreshSecurityState();
}

void MailComposePage::refresh() {
    refreshAccounts();
    refreshSecurityState();
    if (!toEdit_->text().trimmed().isEmpty()) {
        resolveRecipient(false);
    }
}

void MailComposePage::setDraft(const QString& toMailAddress, const QString& subject, const QString& body) {
    if (!toMailAddress.isEmpty()) toEdit_->setText(toMailAddress);
    if (!subject.isEmpty()) subjectEdit_->setText(subject);
    if (!body.isEmpty()) bodyEdit_->setPlainText(body);
    if (!toEdit_->text().trimmed().isEmpty()) {
        resolveRecipient(false);
    }
}

void MailComposePage::setStatus(const QString& text, bool error) {
    statusValue_->setText(text);
    statusValue_->setStyleSheet(error ? QStringLiteral("color:#ff88a3;") : QString());
}

QString MailComposePage::currentFromAlias() const {
    if (!fromCombo_) {
        return QString();
    }
    const QString alias = fromCombo_->currentData().toString().trimmed();
    return alias.isEmpty() ? fromCombo_->currentText().trimmed() : alias;
}

void MailComposePage::refreshAccounts() {
    if (!rpc_) return;
    rpc_->call(QStringLiteral("getp2pmailaccounts"), QJsonArray{}, this,
        [this](const QJsonValue& result) {
            accounts_.clear();
            const auto array = result.toArray();
            const QString previous = currentFromAlias();
            fromCombo_->blockSignals(true);
            fromCombo_->clear();
            int preferredIndex = -1;
            for (int i = 0; i < array.size(); ++i) {
                const auto obj = array.at(i).toObject();
                accounts_.push_back(obj);
                const QString alias = obj.value(QStringLiteral("mail_address")).toString();
                const QString label = obj.value(QStringLiteral("label")).toString();
                QString display = alias;
                if (!label.trimmed().isEmpty()) {
                    display += QStringLiteral("  [") + label + QStringLiteral("]");
                }
                fromCombo_->addItem(display, alias);
                if (obj.value(QStringLiteral("primary")).toBool(false)) preferredIndex = i;
                if (!previous.isEmpty() && alias == previous) preferredIndex = i;
            }
            if (preferredIndex >= 0) fromCombo_->setCurrentIndex(preferredIndex);
            fromCombo_->blockSignals(false);
        },
        [this](const QString& error) {
            setStatus(QStringLiteral("Unable to load mail accounts: %1").arg(error), true);
        });
}

void MailComposePage::resolveRecipient(bool userVisible) {
    if (!rpc_) return;
    const QString target = toEdit_->text().trimmed();
    if (target.isEmpty()) {
        resolvedRecipient_ = QJsonObject{};
        recipientSummaryValue_->setText(QStringLiteral("Recipient lookup pending."));
        return;
    }
    rpc_->call(QStringLiteral("resolvep2pmailrecipient"), QJsonArray{target}, this,
        [this](const QJsonValue& result) {
            resolvedRecipient_ = result.toObject();
            recipientSummaryValue_->setText(summarizeRecipient(resolvedRecipient_));
        },
        [this, userVisible](const QString& error) {
            resolvedRecipient_ = QJsonObject{};
            recipientSummaryValue_->setText(QStringLiteral("Recipient lookup failed."));
            if (userVisible) {
                setStatus(QStringLiteral("Recipient lookup failed: %1").arg(error), true);
            }
        });
}

void MailComposePage::chooseAttachment() {
    const auto path = QFileDialog::getOpenFileName(this,
                                                   QStringLiteral("Select attachment"),
                                                   QString(),
                                                   QStringLiteral("All Files (*.*)"));
    if (!path.isEmpty()) {
        attachmentEdit_->setText(path);
    }
}

void MailComposePage::clearAttachment() {
    attachmentEdit_->clear();
    mediaTypeCombo_->setCurrentIndex(0);
    transcriptEdit_->clear();
    obfuscateAudioCheck_->setChecked(false);
}

void MailComposePage::refreshSecurityState() {
    if (!rpc_) return;
    rpc_->call(QStringLiteral("getp2pmailsecurity"), QJsonArray{}, this,
        [this](const QJsonValue& result) {
            const auto obj = result.toObject();
            twoFactorEnabled_ = obj.value(QStringLiteral("two_factor_enabled")).toBool(false);
            const auto storeCount = obj.value(QStringLiteral("distributed_store_count")).toInteger();
            const auto dhtPeers = obj.value(QStringLiteral("dht_active_peers")).toInteger();
            securitySummaryValue_->setText(QStringLiteral("Distributed mailbox replicas: %1 | DHT peers: %2 | 2FA: %3")
                                               .arg(storeCount)
                                               .arg(dhtPeers)
                                               .arg(twoFactorEnabled_ ? QStringLiteral("enabled") : QStringLiteral("disabled")));
            totpCodeEdit_->setEnabled(twoFactorEnabled_);
            totpCodeEdit_->setPlaceholderText(twoFactorEnabled_
                                                  ? QStringLiteral("6-digit mail 2FA code")
                                                  : QStringLiteral("Mail 2FA is currently disabled"));
        },
        [this](const QString&) {
            twoFactorEnabled_ = false;
            securitySummaryValue_->setText(QStringLiteral("Mail security unavailable until backend is ready."));
            totpCodeEdit_->setEnabled(false);
            totpCodeEdit_->setPlaceholderText(QStringLiteral("Mail security unavailable"));
        });
}

void MailComposePage::sendMail() {
    if (!rpc_) return;
    const QString to = toEdit_->text().trimmed();
    const QString subject = subjectEdit_->text().trimmed();
    const QString body = bodyEdit_->toPlainText().trimmed();
    const QString attachment = attachmentEdit_->text().trimmed();
    if (to.isEmpty()) {
        setStatus(QStringLiteral("Recipient mail address is required."), true);
        return;
    }
    if (body.isEmpty() && attachment.isEmpty()) {
        setStatus(QStringLiteral("Mail body or attachment is required."), true);
        return;
    }
    if (twoFactorEnabled_ && totpCodeEdit_->text().trimmed().size() < 6) {
        setStatus(QStringLiteral("Mail 2FA is enabled. Enter the 6-digit code before sending."), true);
        return;
    }

    QJsonObject payload;
    payload.insert(QStringLiteral("from"), currentFromAlias());
    payload.insert(QStringLiteral("to"), to);
    if (!ccEdit_->text().trimmed().isEmpty()) {
        payload.insert(QStringLiteral("cc"), ccEdit_->text().trimmed());
    }
    if (!bccEdit_->text().trimmed().isEmpty()) {
        payload.insert(QStringLiteral("bcc"), bccEdit_->text().trimmed());
    }
    payload.insert(QStringLiteral("subject"), subject);
    payload.insert(QStringLiteral("body"), body);
    const QString encryption = encryptionCombo_->currentData().toString();
    if (!encryption.isEmpty()) payload.insert(QStringLiteral("encryption"), encryption);
    const QString kdf = kdfCombo_->currentData().toString();
    if (!kdf.isEmpty()) payload.insert(QStringLiteral("kdf"), kdf);
    const QString mediaType = mediaTypeCombo_->currentData().toString();
    if (!mediaType.isEmpty() && mediaType != QStringLiteral("text")) {
        payload.insert(QStringLiteral("media_type"), mediaType);
    }
    if (!attachment.isEmpty()) {
        payload.insert(QStringLiteral("attachment_path"), attachment);
    }
    if (!transcriptEdit_->text().trimmed().isEmpty()) {
        payload.insert(QStringLiteral("attachment_transcript"), transcriptEdit_->text().trimmed());
    }
    if (obfuscateAudioCheck_->isChecked()) {
        payload.insert(QStringLiteral("obfuscate_audio"), true);
    }
    if (twoFactorEnabled_) {
        payload.insert(QStringLiteral("totp_code"), totpCodeEdit_->text().trimmed());
    }

    sendButton_->setEnabled(false);
    rpc_->call(QStringLiteral("sendp2pmail"), QJsonArray{payload}, this,
        [this](const QJsonValue& result) {
            sendButton_->setEnabled(true);
            const auto obj = result.toObject();
            setStatus(QStringLiteral("Mail queued for %1 recipient(s) (%2)")
                          .arg(obj.value(QStringLiteral("recipient_count")).toInteger(1))
                          .arg(obj.value(QStringLiteral("status")).toString(QStringLiteral("queued"))),
                      false);
            subjectEdit_->clear();
            bodyEdit_->clear();
            ccEdit_->clear();
            bccEdit_->clear();
            attachmentEdit_->clear();
            transcriptEdit_->clear();
            obfuscateAudioCheck_->setChecked(false);
            totpCodeEdit_->clear();
            encryptionCombo_->setCurrentIndex(0);
            kdfCombo_->setCurrentIndex(0);
            mediaTypeCombo_->setCurrentIndex(0);
            emit mailSent();
        },
        [this](const QString& error) {
            sendButton_->setEnabled(true);
            setStatus(QStringLiteral("Mail send failed: %1").arg(error), true);
        });
}
