#include "ChatPage.hpp"
#include "AudioPreviewWidget.hpp"
#include "ChatEntryDialog.hpp"
#include "ChatTheme.hpp"
#include "MediaComposerDialog.hpp"
#include "platform/SpeechTranscriber.hpp"
#include "rpc/RpcClient.hpp"

#include <QByteArray>
#include <QCheckBox>
#include <QComboBox>
#include <QDragEnterEvent>
#include <QDropEvent>
#include <QFileDialog>
#include <QFile>
#include <QFormLayout>
#include <QHeaderView>
#include <QFileInfo>
#include <QHBoxLayout>
#include <QJsonArray>
#include <QJsonObject>
#include <QLabel>
#include <QLineEdit>
#include <QMimeData>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QSplitter>
#include <QSpinBox>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QVBoxLayout>

#include <algorithm>
#include <cstdint>

namespace {

uint16_t readLe16(const uchar* ptr) {
    return static_cast<uint16_t>(ptr[0]) |
           (static_cast<uint16_t>(ptr[1]) << 8);
}

uint32_t readLe32(const uchar* ptr) {
    return static_cast<uint32_t>(ptr[0]) |
           (static_cast<uint32_t>(ptr[1]) << 8) |
           (static_cast<uint32_t>(ptr[2]) << 16) |
           (static_cast<uint32_t>(ptr[3]) << 24);
}

QVector<float> reduceLevels(const QVector<float>& rawLevels, int buckets = 96) {
    if (rawLevels.isEmpty()) {
        return {};
    }
    QVector<float> reduced;
    reduced.reserve(buckets);
    for (int i = 0; i < buckets; ++i) {
        const int start = (rawLevels.size() * i) / buckets;
        const int end = std::max(start + 1, static_cast<int>((rawLevels.size() * (i + 1)) / buckets));
        float sum = 0.0f;
        for (int j = start; j < end && j < rawLevels.size(); ++j) {
            sum += rawLevels.at(j);
        }
        reduced.push_back(sum / std::max(1, end - start));
    }
    return reduced;
}

QVector<float> waveformFromWav(const QByteArray& data) {
    if (data.size() < 44 || data.mid(0, 4) != "RIFF" || data.mid(8, 4) != "WAVE") {
        return {};
    }

    int offset = 12;
    quint16 channels = 0;
    quint16 bitsPerSample = 0;
    quint16 blockAlign = 0;
    quint16 audioFormat = 0;
    QByteArray dataChunk;

    while (offset + 8 <= data.size()) {
        const QByteArray chunkId = data.mid(offset, 4);
        const quint32 chunkSize = readLe32(reinterpret_cast<const uchar*>(data.constData() + offset + 4));
        offset += 8;
        if (offset + static_cast<int>(chunkSize) > data.size()) {
            break;
        }
        if (chunkId == "fmt " && chunkSize >= 16) {
            const auto* ptr = reinterpret_cast<const uchar*>(data.constData() + offset);
            audioFormat = readLe16(ptr + 0);
            channels = readLe16(ptr + 2);
            blockAlign = readLe16(ptr + 12);
            bitsPerSample = readLe16(ptr + 14);
        } else if (chunkId == "data") {
            dataChunk = data.mid(offset, static_cast<int>(chunkSize));
        }
        offset += static_cast<int>(chunkSize) + static_cast<int>(chunkSize % 2);
    }

    if (audioFormat != 1 || channels == 0 || blockAlign == 0 || dataChunk.isEmpty()) {
        return {};
    }

    QVector<float> rawLevels;
    if (bitsPerSample == 16) {
        const int frameCount = dataChunk.size() / blockAlign;
        rawLevels.reserve(frameCount);
        for (int frame = 0; frame < frameCount; ++frame) {
            float level = 0.0f;
            for (int channel = 0; channel < channels; ++channel) {
                const int sampleOffset = frame * blockAlign + channel * 2;
                if (sampleOffset + 1 >= dataChunk.size()) {
                    break;
                }
                const qint16 sample = static_cast<qint16>(readLe16(reinterpret_cast<const uchar*>(dataChunk.constData() + sampleOffset)));
                level += std::abs(static_cast<int>(sample)) / 32768.0f;
            }
            rawLevels.push_back(level / channels);
        }
    } else if (bitsPerSample == 8) {
        const int frameCount = dataChunk.size() / blockAlign;
        rawLevels.reserve(frameCount);
        for (int frame = 0; frame < frameCount; ++frame) {
            float level = 0.0f;
            for (int channel = 0; channel < channels; ++channel) {
                const int sampleOffset = frame * blockAlign + channel;
                if (sampleOffset >= dataChunk.size()) {
                    break;
                }
                const int sample = static_cast<unsigned char>(dataChunk.at(sampleOffset));
                level += std::abs(sample - 128) / 128.0f;
            }
            rawLevels.push_back(level / channels);
        }
    }

    return reduceLevels(rawLevels);
}

QVector<float> fallbackWaveform(const QByteArray& data, int buckets = 96) {
    if (data.isEmpty()) {
        return {};
    }
    QVector<float> levels;
    levels.reserve(buckets);
    for (int i = 0; i < buckets; ++i) {
        const int start = (data.size() * i) / buckets;
        const int end = std::max(start + 1, static_cast<int>((data.size() * (i + 1)) / buckets));
        float sum = 0.0f;
        for (int j = start; j < end && j < data.size(); ++j) {
            const int byteValue = static_cast<unsigned char>(data.at(j));
            sum += std::abs(byteValue - 127) / 127.0f;
        }
        levels.push_back(sum / std::max(1, end - start));
    }
    return levels;
}

QVector<float> extractAudioPreviewLevels(const QString& path) {
    QFile file(path);
    if (!file.open(QIODevice::ReadOnly)) {
        return {};
    }
    const QByteArray data = file.readAll();
    if (const auto wav = waveformFromWav(data); !wav.isEmpty()) {
        return wav;
    }
    return fallbackWaveform(data);
}

QVector<float> simulateDeepenedWaveform(const QVector<float>& input) {
    if (input.isEmpty()) {
        return {};
    }
    QVector<float> out;
    out.reserve(input.size());
    const double pitchFactor = 0.82;
    for (int i = 0; i < input.size(); ++i) {
        const double src = std::min<double>(input.size() - 1, i * pitchFactor);
        const int base = static_cast<int>(src);
        const int next = std::min(static_cast<int>(input.size()) - 1, base + 1);
        const double alpha = src - base;
        double sample = input.at(base) + (input.at(next) - input.at(base)) * alpha;
        if (!out.isEmpty()) {
            sample = (sample * 0.72) + (out.back() * 0.28);
        }
        sample = std::clamp(sample * 0.88, 0.0, 1.0);
        out.push_back(static_cast<float>(sample));
    }
    return out;
}

QString inferDroppedMediaType(const QString& path) {
    const QString suffix = QFileInfo(path).suffix().trimmed().toLower();
    if (QStringList{QStringLiteral("png"), QStringLiteral("jpg"), QStringLiteral("jpeg"), QStringLiteral("gif"), QStringLiteral("webp"), QStringLiteral("bmp")}.contains(suffix)) {
        return QStringLiteral("image");
    }
    if (QStringList{QStringLiteral("mp4"), QStringLiteral("mov"), QStringLiteral("webm"), QStringLiteral("mkv"), QStringLiteral("avi"), QStringLiteral("m4v")}.contains(suffix)) {
        return QStringLiteral("video");
    }
    if (QStringList{QStringLiteral("wav"), QStringLiteral("mp3"), QStringLiteral("ogg"), QStringLiteral("m4a"), QStringLiteral("flac"), QStringLiteral("aac")}.contains(suffix)) {
        return QStringLiteral("audio");
    }
    return QString();
}

} // namespace

ChatPage::ChatPage(ViewMode viewMode, QWidget* parent)
    : QWidget(parent),
      viewMode_(viewMode) {
    setAcceptDrops(true);
    auto* root = new QVBoxLayout(this);
    root->setContentsMargins(12, 12, 12, 12);
    root->setSpacing(12);

    auto* title = new QLabel(QStringLiteral("P2P Messenger"));
    title->setObjectName(QStringLiteral("pageTitle"));
    root->addWidget(title);

    infoValue_ = new QLabel(QStringLiteral("-"));
    infoValue_->setWordWrap(true);
    infoValue_->setTextInteractionFlags(Qt::TextSelectableByMouse);
    statusValue_ = new QLabel(QStringLiteral("-"));
    statusValue_->setWordWrap(true);
    root->addWidget(infoValue_);
    root->addWidget(statusValue_);

    auto* mainSplitter = new QSplitter(Qt::Vertical, this);
    mainSplitter->setChildrenCollapsible(false);
    root->addWidget(mainSplitter, 1);

    inboxTable_ = new QTableWidget(this);
    inboxTable_->setColumnCount(7);
    inboxTable_->setHorizontalHeaderLabels({QStringLiteral("Time"), QStringLiteral("Direction"), QStringLiteral("Scope"), QStringLiteral("Sender"), QStringLiteral("Channel/Peer"), QStringLiteral("Message"), QStringLiteral("Status")});
    inboxTable_->horizontalHeader()->setStretchLastSection(true);
    inboxTable_->horizontalHeader()->setSectionResizeMode(5, QHeaderView::Stretch);
    inboxTable_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    inboxTable_->setSelectionBehavior(QAbstractItemView::SelectRows);
    inboxTable_->verticalHeader()->setVisible(false);
    inboxTable_->setAlternatingRowColors(false);
    inboxTable_->setShowGrid(true);
    mainSplitter->addWidget(inboxTable_);

    auto* composeWidget = new QWidget(this);
    auto* composeRoot = new QVBoxLayout(composeWidget);
    composeRoot->setContentsMargins(0, 0, 0, 0);
    composeRoot->setSpacing(0);
    composeLayout_ = new QFormLayout();
    limitSpin_ = new QSpinBox(this);
    limitSpin_->setRange(1, 500);
    limitSpin_->setValue(50);
    modeCombo_ = new QComboBox(this);
    modeCombo_->addItems({QStringLiteral("Public"), QStringLiteral("Private")});
    modeCombo_->setVisible(viewMode_ == ViewMode::Mixed);
    peerEdit_ = new QLineEdit(this);
    peerEdit_->setPlaceholderText(QStringLiteral("Optional direct peer. Leave blank to use the connected network and seeds."));
    channelEdit_ = new QLineEdit(QStringLiteral("general"), this);
    recipientEdit_ = new QLineEdit(this);
    recipientPubkeyEdit_ = new QLineEdit(this);
    recipientRsaPubkeyEdit_ = new QPlainTextEdit(this);
    recipientRsaPubkeyEdit_->setPlaceholderText(QStringLiteral("Optional RSA public key PEM for RSA-encrypted private chat"));
    recipientRsaPubkeyEdit_->setMaximumHeight(88);
    privateKdfCombo_ = new QComboBox(this);
    privateKdfCombo_->addItem(QStringLiteral("Argon2id"), QStringLiteral("argon2id"));
    privateKdfCombo_->addItem(QStringLiteral("Scrypt"), QStringLiteral("scrypt"));
    privateKdfCombo_->addItem(QStringLiteral("PBKDF2"), QStringLiteral("pbkdf2"));
    privateEncryptionCombo_ = new QComboBox(this);
    privateEncryptionCombo_->addItem(QStringLiteral("ECDH"), QStringLiteral("ecdh"));
    privateEncryptionCombo_->addItem(QStringLiteral("RSA-OAEP"), QStringLiteral("rsa"));
    attachmentPathEdit_ = new QLineEdit(this);
    attachmentPathEdit_->setPlaceholderText(QStringLiteral("Optional image, video, or audio attachment"));
    attachmentPathEdit_->setReadOnly(true);
    mediaTypeCombo_ = new QComboBox(this);
    mediaTypeCombo_->addItem(QStringLiteral("Auto"), QStringLiteral(""));
    mediaTypeCombo_->addItem(QStringLiteral("Image"), QStringLiteral("image"));
    mediaTypeCombo_->addItem(QStringLiteral("Video"), QStringLiteral("video"));
    mediaTypeCombo_->addItem(QStringLiteral("Audio"), QStringLiteral("audio"));
    obfuscateAudioCheck_ = new QCheckBox(QStringLiteral("Deepen / obfuscate audio before send"), this);
    attachmentStatusValue_ = new QLabel(QStringLiteral("No attachment selected."), this);
    attachmentStatusValue_->setWordWrap(true);
    audioPreview_ = new AudioPreviewWidget(this);
    messageEdit_ = new QPlainTextEdit(this);
    messageEdit_->setPlaceholderText(QStringLiteral("Write a message..."));
    auto* attachButtons = new QWidget(this);
    auto* attachButtonsLayout = new QHBoxLayout(attachButtons);
    attachButtonsLayout->setContentsMargins(0, 0, 0, 0);
    attachButtonsLayout->setSpacing(6);
    openMediaComposerButton_ = new QPushButton(QStringLiteral("Open Media Composer"), this);
    clearAttachmentButton_ = new QPushButton(QStringLiteral("Clear Attachment"), this);
    openMediaComposerButton_->setObjectName(QStringLiteral("forumAccentButton"));
    clearAttachmentButton_->setObjectName(QStringLiteral("forumGhostButton"));
    attachButtonsLayout->addWidget(openMediaComposerButton_);
    attachButtonsLayout->addWidget(clearAttachmentButton_);
    attachButtonsLayout->addStretch(1);
    sendButton_ = new QPushButton(QStringLiteral("Send"), this);

    composeLayout_->addRow(QStringLiteral("Inbox Limit"), limitSpin_);
    if (viewMode_ == ViewMode::Mixed) {
        composeLayout_->addRow(QStringLiteral("Mode"), modeCombo_);
    }
    composeLayout_->addRow(QStringLiteral("Direct Peer Override"), peerEdit_);
    composeLayout_->addRow(QStringLiteral("Channel"), channelEdit_);
    composeLayout_->addRow(QStringLiteral("Recipient Address"), recipientEdit_);
    composeLayout_->addRow(QStringLiteral("Recipient Pubkey"), recipientPubkeyEdit_);
    composeLayout_->addRow(QStringLiteral("Recipient RSA Key"), recipientRsaPubkeyEdit_);
    composeLayout_->addRow(QStringLiteral("Private Encryption"), privateEncryptionCombo_);
    composeLayout_->addRow(QStringLiteral("Private KDF"), privateKdfCombo_);
    composeLayout_->addRow(QStringLiteral("Attachment Path"), attachmentPathEdit_);
    composeLayout_->addRow(QStringLiteral("Media Type"), mediaTypeCombo_);
    composeLayout_->addRow(QString(), obfuscateAudioCheck_);
    composeLayout_->addRow(QStringLiteral("Media Window"), attachButtons);
    composeLayout_->addRow(QStringLiteral("Media Summary"), attachmentStatusValue_);
    composeLayout_->addRow(QStringLiteral("Audio Identity"), audioPreview_);
    composeLayout_->addRow(QStringLiteral("Message"), messageEdit_);
    composeLayout_->addRow(QString(), sendButton_);
    composeRoot->addLayout(composeLayout_);
    mainSplitter->addWidget(composeWidget);
    mainSplitter->setStretchFactor(0, 3);
    mainSplitter->setStretchFactor(1, 2);

    connect(modeCombo_, qOverload<int>(&QComboBox::currentIndexChanged), this, [this](int) { updateModeUi(); });
    connect(sendButton_, &QPushButton::clicked, this, [this]() { sendMessage(); });
    connect(inboxTable_, &QTableWidget::cellDoubleClicked, this, [this](int row, int) { openEntry(row); });
    connect(openMediaComposerButton_, &QPushButton::clicked, this, [this]() {
        chooseAttachment(mediaTypeCombo_->currentData().toString().trimmed().isEmpty()
                             ? QStringLiteral("image")
                             : mediaTypeCombo_->currentData().toString());
    });
    connect(clearAttachmentButton_, &QPushButton::clicked, this, [this]() { clearAttachment(); });
    connect(mediaTypeCombo_, qOverload<int>(&QComboBox::currentIndexChanged), this, [this](int) {
        if (!mediaTypeCombo_->currentData().toString().trimmed().isEmpty()) {
            chooseAttachment(mediaTypeCombo_->currentData().toString());
        } else {
            syncMediaSummary();
        }
        updateModeUi();
    });
    connect(privateEncryptionCombo_, qOverload<int>(&QComboBox::currentIndexChanged), this, [this](int) { updateModeUi(); });
    connect(obfuscateAudioCheck_, &QCheckBox::checkStateChanged, this, [this](Qt::CheckState) { updateAudioPreview(); });
    if (viewMode_ == ViewMode::PublicOnly) modeCombo_->setCurrentIndex(0);
    else if (viewMode_ == ViewMode::PrivateOnly) modeCombo_->setCurrentIndex(1);
    syncMediaSummary();
    updateModeUi();
}

void ChatPage::dragEnterEvent(QDragEnterEvent* event) {
    if (!event->mimeData()->hasUrls()) {
        event->ignore();
        return;
    }
    for (const auto& url : event->mimeData()->urls()) {
        if (!url.isLocalFile()) {
            continue;
        }
        if (!inferDroppedMediaType(url.toLocalFile()).isEmpty()) {
            event->acceptProposedAction();
            return;
        }
    }
    event->ignore();
}

void ChatPage::dropEvent(QDropEvent* event) {
    if (!event->mimeData()->hasUrls()) {
        event->ignore();
        return;
    }
    for (const auto& url : event->mimeData()->urls()) {
        if (!url.isLocalFile()) {
            continue;
        }
        const QString localPath = url.toLocalFile();
        if (inferDroppedMediaType(localPath).isEmpty()) {
            continue;
        }
        openDroppedMedia(localPath);
        event->acceptProposedAction();
        return;
    }
    event->ignore();
}

void ChatPage::setRpcClient(RpcClient* client) {
    rpc_ = client;
}

void ChatPage::setStatus(const QString& text, bool error) {
    statusValue_->setText(text);
    statusValue_->setStyleSheet(error ? chatui::errorColorStyle() : QString());
}

QString ChatPage::formatChatInfo(const QJsonObject& obj) const {
    const auto historyPath = obj.value(QStringLiteral("historyfile")).toString();
    const QFileInfo historyInfo(historyPath);
    const auto historyName = historyInfo.fileName().isEmpty() ? historyPath : historyInfo.fileName();
    return QStringLiteral("Messages: %1 | Wallet: %2 | Peers: %3 connected / %4 validated | Routing: %5 | History file: %6")
        .arg(obj.value(QStringLiteral("messages")).toInteger())
        .arg(obj.value(QStringLiteral("wallet_loaded")).toBool() ? QStringLiteral("loaded") : QStringLiteral("not open"))
        .arg(obj.value(QStringLiteral("connections")).toInteger())
        .arg(obj.value(QStringLiteral("validated_peers")).toInteger())
        .arg(obj.value(QStringLiteral("routing_mode")).toString())
        .arg(historyName);
}

void ChatPage::setFormRowVisible(QWidget* field, bool visible) {
    if (!field) return;
    field->setVisible(visible);
    if (!composeLayout_) return;
    if (auto* label = composeLayout_->labelForField(field)) {
        label->setVisible(visible);
    }
}

void ChatPage::updateModeUi() {
    const bool isPrivate = viewMode_ == ViewMode::PrivateOnly || modeCombo_->currentIndex() == 1;
    const bool rsaPrivate = isPrivate && privateEncryptionCombo_->currentData().toString() == QStringLiteral("rsa");
    setFormRowVisible(channelEdit_, !isPrivate);
    setFormRowVisible(recipientEdit_, isPrivate);
    setFormRowVisible(recipientPubkeyEdit_, isPrivate);
    setFormRowVisible(recipientRsaPubkeyEdit_, isPrivate);
    setFormRowVisible(privateEncryptionCombo_, isPrivate);
    setFormRowVisible(privateKdfCombo_, isPrivate);
    privateKdfCombo_->setEnabled(!rsaPrivate);
    setFormRowVisible(attachmentPathEdit_, false);
    setFormRowVisible(obfuscateAudioCheck_, false);
    setFormRowVisible(audioPreview_, false);
    syncMediaSummary();
}

void ChatPage::setPublicDraft(const QString& channel, const QString& draft, const QString& peer) {
    if (viewMode_ == ViewMode::Mixed) {
        modeCombo_->setCurrentIndex(0);
    }
    if (!channel.trimmed().isEmpty()) {
        channelEdit_->setText(channel.trimmed());
    }
    if (!peer.trimmed().isEmpty()) {
        peerEdit_->setText(peer.trimmed());
    }
    if (!draft.isEmpty()) {
        messageEdit_->setPlainText(draft);
    }
    updateModeUi();
    messageEdit_->setFocus();
}

void ChatPage::setPrivateRecipient(const QString& address,
                                   const QString& pubkeyB64,
                                   const QString& peer,
                                   const QString& draft,
                                   const QString& rsaPubkeyPem) {
    recipientEdit_->setText(address);
    recipientPubkeyEdit_->setText(pubkeyB64);
    recipientRsaPubkeyEdit_->setPlainText(rsaPubkeyPem);
    if (!peer.trimmed().isEmpty()) {
        peerEdit_->setText(peer.trimmed());
    }
    if (!draft.isEmpty()) {
        messageEdit_->setPlainText(draft);
    }
    if (viewMode_ == ViewMode::Mixed) {
        modeCombo_->setCurrentIndex(1);
    }
    updateModeUi();
    messageEdit_->setFocus();
}

void ChatPage::chooseAttachment(const QString& mediaType) {
    if (!mediaComposer_) {
        mediaComposer_ = new MediaComposerDialog(this);
        connect(mediaComposer_, &MediaComposerDialog::mediaApplied, this,
                [this](const QString& appliedType,
                       const QString& appliedPath,
                       const QString& transcript,
                       bool obfuscateAudio) {
                    attachmentPathEdit_->setText(appliedPath.trimmed());
                    attachmentTranscript_ = transcript;
                    transcriptPath_ = appliedPath.trimmed();
                    obfuscateAudioCheck_->setChecked(obfuscateAudio);
                    {
                        QSignalBlocker blocker(mediaTypeCombo_);
                        const QString effectiveType = appliedPath.trimmed().isEmpty() ? QStringLiteral("") : appliedType.trimmed();
                        const int mediaIndex = std::max(0, mediaTypeCombo_->findData(effectiveType));
                        mediaTypeCombo_->setCurrentIndex(mediaIndex);
                    }
                    if (appliedPath.trimmed().isEmpty()) {
                        clearAttachment();
                        return;
                    }
                    syncMediaSummary();
                });
        connect(mediaComposer_, &MediaComposerDialog::composerDismissed, this, [this]() {
            if (attachmentPathEdit_->text().trimmed().isEmpty()) {
                QSignalBlocker blocker(mediaTypeCombo_);
                mediaTypeCombo_->setCurrentIndex(0);
                syncMediaSummary();
            }
        });
        connect(mediaComposer_, &QObject::destroyed, this, [this]() {
            mediaComposer_ = nullptr;
        });
    }
    mediaComposer_->setSelectedType(mediaType.trimmed().isEmpty() ? QStringLiteral("image") : mediaType.trimmed());
    mediaComposer_->setInitialState(attachmentPathEdit_->text(),
                                    attachmentTranscript_,
                                    obfuscateAudioCheck_->isChecked());
    mediaComposer_->show();
    mediaComposer_->raise();
    mediaComposer_->activateWindow();
}

void ChatPage::openDroppedMedia(const QString& path) {
    const QString mediaType = inferDroppedMediaType(path);
    if (mediaType.isEmpty()) {
        return;
    }
    chooseAttachment(mediaType);
    if (mediaComposer_) {
        mediaComposer_->setSelectedType(mediaType);
        mediaComposer_->setInitialState(path, QString(), false);
        mediaComposer_->show();
        mediaComposer_->raise();
        mediaComposer_->activateWindow();
    }
}

void ChatPage::clearAttachment() {
    attachmentPathEdit_->clear();
    {
        QSignalBlocker blocker(mediaTypeCombo_);
        mediaTypeCombo_->setCurrentIndex(0);
    }
    obfuscateAudioCheck_->setChecked(false);
    attachmentTranscript_.clear();
    transcriptPath_.clear();
    audioPreview_->clearPreview();
    if (mediaComposer_) {
        mediaComposer_->setInitialState(QString(), QString(), false);
    }
    syncMediaSummary();
}

void ChatPage::syncMediaSummary() {
    const auto path = attachmentPathEdit_->text().trimmed();
    const auto mediaType = mediaTypeCombo_->currentData().toString();
    if (path.isEmpty()) {
        attachmentStatusValue_->setText(QStringLiteral("No media attachment selected. Choose Image, Video, or Audio to open the separate composer."));
        return;
    }
    const QFileInfo info(path);
    QString summary = QStringLiteral("%1 queued: %2").arg(mediaType.isEmpty() ? QStringLiteral("Media") : mediaType.toUpper(),
                                                          info.fileName().isEmpty() ? path : info.fileName());
    if (info.exists()) {
        summary += QStringLiteral(" (%1 bytes)").arg(info.size());
    }
    if (mediaType == QStringLiteral("audio") && obfuscateAudioCheck_->isChecked()) {
        summary += QStringLiteral(" | privacy cloak on");
    }
    if (mediaType == QStringLiteral("audio") && !attachmentTranscript_.trimmed().isEmpty()) {
        summary += QStringLiteral(" | transcript ready");
    }
    attachmentStatusValue_->setText(summary);
}

void ChatPage::updateAudioPreview() {
    if (!audioPreview_) {
        return;
    }

    const bool audioAttachment = mediaTypeCombo_->currentData().toString() == QStringLiteral("audio");
    if (!audioAttachment) {
        attachmentTranscript_.clear();
        transcriptPath_.clear();
        audioPreview_->clearPreview();
        return;
    }

    audioPreview_->setPrivacyEnabled(obfuscateAudioCheck_->isChecked());

    const auto path = attachmentPathEdit_->text().trimmed();
    if (path.isEmpty()) {
        attachmentTranscript_.clear();
        transcriptPath_.clear();
        audioPreview_->clearPreview();
        audioPreview_->setPrivacyEnabled(obfuscateAudioCheck_->isChecked());
        audioPreview_->setTranscriptStatus(QStringLiteral("Select an audio file to render the anonymous voice profile."));
        return;
    }

    const QFileInfo info(path);
    audioPreview_->setMediaPath(path);
    audioPreview_->setAttachmentLabel(QStringLiteral("%1\n%2")
                                          .arg(info.fileName().isEmpty() ? path : info.fileName(),
                                               info.absoluteFilePath()));
    auto waveform = extractAudioPreviewLevels(path);
    if (obfuscateAudioCheck_->isChecked()) {
        waveform = simulateDeepenedWaveform(waveform);
    }
    audioPreview_->setWaveformSamples(waveform);

    if (transcriptPath_ == path && !attachmentTranscript_.trimmed().isEmpty()) {
        audioPreview_->setTranscript(attachmentTranscript_);
        audioPreview_->setTranscriptStatus(QStringLiteral("Transcript ready. Voice profile remains anonymous."));
        return;
    }

    attachmentTranscript_.clear();
    transcriptPath_ = path;
    audioPreview_->setTranscript(QString());
    audioPreview_->setTranscriptStatus(QStringLiteral("Generating transcript preview…"));

    const quint64 requestId = ++transcriptRequestSerial_;
    chatui::requestAudioTranscript(path, this,
        [this, requestId](const QString& transcript, const QString& error) {
            if (requestId != transcriptRequestSerial_ || !audioPreview_) {
                return;
            }
            if (!error.isEmpty()) {
                attachmentTranscript_.clear();
                audioPreview_->setTranscriptStatus(error, true);
                return;
            }
            attachmentTranscript_ = transcript;
            audioPreview_->setTranscript(transcript);
            audioPreview_->setTranscriptStatus(
                transcript.trimmed().isEmpty()
                    ? QStringLiteral("Transcript returned no spoken content.")
                    : QStringLiteral("Transcript ready. Voice profile remains anonymous."));
        });
}

void ChatPage::refresh() {
    if (!rpc_) {
        setStatus(QStringLiteral("RPC client not configured."), true);
        return;
    }

    setStatus(QStringLiteral("Refreshing inbox..."));
    rpc_->call(QStringLiteral("getchatinfo"), {}, this,
        [this](const QJsonValue& result) {
            const auto obj = result.toObject();
            infoValue_->setText(formatChatInfo(obj));
            infoValue_->setToolTip(obj.value(QStringLiteral("historyfile")).toString());
            setStatus(QStringLiteral("Chat backend ready."));
        },
        [this](const QString& error) { setStatus(error, true); });

    QJsonArray params;
    params.append(limitSpin_->value());
    QJsonObject filters;
    if (viewMode_ == ViewMode::PublicOnly) {
        filters.insert(QStringLiteral("private_only"), false);
    } else if (viewMode_ == ViewMode::PrivateOnly) {
        filters.insert(QStringLiteral("private_only"), true);
    }
    if (!filters.isEmpty()) {
        params.append(filters);
    }
    rpc_->call(QStringLiteral("getchatinbox"), params, this,
        [this](const QJsonValue& result) {
            const auto rows = result.toArray();
            entries_.clear();
            entries_.reserve(rows.size());
            inboxTable_->setRowCount(rows.size());
            for (int i = 0; i < rows.size(); ++i) {
                const auto obj = rows.at(i).toObject();
                entries_.push_back(obj);
                const auto scope = obj.value(QStringLiteral("private")).toBool() ? QStringLiteral("Private") : QStringLiteral("Public");
                const auto channelOrPeer = obj.value(QStringLiteral("channel")).toString();
                inboxTable_->setItem(i, 0, new QTableWidgetItem(QString::number(obj.value(QStringLiteral("timestamp")).toInteger())));
                inboxTable_->setItem(i, 1, new QTableWidgetItem(obj.value(QStringLiteral("direction")).toString()));
                inboxTable_->setItem(i, 2, new QTableWidgetItem(scope));
                inboxTable_->setItem(i, 3, new QTableWidgetItem(obj.value(QStringLiteral("sender")).toString()));
                inboxTable_->setItem(i, 4, new QTableWidgetItem(channelOrPeer.isEmpty() ? obj.value(QStringLiteral("peer")).toString() : channelOrPeer));
                inboxTable_->setItem(i, 5, new QTableWidgetItem(obj.value(QStringLiteral("message")).toString()));
                inboxTable_->setItem(i, 6, new QTableWidgetItem(obj.value(QStringLiteral("status")).toString()));
            }
        },
        [this](const QString& error) { setStatus(error, true); });
}

void ChatPage::openEntry(int row) {
    if (row < 0 || row >= entries_.size()) return;
    const auto entry = entries_.at(row);
    const bool isPrivate = entry.value(QStringLiteral("private")).toBool();
    ChatEntryDialog dialog(isPrivate ? ChatEntryDialog::Mode::PrivateHistory
                                     : ChatEntryDialog::Mode::Forum,
                           this);
    dialog.setEntry(entry);
    if (!isPrivate) {
        connect(&dialog, &ChatEntryDialog::publicCommentRequested,
                this, [this](const QString& channel, const QString& draft) {
                    setPublicDraft(channel, draft);
                });
    } else {
        connect(&dialog, &ChatEntryDialog::privateReplyRequested,
                this, [this](const QString& address, const QString& pubkeyB64, const QString& peer, const QString& draft) {
                    setPrivateRecipient(address, pubkeyB64, peer, draft);
                });
    }
    connect(&dialog, &ChatEntryDialog::deleteRequested,
            this, [this](const QString& messageId) {
                if (!rpc_ || messageId.trimmed().isEmpty()) {
                    setStatus(QStringLiteral("Message ID is required for deletion."), true);
                    return;
                }
                rpc_->call(QStringLiteral("deletechatmessage"), QJsonArray{messageId}, this,
                    [this](const QJsonValue&) {
                        setStatus(QStringLiteral("Message deleted from local messenger history."));
                        refresh();
                    },
                    [this](const QString& error) { setStatus(error, true); });
            });
    dialog.exec();
}

void ChatPage::sendMessage() {
    if (!rpc_) {
        setStatus(QStringLiteral("RPC client not configured."), true);
        return;
    }

    const bool isPrivate = viewMode_ == ViewMode::PrivateOnly ||
                           (viewMode_ == ViewMode::Mixed && modeCombo_->currentIndex() == 1);
    const auto attachmentPath = attachmentPathEdit_->text().trimmed();
    if (messageEdit_->toPlainText().trimmed().isEmpty() && attachmentPath.isEmpty()) {
        setStatus(QStringLiteral("Message text or an attachment is required."), true);
        return;
    }

    const auto peer = peerEdit_->text().trimmed();
    QJsonObject request;
    if (!peer.isEmpty()) {
        request.insert(QStringLiteral("peer"), peer);
    }
    request.insert(QStringLiteral("message"), messageEdit_->toPlainText());
    if (!attachmentPath.isEmpty()) {
        request.insert(QStringLiteral("attachment_path"), attachmentPath);
        if (!mediaTypeCombo_->currentData().toString().trimmed().isEmpty()) {
            request.insert(QStringLiteral("media_type"), mediaTypeCombo_->currentData().toString());
        }
        if (obfuscateAudioCheck_->isChecked()) {
            request.insert(QStringLiteral("obfuscate_audio"), true);
        }
        if (!attachmentTranscript_.trimmed().isEmpty()) {
            request.insert(QStringLiteral("attachment_transcript"), attachmentTranscript_);
        }
    }
    QJsonArray params;
    if (!isPrivate) {
        if (channelEdit_->text().trimmed().isEmpty()) {
            setStatus(QStringLiteral("Channel is required for public chat."), true);
            return;
        }
        request.insert(QStringLiteral("channel"), channelEdit_->text().trimmed());
        params.append(request);
    } else {
        if (recipientEdit_->text().trimmed().isEmpty()) {
            setStatus(QStringLiteral("Recipient address is required for private chat."), true);
            return;
        }
        const auto encryptionMode = privateEncryptionCombo_->currentData().toString();
        const auto rsaPubkey = recipientRsaPubkeyEdit_->toPlainText().trimmed();
        const auto secpPubkey = recipientPubkeyEdit_->text().trimmed();
        if (encryptionMode == QStringLiteral("rsa")) {
            if (rsaPubkey.isEmpty()) {
                setStatus(QStringLiteral("Recipient RSA public key is required for RSA private chat."), true);
                return;
            }
        } else if (secpPubkey.isEmpty()) {
            setStatus(QStringLiteral("Recipient pubkey is required for ECDH private chat."), true);
            return;
        }
        request.insert(QStringLiteral("recipient_address"), recipientEdit_->text().trimmed());
        if (!secpPubkey.isEmpty()) {
            request.insert(QStringLiteral("recipient_pubkey_b64"), secpPubkey);
        }
        if (!rsaPubkey.isEmpty()) {
            request.insert(QStringLiteral("recipient_rsa_pubkey_pem"), rsaPubkey);
        }
        request.insert(QStringLiteral("kdf"), privateKdfCombo_->currentData().toString());
        request.insert(QStringLiteral("encryption"), encryptionMode);
        params.append(request);
    }

    rpc_->call(isPrivate ? QStringLiteral("sendchatprivate") : QStringLiteral("sendchatpublic"), params, this,
        [this](const QJsonValue& result) {
            const auto obj = result.toObject();
            setStatus(QStringLiteral("Chat sent. id=%1 status=%2 peers=%3 type=%4")
                .arg(obj.value(QStringLiteral("messageid")).toString())
                .arg(obj.value(QStringLiteral("status")).toString())
                .arg(obj.value(QStringLiteral("peers")).toInteger())
                .arg(obj.value(QStringLiteral("content_type")).toString(QStringLiteral("text"))));
            messageEdit_->clear();
            clearAttachment();
            refresh();
        },
        [this](const QString& error) { setStatus(error, true); });
}
