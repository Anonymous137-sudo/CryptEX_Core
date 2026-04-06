#include "MediaComposerDialog.hpp"

#include "AudioPreviewWidget.hpp"
#include "ChatTheme.hpp"
#include "platform/SpeechTranscriber.hpp"
#include "platform/VideoThumbnailer.hpp"

#include <QAudioOutput>
#include <QCheckBox>
#include <QCloseEvent>
#include <QComboBox>
#include <QDragEnterEvent>
#include <QDropEvent>
#include <QFile>
#include <QFileDialog>
#include <QFileInfo>
#include <QFrame>
#include <QHBoxLayout>
#include <QImage>
#include <QImageReader>
#include <QLabel>
#include <QLineEdit>
#include <QMediaPlayer>
#include <QMimeData>
#include <QPixmap>
#include <QPushButton>
#include <QSignalBlocker>
#include <QStackedWidget>
#include <QUrl>
#include <QVBoxLayout>
#include <QVideoWidget>

#include <algorithm>

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
        const int start = static_cast<int>((rawLevels.size() * i) / buckets);
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
        const int start = static_cast<int>((data.size() * i) / buckets);
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

QString filterForType(const QString& mediaType) {
    if (mediaType == QStringLiteral("image")) {
        return QStringLiteral("Images (*.png *.jpg *.jpeg *.gif *.webp *.bmp)");
    }
    if (mediaType == QStringLiteral("video")) {
        return QStringLiteral("Videos (*.mp4 *.mov *.webm *.mkv *.avi *.m4v)");
    }
    return QStringLiteral("Audio (*.wav *.mp3 *.ogg *.m4a *.flac *.aac)");
}

QString titleForType(const QString& mediaType) {
    if (mediaType == QStringLiteral("image")) return QStringLiteral("Image Composer");
    if (mediaType == QStringLiteral("video")) return QStringLiteral("Video Composer");
    if (mediaType == QStringLiteral("audio")) return QStringLiteral("Anonymous Audio Composer");
    return QStringLiteral("Media Composer");
}

QString inferTypeFromPath(const QString& path) {
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

QString humanBytes(qint64 size) {
    const QStringList units{QStringLiteral("B"), QStringLiteral("KB"), QStringLiteral("MB"), QStringLiteral("GB")};
    double value = static_cast<double>(std::max<qint64>(0, size));
    int unit = 0;
    while (value >= 1024.0 && unit < units.size() - 1) {
        value /= 1024.0;
        ++unit;
    }
    return QStringLiteral("%1 %2").arg(unit == 0 ? QString::number(static_cast<qint64>(value))
                                                  : QString::number(value, 'f', 1),
                                        units.at(unit));
}

} // namespace

MediaComposerDialog::MediaComposerDialog(QWidget* parent)
    : QDialog(parent) {
    setModal(false);
    setWindowModality(Qt::NonModal);
    setWindowFlag(Qt::Window, true);
    setAcceptDrops(true);
    resize(920, 720);
    setMinimumSize(820, 620);
    setWindowTitle(QStringLiteral("Media Composer"));
    chatui::applyCyberpunkTheme(this);

    auto* root = new QVBoxLayout(this);
    root->setContentsMargins(12, 12, 12, 12);
    root->setSpacing(12);

    titleLabel_ = new QLabel(QStringLiteral("Media Composer"), this);
    titleLabel_->setObjectName(QStringLiteral("pageTitle"));
    root->addWidget(titleLabel_);

    dropHintLabel_ = new QLabel(QStringLiteral("Drag a file into this window or browse manually. The composer stays separate so the messenger page stays compact."), this);
    dropHintLabel_->setWordWrap(true);
    dropHintLabel_->setObjectName(QStringLiteral("audioAttachmentMeta"));
    root->addWidget(dropHintLabel_);

    auto* topRow = new QHBoxLayout();
    auto* typeLabel = new QLabel(QStringLiteral("Media Type"), this);
    mediaTypeCombo_ = new QComboBox(this);
    mediaTypeCombo_->addItem(QStringLiteral("Image"), QStringLiteral("image"));
    mediaTypeCombo_->addItem(QStringLiteral("Video"), QStringLiteral("video"));
    mediaTypeCombo_->addItem(QStringLiteral("Audio"), QStringLiteral("audio"));
    topRow->addWidget(typeLabel);
    topRow->addWidget(mediaTypeCombo_, 1);
    root->addLayout(topRow);

    auto* pathRow = new QHBoxLayout();
    pathEdit_ = new QLineEdit(this);
    pathEdit_->setReadOnly(true);
    pathEdit_->setPlaceholderText(QStringLiteral("Drop a media file here or use Browse"));
    browseButton_ = new QPushButton(QStringLiteral("Browse"), this);
    clearButton_ = new QPushButton(QStringLiteral("Clear"), this);
    clearButton_->setObjectName(QStringLiteral("forumGhostButton"));
    pathRow->addWidget(pathEdit_, 1);
    pathRow->addWidget(browseButton_);
    pathRow->addWidget(clearButton_);
    root->addLayout(pathRow);

    summaryLabel_ = new QLabel(QStringLiteral("Choose a file to prepare a media message."), this);
    summaryLabel_->setWordWrap(true);
    root->addWidget(summaryLabel_);

    previewStack_ = new QStackedWidget(this);

    auto* imagePage = new QFrame(previewStack_);
    imagePage_ = imagePage;
    imagePage_->setObjectName(QStringLiteral("imagePreviewCard"));
    auto* imageLayout = new QVBoxLayout(imagePage_);
    auto* imageTitle = new QLabel(QStringLiteral("Image Thread Card"), imagePage_);
    imageTitle->setObjectName(QStringLiteral("audioPreviewTitle"));
    imageLayout->addWidget(imageTitle);
    imagePreviewLabel_ = new QLabel(QStringLiteral("Image preview will appear here."), imagePage_);
    imagePreviewLabel_->setObjectName(QStringLiteral("imagePreviewSurface"));
    imagePreviewLabel_->setAlignment(Qt::AlignCenter);
    imagePreviewLabel_->setMinimumHeight(360);
    imagePreviewLabel_->setScaledContents(false);
    imageLayout->addWidget(imagePreviewLabel_, 1);
    imageMetaLabel_ = new QLabel(QStringLiteral("Drop or browse for an image to inspect format, dimensions, and attachment route."), imagePage_);
    imageMetaLabel_->setObjectName(QStringLiteral("imageMetaLabel"));
    imageMetaLabel_->setWordWrap(true);
    imageLayout->addWidget(imageMetaLabel_);
    previewStack_->addWidget(imagePage_);

    auto* videoPage = new QFrame(previewStack_);
    videoPage->setObjectName(QStringLiteral("videoPreviewCard"));
    auto* videoLayout = new QVBoxLayout(videoPage);
    auto* videoTitle = new QLabel(QStringLiteral("Video Relay Deck"), videoPage);
    videoTitle->setObjectName(QStringLiteral("audioPreviewTitle"));
    videoLayout->addWidget(videoTitle);
    videoSurfaceStack_ = new QStackedWidget(videoPage);
    videoPosterLabel_ = new QLabel(QStringLiteral("Poster frame will appear here."), videoPage);
    videoPosterLabel_->setObjectName(QStringLiteral("videoPosterSurface"));
    videoPosterLabel_->setAlignment(Qt::AlignCenter);
    videoPosterLabel_->setMinimumHeight(360);
    videoPosterLabel_->setWordWrap(true);
    videoSurfaceStack_->addWidget(videoPosterLabel_);
    videoPreviewWidget_ = new QVideoWidget(videoPage);
    videoPreviewWidget_->setMinimumHeight(360);
    videoSurfaceStack_->addWidget(videoPreviewWidget_);
    videoLayout->addWidget(videoSurfaceStack_, 1);
    auto* videoControls = new QHBoxLayout();
    videoPlayPauseButton_ = new QPushButton(QStringLiteral("Play"), videoPage);
    videoPlayPauseButton_->setObjectName(QStringLiteral("forumAccentButton"));
    videoStopButton_ = new QPushButton(QStringLiteral("Stop"), videoPage);
    videoStopButton_->setObjectName(QStringLiteral("forumGhostButton"));
    videoStatusLabel_ = new QLabel(QStringLiteral("Video preview idle"), videoPage);
    videoStatusLabel_->setObjectName(QStringLiteral("audioAttachmentMeta"));
    videoControls->addWidget(videoPlayPauseButton_);
    videoControls->addWidget(videoStopButton_);
    videoControls->addWidget(videoStatusLabel_, 1);
    videoLayout->addLayout(videoControls);
    videoMetaLabel_ = new QLabel(QStringLiteral("Drop or browse for a video to inspect playback, format, poster frame, and attachment metadata."), videoPage);
    videoMetaLabel_->setObjectName(QStringLiteral("videoMetaLabel"));
    videoMetaLabel_->setWordWrap(true);
    videoMetaLabel_->setObjectName(QStringLiteral("audioAttachmentMeta"));
    videoLayout->addWidget(videoMetaLabel_);
    previewStack_->addWidget(videoPage);

    auto* audioPage = new QWidget(previewStack_);
    auto* audioLayout = new QVBoxLayout(audioPage);
    obfuscateAudioCheck_ = new QCheckBox(QStringLiteral("Deepen / obfuscate audio before send"), audioPage);
    audioLayout->addWidget(obfuscateAudioCheck_);
    audioPreview_ = new AudioPreviewWidget(audioPage);
    audioLayout->addWidget(audioPreview_, 1);
    previewStack_->addWidget(audioPage);

    root->addWidget(previewStack_, 1);

    auto* buttons = new QHBoxLayout();
    buttons->addStretch(1);
    closeButton_ = new QPushButton(QStringLiteral("Close"), this);
    closeButton_->setObjectName(QStringLiteral("forumGhostButton"));
    applyButton_ = new QPushButton(QStringLiteral("Apply Media"), this);
    applyButton_->setObjectName(QStringLiteral("forumAccentButton"));
    buttons->addWidget(closeButton_);
    buttons->addWidget(applyButton_);
    root->addLayout(buttons);

    videoAudioOutput_ = new QAudioOutput(this);
    videoAudioOutput_->setVolume(0.7f);
    videoPlayer_ = new QMediaPlayer(this);
    videoPlayer_->setAudioOutput(videoAudioOutput_);
    videoPlayer_->setVideoOutput(videoPreviewWidget_);

    connect(browseButton_, &QPushButton::clicked, this, [this]() { browseForFile(); });
    connect(clearButton_, &QPushButton::clicked, this, [this]() { clearSelection(); });
    connect(applyButton_, &QPushButton::clicked, this, [this]() { applySelection(); });
    connect(closeButton_, &QPushButton::clicked, this, [this]() {
        videoPlayer_->stop();
        hide();
        emit composerDismissed();
    });
    connect(mediaTypeCombo_, qOverload<int>(&QComboBox::currentIndexChanged), this, [this](int) { refreshUi(); });
    connect(obfuscateAudioCheck_, &QCheckBox::checkStateChanged, this, [this](Qt::CheckState) { updatePreview(); });
    connect(videoPlayPauseButton_, &QPushButton::clicked, this, [this]() { toggleVideoPlayback(); });
    connect(videoStopButton_, &QPushButton::clicked, this, [this]() { stopVideoPlayback(); });
    connect(videoPlayer_, &QMediaPlayer::playbackStateChanged, this, [this](QMediaPlayer::PlaybackState) {
        refreshVideoPlaybackUi();
    });
    connect(videoPlayer_, &QMediaPlayer::errorOccurred, this, [this](QMediaPlayer::Error, const QString& errorString) {
        videoStatusLabel_->setText(errorString.isEmpty() ? QStringLiteral("Video playback failed") : errorString);
    });

    refreshVideoPlaybackUi();
    refreshUi();
}

void MediaComposerDialog::setSelectedType(const QString& mediaType) {
    const int index = mediaTypeCombo_->findData(mediaType.trimmed());
    if (index >= 0) {
        QSignalBlocker blocker(mediaTypeCombo_);
        mediaTypeCombo_->setCurrentIndex(index);
    }
    refreshUi();
}

void MediaComposerDialog::setInitialState(const QString& attachmentPath,
                                          const QString& transcript,
                                          bool obfuscateAudio) {
    pathEdit_->setText(attachmentPath.trimmed());
    attachmentTranscript_ = transcript;
    transcriptPath_ = attachmentPath.trimmed();
    obfuscateAudioCheck_->setChecked(obfuscateAudio);
    refreshUi();
}

QString MediaComposerDialog::selectedType() const {
    return mediaTypeCombo_->currentData().toString();
}

QString MediaComposerDialog::attachmentPath() const {
    return pathEdit_->text().trimmed();
}

QString MediaComposerDialog::attachmentTranscript() const {
    return attachmentTranscript_;
}

bool MediaComposerDialog::obfuscateAudio() const {
    return obfuscateAudioCheck_->isChecked();
}

void MediaComposerDialog::dragEnterEvent(QDragEnterEvent* event) {
    if (!event->mimeData()->hasUrls()) {
        event->ignore();
        return;
    }
    for (const auto& url : event->mimeData()->urls()) {
        if (!url.isLocalFile()) {
            continue;
        }
        if (!inferTypeFromPath(url.toLocalFile()).isEmpty()) {
            event->acceptProposedAction();
            return;
        }
    }
    event->ignore();
}

void MediaComposerDialog::dropEvent(QDropEvent* event) {
    if (!event->mimeData()->hasUrls()) {
        event->ignore();
        return;
    }
    for (const auto& url : event->mimeData()->urls()) {
        if (!url.isLocalFile()) {
            continue;
        }
        const QString local = url.toLocalFile();
        if (inferTypeFromPath(local).isEmpty()) {
            continue;
        }
        openFromDroppedPath(local);
        event->acceptProposedAction();
        return;
    }
    event->ignore();
}

void MediaComposerDialog::closeEvent(QCloseEvent* event) {
    QDialog::closeEvent(event);
    if (!applying_) {
        emit composerDismissed();
    }
}

void MediaComposerDialog::refreshUi() {
    const auto mediaType = selectedType();
    titleLabel_->setText(titleForType(mediaType));
    setWindowTitle(titleForType(mediaType));
    dropHintLabel_->setText(QStringLiteral("Drag a %1 file into this window or browse manually. This stays separate so the messenger page remains uncluttered.")
                                .arg(mediaType == QStringLiteral("audio")
                                         ? QStringLiteral("voice/media")
                                         : mediaType));
    previewStack_->setCurrentIndex(mediaType == QStringLiteral("video") ? 1 : mediaType == QStringLiteral("audio") ? 2 : 0);
    obfuscateAudioCheck_->setVisible(mediaType == QStringLiteral("audio"));
    updatePreview();
}

void MediaComposerDialog::browseForFile() {
    const auto mediaType = selectedType();
    const auto path = QFileDialog::getOpenFileName(this,
                                                   QStringLiteral("Select %1 attachment").arg(mediaType),
                                                   QString(),
                                                   filterForType(mediaType));
    if (path.isEmpty()) {
        return;
    }
    acceptPath(path, false);
}

void MediaComposerDialog::clearSelection() {
    pathEdit_->clear();
    attachmentTranscript_.clear();
    transcriptPath_.clear();
    obfuscateAudioCheck_->setChecked(false);
    refreshUi();
}

void MediaComposerDialog::acceptPath(const QString& path, bool inferType) {
    const QString normalizedPath = path.trimmed();
    if (normalizedPath.isEmpty()) {
        return;
    }
    if (inferType) {
        const QString inferred = inferTypeFromPath(normalizedPath);
        if (!inferred.isEmpty()) {
            setSelectedType(inferred);
        }
    }
    pathEdit_->setText(normalizedPath);
    if (transcriptPath_ != normalizedPath) {
        attachmentTranscript_.clear();
    }
    refreshUi();
}

void MediaComposerDialog::openFromDroppedPath(const QString& path) {
    acceptPath(path, true);
    show();
    raise();
    activateWindow();
}

void MediaComposerDialog::applySelection() {
    applying_ = true;
    emit mediaApplied(selectedType(), attachmentPath(), attachmentTranscript_, obfuscateAudio());
    hide();
    applying_ = false;
}

void MediaComposerDialog::toggleVideoPlayback() {
    if (attachmentPath().isEmpty()) {
        videoStatusLabel_->setText(QStringLiteral("Select a video file to enable preview playback."));
        return;
    }
    if (videoPlayer_->playbackState() == QMediaPlayer::PlayingState) {
        videoPlayer_->pause();
    } else {
        videoSurfaceStack_->setCurrentWidget(videoPreviewWidget_);
        videoPlayer_->play();
    }
    refreshVideoPlaybackUi();
}

void MediaComposerDialog::stopVideoPlayback() {
    videoPlayer_->stop();
    if (videoSurfaceStack_) {
        videoSurfaceStack_->setCurrentWidget(videoPosterLabel_);
    }
    refreshVideoPlaybackUi();
}

void MediaComposerDialog::refreshVideoPlaybackUi() {
    const bool hasMedia = !attachmentPath().isEmpty() && selectedType() == QStringLiteral("video");
    videoPlayPauseButton_->setEnabled(hasMedia);
    videoStopButton_->setEnabled(hasMedia);
    if (!hasMedia) {
        videoPlayPauseButton_->setText(QStringLiteral("Play"));
        videoStatusLabel_->setText(QStringLiteral("Video preview idle"));
        if (videoSurfaceStack_) {
            videoSurfaceStack_->setCurrentWidget(videoPosterLabel_);
        }
        return;
    }
    switch (videoPlayer_->playbackState()) {
    case QMediaPlayer::PlayingState:
        videoPlayPauseButton_->setText(QStringLiteral("Pause"));
        videoStatusLabel_->setText(QStringLiteral("Playing inside the media composer"));
        if (videoSurfaceStack_) {
            videoSurfaceStack_->setCurrentWidget(videoPreviewWidget_);
        }
        break;
    case QMediaPlayer::PausedState:
        videoPlayPauseButton_->setText(QStringLiteral("Resume"));
        videoStatusLabel_->setText(QStringLiteral("Video playback paused"));
        if (videoSurfaceStack_) {
            videoSurfaceStack_->setCurrentWidget(videoPreviewWidget_);
        }
        break;
    case QMediaPlayer::StoppedState:
    default:
        videoPlayPauseButton_->setText(QStringLiteral("Play"));
        videoStatusLabel_->setText(QStringLiteral("Poster frame ready for preview playback"));
        if (videoSurfaceStack_) {
            videoSurfaceStack_->setCurrentWidget(videoPosterLabel_);
        }
        break;
    }
}

void MediaComposerDialog::updatePreview() {
    const auto mediaType = selectedType();
    const auto path = attachmentPath();
    clearButton_->setEnabled(!path.isEmpty());
    applyButton_->setEnabled(!path.isEmpty());

    if (mediaType == QStringLiteral("image")) {
        videoPlayer_->stop();
        if (path.isEmpty()) {
            imagePreviewLabel_->setText(QStringLiteral("Choose an image file to open the full preview card."));
            imagePreviewLabel_->setPixmap(QPixmap());
            imageMetaLabel_->setText(QStringLiteral("This window keeps images separate from the compact messenger composer while still showing a full preview, dimensions, and routing context."));
            summaryLabel_->setText(QStringLiteral("Image messages open here without compressing the messenger page."));
            return;
        }
        QImageReader reader(path);
        reader.setAutoTransform(true);
        const QString format = QString::fromLatin1(reader.format()).toUpper();
        const QImage image = reader.read();
        if (image.isNull()) {
            imagePreviewLabel_->setPixmap(QPixmap());
            imagePreviewLabel_->setText(QStringLiteral("Unable to render the selected image preview."));
            imageMetaLabel_->setText(QStringLiteral("The selected file could not be decoded as an image."));
            summaryLabel_->setText(QStringLiteral("Image selected but preview failed."));
        } else {
            imagePreviewLabel_->setText(QString());
            imagePreviewLabel_->setPixmap(QPixmap::fromImage(image).scaled(620, 380, Qt::KeepAspectRatio, Qt::SmoothTransformation));
            const QFileInfo info(path);
            imageMetaLabel_->setText(QStringLiteral("File: %1\nFormat: %2\nDimensions: %3 × %4\nSize: %5\nPath: %6")
                                         .arg(info.fileName(),
                                              format.isEmpty() ? QStringLiteral("unknown") : format,
                                              QString::number(image.width()),
                                              QString::number(image.height()),
                                              humanBytes(info.size()),
                                              info.absoluteFilePath()));
            summaryLabel_->setText(QStringLiteral("Image queued: %1 | %2 × %3 | %4")
                                       .arg(info.fileName())
                                       .arg(image.width())
                                       .arg(image.height())
                                       .arg(humanBytes(info.size())));
        }
        return;
    }

    if (mediaType == QStringLiteral("video")) {
        if (path.isEmpty()) {
            videoPlayer_->stop();
            videoPosterLabel_->setText(QStringLiteral("Poster frame will appear here after you choose a video."));
            videoPosterLabel_->setPixmap(QPixmap());
            videoMetaLabel_->setText(QStringLiteral("Drop or browse for a video to inspect playback, format, poster frame, and attachment metadata."));
            summaryLabel_->setText(QStringLiteral("Video messages open here so the messenger page stays compact."));
            refreshVideoPlaybackUi();
            return;
        }
        const QFileInfo info(path);
        videoPlayer_->setSource(QUrl::fromLocalFile(path));
        const QImage poster = chatui::requestVideoPosterFrame(path);
        if (!poster.isNull()) {
            videoPosterLabel_->setText(QString());
            videoPosterLabel_->setPixmap(QPixmap::fromImage(poster).scaled(620, 380, Qt::KeepAspectRatio, Qt::SmoothTransformation));
        } else {
            videoPosterLabel_->setPixmap(QPixmap());
            videoPosterLabel_->setText(QStringLiteral("Poster frame unavailable on this build for the selected video.\nYou can still inspect metadata and play the clip inline."));
        }
        videoMetaLabel_->setText(QStringLiteral("File: %1\nSuffix: %2\nSize: %3\nPath: %4\n\nPoster frame is shown before playback. When you hit Play, the live video surface takes over without leaving this composer.")
                                      .arg(info.fileName(),
                                           info.suffix().isEmpty() ? QStringLiteral("unknown") : info.suffix().toUpper(),
                                           humanBytes(info.size()),
                                           info.absoluteFilePath()));
        summaryLabel_->setText(QStringLiteral("Video queued: %1 | %2")
                                   .arg(info.fileName(), humanBytes(info.size())));
        refreshVideoPlaybackUi();
        return;
    }

    videoPlayer_->stop();
    audioPreview_->setPrivacyEnabled(obfuscateAudioCheck_->isChecked());
    if (path.isEmpty()) {
        attachmentTranscript_.clear();
        transcriptPath_.clear();
        audioPreview_->clearPreview();
        audioPreview_->setPrivacyEnabled(obfuscateAudioCheck_->isChecked());
        audioPreview_->setTranscriptStatus(QStringLiteral("Choose an audio file to build the anonymous voice relay view."));
        summaryLabel_->setText(QStringLiteral("Audio messages open in a dedicated privacy-focused composer with transcript and waveform preview."));
        return;
    }

    const QFileInfo info(path);
    audioPreview_->setMediaPath(path);
    audioPreview_->setAttachmentLabel(QStringLiteral("%1\n%2").arg(info.fileName(), info.absoluteFilePath()));
    auto waveform = extractAudioPreviewLevels(path);
    if (obfuscateAudioCheck_->isChecked()) {
        waveform = simulateDeepenedWaveform(waveform);
    }
    audioPreview_->setWaveformSamples(waveform);
    summaryLabel_->setText(QStringLiteral("Audio queued: %1 (%2)").arg(info.fileName(), humanBytes(info.size())));

    if (transcriptPath_ == path && !attachmentTranscript_.trimmed().isEmpty()) {
        audioPreview_->setTranscript(attachmentTranscript_);
        audioPreview_->setTranscriptStatus(QStringLiteral("Transcript ready. Voice profile remains anonymous."));
        return;
    }

    attachmentTranscript_.clear();
    transcriptPath_ = path;
    audioPreview_->setTranscript(QString());
    audioPreview_->setTranscriptStatus(QStringLiteral("Generating transcript preview…"));
    chatui::requestAudioTranscript(path, this,
        [this, path](const QString& transcript, const QString& error) {
            if (attachmentPath() != path) {
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
