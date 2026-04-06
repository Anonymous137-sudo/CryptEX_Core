#include "AudioPreviewWidget.hpp"

#include "ChatTheme.hpp"

#include <QAudioOutput>
#include <QFrame>
#include <QGridLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QMediaPlayer>
#include <QPainter>
#include <QPainterPath>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QUrl>
#include <QVBoxLayout>
#include <QtMath>

namespace {

QPixmap anonymousAvatarPixmap(const QSize& size) {
    QPixmap pixmap(size);
    pixmap.fill(Qt::transparent);

    QPainter painter(&pixmap);
    painter.setRenderHint(QPainter::Antialiasing, true);

    const QRectF bounds(2.0, 2.0, size.width() - 4.0, size.height() - 4.0);
    const QPointF center = bounds.center();

    QRadialGradient bg(center, bounds.width() * 0.55);
    bg.setColorAt(0.0, QColor(18, 46, 60));
    bg.setColorAt(0.55, QColor(10, 16, 29));
    bg.setColorAt(1.0, QColor(6, 7, 18));
    painter.setPen(QPen(QColor(20, 216, 255, 220), 2.0));
    painter.setBrush(bg);
    painter.drawEllipse(bounds);

    painter.setPen(QPen(QColor(255, 72, 108, 200), 1.3));
    painter.drawArc(bounds.adjusted(7, 7, -7, -7), 26 * 16, 238 * 16);

    painter.setPen(Qt::NoPen);
    painter.setBrush(QColor(170, 255, 255, 220));
    painter.drawEllipse(QRectF(center.x() - 13.0, center.y() - 26.0, 26.0, 26.0));

    QPainterPath shoulders;
    shoulders.moveTo(center.x() - 28.0, center.y() + 26.0);
    shoulders.cubicTo(center.x() - 22.0, center.y() + 3.0,
                      center.x() + 22.0, center.y() + 3.0,
                      center.x() + 28.0, center.y() + 26.0);
    shoulders.lineTo(center.x() + 21.0, center.y() + 38.0);
    shoulders.lineTo(center.x() - 21.0, center.y() + 38.0);
    shoulders.closeSubpath();
    painter.setBrush(QColor(90, 244, 255, 205));
    painter.drawPath(shoulders);

    painter.setPen(QPen(QColor(255, 72, 108, 170), 1.0));
    painter.drawLine(QPointF(center.x() - 20.0, center.y() + 33.0), QPointF(center.x() + 20.0, center.y() + 33.0));

    return pixmap;
}

class AudioWaveformView final : public QWidget {
public:
    explicit AudioWaveformView(QWidget* parent = nullptr)
        : QWidget(parent) {
        setMinimumHeight(118);
    }

    void setSamples(const QVector<float>& samples) {
        samples_ = samples;
        update();
    }

protected:
    void paintEvent(QPaintEvent*) override {
        QPainter painter(this);
        painter.setRenderHint(QPainter::Antialiasing, true);
        painter.fillRect(rect(), QColor(7, 8, 20));

        QRectF frame = QRectF(rect()).adjusted(1.5, 1.5, -1.5, -1.5);
        painter.setPen(QPen(QColor(20, 216, 255, 145), 1.0));
        painter.drawRoundedRect(frame, 10.0, 10.0);

        painter.save();
        painter.setClipRect(frame.adjusted(8, 8, -8, -8));

        const QRectF grid = frame.adjusted(10, 10, -10, -10);
        painter.setPen(QPen(QColor(20, 216, 255, 35), 1.0));
        for (int i = 0; i <= 8; ++i) {
            const qreal x = grid.left() + (grid.width() * i / 8.0);
            painter.drawLine(QPointF(x, grid.top()), QPointF(x, grid.bottom()));
        }
        for (int i = 0; i <= 4; ++i) {
            const qreal y = grid.top() + (grid.height() * i / 4.0);
            painter.drawLine(QPointF(grid.left(), y), QPointF(grid.right(), y));
        }

        const qreal midY = grid.center().y();
        painter.setPen(QPen(QColor(255, 72, 108, 140), 1.2));
        painter.drawLine(QPointF(grid.left(), midY), QPointF(grid.right(), midY));

        if (samples_.isEmpty()) {
            painter.setPen(QColor(112, 202, 217, 170));
            painter.drawText(grid, Qt::AlignCenter, QStringLiteral("Anonymous voice graph will appear here"));
            painter.restore();
            return;
        }

        const int count = samples_.size();
        const qreal step = count > 1 ? grid.width() / qreal(count - 1) : grid.width();
        QPainterPath path;
        QPainterPath glow;
        for (int i = 0; i < count; ++i) {
            const qreal x = grid.left() + step * i;
            const qreal amplitude = qBound(0.0, static_cast<double>(samples_.at(i)), 1.0);
            const qreal y = midY - (grid.height() * 0.44 * amplitude);
            const qreal mirrorY = midY + (midY - y);
            if (i == 0) {
                path.moveTo(x, y);
                glow.moveTo(x, mirrorY);
            } else {
                path.lineTo(x, y);
                glow.lineTo(x, mirrorY);
            }
        }

        painter.setPen(QPen(QColor(255, 72, 108, 90), 5.0, Qt::SolidLine, Qt::RoundCap, Qt::RoundJoin));
        painter.drawPath(path);
        painter.drawPath(glow);
        painter.setPen(QPen(QColor(20, 216, 255), 2.2, Qt::SolidLine, Qt::RoundCap, Qt::RoundJoin));
        painter.drawPath(path);
        painter.drawPath(glow);

        painter.restore();
    }

private:
    QVector<float> samples_;
};

} // namespace

AudioPreviewWidget::AudioPreviewWidget(QWidget* parent)
    : QFrame(parent) {
    setObjectName(QStringLiteral("audioPreviewCard"));

    auto* root = new QGridLayout(this);
    root->setContentsMargins(12, 12, 12, 12);
    root->setHorizontalSpacing(12);
    root->setVerticalSpacing(10);

    avatarLabel_ = new QLabel(this);
    avatarLabel_->setPixmap(anonymousAvatarPixmap(QSize(112, 112)));
    avatarLabel_->setFixedSize(112, 112);
    avatarLabel_->setAlignment(Qt::AlignCenter);
    root->addWidget(avatarLabel_, 0, 0, 2, 1, Qt::AlignTop);

    auto* headerBox = new QWidget(this);
    auto* headerLayout = new QVBoxLayout(headerBox);
    headerLayout->setContentsMargins(0, 0, 0, 0);
    headerLayout->setSpacing(4);

    auto* title = new QLabel(QStringLiteral("Anonymous Voice Relay"), headerBox);
    title->setObjectName(QStringLiteral("audioPreviewTitle"));
    headerLayout->addWidget(title);

    attachmentLabel_ = new QLabel(QStringLiteral("Select an audio attachment to preview the cloaked voice profile."), headerBox);
    attachmentLabel_->setObjectName(QStringLiteral("audioAttachmentMeta"));
    attachmentLabel_->setWordWrap(true);
    headerLayout->addWidget(attachmentLabel_);

    privacyBadge_ = new QLabel(QStringLiteral("Voice cloak idle"), headerBox);
    privacyBadge_->setObjectName(QStringLiteral("audioPrivacyBadge"));
    privacyBadge_->setAlignment(Qt::AlignLeft | Qt::AlignVCenter);
    headerLayout->addWidget(privacyBadge_, 0, Qt::AlignLeft);

    auto* controls = new QWidget(headerBox);
    auto* controlsLayout = new QHBoxLayout(controls);
    controlsLayout->setContentsMargins(0, 6, 0, 0);
    controlsLayout->setSpacing(6);
    playPauseButton_ = new QPushButton(QStringLiteral("Play"), controls);
    playPauseButton_->setObjectName(QStringLiteral("forumAccentButton"));
    stopButton_ = new QPushButton(QStringLiteral("Stop"), controls);
    stopButton_->setObjectName(QStringLiteral("forumGhostButton"));
    playbackStatusLabel_ = new QLabel(QStringLiteral("Audio preview idle"), controls);
    playbackStatusLabel_->setObjectName(QStringLiteral("audioAttachmentMeta"));
    controlsLayout->addWidget(playPauseButton_);
    controlsLayout->addWidget(stopButton_);
    controlsLayout->addWidget(playbackStatusLabel_, 1);
    headerLayout->addWidget(controls);

    root->addWidget(headerBox, 0, 1);

    waveformView_ = new AudioWaveformView(this);
    root->addWidget(waveformView_, 1, 1);

    auto* transcriptTitle = new QLabel(QStringLiteral("Transcript"), this);
    transcriptTitle->setObjectName(QStringLiteral("audioTranscriptLabel"));
    root->addWidget(transcriptTitle, 2, 0, 1, 2);

    transcriptStatusLabel_ = new QLabel(QStringLiteral("Transcript will appear after audio analysis."), this);
    transcriptStatusLabel_->setObjectName(QStringLiteral("audioTranscriptStatus"));
    transcriptStatusLabel_->setWordWrap(true);
    root->addWidget(transcriptStatusLabel_, 3, 0, 1, 2);

    transcriptView_ = new QPlainTextEdit(this);
    transcriptView_->setReadOnly(true);
    transcriptView_->setPlaceholderText(QStringLiteral("Speech transcript preview"));
    transcriptView_->setMaximumBlockCount(200);
    transcriptView_->setMinimumHeight(112);
    root->addWidget(transcriptView_, 4, 0, 1, 2);

    audioOutput_ = new QAudioOutput(this);
    audioOutput_->setVolume(0.85f);
    mediaPlayer_ = new QMediaPlayer(this);
    mediaPlayer_->setAudioOutput(audioOutput_);

    connect(playPauseButton_, &QPushButton::clicked, this, [this]() { togglePlayback(); });
    connect(stopButton_, &QPushButton::clicked, this, [this]() { stopPlayback(); });
    connect(mediaPlayer_, &QMediaPlayer::playbackStateChanged, this, [this](QMediaPlayer::PlaybackState) {
        refreshPlaybackUi();
    });
    connect(mediaPlayer_, &QMediaPlayer::errorOccurred, this, [this](QMediaPlayer::Error, const QString& errorString) {
        playbackStatusLabel_->setText(errorString.isEmpty() ? QStringLiteral("Audio playback failed") : errorString);
    });
    refreshPlaybackUi();
}

void AudioPreviewWidget::setWaveformSamples(const QVector<float>& samples) {
    waveformSamples_ = samples;
    if (auto* view = static_cast<AudioWaveformView*>(waveformView_)) {
        view->setSamples(waveformSamples_);
    }
}

void AudioPreviewWidget::setAttachmentLabel(const QString& text) {
    attachmentLabel_->setText(text);
}

void AudioPreviewWidget::setMediaPath(const QString& path) {
    mediaPath_ = path.trimmed();
    mediaPlayer_->stop();
    if (mediaPath_.isEmpty()) {
        mediaPlayer_->setSource(QUrl());
    } else {
        mediaPlayer_->setSource(QUrl::fromLocalFile(mediaPath_));
    }
    refreshPlaybackUi();
}

void AudioPreviewWidget::setTranscript(const QString& text) {
    transcriptView_->setPlainText(text);
}

void AudioPreviewWidget::setTranscriptStatus(const QString& text, bool error) {
    transcriptStatusLabel_->setText(text);
    transcriptStatusLabel_->setStyleSheet(error ? chatui::errorColorStyle() : QString());
}

void AudioPreviewWidget::setPrivacyEnabled(bool enabled) {
    privacyBadge_->setText(enabled ? QStringLiteral("Voice cloak armed")
                                   : QStringLiteral("Voice cloak passive"));
}

void AudioPreviewWidget::clearPreview() {
    setMediaPath(QString());
    setWaveformSamples({});
    setAttachmentLabel(QStringLiteral("Select an audio attachment to preview the cloaked voice profile."));
    setPrivacyEnabled(false);
    setTranscriptStatus(QStringLiteral("Transcript will appear after audio analysis."));
    transcriptView_->clear();
}

void AudioPreviewWidget::togglePlayback() {
    if (mediaPath_.isEmpty()) {
        playbackStatusLabel_->setText(QStringLiteral("Select an audio file to enable inline playback."));
        return;
    }
    if (mediaPlayer_->playbackState() == QMediaPlayer::PlayingState) {
        mediaPlayer_->pause();
    } else {
        mediaPlayer_->play();
    }
    refreshPlaybackUi();
}

void AudioPreviewWidget::stopPlayback() {
    mediaPlayer_->stop();
    refreshPlaybackUi();
}

void AudioPreviewWidget::refreshPlaybackUi() {
    const bool hasMedia = !mediaPath_.isEmpty();
    playPauseButton_->setEnabled(hasMedia);
    stopButton_->setEnabled(hasMedia);
    if (!hasMedia) {
        playPauseButton_->setText(QStringLiteral("Play"));
        playbackStatusLabel_->setText(QStringLiteral("Audio preview idle"));
        return;
    }
    switch (mediaPlayer_->playbackState()) {
    case QMediaPlayer::PlayingState:
        playPauseButton_->setText(QStringLiteral("Pause"));
        playbackStatusLabel_->setText(QStringLiteral("Playing through the anonymous relay preview"));
        break;
    case QMediaPlayer::PausedState:
        playPauseButton_->setText(QStringLiteral("Resume"));
        playbackStatusLabel_->setText(QStringLiteral("Playback paused"));
        break;
    case QMediaPlayer::StoppedState:
    default:
        playPauseButton_->setText(QStringLiteral("Play"));
        playbackStatusLabel_->setText(QStringLiteral("Ready for inline playback"));
        break;
    }
}
