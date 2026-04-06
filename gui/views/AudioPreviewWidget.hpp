#pragma once

#include <QFrame>
#include <QVector>

class QLabel;
class QPlainTextEdit;
class QPushButton;
class QWidget;
class QMediaPlayer;
class QAudioOutput;

class AudioPreviewWidget : public QFrame {
    Q_OBJECT
public:
    explicit AudioPreviewWidget(QWidget* parent = nullptr);

    void setWaveformSamples(const QVector<float>& samples);
    void setAttachmentLabel(const QString& text);
    void setMediaPath(const QString& path);
    void setTranscript(const QString& text);
    void setTranscriptStatus(const QString& text, bool error = false);
    void setPrivacyEnabled(bool enabled);
    void clearPreview();

private:
    void togglePlayback();
    void stopPlayback();
    void refreshPlaybackUi();

private:
    QWidget* waveformView_{nullptr};
    QLabel* avatarLabel_{nullptr};
    QLabel* attachmentLabel_{nullptr};
    QLabel* privacyBadge_{nullptr};
    QLabel* transcriptStatusLabel_{nullptr};
    QLabel* playbackStatusLabel_{nullptr};
    QPlainTextEdit* transcriptView_{nullptr};
    QPushButton* playPauseButton_{nullptr};
    QPushButton* stopButton_{nullptr};
    QMediaPlayer* mediaPlayer_{nullptr};
    QAudioOutput* audioOutput_{nullptr};
    QString mediaPath_;
    QVector<float> waveformSamples_;
};
