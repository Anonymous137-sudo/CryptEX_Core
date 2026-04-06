#pragma once

#include <QDialog>

class AudioPreviewWidget;
class QAudioOutput;
class QCheckBox;
class QCloseEvent;
class QComboBox;
class QDragEnterEvent;
class QDropEvent;
class QFrame;
class QLabel;
class QLineEdit;
class QMediaPlayer;
class QPushButton;
class QStackedWidget;
class QVideoWidget;

class MediaComposerDialog : public QDialog {
    Q_OBJECT
public:
    explicit MediaComposerDialog(QWidget* parent = nullptr);

    void setSelectedType(const QString& mediaType);
    void setInitialState(const QString& attachmentPath,
                         const QString& transcript,
                         bool obfuscateAudio);

    QString selectedType() const;
    QString attachmentPath() const;
    QString attachmentTranscript() const;
    bool obfuscateAudio() const;

signals:
    void mediaApplied(const QString& mediaType,
                      const QString& attachmentPath,
                      const QString& transcript,
                      bool obfuscateAudio);
    void composerDismissed();

protected:
    void dragEnterEvent(QDragEnterEvent* event) override;
    void dropEvent(QDropEvent* event) override;
    void closeEvent(QCloseEvent* event) override;

private:
    void refreshUi();
    void browseForFile();
    void clearSelection();
    void updatePreview();
    void applySelection();
    void acceptPath(const QString& path, bool inferType);
    void toggleVideoPlayback();
    void stopVideoPlayback();
    void refreshVideoPlaybackUi();
    void openFromDroppedPath(const QString& path);

    QString attachmentTranscript_;
    QString transcriptPath_;
    bool applying_{false};
    QLabel* titleLabel_{nullptr};
    QLabel* dropHintLabel_{nullptr};
    QComboBox* mediaTypeCombo_{nullptr};
    QLineEdit* pathEdit_{nullptr};
    QPushButton* browseButton_{nullptr};
    QPushButton* clearButton_{nullptr};
    QPushButton* applyButton_{nullptr};
    QPushButton* closeButton_{nullptr};
    QLabel* summaryLabel_{nullptr};
    QStackedWidget* previewStack_{nullptr};
    QFrame* imagePage_{nullptr};
    QLabel* imagePreviewLabel_{nullptr};
    QLabel* imageMetaLabel_{nullptr};
    QStackedWidget* videoSurfaceStack_{nullptr};
    QLabel* videoPosterLabel_{nullptr};
    QVideoWidget* videoPreviewWidget_{nullptr};
    QLabel* videoMetaLabel_{nullptr};
    QPushButton* videoPlayPauseButton_{nullptr};
    QPushButton* videoStopButton_{nullptr};
    QLabel* videoStatusLabel_{nullptr};
    AudioPreviewWidget* audioPreview_{nullptr};
    QCheckBox* obfuscateAudioCheck_{nullptr};
    QMediaPlayer* videoPlayer_{nullptr};
    QAudioOutput* videoAudioOutput_{nullptr};
};
