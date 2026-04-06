#pragma once

#include <QAudioFormat>
#include <QJsonObject>
#include <QWidget>

class QLabel;
class QLineEdit;
class QPushButton;
class QCheckBox;
class QTimer;
class QAudioSource;
class QAudioSink;
class QIODevice;
class RpcClient;

class VoiceCallPage : public QWidget {
    Q_OBJECT
public:
    explicit VoiceCallPage(QWidget* parent = nullptr);

    void setRpcClient(RpcClient* client);
    void refresh();
    void setCallTarget(const QString& address,
                       const QString& pubkeyB64,
                       const QString& peer = QString());

private:
    void setStatus(const QString& text, bool error = false);
    void startCall();
    void acceptCall();
    void declineCall();
    void endCall();
    void pollState();
    void pollIncomingAudio();
    void updateUiFromState(const QJsonObject& state);
    void updateControls();
    void updateLiveTimestamp();
    void startAudioPipeline();
    void stopAudioPipeline();
    void processCapturedAudio();
    void queueIncomingFrame(const QJsonObject& frame);
    void resetWaveforms();
    void updateQualityIndicators();

    RpcClient* rpc_{nullptr};
    QJsonObject state_;
    QString activeCallId_;
    bool pollingState_{false};
    bool pollingAudio_{false};
    int audioSendInFlight_{0};
    int ringPhase_{0};

    QTimer* stateTimer_{nullptr};
    QTimer* audioTimer_{nullptr};
    QTimer* clockTimer_{nullptr};

    QLabel* statusValue_{nullptr};
    QLabel* avatarLabel_{nullptr};
    QLabel* callStateValue_{nullptr};
    QLabel* routeValue_{nullptr};
    QLabel* timestampValue_{nullptr};
    QLabel* securityValue_{nullptr};
    QLabel* ringStateValue_{nullptr};
    QLabel* latencyValue_{nullptr};
    QLabel* qualityValue_{nullptr};
    QWidget* waveformView_{nullptr};

    QLineEdit* recipientEdit_{nullptr};
    QLineEdit* recipientPubkeyEdit_{nullptr};
    QLineEdit* peerEdit_{nullptr};
    QLineEdit* fromAddressEdit_{nullptr};
    QCheckBox* obfuscateCheck_{nullptr};
    QPushButton* startButton_{nullptr};
    QPushButton* acceptButton_{nullptr};
    QPushButton* declineButton_{nullptr};
    QPushButton* endButton_{nullptr};
    QPushButton* refreshButton_{nullptr};

    QAudioFormat captureFormat_;
    QAudioFormat playbackFormat_;
    QAudioSource* audioSource_{nullptr};
    QAudioSink* audioSink_{nullptr};
    QIODevice* captureDevice_{nullptr};
    QIODevice* playbackDevice_{nullptr};
    QByteArray captureBuffer_;
};
