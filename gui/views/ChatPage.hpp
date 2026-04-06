#pragma once

#include <QJsonObject>
#include <QVector>
#include <QWidget>

class QComboBox;
class QCheckBox;
class QDragEnterEvent;
class QDropEvent;
class QFormLayout;
class QJsonObject;
class QLabel;
class QLineEdit;
class QPlainTextEdit;
class QSpinBox;
class QTableWidget;
class QPushButton;
class RpcClient;
class AudioPreviewWidget;
class MediaComposerDialog;

class ChatPage : public QWidget {
    Q_OBJECT
public:
    enum class ViewMode {
        Mixed,
        PublicOnly,
        PrivateOnly,
    };

    explicit ChatPage(ViewMode viewMode = ViewMode::Mixed, QWidget* parent = nullptr);

    void setRpcClient(RpcClient* client);
    void refresh();
    void setPublicDraft(const QString& channel, const QString& draft = QString(), const QString& peer = QString());
    void setPrivateRecipient(const QString& address,
                             const QString& pubkeyB64,
                             const QString& peer = QString(),
                             const QString& draft = QString(),
                             const QString& rsaPubkeyPem = QString());

protected:
    void dragEnterEvent(QDragEnterEvent* event) override;
    void dropEvent(QDropEvent* event) override;

private:
    void setFormRowVisible(QWidget* field, bool visible);
    void updateModeUi();
    void sendMessage();
    void openEntry(int row);
    void setStatus(const QString& text, bool error = false);
    QString formatChatInfo(const QJsonObject& obj) const;
    void chooseAttachment(const QString& mediaType);
    void openDroppedMedia(const QString& path);
    void clearAttachment();
    void updateAudioPreview();
    void syncMediaSummary();

    ViewMode viewMode_{ViewMode::Mixed};
    RpcClient* rpc_{nullptr};
    quint64 transcriptRequestSerial_{0};
    QString attachmentTranscript_;
    QString transcriptPath_;
    QVector<QJsonObject> entries_;
    QLabel* infoValue_{nullptr};
    QLabel* statusValue_{nullptr};
    QTableWidget* inboxTable_{nullptr};
    QSpinBox* limitSpin_{nullptr};
    QFormLayout* composeLayout_{nullptr};
    QComboBox* modeCombo_{nullptr};
    QLineEdit* peerEdit_{nullptr};
    QLineEdit* channelEdit_{nullptr};
    QLineEdit* recipientEdit_{nullptr};
    QLineEdit* recipientPubkeyEdit_{nullptr};
    QPlainTextEdit* recipientRsaPubkeyEdit_{nullptr};
    QComboBox* privateKdfCombo_{nullptr};
    QComboBox* privateEncryptionCombo_{nullptr};
    MediaComposerDialog* mediaComposer_{nullptr};
    QLineEdit* attachmentPathEdit_{nullptr};
    QComboBox* mediaTypeCombo_{nullptr};
    QCheckBox* obfuscateAudioCheck_{nullptr};
    QLabel* attachmentStatusValue_{nullptr};
    AudioPreviewWidget* audioPreview_{nullptr};
    QPushButton* openMediaComposerButton_{nullptr};
    QPlainTextEdit* messageEdit_{nullptr};
    QPushButton* clearAttachmentButton_{nullptr};
    QPushButton* sendButton_{nullptr};
};
