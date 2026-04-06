#pragma once

#include <QDialog>
#include <QJsonObject>

class QLabel;
class QPlainTextEdit;
class QPushButton;

class ChatEntryDialog : public QDialog {
    Q_OBJECT
public:
    enum class Mode {
        Forum,
        PrivateHistory,
    };

    explicit ChatEntryDialog(Mode mode, QWidget* parent = nullptr);

    void setEntry(const QJsonObject& entry);

signals:
    void publicCommentRequested(const QString& channel, const QString& draft);
    void privateReplyRequested(const QString& address,
                               const QString& pubkeyB64,
                               const QString& peer,
                               const QString& draft);
    void deleteRequested(const QString& messageId);

private:
    static QString formatTimestamp(qint64 unixTs);
    void updateVoteLabel();
    void handleCommentOrReply();
    void shareEntry();
    void deleteEntry();
    void openAttachment();

    Mode mode_;
    QJsonObject entry_;
    QLabel* headingValue_{nullptr};
    QPlainTextEdit* messageValue_{nullptr};
    QLabel* senderValue_{nullptr};
    QLabel* recipientValue_{nullptr};
    QLabel* channelValue_{nullptr};
    QLabel* timeValue_{nullptr};
    QLabel* peerValue_{nullptr};
    QLabel* statusValue_{nullptr};
    QLabel* messageIdValue_{nullptr};
    QLabel* contentTypeValue_{nullptr};
    QLabel* attachmentPathValue_{nullptr};
    QPlainTextEdit* transcriptValue_{nullptr};
    QLabel* voteValue_{nullptr};
    QPushButton* commentButton_{nullptr};
    QPushButton* shareButton_{nullptr};
    QPushButton* deleteButton_{nullptr};
    QPushButton* openAttachmentButton_{nullptr};
    QPushButton* upvoteButton_{nullptr};
    QPushButton* downvoteButton_{nullptr};
    int voteDelta_{0};
};
