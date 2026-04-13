#pragma once

#include <QJsonObject>
#include <QVector>
#include <QWidget>

class QLabel;
class QLineEdit;
class QComboBox;
class QCheckBox;
class QPushButton;
class QPlainTextEdit;
class RpcClient;

class MailComposePage : public QWidget {
    Q_OBJECT
public:
    explicit MailComposePage(QWidget* parent = nullptr);

    void setRpcClient(RpcClient* client);
    void refresh();
    void setDraft(const QString& toMailAddress = QString(),
                  const QString& subject = QString(),
                  const QString& body = QString());

signals:
    void mailSent();

private:
    void setStatus(const QString& text, bool error = false);
    void refreshAccounts();
    void resolveRecipient(bool userVisible = true);
    void chooseAttachment();
    void clearAttachment();
    void sendMail();
    void refreshSecurityState();
    QString currentFromAlias() const;

    RpcClient* rpc_{nullptr};
    QVector<QJsonObject> accounts_;
    QJsonObject resolvedRecipient_;
    bool twoFactorEnabled_{false};

    QLabel* statusValue_{nullptr};
    QComboBox* fromCombo_{nullptr};
    QLineEdit* toEdit_{nullptr};
    QLineEdit* ccEdit_{nullptr};
    QLineEdit* bccEdit_{nullptr};
    QPushButton* resolveButton_{nullptr};
    QLabel* recipientSummaryValue_{nullptr};
    QLabel* securitySummaryValue_{nullptr};
    QLineEdit* subjectEdit_{nullptr};
    QComboBox* encryptionCombo_{nullptr};
    QComboBox* kdfCombo_{nullptr};
    QComboBox* mediaTypeCombo_{nullptr};
    QLineEdit* attachmentEdit_{nullptr};
    QPushButton* attachButton_{nullptr};
    QPushButton* clearAttachmentButton_{nullptr};
    QCheckBox* obfuscateAudioCheck_{nullptr};
    QLineEdit* transcriptEdit_{nullptr};
    QLineEdit* totpCodeEdit_{nullptr};
    QPlainTextEdit* bodyEdit_{nullptr};
    QPushButton* sendButton_{nullptr};
};
