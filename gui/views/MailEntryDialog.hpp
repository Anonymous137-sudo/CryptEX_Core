#pragma once

#include <QJsonObject>
#include <QDialog>

class QLabel;
class QPlainTextEdit;
class QPushButton;

class MailEntryDialog : public QDialog {
    Q_OBJECT
public:
    explicit MailEntryDialog(const QJsonObject& entry, QWidget* parent = nullptr);

private:
    void openAttachment();
    void saveAttachmentCopy();

    QJsonObject entry_;
    QLabel* attachmentInfoValue_{nullptr};
    QLabel* imagePreviewLabel_{nullptr};
    QPlainTextEdit* messageView_{nullptr};
    QPushButton* openAttachmentButton_{nullptr};
    QPushButton* saveAttachmentButton_{nullptr};
};
