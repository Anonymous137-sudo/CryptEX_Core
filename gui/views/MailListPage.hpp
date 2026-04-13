#pragma once

#include <QJsonObject>
#include <QVector>
#include <QWidget>

class QLabel;
class QLineEdit;
class QPushButton;
class QSplitter;
class QTableWidget;
class QPlainTextEdit;
class RpcClient;

class MailListPage : public QWidget {
    Q_OBJECT
public:
    enum class Folder {
        Inbox,
        Sent,
    };

    explicit MailListPage(Folder folder, QWidget* parent = nullptr);

    void setRpcClient(RpcClient* client);
    void refresh();

signals:
    void replyRequested(const QString& toMailAddress,
                        const QString& subject,
                        const QString& body);

private:
    void setStatus(const QString& text, bool error = false);
    void applyFilter();
    void updatePreview();
    QJsonObject selectedEntry() const;
    QJsonObject entryForVisibleRow(int row) const;
    void deleteSelected();
    void openSelected();
    void replySelected();
    QString folderKey() const;
    QString folderLabel() const;

    Folder folder_;
    RpcClient* rpc_{nullptr};
    QVector<QJsonObject> entries_;
    QLabel* statusValue_{nullptr};
    QLineEdit* filterEdit_{nullptr};
    QTableWidget* table_{nullptr};
    QLabel* subjectValue_{nullptr};
    QLabel* fromValue_{nullptr};
    QLabel* toValue_{nullptr};
    QLabel* timeValue_{nullptr};
    QLabel* metaValue_{nullptr};
    QLabel* attachmentValue_{nullptr};
    QPlainTextEdit* bodyView_{nullptr};
    QPushButton* refreshButton_{nullptr};
    QPushButton* openButton_{nullptr};
    QPushButton* deleteButton_{nullptr};
    QPushButton* replyButton_{nullptr};
    QSplitter* splitter_{nullptr};
};
