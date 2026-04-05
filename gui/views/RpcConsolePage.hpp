#pragma once

#include <QWidget>

class QLineEdit;
class QPlainTextEdit;
class QPushButton;
class RpcClient;
class QJsonValue;

class RpcConsolePage : public QWidget {
    Q_OBJECT
public:
    explicit RpcConsolePage(QWidget* parent = nullptr);

    void setRpcClient(RpcClient* client);

private:
    void executeCommand();
    void appendTranscript(const QString& line);
    QString stringifyJsonValue(const QJsonValue& value) const;

    RpcClient* rpc_{nullptr};
    QLineEdit* methodEdit_{nullptr};
    QPlainTextEdit* paramsEdit_{nullptr};
    QPlainTextEdit* transcriptView_{nullptr};
    QPushButton* executeButton_{nullptr};
    QPushButton* clearButton_{nullptr};
};
