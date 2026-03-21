#pragma once

#include <QObject>
#include <QJsonArray>
#include <QJsonValue>
#include <QNetworkAccessManager>
#include <QUrl>
#include <functional>

class RpcClient : public QObject {
    Q_OBJECT
public:
    struct Settings {
        QUrl url;
        QString username;
        QString password;
    };

    explicit RpcClient(QObject* parent = nullptr);

    void setSettings(const Settings& settings);
    Settings settings() const { return settings_; }

    using SuccessHandler = std::function<void(const QJsonValue&)>;
    using ErrorHandler = std::function<void(const QString&)>;

    void call(const QString& method,
              const QJsonArray& params,
              QObject* context,
              SuccessHandler onSuccess,
              ErrorHandler onError = {});

signals:
    void transportError(const QString& message);

private:
    QByteArray authorizationHeader() const;

    QNetworkAccessManager network_;
    Settings settings_;
    quint64 nextId_{1};
};
