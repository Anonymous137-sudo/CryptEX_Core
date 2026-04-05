#include "RpcClient.hpp"

#include <QJsonDocument>
#include <QJsonObject>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QPointer>

RpcClient::RpcClient(QObject* parent)
    : QObject(parent) {
}

void RpcClient::setSettings(const Settings& settings) {
    settings_ = settings;
}

QByteArray RpcClient::authorizationHeader() const {
    const auto credential = (settings_.username + ":" + settings_.password).toUtf8().toBase64();
    return "Basic " + credential;
}

void RpcClient::call(const QString& method,
                     const QJsonArray& params,
                     QObject* context,
                     SuccessHandler onSuccess,
                     ErrorHandler onError) {
    if (!settings_.url.isValid() || settings_.url.isEmpty()) {
        if (onError) onError("RPC URL is not configured.");
        return;
    }

    QJsonObject body;
    body.insert(QStringLiteral("jsonrpc"), QStringLiteral("2.0"));
    body.insert(QStringLiteral("id"), QString::number(nextId_++));
    body.insert(QStringLiteral("method"), method);
    body.insert(QStringLiteral("params"), params);

    QNetworkRequest request(settings_.url);
    request.setHeader(QNetworkRequest::ContentTypeHeader, QStringLiteral("application/json"));
    if (!settings_.username.isEmpty()) {
        request.setRawHeader("Authorization", authorizationHeader());
    }

    QPointer<QObject> guard(context);
    auto* reply = network_.post(request, QJsonDocument(body).toJson(QJsonDocument::Compact));
    connect(reply, &QNetworkReply::finished, this, [this, reply, guard, context, onSuccess = std::move(onSuccess), onError = std::move(onError)]() mutable {
        if (context && guard.isNull()) {
            reply->deleteLater();
            return;
        }

        const auto statusAttr = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute);
        const int statusCode = statusAttr.isValid() ? statusAttr.toInt() : 0;
        const auto responseBody = QString::fromUtf8(reply->readAll());

        if (reply->error() != QNetworkReply::NoError) {
            QString message = reply->errorString();
            if (statusCode > 0) {
                message = QStringLiteral("HTTP %1: %2").arg(statusCode).arg(message);
            }
            if (!responseBody.trimmed().isEmpty()) {
                message += QStringLiteral(" | %1").arg(responseBody.trimmed());
            }
            reply->deleteLater();
            emit transportError(message);
            if (onError) onError(message);
            return;
        }

        QJsonParseError parseError;
        const auto doc = QJsonDocument::fromJson(responseBody.toUtf8(), &parseError);
        reply->deleteLater();
        if (parseError.error != QJsonParseError::NoError || !doc.isObject()) {
            const QString message = QStringLiteral("Invalid RPC JSON response.");
            emit transportError(message);
            if (onError) onError(message);
            return;
        }

        const auto obj = doc.object();
        if (obj.contains(QStringLiteral("error")) && !obj.value(QStringLiteral("error")).isNull()) {
            const auto errObj = obj.value(QStringLiteral("error")).toObject();
            QString message = errObj.value(QStringLiteral("message")).toString();
            if (message.isEmpty()) message = QStringLiteral("Unknown RPC error.");
            if (onError) onError(message);
            return;
        }

        if (onSuccess) onSuccess(obj.value(QStringLiteral("result")));
    });
}
