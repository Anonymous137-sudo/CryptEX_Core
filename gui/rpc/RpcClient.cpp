#include "RpcClient.hpp"

#include <QJsonDocument>
#include <QJsonObject>
#include <QFile>
#include <QHostAddress>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QPointer>
#include <QSslCertificate>
#include <QSslConfiguration>
#include <QSslError>

namespace {

bool isLoopbackHost(const QString& host) {
    if (host.compare(QStringLiteral("localhost"), Qt::CaseInsensitive) == 0) {
        return true;
    }
    const QHostAddress address(host);
    return !address.isNull() && address.isLoopback();
}

} // namespace

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
    if (settings_.url.scheme().compare(QStringLiteral("https"), Qt::CaseInsensitive) == 0) {
        auto sslConfig = QSslConfiguration::defaultConfiguration();
        if (!settings_.caCertificatePath.trimmed().isEmpty()) {
            QFile caFile(settings_.caCertificatePath);
            if (caFile.open(QIODevice::ReadOnly)) {
                const auto certs = QSslCertificate::fromData(caFile.readAll(), QSsl::Pem);
                if (!certs.isEmpty()) {
                    auto authorities = sslConfig.caCertificates();
                    authorities.append(certs);
                    sslConfig.setCaCertificates(authorities);
                }
            }
        }
        request.setSslConfiguration(sslConfig);
    }

    QPointer<QObject> guard(context);
    auto* reply = network_.post(request, QJsonDocument(body).toJson(QJsonDocument::Compact));
    connect(reply, &QNetworkReply::sslErrors, this, [this, reply](const QList<QSslError>& errors) {
        if (settings_.allowSelfSigned && isLoopbackHost(settings_.url.host())) {
            QList<QSslError> ignorable;
            bool saw_unexpected = false;
            for (const auto& error : errors) {
                switch (error.error()) {
                case QSslError::SelfSignedCertificate:
                case QSslError::SelfSignedCertificateInChain:
                case QSslError::CertificateUntrusted:
                case QSslError::UnableToGetLocalIssuerCertificate:
                case QSslError::HostNameMismatch:
                    ignorable.push_back(error);
                    break;
                default:
                    saw_unexpected = true;
                    break;
                }
            }
            if (!saw_unexpected && !ignorable.isEmpty()) {
                reply->ignoreSslErrors(ignorable);
                return;
            }
        }

        QStringList parts;
        for (const auto& error : errors) {
            parts.push_back(error.errorString());
        }
        const QString message = parts.isEmpty()
            ? QStringLiteral("TLS verification failed.")
            : QStringLiteral("TLS verification failed: %1").arg(parts.join(QStringLiteral("; ")));
        emit transportError(message);
    });
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
