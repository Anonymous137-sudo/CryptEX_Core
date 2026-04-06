#include "SpeechTranscriber.hpp"

#include <QCoreApplication>
#include <QMetaObject>
#include <QPointer>

namespace chatui {

void requestAudioTranscript(const QString&, QObject* context, TranscriptCallback callback) {
    const bool requireContext = context != nullptr;
    QPointer<QObject> guard(context);
    QObject* target = context ? context : QCoreApplication::instance();
    if (!target) {
        return;
    }
    QMetaObject::invokeMethod(target,
                              [guard, requireContext, callback = std::move(callback)]() mutable {
                                  if (requireContext && guard.isNull()) {
                                      return;
                                  }
                                  callback(QString(), QStringLiteral("Transcript preview is not available on this platform build."));
                              },
                              Qt::QueuedConnection);
}

} // namespace chatui
