#pragma once

#include <QString>
#include <functional>

class QObject;

namespace chatui {

using TranscriptCallback = std::function<void(const QString& transcript, const QString& error)>;

void requestAudioTranscript(const QString& audioPath, QObject* context, TranscriptCallback callback);

} // namespace chatui
