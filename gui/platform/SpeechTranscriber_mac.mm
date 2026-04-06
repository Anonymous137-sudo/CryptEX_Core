#include "SpeechTranscriber.hpp"

#include <QCoreApplication>
#include <QMetaObject>
#include <QPointer>

#import <Foundation/Foundation.h>
#import <Speech/Speech.h>

@interface CryptexSpeechJob : NSObject
@property(nonatomic, strong) SFSpeechRecognizer* recognizer;
@property(nonatomic, strong) SFSpeechURLRecognitionRequest* request;
@property(nonatomic, strong) SFSpeechRecognitionTask* task;
@property(nonatomic, copy) void (^completion)(NSString* transcript, NSString* errorText);
@end

@implementation CryptexSpeechJob
@end

namespace {

static void dispatchTranscript(QObject* context,
                               chatui::TranscriptCallback callback,
                               const QString& transcript,
                               const QString& error) {
    const bool requireContext = context != nullptr;
    QPointer<QObject> guard(context);
    QObject* target = context ? context : QCoreApplication::instance();
    if (!target) {
        return;
    }
    QMetaObject::invokeMethod(target,
                              [guard, requireContext, callback = std::move(callback), transcript, error]() mutable {
                                  if (requireContext && guard.isNull()) {
                                      return;
                                  }
                                  callback(transcript, error);
                              },
                              Qt::QueuedConnection);
}

static NSMutableSet<CryptexSpeechJob*>* activeJobs() {
    static NSMutableSet<CryptexSpeechJob*>* jobs = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        jobs = [[NSMutableSet alloc] init];
    });
    return jobs;
}

static NSString* authStatusText(SFSpeechRecognizerAuthorizationStatus status) {
    switch (status) {
        case SFSpeechRecognizerAuthorizationStatusDenied:
            return @"Speech recognition permission denied.";
        case SFSpeechRecognizerAuthorizationStatusRestricted:
            return @"Speech recognition is restricted on this system.";
        case SFSpeechRecognizerAuthorizationStatusNotDetermined:
            return @"Speech recognition permission has not been granted yet.";
        case SFSpeechRecognizerAuthorizationStatusAuthorized:
            break;
    }
    return @"Speech recognition is unavailable.";
}

} // namespace

namespace chatui {

void requestAudioTranscript(const QString& audioPath, QObject* context, TranscriptCallback callback) {
    if (audioPath.trimmed().isEmpty()) {
        dispatchTranscript(context, std::move(callback), QString(), QStringLiteral("Select an audio file to generate a transcript."));
        return;
    }

    NSString* nsPath = [NSString stringWithUTF8String:audioPath.toUtf8().constData()];
    NSURL* fileURL = [NSURL fileURLWithPath:nsPath];
    if (!fileURL) {
        dispatchTranscript(context, std::move(callback), QString(), QStringLiteral("Unable to open the selected audio file for transcription."));
        return;
    }

    [SFSpeechRecognizer requestAuthorization:^(SFSpeechRecognizerAuthorizationStatus status) {
        if (status != SFSpeechRecognizerAuthorizationStatusAuthorized) {
            dispatchTranscript(context,
                               std::move(callback),
                               QString(),
                               QString::fromUtf8([authStatusText(status) UTF8String]));
            return;
        }

        dispatch_async(dispatch_get_main_queue(), ^{
            SFSpeechRecognizer* recognizer = [[SFSpeechRecognizer alloc] initWithLocale:[NSLocale currentLocale]];
            if (!recognizer) {
                dispatchTranscript(context,
                                   std::move(callback),
                                   QString(),
                                   QStringLiteral("Speech recognizer could not be initialized."));
                return;
            }

            if (@available(macOS 13.0, *)) {
                if (recognizer.supportsOnDeviceRecognition) {
                    // Keep the request local when the platform supports it.
                }
            }

            CryptexSpeechJob* job = [[CryptexSpeechJob alloc] init];
            job.recognizer = recognizer;
            job.request = [[SFSpeechURLRecognitionRequest alloc] initWithURL:fileURL];
            if (@available(macOS 13.0, *)) {
                if (recognizer.supportsOnDeviceRecognition) {
                    job.request.requiresOnDeviceRecognition = YES;
                }
            }

            __block CryptexSpeechJob* jobRef = job;
            job.completion = ^(NSString* transcript, NSString* errorText) {
                if (jobRef) {
                    [activeJobs() removeObject:jobRef];
                    jobRef = nil;
                }
                dispatchTranscript(context,
                                   std::move(callback),
                                   transcript ? QString::fromUtf8(transcript.UTF8String) : QString(),
                                   errorText ? QString::fromUtf8(errorText.UTF8String) : QString());
            };

            [activeJobs() addObject:job];
            job.task = [recognizer recognitionTaskWithRequest:job.request
                                                resultHandler:^(SFSpeechRecognitionResult* result, NSError* error) {
                if (error) {
                    job.completion(nil, error.localizedDescription ?: @"Transcript generation failed.");
                    return;
                }
                if (!result) {
                    job.completion(nil, @"Transcript generation returned no result.");
                    return;
                }
                if (result.isFinal) {
                    NSString* transcript = result.bestTranscription.formattedString ?: @"";
                    job.completion(transcript, nil);
                }
            }];
        });
    }];
}

} // namespace chatui
