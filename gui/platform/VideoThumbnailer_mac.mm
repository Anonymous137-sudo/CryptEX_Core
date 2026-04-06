#include "VideoThumbnailer.hpp"

#import <AVFoundation/AVFoundation.h>
#import <CoreGraphics/CoreGraphics.h>
#import <Foundation/Foundation.h>

#include <algorithm>
#include <cmath>

namespace {

QImage cgImageToQImage(CGImageRef imageRef) {
    if (!imageRef) {
        return QImage();
    }
    const size_t width = CGImageGetWidth(imageRef);
    const size_t height = CGImageGetHeight(imageRef);
    if (width == 0 || height == 0) {
        return QImage();
    }

    QImage image(static_cast<int>(width), static_cast<int>(height), QImage::Format_RGBA8888);
    image.fill(Qt::transparent);

    CGColorSpaceRef colorSpace = CGColorSpaceCreateDeviceRGB();
    CGContextRef context = CGBitmapContextCreate(image.bits(),
                                                 width,
                                                 height,
                                                 8,
                                                 static_cast<size_t>(image.bytesPerLine()),
                                                 colorSpace,
                                                 kCGImageAlphaPremultipliedLast | kCGBitmapByteOrder32Big);
    CGColorSpaceRelease(colorSpace);
    if (!context) {
        return QImage();
    }

    CGContextTranslateCTM(context, 0, static_cast<CGFloat>(height));
    CGContextScaleCTM(context, 1.0, -1.0);
    CGContextDrawImage(context, CGRectMake(0, 0, static_cast<CGFloat>(width), static_cast<CGFloat>(height)), imageRef);
    CGContextRelease(context);
    return image.copy();
}

} // namespace

namespace chatui {

QImage requestVideoPosterFrame(const QString& videoPath) {
    if (videoPath.trimmed().isEmpty()) {
        return QImage();
    }

    NSString* nsPath = [NSString stringWithUTF8String:videoPath.toUtf8().constData()];
    if (!nsPath) {
        return QImage();
    }
    NSURL* fileURL = [NSURL fileURLWithPath:nsPath];
    if (!fileURL) {
        return QImage();
    }

    AVURLAsset* asset = [AVURLAsset URLAssetWithURL:fileURL options:nil];
    if (!asset) {
        return QImage();
    }

    AVAssetImageGenerator* generator = [[AVAssetImageGenerator alloc] initWithAsset:asset];
    generator.appliesPreferredTrackTransform = YES;
    generator.maximumSize = CGSizeMake(1280.0, 720.0);

    const Float64 durationSeconds = CMTimeGetSeconds(asset.duration);
    const Float64 captureSeconds = (std::isfinite(durationSeconds) && durationSeconds > 0.35)
        ? std::min<Float64>(durationSeconds * 0.1, 1.0)
        : 0.0;
    const CMTime captureTime = CMTimeMakeWithSeconds(captureSeconds, 600);

    NSError* error = nil;
    CGImageRef frame = [generator copyCGImageAtTime:captureTime actualTime:nil error:&error];
    if (!frame && captureSeconds > 0.0) {
        error = nil;
        frame = [generator copyCGImageAtTime:kCMTimeZero actualTime:nil error:&error];
    }
    if (!frame) {
        return QImage();
    }

    QImage image = cgImageToQImage(frame);
    CGImageRelease(frame);
    return image;
}

} // namespace chatui
