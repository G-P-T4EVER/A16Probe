#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN
/// Observation only: never calls resolved private functions or loads new images.
@interface ContainerProbe : NSObject
+ (NSDictionary<NSString *, id> *)snapshot;
@end
NS_ASSUME_NONNULL_END
