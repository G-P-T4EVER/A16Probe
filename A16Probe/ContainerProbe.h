#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN
/// Normal snapshot only resolves private symbols; escape trial is opt-in and may use private ContainerManager APIs.
@interface ContainerProbe : NSObject
+ (NSDictionary<NSString *, id> *)snapshot;
/// Actual sandbox-extension attempt; never writes system files. Private ABI may crash.
+ (NSDictionary<NSString *, id> *)runEscapeTrial;
@end
NS_ASSUME_NONNULL_END
