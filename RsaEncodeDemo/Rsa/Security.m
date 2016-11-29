//
//  Security.m
//  Security
//

#import "Security.h"

@implementation Security

@synthesize privateKey = _privateKey;
@synthesize publicKey = _publicKey;

static Security *sharedSecurity = nil;

+ (Security *)sharedSecurity {
	if (sharedSecurity == nil) {
		sharedSecurity = [[super allocWithZone:NULL] init];
	}
    
	return sharedSecurity;
}

+ (id)allocWithZone:(NSZone *)zone {
	return [[self sharedSecurity] retain];
}

+ (id)copyWithZone:(NSZone *)zone {
	return self;
}

- (id)retain {
	return self;
}

- (NSUInteger)retainCount {
	return NSUIntegerMax;
}

- (oneway void)release {
	// do nothing
}

- (OSStatus)extractEveryThingFromPKCS12File:(NSString *)pkcsPath passphrase:(NSString *)pkcsPassword {
	SecIdentityRef identity;
	SecTrustRef trust;
	OSStatus status = -1;
	if (_privateKey == nil) {
        
		NSData *p12Data = [NSData dataWithContentsOfFile:pkcsPath];
		if (p12Data) {
			CFStringRef password = (CFStringRef)pkcsPassword;
			const void *keys[] = {
				kSecImportExportPassphrase
			};
			const void *values[] = {
				password
			};
			CFDictionaryRef options = CFDictionaryCreate(kCFAllocatorDefault, keys, values, 1, NULL, NULL);
			CFArrayRef items = CFArrayCreate(kCFAllocatorDefault, NULL, 0, NULL);
			status = SecPKCS12Import((CFDataRef)p12Data, options, &items);
			if (status == errSecSuccess) {
				CFDictionaryRef identity_trust_dic = CFArrayGetValueAtIndex(items, 0);
				identity = (SecIdentityRef)CFDictionaryGetValue(identity_trust_dic, kSecImportItemIdentity);
				trust = (SecTrustRef)CFDictionaryGetValue(identity_trust_dic, kSecImportItemTrust);
				// certs数组中包含了所有的证书
				CFArrayRef certs = (CFArrayRef)CFDictionaryGetValue(identity_trust_dic, kSecImportItemCertChain);
				if ([(NSArray *)certs count] && trust && identity) {
					// 如果没有下面一句，自签名证书的评估信任结果永远是kSecTrustResultRecoverableTrustFailure
					status = SecTrustSetAnchorCertificates(trust, certs);
					if (status == errSecSuccess) {
						SecTrustResultType trustResultType;
						// 通常, 返回的trust result type应为kSecTrustResultUnspecified，如果是，就可以说明签名证书是可信的
						status = SecTrustEvaluate(trust, &trustResultType);
						if ((trustResultType == kSecTrustResultUnspecified || trustResultType == kSecTrustResultProceed) && status == errSecSuccess) {
							// 证书可信，可以提取私钥与公钥，然后可以使用公私钥进行加解密操作
							status = SecIdentityCopyPrivateKey(identity, &_privateKey);
							if (status == errSecSuccess && _privateKey) {
								// 成功提取私钥
								NSLog(@"Get private key successfully~ %@", _privateKey);
							}
							/*
							 // 这里，不提取公钥，提取公钥的任务放在extractPublicKeyFromCertificateFile方法中
							_publicKey = SecTrustCopyPublicKey(trust);
							if (_publicKey) {
								// 成功提取公钥
							}
							 */
						}
					}
				}
			}
			if (options) {
				CFRelease(options);
			}
		}
	}
	return status;
}

- (OSStatus)extractPublicKeyFromCertificateFile:(NSString *)certPath {
	OSStatus status = -1;
	if (_publicKey == nil) {
		SecTrustRef trust;
		SecTrustResultType trustResult;
		NSData *derData = [NSData dataWithContentsOfFile:certPath];
		if (derData) {
			SecCertificateRef cert = SecCertificateCreateWithData(kCFAllocatorDefault, (CFDataRef)derData);
			SecPolicyRef policy = SecPolicyCreateBasicX509();
			status = SecTrustCreateWithCertificates(cert, policy, &trust);
			if (status == errSecSuccess && trust) {
				NSArray *certs = [NSArray arrayWithObject:(id)cert];
				status = SecTrustSetAnchorCertificates(trust, (CFArrayRef)certs);
				if (status == errSecSuccess) {
					status = SecTrustEvaluate(trust, &trustResult);
					// 自签名证书可信
					if (status == errSecSuccess && (trustResult == kSecTrustResultUnspecified || trustResult == kSecTrustResultProceed)) {
						_publicKey = SecTrustCopyPublicKey(trust);
						if (_publicKey) {
							NSLog(@"Get public key successfully~ %@", _publicKey);
						}
						if (cert) {
							CFRelease(cert);
						}
						if (policy) {
							CFRelease(policy);
						}
						if (trust) {
							CFRelease(trust);
						}
					}
				}
			}
		}
	}
	return status;
}

- (NSData *)encryptWithPublicKey:(NSData *)plainData {
    
	// 分配内存块，用于存放加密后的数据段
	size_t cipherBufferSize = SecKeyGetBlockSize(_publicKey);
	uint8_t *cipherBuffer = malloc(cipherBufferSize * sizeof(uint8_t));
	/*
	 为什么这里要减12而不是减11?
	 苹果官方文档给出的说明是，加密时，如果sec padding使用的是kSecPaddingPKCS1，
	 那么支持的最长加密长度为SecKeyGetBlockSize()-11，
	 这里说的最长加密长度，我估计是包含了字符串最后的空字符'\0'，
	 因为在实际应用中我们是不考虑'\0'的，所以，支持的真正最长加密长度应为SecKeyGetBlockSize()-12
	*/
	double totalLength = [plainData length];
	size_t blockSize = cipherBufferSize - 12;// 使用cipherBufferSize - 11是错误的!
	size_t blockCount = (size_t)ceil(totalLength / blockSize);
	NSMutableData *encryptedData = [NSMutableData data];
	// 分段加密
	for (int i = 0; i < blockCount; i++) {
		NSUInteger loc = i * blockSize;
		// 数据段的实际大小。最后一段可能比blockSize小。
		int dataSegmentRealSize = MIN(blockSize, [plainData length] - loc);
		// 截取需要加密的数据段
		NSData *dataSegment = [plainData subdataWithRange:NSMakeRange(loc, dataSegmentRealSize)];
		OSStatus status = SecKeyEncrypt(_publicKey, kSecPaddingPKCS1, (const uint8_t *)[dataSegment bytes], dataSegmentRealSize, cipherBuffer, &cipherBufferSize);
		if (status == errSecSuccess) {
			NSData *encryptedDataSegment = [[NSData alloc] initWithBytes:(const void *)cipherBuffer length:cipherBufferSize];
			// 追加加密后的数据段
			[encryptedData appendData:encryptedDataSegment];
			[encryptedDataSegment release];
		} else {
			if (cipherBuffer) {
				free(cipherBuffer);
			}
			return nil;
		}
	}
	if (cipherBuffer) {
		free(cipherBuffer);
	}
	return encryptedData;
}

- (NSData *)decryptWithPrivateKey:(NSData *)cipherData {

	// 分配内存块，用于存放解密后的数据段
	size_t plainBufferSize = SecKeyGetBlockSize(_privateKey);
	NSLog(@"plainBufferSize = %zd", plainBufferSize);
	uint8_t *plainBuffer = malloc(plainBufferSize * sizeof(uint8_t));
	// 计算数据段最大长度及数据段的个数
	double totalLength = [cipherData length];
	size_t blockSize = plainBufferSize;
	size_t blockCount = (size_t)ceil(totalLength / blockSize);
	NSMutableData *decryptedData = [NSMutableData data];
	// 分段解密
	for (int i = 0; i < blockCount; i++) {
		NSUInteger loc = i * blockSize;
		// 数据段的实际大小。最后一段可能比blockSize小。
		int dataSegmentRealSize = MIN(blockSize, totalLength - loc);
		// 截取需要解密的数据段
		NSData *dataSegment = [cipherData subdataWithRange:NSMakeRange(loc, dataSegmentRealSize)];
		OSStatus status = SecKeyDecrypt(_privateKey, kSecPaddingPKCS1, (const uint8_t *)[dataSegment bytes], dataSegmentRealSize, plainBuffer, &plainBufferSize);
		if (status == errSecSuccess) {
			NSData *decryptedDataSegment = [[NSData alloc] initWithBytes:(const void *)plainBuffer length:plainBufferSize];
			[decryptedData appendData:decryptedDataSegment];
			[decryptedDataSegment release];
		} else {
			if (plainBuffer) {
				free(plainBuffer);
			}
			return nil;
		}
	}
	if (plainBuffer) {
		free(plainBuffer);
	}
	return decryptedData;
}

@end
