//
//  ViewController.m
//  RsaEncodeDemo
//
//  Created by 张舒 on 16/11/25.
//  Copyright © 2016年 张舒. All rights reserved.
//

#import "ViewController.h"
#define SCREENWIDTH self.view.frame.size.width
#define SCREENHEIGHT  self.view.frame.size.height
#import "Security.h"
#import "RSAEncryptor.h"
#import "Base64.h"

@interface ViewController ()<UITextFieldDelegate,UITextViewDelegate>
@property(nonatomic,strong)UIButton *encodeBtn;
@property(nonatomic,strong)UIButton *decryptBtn;
@property(nonatomic,strong)UITextField *oldTextfield;
@property(nonatomic,strong)UITextView *encodeTextView;
@property(nonatomic,strong)UITextView *decryptTextView;
@property(nonatomic,strong)Security *security;
@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    [self.view addSubview:self.encodeBtn];
    [self.view addSubview:self.decryptBtn];
    [self.view addSubview:self.oldTextfield];
    [self.view addSubview:self.encodeTextView];
    [self.view addSubview:self.decryptTextView];
    self.title = @"RSA加解密";
    [self fetchKey];
}

-(void)fetchKey{
    NSString *pkcsPath = [[NSBundle mainBundle] pathForResource:@"p" ofType:@"p12"];
    // 下面的与上面的一样
    //	NSString *pkcsPath = [[NSBundle mainBundle] pathForResource:@"pkcs-daniate" ofType:@"pfx"];
    NSString *certPath = [[NSBundle mainBundle] pathForResource:@"rsacert" ofType:@"der"];
    _security = [Security sharedSecurity];
    OSStatus status = -1;
    // 取得私钥，文件保护密码为111111
    status = [_security extractEveryThingFromPKCS12File:pkcsPath passphrase:@"111111"];
    // 取得公钥
    status = [_security extractPublicKeyFromCertificateFile:certPath];

}
- (BOOL)shouldAutorotateToInterfaceOrientation:(UIInterfaceOrientation)interfaceOrientation
{
    if ([[UIDevice currentDevice] userInterfaceIdiom] == UIUserInterfaceIdiomPhone) {
        return (interfaceOrientation != UIInterfaceOrientationPortraitUpsideDown);
    } else {
        return YES;
    }
}
-(UITextField *)oldTextfield{
    if (!_oldTextfield) {
        _oldTextfield = [[UITextField alloc]initWithFrame:CGRectMake(20, 64, SCREENWIDTH-40, 44)];
        _oldTextfield.borderStyle = UITextBorderStyleRoundedRect;
        _oldTextfield.placeholder = @"请输入加密数据";
        _oldTextfield.delegate = self;
    }
    return _oldTextfield;
}
-(UITextView *)encodeTextView{
    if (!_encodeTextView) {
        _encodeTextView = [[UITextView alloc]initWithFrame:CGRectMake(20, 120, SCREENWIDTH-40, 100)];
        _encodeTextView.backgroundColor = [UIColor cyanColor];
        _encodeTextView.delegate = self;
    }
    return _encodeTextView;
}
-(UITextView *)decryptTextView{
    if (!_decryptTextView) {
        _decryptTextView = [[UITextView alloc]initWithFrame:CGRectMake(20, 240, SCREENWIDTH-40, 100)];
        _decryptTextView.backgroundColor = [UIColor yellowColor];
        _decryptTextView.delegate = self;
    }
    return _decryptTextView;
}
-(UIButton *)encodeBtn{
    if (!_encodeBtn) {
        _encodeBtn = [UIButton buttonWithType:UIButtonTypeCustom];
        [_encodeBtn setTitle:@"加密" forState:UIControlStateNormal];
        _encodeBtn.frame = CGRectMake(0, SCREENHEIGHT-44, SCREENWIDTH/2, 44);
        [_encodeBtn setBackgroundColor:[UIColor blueColor]];
        [_encodeBtn addTarget:self action:@selector(pressEncodeBtn) forControlEvents:UIControlEventTouchUpInside];
    }
    return _encodeBtn;
}
-(UIButton *)decryptBtn{
    if (!_decryptBtn) {
        _decryptBtn = [UIButton buttonWithType:UIButtonTypeCustom];
        [_decryptBtn setTitle:@"解密" forState:UIControlStateNormal];
        [_decryptBtn addTarget:self action:@selector(pressDecryptBtn) forControlEvents:UIControlEventTouchUpInside];
        _decryptBtn.frame = CGRectMake(SCREENWIDTH/2+1, SCREENHEIGHT-44, SCREENWIDTH/2-1, 44);
        [_decryptBtn setBackgroundColor:[UIColor blueColor]];
    }
    return _decryptBtn;
}
-(void)pressEncodeBtn{
    NSData *plainData = [_oldTextfield.text dataUsingEncoding:NSUTF8StringEncoding];
    NSData *encrypted = [_security encryptWithPublicKey:plainData];
    NSString *encryptText = [Base64 stringByEncodingData:encrypted];
    _encodeTextView.text = encryptText;
    NSLog(@"密文: %@", encryptText);
}
-(void)pressDecryptBtn{
    NSData *decryptdata =   [[NSData alloc] initWithBase64EncodedString:_encodeTextView.text options:NSDataBase64DecodingIgnoreUnknownCharacters];
    NSData *decrypted = [_security decryptWithPrivateKey:decryptdata];
    NSString *decryptedText = [[NSString alloc] initWithData:decrypted encoding:NSUTF8StringEncoding];
    _decryptTextView.text = decryptedText;
    NSLog(@"明文: %@", decryptedText);

    
}
- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}


@end
