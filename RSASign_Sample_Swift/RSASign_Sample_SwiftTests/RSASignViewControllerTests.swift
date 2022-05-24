//
//  RSASignViewControllerTests.swift
//  RSASign_Sample_SwiftTests
//
//  Created by Yunju Yang on 2022/05/23.
//  Copyright © 2022 ATON. All rights reserved.
//

import XCTest
@testable import RSASign_Sample_Swift

let RESULT_CODE_SUCCESS =     "0000"
let RSASIGN_VERSION =         "1.0.0"

class RSASignViewControllerTests: XCTestCase {

    private var sut: RSASignViewController!

    override func setUpWithError() throws {
        try super.setUpWithError()
        sut = RSASignViewController()
    }

    override func tearDownWithError() throws {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
    }

    func testGetVersion() {
        // Sync
        let resDic = sut.getVersionSync()
        XCTAssertNotNil(resDic)
        XCTAssertEqual(resDic["resultCode"] as! String, RESULT_CODE_SUCCESS)
        XCTAssertEqual(resDic["libVersion"] as! String, RSASIGN_VERSION)
        
        // Async
        sut.getVersionAsync(callback: {(success: Bool, result: Dictionary) in
            XCTAssertNotNil(success)
            XCTAssertNotNil(result)
            XCTAssertEqual(result["resultCode"] as! String, RESULT_CODE_SUCCESS)
            XCTAssertEqual(result["libVersion"] as! String, RSASIGN_VERSION)
        })
    }
    
    func testGenKey_getPubKey_createSign_verifySign_delKey() {
        let signData: Data! = "original data".data(using: .utf8)
        
        // Sync
        // generateKey
        var resDic = sut.generateKeySync()
        XCTAssertNotNil(resDic)
        XCTAssertEqual(resDic["resultCode"] as! String, RESULT_CODE_SUCCESS)
        let pubKey: Data! = resDic["publicKey"] as? Data
        XCTAssertEqual(pubKey.count, 270)
        
        // getPublicKey
        resDic = sut.getPublicKeySync()
        XCTAssertNotNil(resDic)
        XCTAssertEqual(resDic["resultCode"] as! String, RESULT_CODE_SUCCESS)
        let key: Data! = resDic["publicKey"] as? Data
        XCTAssertEqual(key.count, 270)
        XCTAssertEqual(key, pubKey)
        
        // createSignature
        resDic = sut.createSignatureSync(signData: signData)
        XCTAssertNotNil(resDic)
        XCTAssertEqual(resDic["resultCode"] as! String, RESULT_CODE_SUCCESS)
        let signature: Data! = resDic["signature"] as? Data
        XCTAssertNotNil(signature)
        
        // verifySignature
        resDic = sut.verifySignatureSync(signData: signData, signature: signature)
        XCTAssertNotNil(resDic)
        XCTAssertEqual(resDic["resultCode"] as! String, RESULT_CODE_SUCCESS)
        
        // deleteKey
        resDic = sut.deleteKeySync()
        XCTAssertNotNil(resDic)
        XCTAssertEqual(resDic["resultCode"] as! String, RESULT_CODE_SUCCESS)
        
        // Async
        // generateKey
        sut.generateKeyAsync(callback: {(success: Bool, result: Dictionary) in
            XCTAssertNotNil(success)
            XCTAssertNotNil(result)
            XCTAssertEqual(result["resultCode"] as! String, RESULT_CODE_SUCCESS)
            let pubKey: Data! = result["publicKey"] as? Data
            XCTAssertEqual(pubKey.count, 270)
            
            // getPublicKey
            sut.getPublicKeyAsync(callback: {(success: Bool, result: Dictionary) in
                XCTAssertNotNil(success)
                XCTAssertNotNil(result)
                XCTAssertEqual(result["resultCode"] as! String, RESULT_CODE_SUCCESS)
                let key: Data! = result["publicKey"] as? Data
                XCTAssertEqual(key.count, 270)
                XCTAssertEqual(key, pubKey)
                
                // createSignature
                sut.createSignatureAsync(signData: signData, callback: {(success: Bool, result: Dictionary) in
                    XCTAssertNotNil(success)
                    XCTAssertNotNil(result)
                    XCTAssertEqual(result["resultCode"] as! String, RESULT_CODE_SUCCESS)
                    let sign: Data! = result["signature"] as? Data
                    XCTAssertNotNil(sign)
                    
                    // verifySignature
                    sut.verifySignatureAsync(signData: signData, signature: sign, callback: {(success: Bool, result: Dictionary) in
                        XCTAssertNotNil(success)
                        XCTAssertNotNil(result)
                        XCTAssertEqual(result["resultCode"] as! String, RESULT_CODE_SUCCESS)
                        
                        // deleteKey
                        sut.deleteKeyAsync(callback: {(success: Bool, result: Dictionary) in
                            XCTAssertNotNil(success)
                            XCTAssertNotNil(result)
                            XCTAssertEqual(result["resultCode"] as! String, RESULT_CODE_SUCCESS)
                        })
                    })
                })
            })
        })
    }
}
