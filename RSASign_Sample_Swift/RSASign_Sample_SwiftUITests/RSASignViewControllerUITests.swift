//
//  RSASignViewControllerUITests.swift
//  RSASign_Sample_SwiftUITests
//
//  Created by Yunju Yang on 2022/05/24.
//  Copyright © 2022 ATON. All rights reserved.
//

import XCTest

class RSASignViewControllerUITests: XCTestCase {
    
    private var app:XCUIApplication!
    private var textSignature: XCUIElement!
    private var btnVersion: XCUIElement!
    private var btnGenKey: XCUIElement!
    private var btnGetPubKey: XCUIElement!
    private var btnCreateSign: XCUIElement!
    private var btnVerifySign: XCUIElement!
    private var btnDelKey: XCUIElement!

    override func setUpWithError() throws {
        try super.setUpWithError()
        continueAfterFailure = false
        
        app = XCUIApplication()
        app.launch()
        
        textSignature = app.textFields["textSignature"]
        btnVersion = app.buttons["btnVersion"]
        btnGenKey = app.buttons["btnGenKey"]
        btnGetPubKey = app.buttons["btnGetPubKey"]
        btnCreateSign = app.buttons["btnCreateSign"]
        btnVerifySign = app.buttons["btnVerifySign"]
        btnDelKey = app.buttons["btnDelKey"]
    }

    override func tearDownWithError() throws {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
    }

    func testRSASign() {
        // getVersion
        btnVersion.tap()
        XCTAssertTrue(app.alerts.element.waitForExistence(timeout: 1))
        XCUIApplication().alerts.buttons["OK"].tap()
        
        // generateKey
        btnGenKey.tap()
        XCTAssertTrue(app.alerts.element.waitForExistence(timeout: 5))
        XCUIApplication().alerts.buttons["OK"].tap()
        
        // getPublicKey
        btnGetPubKey.tap()
        XCTAssertTrue(app.alerts.element.waitForExistence(timeout: 1))
        XCUIApplication().alerts.buttons["OK"].tap()
        
        // createSignature
        btnCreateSign.tap()
        XCTAssertTrue(app.alerts.element.waitForExistence(timeout: 1))
        XCUIApplication().alerts.buttons["OK"].tap()
        
        // verifySignature
        btnVerifySign.tap()
        XCTAssertTrue(app.alerts.element.waitForExistence(timeout: 1))
        XCUIApplication().alerts.buttons["OK"].tap()
        
        // deleteKey
        btnDelKey.tap()
        XCTAssertTrue(app.alerts.element.waitForExistence(timeout: 1))
        XCUIApplication().alerts.buttons["OK"].tap()
    }
}
