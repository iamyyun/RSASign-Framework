//
//  RSASignViewController.swift
//  MobileRSign_iOS_Swift
//
//  Created by Yunju on 03/09/2019.
//  Copyright © 2019 ATON. All rights reserved.
//

import UIKit
import CommonCrypto.CommonDigest
import CommonCrypto.CommonHMAC
import CommonCrypto.CommonCryptor
import RSASign

let RESULT_CODE_SUCCESS =     "0000"
let rsaSign: RSASign    = RSASign()

class RSASignViewController: UIViewController, UITextViewDelegate {
    
    @IBOutlet weak var textSignature: UITextView!
    
    private var bgTap: UITapGestureRecognizer?
    
    public typealias RSASignVCCallback = (Bool, Dictionary<String, Any>) -> Void
    
    override func viewDidLoad() {
        super.viewDidLoad()
        
        bgTap = UITapGestureRecognizer.init(target: self, action: #selector(writeFinished))
        
        NotificationCenter.default.addObserver(self, selector: #selector(keyboardWillShow), name: UIResponder.keyboardWillShowNotification, object: nil)
        NotificationCenter.default.addObserver(self, selector: #selector(keyboardWillHide), name: UIResponder.keyboardWillHideNotification, object: nil)
    }
    
    // MARK: Common Functions
    @objc func writeFinished()
    {
        self.view.endEditing(true)
    }
    
    func showResult (title: String, message: String)
    {
        let alert = UIAlertController.init(title: title, message: message, preferredStyle: UIAlertController.Style.alert)
        alert.addAction(UIAlertAction.init(title: "OK", style: UIAlertAction.Style.default, handler: {
            action in
            alert.dismiss(animated: true, completion: nil)
            
        }))
        
        self.present(alert, animated: true, completion: nil)
    }
    
    func jsonStringPrint (dic: [AnyHashable : Any]) -> String
    {
        let jsonData: Data! = try? JSONSerialization.data(withJSONObject: dic, options: JSONSerialization.WritingOptions.prettyPrinted)
        let jsonString: String! = String(data: jsonData, encoding: String.Encoding.utf8)
        
        return jsonString ?? ""
    }
    
    func hexToBytes(_ string: String) -> [UInt8]? {
        let length = string.count
        if length & 1 != 0 {
            return nil
        }
        var bytes = [UInt8]()
        bytes.reserveCapacity(length/2)
        var index = string.startIndex
        for _ in 0..<length/2 {
            let nextIndex = string.index(index, offsetBy: 2)
            if let b = UInt8(string[index..<nextIndex], radix: 16) {
                bytes.append(b)
            } else {
                return nil
            }
            index = nextIndex
        }
        return bytes
    }
    
    // MARK: UITextViewDelegate
    func textViewShouldEndEditing(_ textView: UITextView) -> Bool {
        textView.resignFirstResponder()
        return true
    }
    
    // MARK: Actions
    @IBAction func actionBtnVersion(_ sender: Any) {
        let title: String! = "Get library version"
        var msg: String! = ""
        
        // Sync
        let resDic: Dictionary! = getVersionSync()
        msg = self.jsonStringPrint(dic: resDic)
        self.showResult(title: title, message: msg)
        
        // Async
//        getVersionAsync(callback: {(success: Bool, result: Dictionary) in
//            msg = self.jsonStringPrint(dic: result)
//            self.showResult(title: title, message: msg)
//        })
    }
    
    @IBAction func actionBtnGenKey(_ sender: Any) {
        let title: String! = "Generate RSA key"
        var msg: String! = ""
        
        self.textSignature.text = ""
        
        // Sync
        var resDic: Dictionary! = generateKeySync()
        if (resDic["resultCode"] as! String? == RESULT_CODE_SUCCESS) {
            let pubKey: Data! = resDic["publicKey"] as? Data
            resDic["publicKey"] = pubKey.hexEncodedString()
        }
        msg = self.jsonStringPrint(dic: resDic);
        self.showResult(title: title, message: msg)
        
        // Async
//        generateKeyAsync(callback: { (success: Bool, result: Dictionary) in
//            if success == true {
//                var resDic: Dictionary = result;
//                let pubKey: Data! = resDic["publicKey"] as? Data
//                resDic["publicKey"] = pubKey.hexEncodedString()
//            }
//            msg = self.jsonStringPrint(dic: resDic);
//            self.showResult(title: title, message: msg)
//        })
    }
    
    @IBAction func actionBtnGetPubKey(_ sender: Any) {
        let title: String! = "Get public key"
        var msg: String! = ""

        // Sync
        var resDic: Dictionary! = getPublicKeySync()
        if (resDic["resultCode"] as! String? == RESULT_CODE_SUCCESS) {
            let pubKey: Data! = resDic["publicKey"] as? Data
            resDic["publicKey"] = pubKey.hexEncodedString()
        }
        msg = self.jsonStringPrint(dic: resDic);
        self.showResult(title: title, message: msg)
        
        // Async
//        getPublicKeyAsync(callback: { (success: Bool, result: Dictionary) in
//            if success == true {
//                var resDic: Dictionary = result;
//                let pubKey: Data! = resDic["publicKey"] as? Data
//                resDic["publicKey"] = pubKey.hexEncodedString()
//            }
//            msg = self.jsonStringPrint(dic: resDic);
//            self.showResult(title: title, message: msg)
//        })
    }
    
    @IBAction func actionBtnCreateSign(_ sender: Any) {
        let title: String! = "Create Signature"
        var msg: String! = ""
        
        let signData: Data! = "original data".data(using: .utf8)

        // Sync
        var resDic: Dictionary! = createSignatureSync(signData: signData)
        if resDic["resultCode"] as! String? == RESULT_CODE_SUCCESS {
            let signature: Data! = resDic["signature"] as? Data
            resDic["signature"] = signature.hexEncodedString()
            
            self.textSignature.text = signature.hexEncodedString()
        }
        msg = self.jsonStringPrint(dic: resDic);
        self.showResult(title: title, message: msg)
            
        // Async
//        createSignatureAsync(signData: signData, callback: { (success: Bool, result: Dictionary) in
//            if success == true {
//                let signature: Data! = resDic["signature"] as? Data
//                resDic["signature"] = signature.hexEncodedString()
//
//                self.textSignature.text = signature.hexEncodedString()
//            }
//            msg = self.jsonStringPrint(dic: result);
//            self.showResult(title: title, message: msg)
//        })
    }
    
    @IBAction func actionBtnVerifySign(_ sender: Any) {
        let title: String! = "Verify Signature"
        var msg: String! = ""
        
        let signData: Data! = "original data".data(using: .utf8)
        let signature: [UInt8]! = self.hexToBytes(self.textSignature.text)
        let signatureData: NSData! = NSData(bytes: signature, length: signature.count)
        
        // Sync
        let resDic: Dictionary! = verifySignatureSync(signData: signData, signature: signatureData as Data)
        msg = self.jsonStringPrint(dic: resDic);
        self.showResult(title: title, message: msg)
        
        // Async
//        verifySignatureAsync(signData: signData, signature: signatureData as Data, callback:{ (success: Bool, result: Dictionary) in
//            msg = self.jsonStringPrint(dic: resDic);
//            self.showResult(title: title, message: msg)
//        })
    }
    
    @IBAction func actionBtnDelKey(_ sender: Any) {
        let title: String! = "Delete RSA key"
        var msg: String! = ""
        
        self.textSignature.text = ""
        
        // Sync
        let resDic: Dictionary! = deleteKeySync()
        msg = self.jsonStringPrint(dic: resDic);
        self.showResult(title: title, message: msg)
        
        // Async
//        deleteKeyAsync(callback: { (success: Bool, result: Dictionary) in
//            msg = self.jsonStringPrint(dic: result);
//            self.showResult(title: title, message: msg)
//        })
    }
    
    
    // MARK: RSASign Functions
    func getVersionSync() -> Dictionary<String, Any> {
        return rsaSign.getVersion()
    }
    
    func getVersionAsync(callback: RSASignVCCallback) -> Void {
        rsaSign.getVersion(callback: {(success: Bool, result: Dictionary) in
            callback(success, result)
        })
    }
    
    func generateKeySync() -> Dictionary<String, Any> {
        return rsaSign.generateKey()
    }
    
    func generateKeyAsync(callback: RSASignVCCallback) -> Void {
        rsaSign.generateKey(callback: {(success:Bool, result: Dictionary) in
            callback(success, result)
        })
    }
    
    func getPublicKeySync() -> Dictionary<String, Any> {
        return rsaSign.getPublicKey()
    }
    
    func getPublicKeyAsync(callback: RSASignVCCallback) -> Void {
        rsaSign.getPublicKey(callback: {(success: Bool, result: Dictionary) in
            callback(success, result)
        })
    }
    
    func createSignatureSync(signData: Data) -> Dictionary<String, Any> {
        return rsaSign.createSignature(signData: signData)
    }
    
    func createSignatureAsync(signData: Data, callback: RSASignVCCallback) -> Void {
        rsaSign.createSignature(signData: signData, callback: {(success: Bool, result: Dictionary) in
            callback(success, result)
        })
    }
    
    func verifySignatureSync(signData: Data, signature: Data) -> Dictionary<String, Any> {
        return rsaSign.verifySignature(signData: signData, signature: signature)
    }
    
    func verifySignatureAsync(signData: Data, signature: Data, callback: RSASignVCCallback) -> Void {
        rsaSign.verifySignature(signData: signData, signature: signature, callback: {(success: Bool, result: Dictionary) in
            callback(success, result)
        })
    }
    
    func deleteKeySync() -> Dictionary<String, Any> {
        return rsaSign.deleteKey()
    }
    
    func deleteKeyAsync(callback: RSASignVCCallback) -> Void {
        rsaSign.deleteKey(callback: {(success: Bool, result: Dictionary) in
            callback(success, result)
        })
    }
    
    // MARK: Keyboard Notification
    @objc func keyboardWillShow(notification: NSNotification) {
        view.addGestureRecognizer(bgTap!)
    }
    
    @objc func keyboardWillHide(notification: NSNotification) {
        view.removeGestureRecognizer(bgTap!)
    }
    
}
