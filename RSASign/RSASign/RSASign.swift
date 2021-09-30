//
//  RSASign.swift
//  RSASign
//
//  Created by Yunju Yang on 2021/09/30.
//

import Foundation

import CommonCrypto.CommonDigest
import CommonCrypto.CommonHMAC
import CommonCrypto.CommonCryptor

public class RSASign {
    
    public typealias RSASignCallback = (Bool, Dictionary<String, Any>) -> Void
    
    public init() {}
    
    private var prvKey: SecKey?
    private var pubKey: SecKey?
    
    
    /// Get library version (Sync)
    ///
    /// - Returns: Dictionary<String, Any> (resultCode, resultMsg, libVersion)
    public func getVersion() -> Dictionary<String, Any> {
        var resDic: Dictionary<String, Any> = [:]
        resDic[RSASignError.def_resultCode] = RSASignError.RSASIGN_SUCCESS
        resDic[RSASignError.def_resultMsg] = RSASignError.RSASIGN_SUCCESS_MSG
        
        // iOS version check
        if #available(iOS 8.0, *) {}
        else {
            resDic[RSASignError.def_resultCode] = RSASignError.RSASIGN_ERR_E001
            resDic[RSASignError.def_resultMsg] = RSASignError.RSASIGN_ERR_E001_MSG
            return resDic
        }
        
        resDic[RSASignError.def_libVersion] = RSASignError.RSASIGN_LIBRARY_VERSION
        return resDic
    }
    
    /// Get library version (Async)
    ///
    /// - Parameter callback: RSASignCallback
    public func getVersion(callback: RSASignCallback) -> Void {
        let resDic: Dictionary = self.getVersion()
        callback(resDic[RSASignError.def_resultCode] as! String == RSASignError.RSASIGN_SUCCESS, resDic)
    }
    
    
    /// Generate RSA 2048 Key pair (Sync)
    ///
    /// - Returns: Dictionary<String, Any> (resultCode, resultMsg, publicKey)
    public func generateKey() -> Dictionary<String, Any> {
        var resDic: Dictionary<String, Any> = [:]
        resDic[RSASignError.def_resultCode] = RSASignError.RSASIGN_SUCCESS
        resDic[RSASignError.def_resultMsg] = RSASignError.RSASIGN_SUCCESS_MSG
        
        // iOS version check
        if #available(iOS 8.0, *) {}
        else {
            resDic[RSASignError.def_resultCode] = RSASignError.RSASIGN_ERR_E001
            resDic[RSASignError.def_resultMsg] = RSASignError.RSASIGN_ERR_E001_MSG
            return resDic
        }
        
        // delete RSA key
        resDic = self.deleteKey()
        let delCode: String = resDic[RSASignError.def_resultCode] as! String
        if delCode != RSASignError.RSASIGN_SUCCESS && delCode != RSASignError.RSASIGN_ERR_E003 {
            return resDic
        }
        
        let keyAlias: String = "RSASIGN_KEY_ALIAS"
        
        // Key tag
        let pubTag = String.init(format: "%@_PUB", keyAlias)
        let prvTag = String.init(format: "%@_PRV", keyAlias)
        
        // Generate key pair
        let pubKeyAttr = [
            kSecAttrIsPermanent: false,
            kSecAttrApplicationTag: pubTag.data(using: .utf8)!,
            kSecAttrAccessible: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            kSecClass: kSecClassKey,
            kSecReturnRef: true,
            kSecReturnData: true] as CFDictionary
        
        let prvKeyAttr = [
            kSecAttrIsPermanent: false,
            kSecAttrApplicationTag: prvTag.data(using: .utf8)!,
            kSecAttrAccessible: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            kSecClass: kSecClassKey,
            kSecReturnRef: true,
            kSecReturnData: true] as CFDictionary
        
        let attributes = [
            kSecAttrKeyType: kSecAttrKeyTypeRSA,
            kSecAttrKeySizeInBits: 2048,
//            kSecAttrTokenID: kSecAttrTokenIDSecureEnclave,
//            kSecAttrCanSign: true,
            kSecPublicKeyAttrs: pubKeyAttr,
            kSecPrivateKeyAttrs: prvKeyAttr] as CFDictionary
        
        var pubData = Data()
        
        // Upper iOS 10
        if #available(iOS 10.0, *) {
            var errRef: Unmanaged<CFError>?
            prvKey = SecKeyCreateRandomKey(attributes, &errRef)
            
            if prvKey == nil {
                resDic[RSASignError.def_resultCode] = RSASignError.RSASIGN_ERR_E005
                resDic[RSASignError.def_resultMsg] = RSASignError.RSASIGN_ERR_E005_MSG
                return resDic
            } else {
                pubKey = SecKeyCopyPublicKey(prvKey!)
                
                if pubKey == nil {
                    resDic[RSASignError.def_resultCode] = RSASignError.RSASIGN_ERR_E005
                    resDic[RSASignError.def_resultMsg] = RSASignError.RSASIGN_ERR_E005_MSG
                    return resDic
                }
            }
            
            // SecKey -> Data
            var cfError: Unmanaged<CFError>?
            pubData = SecKeyCopyExternalRepresentation(pubKey!, &cfError) as! Data
            
        } else {
            let status = SecKeyGeneratePair(attributes, &pubKey, &prvKey)
            if status != errSecSuccess {
                resDic[RSASignError.def_resultCode] = RSASignError.RSASIGN_ERR_E005
                resDic[RSASignError.def_resultMsg] = RSASignError.RSASIGN_ERR_E005_MSG
                return resDic
            } else {
                if pubKey == nil {
                    resDic[RSASignError.def_resultCode] = RSASignError.RSASIGN_ERR_E005
                    resDic[RSASignError.def_resultMsg] = RSASignError.RSASIGN_ERR_E005_MSG
                    return resDic
                }
            }
            
            // SecKey -> Data
            var finalPub: AnyObject?
            
            let attributes = [
                kSecClass: kSecClassKey,
                kSecAttrApplicationTag: pubTag,
                kSecAttrKeyType: kSecAttrKeyTypeRSA,
                kSecAttrKeyClass: kSecAttrKeyClassPublic,
                kSecReturnData: true] as CFDictionary
            
            let ostatus = SecItemCopyMatching(attributes, &finalPub)
            if ostatus == errSecSuccess {
                if finalPub == nil {
                    resDic[RSASignError.def_resultCode] = RSASignError.RSASIGN_ERR_E003
                    resDic[RSASignError.def_resultMsg] = RSASignError.RSASIGN_ERR_E003_MSG
                    return resDic
                } else {
                    pubData = (finalPub as! SecKey) as! Data
                }
            } else {
                resDic[RSASignError.def_resultCode] = RSASignError.RSASIGN_ERR_E005
                resDic[RSASignError.def_resultMsg] = RSASignError.RSASIGN_ERR_E005_MSG
                return resDic
            }
        }
        
        if pubData.count == 0 {
            resDic[RSASignError.def_resultCode] = RSASignError.RSASIGN_ERR_E004
            resDic[RSASignError.def_resultMsg] = RSASignError.RSASIGN_ERR_E004_MSG
            return resDic
        } else {
            resDic[RSASignError.def_resultCode] = RSASignError.RSASIGN_SUCCESS
            resDic[RSASignError.def_resultMsg] = RSASignError.RSASIGN_SUCCESS_MSG
            resDic[RSASignError.def_publicKey] = pubData
        }
        
        return resDic
    }
    
    /// Generate RSA 2048 Key pair (Async)
    ///
    /// - Parameter callback: RSASignCallback
    public func generateKey(callback: RSASignCallback) -> Void {
        let resDic: Dictionary = self.generateKey()
        callback(resDic[RSASignError.def_resultCode] as! String == RSASignError.RSASIGN_SUCCESS, resDic)
    }
    
    
    /// get Public Key (Sync)
    ///
    /// - Returns: Dictionary<String, Any> (resultCode, resultMsg, publicKey)
    public func getPublicKey() -> Dictionary<String, Any> {
        var resDic: Dictionary<String, Any> = [:]
        resDic[RSASignError.def_resultCode] = RSASignError.RSASIGN_SUCCESS
        resDic[RSASignError.def_resultMsg] = RSASignError.RSASIGN_SUCCESS_MSG
        
        // iOS version check
        if #available(iOS 8.0, *) {}
        else {
            resDic[RSASignError.def_resultCode] = RSASignError.RSASIGN_ERR_E001
            resDic[RSASignError.def_resultMsg] = RSASignError.RSASIGN_ERR_E001_MSG
            return resDic
        }
        
        // get public key
        if pubKey == nil {
            resDic[RSASignError.def_resultCode] = RSASignError.RSASIGN_ERR_E003
            resDic[RSASignError.def_resultMsg] = RSASignError.RSASIGN_ERR_E003_MSG
            return resDic
        } else {
            // SecKey -> Data
            var pubData = Data()
            
            // Upper iOS 10
            if #available(iOS 10.0, *) {
                var errRef: Unmanaged<CFError>?
                pubData = SecKeyCopyExternalRepresentation(pubKey!, &errRef) as! Data
            } else {
                let keyAlias: String = "RSASIGN_KEY_ALIAS"
                let pubTag = String.init(format: "%@_PUB", keyAlias)
                
                var finalPub: AnyObject?
                let attributes = [
                    kSecClass: kSecClassKey,
                    kSecAttrApplicationTag: pubTag,
                    kSecAttrKeyType: kSecAttrKeyTypeRSA,
                    kSecAttrKeyClass: kSecAttrKeyClassPublic,
                    kSecReturnData: true] as CFDictionary
                
                let ostatus = SecItemCopyMatching(attributes, &finalPub)
                if ostatus == errSecSuccess {
                    if finalPub == nil {
                        resDic[RSASignError.def_resultCode] = RSASignError.RSASIGN_ERR_E003
                        resDic[RSASignError.def_resultMsg] = RSASignError.RSASIGN_ERR_E003_MSG
                        return resDic
                    } else {
                        pubData = (finalPub as! SecKey) as! Data
                    }
                } else {
                    resDic[RSASignError.def_resultCode] = RSASignError.RSASIGN_ERR_E005
                    resDic[RSASignError.def_resultMsg] = RSASignError.RSASIGN_ERR_E005_MSG
                    return resDic
                }
            }
            
            if pubData.count == 0 {
                resDic[RSASignError.def_resultCode] = RSASignError.RSASIGN_ERR_E004
                resDic[RSASignError.def_resultMsg] = RSASignError.RSASIGN_ERR_E004_MSG
                return resDic
            } else {
                resDic[RSASignError.def_publicKey] = pubData
            }
        }
        
        return resDic
    }
    
    /// get Public Key (Async)
    ///
    /// - Parameter callback: RSASignCallback
    public func getPublicKey(callback: RSASignCallback) -> Void {
        let resDic: Dictionary = self.getPublicKey()
        callback(resDic[RSASignError.def_resultCode] as! String == RSASignError.RSASIGN_SUCCESS, resDic)
    }
    
    
    /// Signature with PKCS1 & sha256 (Sync)
    ///
    /// - Parameter signData: Data to sign
    /// - Returns: Dictionary<String, Any> (resultCode, resultMsg, signature)
    public func createSignature(signData: Data) -> Dictionary<String, Any> {
        var resDic: Dictionary<String, Any> = [:]
        resDic[RSASignError.def_resultCode] = RSASignError.RSASIGN_SUCCESS
        resDic[RSASignError.def_resultMsg] = RSASignError.RSASIGN_SUCCESS_MSG
        
        // check parameter
        if signData.count == 0 {
            resDic[RSASignError.def_resultCode] = RSASignError.RSASIGN_ERR_E002
            resDic[RSASignError.def_resultMsg] = RSASignError.RSASIGN_ERR_E002_MSG
            return resDic
        }
        
        // iOS version check
        if #available(iOS 8.0, *) {}
        else {
            resDic[RSASignError.def_resultCode] = RSASignError.RSASIGN_ERR_E001
            resDic[RSASignError.def_resultMsg] = RSASignError.RSASIGN_ERR_E001_MSG
            return resDic
        }
        
        // get private key
        if prvKey == nil {
            resDic[RSASignError.def_resultCode] = RSASignError.RSASIGN_ERR_E003
            resDic[RSASignError.def_resultMsg] = RSASignError.RSASIGN_ERR_E003_MSG
            return resDic
        } else {
            // sign data
            let hashData: Data = self.sha256Data(data: signData)
            
            // signature
            var signature = Data()
            
            // Upper iOS 10
            if #available(iOS 10.0, *) {
                let canSign = SecKeyIsAlgorithmSupported(prvKey!, SecKeyOperationType.sign, SecKeyAlgorithm.rsaSignatureDigestPKCS1v15SHA256)
                
                if canSign == true {
                    var error: Unmanaged<CFError>?
                    signature = SecKeyCreateSignature(prvKey!, SecKeyAlgorithm.rsaSignatureDigestPKCS1v15SHA256, ((hashData as? CFData?)!!), &error) as! Data
                    if signature.count == 0 {
                        resDic[RSASignError.def_resultCode] = RSASignError.RSASIGN_ERR_E006
                        resDic[RSASignError.def_resultMsg] = RSASignError.RSASIGN_ERR_E006_MSG
                        return resDic
                    } else {
                        resDic[RSASignError.def_resultCode] = RSASignError.RSASIGN_SUCCESS
                        resDic[RSASignError.def_signature] = signature
                    }
                } else {
                    resDic[RSASignError.def_resultCode] = RSASignError.RSASIGN_ERR_E006
                    resDic[RSASignError.def_resultMsg] = RSASignError.RSASIGN_ERR_E006_MSG
                    return resDic
                }
            } else {
                
                var signLength = 32
//                var sign = [UInt8](repeating: 0, count: signLength)
                var pSign = UnsafeMutablePointer<UInt8>.allocate(capacity: 32)
                
                let status = SecKeyRawSign(prvKey!, SecPadding.PKCS1SHA256, [UInt8](hashData), hashData.count, pSign, &signLength)
                if status != errSecSuccess {
                    resDic[RSASignError.def_resultCode] = RSASignError.RSASIGN_ERR_E006
                    resDic[RSASignError.def_resultMsg] = RSASignError.RSASIGN_ERR_E006_MSG
                    return resDic
                } else {
                    if signLength == 0 {
                        resDic[RSASignError.def_resultCode] = RSASignError.RSASIGN_ERR_E006
                        resDic[RSASignError.def_resultMsg] = RSASignError.RSASIGN_ERR_E006_MSG
                        return resDic
                    } else {
                        signature = Data.init(bytes: pSign, count: signLength)
                        resDic[RSASignError.def_signature] = signature
                    }
                }
            }
        }
        
        return resDic
    }
    
    /// Signature with PKCS1 & sha256 (Async)
    ///
    /// - Parameters:
    ///     - signData: Data to sign
    ///     - callback: RSASignCallback
    public func createSignature(signData: Data, callback: RSASignCallback) -> Void {
        let resDic: Dictionary = self.createSignature(signData: signData)
        callback(resDic[RSASignError.def_resultCode] as! String == RSASignError.RSASIGN_SUCCESS, resDic)
    }
    
    
    /// Verify RSA Signature (Sync)
    ///
    /// - Parameters:
    ///     - signData: Data to sign
    ///     - signature: signature to verify
    /// - Returns: Dictionary<String, Any> (resultCode, resultMsg)
    public func verifySignature(signData: Data, signature: Data) -> Dictionary<String, Any> {
        var resDic: Dictionary<String, Any> = [:]
        resDic[RSASignError.def_resultCode] = RSASignError.RSASIGN_SUCCESS
        resDic[RSASignError.def_resultMsg] = RSASignError.RSASIGN_SUCCESS_MSG
        
        // check parameter
        if signData.count == 0 || signature.count == 0 {
            resDic[RSASignError.def_resultCode] = RSASignError.RSASIGN_ERR_E002
            resDic[RSASignError.def_resultMsg] = RSASignError.RSASIGN_ERR_E002_MSG
            return resDic
        }
        
        // iOS version check
        if #available(iOS 8.0, *) {}
        else {
            resDic[RSASignError.def_resultCode] = RSASignError.RSASIGN_ERR_E001
            resDic[RSASignError.def_resultMsg] = RSASignError.RSASIGN_ERR_E001_MSG
            return resDic
        }
        
        // get public key
        if pubKey == nil {
            resDic[RSASignError.def_resultCode] = RSASignError.RSASIGN_ERR_E003
            resDic[RSASignError.def_resultMsg] = RSASignError.RSASIGN_ERR_E003_MSG
            return resDic
        } else {
            // sign data
            let hashData: Data = self.sha256Data(data: signData)
            
            // Upper iOS 10
            if #available(iOS 10.0, *) {
                let canVerify = SecKeyIsAlgorithmSupported(pubKey!, SecKeyOperationType.verify, SecKeyAlgorithm.rsaSignatureDigestPKCS1v15SHA256)
                
                if canVerify == true {
                    var error: Unmanaged<CFError>?
                    let result: Bool = SecKeyVerifySignature(pubKey!, SecKeyAlgorithm.rsaSignatureDigestPKCS1v15SHA256, ((hashData as? CFData?)!!), ((signature as? CFData?)!!), &error)
                    if result == false {
                        resDic[RSASignError.def_resultCode] = RSASignError.RSASIGN_ERR_E007
                        resDic[RSASignError.def_resultMsg] = RSASignError.RSASIGN_ERR_E007_MSG
                        return resDic
                    }
                } else {
                    resDic[RSASignError.def_resultCode] = RSASignError.RSASIGN_ERR_E007
                    resDic[RSASignError.def_resultMsg] = RSASignError.RSASIGN_ERR_E007_MSG
                    return resDic
                }
            }
        }
        
        return resDic
    }
    
    /// Verify RSA Signature  (Async)
    ///
    /// - Parameters:
    ///     - signData: Data to sign
    ///     - signature: signature to verify
    ///     - callback: RSASignCallback
    public func verifySignature(signData: Data, signature: Data, callback: RSASignCallback) -> Void {
        let resDic: Dictionary = self.verifySignature(signData: signData, signature: signature)
        callback(resDic[RSASignError.def_resultCode] as! String == RSASignError.RSASIGN_SUCCESS, resDic)
    }
    
    
    /// Delete RSA 2048 Key pair (Sync)
    ///
    /// - Returns: Dictionary<String, Any> (resultCode, resultMsg)
    public func deleteKey() -> Dictionary<String, Any> {
        var resDic: Dictionary<String, Any> = [:]
        resDic[RSASignError.def_resultCode] = RSASignError.RSASIGN_SUCCESS
        resDic[RSASignError.def_resultMsg] = RSASignError.RSASIGN_SUCCESS_MSG
        
        // iOS version check
        if #available(iOS 8.0, *) {}
        else {
            resDic[RSASignError.def_resultCode] = RSASignError.RSASIGN_ERR_E001
            resDic[RSASignError.def_resultMsg] = RSASignError.RSASIGN_ERR_E001_MSG
            return resDic
        }
        
        // check private key
        if prvKey == nil {
            resDic[RSASignError.def_resultCode] = RSASignError.RSASIGN_ERR_E003
            resDic[RSASignError.def_resultMsg] = RSASignError.RSASIGN_ERR_E003_MSG
            return resDic
        } else {
            // delete SecKeyRef
            pubKey = nil
            prvKey = nil
        }
        
        return resDic
    }
    
    /// Delete RSA 2048 Key pair (Async)
    ///
    /// - Parameter callback: RSASignCallback
    public func deleteKey(callback: RSASignCallback) -> Void {
        let resDic: Dictionary = self.deleteKey()
        callback(resDic[RSASignError.def_resultCode] as! String == RSASignError.RSASIGN_SUCCESS, resDic)
    }
    
    
    // MARK: Common APIs
    func sha256Data(data: Data) -> Data
    {
        var hash = [UInt8](repeating: 0,  count: Int(CC_SHA256_DIGEST_LENGTH))
        data.withUnsafeBytes {
            _ = CC_SHA256($0.baseAddress, CC_LONG(data.count), &hash)
        }
        return Data(hash)
    }
}
