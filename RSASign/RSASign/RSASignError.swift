//
//  RSASignError.swift
//  RSASign
//
//  Created by Yunju Yang on 2021/09/30.
//

public struct RSASignError {

    public static let RSASIGN_LIBRARY_VERSION             = "1.0.0"
    
    
    // MARK Define Constant
    /// Result Code
    public static let def_resultCode                   = "resultCode"
    
    /// Result Msg
    public static let def_resultMsg                    = "resultMsg"
    
    /// library version
    public static let def_libVersion                  = "libVersion"
    
    /// public key
    public static let def_publicKey                   = "publicKey"
    
    /// signature
    public static let def_signature                   = "signature"
    
    
    
    // MARK: Define Success Code
    /// Success
    public static let RSASIGN_SUCCESS                      = "0000"
    public static let RSASIGN_SUCCESS_MSG                  = "Success"
    
    
    // MARK: Define Error Code
    /// E000 - General Fail
    public static let RSASIGN_ERR_E000                    = "E000"
    public static let RSASIGN_ERR_E000_MSG                = "General Fail"
    
    /// E001 - Unsupported OS Version
    public static let RSASIGN_ERR_E001                    = "E001"
    public static let RSASIGN_ERR_E001_MSG                = "Unsupported OS Version"
    
    /// E002 - Missing required parameter
    public static let RSASIGN_ERR_E002                    = "E002"
    public static let RSASIGN_ERR_E002_MSG                = "Missing required parameter"
    
    /// E003 - RSA key not found
    public static let RSASIGN_ERR_E003                    = "E003";
    public static let RSASIGN_ERR_E003_MSG                = "RSA key not found";

    /// E004 - Public key not found
    public static let RSASIGN_ERR_E004                    = "E004";
    public static let RSASIGN_ERR_E004_MSG                = "Public key not found";

    /// E005 - RSA key generating failed
    public static let RSASIGN_ERR_E005                    = "E005";
    public static let RSASIGN_ERR_E005_MSG                = "RSA key generating failed";

    /// E006 - RSA signature failed
    public static let RSASIGN_ERR_E006                    = "E006";
    public static let RSASIGN_ERR_E006_MSG                = "RSA signature failed";

    /// E007 - RSA signature verify failed
    public static let RSASIGN_ERR_E007                    = "E007";
    public static let RSASIGN_ERR_E007_MSG                = "RSA signature verify failed";
}
