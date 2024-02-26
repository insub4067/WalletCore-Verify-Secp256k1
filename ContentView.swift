import SwiftUI
import WalletCore

let privateKeyString = """
-----BEGIN EC PRIVATE KEY-----
MHQCAQEEIAFmg/cV5R6IBpUEvx5ujJG1QRXcxP7Oi2bEfVIH5vt+oAcGBSuBBAAKoUQDQgAEfiMYgsKkLIPNTdHaK0v7ilxuExYtQWW7OghRlNB3kBx52tLjPLaz5O0BSTaVe6jg8rUREqwqZ0prHOTyxHgHww==
-----END EC PRIVATE KEY-----
"""
let publicKeyString = """
-----BEGIN PUBLIC KEY-----
MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEfiMYgsKkLIPNTdHaK0v7ilxuExYtQWW7OghRlNB3kBx52tLjPLaz5O0BSTaVe6jg8rUREqwqZ0prHOTyxHgHww==
-----END PUBLIC KEY-----
"""

struct ContentView: View {
    
    var body: some View {
        Button(action: {
            // MARK: - Private Key
            let privateKey = privateKey(string: privateKeyString)
            print("Private Key: ", privateKey)
            
            // MARK: - Signature
            let digest = "hello".data(using: .utf8)
            guard let digest else { return }
            let signature = privateKey?.signAsDER(digest: digest)
            let jws = signature?.base64EncodedString()
            
            // MARK: - Public Key
            let publicKey = publicKey(string: publicKeyString)
            print("Public Key: ", publicKey)
            
            // MARK: - Verify
            let result = publicKey?.verifyAsDER(
                signature: Data(base64Encoded: jws!)!,
                message: digest)
            print("Verify Result: ", result)
        }, label: {
            Text("Button")
        })
    }
}

func removeKeyHeaderAndFooter(keyString: String) -> String {
    keyString
        .replacingOccurrences(of: "-----BEGIN EC PRIVATE KEY-----", with: "")
        .replacingOccurrences(of: "-----END EC PRIVATE KEY-----", with: "")
        .replacingOccurrences(of: "-----BEGIN PUBLIC KEY-----", with: "")
        .replacingOccurrences(of: "-----END PUBLIC KEY-----", with: "")
        .replacingOccurrences(of: "\n", with: "")
        .trimmingCharacters(in: .whitespaces)
}

func privateKey(string: String) -> PrivateKey? {
    let cleanString = removeKeyHeaderAndFooter(keyString: string)
    let hexString = base64ToHexString(cleanString)
    guard let hexString else { return nil }
    let privateKeyStartIndex = hexString.index(hexString.startIndex, offsetBy: 14)
    let privateKeyEndIndex = hexString.index(hexString.startIndex, offsetBy: 77)
    let privateKeyString = String(hexString[privateKeyStartIndex...privateKeyEndIndex])
    let data = Data(hexString: privateKeyString)
    guard let data else { return nil }
    return PrivateKey(data: data)
}

func publicKey(string: String) -> PublicKey? {
    let cleanString = removeKeyHeaderAndFooter(keyString: string)
    let hexString = base64ToHexString(cleanString)
    guard let hexString else { return nil }
    let prefixed = removePublicHexStringPrefix(hexString)
    let keyData = Data(hexString: prefixed)
    guard let keyData else { return nil }
    return PublicKey(data: keyData, type: .secp256k1Extended)
}

public func base64ToHexString(_ base64String: String) -> String? {
    guard let data = Data(base64Encoded: base64String) else {
        return nil
    }
    return data.map { String(format: "%02x", $0) }.joined()
}

public func removePublicHexStringPrefix(_ hexString: String) -> String {
    String(hexString.replacingOccurrences(of: "3056301006072a8648ce3d020106052b8104000a034200", with: ""))
}
