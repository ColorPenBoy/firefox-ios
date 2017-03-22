/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

import Foundation
import FxA

/// Class to wrap ecec which does the decryption with OpenSSL.
/// This supports aesgcm and the newer aes128gcm.
/// This will also support the generation of keys to register with a push server.
/// For each standard of decryption, two methods are supplied: one with Data parameters and return value, 
/// and one with a String based one.
class PushDecrypt {
    // stateless
}

// AES128GCM
extension PushDecrypt {
    func aes128gcm(payload data: String, decryptWith privateKey: String, authenticateWith authKey: String) throws -> String {
        guard let authSecret = authKey.base64DecodedData,
            let rawRecvPrivKey = privateKey.base64DecodedData,
            let payload = data.base64DecodedData else {
                throw PushDecryptError.base64DecodeError
        }

        let decrypted = try aes128gcm(payload: payload,
                             decryptWith: rawRecvPrivKey,
                             authenticateWith: authSecret)

        guard let plaintext = decrypted.utf8EncodedString else {
            throw PushDecryptError.utf8EncodingError
        }

        return plaintext
    }

    func aes128gcm(payload: Data, decryptWith rawRecvPrivKey: Data, authenticateWith authSecret: Data) throws -> Data {
        var plaintextLen = ece_aes128gcm_plaintext_max_length(payload.getBytes(), payload.count) + 1
        var plaintext = [UInt8](repeating: 0, count: plaintextLen)

        let err = ece_webpush_aes128gcm_decrypt(
                rawRecvPrivKey.getBytes(), rawRecvPrivKey.count,
                authSecret.getBytes(), authSecret.count,
                payload.getBytes(), payload.count,
                &plaintext, &plaintextLen)

        if err != 0 {
            throw PushDecryptError.decryptionError(errCode: Int(err))
        }
        
        return Data(bytes: plaintext, count: plaintextLen)
    }
}

// AESGCM
extension PushDecrypt {
    func aesgcm(ciphertext data: String, decryptWith privateKey: String, authenticateWith authKey: String, encryptionHeader: String, cryptoKeyHeader: String) throws -> String {
        guard let authSecret = authKey.base64DecodedData,
            let rawRecvPrivKey = privateKey.base64DecodedData,
            let ciphertext = data.base64DecodedData else {
                throw PushDecryptError.base64DecodeError
        }

        let decrypted = try aesgcm(ciphertext: ciphertext,
                          decryptWith: rawRecvPrivKey,
                          authenticateWith: authSecret,
                          encryptionHeader: encryptionHeader,
                          cryptoKeyHeader: cryptoKeyHeader)

        guard let plaintext = decrypted.utf8EncodedString else {
            throw PushDecryptError.utf8EncodingError
        }

        return plaintext
    }

    func aesgcm(ciphertext: Data, decryptWith rawRecvPrivKey: Data, authenticateWith authSecret: Data, encryptionHeader: String, cryptoKeyHeader: String) throws -> Data {
        var plaintextLen = ece_aesgcm_plaintext_max_length(ciphertext.count) + 1
        var plaintext = [UInt8](repeating: 0, count: plaintextLen)

        let err = ece_webpush_aesgcm_decrypt(
                rawRecvPrivKey.getBytes(), rawRecvPrivKey.count,
                authSecret.getBytes(), authSecret.count,
                cryptoKeyHeader, encryptionHeader,
                ciphertext.getBytes(), ciphertext.count,
                &plaintext, &plaintextLen)

        if (err != 0) {
            throw PushDecryptError.decryptionError(errCode: Int(err))
        }

        return Data(bytes: plaintext, count: plaintextLen)
    }
}

enum PushDecryptError: Error {
    case base64DecodeError
    case decryptionError(errCode: Int)
    case utf8EncodingError
}

extension String {
    /// Returns a base64 decoding of the given string.
    /// The string is allowed to be padded (unlike using Data(base64Encoded:,options:))
    /// What is padding?: http://stackoverflow.com/a/26632221
    var base64DecodedData: Data? {
        // We call this method twice: once with the last two args as nil, 0 – this gets us the length
        // of the decoded string.
        let length = ece_base64url_decode(self, self.characters.count, ECE_BASE64URL_REJECT_PADDING, nil, 0)
        guard length > 0 else {
            return nil
        }

        // The second time, we actually decode, and copy it into a made to measure byte array.
        var bytes = [UInt8](repeating: 0, count: length)
        let checkLength = ece_base64url_decode(self, self.characters.count, ECE_BASE64URL_REJECT_PADDING, &bytes, length)
        guard checkLength == length else {
            return nil
        }

        return Data(bytes: bytes, count: length)
    }
}
