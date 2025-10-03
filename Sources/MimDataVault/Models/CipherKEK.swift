//
//  CipherKEK.swift
//  MimDataVault
//
//  Copyright (c) 2025 Luther Stanton
//
//  This source code is licensed under the MIT license found in the
//  LICENSE file in the root directory of this source tree.
//

import Foundation

struct DataEncryptionKey: Codable {
    let cipherBlob: Data

}
  
struct VersionedCipherDEK: Codable {
    let version: Int
    let blob: Data
}

struct VersionedCipherDEKList: Codable {
    let keys: [VersionedCipherDEK]
    
    func latestVersion() -> Int {
        return  keys.reduce(0) { max($1.version, $0) }
    }
       
}
