//
//  DataVaultService.swift
//  MimDataVault
//
//  Copyright (c) 2025 Luther Stanton
//
//  This source code is licensed under the MIT license found in the
//  LICENSE file in the root directory of this source tree.
//

import Foundation
import CryptoKit

public enum DataVaultError: Error {
    case failedToCreateSecureStorageKey
    case errorCastingTagToData
    
    
    case errorRetrievingSecureStorageKey
    case errorRetrievingApplicationSupportLocation
    case errorCreatingKeyStorageLocation
    case errorWritingKeyToStorage
    case errorMaskingKeyFromBackup
    
    case unknownError
    case kekExists
    case dekExists
    case kekNotFound
    case dekDoesNotExist
    case errorValidatingSecureStorageKeyExistence
    case errorFetchingKEK
    case errorFetchingDEK
    case keyConsistencyError
    case errorSecureStorageKeyDoesNotExist
    case errorDeletingSecureStorageKey
    case errorSecureStorageKeyExists
    case errorDeletingDEK
    case errorCreatingEncryptedDEK
    case encryptionFailed
}

private struct EncryptionEnvelope {
    
    static func build(version: UInt8 = 1,
                          keyIdHash: UInt32,
                          nonce: Data,
                          aad: Data?,
                          ciphertext: Data) -> Data
        {
            var out = Data()
            out.append(version)
            
            var keyIdBE = keyIdHash.bigEndian
            withUnsafeBytes(of: &keyIdBE) { out.append(contentsOf: $0) }

            guard nonce.count <= UInt8.max else { fatalError("nonce too large") }
            out.append(UInt8(nonce.count))
            out.append(nonce)

            let aadLen: UInt16 = UInt16(aad?.count ?? 0)
            var aadLenBE = aadLen.bigEndian
            withUnsafeBytes(of: &aadLenBE) { out.append(contentsOf: $0) }
            if let aad = aad { out.append(aad) }

            var ctLenBE = UInt32(ciphertext.count).bigEndian
            withUnsafeBytes(of: &ctLenBE) { out.append(contentsOf: $0) }
            out.append(ciphertext)

            return out
}


public class DataVaultService {
    
    private struct Constants {
        static let kekPrefix: String = "com.MimDataVault.DataVault.DataVaultKey.kek"
        static let dekPrefix: String = "com.MimDataVault.DataVault.DataVaultKey.dek"
    }
    
    public init() {}
    
    public func secureStorageKeyExists(keyTag: String) throws -> Bool {
        
        let kekExists: Bool
        let dekExists: Bool
        
        do {
            kekExists = try self.kekExists(kekTag: kekTag(keyTag))
        } catch {
            print("DataVaultService::secureStorageKeyExists - error encountered checking for kek existence - error says: \(error)")
            throw DataVaultError.errorValidatingSecureStorageKeyExistence
        }
        
        do {
            dekExists = try self.dekExists(dekTag: dekTag(keyTag))
        } catch {
            print("DataVaultService::secureStorageKeyExists - error encountered checking for dek existence - error says: \(error)")
            throw DataVaultError.errorValidatingSecureStorageKeyExistence
        }
        
        if kekExists != dekExists {
            throw DataVaultError.keyConsistencyError
        }
        
        return kekExists
    }
    
    public func createSecureStorageKey(keyTag: String, forceOverwrite: Bool = false, excludeFromBackup: Bool = true) throws {
        
        print("DataVaultService::createSecureStorageKey() - creating secure storage key")
        
        if !forceOverwrite {
            
            do {
                if try secureStorageKeyExists(keyTag: keyTag) {
                    print("DataVaultService::createSecureStorageKey() - Key requested w/o force overwrite already exists")
                    throw DataVaultError.errorSecureStorageKeyExists
                }
            } catch {
                print("DataVaultService::createSecureStorageKey() - encountered an error checking for key existence - error says:[\(error)]")
                throw DataVaultError.errorValidatingSecureStorageKeyExistence
            }
        }
        
        do {
            try createKEK(kekTag: kekTag(keyTag), forceOverwrite: forceOverwrite)
        } catch {
            print("DataVaultService::createSecureStorageKey() - kek generation failed")
            throw DataVaultError.failedToCreateSecureStorageKey
        }
        
        let dataEncryptionKey = SymmetricKey(size: .bits256)
        
        let cipherDEKBytes: Data
        do {
            cipherDEKBytes = try {
                var dekBytes = dataEncryptionKey.withUnsafeBytes { Data($0) }
                defer { dekBytes.wipe() }
                return try encryptDEK(dek: dekBytes, kekTag: kekTag(keyTag))
            }()
        } catch {
            print("DataVaultService::createSecureStorageKey() - kek encryption failed")
            throw DataVaultError.failedToCreateSecureStorageKey
        }
        
        do {
            try writeCipherDEK(DataEncryptionKey(blob: cipherDEKBytes), as: dekTag(keyTag), excludeFromBackup: excludeFromBackup)
        } catch {
            print("DataVaultService::createSecureStorageKey() - error persisting wrapped DEK: \(error)")
            throw DataVaultError.errorWritingKeyToStorage
        }
        
        print("DataVaultService::createSecureStorageKey() - secure storage key created successfully")
    }
    
    public func deleteSecureStorageKey(keyTag: String, forceDelete: Bool = false) throws {
        
        print("DataVaultService::deleteSecureStorageKey() - deleting signing key with tag:[\(keyTag)]...")
        
        let kekTag = kekTag(keyTag)
        let dekTag = dekTag(keyTag)
        
        let kekExists: Bool
        do {
            kekExists = try self.kekExists(kekTag: kekTag)
        } catch {
            print("DataVaultService::deleteSecureStorageKey() - Encountered error verifying kek exists - error says:[\(error)]")
            throw DataVaultError.errorValidatingSecureStorageKeyExistence
        }
        
        let dekExists: Bool
        do {
            dekExists = try self.dekExists(dekTag: dekTag)
        } catch {
            print("DataVaultService::deleteSecureStorageKey() - Encountered error verifying dek exists - error says:[\(error)]")
            throw DataVaultError.errorValidatingSecureStorageKeyExistence
        }
        
        if !(kekExists && dekExists) && !forceDelete {
            print("DataVaultService::deleteSecureStorageKey() - preflight failed - not deleting.")
            throw DataVaultError.errorSecureStorageKeyDoesNotExist
        }
        
        if dekExists {
            
            let dekFileURL: URL
            
            do {
                dekFileURL = try self.dekFileURL(dekTag: dekTag)
            } catch {
                print("DataVaultService::deleteSecureStorageKey() - error building dek URL: \(error)")
                throw DataVaultError.errorDeletingSecureStorageKey
            }
            
            do {
                try FileManager.default.removeItem(at: dekFileURL)
            } catch {
                print("DataVaultService::deleteSecureStorageKey() - error deleting local DEK: \(error)")
                throw DataVaultError.errorDeletingSecureStorageKey
            }
            
            print("DataVaultService::deleteSecureStorageKey() - DEK found and removed.")
        }
        
        if kekExists {
            
            let query = KEKKeyChainQuery.deleteKEK(kekTag: kekTag)
            
            let status = SecItemDelete(query as CFDictionary)
            if status == errSecSuccess {
                print("DataVaultService::deleteSecureStorageKey() - KEK found and removed.")
                return
            } else if status == errSecItemNotFound {
                print("DataVaultService::deleteSecureStorageKey() - key not found.")
                throw DataVaultError.errorSecureStorageKeyDoesNotExist
            } else {
                print("DataVaultService::deleteSecureStorageKey() - failed to delete key. Error code: \(status)")
                throw DataVaultError.unknownError
            }
        }
    }
    
    public func encryptData(keyTag: String, plaintext: Data) throws -> Data {
        
        let kekTag = self.kekTag(keyTag)
        let dekTag = self.dekTag(keyTag)
        
        let kekExists: Bool
        do {
            kekExists = try self.kekExists(kekTag: kekTag)
        } catch {
            print("DataVaultService::encryptData() - Encountered error verifying kek exists - error says:[\(error)]")
            throw DataVaultError.errorValidatingSecureStorageKeyExistence
        }
        
        let dekExists: Bool
        do {
            dekExists = try self.dekExists(dekTag: dekTag)
        } catch {
            print("DataVaultService::encryptData() - Encountered error verifying dek exists - error says:[\(error)]")
            throw DataVaultError.errorValidatingSecureStorageKeyExistence
        }
        
        if !(kekExists && dekExists) {
            print("DataVaultService::encryptData() - preflight failed - not able to continue with encryption.")
            throw DataVaultError.errorSecureStorageKeyDoesNotExist
        }
        
        let dek: DataEncryptionKey
        do {
            dek = try readDEK(dekTag: dekTag)
        } catch {
            print("DataVaultService::encryptData() - error loading cipher DEK.")
            throw DataVaultError.errorFetchingDEK
        }
        
       return Data()
    }
    
    private func loadKEKHandle(kekTag: String) throws -> SecKey {
        
        print("DataVaultService::loadKEKHandle() - loading KEK at tag:[\(kekTag)]")
        
        var item: CFTypeRef?
        let status = SecItemCopyMatching(KEKKeyChainQuery.findKEK(kekTag: kekTag), &item)
        
        guard status == errSecSuccess, let anyRef = item else {
            print("DataVaultService::loadKEKReference() - unable to load KEK; status=[\(status)], kekTag=[\(kekTag)]")
            throw DataVaultError.errorFetchingKEK
        }
        
        guard CFGetTypeID(anyRef) == SecKeyGetTypeID() else {
            print("DataVaultService::kekExists() - item found is not a SecKey; keyName=[\(kekTag)]")
            throw DataVaultError.errorFetchingKEK
        }
        
        return anyRef as! SecKey
    }
    
    private func readDEK(dekTag: String) throws -> DataEncryptionKey {
        
        print("DataVaultService::loadCipherDEK - loading cipher DEK @:[\(dekTag)]")
        
        let url = try self.dekFileURL(dekTag: dekTag)
        if !FileManager.default.fileExists(atPath: url.path) {
            print("DataVaultService::readCipherDEK - key does not exist:\(url.path)")
            throw DataVaultError.dekDoesNotExist
        }
        
        let cipherDEKData: Data
        
        do {
            cipherDEKData = try Data(contentsOf: url, options: .mappedIfSafe)
        } catch {
            print("DataVaultService::readCipherDEK - error reading cipher KEK\(error)")
            throw DataVaultError.errorFetchingDEK
        }
        
        if cipherDEKData.isEmpty {
            print("DataVaultService::readCipherDEK - file exists but is empty: \(url.path)")
            throw DataVaultError.errorFetchingDEK
        }
        
        let dataEncryptionKey: DataEncryptionKey
        do {
            dataEncryptionKey = try JSONDecoder().decode(DataEncryptionKey.self, from: cipherDEKData)
        } catch {
            print("DataVaultService::readCipherDEK() - error deserializing DEK.")
            throw DataVaultError.errorFetchingDEK
        }
        
        print("DataVaultService::loadCipherDEK - cipher DEK read")
        return dataEncryptionKey
    }
    
    private func kekTag(_ baseTag: String) -> String {
        return "\(Constants.kekPrefix)-\(baseTag)"
    }
    
    private func dekTag(_ baseTag: String) -> String {
        return "\(Constants.dekPrefix)-\(baseTag)"
    }
    
    private func kekExists(kekTag: String) throws -> Bool {
        
        let keySearchResult: Bool
        
        let query = KEKKeyChainQuery.findKEK(kekTag: kekTag)
        
        var item: CFTypeRef?
        let exists = SecItemCopyMatching(query as CFDictionary, &item)
        
        if exists == errSecSuccess {
            
            guard let item = item else {
                print("DataVaultService::kekExists() specified key not found on successful query")
                throw DataVaultError.errorFetchingKEK
            }
            
            guard CFGetTypeID(item) == SecKeyGetTypeID() else {
                print("DataVaultService::kekExists() - item is not a SecKey; keyName=[\(kekTag)]")
                throw DataVaultError.errorFetchingKEK
            }
    
            keySearchResult = true
        } else {
            if exists == errSecItemNotFound {
                print("DataVaultService::kekExists() specified key not found")
                keySearchResult = false
            } else {
                let statusString = SecCopyErrorMessageString(exists, nil) as String? ?? "Unknown error"
                print("DataVaultService::kekExists() error querying for key: \(statusString)")
                throw DataVaultError.unknownError
            }
        }
        
        return keySearchResult
    }
    
    private func dekExists(dekTag: String) throws -> Bool {
        
        let dekFileURL: URL
        
        do {
            dekFileURL = try self.dekFileURL(dekTag: dekTag)
        } catch {
            print("DataVaultService::dekExists() error building dek URL: \(error)")
            throw DataVaultError.errorFetchingDEK
        }
        
        return FileManager.default.fileExists(atPath: dekFileURL.path)
    }
    
    private func writeCipherDEK(_ cipherDEK: DataEncryptionKey,
                                as dekTag: String,
                                excludeFromBackup: Bool = true) throws {
        
        print("DataVaultService::writeCipherDEK - writing cipher DEK:[\(dekTag)]")
        
        var url = try self.dekFileURL(dekTag: dekTag)
        
        do {
            try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        } catch {
            
            print("DataVaultService::writeCipherDEK - failed to create directory for key file:[\(error.localizedDescription)]")
            throw DataVaultError.errorCreatingKeyStorageLocation
        }
        
        if FileManager.default.fileExists(atPath: url.path) {
            print("DataVaultService::writeCipherDEK - key exists:\(url.path)")
            throw DataVaultError.errorSecureStorageKeyExists
        }
        
        let keyData = try JSONEncoder().encode(cipherDEK)
        
        do {
            try keyData.write(to: url, options: [.atomic, .completeFileProtection])
        } catch {
            print("DataVaultService::writeCipherDEK - failed to write cipher DEK to file:[\(url.path)]")
            throw DataVaultError.errorWritingKeyToStorage
        }
        
        if excludeFromBackup {
            var values = URLResourceValues()
            values.isExcludedFromBackup = true
            
            do {
                try url.setResourceValues(values)
            } catch {
                print("DataVaultService::writeCipherDEK - failure trying to set attributes to exclude cipher DEK from backup:[\(url.path)]")
                throw DataVaultError.errorWritingKeyToStorage
            }
        }
    }
    
    private func dekFileURL(dekTag: String) throws -> URL {
        
        guard let appSupportURL = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first else {
            throw DataVaultError.errorRetrievingApplicationSupportLocation
        }
        
        let bundleID = Bundle.main.bundleIdentifier ?? "App"
        let dir = appSupportURL.appendingPathComponent(bundleID, isDirectory: true)
            .appendingPathComponent("keys", isDirectory: true)
        
        return dir.appendingPathComponent("\(dekTag).json")
    }

    
    private func encryptWithDEK(kekTag: String, encryptedDEKBytes: Data, plaintext: Data) throws -> Data {
        
        try withDEK(kekTag: kekTag, encryptedDEK: encryptedDEKBytes) { key in
                let sealed = try AES.GCM.seal(plaintext, using: key)
                guard let combined = sealed.combined else {
                    throw DataVaultError.encryptionFailed
                }
                return combined // nonce || ciphertext || tag
            }
        
    }
    
    private func withDEK<R>(kekTag: String, encryptedDEK: Data, _ body: (SymmetricKey) throws -> R) throws -> R {
        
        let kekHandle: SecKey
        do {
            kekHandle = try loadKEKHandle(kekTag: kekTag)
        } catch {
            
        }
        
        let primaryAlg: SecKeyAlgorithm = .eciesEncryptionCofactorX963SHA256AESGCM
        let fallbackAlg: SecKeyAlgorithm = .eciesEncryptionStandardX963SHA256AESGCM
        
        guard let dekZeroizingData = try decryptBlobAIntoZeroingBuffer(privateKeyHandle: kekHandle,
                                                                       cipherBlob: encryptedDEK as CFData,
                                                                       primaryAlg: primaryAlg,
                                                                       fallbackAlg: fallbackAlg)
        else {
            throw DataVaultError.errorRetrievingSecureStorageKey
        }
        
        let result: R = try dekZeroizingData.withUnsafeBytes { buf in
            let key = SymmetricKey(data: buf)
            return try body(key)
        }
        
        return result
    }
    
    private func decryptBlobAIntoZeroingBuffer(privateKeyHandle: SecKey,
                                               cipherBlob: CFData,
                                               primaryAlg: SecKeyAlgorithm,
                                               fallbackAlg: SecKeyAlgorithm) throws -> Data? {
        func tryAlg(_ alg: SecKeyAlgorithm) -> Data? {
            guard SecKeyIsAlgorithmSupported(privateKeyHandle, .decrypt, alg) else {
                return nil
            }
            var err: Unmanaged<CFError>?
            guard let cfPlain = SecKeyCreateDecryptedData(privateKeyHandle, alg, cipherBlob, &err) else {
                if let e = err?.takeRetainedValue() {
                    print("decryptBlobToZeroizingData() - decrypt failed for [\(alg)]: \(e)")
                }
                return nil
            }
            
            let length = CFDataGetLength(cfPlain)
            let outPtr = UnsafeMutableRawPointer.allocate(byteCount: length,
                                                          alignment: MemoryLayout<UInt8>.alignment)
            CFDataGetBytes(cfPlain, CFRange(location: 0, length: length),
                           outPtr.assumingMemoryBound(to: UInt8.self))
            
            let zeroizing = Data(bytesNoCopy: outPtr, count: length, deallocator: .custom { p, len in
                p.bindMemory(to: UInt8.self, capacity: len).initialize(repeating: 0, count: len)
                p.deallocate()
            })
            return zeroizing
        }

        if let d = tryAlg(primaryAlg) { return d }
        if let d = tryAlg(fallbackAlg) {
            print("decryptBlobToZeroizingData() - used fallback algorithm: [\(fallbackAlg)]")
            return d
        }
        print("decryptBlobToZeroizingData() - no supported algorithm succeeded")
        return nil
    }
    
    private func encryptDEK(dek: Data, kekTag: String) throws -> Data {
        
        var item: CFTypeRef?
        let status = SecItemCopyMatching(KEKKeyChainQuery.findKEK(kekTag: kekTag), &item)
        guard status == errSecSuccess, let item = item else {
            print("DataVaultService::encryptDEK() - unable to locate the signing key (KEK); status=[\(status)], keyName=[\(kekTag)]")
            throw DataVaultError.errorRetrievingSecureStorageKey
        }
        
        guard CFGetTypeID(item) == SecKeyGetTypeID() else {
            print("DataVaultService::encryptDEK() - item is not a SecKey; keyName=[\(kekTag)]")
            throw DataVaultError.errorRetrievingSecureStorageKey
        }
        
        let kekPrivateKey = item as! SecKey
        guard let publicKey = SecKeyCopyPublicKey(kekPrivateKey) else {
            print("DataVaultService::encryptDEK() - unable to copy KEK public key; tag=[\(kekTag)]")
            throw DataVaultError.errorRetrievingSecureStorageKey
        }
        
        let primaryAlg: SecKeyAlgorithm = .eciesEncryptionCofactorX963SHA256AESGCM
        let fallbackAlg: SecKeyAlgorithm = .eciesEncryptionStandardX963SHA256AESGCM
        let alg: SecKeyAlgorithm
        
        if SecKeyIsAlgorithmSupported(publicKey, .encrypt, primaryAlg) {
            alg = primaryAlg
        } else if SecKeyIsAlgorithmSupported(publicKey, .encrypt, fallbackAlg) {
            alg = fallbackAlg
            print("DataVaultService::encryptDEK() - primary ECIES alg not supported; falling back to Standard X9.63")
        } else {
            print("DataVaultService::encryptDEK() - no supported ECIES AES-GCM algorithm for this key")
            throw DataVaultError.failedToCreateSecureStorageKey
        }
        
        var unmanagedError: Unmanaged<CFError>?
        if let encryptedKey = SecKeyCreateEncryptedData(publicKey, alg, dek as CFData, &unmanagedError) {
            return encryptedKey as Data
        } else {
            let managedError = unmanagedError?.takeRetainedValue()
            print("DataVaultService::encryptDEK() - ECIES encrypt failed; alg=\(alg), error=\(String(describing: managedError))")
            throw DataVaultError.failedToCreateSecureStorageKey
        }
    }
    
    private func createDEK(dekTag: String, kekTag: String, forceOverwrite: Bool = false) throws {
        
        do {
            let kekExists = try self.kekExists(kekTag: kekTag)
            if !kekExists {
                print("DataVaultService::generateDEK() - unable to find associated KEK")
                throw DataVaultError.kekNotFound
            }
        } catch {
            print("DataVaultService::generateDEK() - encountered error verifying existence of the required KEK - error says:[\(error)]")
            throw error
        }
        
        let dekExists: Bool
        do {
            dekExists = try self.dekExists(dekTag: dekTag)
            if dekExists && !forceOverwrite {
                print("DataVaultService::generateDEK() - An existing DEK was discovered during a request to create a new DEK when forceOverwrite was not requested")
                throw DataVaultError.dekExists
            }
        } catch {
            print("DataVaultService::generateDEK() - encountered error verifying existence of the required DEK - error says:[\(error)]")
            throw error
        }
        
        if dekExists && forceOverwrite {
            do {
                try deleteDEK(dekTag: dekTag)
            } catch {
                print("DataVaultService::generateDEK() - encountered error trying to delete the existing DEK - error says:[\(error)]")
                throw DataVaultError.errorDeletingDEK
            }
        }
        
        let cipherDEKBytes: Data
        do {
            cipherDEKBytes = try {
                var dekBytes = SymmetricKey(size: .bits256).withUnsafeBytes { Data($0) }
                defer { dekBytes.wipe() }
                return try encryptDEK(dek: dekBytes, kekTag: kekTag)
            }()
            print("DataVaultService::generateDEK() - DEK created")
        } catch {
            print("DataVaultService::generateDEK() - there was an error creating the encrypted DEK - error says:[\(error)]")
            throw DataVaultError.errorCreatingEncryptedDEK
        }
        
        do {
            try writeCipherDEK(DataEncryptionKey(cipherBlob: cipherDEKBytes), as: dekTag, excludeFromBackup: false)
            print("DataVaultService::generateDEK() - DEK persisted")
        } catch {
            print("DataVaultService::generateDEK() - error persisting wrapped DEK: \(error)")
                throw DataVaultError.errorWritingKeyToStorage
        }

    }
    
    private func deleteDEK(dekTag: String) throws {
        
        let targetURL: URL
        
        do {
            targetURL = try self.dekFileURL(dekTag: dekTag)
        } catch {
            print("DataVaultService::deleteDEK() - encountered an error trying to build the file URL - error says:[\(error)]")
            throw DataVaultError.errorDeletingDEK
        }
        
        guard FileManager.default.fileExists(atPath: targetURL.path) else {
            print("DataVaultService::deleteDEK() - DEK file not found; treating as already deleted")
            return
        }
        
        do {
            try FileManager.default.removeItem(at: targetURL)
        } catch {
            print("DataVaultService::deleteDEK() - encountered an error deleting the DEK - error says:[\(error)]")
            throw DataVaultError.errorDeletingDEK
        }
        
        print("DataVaultService::deleteDEK() - DEK successfully deleted")
    }
    
    private func createKEK(kekTag: String, forceOverwrite: Bool = false) throws {
        
        print("DataVaultService::generateKEK() - generating KEK with tag:[\(kekTag)]...")
    
        var accessControlError: Unmanaged<CFError>?
        let secAccessControl = SecAccessControlCreateWithFlags(kCFAllocatorDefault,
                                                               kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                                                               [.privateKeyUsage],
                                                               &accessControlError)
        
        guard let secAccessControl = secAccessControl else {
            let managedAccessControlError = accessControlError?.takeRetainedValue()
            print("DataVaultService::generateKEK() - error creating access control object:[\(managedAccessControlError)]")
            throw DataVaultError.failedToCreateSecureStorageKey
        }
        
        let kekTagData = Data(kekTag.utf8)
        
        let privateKeyParams: [String: AnyObject] = [
            kSecAttrIsPermanent as String: true as AnyObject,
            kSecAttrApplicationTag as String: kekTagData as AnyObject,
            kSecAttrAccessControl as String: secAccessControl]
        

        var attributes: [String: Any] = [
                    kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
                    kSecAttrKeySizeInBits as String: 256,
                    kSecPrivateKeyAttrs as String: privateKeyParams
                ]
        
#if !targetEnvironment(simulator)
        attributes[kSecAttrTokenID as String] = kSecAttrTokenIDSecureEnclave
#endif
        
        var createKEKError: Unmanaged<CFError>?
        if SecKeyCreateRandomKey(attributes as CFDictionary, &createKEKError) != nil { return }
        
        if let managedCreateKEKError = createKEKError?.takeRetainedValue() {
            let nserr = managedCreateKEKError as Error as NSError
            if nserr.domain == NSOSStatusErrorDomain && nserr.code == errSecDuplicateItem {
                
                if forceOverwrite {
                    print("DataVaultService::generateKEK() - Honoring forceOverwrite request - deleting existing and recreating new KEK...")
                    do {
                        try deleteKEK(kekTag: kekTag)
                    } catch DataVaultError.errorSecureStorageKeyDoesNotExist{
                        // key is already gone - continuing is OK
                    } catch {
                        print("DataVaultService::generateKEK() - Encountered an error attempting to delete the existing KEK - error says:[\(error)]")
                        throw DataVaultError.failedToCreateSecureStorageKey
                    }
                    
                    var recreateKEKError: Unmanaged<CFError>?
                    guard SecKeyCreateRandomKey(attributes as CFDictionary, &recreateKEKError) != nil else {
                        let managedRecreateKEKError = recreateKEKError?.takeRetainedValue()
                        print("DataVaultService::generateKEK() - Encountered an error attempting to recreate a new KEK - error says:[\(String(describing: managedRecreateKEKError))]")
                        throw DataVaultError.failedToCreateSecureStorageKey
                    }
                    return
                } else {
                    print("DataVaultService::generateKEK() - An existing KEK was discovered during a request to create a new KEK when forceOverwrite was not requested")
                    throw DataVaultError.errorSecureStorageKeyExists
                }
            } else {
                print("DataVaultService::generateKEK() - encountered an error while creating the KEK - error says:[\(String(describing: managedCreateKEKError))]")
                throw DataVaultError.failedToCreateSecureStorageKey
            }
        }
        
        print("DataVaultService::generateKEK() - encountered an error while creating the KEK - however there was no CFError to extract...")
        throw DataVaultError.failedToCreateSecureStorageKey
    }
    
    private func deleteKEK(kekTag: String) throws {
        
        let query = KEKKeyChainQuery.deleteKEK(kekTag: kekTag)
        let status = SecItemDelete(query as CFDictionary)
        
        if status == errSecSuccess {
            return
        } else if status == errSecItemNotFound {
            print("DataVaultService::deleteSecureStorageKey() - key not found.")
            throw DataVaultError.errorSecureStorageKeyDoesNotExist
        } else {
            
            let msg = SecCopyErrorMessageString(status, nil) ?? "unknown error" as CFString
            
            print("DataVaultService::deleteSecureStorageKey() - failed to delete key. Error says: \(msg)")
            throw DataVaultError.unknownError
        }
    }
}

enum KEKKeyChainQuery {
    
    static func deleteKEK(kekTag: String) -> CFDictionary {
        
        let kekTagData = Data(kekTag.utf8)
        
        var query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: kekTagData,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom
        ]
        
#if !targetEnvironment(simulator)
        query[kSecAttrTokenID as String] = kSecAttrTokenIDSecureEnclave
#endif
        
        return query as CFDictionary
    }
    
    static func findKEK(kekTag: String) -> CFDictionary {
        
        let tagData = Data(kekTag.utf8)
        
        var query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: tagData,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
            kSecReturnRef as String: kCFBooleanTrue as Any,
            kSecMatchLimit as String: kSecMatchLimitOne]
        
#if !targetEnvironment(simulator)
        query[kSecAttrTokenID as String] = kSecAttrTokenIDSecureEnclave
#endif
        
        return query as CFDictionary
    }
}
