//
//  DataVaultDemoMainViewModel.swift
//  DataVaultDemo
//
//  Created by Luther Stanton on 9/12/25.
//

import SwiftUI
import MimDataVault

@MainActor
class DataVaultDemoMainViewModel: ObservableObject {
    
    @Published var keyName: String = ""
    @Published var secureStorageKeyExists: Bool = false
    @Published var errorMessage: String? = nil
    @Published var isChecking: Bool = false
    
    private let dataVaultService: DataVaultService = DataVaultService()
    private var checkTask: Task<Void, Never>?
    
    func scheduleDebounceCheckForSecureStorageKey(delay: Duration = .milliseconds(750)) {
        checkTask?.cancel()
        
        let trimmed = keyName.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else {
            errorMessage = nil
            isChecking = false
            secureStorageKeyExists = false
            return
        }
        
        errorMessage = nil
        isChecking = true
        
        checkTask = Task { [weak self] in
            
            try? await Task.sleep(for: delay)
            guard !Task.isCancelled, let self else { return }
            guard !Task.isCancelled else { return }
            
            var exists: Bool = false
            
            let service = self.dataVaultService
            
            do {
                exists = try await Task.detached(priority: .userInitiated) { [service, trimmed] in
                    return try service.secureStorageKeyExists(keyTag: trimmed)
                }.value
                
                guard !Task.isCancelled else { return }
                self.secureStorageKeyExists = exists
                self.isChecking = false
                
            } catch DataVaultError.keyConsistencyError {
                guard !Task.isCancelled else { return }
                errorMessage = "Detected a key consistency error."
                self.isChecking = false
            } catch {
                guard !Task.isCancelled else { return }
                errorMessage = "An unknown error occurred checking for key existance."
                self.isChecking = false
            }
        }
    }
    
    func checkKeyExistance(keyTag: String) {
        
        do {
            secureStorageKeyExists = try dataVaultService.secureStorageKeyExists(keyTag: keyName)
        } catch {
            print("Encountered an error trying to check key existance: \(error)")
            errorMessage = "Key existance check failed"
        }
    }
    
    var canCreateKey: Bool {
        let trimmed = keyName.trimmingCharacters(in: .whitespacesAndNewlines)
        return !trimmed.isEmpty && errorMessage == nil && !secureStorageKeyExists && !isChecking
    }
    
    func createKey(as tag: String, forceOverwrite: Bool, excludeFromBackup: Bool) {
        
        print("DataDemoMainViewModel - creating key")
        
        do {
            try dataVaultService.createSecureStorageKey(keyTag: tag,
                                                        forceOverwrite: forceOverwrite,
                                                        excludeFromBackup: excludeFromBackup)
        } catch {
            print("Encountered an error trying to create the key: \(error)")
            errorMessage = "Key creation failed"
        }
    }
    
    func deleteKey(tag: String) {
        do {
            try dataVaultService.deleteSecureStorageKey(keyTag: tag, forceDelete: true)
        } catch {
            print("Encountered an error trying to delete the key: \(error)")
            errorMessage = "Key creation failed"
        }
        
    }
    
}
