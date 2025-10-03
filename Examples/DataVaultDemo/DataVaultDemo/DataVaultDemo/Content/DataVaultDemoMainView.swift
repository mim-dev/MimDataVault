//
//  DataVaultDemoMainView.swift
//  DataVaultDemo
//
//  Copyright (c) 2025 Luther Stanton
//
//  This source code is licensed under the MIT license found in the
//  LICENSE file in the root directory of this source tree.
//

import SwiftUI

//private struct TagEntryView: View {
//    
//    @State private var keyTag: String = ""
//    @State private var showEditor: Bool = false
//    @State private var hasPresentedOnce = false
//    
//    var body: some View {
//        Form {
//                    Section(header: Text("Key Encryption Key (KEK) Tag")) {
//                        HStack(spacing: 8) {
//                            TextField("Enter key tag…", text: $keyTag)
//                                .textInputAutocapitalization(.none)
//                                .autocorrectionDisabled(true)
//                                .submitLabel(.done)
//
//                            Button {
//                                showEditor = true
//                            } label: {
//                                Image(systemName: "pencil.and.scribble")
//                                    .imageScale(.medium)
//                                    .accessibilityLabel("Edit key tag")
//                            }
//                        }
//                        .padding(.vertical, 4)
//                        .contentShape(Rectangle())
//                    }
//                }
//                .navigationTitle("DataVault Setup")
//                .onAppear {
//                    if !hasPresentedOnce {
//                        hasPresentedOnce = true
//                        showEditor = true
//                    }
//                }
//                .sheet(isPresented: $showEditor) {
//                    KeyTagSheet(
//                        initialValue: keyTag,
//                        onConfirm: { newValue in
//                            keyTag = newValue.trimmingCharacters(in: .whitespacesAndNewlines)
//                        },
//                        onErase: {
//                            keyTag = ""
//                        }
//                    )
//                    .presentationDetents([.height(260), .medium]) // feels like a dialog
//                    .presentationDragIndicator(.visible)
//                }
//    }
//}

struct DataVaultDemoMainView: View {
    
    @StateObject private var viewModel: DataVaultDemoMainViewModel = DataVaultDemoMainViewModel()
    @State private var forceOverwrite: Bool = false
    @State private var excludeFromBackup: Bool = true
    
    var body: some View {
        VStack(spacing: 12) {
            
            TextField("Enter key name", text: $viewModel.keyName)
                .textFieldStyle(.roundedBorder)
                .layoutPriority(1)
                .frame(maxWidth: .infinity)
                .padding(.horizontal)
//                .onChange(of: viewModel.keyName) {
//                    viewModel.scheduleDebounceCheckForSecureStorageKey()
//                }
            
            Button("Create Key") {
                viewModel.createKey(as: viewModel.keyName,
                                    forceOverwrite: forceOverwrite,
                                    excludeFromBackup: excludeFromBackup)
            }
            .disabled(!viewModel.secureStorageKeyExists)
            .buttonStyle(.borderedProminent)
            
            
            .buttonStyle(.borderedProminent)
            
            Toggle("forceOverwrite", isOn: $forceOverwrite)
                .toggleStyle(.switch)
                .padding()
              //  .disabled(!viewModel.canCreateKey)
            
            Toggle("excludeFromBackup", isOn: $excludeFromBackup)
                .toggleStyle(.switch)
                .padding()
                //.disabled(!viewModel.canCreateKey)
            
            
            Button("Delete Key") {
                viewModel.deleteKey(tag: viewModel.keyName)
            }
            .buttonStyle(.borderedProminent)
            .disabled(viewModel.secureStorageKeyExists)
            
            Button("Check Key") {
                viewModel.checkKeyExistance(keyTag: viewModel.keyName)
            }
        }
        .padding()
    }
}

#Preview {
    DataVaultDemoMainView()
}
