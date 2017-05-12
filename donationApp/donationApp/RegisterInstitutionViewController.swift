//
//  RegisterInstitutionViewController.swift
//  donationApp
//
//  Created by Leticia Vieira Fernandes on 14/04/17.
//  Copyright © 2017 PUC. All rights reserved.
//

import UIKit
import Firebase
import SVProgressHUD
import CryptoSwift

class RegisterInstitutionViewController: UIViewController {
    
    @IBOutlet weak var emailField: UITextField!
    @IBOutlet weak var passwordField: UITextField!
    @IBOutlet weak var confirmPasswordField: UITextField!

    @IBOutlet weak var emailErrorImage: UIImageView!
    @IBOutlet weak var passwordErrorImage: UIImageView!
    @IBOutlet weak var confirmPaswordErrorImage: UIImageView!
    
    let refInstitutions = FIRDatabase.database().reference(withPath: "features")
    let refInstitutionsUsers = FIRDatabase.database().reference(withPath: "institution-users")
    
    var password_aes : String = "";

    // MARK: Life Cycle methods
    override func viewDidLoad() {
        super.viewDidLoad()
    }

    // MARK: Actions
    @IBAction func registerAction(_ sender: Any) {
        
        if isEmptyFields() {
            return
        }
        
        if !isMatchPasswords() {
            self.showAlert(withTitle: "Atenção!", message: "As senhas digitadas não correspondem.")
        }
        else {
            // Busca Instituições
            
            SVProgressHUD.setDefaultStyle(.dark)
            SVProgressHUD.show()
            
            refInstitutions.observe(.value, with: { snapshot in
                
                if let institution = self.findInstitutionInResults(snapshot) {
                    self.register(institution)
                }
                else {
                    SVProgressHUD.dismiss()
                    self.showAlert(withTitle: "Atenção!", message: "\n Não foi possível realizar o cadastro.\n\n Este e-mail não foi encontrado na base de Instituições reconhecidas.")
                }
            })
        }
    }
    
    @IBAction func closePopOver(_ sender: Any) {
        self.dismiss(animated: true, completion: nil)
    }
    
    // MARK: Firebase methods
    func register(_ institution : Institution) {
        
        //  Criptografia insegura (md5)
        // let password_md5 = md5Encryption(self.passwordField.text!)
        
        // Criptografia segura (AES)
        password_aes = aesEncryption(self.passwordField.text!)
        
        FIRAuth.auth()?.createUser(withEmail: self.emailField.text!, password: password_aes) { (user, error) in
            
            var title : String = ""
            var msg : String = ""
            
            //Error
            if let error = error {
                SVProgressHUD.dismiss()
                print("Firebase: Register Error!")
                title = "Erro"
                msg = error.localizedDescription
            }
            
            //Success
            if let user = user {
                print("Firebase: Register successfull")
                title = "Sucesso"
                msg = "Cadastro realizado com sucesso. "
                
                self.insertRegisteredUser(institution, uid:user.uid)
            }
            
            let alert = UIAlertController(title: title, message: msg, preferredStyle: .alert)
            let okAction = UIAlertAction(title: "Ok", style: .default, handler: { (okAction) in
                if (error == nil) {
                    self.dismiss(animated: true, completion: nil)
                }
            })
            
            alert.addAction(okAction)
            self.present(alert, animated: true, completion: nil)
        }
    }
    
    func findInstitutionInResults(_ snapshot : FIRDataSnapshot) -> Institution? {
        
        var foundedInstitution : Institution? = nil
        
        for item in snapshot.children {
            let institution = Institution(snapshot: item as! FIRDataSnapshot)
            
            if self.emailField.text == institution.email  {
                foundedInstitution = institution
            }
        }
        return foundedInstitution
    }
    
    //Save registered user in database
    func insertRegisteredUser(_ institution: Institution, uid: String) {
    
        let date = Date()
        let formatter = DateFormatter()
        formatter.dateFormat = "dd/MM/yyyy HH:mm:ss"
        let dateStr = formatter.string(from: date)
    
        let userInstitution = InstitutionUser(uid: uid,
                                          name: institution.name,
                                          info: institution.info,
                                          email: institution.email,
                                          password: password_aes,
                                          registerDate: dateStr,
                                          contact: institution.contact,
                                          phone: institution.phone,
                                          bank: institution.bank,
                                          agency: institution.agency,
                                          accountNumber: institution.accountNumber,
                                          address: institution.address,
                                          district: institution.district,
                                          city: institution.city,
                                          state: institution.state,
                                          zipCode: institution.zipCode,
                                          group: institution.group)
        
        let userInstitutionRef = self.refInstitutionsUsers.child(userInstitution.uid)
        userInstitutionRef.setValue(userInstitution.toAnyObject())
        
        SVProgressHUD.dismiss()
    }
    
    // MARK: Encryption methods
    func md5Encryption(_ password: String) -> String {
        return password.md5()
    }
    
    func aesEncryption(_ password: String) -> String {
        
        do {
            let key : Array<UInt8> = Array("770A8A65DA156D24EE2A093277530142".utf8)
            let iv  : Array<UInt8> = Array("F5502320F8429037".utf8)
            let bytesPass : Array<UInt8> = Array(password.utf8)
            
            let encrypted = try AES(key: key, iv: iv, blockMode: .CBC, padding: PKCS7()).encrypt(bytesPass);
            let decrypted = try AES(key: key, iv: iv, blockMode: .CBC, padding: PKCS7()).decrypt(encrypted)
            
            let encryptedStr = Data(bytes: encrypted).toHexString()
            print(encryptedStr)
            
            if let decryptedStr = String(data: Data(bytes: decrypted), encoding: .utf8) {
                print(decryptedStr)
            } else {
                print("That's not a valid UTF-8 sequence.")
            }
            
            return encryptedStr
            
        } catch {
            print(error)
        }
        
        return password;
    }
    
    // MARK: Validation methods
    func isEmptyFields() -> Bool {
        
        var isEmpty : Bool = false;
        
        if let email = self.emailField.text, email.isEmpty {
            self.emailErrorImage.isHidden = false;
            isEmpty = true;
        } else {
            self.emailErrorImage.isHidden = true;
        }
        
        if let password = self.passwordField.text, password.isEmpty {
            self.passwordErrorImage.isHidden = false;
            isEmpty = true;
        } else {
            self.passwordErrorImage.isHidden = true;
        }
        
        if let confirmPassword = self.confirmPasswordField.text, confirmPassword.isEmpty {
            self.confirmPaswordErrorImage.isHidden = false;
            isEmpty = true;
        } else {
            self.confirmPaswordErrorImage.isHidden = true;
        }
        
        return isEmpty
    }
    
    func isMatchPasswords() -> Bool {
        
        var  isMatch : Bool = true;
        
        if self.passwordField.text != self.confirmPasswordField.text {
            isMatch = false
        }
        
        return isMatch
    }
    
    func showAlert(withTitle: String, message: String) {
        
        let alert = UIAlertController(title: title,
                                      message: message,
                                      preferredStyle: .alert)
        
        let okAction = UIAlertAction(title: "Ok",
                                     style: .default)
        
        alert.addAction(okAction)
        self.present(alert, animated: true, completion: nil)
    }
}
